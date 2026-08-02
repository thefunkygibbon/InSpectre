from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import StreamingResponse, Response
from sqlalchemy import text
from sqlalchemy.orm import Session
from typing import Optional, List
from collections import defaultdict
import asyncio, json, os, shutil, threading, subprocess
from datetime import datetime, timezone, timedelta
from database import get_db, SessionLocal
from auth_utils import get_current_user
from models import Setting
from schemas import ContainerHostCreate, ContainerHostUpdate
from probe_client import _probe_client
from background_loops import (
    _trivy_db_status, _run_trivy_db_download, _trivy_db_update_lock,
    _container_vuln_scans, _run_trivy_for_container, _schedule_trivy_db_download_if_missing,
    _save_trivy_result,
)
from notifications_core import _notification_dispatch
import container_updates as _cu
import httpx
import yaml as _yaml
from config import PROBE_URL
from trivy_utils import run_trivy_image_scan_sync
from plugins.security_audit import audit_docker_container, audit_proxmox_guest

router = APIRouter()


# ---------------------------------------------------------------------------
# Container host helpers
# ---------------------------------------------------------------------------

def _row_to_host(row) -> dict:
    return {
        "id":         row.id,
        "name":       row.name,
        "type":       row.type,
        "url":        row.url,
        "auth_user":  row.auth_user,
        "auth_token": "***" if row.auth_token else None,  # never expose token
        "tls_verify": row.tls_verify,
        "enabled":    row.enabled,
        "node":       row.node,
        "local_ip":   row.local_ip,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.get("/container-hosts")
async def list_container_hosts(db: Session = Depends(get_db)):
    rows = db.execute(text("SELECT * FROM container_hosts ORDER BY id")).fetchall()
    return [_row_to_host(r) for r in rows]


@router.post("/container-hosts", status_code=201)
async def create_container_host(body: ContainerHostCreate, db: Session = Depends(get_db)):
    row = db.execute(text("""
        INSERT INTO container_hosts (name, type, url, auth_user, auth_token, tls_verify, enabled, node, local_ip)
        VALUES (:name, :type, :url, :au, :at, :tls, :enabled, :node, :local_ip)
        RETURNING *
    """), {
        "name": body.name, "type": body.type, "url": body.url or None,
        "au": body.auth_user or None, "at": body.auth_token or None,
        "tls": body.tls_verify, "enabled": body.enabled, "node": body.node or "pve",
        "local_ip": body.local_ip or None,
    }).fetchone()
    db.commit()
    if body.enabled:
        _schedule_trivy_db_download_if_missing()
    return _row_to_host(row)


@router.put("/container-hosts/{host_id}")
async def update_container_host(host_id: int, body: ContainerHostUpdate, db: Session = Depends(get_db)):
    row = db.execute(text("SELECT * FROM container_hosts WHERE id = :id"), {"id": host_id}).fetchone()
    if not row:
        raise HTTPException(404, "Host not found.")
    fields = {}
    if body.name       is not None: fields["name"]       = body.name
    if body.type       is not None: fields["type"]       = body.type
    if body.url        is not None: fields["url"]        = body.url or None
    if body.auth_user  is not None: fields["auth_user"]  = body.auth_user or None
    if body.tls_verify is not None: fields["tls_verify"] = body.tls_verify
    if body.enabled    is not None: fields["enabled"]    = body.enabled
    if body.node       is not None: fields["node"]       = body.node or "pve"
    if body.local_ip   is not None: fields["local_ip"]   = body.local_ip or None
    # Only update auth_token if explicitly supplied and not masked
    if body.auth_token is not None and body.auth_token != "***":
        fields["auth_token"] = body.auth_token or None
    if not fields:
        return _row_to_host(row)
    set_clause = ", ".join(f"{k} = :{k}" for k in fields)
    fields["id"] = host_id
    updated = db.execute(text(f"UPDATE container_hosts SET {set_clause} WHERE id = :id RETURNING *"), fields).fetchone()
    db.commit()
    if fields.get("enabled"):
        _schedule_trivy_db_download_if_missing()
    return _row_to_host(updated)


@router.delete("/container-hosts/{host_id}", status_code=204)
async def delete_container_host(host_id: int, db: Session = Depends(get_db)):
    db.execute(text("DELETE FROM container_hosts WHERE id = :id"), {"id": host_id})
    db.commit()


@router.post("/container-hosts/{host_id}/test")
async def test_container_host(host_id: int, db: Session = Depends(get_db)):
    row = db.execute(text("SELECT * FROM container_hosts WHERE id = :id"), {"id": host_id}).fetchone()
    if not row:
        raise HTTPException(404, "Host not found.")

    def _do_test():
        if row.type == "proxmox":
            resp = _proxmox_request(row, "GET", "/api2/json/version")
            return {"ok": True, "detail": f"Proxmox VE {resp.get('data', {}).get('version', '?')}"}
        else:
            client = _make_docker_client(row.url or "unix:///var/run/docker.sock")
            try:
                v = client.version()
                return {"ok": True, "detail": f"Docker {v.get('Version','?')} (API {v.get('ApiVersion','?')})"}
            finally:
                client.close()

    try:
        return await asyncio.to_thread(_do_test)
    except Exception as e:
        return {"ok": False, "detail": str(e)}


def _get_enabled_hosts(db: Session) -> list:
    """Return all enabled container_hosts rows as dicts (with real auth_token)."""
    rows = db.execute(text("SELECT * FROM container_hosts WHERE enabled = true ORDER BY id")).fetchall()
    return [
        {
            "id":         r.id, "name": r.name, "type": r.type,
            "url":        r.url, "auth_user": r.auth_user, "auth_token": r.auth_token,
            "tls_verify": r.tls_verify, "node": r.node, "local_ip": r.local_ip,
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Proxmox helpers
# ---------------------------------------------------------------------------

def _proxmox_request(host, method: str, path: str, **kwargs):
    """Make an authenticated httpx request to a Proxmox VE API.
    host may be a dict or an SQLAlchemy row-like object."""
    if isinstance(host, dict):
        base   = (host.get("url") or "").rstrip("/")
        user   = host.get("auth_user") or ""
        token  = host.get("auth_token") or ""
        verify = host.get("tls_verify", False)
    else:
        base   = (getattr(host, "url",        None) or "").rstrip("/")
        user   = getattr(host, "auth_user",   None) or ""
        token  = getattr(host, "auth_token",  None) or ""
        verify = getattr(host, "tls_verify",  False)
    if not base:
        raise ValueError("Proxmox URL not configured.")
    headers = {}
    if user and token:
        headers["Authorization"] = f"PVEAPIToken={user}={token}"
    with httpx.Client(verify=verify, timeout=15) as client:
        resp = client.request(method, f"{base}{path}", headers=headers, **kwargs)
        resp.raise_for_status()
        return resp.json()

# Keep alias for backward compat within this file
_proxmox_request_row = _proxmox_request


def _fmt_proxmox_container(data: dict, vmid: int, node: str, host: dict, vm_type: str = "lxc") -> dict:
    """Normalise a Proxmox LXC/QEMU container to the same shape as a Docker container."""
    status = data.get("status", "stopped")
    docker_status = "running" if status == "running" else ("paused" if status == "paused" else "exited")
    uptime_secs = data.get("uptime", 0)
    uptime_str = ""
    if uptime_secs:
        h, m = divmod(uptime_secs // 60, 60)
        d, h = divmod(h, 24)
        uptime_str = (f"{d}d " if d else "") + (f"{h}h " if h else "") + f"{m}m"
    template = data.get("ostemplate", data.get("template", ""))
    image = template.split(":")[0].split("/")[-1] if template else f"{vm_type}-{vmid}"
    return {
        "id":             f"px-{host['id']}-{node}-{vmid}",
        "short_id":       str(vmid),
        "name":           data.get("name", f"ct-{vmid}"),
        "image":          image,
        "image_id":       template,
        "status":         docker_status,
        "state": {
            "status":      status,
            "running":     status == "running",
            "paused":      status == "paused",
            "restarting":  False,
            "started_at":  "",
            "finished_at": "",
            "exit_code":   0,
        },
        "ports":          [],
        "networks":       [],
        "mounts":         [],
        "env":            [],
        "labels":         {"proxmox.vmid": str(vmid), "proxmox.node": node, "proxmox.type": vm_type},
        "created":        "",
        "restart_policy": "",
        "platform":       "linux",
        "command":        [],
        "hostname":       data.get("hostname", data.get("name", "")),
        "working_dir":    "",
        "uptime":         uptime_str,
        "host_id":        host["id"],
        "host_name":      host["name"],
        "host_type":      "proxmox",
        "vmid":           vmid,
        "node":           node,
    }


def _fetch_containers_for_host(host: dict) -> list:
    """Fetch and normalise containers from a single host (Docker or Proxmox)."""
    htype = host["type"]
    host_url = host["url"] or "unix:///var/run/docker.sock"

    if htype == "proxmox":
        containers = []
        try:
            nodes_resp = _proxmox_request(host, "GET", "/api2/json/nodes")
            nodes = [n["node"] for n in nodes_resp.get("data", [])]
        except Exception:
            nodes = [host.get("node", "pve")]
        for node in nodes:
            try:
                lxc_resp = _proxmox_request(host, "GET", f"/api2/json/nodes/{node}/lxc")
                for item in lxc_resp.get("data", []):
                    vmid = int(item.get("vmid", 0))
                    if vmid:
                        containers.append(_fmt_proxmox_container(item, vmid, node, host, "lxc"))
            except Exception:
                pass
        return containers

    # Docker (local or remote)
    client = _make_docker_client(host_url)
    try:
        result = []
        for c in client.containers.list(all=True):
            result.append(_add_docker_host_meta(_fmt_container(c), host, host_url))
        return result
    finally:
        client.close()


def _docker_enabled(db: Session) -> bool:
    """Returns True if any container host is enabled (hosts table or legacy setting)."""
    try:
        count = db.execute(text("SELECT COUNT(*) FROM container_hosts WHERE enabled = true")).scalar()
        if count and count > 0:
            return True
    except Exception:
        pass
    s = db.get(Setting, "docker_enabled")
    return (s.value if s else "false") == "true"

def _get_docker_host(db: Session) -> str:
    s = db.get(Setting, "docker_host")
    return (s.value if s else None) or "unix:///var/run/docker.sock"

def _parse_extra_hosts(extra_hosts):
    """Docker stores ExtraHosts as ['host:ip', ...]; the SDK wants {host: ip}."""
    out = {}
    for item in (extra_hosts or []):
        if ":" in item:
            host, ip = item.rsplit(":", 1)
            out[host] = ip
    return out or None


def _make_docker_client(host: str):
    try:
        import docker as _docker
        return _docker.DockerClient(base_url=host)
    except ImportError:
        raise HTTPException(503, "Docker SDK not installed in backend.")
    except Exception as e:
        raise HTTPException(503, f"Cannot connect to Docker at '{host}': {e}")

def _fmt_container(c) -> dict:
    attrs      = c.attrs or {}
    state      = attrs.get("State", {})
    config     = attrs.get("Config", {})
    host_cfg   = attrs.get("HostConfig", {})
    net        = attrs.get("NetworkSettings", {})

    ports = []
    seen_port_entries: set = set()
    for cport, bindings in (net.get("Ports") or {}).items():
        if cport.endswith("/0"):
            continue
        if bindings:
            for b in bindings:
                hip   = b.get("HostIp", "") or ""
                hport = b.get("HostPort", "") or ""
                if hip in ("0.0.0.0", "::"):
                    hip = ""
                key = (hip, hport, cport)
                if key in seen_port_entries:
                    continue
                seen_port_entries.add(key)
                ports.append({"host_ip": hip, "host_port": hport, "container_port": cport})
        else:
            if cport not in seen_port_entries:
                seen_port_entries.add(cport)
                ports.append({"host_ip": "", "host_port": "", "container_port": cport})

    mounts = [
        {"type": m.get("Type",""), "source": m.get("Source",""), "destination": m.get("Destination",""), "mode": m.get("Mode","")}
        for m in (attrs.get("Mounts") or [])
    ]

    finished = state.get("FinishedAt","")

    return {
        "id":             c.id,
        "short_id":       c.short_id,
        "name":           c.name.lstrip("/"),
        "image":          (config.get("Image") or ""),
        "image_id":       attrs.get("Image",""),
        "status":         c.status,
        "state": {
            "status":      state.get("Status",""),
            "running":     state.get("Running", False),
            "paused":      state.get("Paused", False),
            "restarting":  state.get("Restarting", False),
            "started_at":  state.get("StartedAt",""),
            "finished_at": finished if finished and finished != "0001-01-01T00:00:00Z" else "",
            "exit_code":   state.get("ExitCode", 0),
        },
        "ports":          ports,
        "networks":       list((net.get("Networks") or {}).keys()),
        "mounts":         mounts,
        "env":            config.get("Env") or [],
        "created":        attrs.get("Created",""),
        "labels":         config.get("Labels") or {},
        "restart_policy": (host_cfg.get("RestartPolicy") or {}).get("Name",""),
        "platform":       attrs.get("Platform",""),
        "command":        config.get("Cmd") or [],
        "hostname":       config.get("Hostname",""),
        "working_dir":    config.get("WorkingDir",""),
    }


def _add_docker_host_meta(container: dict, host: dict, host_url: str) -> dict:
    container["host_id"] = host["id"]
    container["host_name"] = host["name"]
    container["host_type"] = host["type"]
    container["host_url"] = host_url
    container["host_local_ip"] = host.get("local_ip")  # Store local_ip for port links
    return container


@router.get("/docker/stats")
async def docker_stats(db: Session = Depends(get_db)):
    hosts = _get_enabled_hosts(db)
    if not hosts:
        raise HTTPException(503, "No container hosts configured. Add one in Settings → Containers.")

    def _do_host(h):
        return _fetch_containers_for_host(h)

    tasks = [asyncio.to_thread(_do_host, h) for h in hosts]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_containers = []
    for r in results:
        if not isinstance(r, Exception):
            all_containers.extend(r)

    counts = {}
    for c in all_containers:
        st = c.get("status", "exited")
        counts[st] = counts.get(st, 0) + 1

    return {
        "total":          len(all_containers),
        "running":        counts.get("running", 0),
        "stopped":        counts.get("exited", 0) + counts.get("created", 0) + counts.get("dead", 0),
        "paused":         counts.get("paused", 0),
        "restarting":     counts.get("restarting", 0),
        "hosts":          len(hosts),
        "connected":      True,
    }


@router.get("/docker/containers")
async def list_docker_containers(db: Session = Depends(get_db)):
    hosts = _get_enabled_hosts(db)
    if not hosts:
        raise HTTPException(503, "No container hosts configured. Add one in Settings → Containers.")

    tasks = [asyncio.to_thread(_fetch_containers_for_host, h) for h in hosts]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_containers = []
    for r in results:
        if not isinstance(r, Exception):
            all_containers.extend(r)

    return all_containers


def _parse_proxmox_id(container_id: str):
    """Parse 'px-{host_id}-{node}-{vmid}' → (host_id, node, vmid) or None."""
    if not container_id.startswith("px-"):
        return None
    parts = container_id.split("-", 3)
    if len(parts) != 4:
        return None
    try:
        return int(parts[1]), parts[2], int(parts[3])
    except ValueError:
        return None


def _get_host_row(db: Session, host_id: int) -> dict:
    row = db.execute(text("SELECT * FROM container_hosts WHERE id = :id"), {"id": host_id}).fetchone()
    if not row:
        raise HTTPException(404, f"Container host {host_id} not found.")
    return {"id": row.id, "name": row.name, "type": row.type, "url": row.url,
            "auth_user": row.auth_user, "auth_token": row.auth_token,
            "tls_verify": row.tls_verify, "node": row.node}


def _proxmox_action(host: dict, node: str, vmid: int, action: str) -> dict:
    """Run a lifecycle action on a Proxmox LXC and return updated container info."""
    import time
    pve_action = "reboot" if action == "restart" else action
    _proxmox_request(host, "POST", f"/api2/json/nodes/{node}/lxc/{vmid}/status/{pve_action}")
    time.sleep(1)
    status_resp = _proxmox_request(host, "GET", f"/api2/json/nodes/{node}/lxc/{vmid}/status/current")
    return _fmt_proxmox_container(status_resp.get("data", {}), vmid, node, host)


@router.get("/docker/containers/{container_id}")
async def get_docker_container(container_id: str, db: Session = Depends(get_db)):
    px = _parse_proxmox_id(container_id)
    if px:
        host_id, node, vmid = px
        host = _get_host_row(db, host_id)
        def _do():
            r = _proxmox_request(host, "GET", f"/api2/json/nodes/{node}/lxc/{vmid}/status/current")
            return _fmt_proxmox_container(r.get("data", {}), vmid, node, host)
        try:
            return await asyncio.to_thread(_do)
        except Exception as e:
            raise HTTPException(503, str(e))

    hosts = _get_enabled_hosts(db)
    docker_hosts = [h for h in hosts if h["type"] != "proxmox"]
    if not docker_hosts:
        raise HTTPException(503, "No Docker hosts configured.")
    host_url = docker_hosts[0]["url"] or "unix:///var/run/docker.sock"

    def _do():
        client = _make_docker_client(host_url)
        try:
            c = client.containers.get(container_id)
            return _add_docker_host_meta(_fmt_container(c), docker_hosts[0], host_url)
        finally:
            client.close()

    try:
        return await asyncio.to_thread(_do)
    except HTTPException:
        raise
    except Exception as e:
        code = 404 if "404" in str(e) or "Not Found" in str(e) else 503
        raise HTTPException(code, str(e))


@router.post("/docker/containers/{container_id}/start")
async def docker_start(container_id: str, db: Session = Depends(get_db)):
    px = _parse_proxmox_id(container_id)
    if px:
        host_id, node, vmid = px
        host = _get_host_row(db, host_id)
        try:
            return await asyncio.to_thread(_proxmox_action, host, node, vmid, "start")
        except Exception as e:
            raise HTTPException(400, str(e))

    hosts = _get_enabled_hosts(db)
    docker_hosts = [h for h in hosts if h["type"] != "proxmox"]
    if not docker_hosts:
        raise HTTPException(503, "No Docker hosts.")
    host_url = docker_hosts[0]["url"] or "unix:///var/run/docker.sock"

    def _do():
        client = _make_docker_client(host_url)
        try:
            c = client.containers.get(container_id)
            c.start(); c.reload()
            return _add_docker_host_meta(_fmt_container(c), docker_hosts[0], host_url)
        finally:
            client.close()

    try:
        return await asyncio.to_thread(_do)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/docker/containers/{container_id}/stop")
async def docker_stop(container_id: str, db: Session = Depends(get_db)):
    px = _parse_proxmox_id(container_id)
    if px:
        host_id, node, vmid = px
        host = _get_host_row(db, host_id)
        try:
            return await asyncio.to_thread(_proxmox_action, host, node, vmid, "stop")
        except Exception as e:
            raise HTTPException(400, str(e))

    hosts = _get_enabled_hosts(db)
    docker_hosts = [h for h in hosts if h["type"] != "proxmox"]
    if not docker_hosts:
        raise HTTPException(503, "No Docker hosts.")
    host_url = docker_hosts[0]["url"] or "unix:///var/run/docker.sock"

    def _do():
        client = _make_docker_client(host_url)
        try:
            c = client.containers.get(container_id)
            c.stop(timeout=10); c.reload()
            return _add_docker_host_meta(_fmt_container(c), docker_hosts[0], host_url)
        finally:
            client.close()

    try:
        return await asyncio.to_thread(_do)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/docker/containers/{container_id}/restart")
async def docker_restart(container_id: str, db: Session = Depends(get_db)):
    px = _parse_proxmox_id(container_id)
    if px:
        host_id, node, vmid = px
        host = _get_host_row(db, host_id)
        try:
            return await asyncio.to_thread(_proxmox_action, host, node, vmid, "restart")
        except Exception as e:
            raise HTTPException(400, str(e))

    hosts = _get_enabled_hosts(db)
    docker_hosts = [h for h in hosts if h["type"] != "proxmox"]
    if not docker_hosts:
        raise HTTPException(503, "No Docker hosts.")
    host_url = docker_hosts[0]["url"] or "unix:///var/run/docker.sock"

    def _do():
        client = _make_docker_client(host_url)
        try:
            c = client.containers.get(container_id)
            c.restart(timeout=10); c.reload()
            return _add_docker_host_meta(_fmt_container(c), docker_hosts[0], host_url)
        finally:
            client.close()

    try:
        return await asyncio.to_thread(_do)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, str(e))


@router.delete("/docker/containers/{container_id}")
async def docker_delete(container_id: str, db: Session = Depends(get_db)):
    """Delete (remove) a container."""
    px = _parse_proxmox_id(container_id)
    if px:
        host_id, node, vmid = px
        host = _get_host_row(db, host_id)
        try:
            # Delete Proxmox LXC
            _proxmox_request(host, "DELETE", f"/api2/json/nodes/{node}/lxc/{vmid}")
            return {"status": "deleted"}
        except Exception as e:
            raise HTTPException(400, str(e))

    hosts = _get_enabled_hosts(db)
    docker_hosts = [h for h in hosts if h["type"] != "proxmox"]
    if not docker_hosts:
        raise HTTPException(503, "No Docker hosts.")
    host_url = docker_hosts[0]["url"] or "unix:///var/run/docker.sock"

    def _do():
        client = _make_docker_client(host_url)
        try:
            c = client.containers.get(container_id)
            # Stop if running
            if c.status != "exited":
                c.stop(timeout=10)
            # Remove container
            c.remove(force=True)
            return {"status": "deleted", "container_id": container_id}
        finally:
            client.close()

    try:
        return await asyncio.to_thread(_do)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, str(e))


@router.post("/docker/containers/{container_id}/update")
async def docker_update(container_id: str, db: Session = Depends(get_db)):
    """Update container by pulling latest image and recreating it (Watchtower-like)."""
    px = _parse_proxmox_id(container_id)
    if px:
        raise HTTPException(400, "Update is not supported for Proxmox containers.")

    hosts = _get_enabled_hosts(db)
    docker_hosts = [h for h in hosts if h["type"] != "proxmox"]
    if not docker_hosts:
        raise HTTPException(503, "No Docker hosts.")
    host_url = docker_hosts[0]["url"] or "unix:///var/run/docker.sock"

    def _do():
        client = _make_docker_client(host_url)
        try:
            c = client.containers.get(container_id)
            attrs = c.attrs or {}
            config = attrs.get("Config", {})
            host_cfg = attrs.get("HostConfig", {})

            # Use the original image reference from the container config (not digest)
            image_name = config.get("Image", "")
            if not image_name:
                raise Exception("Could not determine container image reference")

            # Pull latest image with 5-minute timeout
            try:
                import signal
                def _timeout_handler(signum, frame):
                    raise TimeoutError("Image pull timed out after 5 minutes")

                old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
                signal.alarm(300)  # 5 minutes
                try:
                    client.images.pull(image_name)
                finally:
                    signal.alarm(0)
                    signal.signal(signal.SIGALRM, old_handler)
            except (TimeoutError, Exception) as pull_err:
                raise Exception(f"Failed to pull image '{image_name}': {pull_err}")

            # Preserve network attachments + aliases for user-defined networks
            networks_to_attach = {}
            net_settings = attrs.get("NetworkSettings", {}) or {}
            networks = (net_settings.get("Networks") or {})
            if networks:
                ordered_nets = list(networks.items())
                if ordered_nets:
                    first_name, first_info = ordered_nets[0]
                    first_aliases = [a for a in (first_info.get("Aliases") or []) if a]
                    if first_name not in ("bridge", "host", "none"):
                        networks_to_attach[first_name] = first_aliases

            # Stop container
            if c.status != "exited":
                c.stop(timeout=10)

            # Remove old container
            c.remove(force=True)

            # Parse port bindings correctly from HostConfig
            port_bindings = None
            pb = host_cfg.get("PortBindings") or {}
            if pb:
                port_bindings = {}
                for cport, binds in pb.items():
                    if binds:
                        hostport = binds[0].get("HostPort")
                        hostip = binds[0].get("HostIp") or ""
                        if hostport:
                            port_bindings[cport] = (hostip, int(hostport)) if hostip else int(hostport)
                    else:
                        port_bindings[cport] = None

            # Parse devices if any
            devices = []
            for d in (host_cfg.get("Devices") or []):
                devices.append(
                    f"{d.get('PathOnHost')}:{d.get('PathInContainer')}:{d.get('CgroupPermissions', 'rwm')}"
                )

            # Get restart policy
            restart = host_cfg.get("RestartPolicy") or {}
            restart_policy = None
            if restart.get("Name"):
                restart_policy = {
                    "Name": restart.get("Name"),
                    "MaximumRetryCount": restart.get("MaximumRetryCount", 0),
                }

            # Build host config
            host_config = client.api.create_host_config(
                binds=host_cfg.get("Binds") or None,
                port_bindings=port_bindings,
                privileged=bool(host_cfg.get("Privileged")),
                cap_add=host_cfg.get("CapAdd") or None,
                cap_drop=host_cfg.get("CapDrop") or None,
                extra_hosts=_parse_extra_hosts(host_cfg.get("ExtraHosts")),
                restart_policy=restart_policy,
                network_mode=host_cfg.get("NetworkMode") or "bridge",
                devices=devices or None,
            )

            # Exposed ports
            exposed = list((config.get("ExposedPorts") or {}).keys()) or None

            # Create networking config for first network
            networking_config = None
            if networks_to_attach:
                first_net_name = list(networks_to_attach.keys())[0]
                first_net_aliases = networks_to_attach[first_net_name]
                networking_config = client.api.create_networking_config(
                    {first_net_name: client.api.create_endpoint_config(aliases=first_net_aliases)}
                )

            # Create new container
            new_c = client.containers.create(
                image=image_name,
                name=c.name.lstrip("/"),
                command=config.get("Cmd"),
                entrypoint=config.get("Entrypoint"),
                environment=config.get("Env"),
                labels=config.get("Labels"),
                hostname=None if host_cfg.get("NetworkMode") in ("host", "none") else config.get("Hostname"),
                working_dir=config.get("WorkingDir") or None,
                ports=exposed,
                host_config=host_config,
                networking_config=networking_config,
            )

            # Attach additional networks (skip first, already attached)
            if len(networks_to_attach) > 1:
                for i, (net_name, aliases) in enumerate(list(networks_to_attach.items())[1:]):
                    try:
                        client.api.connect_container_to_network(
                            new_c.id, net_name, aliases=aliases
                        )
                    except Exception:
                        pass

            # Start new container
            client.api.start(new_c.id)
            new_c.reload()
            return _add_docker_host_meta(_fmt_container(new_c), docker_hosts[0], host_url)
        finally:
            client.close()

    try:
        return await asyncio.to_thread(_do)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, str(e))


@router.get("/docker/containers/{container_id}/logs")
async def stream_docker_logs(container_id: str, tail: int = 100, db: Session = Depends(get_db)):
    """Stream container logs as SSE."""
    if container_id.startswith("px-"):
        raise HTTPException(400, "Log streaming is not yet available for Proxmox containers.")
    if not _docker_enabled(db):
        raise HTTPException(503, "No container hosts configured.")
    docker_hosts = [h for h in _get_enabled_hosts(db) if h["type"] != "proxmox"]
    host = docker_hosts[0]["url"] if docker_hosts else _get_docker_host(db)

    def _ensure_exists():
        client = _make_docker_client(host)
        try:
            client.containers.get(container_id)
        finally:
            client.close()

    try:
        await asyncio.to_thread(_ensure_exists)
    except Exception as e:
        code = 404 if "404" in str(e) or "Not Found" in str(e) else 503
        raise HTTPException(code, str(e))

    line_queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_event_loop()

    def _stream():
        try:
            client = _make_docker_client(host)
            c = client.containers.get(container_id)
            for raw in c.logs(stream=True, follow=True, tail=tail, timestamps=True):
                line = raw.decode("utf-8", errors="replace").rstrip("\n")
                loop.call_soon_threadsafe(line_queue.put_nowait, line)
        except Exception as exc:
            loop.call_soon_threadsafe(line_queue.put_nowait, f"[ERROR] {exc}")
        finally:
            loop.call_soon_threadsafe(line_queue.put_nowait, None)

    threading.Thread(target=_stream, daemon=True).start()

    async def _gen():
        while True:
            try:
                line = await asyncio.wait_for(line_queue.get(), timeout=120)
            except asyncio.TimeoutError:
                break
            if line is None:
                break
            yield f"data: {line}\n\n"

    return StreamingResponse(_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def _parse_trivy_json(data: dict) -> list:
    """Flatten Trivy JSON output into a list of structured vulnerability dicts."""
    vulns = []
    for result in data.get("Results", []):
        target = result.get("Target", "")
        for v in (result.get("Vulnerabilities") or []):
            cvss_score = None
            for src in (v.get("CVSS") or {}).values():
                score = src.get("V3Score") or src.get("V2Score")
                if score:
                    cvss_score = score
                    break
            vulns.append({
                "id":        v.get("VulnerabilityID", ""),
                "severity":  v.get("Severity", "UNKNOWN").lower(),
                "pkg":       v.get("PkgName", ""),
                "installed": v.get("InstalledVersion", ""),
                "fixed":     v.get("FixedVersion", ""),
                "title":     v.get("Title", ""),
                "cvss":      cvss_score,
                "target":    target,
            })
    return vulns


def _scan_matches_current_image(stored_image: str | None, stored_image_id: str | None,
                                current_image: str, current_image_id: str | None) -> bool:
    if stored_image_id and current_image_id:
        return stored_image_id == current_image_id
    return bool(stored_image and stored_image == current_image)


def _scan_candidate(image: str | None, image_id: str | None, vulns, scanned_at, source: str) -> dict | None:
    if scanned_at is None:
        return None
    payload = vulns if isinstance(vulns, list) else json.loads(vulns or "[]")
    scanned_iso = scanned_at.isoformat() if hasattr(scanned_at, "isoformat") else str(scanned_at)
    return {
        "image": image,
        "image_id": image_id,
        "vulns": payload,
        "scanned_at": scanned_iso,
        "source": source,
    }


def _latest_current_image_scan(db: Session, container_name: str, host_id: int | None,
                               current_image: str, current_image_id: str | None) -> dict:
    scanning = bool(_container_vuln_scans.get(container_name, {}).get("scanning"))
    stale = None
    candidates: list[dict] = []

    row = db.execute(
        text("SELECT image, image_id, vulns, scanned_at FROM container_vuln_results WHERE name = :name"),
        {"name": container_name},
    ).fetchone()
    if row:
        row_image_id = getattr(row, "image_id", None)
        if _scan_matches_current_image(row.image, row_image_id, current_image, current_image_id):
            cand = _scan_candidate(row.image, row_image_id, row.vulns, row.scanned_at, "manual_or_scheduled")
            if cand:
                candidates.append(cand)
        else:
            stale = {
                "image": row.image,
                "image_id": row_image_id,
                "scanned_at": row.scanned_at.isoformat() if row.scanned_at else None,
            }

    update_row = _cu._get_update_status_row(db, container_name, host_id)
    if update_row and update_row.get("new_image_scanned_at") and update_row.get("new_image_vulns") is not None:
        update_image = update_row.get("image") or current_image
        update_image_id = update_row.get("running_image_id")
        if (
            update_row.get("last_update_status") == "success"
            and _scan_matches_current_image(update_image, update_image_id, current_image, current_image_id)
        ):
            cand = _scan_candidate(
                update_image,
                update_image_id,
                update_row.get("new_image_vulns"),
                update_row.get("new_image_scanned_at"),
                "update_time_scan",
            )
            if cand:
                candidates.append(cand)

    def _scan_sort_key(item: dict) -> datetime:
        return datetime.fromisoformat(item["scanned_at"].replace("Z", "+00:00"))

    best = max(candidates, key=_scan_sort_key) if candidates else None
    if not best:
        return {
            "scanning": scanning,
            "image": current_image,
            "image_id": current_image_id,
            "vulns": None,
            "scanned_at": None,
            "source": None,
            "stale": stale,
        }
    return {**best, "scanning": scanning, "stale": stale}


# ---------------------------------------------------------------------------
# Compose file generation
# ---------------------------------------------------------------------------

def _generate_compose_yaml(c) -> tuple[str, dict]:
    """Return (yaml_string, meta) for a container object.

    meta contains:
      compose_managed: bool — whether container was started via docker compose
      project:         str | None
      service:         str | None
    """
    attrs    = c.attrs or {}
    cfg      = attrs.get("Config", {})
    hcfg     = attrs.get("HostConfig", {})
    net_sets = attrs.get("NetworkSettings", {})
    name     = c.name.lstrip("/")
    labels   = cfg.get("Labels") or {}

    compose_managed = bool(labels.get("com.docker.compose.project"))
    meta = {
        "compose_managed": compose_managed,
        "project":  labels.get("com.docker.compose.project"),
        "service":  labels.get("com.docker.compose.service"),
    }

    svc: dict = {}

    # image
    svc["image"] = cfg.get("Image") or ""

    # container_name
    svc["container_name"] = name

    # restart
    rp      = hcfg.get("RestartPolicy") or {}
    rp_name = rp.get("Name", "no") or "no"
    if rp_name not in ("no", ""):
        if rp_name == "on-failure":
            max_r = rp.get("MaximumRetryCount") or 0
            svc["restart"] = f"on-failure:{max_r}" if max_r else "on-failure"
        else:
            svc["restart"] = rp_name

    # ports
    ports = []
    seen_port_entries: set = set()
    for cport, bindings in (net_sets.get("Ports") or {}).items():
        # Bug 2: skip phantom /0 protocol entries Docker creates on recreation
        if cport.endswith("/0"):
            continue
        if bindings:
            for b in bindings:
                hip   = b.get("HostIp", "") or ""
                hport = b.get("HostPort", "") or ""
                # Bug 3: normalize all-interfaces addresses to empty string
                if hip in ("0.0.0.0", "::"):
                    hip = ""
                if hip:
                    entry = f"{hip}:{hport}:{cport}" if hport else cport
                else:
                    entry = f"{hport}:{cport}" if hport else cport
                # Bug 1: deduplicate IPv4 and IPv6 bindings for the same port
                if entry not in seen_port_entries:
                    seen_port_entries.add(entry)
                    ports.append(entry)
        else:
            # exposed but not published
            if cport not in seen_port_entries:
                seen_port_entries.add(cport)
                ports.append(cport)
    if ports:
        svc["ports"] = ports

    # volumes / bind mounts
    volumes  = []
    tmpfs    = []
    top_vols = {}
    for m in (attrs.get("Mounts") or []):
        mtype = m.get("Type", "bind")
        src   = m.get("Source", "") or ""
        dst   = m.get("Destination", "") or ""
        mode  = m.get("Mode", "") or ""
        if mtype == "tmpfs":
            tmpfs.append(dst)
        elif mtype == "volume":
            vol_name = m.get("Name") or src
            v = f"{vol_name}:{dst}"
            if mode and mode not in ("", "rw"):
                v += f":{mode}"
            volumes.append(v)
            if vol_name:
                top_vols[vol_name] = None  # mark for top-level volumes block
        else:  # bind
            v = f"{src}:{dst}"
            if mode and mode not in ("", "rw", "z"):
                v += f":{mode}"
            volumes.append(v)
    if volumes:
        svc["volumes"] = volumes
    if tmpfs:
        svc["tmpfs"] = tmpfs

    # environment (skip empty, mask nothing — user can see their own config)
    env = [e for e in (cfg.get("Env") or []) if e and "=" in e]
    if env:
        svc["environment"] = env

    # entrypoint
    ep = cfg.get("Entrypoint")
    if ep:
        svc["entrypoint"] = ep[0] if len(ep) == 1 else ep

    # command (skip if identical to entrypoint)
    cmd = cfg.get("Cmd")
    if cmd and cmd != ep:
        svc["command"] = cmd[0] if len(cmd) == 1 else cmd

    # hostname (skip docker-assigned default = first 12 chars of ID)
    hn = cfg.get("Hostname") or ""
    cid = attrs.get("Id", "") or ""
    if hn and hn != cid[:12]:
        svc["hostname"] = hn

    # working dir
    wd = cfg.get("WorkingDir") or ""
    if wd:
        svc["working_dir"] = wd

    # user
    user = cfg.get("User") or ""
    if user:
        svc["user"] = user

    # network_mode / networks
    networks    = net_sets.get("Networks") or {}
    net_names   = list(networks.keys())
    _std_nets   = {"bridge", "host", "none"}
    custom_nets = [n for n in net_names if n not in _std_nets]
    _hc_net_mode = (hcfg.get("NetworkMode") or "").lower()
    if _hc_net_mode == "host" or "host" in net_names:
        svc["network_mode"] = "host"
    elif _hc_net_mode == "none":
        svc["network_mode"] = "none"
    elif _hc_net_mode.startswith("container:"):
        _parent_ref = hcfg["NetworkMode"].split(":", 1)[1]
        try:
            _parent = c.client.containers.get(_parent_ref)
            _parent_name = _parent.name.lstrip("/")
        except Exception:
            _parent_name = _parent_ref  # fall back to raw ID/name
        svc["network_mode"] = f"container:{_parent_name}"
    elif custom_nets:
        net_block = {}
        for n in custom_nets:
            aliases = (networks.get(n) or {}).get("Aliases") or []
            # strip docker-assigned aliases (container name + short ID)
            real_aliases = [a for a in aliases if a not in (name, cid[:12])]
            net_block[n] = {"aliases": real_aliases} if real_aliases else {}
        svc["networks"] = net_block

    # extra_hosts
    extra_hosts = [h for h in (hcfg.get("ExtraHosts") or []) if h]
    if extra_hosts:
        svc["extra_hosts"] = extra_hosts

    # capabilities
    cap_add  = hcfg.get("CapAdd")  or []
    cap_drop = hcfg.get("CapDrop") or []
    if cap_add:
        svc["cap_add"]  = cap_add
    if cap_drop:
        svc["cap_drop"] = cap_drop

    if hcfg.get("Privileged"):
        svc["privileged"] = True

    # devices
    devs = [
        f"{d['PathOnHost']}:{d['PathInContainer']}"
        for d in (hcfg.get("Devices") or [])
        if d.get("PathOnHost")
    ]
    if devs:
        svc["devices"] = devs

    # dns
    dns = [d for d in (hcfg.get("Dns") or []) if d]
    if dns:
        svc["dns"] = dns

    # resource limits
    mem = hcfg.get("Memory") or 0
    if mem:
        if mem >= 1024 ** 3:
            svc["mem_limit"] = f"{mem // 1024**3}g"
        elif mem >= 1024 ** 2:
            svc["mem_limit"] = f"{mem // 1024**2}m"
        else:
            svc["mem_limit"] = f"{mem // 1024}k"

    nano = hcfg.get("NanoCpus") or 0
    if nano:
        svc["cpus"] = round(nano / 1e9, 4)

    # sysctls
    sysctls = hcfg.get("Sysctls") or {}
    if sysctls:
        svc["sysctls"] = sysctls

    # logging
    log_cfg = hcfg.get("LogConfig") or {}
    log_driver = log_cfg.get("Type") or ""
    if log_driver and log_driver not in ("json-file", ""):
        log_block: dict = {"driver": log_driver}
        log_opts = log_cfg.get("Config") or {}
        if log_opts:
            log_block["options"] = log_opts
        svc["logging"] = log_block

    # build compose document
    compose: dict = {"services": {name: svc}}

    if top_vols:
        compose["volumes"] = {v: None for v in top_vols}

    if custom_nets and "network_mode" not in svc:
        compose["networks"] = {n: {"external": True} for n in custom_nets}

    yaml_str = _yaml.dump(compose, default_flow_style=False, sort_keys=False, allow_unicode=True)
    return yaml_str, meta


@router.get("/docker/containers/{container_id}/compose")
async def get_container_compose(container_id: str, db: Session = Depends(get_db)):
    """Return a docker-compose.yml snippet generated from the container's live config."""
    if container_id.startswith("px-"):
        raise HTTPException(400, "Compose generation is not available for Proxmox containers.")
    if not _docker_enabled(db):
        raise HTTPException(503, "No container hosts configured.")

    hosts      = _get_enabled_hosts(db)
    docker_h   = [h for h in hosts if h["type"] != "proxmox"]
    if not docker_h:
        raise HTTPException(503, "No Docker hosts configured.")
    host_url   = docker_h[0]["url"] or "unix:///var/run/docker.sock"

    def _do():
        client = _make_docker_client(host_url)
        try:
            c = client.containers.get(container_id)
            return _generate_compose_yaml(c)
        finally:
            client.close()

    try:
        yaml_str, meta = await asyncio.to_thread(_do)
        return {"yaml": yaml_str, **meta}
    except HTTPException:
        raise
    except Exception as e:
        code = 404 if "404" in str(e) or "Not Found" in str(e) else 503
        raise HTTPException(code, str(e))


@router.get("/docker/containers/{container_id}/trivy-scan")
async def stream_docker_trivy_scan(container_id: str, db: Session = Depends(get_db)):
    """Stream a Trivy vulnerability scan of the container image as SSE."""
    if container_id.startswith("px-"):
        raise HTTPException(400, "Trivy image scanning is not available for Proxmox containers.")
    if not _docker_enabled(db):
        raise HTTPException(503, "No container hosts configured.")
    # Resolve the Docker host for this container
    hosts = _get_enabled_hosts(db)
    docker_hosts = [h for h in hosts if h["type"] != "proxmox"]
    host = docker_hosts[0]["url"] if docker_hosts else _get_docker_host(db)

    def _get_container_info():
        client = _make_docker_client(host)
        try:
            c = client.containers.get(container_id)
            image = (c.attrs.get("Config") or {}).get("Image", "")
            name  = c.name.lstrip("/")
            image_id = getattr(c.image, "id", None)
            return image, name, image_id
        finally:
            client.close()

    try:
        image, container_name, image_id = await asyncio.to_thread(_get_container_info)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, str(e))

    if not image:
        raise HTTPException(400, "Could not determine container image.")

    line_queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_event_loop()

    def _run():
        _container_vuln_scans[container_name] = {"scanning": True, "image": image}
        try:
            result = run_trivy_image_scan_sync(image)
            if not result.get("ok"):
                _container_vuln_scans[container_name]["error"] = result.get("error")
                loop.call_soon_threadsafe(line_queue.put_nowait, f"LOG: [ERROR] {result.get('error')}")
                return

            vulns = result.get("vulns") or []
            scanned_at = result["scanned_at"]
            _save_trivy_result(container_name, image, vulns, scanned_at, image_id=image_id)
            result_payload = json.dumps({
                "vulns": vulns,
                "image": image,
                "image_id": image_id,
                "scanned_at": scanned_at,
            })
            loop.call_soon_threadsafe(line_queue.put_nowait, f"TRIVY_RESULT:{result_payload}")
        except Exception as exc:
            loop.call_soon_threadsafe(line_queue.put_nowait, f"LOG: [ERROR] {exc}")
        finally:
            if container_name in _container_vuln_scans:
                _container_vuln_scans[container_name]["scanning"] = False
            loop.call_soon_threadsafe(line_queue.put_nowait, "TRIVY_DONE")
            loop.call_soon_threadsafe(line_queue.put_nowait, None)

    threading.Thread(target=_run, daemon=True).start()

    async def _gen():
        while True:
            try:
                line = await asyncio.wait_for(line_queue.get(), timeout=300)
            except asyncio.TimeoutError:
                yield "data: TRIVY_DONE\n\n"
                break
            if line is None:
                break
            yield f"data: {line}\n\n"

    return StreamingResponse(_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------------------
# Trivy DB status + force-update endpoints
# ---------------------------------------------------------------------------
@router.get("/trivy/db-status")
async def trivy_db_status_endpoint(_user: str = Depends(get_current_user)):
    status = _trivy_db_status()
    status["updating"] = _trivy_db_update_lock.locked()
    return status


@router.get("/trivy/db-update")
async def trivy_db_update_stream(_user: str = Depends(get_current_user)):
    """SSE stream that triggers a Trivy DB download and streams its output."""
    if not shutil.which("trivy"):
        async def _no_trivy():
            yield "data: [ERROR] Trivy binary not found in container.\n\n"
            yield "data: TRIVY_DB_DONE\n\n"
        return StreamingResponse(_no_trivy(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    async def _stream():
        if _trivy_db_update_lock.locked():
            yield "data: [INFO] Update already in progress — please wait.\n\n"
            yield "data: TRIVY_DB_DONE\n\n"
            return
        async with _trivy_db_update_lock:
            try:
                yield "data: [INFO] Starting Trivy vulnerability DB download…\n\n"
                proc = await asyncio.create_subprocess_exec(
                    "trivy", "image", "--download-db-only",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                if proc.stdout:
                    async for raw in proc.stdout:
                        line = raw.decode(errors="replace").rstrip()
                        if line:
                            yield f"data: {line}\n\n"
                await proc.wait()
                if proc.returncode == 0:
                    yield "data: [INFO] Trivy DB updated successfully.\n\n"
                else:
                    yield f"data: [ERROR] Update exited with code {proc.returncode}.\n\n"
            except Exception as exc:
                yield f"data: [ERROR] {exc}\n\n"
        yield "data: TRIVY_DB_DONE\n\n"

    return StreamingResponse(_stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------------------
# Nuclei template status + force-update endpoints (proxy to probe)
# ---------------------------------------------------------------------------
@router.get("/nuclei/template-status")
async def nuclei_template_status(_user: str = Depends(get_current_user)):
    try:
        async with _probe_client(timeout=10) as client:
            r = await client.get(f"{PROBE_URL}/nuclei/status")
            return r.json()
    except Exception:
        return {"exists": False, "version": None, "last_updated": None, "binary_available": False}


@router.get("/nuclei/template-update")
async def nuclei_template_update_stream(_user: str = Depends(get_current_user)):
    """SSE proxy: streams Nuclei template update output from the probe."""
    async def _proxy():
        try:
            async with _probe_client(timeout=None) as client:
                async with client.stream("GET", f"{PROBE_URL}/nuclei/update") as r:
                    async for line in r.aiter_lines():
                        if line:
                            yield f"{line}\n"
                        else:
                            yield "\n"
        except Exception as exc:
            yield f"data: [ERROR] Could not reach probe: {exc}\n\n"
            yield "data: NUCLEI_UPDATE_DONE\n\n"

    return StreamingResponse(_proxy(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/docker/containers/{container_id}/security-state")
async def docker_container_security_state(container_id: str, db: Session = Depends(get_db)):
    if container_id.startswith("px-"):
        parsed = _parse_proxmox_id(container_id)
        if not parsed:
            raise HTTPException(400, "Invalid Proxmox container identifier.")
        host_id, node, vmid = parsed
        host = _get_host_row(db, host_id)
        audit = await asyncio.to_thread(audit_proxmox_guest, host, node, vmid, "lxc", _proxmox_request)
        return {"image_scan": None, "audit": audit}

    if not _docker_enabled(db):
        raise HTTPException(503, "No container hosts configured.")

    host_url, host_meta, host_id = _cu._resolve_host(db, container_id)

    def _get_container_info():
        client = _make_docker_client(host_url)
        try:
            c = client.containers.get(container_id)
            return c.name.lstrip("/"), _cu._container_image_ref(c), getattr(c.image, "id", None)
        finally:
            client.close()

    try:
        container_name, current_image, current_image_id = await asyncio.to_thread(_get_container_info)
    except Exception as exc:
        raise HTTPException(404, str(exc))

    image_scan = _latest_current_image_scan(db, container_name, host_id, current_image, current_image_id)
    audit = await asyncio.to_thread(
        audit_docker_container,
        host_url,
        container_id,
        host_meta.get("name"),
    )
    return {"image_scan": image_scan, "audit": audit}


@router.get("/docker/auto-scan/{name}")
async def docker_auto_scan_result(name: str, db: Session = Depends(get_db)):
    """Return the stored Trivy scan result for a container name."""
    # If a scan is actively running, report that
    mem = _container_vuln_scans.get(name)
    if mem and mem.get("scanning"):
        return {"scanning": True, "vulns": [], "image": mem.get("image", ""), "scanned_at": None}
    # Read persisted result from DB
    row = db.execute(
        text("SELECT image, image_id, vulns, scanned_at FROM container_vuln_results WHERE name = :name"),
        {"name": name},
    ).fetchone()
    if row is None:
        raise HTTPException(404, "No scan data for this container.")
    vulns = row.vulns if isinstance(row.vulns, list) else json.loads(row.vulns or "[]")
    return {
        "scanning": False,
        "image": row.image,
        "image_id": getattr(row, "image_id", None),
        "vulns": vulns,
        "scanned_at": row.scanned_at.isoformat() if row.scanned_at else None,
    }


@router.get("/docker/vuln-summary")
async def docker_vuln_summary(db: Session = Depends(get_db)):
    """Return aggregated Trivy scan results for all current Docker containers."""
    if not _docker_enabled(db):
        raise HTTPException(503, "Docker monitoring is disabled.")

    hosts = [h for h in _get_enabled_hosts(db) if h["type"] != "proxmox"]
    if not hosts:
        raise HTTPException(503, "No Docker hosts configured.")

    def _list_current():
        current = []
        for host in hosts:
            client = _make_docker_client(host["url"] or "unix:///var/run/docker.sock")
            try:
                for c in client.containers.list(all=True):
                    current.append({
                        "name": c.name.lstrip("/"),
                        "host_id": host["id"],
                        "image": _cu._container_image_ref(c),
                        "image_id": getattr(c.image, "id", None),
                    })
            finally:
                client.close()
        return current

    try:
        containers = await asyncio.to_thread(_list_current)
    except Exception as exc:
        raise HTTPException(503, str(exc))

    result = []
    for container in containers:
        current = _latest_current_image_scan(
            db,
            container["name"],
            container["host_id"],
            container["image"],
            container["image_id"],
        )
        vulns = current.get("vulns") or []
        scanned_at = current.get("scanned_at")
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in vulns:
            sev = v.get("severity", "").lower()
            if sev in counts:
                counts[sev] += 1
        if counts["critical"] > 0:        severity = "critical"
        elif counts["high"] > 0:          severity = "high"
        elif counts["medium"] > 0:        severity = "medium"
        elif counts["low"] > 0:           severity = "low"
        elif scanned_at:                  severity = "clean"
        else:                             severity = None
        result.append({
            "name":       container["name"],
            "image":      container["image"],
            "image_id":   container["image_id"],
            "scanning":   current.get("scanning", False),
            "severity":   severity,
            "counts":     counts,
            "vulns":      vulns,
            "scanned_at": scanned_at,
            "source":     current.get("source"),
            "stale":      current.get("stale"),
        })
    return result


@router.post("/docker/scan-all")
async def docker_scan_all(db: Session = Depends(get_db)):
    """Trigger Trivy scans on all running containers."""
    if not _docker_enabled(db):
        raise HTTPException(503, "Docker monitoring is disabled.")
    host = _get_docker_host(db)

    def _get_containers():
        client = _make_docker_client(host)
        try:
            return [
                (
                    c.name.lstrip("/"),
                    _cu._container_image_ref(c),
                    getattr(c.image, "id", None),
                )
                    for c in client.containers.list()]
        finally:
            client.close()

    try:
        containers = await asyncio.to_thread(_get_containers)
    except Exception as e:
        raise HTTPException(503, str(e))

    # Run scans sequentially in a single thread — parallel Trivy processes compete
    # for the shared vulnerability DB and fail silently, returning empty results.
    def _run_all():
        for name, image, image_id in containers:
            _run_trivy_for_container(name, image, image_id=image_id)

    threading.Thread(target=_run_all, daemon=True).start()

    return {"started": len(containers), "containers": [n for n, _, _ in containers]}


@router.get("/docker/timeline")
async def docker_timeline(days: int = Query(7, ge=1, le=365), db: Session = Depends(get_db)):
    """Return container uptime timeline data keyed by container NAME."""
    if not _docker_enabled(db):
        raise HTTPException(503, "Docker monitoring is disabled.")

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=days)

    rows = db.execute(
        text("SELECT name, status, ts FROM container_events WHERE ts >= :start ORDER BY name, ts"),
        {"start": window_start},
    ).fetchall()

    # Also get current state from Docker daemon
    host = _get_docker_host(db)
    current_states: dict = {}
    try:
        def _get_states():
            client = _make_docker_client(host)
            try:
                return {c.name.lstrip("/"): c.status for c in client.containers.list(all=True)}
            finally:
                client.close()
        current_states = await asyncio.to_thread(_get_states)
    except Exception:
        pass

    # Group events by name
    events_by_name: dict = defaultdict(list)
    for name, status, ts in rows:
        events_by_name[name].append({"status": status, "ts": ts})

    # Build segments from events
    containers_out = []
    all_names = set(events_by_name.keys()) | set(current_states.keys())

    for name in sorted(all_names):
        evts = sorted(events_by_name.get(name, []), key=lambda e: e["ts"])
        segs = []

        # If we have events, build segments
        if evts:
            # Segment before first event
            first_ts = evts[0]["ts"]
            if first_ts > window_start:
                segs.append({"from": window_start.isoformat(), "to": first_ts.isoformat(), "status": "unknown"})

            for i, ev in enumerate(evts):
                seg_start = ev["ts"]
                seg_end   = evts[i + 1]["ts"] if i + 1 < len(evts) else now
                seg_status = "running" if ev["status"] == "running" else "stopped"
                segs.append({"from": seg_start.isoformat(), "to": seg_end.isoformat(), "status": seg_status})
        else:
            # No history — use current state for whole window
            cur = current_states.get(name, "unknown")
            seg_status = "running" if cur == "running" else "stopped" if cur in ("exited","created","dead","paused") else "unknown"
            segs.append({"from": window_start.isoformat(), "to": now.isoformat(), "status": seg_status})

        cur_status = current_states.get(name, "unknown")
        containers_out.append({
            "name":       name,
            "is_running": cur_status == "running",
            "segments":   segs,
        })

    return {
        "window_start": window_start.isoformat(),
        "window_end":   now.isoformat(),
        "containers":   containers_out,
    }
