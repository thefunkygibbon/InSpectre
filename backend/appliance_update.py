"""Native appliance auto-updater (Watchtower replacement).

This module pulls the latest images for the InSpectre appliance containers and
recreates any whose image changed, preserving their full runtime configuration
(network attachments + aliases, port bindings, bind/volume mounts, privileged
flag, capabilities, restart policy, env, labels, command, devices, extra hosts).

It is used in two ways:

* In-process, by the backend's scheduled auto-update loop, to update the
  non-self containers (db / frontend / probe) — safe because recreating those
  does not kill the backend process.

* As a standalone entrypoint inside a short-lived helper container
  (``inspectre-updater``) to recreate the backend's OWN container
  (``inspectre-web``). Doing the self-recreate from a separate container avoids
  the process killing itself half-way through the swap.

Auto-update is only meaningful for "online" appliance builds whose images come
from a registry (``thefunkygibbon/inspectre-*``). Offline builds use local-only
tags (``inspectre-*:amd64``) that cannot be pulled, so updates are simply
skipped for them.
"""

from __future__ import annotations

import json
import os
import time
import traceback
from datetime import datetime, timezone

WEB_CONTAINER     = "inspectre-web"
UPDATER_CONTAINER = "inspectre-updater"

# Order matters: dependencies first, the backend (self) is handled separately.
NON_SELF_CONTAINERS = ["inspectre-db", "inspectre-frontend", "inspectre-probe"]
MANAGED_CONTAINERS  = NON_SELF_CONTAINERS + [WEB_CONTAINER]

DOCKER_SOCK = "unix:///var/run/docker.sock"


# ---------------------------------------------------------------------------
# Docker helpers
# ---------------------------------------------------------------------------
def make_client():
    import docker
    return docker.DockerClient(base_url=DOCKER_SOCK)


def _container(client, name):
    try:
        return client.containers.get(name)
    except Exception:
        return None


def _image_ref(container) -> str:
    tags = container.image.tags
    if tags:
        return tags[0]
    return (container.attrs.get("Config", {}) or {}).get("Image") or container.image.id


def _parse_extra_hosts(extra_hosts):
    """Docker stores ExtraHosts as ['host:ip', ...]; the SDK wants {host: ip}."""
    out = {}
    for item in (extra_hosts or []):
        if ":" in item:
            host, ip = item.rsplit(":", 1)
            out[host] = ip
    return out or None


def _endpoint_aliases(netinfo):
    return [a for a in (netinfo.get("Aliases") or []) if a]


# ---------------------------------------------------------------------------
# Faithful recreate
# ---------------------------------------------------------------------------
def recreate(client, name, image_ref=None) -> dict:
    """Recreate container ``name`` from ``image_ref`` (or its current image tag),
    preserving its runtime configuration. Uses a rename-to-backup + rollback
    strategy so a failure never leaves the user with no container."""
    api = client.api
    c = client.containers.get(name)
    attrs   = c.attrs or {}
    config  = attrs.get("Config", {}) or {}
    hostcfg = attrs.get("HostConfig", {}) or {}
    networks = (attrs.get("NetworkSettings", {}) or {}).get("Networks", {}) or {}

    image_ref   = image_ref or _image_ref(c)
    old_image   = c.image.id

    netmode = hostcfg.get("NetworkMode") or "bridge"
    is_special_net = netmode in ("host", "none") or netmode.startswith("container:")

    # Port bindings (skip for host/none networking).
    port_bindings = None
    if not is_special_net:
        pb = hostcfg.get("PortBindings") or {}
        if pb:
            port_bindings = {}
            for cport, binds in pb.items():
                if binds:
                    hostport = binds[0].get("HostPort")
                    hostip   = binds[0].get("HostIp") or ""
                    if hostport:
                        port_bindings[cport] = (hostip, int(hostport)) if hostip else int(hostport)
                else:
                    port_bindings[cport] = None

    devices = []
    for d in (hostcfg.get("Devices") or []):
        devices.append(
            f"{d.get('PathOnHost')}:{d.get('PathInContainer')}:{d.get('CgroupPermissions', 'rwm')}"
        )

    restart = hostcfg.get("RestartPolicy") or {}
    restart_policy = None
    if restart.get("Name"):
        restart_policy = {
            "Name": restart.get("Name"),
            "MaximumRetryCount": restart.get("MaximumRetryCount", 0),
        }

    host_config = api.create_host_config(
        binds=hostcfg.get("Binds") or None,
        port_bindings=port_bindings,
        privileged=bool(hostcfg.get("Privileged")),
        cap_add=hostcfg.get("CapAdd") or None,
        cap_drop=hostcfg.get("CapDrop") or None,
        extra_hosts=_parse_extra_hosts(hostcfg.get("ExtraHosts")),
        restart_policy=restart_policy,
        network_mode=netmode,
        devices=devices or None,
    )

    # Preserve network attachment + aliases for user-defined networks.
    networking_config = None
    ordered_nets = list(networks.items())
    if not is_special_net and ordered_nets:
        first_name, first_info = ordered_nets[0]
        networking_config = api.create_networking_config(
            {first_name: api.create_endpoint_config(aliases=_endpoint_aliases(first_info))}
        )

    exposed = list((config.get("ExposedPorts") or {}).keys()) or None

    backup = f"{name}_inspectre_bak_{int(time.time())}"
    was_running = c.status not in ("exited", "created", "dead")
    if was_running:
        try:
            c.stop(timeout=10)
        except Exception:
            pass
    c.rename(backup)

    new_id = None
    try:
        created = api.create_container(
            image=image_ref,
            name=name,
            command=config.get("Cmd"),
            entrypoint=config.get("Entrypoint"),
            environment=config.get("Env"),
            labels=config.get("Labels"),
            hostname=None if is_special_net else config.get("Hostname"),
            working_dir=config.get("WorkingDir") or None,
            ports=exposed,
            host_config=host_config,
            networking_config=networking_config,
        )
        new_id = created.get("Id")

        # Attach any additional networks (with their aliases).
        if not is_special_net and len(ordered_nets) > 1:
            for net_name, info in ordered_nets[1:]:
                try:
                    api.connect_container_to_network(
                        new_id, net_name, aliases=_endpoint_aliases(info)
                    )
                except Exception:
                    pass

        api.start(new_id)
    except Exception:
        # Roll back: discard the half-created container and restore the original.
        try:
            if new_id:
                api.remove_container(new_id, force=True)
        except Exception:
            pass
        try:
            old = client.containers.get(backup)
            old.rename(name)
            if was_running:
                old.start()
        except Exception:
            pass
        raise

    # Success — remove the backup (non-fatal if it lingers).
    try:
        client.containers.get(backup).remove(force=True)
    except Exception:
        pass

    new_image = None
    try:
        new_image = client.containers.get(name).image.id
    except Exception:
        pass

    return {
        "name": name,
        "old_image": (old_image or "")[:19],
        "new_image": (new_image or "")[:19],
        "changed": old_image != new_image,
    }


def _pull(client, ref):
    """Pull ``ref`` and return the resulting image id, or None on failure."""
    try:
        img = client.images.pull(ref)
        if isinstance(img, list):
            img = img[0] if img else None
        return img.id if img else None
    except Exception:
        return None


def update_container(client, name) -> dict:
    """Pull ``name``'s image and recreate it only if the image actually changed."""
    c = _container(client, name)
    if c is None:
        return {"name": name, "changed": False, "skipped": True, "reason": "not present"}

    ref = _image_ref(c)
    old_id = c.image.id
    new_id = _pull(client, ref)
    if new_id is None:
        # Local-only tag or registry unreachable — nothing to do.
        return {"name": name, "changed": False, "skipped": True,
                "reason": "image not pullable", "image": ref}
    if new_id == old_id:
        return {"name": name, "changed": False, "skipped": False, "image": ref}

    res = recreate(client, name, ref)
    res["image"] = ref
    return res


def update_available(client, name) -> bool:
    """Return True if pulling ``name``'s image yields a different image id."""
    c = _container(client, name)
    if c is None:
        return False
    old_id = c.image.id
    new_id = _pull(client, _image_ref(c))
    return bool(new_id and new_id != old_id)


# ---------------------------------------------------------------------------
# Status persistence (used by both in-process and helper code paths)
# ---------------------------------------------------------------------------
def write_status(status: str, detail) -> None:
    """Best-effort upsert of the auto-update result into the settings table.

    Uses psycopg2 directly (with a short reconnect retry) so it works even from
    the standalone helper container right after the database container was
    itself recreated."""
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        return
    now_iso = datetime.now(timezone.utc).isoformat()
    rows = [
        ("auto_update_last_run", now_iso),
        ("auto_update_last_status", str(status)),
        ("auto_update_last_detail",
         detail if isinstance(detail, str) else json.dumps(detail)[:4000]),
    ]
    last_err = None
    for attempt in range(6):
        try:
            import psycopg2
            conn = psycopg2.connect(db_url, connect_timeout=5)
            try:
                conn.autocommit = True
                with conn.cursor() as cur:
                    for key, value in rows:
                        cur.execute(
                            "INSERT INTO settings (key, value) VALUES (%s, %s) "
                            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                            (key, value),
                        )
                return
            finally:
                conn.close()
        except Exception as exc:  # db may be briefly down after recreate
            last_err = exc
            time.sleep(5)
    print(f"[updater] failed to write status: {last_err}", flush=True)


# ---------------------------------------------------------------------------
# Standalone helper entrypoint (runs inside the inspectre-updater container)
# ---------------------------------------------------------------------------
def run_self_recreate() -> None:
    """Recreate the backend's own container (inspectre-web). Invoked inside the
    short-lived helper container so the swap doesn't kill the running backend."""
    print("[updater] helper: recreating inspectre-web", flush=True)
    try:
        client = make_client()
        res = update_container(client, WEB_CONTAINER)
        print(f"[updater] helper result: {res}", flush=True)
        write_status("ok" if res.get("changed") else "no-change", {WEB_CONTAINER: res})
    except Exception as exc:
        print(f"[updater] helper FAILED: {exc}\n{traceback.format_exc()}", flush=True)
        write_status("error", {"error": str(exc), "container": WEB_CONTAINER})


if __name__ == "__main__":
    # Allows: python -m appliance_update  (used by the helper container command).
    run_self_recreate()
