import asyncio
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import text

import probe_config as _cfg
import traffic_monitor as _tm
from probe_models import Session, Device
from probe_config import VERSION, apply_runtime_config
from probe_hostname import resolve_hostname, _get_default_gateway
from probe_mdns import _mdns_browse, _apply_mdns_enrichment
from probe_ssdp import _ssdp_browse, _apply_ssdp_enrichment
from probe_blocking import (
    _blocked_devices, _blocked_lock,
    _get_mac_for_ip, _arp_spoof_loop,
)
from probe_scanner import trigger_deep_scan, _scan_lock, _scanning
from probe_fingerprint import (
    _nuclei_templates_exist, _nuclei_update_lock,
    _last_nuclei_template_update,
)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
_PROBE_ALLOWED_ORIGINS = [
    o.strip() for o in os.environ.get("PROBE_ALLOWED_ORIGINS", "*").split(",") if o.strip()
] or ["*"]

probe_api = FastAPI(
    title="InSpectre Probe Internal API",
    version=VERSION,
    docs_url=None,
    redoc_url=None,
)
probe_api.add_middleware(
    CORSMiddleware,
    allow_origins=_PROBE_ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

PROBE_API_SECRET  = os.environ.get("PROBE_API_SECRET", "").strip()
_PROBE_PUBLIC_PATHS = {"/health"}


@probe_api.middleware("http")
async def _probe_auth_middleware(request, call_next):
    if PROBE_API_SECRET and request.url.path not in _PROBE_PUBLIC_PATHS:
        if request.headers.get("X-Probe-Secret") != PROBE_API_SECRET:
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
    return await call_next(request)


# ---------------------------------------------------------------------------
# SSE / streaming helpers
# ---------------------------------------------------------------------------
def _sse_line(data: str) -> str:
    safe = data.replace("\n", " ").replace("\r", "")
    return f"data: {safe}\n\n"


def _stream_subprocess(cmd: list[str]):
    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                yield _sse_line(line)
        proc.wait()
        yield _sse_line(f"--- exit code {proc.returncode} ---")
        yield "event: done\ndata: {}\n\n"
    except FileNotFoundError as e:
        yield _sse_line(f"ERROR: command not found -- {e}")
        yield "event: done\ndata: {}\n\n"
    except Exception as e:
        yield _sse_line(f"ERROR: {e}")
        yield "event: done\ndata: {}\n\n"
    finally:
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except Exception:
                    proc.kill()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@probe_api.get("/health")
def probe_health():
    with _scan_lock:
        active_port_scans = list(_scanning)
        scanning_count    = len(active_port_scans)
    return {
        "ok": True,
        "status": "ok",
        "message": f"Probe running — scanning {_cfg.IP_RANGE}, {scanning_count} active port scan(s)",
        "active_port_scans": active_port_scans,
        "version": VERSION,
        "dns_server": _cfg._DNS_SERVER,
        "config": {
            "scan_interval":        _cfg.SCAN_INTERVAL,
            "ip_range":             _cfg.IP_RANGE,
            "port_scan_workers":    _cfg.PORT_SCAN_WORKERS,
            "gateway_scan_workers": _cfg.GATEWAY_SCAN_WORKERS,
            "os_confidence_threshold": _cfg.OS_CONFIDENCE_THRESHOLD,
            "offline_miss_threshold":  _cfg.OFFLINE_MISS_THRESHOLD,
            "sniffer_workers":         _cfg.SNIFFER_WORKERS,
        },
    }


class ConfigReloadRequest(BaseModel):
    scan_interval: int | None = None
    ip_range: str | None = None
    os_confidence_threshold: int | None = None
    offline_miss_threshold: int | None = None
    sniffer_workers: int | None = None
    nuclei_template_update_interval: str | None = None


@probe_api.post("/config/reload")
def probe_config_reload(payload: ConfigReloadRequest):
    return apply_runtime_config(payload.model_dump(exclude_none=True))


@probe_api.get("/resolve/{ip}")
def probe_resolve(ip: str):
    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "Invalid IP address")
    name = resolve_hostname(ip)
    return {"ip": ip, "hostname": name}


@probe_api.post("/rescan/{mac}")
def probe_rescan(mac: str):
    session = Session()
    try:
        device = session.get(Device, mac.lower())
        if not device:
            raise HTTPException(404, "Device not found")
        scan_ip = device.primary_ip or device.ip_address
        if not scan_ip:
            raise HTTPException(422, "Device has no IP address")
        device.deep_scanned = False
        device.scan_results = None
        session.commit()
        trigger_deep_scan(scan_ip, device.mac_address)
        return {"queued": True, "mac": mac, "ip": scan_ip}
    finally:
        session.close()


@probe_api.get("/stream/ping/{ip}")
def stream_ping(ip: str):
    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "Invalid IP address")
    cmd = ["ping", "-c", str(_cfg.PING_COUNT), "-W", "2", ip]
    return StreamingResponse(
        _stream_subprocess(cmd),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@probe_api.get("/stream/traceroute/{ip}")
def stream_traceroute(ip: str):
    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "Invalid IP address")
    cmd = ["traceroute", "-m", str(_cfg.TRACE_MAX_HOP), "-w", "2", ip]
    return StreamingResponse(
        _stream_subprocess(cmd),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@probe_api.get("/stream/tools/ping")
def stream_tools_ping(host: str = Query(...)):
    if not re.match(r'^[a-zA-Z0-9._\-]{1,253}$', host):
        raise HTTPException(400, "Invalid host")
    cmd = ["ping", "-c", str(_cfg.PING_COUNT), "-W", "2", host]
    return StreamingResponse(
        _stream_subprocess(cmd),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@probe_api.get("/stream/tools/traceroute")
def stream_tools_traceroute(host: str = Query(...)):
    if not re.match(r'^[a-zA-Z0-9._\-]{1,253}$', host):
        raise HTTPException(400, "Invalid host")
    cmd = ["traceroute", "-m", str(_cfg.TRACE_MAX_HOP), "-w", "2", host]
    return StreamingResponse(
        _stream_subprocess(cmd),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@probe_api.get("/stream/tools/portscan")
def stream_tools_portscan(host: str = Query(...), ports: str = Query("1-1024")):
    if not re.match(r'^[a-zA-Z0-9._\-]{1,253}$', host):
        raise HTTPException(400, "Invalid host")
    if not re.match(r'^[\d,\-]{1,100}$', ports):
        raise HTTPException(400, "Invalid ports specification")

    def _expand_ports(spec: str) -> list[int]:
        out: list[int] = []
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                a, b = part.split("-", 1)
                out.extend(range(max(1, int(a)), min(65535, int(b)) + 1))
            else:
                pnum = int(part)
                if 1 <= pnum <= 65535:
                    out.append(pnum)
        return sorted(set(out))

    def _tcp_portscan_stream():
        import concurrent.futures as _cf
        import socket as _socket
        try:
            port_list = _expand_ports(ports)
        except Exception:
            yield _sse_line("ERROR: invalid port specification")
            return
        try:
            target_ip = _socket.gethostbyname(host)
        except Exception:
            yield _sse_line(f"ERROR: could not resolve {host!r}")
            return
        yield _sse_line(f"Scanning {host} ({target_ip}) — {len(port_list)} port(s) …")
        open_count = 0

        def _check(port):
            try:
                with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
                    s.settimeout(1.0)
                    return port if s.connect_ex((target_ip, port)) == 0 else None
            except Exception:
                return None

        with _cf.ThreadPoolExecutor(max_workers=200) as ex:
            futs = {ex.submit(_check, p): p for p in port_list}
            for fut in _cf.as_completed(futs):
                try:
                    r = fut.result()
                    if r is not None:
                        open_count += 1
                        yield _sse_line(f"  OPEN  {target_ip}:{r}/tcp")
                except Exception:
                    pass
        yield _sse_line(f"Done — {open_count} open port(s) found.")

    return StreamingResponse(
        _tcp_portscan_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@probe_api.get("/stream/tools/speedtest")
async def stream_speedtest(server_id: str = "", single: bool = False):
    async def _gen():
        result: dict = {}
        cmd = ["speedtest", "--format=jsonl", "--accept-license", "--accept-gdpr"]
        if server_id:
            cmd += [f"--server-id={server_id}"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            assert proc.stdout
            yield 'data: {"type":"testStart"}\n\n'
            async for raw in proc.stdout:
                line = raw.decode(errors="replace").rstrip()
                if not line:
                    continue
                try:
                    evt   = json.loads(line)
                    etype = evt.get("type", "")
                    if etype == "testStart":
                        srv = evt.get("server", {})
                        result["server"] = f"{srv.get('name', '')}, {srv.get('location', '')}"
                    elif etype == "ping":
                        ping_ms = round(evt.get("ping", {}).get("latency", 0), 2)
                        result["ping_ms"] = ping_ms
                        srv = evt.get("server", {})
                        if srv:
                            result["server"] = f"{srv.get('name', '')}, {srv.get('location', '')}"
                        yield f'data: {json.dumps({"type":"ping","ping":{"latency":ping_ms}})}\n\n'
                    elif etype == "download":
                        bw       = evt.get("download", {}).get("bandwidth", 0)
                        progress = evt.get("download", {}).get("progress", 0)
                        yield f'data: {json.dumps({"type":"download","download":{"bandwidth":bw,"progress":progress}})}\n\n'
                    elif etype == "upload":
                        bw       = evt.get("upload", {}).get("bandwidth", 0)
                        progress = evt.get("upload", {}).get("progress", 0)
                        yield f'data: {json.dumps({"type":"upload","upload":{"bandwidth":bw,"progress":progress}})}\n\n'
                    elif etype == "result":
                        dl_bw = evt.get("download", {}).get("bandwidth", 0)
                        ul_bw = evt.get("upload", {}).get("bandwidth", 0)
                        result["download_mbps"] = round(dl_bw * 8 / 1_000_000, 2)
                        result["upload_mbps"]   = round(ul_bw * 8 / 1_000_000, 2)
                        result["ping_ms"]       = round(evt.get("ping", {}).get("latency", result.get("ping_ms", 0)), 2)
                        srv = evt.get("server", {})
                        if srv:
                            result["server"] = f"{srv.get('name', '')}, {srv.get('location', '')}"
                        if evt.get("result", {}).get("url"):
                            result["result_url"] = evt["result"]["url"]
                        yield f'data: {json.dumps({"type":"download","download":{"bandwidth":dl_bw,"progress":1.0}})}\n\n'
                        yield f'data: {json.dumps({"type":"upload","upload":{"bandwidth":ul_bw,"progress":1.0}})}\n\n'
                except (json.JSONDecodeError, KeyError, TypeError):
                    pass
            await proc.wait()
            if result.get("download_mbps") is not None:
                yield f"data: RESULT:{json.dumps(result)}\n\n"
            else:
                stderr_out = b""
                if proc.stderr:
                    stderr_out = await proc.stderr.read()
                err_msg = stderr_out.decode(errors="replace").strip()
                yield f"data: ERROR: Speed test produced no measurements — {err_msg or 'check probe network connectivity'}\n\n"
        except FileNotFoundError:
            yield "data: ERROR: Ookla speedtest CLI not found — rebuild probe container\n\n"
        except Exception as exc:
            yield f"data: ERROR: {exc}\n\n"

    return StreamingResponse(
        _gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@probe_api.get("/tools/speedtest-servers")
async def get_speedtest_servers():
    try:
        proc = await asyncio.create_subprocess_exec(
            "speedtest", "--servers", "--format=json", "--accept-license", "--accept-gdpr",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=30.0)
        except asyncio.TimeoutError:
            proc.kill()
            return {"servers": [], "error": "Server list request timed out"}

        text_out = out.decode(errors="replace").strip()
        print(f"[speedtest-servers] exit={proc.returncode} output={repr(text_out[:400])}", flush=True)

        try:
            data = json.loads(text_out)
            raw  = data.get("servers", [])
            servers = [
                {"id": str(s["id"]), "label": f"{s['name']} ({s.get('location','')}, {s.get('country','')})"[:90]}
                for s in raw if "id" in s and "name" in s
            ]
            return {"servers": servers[:50]}
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            return {"servers": [], "error": f"Failed to parse server list: {e}"}
    except FileNotFoundError:
        return {"servers": [], "error": "Ookla speedtest CLI not found — rebuild probe container"}
    except Exception as exc:
        return {"servers": [], "error": str(exc)}


@probe_api.get("/tools/arp-table")
def get_arp_table():
    try:
        out = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, timeout=5)
        entries = []
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[1] == "dev":
                ip    = parts[0]
                mac   = parts[4] if len(parts) > 4 else None
                state = parts[-1] if len(parts) > 5 else "unknown"
                if mac and mac != "FAILED" and ":" in mac:
                    entries.append({"ip": ip, "mac": mac.upper(), "state": state})
        return {"entries": entries}
    except Exception as exc:
        return {"entries": [], "error": str(exc)}


@probe_api.post("/tools/wake-on-lan")
async def wake_on_lan(body: dict):
    import ipaddress as _ipa
    mac = body.get("mac", "").strip()
    broadcast = (body.get("broadcast") or "255.255.255.255").strip()
    if not mac:
        raise HTTPException(400, "mac required")
    try:
        _ipa.IPv4Address(broadcast)
    except Exception:
        raise HTTPException(400, "Invalid broadcast address")

    mac_clean = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(mac_clean) != 12:
        raise HTTPException(400, "Invalid MAC address")
    magic = bytes.fromhex("FF" * 6 + mac_clean * 16)

    targets = [broadcast]
    try:
        net = _ipa.ip_network(_cfg.IP_RANGE, strict=False)
        sub_bcast = str(net.broadcast_address)
        if sub_bcast not in targets:
            targets.append(sub_bcast)
    except Exception:
        pass

    from probe_sniffer import _PROBE_OWN_MAC
    _SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)
    sent, errors = [], []
    for tgt in targets:
        for port in (9, 7):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    try:
                        s.setsockopt(socket.SOL_SOCKET, _SO_BINDTODEVICE, _cfg.INTERFACE.encode())
                    except Exception:
                        pass
                    s.sendto(magic, (tgt, port))
                sent.append(f"{tgt}:{port}")
            except Exception as exc:
                errors.append(f"{tgt}:{port} -> {exc}")

    l2_sent, l2_errors = [], []
    src_mac = None
    try:
        from scapy.all import Ether, Raw, sendp, get_if_hwaddr
        target_mac = ":".join(mac_clean[i:i+2] for i in range(0, 12, 2))
        src_mac = _PROBE_OWN_MAC or _cfg._get_own_mac(_cfg.INTERFACE)
        if not src_mac or src_mac == "00:00:00:00:00:00":
            try:
                src_mac = get_if_hwaddr(_cfg.INTERFACE)
            except Exception:
                src_mac = None
        for dst in (target_mac, "ff:ff:ff:ff:ff:ff"):
            try:
                eth = Ether(dst=dst, type=0x0842)
                if src_mac:
                    eth.src = src_mac
                frame = eth / Raw(load=magic)
                sendp(frame, iface=_cfg.INTERFACE, count=5, inter=0.12, verbose=0)
                l2_sent.append(f"L2:{dst}")
            except Exception as exc:
                l2_errors.append(f"L2:{dst} -> {exc}")
    except Exception as exc:
        l2_errors.append(f"scapy unavailable: {exc}")

    sent.extend(l2_sent)
    errors.extend(l2_errors)

    print(f"[wol] mac={mac} iface={_cfg.INTERFACE} src_mac={src_mac} ip_range={_cfg.IP_RANGE} "
          f"sent={sent} errors={errors}", flush=True)

    if not sent:
        raise HTTPException(500, "; ".join(errors) or "Failed to send magic packet")
    return {"ok": True, "mac": mac, "sent_to": sent}


@probe_api.get("/stream/vuln-scan/{ip}")
async def stream_vuln_scan(ip: str, templates: str = "", mac: str = ""):
    import ipaddress
    from vuln_scanner import run_vuln_scan, DEFAULT_TEMPLATES

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "Invalid IP address")

    effective_templates = templates.strip() if templates.strip() else DEFAULT_TEMPLATES

    known_ports:    list[int]        = []
    port_services:  dict[int, dict]  = {}
    pipeline_stage: str              = ""
    try:
        session = Session()
        if mac:
            device = session.get(Device, mac.lower())
        else:
            device = session.query(Device).filter(Device.primary_ip == ip).first()
            if not device:
                device = session.query(Device).filter(Device.ip_address == ip).first()
            if not device:
                row = session.execute(
                    text("SELECT mac_address FROM ip_history WHERE ip_address = :ip ORDER BY last_seen DESC LIMIT 1"),
                    {"ip": ip}
                ).fetchone()
                if row:
                    device = session.get(Device, row[0])
        if device and device.scan_results:
            for p in (device.scan_results.get("open_ports") or []):
                if isinstance(p.get("port"), int):
                    port = p["port"]
                    known_ports.append(port)
                    port_services[port] = {
                        "service": p.get("service", ""),
                        "product": p.get("product", ""),
                        "version": p.get("version", ""),
                        "cpe":     p.get("cpe", ""),
                    }
            for svc in (device.scan_results.get("services") or []):
                port = svc.get("port")
                if isinstance(port, int) and port in port_services:
                    if not port_services[port].get("service"):
                        port_services[port]["service"] = svc.get("service", "")
            pipeline_stage = device.scan_results.get("pipeline_stage", "")
        print(
            f"[vuln-scan] {ip} (mac={mac or 'unknown'}): "
            f"{len(known_ports)} port(s), pipeline_stage={pipeline_stage!r}",
            flush=True,
        )
        session.close()
    except Exception as e:
        print(f"[vuln-scan] scan_results lookup error for {ip}: {e}", flush=True)

    async def _gen():
        yield "data: [INFO] Initiating vulnerability scan…\n\n"
        if pipeline_stage == "ports_done":
            yield "data: [WARN] Service fingerprinting not yet complete — template selection may be less precise\n\n"
        elif not pipeline_stage:
            yield "data: [WARN] No prior port scan — will run full TCP sweep first\n\n"
        async for line in run_vuln_scan(
            ip,
            templates=effective_templates,
            known_ports=known_ports,
            port_services=port_services,
        ):
            safe = line.replace("\n", " ").replace("\r", "")
            yield f"data: {safe}\n\n"
        yield "data: --- done ---\n\n"
        yield "event: done\ndata: {}\n\n"

    return StreamingResponse(
        _gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@probe_api.post("/mdns/refresh")
def probe_mdns_refresh():
    mdns_data = _mdns_browse()
    if mdns_data:
        _apply_mdns_enrichment(mdns_data)
    return {"discovered": len(mdns_data), "ips": list(mdns_data.keys())}


@probe_api.post("/ssdp/refresh")
def probe_ssdp_refresh():
    ssdp_data = _ssdp_browse()
    if ssdp_data:
        _apply_ssdp_enrichment(ssdp_data)
    total = sum(len(v) for v in ssdp_data.values())
    return {"discovered": len(ssdp_data), "services": total, "ips": list(ssdp_data.keys())}


@probe_api.post("/block/{mac}")
def probe_block_device(mac: str):
    mac = mac.lower()
    session = Session()
    try:
        device = session.get(Device, mac)
        if not device:
            raise HTTPException(404, "Device not found")
        target_ip = device.primary_ip or device.ip_address
        if not target_ip or not _cfg._is_valid_ip(target_ip):
            raise HTTPException(422, "Device has no valid IP address")
        target_mac = mac
    finally:
        session.close()

    with _blocked_lock:
        if mac in _blocked_devices:
            return {"ok": True, "already_blocked": True, "target_ip": target_ip}

    gateway_ip = _get_default_gateway()
    if not gateway_ip:
        raise HTTPException(500, "Could not detect default gateway")

    gateway_mac = _get_mac_for_ip(gateway_ip)
    if not gateway_mac:
        raise HTTPException(500, f"Could not resolve gateway MAC for {gateway_ip}")

    stop_event = threading.Event()
    t = threading.Thread(
        target=_arp_spoof_loop,
        args=(target_ip, target_mac, gateway_ip, gateway_mac, _cfg.INTERFACE, stop_event),
        daemon=True,
        name=f"arp-block-{mac}",
    )

    with _blocked_lock:
        _blocked_devices[mac] = {
            "target_ip":   target_ip,
            "target_mac":  target_mac,
            "gateway_ip":  gateway_ip,
            "gateway_mac": gateway_mac,
            "stop_event":  stop_event,
            "thread":      t,
        }

    t.start()
    return {"ok": True, "blocked": True, "target_ip": target_ip, "gateway_ip": gateway_ip}


@probe_api.delete("/block/{mac}")
def probe_unblock_device(mac: str):
    mac = mac.lower()
    with _blocked_lock:
        entry = _blocked_devices.pop(mac, None)
    if not entry:
        return {"ok": True, "was_blocked": False}
    entry["stop_event"].set()
    return {"ok": True, "was_blocked": True}


@probe_api.get("/blocked")
def probe_list_blocked():
    with _blocked_lock:
        return {
            "blocked": [
                {"mac": m, "target_ip": e["target_ip"], "gateway_ip": e["gateway_ip"]}
                for m, e in _blocked_devices.items()
            ]
        }


# ---------------------------------------------------------------------------
# Traffic monitoring
# ---------------------------------------------------------------------------
@probe_api.post("/traffic/start/{ip}")
def probe_traffic_start(ip: str):
    if not _cfg._is_valid_ip(ip):
        raise HTTPException(422, "Invalid IP address")

    with _blocked_lock:
        blocked_by_mac = next(
            (m for m, e in _blocked_devices.items() if e["target_ip"] == ip),
            None,
        )
    if blocked_by_mac:
        raise HTTPException(409, f"Device {ip} is currently blocked — unblock first")

    session_tm = _tm.get_session_by_ip(ip)
    if session_tm:
        return {"ok": True, "already_monitoring": True, "mac": session_tm.mac}

    session_db = Session()
    try:
        row = session_db.execute(
            text("SELECT mac_address FROM devices WHERE ip_address = :ip LIMIT 1"),
            {"ip": ip},
        ).fetchone()
        mac = row[0] if row else None
    finally:
        session_db.close()

    if not mac:
        mac = _get_mac_for_ip(ip)
    if not mac:
        raise HTTPException(404, f"Could not resolve MAC for {ip}")

    gateway_ip = _get_default_gateway()
    if not gateway_ip:
        raise HTTPException(500, "Could not detect default gateway")
    gateway_mac = _get_mac_for_ip(gateway_ip)
    if not gateway_mac:
        raise HTTPException(500, f"Could not resolve gateway MAC for {gateway_ip}")

    _tm.start_monitor(
        target_ip=ip,
        target_mac=mac,
        gateway_ip=gateway_ip,
        gateway_mac=gateway_mac,
        iface=_cfg.INTERFACE,
    )
    return {"ok": True, "mac": mac, "target_ip": ip, "gateway_ip": gateway_ip}


@probe_api.delete("/traffic/stop/{ip}")
def probe_traffic_stop(ip: str):
    stopped = _tm.stop_monitor_by_ip(ip)
    return {"ok": True, "was_monitoring": stopped}


@probe_api.get("/traffic/stats")
def probe_traffic_stats_all():
    return {"sessions": _tm.list_sessions_with_stats()}


@probe_api.get("/traffic/stats/{mac}")
def probe_traffic_stats(mac: str):
    session = _tm.get_session(mac)
    if not session:
        raise HTTPException(404, "No active monitor for this device")
    return session.get_stats()


@probe_api.get("/traffic/stream/{mac}")
def probe_traffic_stream(mac: str):
    session = _tm.get_session(mac)
    if not session:
        raise HTTPException(404, "No active monitor for this device")

    def _generate():
        while True:
            stats = session.get_stats()
            yield f"data: {json.dumps(stats)}\n\n"
            stop = session._stop_event.wait(timeout=3)
            if stop:
                break

    return StreamingResponse(_generate(), media_type="text/event-stream")


@probe_api.get("/network/info")
def probe_network_info():
    import ipaddress as _ipaddress
    info = {
        "interface":  _cfg.INTERFACE,
        "ip_range":   None,
        "gateway":    None,
        "dns_server": _cfg._DNS_SERVER,
    }
    try:
        out = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=3)
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "default" and parts[1] == "via":
                info["gateway"] = parts[2]
                if "dev" in parts:
                    info["interface"] = parts[parts.index("dev") + 1]
                break
    except Exception:
        pass
    try:
        if info["interface"]:
            out = subprocess.run(["ip", "addr", "show", info["interface"]], capture_output=True, text=True, timeout=3)
            for line in out.stdout.splitlines():
                line = line.strip()
                if line.startswith("inet ") and "/" in line:
                    cidr = line.split()[1]
                    info["ip_range"] = str(_ipaddress.ip_interface(cidr).network)
                    break
    except Exception:
        pass
    if not info["dns_server"] and info["gateway"]:
        info["dns_server"] = info["gateway"]
    return info


@probe_api.post("/restart")
def probe_restart():
    import signal as _signal
    def _do():
        time.sleep(0.5)
        os.kill(os.getpid(), _signal.SIGTERM)
    threading.Thread(target=_do, daemon=True).start()
    return {"ok": True, "restarting": True}


@probe_api.get("/nuclei/status")
def nuclei_status():
    templates_dir = "/root/nuclei-templates"
    exists  = _nuclei_templates_exist()
    version = None
    try:
        with open(os.path.join(templates_dir, ".version")) as f:
            version = f.read().strip()
    except Exception:
        pass
    return {
        "exists":           exists,
        "version":          version,
        "last_updated":     _last_nuclei_template_update.isoformat() if _last_nuclei_template_update else None,
        "binary_available": bool(shutil.which("nuclei")),
    }


@probe_api.get("/nuclei/update")
async def nuclei_update_stream():
    """SSE stream that triggers a Nuclei template update."""
    if not shutil.which("nuclei"):
        async def _no_bin():
            yield "data: [ERROR] Nuclei binary not found in container.\n\n"
            yield "data: NUCLEI_UPDATE_DONE\n\n"
        return StreamingResponse(_no_bin(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    async def _stream():
        import probe_fingerprint as _pf
        if _nuclei_update_lock.locked():
            yield "data: [INFO] Update already in progress — please wait.\n\n"
            yield "data: NUCLEI_UPDATE_DONE\n\n"
            return
        async with _nuclei_update_lock:
            try:
                yield "data: [INFO] Starting Nuclei template update…\n\n"
                proc = await asyncio.create_subprocess_exec(
                    "nuclei", "-update-templates",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                async for raw in proc.stdout:
                    line = raw.decode(errors="replace").rstrip()
                    if line:
                        yield f"data: {line}\n\n"
                await proc.wait()
                if proc.returncode == 0:
                    from datetime import datetime, timezone
                    _pf._last_nuclei_template_update = datetime.now(timezone.utc)
                    yield "data: [INFO] Templates updated successfully.\n\n"
                else:
                    yield f"data: [ERROR] nuclei exited with code {proc.returncode}\n\n"
            except Exception as exc:
                yield f"data: [ERROR] {exc}\n\n"
        yield "data: NUCLEI_UPDATE_DONE\n\n"

    return StreamingResponse(_stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def start_probe_api() -> None:
    print(f"[*] Probe API v{VERSION} listening on :{_cfg.PROBE_API_PORT}", flush=True)
    uvicorn.run(
        probe_api,
        host="0.0.0.0",
        port=_cfg.PROBE_API_PORT,
        log_level="warning",
        loop="none",
    )
