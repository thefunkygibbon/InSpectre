import asyncio
import os
import queue
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone

import nmap
import requests
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from scapy.all import ARP, Ether, sniff, srp
from sqlalchemy import (
    Boolean, Column, DateTime, Integer, JSON, String, UniqueConstraint,
    create_engine, text,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import declarative_base, sessionmaker

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DATABASE_URL            = os.environ.get("DATABASE_URL",            "postgresql://admin:password123@localhost:5432/inspectre")
SCAN_INTERVAL           = int(os.environ.get("SCAN_INTERVAL",           60))
IP_RANGE                = os.environ.get("IP_RANGE",                "192.168.0.0/24")
INTERFACE               = os.environ.get("INTERFACE",               "eth0")
NMAP_ARGS               = os.environ.get("NMAP_ARGS",               "-O --osscan-limit -sV --version-intensity 5 -T4")
OS_CONFIDENCE_THRESHOLD = int(os.environ.get("OS_CONFIDENCE_THRESHOLD", 85))
OFFLINE_MISS_THRESHOLD  = int(os.environ.get("OFFLINE_MISS_THRESHOLD",   3))
SNIFFER_WORKERS         = int(os.environ.get("SNIFFER_WORKERS",          4))
PROBE_API_PORT          = int(os.environ.get("PROBE_API_PORT",         8001))

PING_COUNT    = 10
TRACE_MAX_HOP = 30

# ---------------------------------------------------------------------------
# SQLAlchemy models
# ---------------------------------------------------------------------------
Base = declarative_base()

class Device(Base):
    __tablename__ = "devices"
    mac_address  = Column(String,  primary_key=True, index=True)
    ip_address   = Column(String)
    hostname     = Column(String,  nullable=True)
    vendor       = Column(String,  nullable=True)
    custom_name  = Column(String,  nullable=True)
    is_online    = Column(Boolean, default=True)
    first_seen   = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen    = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    scan_results = Column(JSON,    nullable=True)
    deep_scanned = Column(Boolean, default=False)
    miss_count   = Column(Integer, default=0)

class IPHistory(Base):
    __tablename__ = "ip_history"
    __table_args__ = (UniqueConstraint("mac_address", "ip_address", name="uq_ip_history_mac_ip"),)
    id          = Column(Integer, primary_key=True, autoincrement=True)
    mac_address = Column(String, nullable=False, index=True)
    ip_address  = Column(String, nullable=False)
    first_seen  = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen   = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

engine  = create_engine(DATABASE_URL, pool_pre_ping=True)
Session = sessionmaker(bind=engine)

_sniffer_queue: queue.Queue = queue.Queue()
_upsert_locks: dict[str, threading.Lock] = {}
_upsert_locks_lock = threading.Lock()

def _get_mac_lock(mac: str) -> threading.Lock:
    with _upsert_locks_lock:
        if mac not in _upsert_locks:
            _upsert_locks[mac] = threading.Lock()
        return _upsert_locks[mac]

_scan_lock = threading.Lock()
_scanning: set[str] = set()

# ---------------------------------------------------------------------------
# DB init
# ---------------------------------------------------------------------------
def wait_for_db(retries: int = 10, delay: int = 5) -> None:
    for attempt in range(retries):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            print("[DB] Connected.", flush=True)
            return
        except Exception as e:
            print(f"[DB] Not ready ({attempt+1}/{retries}): {e}", flush=True)
            time.sleep(delay)
    raise RuntimeError("Could not connect to database.")

def init_db() -> None:
    Base.metadata.create_all(engine)
    with engine.connect() as conn:
        try:
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS deep_scanned BOOLEAN DEFAULT FALSE"))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS miss_count INTEGER DEFAULT 0"))
            conn.commit()
        except Exception as e:
            print(f"[DB] Migration note: {e}", flush=True)
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS ip_history (
                id          SERIAL PRIMARY KEY,
                mac_address VARCHAR NOT NULL,
                ip_address  VARCHAR NOT NULL,
                first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                CONSTRAINT uq_ip_history_mac_ip UNIQUE (mac_address, ip_address)
            )
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_ip_history_mac ON ip_history (mac_address)"))
        conn.commit()
    print("[DB] Migrations complete.", flush=True)

# ---------------------------------------------------------------------------
# IP History
# ---------------------------------------------------------------------------
def record_ip(mac: str, ip: str) -> bool:
    now     = datetime.now(timezone.utc)
    session = Session()
    try:
        stmt = (
            pg_insert(IPHistory)
            .values(mac_address=mac, ip_address=ip, first_seen=now, last_seen=now)
            .on_conflict_do_update(
                constraint="uq_ip_history_mac_ip",
                set_={"last_seen": now},
            )
            .returning(IPHistory.first_seen, IPHistory.last_seen)
        )
        result = session.execute(stmt)
        row    = result.fetchone()
        session.commit()
        if row:
            delta = abs((row.last_seen - row.first_seen).total_seconds())
            return delta < 2
        return False
    except Exception as e:
        session.rollback()
        print(f"[ip_history] record error {mac}/{ip}: {e}", flush=True)
        return False
    finally:
        session.close()

# ---------------------------------------------------------------------------
# Hostname resolution
# ---------------------------------------------------------------------------
def _strip_fqdn(name: str) -> str:
    return name.rstrip('.') if name else ''

_DNS_SERVER: str | None = None
_DNS_DETECTED = False

def _detect_dns_server() -> str | None:
    """Read the first non-loopback nameserver from /etc/resolv.conf (usually the router)."""
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                parts = line.strip().split()
                if parts and parts[0] == "nameserver" and len(parts) >= 2:
                    ip = parts[1]
                    # Skip loopback / link-local
                    if not ip.startswith("127.") and not ip.startswith("169.254."):
                        print(f"[hostname] Using DNS server: {ip}", flush=True)
                        return ip
    except Exception:
        pass
    return None

def resolve_hostname(ip: str) -> str | None:
    global _DNS_SERVER, _DNS_DETECTED
    if not _DNS_DETECTED:
        _DNS_SERVER = _detect_dns_server()
        _DNS_DETECTED = True

    print(f"[hostname] Resolving {ip} (DNS server: {_DNS_SERVER})", flush=True)

    # ── Method 1: dig PTR against the local DNS/router ──
    # Most reliable for .lan / .home / router-assigned names
    if _DNS_SERVER:
        try:
            out = subprocess.run(
                ["dig", "+short", "+time=2", "+tries=1", f"@{_DNS_SERVER}", "-x", ip],
                capture_output=True, text=True, timeout=5,
            )
            print(f"[hostname] dig stdout: {out.stdout.strip()!r}  stderr: {out.stderr.strip()!r}", flush=True)
            for line in out.stdout.splitlines():
                candidate = _strip_fqdn(line.strip())
                if candidate and candidate != ip and not candidate.startswith(";"):
                    print(f"[hostname] dig resolved {ip} -> {candidate}", flush=True)
                    return candidate
        except Exception as e:
            print(f"[hostname] dig failed: {e}", flush=True)

    # ── Method 2: system gethostbyaddr ──
    try:
        result = socket.gethostbyaddr(ip)
        candidate = _strip_fqdn(result[0])
        if candidate and candidate != ip:
            print(f"[hostname] gethostbyaddr resolved {ip} -> {candidate}", flush=True)
            return candidate
    except Exception as e:
        print(f"[hostname] gethostbyaddr failed for {ip}: {e}", flush=True)

    # ── Method 3: host command against local DNS ──
    if _DNS_SERVER:
        try:
            out = subprocess.run(
                ["host", ip, _DNS_SERVER],
                capture_output=True, text=True, timeout=5,
            )
            print(f"[hostname] host stdout: {out.stdout.strip()!r}", flush=True)
            for line in out.stdout.splitlines():
                if "domain name pointer" in line:
                    parts = line.strip().split()
                    if parts:
                        candidate = _strip_fqdn(parts[-1])
                        if candidate and candidate != ip:
                            print(f"[hostname] host resolved {ip} -> {candidate}", flush=True)
                            return candidate
        except Exception as e:
            print(f"[hostname] host cmd failed: {e}", flush=True)

    # ── Method 4: nslookup ──
    try:
        cmd = ["nslookup", ip]
        if _DNS_SERVER:
            cmd.append(_DNS_SERVER)
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        print(f"[hostname] nslookup stdout: {out.stdout.strip()!r}", flush=True)
        for line in out.stdout.splitlines():
            line_l = line.lower()
            if "name =" in line_l or "name=" in line_l:
                parts = line.strip().split("=")
                if len(parts) >= 2:
                    candidate = _strip_fqdn(parts[-1].strip())
                    if candidate and candidate != ip:
                        print(f"[hostname] nslookup resolved {ip} -> {candidate}", flush=True)
                        return candidate
    except Exception as e:
        print(f"[hostname] nslookup failed: {e}", flush=True)

    # ── Method 5: avahi-resolve (mDNS .local names) ──
    try:
        out = subprocess.run(
            ["avahi-resolve", "-a", ip],
            capture_output=True, text=True, timeout=4,
        )
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                candidate = _strip_fqdn(parts[1])
                if candidate and candidate != ip:
                    print(f"[hostname] avahi resolved {ip} -> {candidate}", flush=True)
                    return candidate
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # ── Method 6: nmblookup (NetBIOS/Windows names) ──
    try:
        out = subprocess.run(
            ["nmblookup", "-A", ip],
            capture_output=True, text=True, timeout=4,
        )
        for line in out.stdout.splitlines():
            if "<00>" in line and "<GROUP>" not in line:
                parts = line.strip().split()
                if parts:
                    candidate = parts[0].strip()
                    if candidate and candidate not in ("WORKGROUP", ip, "Looking"):
                        print(f"[hostname] nmblookup resolved {ip} -> {candidate}", flush=True)
                        return candidate
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    print(f"[hostname] All methods failed for {ip}", flush=True)
    return None

# ---------------------------------------------------------------------------
# Vendor lookup
# ---------------------------------------------------------------------------
def lookup_vendor(mac: str) -> str:
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        if r.status_code == 200:
            return r.text.strip()
    except Exception:
        pass
    return "Unknown"

# ---------------------------------------------------------------------------
# ARP sweep
# ---------------------------------------------------------------------------
def arp_scan(interface: str, ip_range: str) -> list[dict]:
    pkt    = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    result = srp(pkt, iface=interface, timeout=3, verbose=0)[0]
    return [{"ip": rcv.psrc, "mac": rcv.hwsrc.lower()} for _, rcv in result]

# ---------------------------------------------------------------------------
# Nmap deep scan
# ---------------------------------------------------------------------------
def deep_scan(ip: str, mac: str) -> dict:
    print(f"[nmap] Starting deep scan: {ip} ({mac})", flush=True)
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip, arguments=NMAP_ARGS)
    except nmap.PortScannerError as e:
        return {"error": str(e), "scanned_at": datetime.now(timezone.utc).isoformat()}

    host_data: dict = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "os_matches": [],
        "open_ports": [],
        "hostnames":  [],
    }

    if ip not in nm.all_hosts():
        host_data["error"] = "Host not found in nmap results"
        return host_data

    host = nm[ip]
    for match in host.get("osmatch", [])[:3]:
        confidence = int(match.get("accuracy", 0))
        if confidence < OS_CONFIDENCE_THRESHOLD:
            continue
        host_data["os_matches"].append({
            "name":     match.get("name", ""),
            "accuracy": confidence,
            "osclass": [{
                "type":     c.get("type", ""),
                "vendor":   c.get("vendor", ""),
                "osfamily": c.get("osfamily", ""),
                "osgen":    c.get("osgen", ""),
            } for c in match.get("osclass", [])],
        })
    for proto in host.all_protocols():
        for port, info in host[proto].items():
            if info.get("state") == "open":
                host_data["open_ports"].append({
                    "port":    port,
                    "proto":   proto,
                    "service": info.get("name", ""),
                    "product": info.get("product", ""),
                    "version": info.get("version", ""),
                    "cpe":     info.get("cpe", ""),
                })
    host_data["hostnames"] = [
        h["name"] for h in host.get("hostnames", [])
        if h.get("name") and h["name"] != ip
    ]
    os_label = host_data["os_matches"][0]["name"] if host_data["os_matches"] else "unknown"
    print(f"[nmap] Done: {ip} -- {len(host_data['open_ports'])} ports, OS: {os_label}", flush=True)
    return host_data

def _run_deep_scan_thread(ip: str, mac: str) -> None:
    results = deep_scan(ip, mac)
    session = Session()
    try:
        device = session.get(Device, mac)
        if device:
            device.scan_results = results
            device.deep_scanned = True
            if not device.hostname and results.get("hostnames"):
                device.hostname = _strip_fqdn(results["hostnames"][0])
            session.commit()
    except Exception as e:
        session.rollback()
        print(f"[DB] Scan save error {mac}: {e}", flush=True)
    finally:
        session.close()
        with _scan_lock:
            _scanning.discard(mac)

def trigger_deep_scan(ip: str, mac: str) -> None:
    with _scan_lock:
        if mac in _scanning:
            return
        _scanning.add(mac)
    threading.Thread(target=_run_deep_scan_thread, args=(ip, mac), daemon=True).start()

# ---------------------------------------------------------------------------
# Device upsert
# ---------------------------------------------------------------------------
def upsert_seen_device(mac: str, ip: str, source: str) -> None:
    if not mac or mac == "00:00:00:00:00:00":
        return
    ip_is_new = record_ip(mac, ip)
    mac_lock  = _get_mac_lock(mac)
    with mac_lock:
        now     = datetime.now(timezone.utc)
        session = Session()
        try:
            existing = session.get(Device, mac)
            is_new   = existing is None
            if is_new:
                hostname = resolve_hostname(ip)
                vendor   = lookup_vendor(mac)
            else:
                hostname = existing.hostname or resolve_hostname(ip)
                vendor   = existing.vendor
            ip_changed = (not is_new) and (existing.ip_address != ip)
            safe_hostname = (hostname or '').replace("'", "''")
            stmt = (
                pg_insert(Device)
                .values(
                    mac_address  = mac,
                    ip_address   = ip,
                    hostname     = hostname,
                    vendor       = vendor,
                    custom_name  = None,
                    is_online    = True,
                    first_seen   = now,
                    last_seen    = now,
                    deep_scanned = False,
                    miss_count   = 0,
                )
                .on_conflict_do_update(
                    index_elements=["mac_address"],
                    set_=dict(
                        ip_address = ip,
                        is_online  = True,
                        last_seen  = now,
                        miss_count = 0,
                        hostname   = text(
                            "CASE WHEN devices.hostname IS NOT NULL AND devices.hostname != '' "
                            f"THEN devices.hostname ELSE '{safe_hostname}' END"
                        ),
                    ),
                )
            )
            session.execute(stmt)
            session.commit()
            if is_new:
                print(f"[+] New device via {source}: {ip} ({mac}) hostname={hostname} vendor={vendor}", flush=True)
                trigger_deep_scan(ip, mac)
            elif not existing.is_online:
                print(f"[~] Back online via {source}: {ip} ({mac})", flush=True)
            if ip_changed:
                print(f"[~] IP changed {existing.ip_address} -> {ip} for {mac} -- queuing rescan", flush=True)
                session2 = Session()
                try:
                    dev2 = session2.get(Device, mac)
                    if dev2:
                        dev2.deep_scanned = False
                        dev2.scan_results = None
                        session2.commit()
                except Exception:
                    session2.rollback()
                finally:
                    session2.close()
                trigger_deep_scan(ip, mac)
        except Exception as e:
            session.rollback()
            print(f"[DB] Upsert error {mac}: {e}", flush=True)
        finally:
            session.close()

def refresh_missing_hostnames() -> None:
    """Re-try hostname resolution for all online devices missing a name."""
    session = Session()
    try:
        unnamed = session.query(Device).filter(
            Device.is_online == True,
            Device.hostname  == None,
        ).all()
        updated = 0
        for dev in unnamed:
            if not dev.ip_address:
                continue
            name = resolve_hostname(dev.ip_address)
            if name:
                dev.hostname = name
                updated += 1
                print(f"[hostname] Resolved: {dev.ip_address} -> {name}", flush=True)
        if updated:
            session.commit()
            print(f"[hostname] Resolved {updated} new hostnames this pass.", flush=True)
    except Exception as e:
        session.rollback()
        print(f"[hostname] Refresh error: {e}", flush=True)
    finally:
        session.close()

def bulk_reresolve_all() -> None:
    """On startup, attempt to resolve hostnames for every device in the DB."""
    session = Session()
    try:
        all_devs = session.query(Device).filter(Device.ip_address != None).all()
        updated = 0
        for dev in all_devs:
            name = resolve_hostname(dev.ip_address)
            if name and name != dev.hostname:
                print(f"[hostname] Re-resolved: {dev.ip_address} -> {name}", flush=True)
                dev.hostname = name
                updated += 1
        if updated:
            session.commit()
        print(f"[hostname] Startup re-resolve complete: {updated}/{len(all_devs)} updated.", flush=True)
    except Exception as e:
        session.rollback()
        print(f"[hostname] Bulk re-resolve error: {e}", flush=True)
    finally:
        session.close()

# ---------------------------------------------------------------------------
# Sniffer
# ---------------------------------------------------------------------------
def process_arp_packet(packet) -> None:
    if not packet.haslayer(ARP):
        return
    arp = packet[ARP]
    mac = (arp.hwsrc or "").lower().strip()
    ip  = (arp.psrc  or "").strip()
    if not mac or not ip or mac == "ff:ff:ff:ff:ff:ff" or mac.startswith("01:"):
        return
    try:
        _sniffer_queue.put_nowait((mac, ip))
    except queue.Full:
        pass

def _sniffer_worker() -> None:
    while True:
        try:
            mac, ip = _sniffer_queue.get(timeout=1)
            upsert_seen_device(mac, ip, "sniffer")
            _sniffer_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            print(f"[sniffer-worker] {e}", flush=True)

def start_arp_sniffer() -> None:
    for i in range(SNIFFER_WORKERS):
        threading.Thread(target=_sniffer_worker, name=f"sniffer-worker-{i}", daemon=True).start()
    print(f"[*] Passive ARP sniffer on {INTERFACE} ({SNIFFER_WORKERS} workers)", flush=True)
    sniff(iface=INTERFACE, filter="arp", store=False, prn=process_arp_packet)

# ---------------------------------------------------------------------------
# Presence sweep
# ---------------------------------------------------------------------------
def update_presence_from_sweep(session, active_macs: set) -> None:
    for dev in session.query(Device).all():
        if dev.mac_address in active_macs:
            dev.is_online  = True
            dev.miss_count = 0
        else:
            dev.miss_count = (dev.miss_count or 0) + 1
            if dev.miss_count >= OFFLINE_MISS_THRESHOLD and dev.is_online:
                dev.is_online = False
                print(f"[-] Offline: {dev.ip_address} ({dev.mac_address})", flush=True)

# ---------------------------------------------------------------------------
# Probe HTTP API (port 8001)
# Handles: ping/traceroute SSE, hostname resolution, nmap rescan trigger
# ---------------------------------------------------------------------------
probe_api = FastAPI(title="InSpectre Probe Internal API", docs_url=None, redoc_url=None)
probe_api.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

def _sse_line(data: str) -> str:
    safe = data.replace("\n", " ").replace("\r", "")
    return f"data: {safe}\n\n"

def _stream_subprocess(cmd: list[str]):
    """Generator: yield SSE frames from a subprocess line-by-line."""
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


@probe_api.get("/health")
def probe_health():
    return {"status": "ok", "dns_server": _DNS_SERVER}


@probe_api.get("/resolve/{ip}")
def probe_resolve(ip: str):
    """
    Resolve a hostname for the given IP using the probe's full resolution stack.
    Called by the backend when the user clicks the 'refresh hostname' button.
    The probe has host networking so it can reach LAN DNS; the backend cannot.
    """
    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "Invalid IP address")
    name = resolve_hostname(ip)
    return {"ip": ip, "hostname": name}


@probe_api.post("/rescan/{mac}")
def probe_rescan(mac: str):
    """
    Immediately queue a deep nmap scan for the given MAC address.
    Called by the backend when the user clicks 'Re-scan ports'.
    """
    session = Session()
    try:
        device = session.get(Device, mac.lower())
        if not device:
            raise HTTPException(404, "Device not found")
        if not device.ip_address:
            raise HTTPException(422, "Device has no IP address")
        device.deep_scanned = False
        device.scan_results = None
        session.commit()
        trigger_deep_scan(device.ip_address, device.mac_address)
        return {"queued": True, "mac": mac, "ip": device.ip_address}
    finally:
        session.close()


@probe_api.get("/stream/ping/{ip}")
def stream_ping(ip: str):
    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "Invalid IP address")
    cmd = ["ping", "-c", str(PING_COUNT), "-W", "2", ip]
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
    cmd = ["traceroute", "-m", str(TRACE_MAX_HOP), "-w", "2", ip]
    return StreamingResponse(
        _stream_subprocess(cmd),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def start_probe_api() -> None:
    print(f"[*] Probe API listening on :{PROBE_API_PORT}", flush=True)
    uvicorn.run(
        probe_api,
        host="0.0.0.0",
        port=PROBE_API_PORT,
        log_level="warning",
        loop="none",
    )

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    print("[*] InSpectre Probe starting...", flush=True)
    wait_for_db()
    init_db()

    print(
        f"[*] Scanning {IP_RANGE} on {INTERFACE} every {SCAN_INTERVAL}s\n"
        f"[*] Offline threshold: {OFFLINE_MISS_THRESHOLD} | OS confidence: {OS_CONFIDENCE_THRESHOLD}%",
        flush=True,
    )

    # Detect DNS server early so it's available before first scan
    global _DNS_SERVER, _DNS_DETECTED
    _DNS_SERVER  = _detect_dns_server()
    _DNS_DETECTED = True
    print(f"[*] DNS server detected: {_DNS_SERVER}", flush=True)

    # Start probe HTTP API in background thread
    threading.Thread(target=start_probe_api, daemon=True, name="probe-api").start()

    # Give the API time to bind before the first sweep
    time.sleep(2)

    # Resolve hostnames for all existing devices on startup (background)
    print("[*] Running startup hostname resolution pass...", flush=True)
    threading.Thread(target=bulk_reresolve_all, daemon=True, name="startup-resolve").start()

    # Start passive ARP sniffer in background
    threading.Thread(target=start_arp_sniffer, daemon=True, name="arp-sniffer").start()

    while True:
        session = Session()
        try:
            found        = arp_scan(INTERFACE, IP_RANGE)
            active_macs: set[str] = set()
            for entry in found:
                active_macs.add(entry["mac"])
                upsert_seen_device(entry["mac"], entry["ip"], "sweep")
            update_presence_from_sweep(session, active_macs)
            session.commit()
            print(f"[*] Sweep done -- {len(active_macs)} online", flush=True)
            threading.Thread(target=refresh_missing_hostnames, daemon=True).start()
        except Exception as e:
            session.rollback()
            print(f"[!] Sweep error: {e}", flush=True)
        finally:
            session.close()
        time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    main()
