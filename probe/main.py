import os
import queue
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone

import nmap
import requests
from scapy.all import ARP, Ether, sniff, srp
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    JSON,
    String,
    create_engine,
    text,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import declarative_base, sessionmaker

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DATABASE_URL          = os.environ.get("DATABASE_URL", "postgresql://admin:password123@localhost:5432/inspectre")
SCAN_INTERVAL         = int(os.environ.get("SCAN_INTERVAL", 60))
IP_RANGE              = os.environ.get("IP_RANGE", "192.168.0.0/24")
INTERFACE             = os.environ.get("INTERFACE", "eth0")
NMAP_ARGS             = os.environ.get("NMAP_ARGS", "-O --osscan-limit -sV --version-intensity 5 -T4")
OS_CONFIDENCE_THRESHOLD = int(os.environ.get("OS_CONFIDENCE_THRESHOLD", 85))
OFFLINE_MISS_THRESHOLD  = int(os.environ.get("OFFLINE_MISS_THRESHOLD", 3))
SNIFFER_WORKERS         = int(os.environ.get("SNIFFER_WORKERS", 4))

# ---------------------------------------------------------------------------
# SQLAlchemy model
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

# ---------------------------------------------------------------------------
# Hostname resolution  --  multi-strategy
# ---------------------------------------------------------------------------
def _strip_fqdn(name: str) -> str:
    """Remove trailing dot from FQDN and return the shortest useful label."""
    return name.rstrip('.') if name else ''

def resolve_hostname(ip: str) -> str | None:
    """
    Try multiple strategies in order of speed / reliability:
      1. Standard reverse-DNS (gethostbyaddr) — works if router pushes names
         into the local DNS server.
      2. mDNS / Bonjour via `avahi-resolve` (if available) — catches Apple,
         Android, Linux devices advertising .local names.
      3. NetBIOS via `nmblookup -A` (if available) — catches Windows PCs
         and Samba servers.
      4. LLMNR via `dig` @ff02::1:3 (if available, IPv6 networks).
      5. Nmap -sn fallback — last resort, slower but thorough.
    Returns the best name found, or None.
    """
    name = None

    # 1. Reverse DNS
    try:
        result = socket.gethostbyaddr(ip)
        candidate = _strip_fqdn(result[0])
        # Reject bare-IP results the resolver sometimes hands back
        if candidate and candidate != ip:
            name = candidate
    except Exception:
        pass
    if name:
        return name

    # 2. mDNS / Avahi  (avahi-resolve -a <ip>)
    try:
        out = subprocess.run(
            ["avahi-resolve", "-a", ip],
            capture_output=True, text=True, timeout=3
        )
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                candidate = _strip_fqdn(parts[1])
                if candidate and candidate != ip:
                    return candidate
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # 3. NetBIOS  (nmblookup -A <ip>)
    try:
        out = subprocess.run(
            ["nmblookup", "-A", ip],
            capture_output=True, text=True, timeout=4
        )
        for line in out.stdout.splitlines():
            # Lines look like:  	HOSTNAME         <00> -         B <ACTIVE>
            if '<00>' in line and '<GROUP>' not in line:
                parts = line.strip().split()
                if parts:
                    candidate = parts[0].strip()
                    if candidate and candidate not in ('WORKGROUP', ip, 'Looking'):
                        return candidate
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # 4. nmap -sn hostname extraction (slowest fallback)
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, arguments="-sn --dns-servers 8.8.8.8")
        if ip in nm.all_hosts():
            hostnames = [h["name"] for h in nm[ip].get("hostnames", []) if h.get("name") and h["name"] != ip]
            if hostnames:
                return _strip_fqdn(hostnames[0])
    except Exception:
        pass

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
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
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

    host_data["hostnames"] = [h["name"] for h in host.get("hostnames", []) if h.get("name") and h["name"] != ip]
    os_label = host_data["os_matches"][0]["name"] if host_data["os_matches"] else "unknown"
    print(f"[nmap] Done: {ip} — {len(host_data['open_ports'])} ports, OS: {os_label}", flush=True)
    return host_data


def _run_deep_scan_thread(ip: str, mac: str) -> None:
    results = deep_scan(ip, mac)
    session = Session()
    try:
        device = session.get(Device, mac)
        if device:
            device.scan_results = results
            device.deep_scanned = True
            # Promote nmap hostname if we still don't have one
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

    mac_lock = _get_mac_lock(mac)
    with mac_lock:
        now     = datetime.now(timezone.utc)
        session = Session()
        try:
            existing = session.get(Device, mac)
            is_new   = existing is None

            # For new devices try all resolution strategies.
            # For existing devices: only re-resolve if hostname is still None.
            if is_new:
                hostname = resolve_hostname(ip)
                vendor   = lookup_vendor(mac)
            else:
                hostname = existing.hostname or resolve_hostname(ip)
                vendor   = existing.vendor

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

        except Exception as e:
            session.rollback()
            print(f"[DB] Upsert error {mac}: {e}", flush=True)
        finally:
            session.close()


# Re-attempt hostname resolution for devices that still have none.
# Runs after every sweep so persistent devices eventually get named.
def refresh_missing_hostnames() -> None:
    session = Session()
    try:
        unnamed = session.query(Device).filter(
            Device.is_online == True,
            Device.hostname  == None,
        ).all()
        for dev in unnamed:
            name = resolve_hostname(dev.ip_address)
            if name:
                dev.hostname = name
                print(f"[hostname] Resolved late: {dev.ip_address} -> {name}", flush=True)
        if unnamed:
            session.commit()
    except Exception as e:
        session.rollback()
        print(f"[hostname] Refresh error: {e}", flush=True)
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
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    print("[*] InSpectre Probe starting…", flush=True)
    wait_for_db()
    init_db()

    # Install NetBIOS tools if available (best-effort; won't crash if absent)
    for pkg in ["avahi-utils", "samba-common-bin"]:
        try:
            subprocess.run(["apt-get", "install", "-y", "--no-install-recommends", pkg],
                           capture_output=True, timeout=30)
        except Exception:
            pass

    print(
        f"[*] Scanning {IP_RANGE} on {INTERFACE} every {SCAN_INTERVAL}s\n"
        f"[*] Offline threshold: {OFFLINE_MISS_THRESHOLD} | OS confidence: {OS_CONFIDENCE_THRESHOLD}%",
        flush=True,
    )

    threading.Thread(target=start_arp_sniffer, daemon=True).start()

    while True:
        session     = Session()
        try:
            found       = arp_scan(INTERFACE, IP_RANGE)
            active_macs: set[str] = set()

            for entry in found:
                active_macs.add(entry["mac"])
                upsert_seen_device(entry["mac"], entry["ip"], "sweep")

            update_presence_from_sweep(session, active_macs)
            session.commit()
            print(f"[*] Sweep done — {len(active_macs)} online", flush=True)

            # Background: try to resolve hostnames for any still-unnamed devices
            threading.Thread(target=refresh_missing_hostnames, daemon=True).start()

        except Exception as e:
            session.rollback()
            print(f"[!] Sweep error: {e}", flush=True)
        finally:
            session.close()

        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    main()
