import os
import time
import socket
import threading
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

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://admin:password123@localhost:5432/inspectre")
SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", 60))
IP_RANGE = os.environ.get("IP_RANGE", "192.168.0.0/24")
INTERFACE = os.environ.get("INTERFACE", "eth0")
NMAP_ARGS = os.environ.get(
    "NMAP_ARGS",
    # Removed --osscan-guess so only confident matches are returned.
    # --osscan-limit skips OS detection on hosts with no useful port state.
    "-O --osscan-limit -sV --version-intensity 5 -T4",
)
# Only store OS matches at or above this confidence percentage.
OS_CONFIDENCE_THRESHOLD = int(os.environ.get("OS_CONFIDENCE_THRESHOLD", 85))
OFFLINE_MISS_THRESHOLD = int(os.environ.get("OFFLINE_MISS_THRESHOLD", 3))

Base = declarative_base()

# Per-MAC mutex so sniffer and sweep threads never race on the same device.
_upsert_locks: dict[str, threading.Lock] = {}
_upsert_locks_lock = threading.Lock()

def _get_mac_lock(mac: str) -> threading.Lock:
    with _upsert_locks_lock:
        if mac not in _upsert_locks:
            _upsert_locks[mac] = threading.Lock()
        return _upsert_locks[mac]


class Device(Base):
    __tablename__ = "devices"

    mac_address = Column(String, primary_key=True, index=True)
    ip_address = Column(String)
    hostname = Column(String, nullable=True)
    vendor = Column(String, nullable=True)
    custom_name = Column(String, nullable=True)
    is_online = Column(Boolean, default=True)
    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    scan_results = Column(JSON, nullable=True)
    deep_scanned = Column(Boolean, default=False)
    miss_count = Column(Integer, default=0)


engine = create_engine(DATABASE_URL, pool_pre_ping=True)
Session = sessionmaker(bind=engine)
_scan_lock = threading.Lock()
_scanning: set[str] = set()


def wait_for_db(retries=10, delay=5):
    for attempt in range(retries):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            print("[DB] Connected.", flush=True)
            return
        except Exception as e:
            print(f"[DB] Not ready (attempt {attempt + 1}/{retries}): {e}", flush=True)
            time.sleep(delay)
    raise RuntimeError("Could not connect to database after multiple attempts.")


def init_db():
    Base.metadata.create_all(engine)
    with engine.connect() as conn:
        try:
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS deep_scanned BOOLEAN DEFAULT FALSE"))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS miss_count INTEGER DEFAULT 0"))
            conn.commit()
        except Exception as e:
            print(f"[DB] Migration warning: {e}", flush=True)


def lookup_vendor(mac: str) -> str:
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        if r.status_code == 200:
            return r.text.strip()
    except Exception:
        pass
    return "Unknown"


def resolve_hostname(ip: str):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def arp_scan(interface: str, ip_range: str) -> list[dict]:
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    result = srp(pkt, iface=interface, timeout=3, verbose=0)[0]
    return [{"ip": rcv.psrc, "mac": rcv.hwsrc.lower()} for _, rcv in result]


def deep_scan(ip: str, mac: str) -> dict:
    print(f"[nmap] Starting deep scan: {ip} ({mac})", flush=True)
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip, arguments=NMAP_ARGS)
    except nmap.PortScannerError as e:
        print(f"[nmap] Scan failed for {ip}: {e}", flush=True)
        return {"error": str(e), "scanned_at": datetime.now(timezone.utc).isoformat()}

    host_data = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "os_matches": [],
        "open_ports": [],
        "hostnames": [],
    }

    if ip not in nm.all_hosts():
        host_data["error"] = "Host not found in nmap results"
        return host_data

    host = nm[ip]

    # Only include OS matches that meet the confidence threshold.
    # Without --osscan-guess, nmap won't speculate wildly, but we
    # add this second gate so low-quality matches are never surfaced.
    for match in host.get("osmatch", [])[:3]:
        confidence = int(match.get("accuracy", 0))
        if confidence < OS_CONFIDENCE_THRESHOLD:
            continue
        host_data["os_matches"].append(
            {
                "name": match.get("name", ""),
                "accuracy": confidence,
                "osclass": [
                    {
                        "type": c.get("type", ""),
                        "vendor": c.get("vendor", ""),
                        "osfamily": c.get("osfamily", ""),
                        "osgen": c.get("osgen", ""),
                    }
                    for c in match.get("osclass", [])
                ],
            }
        )

    for proto in host.all_protocols():
        for port, port_info in host[proto].items():
            if port_info.get("state") == "open":
                host_data["open_ports"].append(
                    {
                        "port": port,
                        "proto": proto,
                        "service": port_info.get("name", ""),
                        "product": port_info.get("product", ""),
                        "version": port_info.get("version", ""),
                        "cpe": port_info.get("cpe", ""),
                    }
                )

    host_data["hostnames"] = [h["name"] for h in host.get("hostnames", []) if h.get("name")]
    os_label = host_data["os_matches"][0]["name"] if host_data["os_matches"] else "unknown (below confidence threshold)"
    print(
        f"[nmap] Done: {ip} — {len(host_data['open_ports'])} ports open, OS: {os_label}",
        flush=True,
    )
    return host_data


def _run_deep_scan_thread(ip: str, mac: str):
    results = deep_scan(ip, mac)
    session = Session()
    try:
        device = session.get(Device, mac)
        if device:
            device.scan_results = results
            device.deep_scanned = True
            if not device.hostname and results.get("hostnames"):
                device.hostname = results["hostnames"][0]
            session.commit()
            print(f"[DB] Saved scan results for {ip} ({mac})", flush=True)
    except Exception as e:
        session.rollback()
        print(f"[DB] Error saving scan results for {mac}: {e}", flush=True)
    finally:
        session.close()
        with _scan_lock:
            _scanning.discard(mac)


def trigger_deep_scan(ip: str, mac: str):
    with _scan_lock:
        if mac in _scanning:
            return
        _scanning.add(mac)
    threading.Thread(target=_run_deep_scan_thread, args=(ip, mac), daemon=True).start()


def upsert_seen_device(mac: str, ip: str, source: str):
    """
    Atomically insert-or-update a device record using PostgreSQL's
    INSERT ... ON CONFLICT DO UPDATE. This replaces the previous
    check-then-insert pattern which caused duplicate-key race conditions
    between the passive sniffer thread and the active sweep loop.
    """
    if not mac or mac == "00:00:00:00:00:00":
        return

    # Per-MAC lock ensures only one thread resolves hostname/vendor
    # for a brand-new device, avoiding redundant external lookups.
    mac_lock = _get_mac_lock(mac)
    with mac_lock:
        now = datetime.now(timezone.utc)
        session = Session()
        try:
            # Check existence first so we know whether to log "new device"
            # and trigger a deep scan — both only happen on genuine first-sight.
            existing = session.get(Device, mac)
            is_new = existing is None

            hostname = resolve_hostname(ip) if is_new else (existing.hostname if existing.hostname else resolve_hostname(ip))
            vendor = lookup_vendor(mac) if is_new else existing.vendor

            stmt = (
                pg_insert(Device)
                .values(
                    mac_address=mac,
                    ip_address=ip,
                    hostname=hostname,
                    vendor=vendor,
                    custom_name=None,
                    is_online=True,
                    first_seen=now,
                    last_seen=now,
                    deep_scanned=False,
                    miss_count=0,
                )
                .on_conflict_do_update(
                    index_elements=["mac_address"],
                    set_=dict(
                        ip_address=ip,
                        is_online=True,
                        last_seen=now,
                        miss_count=0,
                        # Preserve existing hostname/vendor if already set.
                        hostname=text(
                            "CASE WHEN devices.hostname IS NOT NULL THEN devices.hostname "
                            f"ELSE '{hostname or ''}' END"
                        ),
                    ),
                )
            )
            session.execute(stmt)
            session.commit()

            if is_new:
                print(f"[+] New device via {source}: {ip} ({mac}) — vendor: {vendor}", flush=True)
                trigger_deep_scan(ip, mac)
            else:
                came_back_online = not existing.is_online
                if came_back_online:
                    print(f"[+] Device back online via {source}: {ip} ({mac})", flush=True)

        except Exception as e:
            session.rollback()
            print(f"[DB] Upsert error for {mac}: {e}", flush=True)
        finally:
            session.close()


def process_arp_packet(packet):
    if not packet.haslayer(ARP):
        return
    arp = packet[ARP]
    mac = (arp.hwsrc or "").lower()
    ip = arp.psrc
    upsert_seen_device(mac, ip, "sniffer")


def start_arp_sniffer():
    print(f"[*] Starting passive ARP sniffer on {INTERFACE}", flush=True)
    sniff(iface=INTERFACE, filter="arp", store=False, prn=process_arp_packet)


def update_presence_from_sweep(session, active_macs: set):
    devices = session.query(Device).all()
    for dev in devices:
        if dev.mac_address in active_macs:
            dev.is_online = True
            dev.miss_count = 0
        else:
            dev.miss_count = (dev.miss_count or 0) + 1
            if dev.miss_count >= OFFLINE_MISS_THRESHOLD and dev.is_online:
                dev.is_online = False
                print(f"[-] Device offline: {dev.ip_address} ({dev.mac_address})", flush=True)


def main():
    print("[*] InSpectre Probe starting…", flush=True)
    wait_for_db()
    init_db()
    print(
        f"[*] Scanning {IP_RANGE} on {INTERFACE} every {SCAN_INTERVAL}s "
        f"(offline threshold: {OFFLINE_MISS_THRESHOLD} missed sweeps)\n"
        f"[*] OS confidence threshold: {OS_CONFIDENCE_THRESHOLD}%",
        flush=True,
    )

    threading.Thread(target=start_arp_sniffer, daemon=True).start()

    while True:
        session = Session()
        try:
            found = arp_scan(INTERFACE, IP_RANGE)
            active_macs = set()

            for entry in found:
                mac = entry["mac"]
                ip = entry["ip"]
                active_macs.add(mac)
                upsert_seen_device(mac, ip, "sweep")

            update_presence_from_sweep(session, active_macs)
            session.commit()
            print(f"[*] Scan complete — {len(active_macs)} online", flush=True)
        except Exception as e:
            session.rollback()
            print(f"[!] Scan loop error: {e}", flush=True)
        finally:
            session.close()

        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    main()
