import time
import json
import socket
import threading
from datetime import datetime, timezone

import nmap
from scapy.all import ARP, Ether, srp
from sqlalchemy import create_engine, Column, String, DateTime, JSON, Boolean, text
from sqlalchemy.orm import sessionmaker, declarative_base
import requests
import os

# ─── Config ────────────────────────────────────────────────────────────────────
DATABASE_URL  = os.environ.get("DATABASE_URL", "postgresql://admin:password123@localhost:5432/inspectre")
SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", 60))
IP_RANGE      = os.environ.get("IP_RANGE", "192.168.0.0/24")
INTERFACE     = os.environ.get("INTERFACE", "eth0")
NMAP_ARGS     = os.environ.get("NMAP_ARGS", "-O --osscan-guess -sV --version-intensity 5 -T4")

# ─── DB Model ──────────────────────────────────────────────────────────────────
Base = declarative_base()

class Device(Base):
    __tablename__ = "devices"
    mac_address  = Column(String, primary_key=True, index=True)
    ip_address   = Column(String)
    hostname     = Column(String, nullable=True)
    vendor       = Column(String, nullable=True)
    custom_name  = Column(String, nullable=True)
    is_online    = Column(Boolean, default=True)
    first_seen   = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen    = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    scan_results = Column(JSON, nullable=True)
    deep_scanned = Column(Boolean, default=False)  # True once nmap scan completes

engine = create_engine(DATABASE_URL, pool_pre_ping=True)

def wait_for_db(retries=10, delay=5):
    for attempt in range(retries):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            print("[DB] Connected.")
            return
        except Exception as e:
            print(f"[DB] Not ready (attempt {attempt+1}/{retries}): {e}")
            time.sleep(delay)
    raise RuntimeError("Could not connect to database.")

def init_db():
    Base.metadata.create_all(engine)
    # Safe migration: add deep_scanned if upgrading from earlier schema
    with engine.connect() as conn:
        try:
            conn.execute(text(
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS deep_scanned BOOLEAN DEFAULT FALSE"
            ))
            conn.commit()
        except Exception:
            pass

Session = sessionmaker(bind=engine)

# ─── Helpers ───────────────────────────────────────────────────────────────────
def lookup_vendor(mac: str) -> str:
    """OUI lookup via macvendors.com — best-effort, returns 'Unknown' on failure."""
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        if r.status_code == 200:
            return r.text.strip()
    except Exception:
        pass
    return "Unknown"

def resolve_hostname(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

# ─── ARP Scanner ───────────────────────────────────────────────────────────────
def arp_scan(interface: str, ip_range: str) -> list[dict]:
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    result = srp(pkt, iface=interface, timeout=3, verbose=0)[0]
    return [{"ip": rcv.psrc, "mac": rcv.hwsrc.lower()} for _, rcv in result]

# ─── Nmap Deep Scanner ─────────────────────────────────────────────────────────
def deep_scan(ip: str, mac: str) -> dict:
    """
    Run OS detection + service version scan.
    Stores structured results in the scan_results JSONB field.
    """
    print(f"[nmap] Starting deep scan: {ip} ({mac})")
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip, arguments=NMAP_ARGS)
    except nmap.PortScannerError as e:
        print(f"[nmap] Scan failed for {ip}: {e}")
        return {"error": str(e), "scanned_at": datetime.now(timezone.utc).isoformat()}

    result = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "os_matches": [],
        "open_ports": [],
        "hostnames":  [],
    }

    if ip not in nm.all_hosts():
        result["error"] = "Host not found in nmap results"
        return result

    host = nm[ip]

    # OS candidates (top 3)
    for match in host.get("osmatch", [])[:3]:
        result["os_matches"].append({
            "name":     match.get("name", ""),
            "accuracy": int(match.get("accuracy", 0)),
            "osclass": [
                {
                    "type":     c.get("type", ""),
                    "vendor":   c.get("vendor", ""),
                    "osfamily": c.get("osfamily", ""),
                    "osgen":    c.get("osgen", ""),
                }
                for c in match.get("osclass", [])
            ],
        })

    # Open ports + service banners
    for proto in host.all_protocols():
        for port, info in host[proto].items():
            if info.get("state") == "open":
                result["open_ports"].append({
                    "port":    port,
                    "proto":   proto,
                    "service": info.get("name", ""),
                    "product": info.get("product", ""),
                    "version": info.get("version", ""),
                    "cpe":     info.get("cpe", ""),
                })

    result["hostnames"] = [h["name"] for h in host.get("hostnames", []) if h.get("name")]

    os_name = result["os_matches"][0]["name"] if result["os_matches"] else "unknown"
    print(f"[nmap] Done: {ip} — {len(result['open_ports'])} ports open, OS: {os_name}")
    return result

# ─── Background Thread Pool ────────────────────────────────────────────────────
_scan_lock = threading.Lock()
_scanning  = set()  # MACs currently being scanned (prevent duplicates)

def _run_deep_scan_thread(ip: str, mac: str):
    results = deep_scan(ip, mac)
    session = Session()
    try:
        device = session.get(Device, mac)
        if device:
            device.scan_results = results
            device.deep_scanned = True
            # Backfill hostname from nmap if DNS lookup returned nothing
            if not device.hostname and results.get("hostnames"):
                device.hostname = results["hostnames"][0]
            session.commit()
            print(f"[DB] Saved scan results for {ip} ({mac})")
    except Exception as e:
        session.rollback()
        print(f"[DB] Error saving scan results for {mac}: {e}")
    finally:
        session.close()
        with _scan_lock:
            _scanning.discard(mac)

def trigger_deep_scan(ip: str, mac: str):
    """Non-blocking: launch nmap in a background daemon thread."""
    with _scan_lock:
        if mac in _scanning:
            return
        _scanning.add(mac)
    t = threading.Thread(target=_run_deep_scan_thread, args=(ip, mac), daemon=True)
    t.start()

# ─── DB Sync ───────────────────────────────────────────────────────────────────
def sync_device(session, entry: dict) -> tuple:
    mac, ip = entry["mac"], entry["ip"]
    now     = datetime.now(timezone.utc)
    device  = session.get(Device, mac)
    is_new  = device is None

    if is_new:
        device = Device(
            mac_address  = mac,
            ip_address   = ip,
            hostname     = resolve_hostname(ip),
            vendor       = lookup_vendor(mac),
            is_online    = True,
            first_seen   = now,
            last_seen    = now,
            deep_scanned = False,
        )
        session.add(device)
        print(f"[+] New device: {ip} ({mac}) — vendor: {device.vendor}")
    else:
        device.ip_address = ip
        device.is_online  = True
        device.last_seen  = now
        if not device.hostname:
            device.hostname = resolve_hostname(ip)

    return device, is_new

def mark_offline(session, active_macs: set):
    for dev in session.query(Device).filter_by(is_online=True).all():
        if dev.mac_address not in active_macs:
            dev.is_online = False
            print(f"[-] Device offline: {dev.ip_address} ({dev.mac_address})")

# ─── Main Loop ─────────────────────────────────────────────────────────────────
def main():
    print("[*] InSpectre Probe starting…")
    wait_for_db()
    init_db()
    print(f"[*] Scanning {IP_RANGE} on {INTERFACE} every {SCAN_INTERVAL}s")

    while True:
        try:
            session     = Session()
            found       = arp_scan(INTERFACE, IP_RANGE)
            active_macs = set()

            for entry in found:
                device, is_new = sync_device(session, entry)
                active_macs.add(entry["mac"])
                if is_new:
                    session.commit()                          # persist device before scanning
                    trigger_deep_scan(entry["ip"], entry["mac"])

            mark_offline(session, active_macs)
            session.commit()
            print(f"[*] Scan complete — {len(found)} online")

        except Exception as e:
            print(f"[!] Scan loop error: {e}")
            try:
                session.rollback()
            except Exception:
                pass
        finally:
            try:
                session.close()
            except Exception:
                pass

        time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    main()
