import asyncio
import json
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
    cast, create_engine, text,
)
from sqlalchemy.dialects.postgresql import JSONB, insert as pg_insert
from sqlalchemy.orm import declarative_base, sessionmaker

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------
VERSION = "0.6.4"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DATABASE_URL            = os.environ.get("DATABASE_URL",            "postgresql://admin:password123@localhost:5432/inspectre")
SCAN_INTERVAL           = int(os.environ.get("SCAN_INTERVAL",           60))
IP_RANGE                = os.environ.get("IP_RANGE",                "192.168.0.0/24")
INTERFACE               = os.environ.get("INTERFACE",               "eth0")
NMAP_ARGS               = os.environ.get("NMAP_ARGS",               "-O --osscan-limit -sV --version-intensity 5 -T4")
OS_CONFIDENCE_THRESHOLD = int(os.environ.get("OS_CONFIDENCE_THRESHOLD", 85))
OFFLINE_MISS_THRESHOLD  = int(os.environ.get("OFFLINE_MISS_THRESHOLD",   5))
SNIFFER_WORKERS         = int(os.environ.get("SNIFFER_WORKERS",          4))
PROBE_API_PORT          = int(os.environ.get("PROBE_API_PORT",         8001))
LAN_DNS_SERVER_ENV      = os.environ.get("LAN_DNS_SERVER", "").strip()

PING_COUNT    = 10
TRACE_MAX_HOP = 30

# IPs that should never be stored, resolved, or rescanned
_INVALID_IPS = {"0.0.0.0", "", "255.255.255.255"}

def _is_valid_ip(ip: str) -> bool:
    if not ip or ip.strip() in _INVALID_IPS:
        return False
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip.strip())
        return not (addr.packed[0] == 0 or str(addr) == "255.255.255.255")
    except ValueError:
        return False

# ---------------------------------------------------------------------------
# SQLAlchemy models
# ---------------------------------------------------------------------------
Base = declarative_base()

class Device(Base):
    __tablename__ = "devices"
    mac_address  = Column(String,  primary_key=True, index=True)
    ip_address   = Column(String)
    primary_ip   = Column(String,  nullable=True)
    hostname     = Column(String,  nullable=True)
    vendor       = Column(String,  nullable=True)
    custom_name  = Column(String,  nullable=True)
    is_online    = Column(Boolean, default=True)
    first_seen   = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen    = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    scan_results = Column(JSON,    nullable=True)
    deep_scanned = Column(Boolean, default=False)
    miss_count   = Column(Integer, default=0)
    is_important = Column(Boolean, default=False, nullable=False)

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

# Track the last time each MAC was seen by the sniffer within the current sweep
# window, so we don't falsely increment miss counts for devices the sniffer saw.
_sniffer_seen_this_interval: set[str] = set()
_sniffer_seen_lock = threading.Lock()

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
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS is_important BOOLEAN NOT NULL DEFAULT FALSE"))
            conn.execute(text("ALTER TABLE devices ALTER COLUMN is_important SET DEFAULT FALSE"))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS primary_ip VARCHAR"))
            conn.execute(text("""
                UPDATE devices SET primary_ip = ip_address
                WHERE primary_ip IS NULL AND ip_address IS NOT NULL
            """))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS vuln_last_scanned TIMESTAMPTZ"))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS vuln_severity VARCHAR"))
            conn.commit()
        except Exception as e:
            print(f"[DB] Column migration note: {e}", flush=True)
            conn.rollback()

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

        try:
            conn.execute(text("""
                ALTER TABLE ip_history
                    ADD CONSTRAINT uq_ip_history_mac_ip UNIQUE (mac_address, ip_address)
            """))
            conn.commit()
            print("[DB] Added uq_ip_history_mac_ip constraint.", flush=True)
        except Exception:
            conn.rollback()

        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS device_events (
                id          SERIAL PRIMARY KEY,
                mac_address VARCHAR NOT NULL REFERENCES devices(mac_address) ON DELETE CASCADE,
                type        VARCHAR NOT NULL,
                detail      JSONB,
                created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_device_events_mac     ON device_events(mac_address)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_device_events_type    ON device_events(type)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_device_events_created ON device_events(created_at)"))
        conn.commit()

        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS vuln_reports (
                id          SERIAL PRIMARY KEY,
                mac_address VARCHAR NOT NULL REFERENCES devices(mac_address) ON DELETE CASCADE,
                ip_address  VARCHAR,
                scanned_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                duration_s  FLOAT,
                severity    VARCHAR NOT NULL DEFAULT 'clean',
                vuln_count  INTEGER NOT NULL DEFAULT 0,
                findings    JSONB,
                raw_output  TEXT,
                nmap_args   VARCHAR
            )
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_vuln_reports_mac      ON vuln_reports(mac_address)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_vuln_reports_scanned  ON vuln_reports(scanned_at)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_vuln_reports_severity ON vuln_reports(severity)"))
        conn.commit()

    print("[DB] Migrations complete.", flush=True)

# ---------------------------------------------------------------------------
# IP History
# ---------------------------------------------------------------------------
def record_ip(mac: str, ip: str) -> bool:
    """
    Upserts the IP into ip_history.  Returns True only if this is a BRAND NEW
    mac+ip combination (first_seen == last_seen within 2s).
    """
    if not _is_valid_ip(ip):
        return False
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
# Event writing
# ---------------------------------------------------------------------------
def _write_event(mac: str, event_type: str, detail: dict) -> None:
    """Write a device_events row.  Silently swallows errors."""
    session = Session()
    try:
        session.execute(
            text("""
                INSERT INTO device_events (mac_address, type, detail, created_at)
                VALUES (:mac, :type, cast(:detail AS jsonb), NOW())
            """),
            {"mac": mac, "type": event_type, "detail": json.dumps(detail)},
        )
        session.commit()
    except Exception as e:
        session.rollback()
        print(f"[events] write error {mac}/{event_type}: {e}", flush=True)
    finally:
        session.close()

# ---------------------------------------------------------------------------
# Hostname resolution
# ---------------------------------------------------------------------------
def _strip_fqdn(name: str) -> str:
    return name.rstrip('.') if name else ''

_DNS_SERVER: str | None = None
_DNS_DETECTED = False

def _get_default_gateway() -> str | None:
    try:
        out = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=3,
        )
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "default" and parts[1] == "via":
                gw = parts[2]
                if not gw.startswith("127.") and not gw.startswith("169.254."):
                    print(f"[hostname] Default gateway detected: {gw}", flush=True)
                    return gw
    except Exception as e:
        print(f"[hostname] Gateway detection failed: {e}", flush=True)
    return None

def _detect_dns_server() -> str | None:
    if LAN_DNS_SERVER_ENV:
        print(f"[hostname] DNS server from env (LAN_DNS_SERVER): {LAN_DNS_SERVER_ENV}", flush=True)
        return LAN_DNS_SERVER_ENV

    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                parts = line.strip().split()
                if parts and parts[0] == "nameserver" and len(parts) >= 2:
                    ip = parts[1]
                    if not ip.startswith("127.") and not ip.startswith("169.254."):
                        print(f"[hostname] DNS server from resolv.conf: {ip}", flush=True)
                        return ip
                    else:
                        print(f"[hostname] Skipping loopback nameserver: {ip}", flush=True)
    except Exception:
        pass

    gw = _get_default_gateway()
    if gw:
        print(f"[hostname] Using default gateway as DNS server: {gw}", flush=True)
        return gw

    print("[hostname] WARNING: no usable DNS server found. "
          "Set LAN_DNS_SERVER=<router_ip> in docker-compose.yml.", flush=True)
    return None

def resolve_hostname(ip: str) -> str | None:
    if not _is_valid_ip(ip):
        return None

    global _DNS_SERVER, _DNS_DETECTED
    if not _DNS_DETECTED:
        _DNS_SERVER   = _detect_dns_server()
        _DNS_DETECTED = True

    print(f"[hostname] Resolving {ip} (DNS server: {_DNS_SERVER})", flush=True)

    if _DNS_SERVER:
        try:
            out = subprocess.run(
                ["dig", "+short", "+time=2", "+tries=1", f"@{_DNS_SERVER}", "-x", ip],
                capture_output=True, text=True, timeout=5,
            )
            for line in out.stdout.splitlines():
                candidate = _strip_fqdn(line.strip())
                if candidate and candidate != ip and not candidate.startswith(";"):
                    print(f"[hostname] dig resolved {ip} -> {candidate}", flush=True)
                    return candidate
        except Exception as e:
            print(f"[hostname] dig failed: {e}", flush=True)

    try:
        result = socket.gethostbyaddr(ip)
        candidate = _strip_fqdn(result[0])
        if candidate and candidate != ip:
            print(f"[hostname] gethostbyaddr resolved {ip} -> {candidate}", flush=True)
            return candidate
    except Exception as e:
        print(f"[hostname] gethostbyaddr failed for {ip}: {e}", flush=True)

    if _DNS_SERVER:
        try:
            out = subprocess.run(
                ["host", ip, _DNS_SERVER],
                capture_output=True, text=True, timeout=5,
            )
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

    try:
        cmd = ["nslookup", ip]
        if _DNS_SERVER:
            cmd.append(_DNS_SERVER)
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
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
            _write_event(mac, "scan_complete", {
                "ports": len(results.get("open_ports") or []),
                "os":    results["os_matches"][0]["name"] if results.get("os_matches") else None,
            })
    except Exception as e:
        session.rollback()
        print(f"[DB] Scan save error {mac}: {e}", flush=True)
    finally:
        session.close()
        with _scan_lock:
            _scanning.discard(mac)

def trigger_deep_scan(ip: str, mac: str) -> None:
    if not _is_valid_ip(ip):
        return
    with _scan_lock:
        if mac in _scanning:
            return
        _scanning.add(mac)
    threading.Thread(target=_run_deep_scan_thread, args=(ip, mac), daemon=True).start()

# ---------------------------------------------------------------------------
# Device upsert
# ---------------------------------------------------------------------------
def upsert_seen_device(mac: str, ip: str, source: str) -> None:
    """
    Insert-or-update a device row.

    Also records the MAC as seen this interval so that update_presence_from_sweep
    does not falsely increment the miss count for devices the sniffer caught
    but the ARP sweep missed.
    """
    if not mac or mac == "00:00:00:00:00:00":
        return
    if not _is_valid_ip(ip):
        return

    # Mark this MAC as seen in the current sweep interval regardless of source
    with _sniffer_seen_lock:
        _sniffer_seen_this_interval.add(mac)

    mac_lock = _get_mac_lock(mac)
    with mac_lock:
        now     = datetime.now(timezone.utc)
        session = Session()
        try:
            existing   = session.get(Device, mac)
            is_new     = existing is None
            old_ip     = None if is_new else (existing.ip_address or "")
            was_online = None if is_new else existing.is_online
            ip_changed = (not is_new) and (old_ip != ip)

            if is_new:
                hostname = resolve_hostname(ip)
                vendor   = lookup_vendor(mac)
            else:
                # FIX: always attempt resolution for existing devices with no hostname.
                # Previously this path only called resolve_hostname for new devices,
                # so existing devices were permanently stuck showing the vendor name.
                if existing.hostname:
                    hostname = existing.hostname
                else:
                    hostname = resolve_hostname(ip)
                vendor   = existing.vendor

            safe_hostname = (hostname or '').replace("'", "''")

            if is_new:
                stmt = (
                    pg_insert(Device)
                    .values(
                        mac_address  = mac,
                        ip_address   = ip,
                        primary_ip   = ip,
                        hostname     = hostname,
                        vendor       = vendor,
                        custom_name  = None,
                        is_online    = True,
                        first_seen   = now,
                        last_seen    = now,
                        deep_scanned = False,
                        miss_count   = 0,
                        is_important = False,
                    )
                    .on_conflict_do_update(
                        index_elements=["mac_address"],
                        set_=dict(
                            ip_address = ip,
                            primary_ip = text(
                                "CASE WHEN devices.primary_ip IS NOT NULL "
                                "THEN devices.primary_ip ELSE EXCLUDED.primary_ip END"
                            ),
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
            else:
                stmt = (
                    pg_insert(Device)
                    .values(
                        mac_address  = mac,
                        ip_address   = ip,
                        primary_ip   = existing.primary_ip or ip,
                        hostname     = hostname,
                        vendor       = vendor,
                        custom_name  = existing.custom_name,
                        is_online    = True,
                        first_seen   = existing.first_seen or now,
                        last_seen    = now,
                        deep_scanned = existing.deep_scanned,
                        miss_count   = 0,
                        is_important = existing.is_important,
                    )
                    .on_conflict_do_update(
                        index_elements=["mac_address"],
                        set_=dict(
                            ip_address = ip,
                            primary_ip = text(
                                "CASE WHEN devices.primary_ip IS NOT NULL "
                                "THEN devices.primary_ip ELSE EXCLUDED.primary_ip END"
                            ),
                            is_online  = True,
                            last_seen  = now,
                            miss_count = 0,
                            # FIX: update hostname if we resolved one and device had none
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
                _write_event(mac, "joined", {"ip": ip, "vendor": vendor or "Unknown"})
                trigger_deep_scan(ip, mac)
            else:
                if not was_online:
                    print(f"[~] Back online via {source}: {ip} ({mac})", flush=True)
                    _write_event(mac, "online", {"ip": ip})
                if ip_changed:
                    primary = existing.primary_ip or old_ip
                    if ip == primary:
                        print(f"[~] IP reverted to primary {ip} for {mac}", flush=True)
                    else:
                        print(f"[~] Secondary IP seen {ip} for {mac} (primary={primary}, source={source})", flush=True)
                    _write_event(mac, "ip_change", {"old_ip": old_ip, "new_ip": ip,
                                                     "primary_ip": primary})

        except Exception as e:
            session.rollback()
            print(f"[DB] Upsert error {mac}: {e}", flush=True)
            return
        finally:
            session.close()

    is_brand_new_ip = record_ip(mac, ip)

    if ip_changed and is_brand_new_ip:
        session2 = Session()
        try:
            dev2 = session2.get(Device, mac)
            if dev2:
                scan_ip = dev2.primary_ip or ip
                if ip == scan_ip:
                    if dev2.deep_scanned:
                        print(f"[~] Primary IP changed {old_ip} -> {ip} for {mac} — invalidating deep scan", flush=True)
                        dev2.deep_scanned = False
                        dev2.scan_results = None
                        session2.commit()
                        trigger_deep_scan(scan_ip, mac)
                    else:
                        print(f"[~] Primary IP change for unscanned device {mac} — scan will use {scan_ip}", flush=True)
                else:
                    print(f"[~] Secondary IP {ip} recorded for {mac} — deep scan target remains {scan_ip}", flush=True)
        except Exception as e:
            session2.rollback()
            print(f"[DB] IP-change rescan error {mac}: {e}", flush=True)
        finally:
            session2.close()


def refresh_missing_hostnames() -> None:
    """
    After each sweep, attempt to resolve hostnames for any online device
    that still has none.  This is a best-effort background pass.
    """
    session = Session()
    try:
        unnamed = session.query(Device).filter(
            Device.is_online == True,
            Device.hostname  == None,
        ).all()
        updated = 0
        for dev in unnamed:
            scan_ip = dev.primary_ip or dev.ip_address
            if not _is_valid_ip(scan_ip):
                continue
            name = resolve_hostname(scan_ip)
            if name:
                dev.hostname = name
                updated += 1
                print(f"[hostname] Resolved: {scan_ip} -> {name}", flush=True)
        if updated:
            session.commit()
            print(f"[hostname] Resolved {updated} new hostnames this pass.", flush=True)
    except Exception as e:
        session.rollback()
        print(f"[hostname] Refresh error: {e}", flush=True)
    finally:
        session.close()

def bulk_reresolve_all() -> None:
    session = Session()
    try:
        all_devs = session.query(Device).all()
        updated = 0
        for dev in all_devs:
            scan_ip = dev.primary_ip or dev.ip_address
            if not _is_valid_ip(scan_ip):
                continue
            name = resolve_hostname(scan_ip)
            if name and name != dev.hostname:
                print(f"[hostname] Re-resolved: {scan_ip} -> {name}", flush=True)
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
    if not _is_valid_ip(ip):
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
    """
    Mark devices online/offline based on the current ARP sweep results,
    combined with anything the passive sniffer saw since the last sweep.

    FIX: The previous logic used `last_seen` timestamp as a proxy for sniffer
    activity, but that was unreliable — last_seen is updated for many reasons.
    We now use a dedicated `_sniffer_seen_this_interval` set that is populated
    by upsert_seen_device (for both sweep and sniffer sources) and cleared at
    the end of each sweep cycle.  A device is considered "seen" this cycle if
    it appears in either the sweep results OR the sniffer set.
    """
    now = datetime.now(timezone.utc)

    # Combine sweep results with anything the sniffer caught this cycle
    with _sniffer_seen_lock:
        seen_this_cycle = active_macs | _sniffer_seen_this_interval.copy()

    for dev in session.query(Device).all():
        if dev.mac_address in seen_this_cycle:
            dev.is_online  = True
            dev.miss_count = 0
        else:
            # Device was not seen at all this cycle — increment miss count
            dev.miss_count = (dev.miss_count or 0) + 1
            if dev.miss_count >= OFFLINE_MISS_THRESHOLD and dev.is_online:
                dev.is_online = False
                print(
                    f"[-] Offline: {dev.ip_address} ({dev.mac_address}) "
                    f"after {dev.miss_count} missed sweeps",
                    flush=True,
                )
                _write_event(dev.mac_address, "offline", {"ip": dev.ip_address})

# ---------------------------------------------------------------------------
# Probe HTTP API (port 8001)
# ---------------------------------------------------------------------------
probe_api = FastAPI(
    title="InSpectre Probe Internal API",
    version=VERSION,
    docs_url=None,
    redoc_url=None,
)
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
    return {"status": "ok", "version": VERSION, "dns_server": _DNS_SERVER}


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


@probe_api.get("/stream/vuln-scan/{ip}")
async def stream_vuln_scan(ip: str, scripts: str = ""):
    import ipaddress
    from vuln_scanner import run_vuln_scan, DEFAULT_VULN_SCRIPTS

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "Invalid IP address")

    effective_scripts = scripts.strip() if scripts.strip() else DEFAULT_VULN_SCRIPTS

    async def _gen():
        yield f"data: [INFO] Initiating vulnerability scan…\n\n"
        async for line in run_vuln_scan(ip, scripts=effective_scripts):
            safe = line.replace("\n", " ").replace("\r", "")
            yield f"data: {safe}\n\n"
        yield "data: --- done ---\n\n"
        yield "event: done\ndata: {}\n\n"

    return StreamingResponse(
        _gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def start_probe_api() -> None:
    print(f"[*] Probe API v{VERSION} listening on :{PROBE_API_PORT}", flush=True)
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
    print(f"[*] InSpectre Probe v{VERSION} starting...", flush=True)
    wait_for_db()
    init_db()

    print(
        f"[*] Scanning {IP_RANGE} on {INTERFACE} every {SCAN_INTERVAL}s\n"
        f"[*] Offline threshold: {OFFLINE_MISS_THRESHOLD} missed sweeps | OS confidence: {OS_CONFIDENCE_THRESHOLD}%",
        flush=True,
    )

    global _DNS_SERVER, _DNS_DETECTED
    _DNS_SERVER   = _detect_dns_server()
    _DNS_DETECTED = True
    print(f"[*] DNS server: {_DNS_SERVER or 'NOT DETECTED — set LAN_DNS_SERVER in docker-compose!'}", flush=True)

    threading.Thread(target=start_probe_api, daemon=True, name="probe-api").start()
    time.sleep(2)

    print("[*] Running startup hostname resolution pass...", flush=True)
    threading.Thread(target=bulk_reresolve_all, daemon=True, name="startup-resolve").start()

    threading.Thread(target=start_arp_sniffer, daemon=True, name="arp-sniffer").start()

    while True:
        # Reset the sniffer-seen set at the start of each sweep cycle so that
        # only activity from THIS interval counts toward online presence.
        with _sniffer_seen_lock:
            _sniffer_seen_this_interval.clear()

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
