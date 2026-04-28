import asyncio
import csv
import json
import os
import queue
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone, timedelta

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from scapy.all import ARP, Ether, sniff, srp, sendp
from sqlalchemy import (
    Boolean, Column, DateTime, Integer, JSON, String, UniqueConstraint,
    cast, create_engine, text,
)
from sqlalchemy.dialects.postgresql import JSONB, insert as pg_insert
from sqlalchemy.orm import declarative_base, sessionmaker
import traffic_monitor as _tm

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------
VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DATABASE_URL            = os.environ.get("DATABASE_URL",            "postgresql://admin:password123@localhost:5432/inspectre")
SCAN_INTERVAL           = int(os.environ.get("SCAN_INTERVAL",           60))
IP_RANGE                = os.environ.get("IP_RANGE",                "192.168.0.0/24")
INTERFACE               = os.environ.get("INTERFACE",               "eth0")
NMAP_ARGS               = os.environ.get("NMAP_ARGS",               "-O --osscan-limit -sV --version-intensity 5 -T4 -p-")
OS_CONFIDENCE_THRESHOLD = int(os.environ.get("OS_CONFIDENCE_THRESHOLD", 85))
OFFLINE_MISS_THRESHOLD  = int(os.environ.get("OFFLINE_MISS_THRESHOLD",   3))
SNIFFER_WORKERS         = int(os.environ.get("SNIFFER_WORKERS",          4))
PROBE_API_PORT          = int(os.environ.get("PROBE_API_PORT",         8001))
LAN_DNS_SERVER_ENV      = os.environ.get("LAN_DNS_SERVER", "").strip()
MDNS_INTERVAL_MINUTES   = int(os.environ.get("MDNS_INTERVAL_MINUTES", 120))  # default: 2 hours

# Scan scheduling globals (overridden by DB settings at each cycle)
NIGHTLY_SCAN_START      = int(os.environ.get("NIGHTLY_SCAN_START", 2))
NIGHTLY_SCAN_END        = int(os.environ.get("NIGHTLY_SCAN_END",   4))
OFFLINE_RESCAN_HOURS    = int(os.environ.get("OFFLINE_RESCAN_HOURS", 4))
BASELINE_SCAN_COUNT_THRESHOLD = 3   # loaded from settings each scan cycle
HOSTNAME_COOLDOWN_HOURS = 24        # fixed per design

# In-memory absent-port counters for baseline drift detection (resets on restart — acceptable)
# { mac: { port: consecutive_absent_count } }
_port_absent_counts: dict = {}
PING_COUNT    = 40
TRACE_MAX_HOP = 30

NUCLEI_TEMPLATE_UPDATE_INTERVAL = os.environ.get("NUCLEI_TEMPLATE_UPDATE_INTERVAL", "24h")
_last_nuclei_template_update: datetime | None = None


def _load_settings_from_db() -> None:
    """
    Override probe globals with values from the settings DB table.
    Called at startup (after DB is ready) and at the top of each scan cycle
    so that UI changes take effect without a container restart.
    Silently skips any key that is missing from the DB.
    """
    global SCAN_INTERVAL, IP_RANGE, NMAP_ARGS, OS_CONFIDENCE_THRESHOLD
    global OFFLINE_MISS_THRESHOLD, SNIFFER_WORKERS, NUCLEI_TEMPLATE_UPDATE_INTERVAL
    global NIGHTLY_SCAN_START, NIGHTLY_SCAN_END, OFFLINE_RESCAN_HOURS, BASELINE_SCAN_COUNT_THRESHOLD
    try:
        session = Session()
        try:
            rows = session.execute(text("SELECT key, value FROM settings")).fetchall()
        finally:
            session.close()
        db = {r[0]: r[1] for r in rows}
        if "scan_interval"           in db: SCAN_INTERVAL           = int(db["scan_interval"])
        if "ip_range"                in db: IP_RANGE                = db["ip_range"].strip()
        if "nmap_args"               in db: NMAP_ARGS               = db["nmap_args"].strip()
        if "os_confidence_threshold" in db: OS_CONFIDENCE_THRESHOLD = int(db["os_confidence_threshold"])
        if "offline_miss_threshold"  in db: OFFLINE_MISS_THRESHOLD  = int(db["offline_miss_threshold"])
        if "sniffer_workers"         in db: SNIFFER_WORKERS         = int(db["sniffer_workers"])
        if "nuclei_template_update_interval" in db:
            NUCLEI_TEMPLATE_UPDATE_INTERVAL = db["nuclei_template_update_interval"]
        if "nightly_scan_start"            in db: NIGHTLY_SCAN_START            = int(db["nightly_scan_start"])
        if "nightly_scan_end"              in db: NIGHTLY_SCAN_END              = int(db["nightly_scan_end"])
        if "offline_rescan_hours"          in db: OFFLINE_RESCAN_HOURS          = int(db["offline_rescan_hours"])
        if "baseline_scan_count_threshold" in db: BASELINE_SCAN_COUNT_THRESHOLD = int(db["baseline_scan_count_threshold"])
    except Exception as exc:
        print(f"[settings] DB load failed (using current values): {exc}", flush=True)


def ping_once(ip: str, timeout_s: int = 2) -> bool:
    if not _is_valid_ip(ip):
        return False
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout_s), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_s + 1,
        )
        return result.returncode == 0
    except Exception:
        return False


def apply_runtime_config(payload: dict) -> dict:
    global SCAN_INTERVAL, IP_RANGE, NMAP_ARGS, OS_CONFIDENCE_THRESHOLD, OFFLINE_MISS_THRESHOLD, SNIFFER_WORKERS, NUCLEI_TEMPLATE_UPDATE_INTERVAL

    changes = {}

    if "scan_interval" in payload:
        SCAN_INTERVAL = int(payload["scan_interval"])
        changes["scan_interval"] = SCAN_INTERVAL
    if "ip_range" in payload:
        IP_RANGE = str(payload["ip_range"]).strip()
        changes["ip_range"] = IP_RANGE
    if "nmap_args" in payload:
        NMAP_ARGS = str(payload["nmap_args"]).strip()
        changes["nmap_args"] = NMAP_ARGS
    if "os_confidence_threshold" in payload:
        OS_CONFIDENCE_THRESHOLD = int(payload["os_confidence_threshold"])
        changes["os_confidence_threshold"] = OS_CONFIDENCE_THRESHOLD
    if "offline_miss_threshold" in payload:
        OFFLINE_MISS_THRESHOLD = int(payload["offline_miss_threshold"])
        changes["offline_miss_threshold"] = OFFLINE_MISS_THRESHOLD
    if "sniffer_workers" in payload:
        changes["sniffer_workers"] = {
            "requested": int(payload["sniffer_workers"]),
            "applied": SNIFFER_WORKERS,
            "note": "worker count changes require probe restart",
        }
    if "nuclei_template_update_interval" in payload:
        NUCLEI_TEMPLATE_UPDATE_INTERVAL = str(payload["nuclei_template_update_interval"]).strip()
        changes["nuclei_template_update_interval"] = NUCLEI_TEMPLATE_UPDATE_INTERVAL

    return {
        "applied": True,
        "changes": changes,
        "effective": {
            "scan_interval": SCAN_INTERVAL,
            "ip_range": IP_RANGE,
            "nmap_args": NMAP_ARGS,
            "os_confidence_threshold": OS_CONFIDENCE_THRESHOLD,
            "offline_miss_threshold": OFFLINE_MISS_THRESHOLD,
            "sniffer_workers": SNIFFER_WORKERS,
            "nuclei_template_update_interval": NUCLEI_TEMPLATE_UPDATE_INTERVAL,
        },
    }

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
    is_ignored   = Column(Boolean, default=False, nullable=False)
    device_type_override    = Column(String,  nullable=True)
    hostname_last_attempted = Column(DateTime(timezone=True), nullable=True)
    deep_scan_last_run      = Column(DateTime(timezone=True), nullable=True)
    baseline_ports          = Column(JSONB,   nullable=True)
    baseline_scan_count     = Column(Integer, default=0, nullable=False)

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
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_type_override VARCHAR"))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS hostname_last_attempted TIMESTAMPTZ"))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS deep_scan_last_run TIMESTAMPTZ"))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS baseline_ports JSONB"))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS baseline_scan_count INTEGER NOT NULL DEFAULT 0"))
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
_MAC_VENDOR_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mac-vendors-export.csv")
_mac_vendor_db: dict[str, str] = {}

def _load_mac_vendor_db() -> None:
    try:
        with open(_MAC_VENDOR_DB_PATH, newline='', encoding='utf-8') as f:
            for row in csv.DictReader(f):
                prefix = row['Mac Prefix'].replace(':', '').lower()
                vendor = row['Vendor Name'].strip()
                if prefix and vendor:
                    _mac_vendor_db[prefix] = vendor
        print(f"[vendor] Loaded {len(_mac_vendor_db)} MAC prefixes from {_MAC_VENDOR_DB_PATH}", flush=True)
    except Exception as e:
        print(f"[vendor] Failed to load MAC vendor DB: {e}", flush=True)

def lookup_vendor(mac: str) -> str:
    norm = mac.replace(':', '').replace('-', '').lower()
    for length in (9, 7, 6):
        vendor = _mac_vendor_db.get(norm[:length])
        if vendor:
            return vendor
    return "Unknown"

# ---------------------------------------------------------------------------
# mDNS enrichment
# ---------------------------------------------------------------------------
def _mdns_browse() -> dict[str, dict]:
    """
    Discover mDNS services by querying the mDNS multicast group (RFC 6762).
    Uses raw UDP sockets — no avahi-daemon or D-Bus required.
    Returns {ip: {"mdns_name": str|None, "services": [str, ...]}}
    """
    import socket, struct, time

    MDNS_ADDR   = "224.0.0.251"
    MDNS_PORT   = 5353
    LISTEN_SECS = 4

    ptr_records: dict[str, list[str]] = {}
    srv_records: dict[str, str]        = {}
    a_records:   dict[str, str]        = {}

    def _decode_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
        if depth > 10:
            return "", offset
        labels: list[str] = []
        jumped = False
        jump_ret = offset
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            elif (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    break
                ptr = ((length & 0x3F) << 8) | data[offset + 1]
                if not jumped:
                    jump_ret = offset + 2
                jumped = True
                suffix, _ = _decode_name(data, ptr, depth + 1)
                if suffix:
                    labels.append(suffix)
                break
            else:
                end = offset + 1 + length
                if end > len(data):
                    break
                labels.append(data[offset + 1:end].decode("utf-8", errors="replace"))
                offset = end
        return ".".join(labels), (jump_ret if jumped else offset)

    def _parse_packet(data: bytes):
        try:
            if len(data) < 12:
                return
            flags = struct.unpack_from(">H", data, 2)[0]
            if not (flags & 0x8000):
                return
            qdcount, ancount, nscount, arcount = struct.unpack_from(">HHHH", data, 4)
            offset = 12
            for _ in range(qdcount):
                _, offset = _decode_name(data, offset)
                offset += 4
            for _ in range(ancount + nscount + arcount):
                if offset + 10 > len(data):
                    break
                name, offset = _decode_name(data, offset)
                if offset + 10 > len(data):
                    break
                rtype, _, _, rdlen = struct.unpack_from(">HHIH", data, offset)
                offset += 10
                rdata_start = offset
                offset += rdlen
                if rdlen == 0 or rdata_start + rdlen > len(data):
                    continue
                name_l = name.lower().rstrip(".")
                if rtype == 12:  # PTR
                    target, _ = _decode_name(data, rdata_start)
                    tgt = target.lower().rstrip(".")
                    if tgt:
                        lst = ptr_records.setdefault(name_l, [])
                        if tgt not in lst:
                            lst.append(tgt)
                elif rtype == 33 and rdlen >= 7:  # SRV
                    tgt, _ = _decode_name(data, rdata_start + 6)
                    srv_records[name_l] = tgt.lower().rstrip(".")
                elif rtype == 1 and rdlen == 4:  # A
                    ip = ".".join(str(b) for b in data[rdata_start:rdata_start + 4])
                    a_records[name_l] = ip
        except Exception:
            pass

    def _build_query(*qnames: str) -> bytes:
        questions = b""
        for qname in qnames:
            for label in qname.rstrip(".").split("."):
                lb = label.encode()
                questions += bytes([len(lb)]) + lb
            questions += b"\x00"
            questions += struct.pack(">HH", 12, 1)  # PTR, IN
        return struct.pack(">HHHHHH", 0, 0, len(qnames), 0, 0, 0) + questions

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        sock.bind(("", MDNS_PORT))
        mreq = struct.pack("4sL", socket.inet_aton(MDNS_ADDR), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(0.5)

        service_types = [
            "_services._dns-sd._udp.local",
            "_googlecast._tcp.local",
            "_airplay._tcp.local",
            "_raop._tcp.local",
            "_printer._tcp.local",
            "_ipp._tcp.local",
            "_http._tcp.local",
            "_https._tcp.local",
            "_smb._tcp.local",
            "_afpovertcp._tcp.local",
            "_ssh._tcp.local",
            "_hap._tcp.local",
            "_companion-link._tcp.local",
            "_amzn-wplay._tcp.local",
        ]
        for i in range(0, len(service_types), 3):
            try:
                sock.sendto(_build_query(*service_types[i:i + 3]), (MDNS_ADDR, MDNS_PORT))
            except Exception:
                pass

        deadline = time.monotonic() + LISTEN_SECS
        while time.monotonic() < deadline:
            try:
                data, _ = sock.recvfrom(8192)
                _parse_packet(data)
            except socket.timeout:
                continue
            except Exception:
                break
    except PermissionError as e:
        print(f"[mdns] permission denied (need privileged/host network): {e}", flush=True)
        return {}
    except Exception as e:
        print(f"[mdns] socket error: {e}", flush=True)
        return {}
    finally:
        if sock:
            try:
                mreq = struct.pack("4sL", socket.inet_aton(MDNS_ADDR), socket.INADDR_ANY)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass

    result: dict[str, dict] = {}

    # Map A records: hostname → IP
    for hostname, ip in a_records.items():
        if _is_valid_ip(ip):
            entry = result.setdefault(ip, {"mdns_name": None, "services": []})
            if not entry["mdns_name"]:
                entry["mdns_name"] = hostname.removesuffix(".local")

    # Map PTR → SRV → A to associate service types with IPs
    for svc_type, instances in ptr_records.items():
        if "._dns-sd." in svc_type:
            continue
        parts = svc_type.removesuffix(".local").split(".")
        svc_label = ".".join(parts[-2:]) if len(parts) >= 2 else svc_type.removesuffix(".local")
        for instance in instances:
            hostname = srv_records.get(instance)
            ip = None
            if hostname:
                ip = a_records.get(hostname) or a_records.get(hostname + ".local")
            if ip and _is_valid_ip(ip):
                entry = result.setdefault(ip, {"mdns_name": None, "services": []})
                if svc_label not in entry["services"]:
                    entry["services"].append(svc_label)

    if result:
        print(f"[mdns] Discovered {len(result)} device(s) via mDNS", flush=True)
    return result


def _apply_mdns_enrichment(mdns_data: dict[str, dict]) -> None:
    """Update device records with mDNS name and service list."""
    if not mdns_data:
        return
    session = Session()
    try:
        updated = 0
        for ip, info in mdns_data.items():
            dev = session.query(Device).filter(Device.ip_address == ip).first()
            if not dev:
                continue
            changed = False
            if info.get("mdns_name") and not dev.hostname:
                dev.hostname = info["mdns_name"]
                changed = True
            if info.get("services"):
                scan = dict(dev.scan_results) if dev.scan_results else {}
                existing = scan.get("mdns_services", [])
                merged = list(dict.fromkeys(existing + info["services"]))  # dedup, preserve order
                if merged != existing:
                    scan["mdns_services"] = merged
                    dev.scan_results = scan
                    changed = True
            if changed:
                updated += 1
        if updated:
            session.commit()
            print(f"[mdns] Enriched {updated} device(s)", flush=True)
    except Exception as e:
        session.rollback()
        print(f"[mdns] Enrichment error: {e}", flush=True)
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Standalone mDNS background loop (Change 3)
# ---------------------------------------------------------------------------
def _mdns_loop() -> None:
    """Scheduled background thread: runs _mdns_browse every MDNS_INTERVAL_MINUTES minutes.
    Independent of the main ARP sweep loop — never triggered per device join."""
    interval_s = MDNS_INTERVAL_MINUTES * 60
    print(f"[mdns] Scheduled loop started (interval={MDNS_INTERVAL_MINUTES}m)", flush=True)
    while True:
        time.sleep(interval_s)
        try:
            print(f"[mdns] Running scheduled browse (interval={MDNS_INTERVAL_MINUTES}m)", flush=True)
            mdns_data = _mdns_browse()
            if mdns_data:
                _apply_mdns_enrichment(mdns_data)
        except Exception as e:
            print(f"[mdns] Loop error: {e}", flush=True)


# ---------------------------------------------------------------------------
# ARP sweep
# ---------------------------------------------------------------------------
def arp_scan(interface: str, ip_range: str) -> list[dict]:
    pkt    = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    # Increased timeout from 3s → 5s and added retry=2 so slow/sleeping
    # devices (IoT, phones, printers) have more time to respond.
    result = srp(pkt, iface=interface, timeout=5, retry=2, verbose=0)[0]
    return [{"ip": rcv.psrc, "mac": rcv.hwsrc.lower()} for _, rcv in result]

# ---------------------------------------------------------------------------
# TCP port sweep (all 65535 ports, pure Python)
# ---------------------------------------------------------------------------

# Cap simultaneous deep scans so 21 newly-detected devices don't all scan at once
_deep_scan_semaphore = threading.Semaphore(3)


def _port_severity(device) -> str:
    """Return severity for a port_opened event based on device type and importance."""
    dtype = (getattr(device, 'device_type_override', None) or '').lower()
    is_important = bool(getattr(device, 'is_important', False))
    iot_types = {'iot', 'camera', 'smart_plug', 'smart_home', 'console'}
    server_types = {'server', 'nas'}
    if not dtype or dtype in iot_types:
        return 'critical'
    if is_important or dtype in server_types:
        return 'warning'
    return 'info'


def _fast_port_sweep(ip: str) -> list[int]:
    """
    Pure-Python TCP connect sweep of all 65535 ports.
    Uses a thread pool — no nmap, no raw sockets, no config file dependencies.
    300 workers × 0.5 s timeout ≈ 60-120 s per host on a typical LAN.
    """
    import concurrent.futures
    import socket as _socket

    def _check(port: int) -> int | None:
        try:
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            s.close()
            return port if result == 0 else None
        except Exception:
            return None

    open_ports: list[int] = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=300) as ex:
            for port in concurrent.futures.as_completed(
                {ex.submit(_check, p): p for p in range(1, 65536)}
            ):
                r = port.result()
                if r is not None:
                    open_ports.append(r)
    except Exception as exc:
        print(f"[fast-scan] socket sweep error for {ip}: {exc}", flush=True)
    return sorted(open_ports)


# ---------------------------------------------------------------------------
# Port baseline logic (Change 4)
# ---------------------------------------------------------------------------
def _update_port_baseline(mac: str, ip: str, current_ports: list[int]) -> None:
    """Compare current port set against confirmed baseline; write port_opened/port_closed events."""
    current_set = frozenset(current_ports)
    session = Session()
    try:
        device = session.get(Device, mac)
        if not device:
            return

        baseline    = device.baseline_ports       # list[int] or None
        scan_count  = device.baseline_scan_count or 0
        threshold   = BASELINE_SCAN_COUNT_THRESHOLD

        if baseline is None:
            # No baseline yet — seed it
            device.baseline_ports      = sorted(current_set)
            device.baseline_scan_count = 1
            session.commit()
            print(f"[baseline] {ip} ({mac}): baseline seeded with {len(current_set)} port(s)", flush=True)
            return

        baseline_set = frozenset(baseline)

        if current_set == baseline_set:
            # Consistent with baseline: increment confirmation count
            device.baseline_scan_count = scan_count + 1
            session.commit()
            if scan_count + 1 == threshold:
                print(f"[baseline] {ip} ({mac}): baseline confirmed after {threshold} matching scans", flush=True)
            return

        if scan_count < threshold:
            # Baseline not yet confirmed and ports changed: reset tentative baseline
            device.baseline_ports      = sorted(current_set)
            device.baseline_scan_count = 1
            session.commit()
            print(f"[baseline] {ip} ({mac}): tentative baseline reset (not yet confirmed)", flush=True)
            return

        # --- Baseline is confirmed; check for drift ---
        severity    = _port_severity(device)
        new_ports   = current_set - baseline_set
        gone_ports  = baseline_set - current_set

        for port in sorted(new_ports):
            _write_event(mac, "port_opened", {"port": port, "severity": severity})
            print(f"[baseline] NEW port vs baseline on {ip}: port {port} severity={severity}", flush=True)

        for port in sorted(gone_ports):
            absent_map = _port_absent_counts.setdefault(mac, {})
            absent_map[port] = absent_map.get(port, 0) + 1
            if absent_map[port] >= 2:
                _write_event(mac, "port_closed", {"port": port, "severity": "info"})
                print(f"[baseline] CLOSED port vs baseline on {ip}: port {port}", flush=True)

        # Reset absent counters for ports that re-appeared
        if mac in _port_absent_counts:
            for port in list(_port_absent_counts[mac].keys()):
                if port in current_set:
                    del _port_absent_counts[mac][port]

    except Exception as e:
        session.rollback()
        print(f"[baseline] Error for {mac}: {e}", flush=True)
    finally:
        session.close()


# ---------------------------------------------------------------------------
# TCP port scan + scan result storage
# ---------------------------------------------------------------------------
def _run_deep_scan_thread(ip: str, mac: str) -> None:
    with _deep_scan_semaphore:
        try:
            t0 = time.monotonic()
            print(f"[scan] TCP sweep starting: {ip} ({mac})", flush=True)
            fast_ports = _fast_port_sweep(ip)
            elapsed = round(time.monotonic() - t0, 1)
            print(f"[scan] {len(fast_ports)} open TCP port(s) on {ip} in {elapsed}s", flush=True)

            scan_results = {
                "scanned_at":    datetime.now(timezone.utc).isoformat(),
                "open_ports":    [
                    {"port": p, "proto": "tcp", "service": "", "product": "", "version": ""}
                    for p in fast_ports
                ],
                "os_matches":    [],
                "hostnames":     [],
                "pipeline_stage": "ports_done",
            }

            session = Session()
            try:
                device = session.get(Device, mac)
                if device:
                    old_scan  = device.scan_results or {}
                    old_ports = {(p.get("port"), p.get("proto")) for p in (old_scan.get("open_ports") or [])}
                    new_ports = {(p.get("port"), p.get("proto")) for p in scan_results["open_ports"]}
                    is_rescan = bool(old_scan)

                    device.scan_results     = scan_results
                    device.deep_scanned     = True
                    device.deep_scan_last_run = datetime.now(timezone.utc)
                    session.commit()

                    _write_event(mac, "scan_complete", {"ports": len(fast_ports), "os": None})

                    if is_rescan and old_ports != new_ports:
                        added   = [{"port": p[0], "proto": p[1]} for p in (new_ports - old_ports)]
                        removed = [{"port": p[0], "proto": p[1]} for p in (old_ports - new_ports)]
                        _write_event(mac, "port_change", {"added": added, "removed": removed})
                        print(f"[scan] Port change on {ip} ({mac}): +{len(added)} -{len(removed)}", flush=True)
            except Exception as e:
                session.rollback()
                print(f"[DB] Scan save error {mac}: {e}", flush=True)
            finally:
                session.close()

            # Stage 3: Nerva service fingerprinting (automatic after port sweep)
            threading.Thread(
                target=_run_nerva_fingerprint,
                args=(ip, mac, fast_ports),
                daemon=True,
                name=f"nerva-{mac}",
            ).start()

            # Stage 4: Port baseline & drift alerting (Change 4)
            _update_port_baseline(mac, ip, fast_ports)

        finally:
            with _scan_lock:
                _scanning.discard(mac)

def trigger_deep_scan(ip: str, mac: str) -> None:
    if not _is_valid_ip(ip):
        return
    # Skip deep scan for ignored devices
    try:
        _s = Session()
        try:
            _dev = _s.get(Device, mac)
            if _dev and getattr(_dev, 'is_ignored', False):
                return
        finally:
            _s.close()
    except Exception:
        pass
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

            # Track how long device was offline (used after commit to decide rescan)
            offline_duration_s = 0.0
            if not is_new and not was_online and existing.last_seen:
                offline_duration_s = (now - existing.last_seen).total_seconds()

            # --- DB-gated hostname resolution (Change 1) ---
            hostname_resolution_attempted = False
            if is_new:
                hostname = resolve_hostname(ip)
                hostname_resolution_attempted = True
                vendor   = lookup_vendor(mac)
            else:
                if existing.hostname:
                    # Already resolved — never re-resolve automatically
                    hostname = existing.hostname
                else:
                    last_att = existing.hostname_last_attempted
                    cooldown_elapsed = (
                        last_att is None or
                        (now - last_att).total_seconds() >= HOSTNAME_COOLDOWN_HOURS * 3600
                    )
                    if cooldown_elapsed:
                        hostname = resolve_hostname(ip)
                        hostname_resolution_attempted = True
                    else:
                        hostname = None
                vendor = existing.vendor

            safe_hostname = (hostname or '').replace("'", "''")

            if is_new:
                stmt = (
                    pg_insert(Device)
                    .values(
                        mac_address              = mac,
                        ip_address               = ip,
                        primary_ip               = ip,
                        hostname                 = hostname,
                        vendor                   = vendor,
                        custom_name              = None,
                        is_online                = True,
                        first_seen               = now,
                        last_seen                = now,
                        deep_scanned             = False,
                        miss_count               = 0,
                        is_important             = False,
                        hostname_last_attempted  = now,
                        baseline_scan_count      = 0,
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
                            last_seen  = text("CASE WHEN devices.is_online = false THEN NOW() ELSE devices.last_seen END"),
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
                            # When device was offline and comes back at a different IP that's
                            # a permanent DHCP reassignment — adopt new IP as primary.
                            # While online a new IP is just a secondary — keep existing primary.
                            primary_ip = text(
                                "CASE "
                                "WHEN devices.is_online = false THEN EXCLUDED.primary_ip "
                                "WHEN devices.primary_ip IS NOT NULL THEN devices.primary_ip "
                                "ELSE EXCLUDED.primary_ip END"
                            ),
                            is_online  = True,
                            last_seen  = text("CASE WHEN devices.is_online = false THEN NOW() ELSE devices.last_seen END"),
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
                _write_event(mac, "joined", {"ip": ip, "vendor": vendor or "Unknown"})
                trigger_deep_scan(ip, mac)
            else:
                if not was_online:
                    print(f"[~] Back online via {source}: {ip} ({mac})", flush=True)
                    _write_event(mac, "online", {"ip": ip})
                if ip_changed:
                    primary = existing.primary_ip or old_ip
                    if ip == primary or not was_online:
                        # Device came back from offline at new IP → primary updated to new IP
                        if not was_online and ip != primary:
                            print(f"[~] Primary IP updated {primary} → {ip} for {mac} (came back from offline)", flush=True)
                            _write_event(mac, "primary_ip_changed", {"old_ip": primary, "new_ip": ip})
                        else:
                            print(f"[~] IP reverted to primary {ip} for {mac}", flush=True)
                    else:
                        print(f"[~] Secondary IP seen {ip} for {mac} (primary={primary}, source={source})", flush=True)
                    _write_event(mac, "ip_change", {"old_ip": old_ip, "new_ip": ip,
                                                     "primary_ip": ip if not was_online else primary})

        except Exception as e:
            session.rollback()
            print(f"[DB] Upsert error {mac}: {e}", flush=True)
            return
        finally:
            session.close()

    # Persist hostname_last_attempted if we attempted resolution this call
    if hostname_resolution_attempted:
        sess_hn = Session()
        try:
            sess_hn.execute(
                text("UPDATE devices SET hostname_last_attempted = NOW() WHERE mac_address = :mac"),
                {"mac": mac},
            )
            sess_hn.commit()
        except Exception as e:
            sess_hn.rollback()
            print(f"[hostname] Failed to update hostname_last_attempted for {mac}: {e}", flush=True)
        finally:
            sess_hn.close()

    # Offline-return rescan: if device was offline for > OFFLINE_RESCAN_HOURS, invalidate scan
    if not is_new and not was_online and offline_duration_s >= OFFLINE_RESCAN_HOURS * 3600:
        sess_or = Session()
        try:
            dev_or = sess_or.get(Device, mac)
            if dev_or and dev_or.deep_scanned:
                print(
                    f"[scan] Device {ip} ({mac}) was offline {offline_duration_s/3600:.1f}h — "
                    "invalidating deep scan for rescan",
                    flush=True,
                )
                dev_or.deep_scanned = False
                dev_or.scan_results = None
                sess_or.commit()
        except Exception as e:
            sess_or.rollback()
            print(f"[DB] Offline-return rescan error {mac}: {e}", flush=True)
        finally:
            sess_or.close()

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


def refresh_missing_vendors() -> None:
    if not _mac_vendor_db:
        return
    session = Session()
    try:
        unvendored = session.query(Device).filter(
            (Device.vendor == None) | (Device.vendor == 'Unknown')
        ).all()
        updated = 0
        for dev in unvendored:
            vendor = lookup_vendor(dev.mac_address)
            if vendor and vendor != 'Unknown':
                dev.vendor = vendor
                updated += 1
                print(f"[vendor] Resolved: {dev.mac_address} -> {vendor}", flush=True)
        if updated:
            session.commit()
            print(f"[vendor] Resolved {updated} vendor(s) from local DB.", flush=True)
    except Exception as e:
        session.rollback()
        print(f"[vendor] Refresh error: {e}", flush=True)
    finally:
        session.close()

def refresh_missing_hostnames() -> None:
    """Resolve hostnames for online devices that have none and whose cooldown has elapsed."""
    now = datetime.now(timezone.utc)
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
            last_att = dev.hostname_last_attempted
            cooldown_elapsed = (
                last_att is None or
                (now - last_att).total_seconds() >= HOSTNAME_COOLDOWN_HOURS * 3600
            )
            if not cooldown_elapsed:
                continue
            name = resolve_hostname(scan_ip)
            # Always update hostname_last_attempted (prevents tight retry loops)
            dev.hostname_last_attempted = now
            if name:
                dev.hostname = name
                updated += 1
                print(f"[hostname] Resolved: {scan_ip} -> {name}", flush=True)
        if updated or True:  # commit timestamp updates even on miss
            session.commit()
            if updated:
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
            if dev.hostname:
                continue
            name = resolve_hostname(scan_ip)
            if name and name != dev.hostname:
                print(f"[hostname] Re-resolved: {scan_ip} -> {name}", flush=True)
                dev.hostname = name
                updated += 1
            elif not name:
                _hostname_failed.add(scan_ip)
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

    When a device first hits the offline miss threshold, do a one-shot ICMP
    confirmation against its current scan IP before marking it offline. This
    avoids false offline events for devices that go ARP-quiet temporarily.
    """
    now = datetime.now(timezone.utc)

    with _sniffer_seen_lock:
        seen_this_cycle = active_macs | _sniffer_seen_this_interval.copy()

    for dev in session.query(Device).all():
        if dev.mac_address in seen_this_cycle:
            dev.is_online = True
            dev.miss_count = 0
            continue

        dev.miss_count = (dev.miss_count or 0) + 1

        if not dev.is_online:
            continue

        if dev.miss_count < OFFLINE_MISS_THRESHOLD:
            continue

        confirm_ip = dev.primary_ip or dev.ip_address
        if confirm_ip and ping_once(confirm_ip, timeout_s=2):
            dev.is_online = True
            dev.miss_count = 0
            print(f"[~] Offline check rescued by ping: {confirm_ip} ({dev.mac_address})", flush=True)
            continue

        dev.is_online = False
        print(
            f"[-] Offline: {confirm_ip or dev.ip_address} ({dev.mac_address}) "
            f"after {dev.miss_count} missed sweeps + ping confirm",
            flush=True,
        )
        _write_event(dev.mac_address, "offline", {"ip": confirm_ip or dev.ip_address})

# ---------------------------------------------------------------------------
# ARP blocking (internet cut-off via ARP spoofing)
# ---------------------------------------------------------------------------
_blocked_devices: dict[str, dict] = {}
_blocked_lock = threading.Lock()


def _get_mac_for_ip(ip: str) -> str | None:
    """Send a unicast ARP request and return the MAC, or None if unreachable."""
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        result = srp(pkt, iface=INTERFACE, timeout=3, retry=1, verbose=0)[0]
        if result:
            return result[0][1].hwsrc.lower()
    except Exception as e:
        print(f"[block] MAC lookup failed for {ip}: {e}", flush=True)
    return None


def _block_table_id(target_ip: str) -> int:
    import ipaddress
    return 10000 + (int(ipaddress.ip_address(target_ip)) % 50000)


def _ip_rule_block(target_ip: str) -> None:
    """
    Policy-routing blackhole: packets forwarded from target_ip are sent to a
    dedicated routing table that has only a blackhole default route.
    Works with iproute2 alone — no iptables required.
    """
    table = _block_table_id(target_ip)
    steps = [
        ["ip", "route", "replace", "blackhole", "default", "table", str(table)],
        ["ip", "rule",  "add", "from", target_ip, "table", str(table), "priority", "100"],
    ]
    for cmd in steps:
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=5)
            print(f"[block] {' '.join(cmd)}: {'OK' if r.returncode == 0 else r.stderr.decode().strip()}", flush=True)
        except Exception as e:
            print(f"[block] ip rule error: {e}", flush=True)


def _ip_rule_unblock(target_ip: str) -> None:
    table = _block_table_id(target_ip)
    for cmd in [
        ["ip", "rule",  "del", "from", target_ip, "table", str(table), "priority", "100"],
        ["ip", "route", "del", "blackhole", "default", "table", str(table)],
    ]:
        try:
            subprocess.run(cmd, capture_output=True, timeout=5)
        except Exception:
            pass


def _iptables(action: str, target_ip: str) -> None:
    """
    iptables FORWARD DROP as defence-in-depth alongside the ip-rule blackhole.
    Uses -I (insert at top) to block, -D to remove.  -D errors are silenced
    because the rule may already be gone after a container restart.
    """
    for direction in ["-s", "-d"]:
        cmd = ["iptables", action, "FORWARD", direction, target_ip, "-j", "DROP"]
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=5)
            if r.returncode == 0:
                print(f"[block] {' '.join(cmd)}: OK", flush=True)
            elif action != "-D":
                print(f"[block] {' '.join(cmd)}: {r.stderr.decode().strip()}", flush=True)
        except FileNotFoundError:
            if action == "-I":
                print("[block] iptables not found — skipping (ip rule is primary)", flush=True)
        except Exception as e:
            if action == "-I":
                print(f"[block] iptables error: {e}", flush=True)


def _arp_spoof_loop(
    target_ip: str, target_mac: str,
    gateway_ip: str, gateway_mac: str,
    iface: str, stop_event: threading.Event,
) -> None:
    """
    Blocks internet access for target_ip using two complementary mechanisms:
    1. ARP spoofing — continuously tells both the target and the gateway that
       the other party lives at the probe's MAC, so all traffic is redirected
       through this host.
    2. iptables FORWARD DROP — since Docker hosts have IP forwarding enabled,
       the redirected packets would otherwise be forwarded to the real gateway.
       The iptables rules ensure they are dropped instead.
    Both are reversed cleanly when the stop_event is set.
    """
    print(
        f"[block] Starting block: {target_ip} ({target_mac}), "
        f"gateway {gateway_ip} ({gateway_mac})",
        flush=True,
    )

    # Install drop rules before spoofing starts so no packets slip through
    _ip_rule_block(target_ip)
    _iptables("-I", target_ip)

    # Poison packets (hwsrc left unset → Scapy uses the interface's own MAC)
    poison_target = Ether(dst=target_mac) / ARP(
        op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip,
    )
    poison_gateway = Ether(dst=gateway_mac) / ARP(
        op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip,
    )

    while not stop_event.is_set():
        try:
            sendp(poison_target,  iface=iface, verbose=0)
            sendp(poison_gateway, iface=iface, verbose=0)
        except Exception as e:
            print(f"[block] send error: {e}", flush=True)
        stop_event.wait(timeout=2)

    # Remove drop rules before restoring ARP so connectivity comes back cleanly
    _ip_rule_unblock(target_ip)
    _iptables("-D", target_ip)

    # Restore correct ARP entries so both devices update their caches
    print(f"[block] Restoring ARP for {target_ip}", flush=True)
    restore_target = Ether(dst=target_mac) / ARP(
        op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac,
    )
    restore_gateway = Ether(dst=gateway_mac) / ARP(
        op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac,
    )
    for _ in range(5):
        try:
            sendp(restore_target,  iface=iface, verbose=0)
            sendp(restore_gateway, iface=iface, verbose=0)
        except Exception:
            pass
        time.sleep(0.5)
    print(f"[block] Block lifted for {target_ip}", flush=True)


# ---------------------------------------------------------------------------
# Nerva service fingerprinting (Stage 3 of scan pipeline)
# ---------------------------------------------------------------------------

def _parse_nerva_output(output: str) -> list[dict]:
    """Parse Nerva URI output into service records: [{port, service, protocol, tls}].
    Handles Nerva's ' (tls)' annotation on TLS lines, e.g. 'https://ip:443 (tls)'."""
    services: list[dict] = []
    seen_ports: set[int] = set()
    for line in output.strip().splitlines():
        line = line.strip()
        if not line or "://" not in line:
            continue
        try:
            scheme, rest = line.split("://", 1)
            # Strip path component and any trailing annotations like " (tls)"
            host_part = rest.split("/")[0].split(" ")[0]
            if ":" not in host_part:
                continue
            _, port_str = host_part.rsplit(":", 1)
            port = int(port_str)
            if port in seen_ports:
                continue
            seen_ports.add(port)
            service = scheme.lower()
            tls = service in ("https", "mqtts", "ldaps", "ftps", "imaps", "pop3s", "smtps", "rediss", "wss")
            services.append({"port": port, "service": service, "protocol": "tcp", "tls": tls})
        except (ValueError, IndexError):
            continue
    return services


def _run_nerva_fingerprint(ip: str, mac: str, open_ports: list[int]) -> None:
    """Pipe open host:port pairs through Nerva and store service fingerprints.

    Always advances pipeline_stage to 'services_done' — even if Nerva is absent,
    returns no output, or the port list is empty — so the UI never spins forever.
    """
    services: list[dict] = []

    if open_ports:
        input_data = "\n".join(f"{ip}:{p}" for p in open_ports)
        try:
            # Scale timeout with port count — each port can take a few seconds to probe
            nerva_timeout = max(300, len(open_ports) * 4)
            result = subprocess.run(
                ["nerva"],
                input=input_data,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # merge stderr so we capture regardless of which fd Nerva uses
                text=True,
                timeout=nerva_timeout,
            )
            output = (result.stdout or "").strip()
            print(f"[nerva] raw output for {ip} ({len(output)} chars, exit={result.returncode}): {output[:300]}", flush=True)
            if output:
                services = _parse_nerva_output(output)
                print(
                    f"[nerva] {ip} ({mac}): {len(services)} service(s) — "
                    + ", ".join(f"{s['service']}:{s['port']}" for s in services),
                    flush=True,
                )
            if result.returncode != 0:
                print(f"[nerva] Non-zero exit ({result.returncode}) for {ip}", flush=True)
        except FileNotFoundError:
            print(f"[nerva] Binary not found — service fingerprinting skipped for {ip}", flush=True)
        except subprocess.TimeoutExpired:
            print(f"[nerva] Timeout fingerprinting {ip}", flush=True)
        except Exception as e:
            print(f"[nerva] Error for {ip}: {e}", flush=True)

    # Always persist — advances pipeline_stage to 'services_done' regardless of outcome
    session = Session()
    try:
        device = session.get(Device, mac)
        if device:
            scan = dict(device.scan_results or {})
            scan["services"] = services
            scan["pipeline_stage"] = "services_done"
            # Merge Nerva service names back into open_ports records
            if services:
                port_map = {s["port"]: s for s in services}
                scan["open_ports"] = [
                    {**p,
                     "service": port_map[p["port"]].get("service", p.get("service", "")),
                     "tls":     port_map[p["port"]].get("tls", False)}
                    if p.get("port") in port_map else p
                    for p in (scan.get("open_ports") or [])
                ]
            device.scan_results = scan
            session.commit()
            if services:
                _write_event(mac, "service_fingerprint_complete", {
                    "service_count": len(services),
                    "services": [f"{s['service']}:{s['port']}" for s in services[:20]],
                })
    except Exception as e:
        session.rollback()
        print(f"[nerva] DB save error {mac}: {e}", flush=True)
    finally:
        session.close()

    # Stage 3b: optional nmap -sV version enrichment
    if open_ports:
        threading.Thread(
            target=_run_nmap_version_scan,
            args=(ip, mac, open_ports),
            daemon=True,
            name=f"nmap-ver-{mac}",
        ).start()


# ---------------------------------------------------------------------------
# nmap version scan (Stage 3b — runs after Nerva)
# ---------------------------------------------------------------------------
def _run_nmap_version_scan(ip: str, mac: str, open_ports: list[int]) -> None:
    """Run nmap -sV on known open ports to get service banners and versions."""
    if not open_ports:
        return
    port_str = ",".join(str(p) for p in open_ports[:50])
    try:
        result = subprocess.run(
            ["nmap", "-sV", "--version-intensity", "5", "-T4",
             "-p", port_str, "--open", "-oX", "-", ip],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return
        import xml.etree.ElementTree as ET
        root = ET.fromstring(result.stdout)
        version_map: dict[int, dict] = {}
        for host in root.findall("host"):
            for port_el in host.findall("ports/port"):
                portid = int(port_el.get("portid", 0))
                svc = port_el.find("service")
                if svc is not None:
                    version_map[portid] = {
                        "service":   svc.get("name", ""),
                        "product":   svc.get("product", ""),
                        "version":   svc.get("version", ""),
                        "extrainfo": svc.get("extrainfo", ""),
                        "cpe":       svc.get("cpe", ""),
                    }
        if not version_map:
            return

        session = Session()
        try:
            device = session.get(Device, mac)
            if device and device.scan_results:
                scan = dict(device.scan_results)
                updated_ports = []
                for p in (scan.get("open_ports") or []):
                    port_num = p.get("port")
                    if port_num in version_map:
                        p = dict(p)
                        p.update(version_map[port_num])
                    updated_ports.append(p)
                scan["open_ports"] = updated_ports
                scan["pipeline_stage"] = "versions_done"
                device.scan_results = scan
                session.commit()
                _write_event(mac, "version_scan_complete", {
                    "versioned_ports": len(version_map)
                })
                print(f"[nmap-version] {ip} ({mac}): {len(version_map)} port(s) versioned", flush=True)
        except Exception as e:
            session.rollback()
            print(f"[nmap-version] DB save error {mac}: {e}", flush=True)
        finally:
            session.close()

    except FileNotFoundError:
        print(f"[nmap-version] nmap not found — skipping version scan for {ip}", flush=True)
    except subprocess.TimeoutExpired:
        print(f"[nmap-version] Timeout for {ip}", flush=True)
    except Exception as e:
        print(f"[nmap-version] Error for {ip}: {e}", flush=True)


# ---------------------------------------------------------------------------
# Nuclei template updater
# ---------------------------------------------------------------------------
def _nuclei_template_update_loop() -> None:
    """Background thread that periodically runs nuclei -update-templates."""
    global _last_nuclei_template_update
    time.sleep(120)  # startup grace period
    _update_intervals = {"12h": 43200, "24h": 86400, "48h": 172800, "weekly": 604800}
    while True:
        try:
            session = Session()
            try:
                row = session.execute(
                    text("SELECT value FROM settings WHERE key = 'nuclei_template_update_interval'")
                ).fetchone()
                interval_str = row[0] if row else NUCLEI_TEMPLATE_UPDATE_INTERVAL
            finally:
                session.close()

            if interval_str != "disabled":
                interval = _update_intervals.get(interval_str, 86400)
                now = datetime.now(timezone.utc)
                if _last_nuclei_template_update is None or (now - _last_nuclei_template_update).total_seconds() >= interval:
                    print(f"[nuclei] Updating templates (interval: {interval_str})…", flush=True)
                    result = subprocess.run(
                        ["nuclei", "-update-templates"],
                        capture_output=True, text=True, timeout=300,
                    )
                    if result.stdout:
                        print(f"[nuclei] {result.stdout.strip()[:500]}", flush=True)
                    if result.returncode == 0:
                        print("[nuclei] Templates updated successfully.", flush=True)
                        _last_nuclei_template_update = now
                    else:
                        print(f"[nuclei] Template update failed (exit {result.returncode})", flush=True)
        except FileNotFoundError:
            print("[nuclei] nuclei binary not found — skipping template update.", flush=True)
        except Exception as exc:
            print(f"[nuclei-updater] Error: {exc}", flush=True)
        time.sleep(3600)  # re-check every hour


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
    return {
        "status": "ok",
        "version": VERSION,
        "dns_server": _DNS_SERVER,
        "config": {
            "scan_interval": SCAN_INTERVAL,
            "ip_range": IP_RANGE,
            "nmap_args": NMAP_ARGS,
            "os_confidence_threshold": OS_CONFIDENCE_THRESHOLD,
            "offline_miss_threshold": OFFLINE_MISS_THRESHOLD,
            "sniffer_workers": SNIFFER_WORKERS,
        },
    }


class ConfigReloadRequest(BaseModel):
    scan_interval: int | None = None
    ip_range: str | None = None
    nmap_args: str | None = None
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


@probe_api.get("/stream/tools/ping")
def stream_tools_ping(host: str = Query(...)):
    import re
    if not re.match(r'^[a-zA-Z0-9._\-]{1,253}$', host):
        raise HTTPException(400, "Invalid host")
    cmd = ["ping", "-c", str(PING_COUNT), "-W", "2", host]
    return StreamingResponse(
        _stream_subprocess(cmd),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@probe_api.get("/stream/tools/traceroute")
def stream_tools_traceroute(host: str = Query(...)):
    import re
    if not re.match(r'^[a-zA-Z0-9._\-]{1,253}$', host):
        raise HTTPException(400, "Invalid host")
    cmd = ["traceroute", "-m", str(TRACE_MAX_HOP), "-w", "2", host]
    return StreamingResponse(
        _stream_subprocess(cmd),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@probe_api.get("/stream/tools/portscan")
def stream_tools_portscan(host: str = Query(...), ports: str = Query("1-1024")):
    import re
    if not re.match(r'^[a-zA-Z0-9._\-]{1,253}$', host):
        raise HTTPException(400, "Invalid host")
    if not re.match(r'^[\d,\-]{1,100}$', ports):
        raise HTTPException(400, "Invalid ports specification")
    cmd = ["nmap", "-sV", "--open", "-T4", "--host-timeout", "120s", "-p", ports, host]
    return StreamingResponse(
        _stream_subprocess(cmd),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@probe_api.get("/stream/tools/speedtest")
async def stream_speedtest(server_id: str = ""):
    async def _gen():
        cmd = ["speedtest-cli", "--no-pre-allocate"]
        if server_id:
            cmd += ["--server", server_id]
        lines_seen: list[str] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            assert proc.stdout
            async for raw in proc.stdout:
                line = raw.decode(errors="replace").rstrip()
                if line:
                    lines_seen.append(line)
                    yield f"data: {line}\n\n"
            await proc.wait()
            # Parse and emit structured result
            result: dict = {}
            for ln in lines_seen:
                if ln.startswith("Download:"):
                    try: result["download_mbps"] = float(ln.split()[1])
                    except (IndexError, ValueError): pass
                elif ln.startswith("Upload:"):
                    try: result["upload_mbps"] = float(ln.split()[1])
                    except (IndexError, ValueError): pass
                elif "Hosted by" in ln:
                    try:
                        # "Hosted by Name (City) [Xkm]: Y ms"
                        parts = ln.split(": ", 1)
                        if len(parts) == 2:
                            result["ping_ms"] = float(parts[1].split()[0])
                        result["server"] = ln.replace("Hosted by ", "").split(" [")[0].strip()
                    except (IndexError, ValueError): pass
            yield f"data: RESULT:{json.dumps(result)}\n\n"
        except FileNotFoundError:
            yield "data: ERROR: speedtest-cli not found — rebuild probe container\n\n"
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
            "speedtest-cli", "--list",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        out, _ = await proc.communicate()
        text = out.decode(errors="replace")
        servers = []
        for line in text.splitlines()[1:]:  # skip header
            line = line.strip()
            if not line:
                continue
            try:
                parts = line.split(")")
                sid = parts[0].strip()
                rest = parts[1].strip() if len(parts) > 1 else line
                servers.append({"id": sid, "label": rest[:80]})
            except Exception:
                pass
        return {"servers": servers[:50]}
    except FileNotFoundError:
        return {"servers": [], "error": "speedtest-cli not found"}
    except Exception as exc:
        return {"servers": [], "error": str(exc)}


@probe_api.get("/tools/arp-table")
def get_arp_table():
    try:
        import subprocess as sp
        out = sp.run(["ip", "neigh", "show"], capture_output=True, text=True, timeout=5)
        entries = []
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[1] == "dev":
                ip  = parts[0]
                mac = parts[4] if len(parts) > 4 else None
                state = parts[-1] if len(parts) > 5 else "unknown"
                if mac and mac != "FAILED" and ":" in mac:
                    entries.append({"ip": ip, "mac": mac.upper(), "state": state})
        return {"entries": entries}
    except Exception as exc:
        return {"entries": [], "error": str(exc)}


@probe_api.post("/tools/wake-on-lan")
async def wake_on_lan(body: dict):
    mac = body.get("mac", "").strip()
    broadcast = body.get("broadcast", "255.255.255.255")
    if not mac:
        raise HTTPException(400, "mac required")
    # Normalise MAC and build magic packet
    import re, socket
    mac_clean = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(mac_clean) != 12:
        raise HTTPException(400, "Invalid MAC address")
    magic = bytes.fromhex("FF" * 6 + mac_clean * 16)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(magic, (broadcast, 9))
        return {"ok": True, "mac": mac}
    except Exception as exc:
        raise HTTPException(500, str(exc))


@probe_api.get("/stream/vuln-scan/{ip}")
async def stream_vuln_scan(ip: str, templates: str = "", mac: str = ""):
    import ipaddress
    from vuln_scanner import run_vuln_scan, DEFAULT_TEMPLATES

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "Invalid IP address")

    effective_templates = templates.strip() if templates.strip() else DEFAULT_TEMPLATES

    # Pull port + service info from the device's prior port sweep.
    # Prefer MAC lookup (stable) over IP lookup (can be stale if sniffer
    # recently updated ip_address to a secondary address).
    known_ports: list[int] = []
    port_services: dict[int, dict] = {}
    pipeline_stage: str = ""
    try:
        session = Session()
        if mac:
            device = session.get(Device, mac.lower())
        else:
            # Query primary_ip first — ip_address can be transiently flipped to a
            # secondary address by the sniffer, causing a missed lookup at scan time.
            device = session.query(Device).filter(Device.primary_ip == ip).first()
            if not device:
                device = session.query(Device).filter(Device.ip_address == ip).first()
            if not device:
                # Last resort: find via ip_history in case DHCP recently reassigned this IP
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
            # Overlay Nerva service data — more accurate than empty TCP-connect labels
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
        yield f"data: [INFO] Initiating vulnerability scan…\n\n"
        if pipeline_stage == "ports_done":
            yield f"data: [WARN] Service fingerprinting not yet complete — template selection may be less precise\n\n"
        elif not pipeline_stage:
            yield f"data: [WARN] No prior port scan — will run full TCP sweep first\n\n"
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
    """Trigger a full mDNS browse and apply enrichment to all devices."""
    mdns_data = _mdns_browse()
    if mdns_data:
        _apply_mdns_enrichment(mdns_data)
    return {"discovered": len(mdns_data), "ips": list(mdns_data.keys())}


@probe_api.post("/block/{mac}")
def probe_block_device(mac: str):
    mac = mac.lower()
    session = Session()
    try:
        device = session.get(Device, mac)
        if not device:
            raise HTTPException(404, "Device not found")
        target_ip = device.primary_ip or device.ip_address
        if not target_ip or not _is_valid_ip(target_ip):
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
        args=(target_ip, target_mac, gateway_ip, gateway_mac, INTERFACE, stop_event),
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
# Traffic monitoring endpoints
# ---------------------------------------------------------------------------

@probe_api.post("/traffic/start/{ip}")
def probe_traffic_start(ip: str):
    if not _is_valid_ip(ip):
        raise HTTPException(422, "Invalid IP address")

    # Refuse if device is currently being blocked (ARP drop rules conflict)
    with _blocked_lock:
        blocked_by_mac = next(
            (m for m, e in _blocked_devices.items() if e["target_ip"] == ip),
            None,
        )
    if blocked_by_mac:
        raise HTTPException(409, f"Device {ip} is currently blocked — unblock first")

    session = _tm.get_session_by_ip(ip)
    if session:
        return {"ok": True, "already_monitoring": True, "mac": session.mac}

    # Look up MAC for this IP
    session_db = Session()
    try:
        from sqlalchemy import text as _text
        row = session_db.execute(
            _text("SELECT mac_address FROM devices WHERE ip_address = :ip LIMIT 1"),
            {"ip": ip},
        ).fetchone()
        mac = row[0] if row else None
    finally:
        session_db.close()

    if not mac:
        # Try ARP resolution
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
        iface=INTERFACE,
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
    gateway_ip = _get_default_gateway()
    return {
        "interface":   INTERFACE,
        "ip_range":    IP_RANGE,
        "gateway_ip":  gateway_ip,
    }


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
# Startup Nerva backfill
# ---------------------------------------------------------------------------
def _startup_nerva_backfill() -> None:
    """Re-fingerprint devices whose services are empty (Nerva was broken or scanned stale IP).
    Always uses the device's CURRENT ip_address, not the historical primary_ip."""
    time.sleep(5)  # let sniffer / ARP threads settle first
    active = {t.name for t in threading.enumerate()}
    session = Session()
    count = 0
    try:
        devices = session.query(Device).filter(Device.deep_scanned == True).all()
        for dev in devices:
            sr = dev.scan_results or {}
            pipeline_stage = sr.get("pipeline_stage")
            services       = sr.get("services")
            # Backfill if: pipeline ran to services_done with empty result, OR stuck at ports_done
            needs_backfill = (
                pipeline_stage in ("services_done", "ports_done")
                and not services  # catches [] and None
                and sr.get("open_ports")
            )
            if not needs_backfill:
                continue
            # Skip if a Nerva thread is already running for this device
            if (f"nerva-{dev.mac_address}" in active or
                    f"nerva-backfill-{dev.mac_address}" in active):
                continue
            ports = [p["port"] for p in sr["open_ports"] if isinstance(p.get("port"), int)]
            if not ports:
                continue
            # Use CURRENT ip_address — primary_ip may be a stale DHCP address
            scan_ip = dev.ip_address or dev.primary_ip
            if not _is_valid_ip(scan_ip):
                continue
            threading.Thread(
                target=_run_nerva_fingerprint,
                args=(scan_ip, dev.mac_address, ports),
                daemon=True,
                name=f"nerva-backfill-{dev.mac_address}",
            ).start()
            count += 1
            print(f"[nerva] Backfill queued: {scan_ip} ({dev.mac_address}), {len(ports)} port(s)", flush=True)
    except Exception as e:
        print(f"[nerva] Backfill query error: {e}", flush=True)
    finally:
        session.close()
    print(f"[nerva] Backfill: {count} device(s) queued for re-fingerprint", flush=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def _graceful_shutdown(signum, frame) -> None:
    """
    SIGTERM / SIGINT handler.  Stop all active traffic monitor sessions and
    wait for their ARP restore threads to complete before exiting so that
    monitored devices are not left with poisoned ARP caches.
    Docker sends SIGTERM and waits 10 s before SIGKILL — our restore takes ~1 s.
    """
    print("[*] Received shutdown signal — restoring ARP tables for all active monitors...", flush=True)
    _tm.stop_all_and_wait(timeout=5.0)
    print("[*] All traffic monitors cleaned up — exiting.", flush=True)
    sys.exit(0)


def main() -> None:
    signal.signal(signal.SIGTERM, _graceful_shutdown)
    signal.signal(signal.SIGINT,  _graceful_shutdown)

    print(f"[*] InSpectre Probe v{VERSION} starting...", flush=True)
    _load_mac_vendor_db()
    wait_for_db()
    init_db()
    _load_settings_from_db()
    threading.Thread(target=refresh_missing_vendors, daemon=True, name="vendor-refresh").start()

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
    threading.Thread(target=_nuclei_template_update_loop, daemon=True, name="nuclei-updater").start()
    time.sleep(2)

    threading.Thread(target=start_arp_sniffer, daemon=True, name="arp-sniffer").start()
    threading.Thread(target=_mdns_loop, daemon=True, name="mdns-loop").start()

    while True:
        _load_settings_from_db()

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

            # Retry any online devices that never got a completed deep scan
            unscanned = session.query(Device).filter(
                Device.is_online == True,
                Device.deep_scanned == False,
            ).all()
            for dev in unscanned:
                scan_ip = dev.primary_ip or dev.ip_address
                if _is_valid_ip(scan_ip):
                    print(f"[scan] Retrying unscanned device: {scan_ip} ({dev.mac_address})", flush=True)
                    trigger_deep_scan(scan_ip, dev.mac_address)

            threading.Thread(target=refresh_missing_hostnames, daemon=True).start()

            # Nightly deep-scan window: rescan fully-scanned online devices once per day
            now_hour = datetime.now().hour
            if NIGHTLY_SCAN_START <= now_hour < NIGHTLY_SCAN_END:
                nightly_threshold = datetime.now(timezone.utc) - timedelta(hours=23)
                nightly_q = session.query(Device).filter(
                    Device.is_online     == True,
                    Device.deep_scanned  == True,
                ).all()
                nightly_count = 0
                for dev in nightly_q:
                    last_run = dev.deep_scan_last_run
                    if last_run is None or last_run < nightly_threshold:
                        scan_ip = dev.primary_ip or dev.ip_address
                        if _is_valid_ip(scan_ip):
                            print(f"[scan] Nightly rescan: {scan_ip} ({dev.mac_address})", flush=True)
                            trigger_deep_scan(scan_ip, dev.mac_address)
                            nightly_count += 1
                if nightly_count:
                    print(f"[scan] Nightly window queued {nightly_count} rescan(s)", flush=True)
        except Exception as e:
            session.rollback()
            print(f"[!] Sweep error: {e}", flush=True)
        finally:
            session.close()
        time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    main()
