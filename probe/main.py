import asyncio
import csv
import ipaddress
import json
import os
import queue
import re
import shutil
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
from scapy.all import ARP, BOOTP, DHCP, Ether, IP, TCP, UDP, sniff, sr, srp, sendp
from sqlalchemy import (
    Boolean, Column, DateTime, Integer, JSON, String, UniqueConstraint,
    cast, create_engine, text,
)
from sqlalchemy.dialects.postgresql import JSONB, insert as pg_insert
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.orm.attributes import flag_modified
import traffic_monitor as _tm
import dhcp_classify as _dhcp_cls

# ---------------------------------------------------------------------------
# Version (single source of truth: repo-root VERSION → probe/_version.py)
# ---------------------------------------------------------------------------
from _version import __version__ as VERSION

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Startup network auto-detection
# Runs once at import time so INTERFACE and IP_RANGE work without ENV vars.
# ENV vars still override if explicitly set (non-empty).
# ---------------------------------------------------------------------------
def _startup_detect_interface() -> str | None:
    """Return the interface that carries the default route, or None."""
    try:
        out = subprocess.run(["ip", "route", "show", "default"],
                             capture_output=True, text=True, timeout=3)
        for line in out.stdout.splitlines():
            parts = line.split()
            if parts and parts[0] == "default" and "dev" in parts:
                iface = parts[parts.index("dev") + 1]
                if iface and not iface.startswith("lo"):
                    return iface
    except Exception:
        pass
    return None

def _startup_detect_ip_range(iface: str) -> str | None:
    """Derive the network CIDR from the named interface, or None."""
    import ipaddress as _ipa
    try:
        out = subprocess.run(["ip", "addr", "show", iface],
                             capture_output=True, text=True, timeout=3)
        for line in out.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet ") and "/" in line:
                return str(_ipa.ip_interface(line.split()[1]).network)
    except Exception:
        pass
    return None

_autodetected_interface = _startup_detect_interface()
_autodetected_ip_range  = _startup_detect_ip_range(_autodetected_interface) if _autodetected_interface else None

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DATABASE_URL            = os.environ.get("DATABASE_URL",            "postgresql://admin:password123@localhost:5432/inspectre")
SCAN_INTERVAL           = int(os.environ.get("SCAN_INTERVAL",           60))
# ENV overrides if non-empty; otherwise use auto-detected value from routing table
IP_RANGE                = os.environ.get("IP_RANGE",  "").strip() or _autodetected_ip_range  or "192.168.0.0/24"
INTERFACE               = os.environ.get("INTERFACE", "").strip() or _autodetected_interface or "eth0"
PORT_SCAN_WORKERS       = int(os.environ.get("PORT_SCAN_WORKERS", 200))
GATEWAY_SCAN_WORKERS    = int(os.environ.get("GATEWAY_SCAN_WORKERS", 50))
PORT_SCAN_METHOD        = os.environ.get("PORT_SCAN_METHOD", "tcp_connect")
OS_CONFIDENCE_THRESHOLD = int(os.environ.get("OS_CONFIDENCE_THRESHOLD", 85))
OFFLINE_MISS_THRESHOLD  = int(os.environ.get("OFFLINE_MISS_THRESHOLD",   3))
SNIFFER_WORKERS         = int(os.environ.get("SNIFFER_WORKERS",          4))
ARP_SCAN_RETRY          = int(os.environ.get("ARP_SCAN_RETRY",           1))
PRIMARY_IP_MODE         = os.environ.get("PRIMARY_IP_MODE",         "locked")
SNIFFER_SUBNET_FILTER   = os.environ.get("SNIFFER_SUBNET_FILTER",   "false").lower() in ("true", "1", "yes")
PROBE_API_PORT          = int(os.environ.get("PROBE_API_PORT",         8001))
LAN_DNS_SERVER_ENV      = os.environ.get("LAN_DNS_SERVER", "").strip()
MDNS_INTERVAL_MINUTES   = int(os.environ.get("MDNS_INTERVAL_MINUTES", 120))  # default: 2 hours

# The probe's own interface MAC — ARP packets originating from this MAC are
# our own (e.g. ARP restore packets sent after unblocking a device). The sniffer
# must ignore them to prevent falsely marking target devices as "online".
def _get_own_mac(iface: str) -> str | None:
    try:
        from scapy.all import get_if_hwaddr
        return get_if_hwaddr(iface).lower()
    except Exception:
        return None

_PROBE_OWN_MAC: str | None = _get_own_mac(INTERFACE)

# Scan scheduling globals (overridden by DB settings at each cycle)
NIGHTLY_SCAN_START      = int(os.environ.get("NIGHTLY_SCAN_START", 2))
NIGHTLY_SCAN_END        = int(os.environ.get("NIGHTLY_SCAN_END",   4))
OFFLINE_RESCAN_HOURS    = int(os.environ.get("OFFLINE_RESCAN_HOURS", 4))
BASELINE_SCAN_COUNT_THRESHOLD = 3
HOSTNAME_COOLDOWN_HOURS = 24

# Feature-flag globals — loaded from DB each scan cycle, all default ON
def _env_bool(key: str, default: bool = True) -> bool:
    v = os.environ.get(key, "").strip().lower()
    if not v:
        return default
    return v in ("true", "1", "yes")

ENABLE_ARP_SWEEP              = _env_bool("ENABLE_ARP_SWEEP")
ENABLE_PASSIVE_SNIFFER        = _env_bool("ENABLE_PASSIVE_SNIFFER")
ENABLE_HOSTNAME_RESOLUTION    = _env_bool("ENABLE_HOSTNAME_RESOLUTION")
ENABLE_PORT_SCANNING          = _env_bool("ENABLE_PORT_SCANNING")
ENABLE_SERVICE_FINGERPRINTING = _env_bool("ENABLE_SERVICE_FINGERPRINTING")
ENABLE_MDNS                   = _env_bool("ENABLE_MDNS")
ENABLE_NIGHTLY_SCAN           = _env_bool("ENABLE_NIGHTLY_SCAN")
ENABLE_UNSCANNED_RETRY        = _env_bool("ENABLE_UNSCANNED_RETRY")
AUTO_GROUP_BY_HOSTNAME        = _env_bool("AUTO_GROUP_BY_HOSTNAME")
SCAN_GROUPED_MEMBERS          = _env_bool("SCAN_GROUPED_MEMBERS", default=False)

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
    global SCAN_INTERVAL, IP_RANGE, INTERFACE, PORT_SCAN_WORKERS, GATEWAY_SCAN_WORKERS, PORT_SCAN_METHOD, OS_CONFIDENCE_THRESHOLD
    global OFFLINE_MISS_THRESHOLD, SNIFFER_WORKERS, ARP_SCAN_RETRY, PRIMARY_IP_MODE, SNIFFER_SUBNET_FILTER, NUCLEI_TEMPLATE_UPDATE_INTERVAL
    global NIGHTLY_SCAN_START, NIGHTLY_SCAN_END, OFFLINE_RESCAN_HOURS, BASELINE_SCAN_COUNT_THRESHOLD, HOSTNAME_COOLDOWN_HOURS
    global ENABLE_ARP_SWEEP, ENABLE_PASSIVE_SNIFFER, ENABLE_HOSTNAME_RESOLUTION, ENABLE_PORT_SCANNING
    global ENABLE_SERVICE_FINGERPRINTING, ENABLE_MDNS, ENABLE_NIGHTLY_SCAN, ENABLE_UNSCANNED_RETRY
    global AUTO_GROUP_BY_HOSTNAME, SCAN_GROUPED_MEMBERS
    global _DNS_SERVER
    try:
        session = Session()
        try:
            rows = session.execute(text("SELECT key, value FROM settings")).fetchall()
        finally:
            session.close()
        db = {r[0]: r[1] for r in rows}
        if "scan_interval"           in db: SCAN_INTERVAL           = int(db["scan_interval"])
        if "ip_range"                in db: IP_RANGE                = db["ip_range"].strip()
        if "port_scan_workers"       in db: PORT_SCAN_WORKERS       = int(db["port_scan_workers"])
        if "gateway_scan_workers"    in db: GATEWAY_SCAN_WORKERS    = int(db["gateway_scan_workers"])
        if "port_scan_method"        in db: PORT_SCAN_METHOD        = db["port_scan_method"].strip()
        if "os_confidence_threshold" in db: OS_CONFIDENCE_THRESHOLD = int(db["os_confidence_threshold"])
        if "offline_miss_threshold"  in db: OFFLINE_MISS_THRESHOLD  = int(db["offline_miss_threshold"])
        if "sniffer_workers"         in db: SNIFFER_WORKERS         = int(db["sniffer_workers"])
        if "arp_scan_retry"          in db: ARP_SCAN_RETRY          = int(db["arp_scan_retry"])
        if "primary_ip_mode"         in db: PRIMARY_IP_MODE         = db["primary_ip_mode"].strip()
        if "sniffer_subnet_filter"   in db: SNIFFER_SUBNET_FILTER   = db["sniffer_subnet_filter"].strip().lower() in ("true", "1", "yes")
        if "nuclei_template_update_interval" in db:
            NUCLEI_TEMPLATE_UPDATE_INTERVAL = db["nuclei_template_update_interval"]
        if "nightly_scan_start"            in db: NIGHTLY_SCAN_START            = int(db["nightly_scan_start"])
        if "nightly_scan_end"              in db: NIGHTLY_SCAN_END              = int(db["nightly_scan_end"])
        if "offline_rescan_hours"          in db: OFFLINE_RESCAN_HOURS          = int(db["offline_rescan_hours"])
        if "baseline_scan_count_threshold" in db: BASELINE_SCAN_COUNT_THRESHOLD = int(db["baseline_scan_count_threshold"])
        if "hostname_cooldown_hours"       in db: HOSTNAME_COOLDOWN_HOURS       = int(db["hostname_cooldown_hours"])
        # Feature flags
        def _pb(k: str, fallback: bool = True) -> bool:
            return db[k].strip().lower() in ("true", "1", "yes") if k in db else fallback
        ENABLE_ARP_SWEEP              = _pb("enable_arp_sweep")
        ENABLE_PASSIVE_SNIFFER        = _pb("enable_passive_sniffer")
        ENABLE_HOSTNAME_RESOLUTION    = _pb("enable_hostname_resolution")
        ENABLE_PORT_SCANNING          = _pb("enable_port_scanning")
        ENABLE_SERVICE_FINGERPRINTING = _pb("enable_service_fingerprinting")
        ENABLE_MDNS                   = _pb("enable_mdns")
        ENABLE_NIGHTLY_SCAN           = _pb("enable_nightly_scan")
        ENABLE_UNSCANNED_RETRY        = _pb("enable_unscanned_retry")
        AUTO_GROUP_BY_HOSTNAME        = _pb("auto_group_by_hostname")
        SCAN_GROUPED_MEMBERS          = _pb("scan_grouped_members", False)
        # dns_server from DB overrides ENV-based detection.
        # Validate strictly to prevent argument-injection into dig/host/nslookup argv.
        ds = db.get("dns_server", "").strip()
        if ds and _is_valid_dns_server(ds):
            _DNS_SERVER = ds
        elif ds:
            print(f"[settings] Ignoring invalid dns_server value: {ds!r}", flush=True)
        # probe_interface: if set in UI, use it; otherwise write auto-detected value back so UI can display it
        pi = db.get("probe_interface", "").strip()
        if pi:
            INTERFACE = pi
        elif _autodetected_interface and not db.get("probe_interface", "").strip():
            try:
                s2 = Session()
                try:
                    s2.execute(text(
                        "UPDATE settings SET value=:v WHERE key='probe_interface' AND (value IS NULL OR value='')"
                    ), {"v": _autodetected_interface})
                    s2.commit()
                finally:
                    s2.close()
            except Exception:
                pass
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
    global SCAN_INTERVAL, IP_RANGE, INTERFACE, PORT_SCAN_WORKERS, GATEWAY_SCAN_WORKERS, PORT_SCAN_METHOD, OS_CONFIDENCE_THRESHOLD, OFFLINE_MISS_THRESHOLD, SNIFFER_WORKERS, ARP_SCAN_RETRY, PRIMARY_IP_MODE, SNIFFER_SUBNET_FILTER, NUCLEI_TEMPLATE_UPDATE_INTERVAL
    global HOSTNAME_COOLDOWN_HOURS, ENABLE_ARP_SWEEP, ENABLE_PASSIVE_SNIFFER, ENABLE_HOSTNAME_RESOLUTION, ENABLE_PORT_SCANNING
    global ENABLE_SERVICE_FINGERPRINTING, ENABLE_MDNS, ENABLE_NIGHTLY_SCAN, ENABLE_UNSCANNED_RETRY
    global AUTO_GROUP_BY_HOSTNAME, SCAN_GROUPED_MEMBERS
    global _DNS_SERVER

    changes = {}

    if "scan_interval" in payload:
        SCAN_INTERVAL = int(payload["scan_interval"])
        changes["scan_interval"] = SCAN_INTERVAL
    if "ip_range" in payload:
        IP_RANGE = str(payload["ip_range"]).strip()
        changes["ip_range"] = IP_RANGE
    if "port_scan_workers" in payload:
        PORT_SCAN_WORKERS = int(payload["port_scan_workers"])
        changes["port_scan_workers"] = PORT_SCAN_WORKERS
    if "gateway_scan_workers" in payload:
        GATEWAY_SCAN_WORKERS = int(payload["gateway_scan_workers"])
        changes["gateway_scan_workers"] = GATEWAY_SCAN_WORKERS
    if "port_scan_method" in payload:
        PORT_SCAN_METHOD = str(payload["port_scan_method"]).strip()
        changes["port_scan_method"] = PORT_SCAN_METHOD
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
    if "arp_scan_retry" in payload:
        ARP_SCAN_RETRY = int(payload["arp_scan_retry"])
        changes["arp_scan_retry"] = ARP_SCAN_RETRY
    if "primary_ip_mode" in payload:
        PRIMARY_IP_MODE = str(payload["primary_ip_mode"]).strip()
        changes["primary_ip_mode"] = PRIMARY_IP_MODE
    if "sniffer_subnet_filter" in payload:
        SNIFFER_SUBNET_FILTER = str(payload["sniffer_subnet_filter"]).strip().lower() in ("true", "1", "yes")
        changes["sniffer_subnet_filter"] = SNIFFER_SUBNET_FILTER
    if "probe_interface" in payload:
        v = str(payload["probe_interface"]).strip()
        if v:
            INTERFACE = v
            changes["probe_interface"] = INTERFACE
    if "hostname_cooldown_hours" in payload:
        HOSTNAME_COOLDOWN_HOURS = int(payload["hostname_cooldown_hours"])
        changes["hostname_cooldown_hours"] = HOSTNAME_COOLDOWN_HOURS
    if "dns_server" in payload:
        ds = str(payload["dns_server"]).strip()
        if ds:
            _DNS_SERVER = ds
            changes["dns_server"] = _DNS_SERVER
    def _abool(v) -> bool:
        return str(v).strip().lower() in ("true", "1", "yes")
    if "enable_arp_sweep"              in payload: ENABLE_ARP_SWEEP              = _abool(payload["enable_arp_sweep"]);              changes["enable_arp_sweep"]              = ENABLE_ARP_SWEEP
    if "enable_passive_sniffer"        in payload: ENABLE_PASSIVE_SNIFFER        = _abool(payload["enable_passive_sniffer"]);        changes["enable_passive_sniffer"]        = ENABLE_PASSIVE_SNIFFER
    if "enable_hostname_resolution"    in payload: ENABLE_HOSTNAME_RESOLUTION    = _abool(payload["enable_hostname_resolution"]);    changes["enable_hostname_resolution"]    = ENABLE_HOSTNAME_RESOLUTION
    if "enable_port_scanning"          in payload: ENABLE_PORT_SCANNING          = _abool(payload["enable_port_scanning"]);          changes["enable_port_scanning"]          = ENABLE_PORT_SCANNING
    if "enable_service_fingerprinting" in payload: ENABLE_SERVICE_FINGERPRINTING = _abool(payload["enable_service_fingerprinting"]); changes["enable_service_fingerprinting"] = ENABLE_SERVICE_FINGERPRINTING
    if "enable_mdns"                   in payload: ENABLE_MDNS                   = _abool(payload["enable_mdns"]);                   changes["enable_mdns"]                   = ENABLE_MDNS
    if "enable_nightly_scan"           in payload: ENABLE_NIGHTLY_SCAN           = _abool(payload["enable_nightly_scan"]);           changes["enable_nightly_scan"]           = ENABLE_NIGHTLY_SCAN
    if "enable_unscanned_retry"        in payload: ENABLE_UNSCANNED_RETRY        = _abool(payload["enable_unscanned_retry"]);        changes["enable_unscanned_retry"]        = ENABLE_UNSCANNED_RETRY
    if "auto_group_by_hostname"        in payload: AUTO_GROUP_BY_HOSTNAME        = _abool(payload["auto_group_by_hostname"]);        changes["auto_group_by_hostname"]        = AUTO_GROUP_BY_HOSTNAME
    if "scan_grouped_members"          in payload: SCAN_GROUPED_MEMBERS          = _abool(payload["scan_grouped_members"]);          changes["scan_grouped_members"]          = SCAN_GROUPED_MEMBERS
    if "nuclei_template_update_interval" in payload:
        NUCLEI_TEMPLATE_UPDATE_INTERVAL = str(payload["nuclei_template_update_interval"]).strip()
        changes["nuclei_template_update_interval"] = NUCLEI_TEMPLATE_UPDATE_INTERVAL

    return {
        "applied": True,
        "changes": changes,
        "effective": {
            "scan_interval": SCAN_INTERVAL,
            "ip_range": IP_RANGE,
            "port_scan_workers": PORT_SCAN_WORKERS,
            "gateway_scan_workers": GATEWAY_SCAN_WORKERS,
            "port_scan_method": PORT_SCAN_METHOD,
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
        return not (
            addr.packed[0] == 0
            or str(addr) == "255.255.255.255"
            or addr.is_link_local
        )
    except ValueError:
        return False


def _is_valid_dns_server(value: str) -> bool:
    """Validate a user-supplied DNS server address (from the settings UI).

    Accepts a literal IPv4/IPv6 address or a conservative hostname. Rejects
    anything that could be interpreted as a CLI flag (leading '-') or that
    contains whitespace, preventing argument injection into dig/host/nslookup.
    """
    if not value:
        return False
    value = value.strip()
    if not value or value[0] == "-" or any(c.isspace() for c in value):
        return False
    import ipaddress as _ipa
    try:
        _ipa.ip_address(value)
        return True
    except ValueError:
        pass
    return bool(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,253}[A-Za-z0-9])?", value))

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
    suppress_presence_events = Column(Boolean, default=False, nullable=False)
    device_type_override    = Column(String,  nullable=True)
    hostname_last_attempted = Column(DateTime(timezone=True), nullable=True)
    deep_scan_last_run      = Column(DateTime(timezone=True), nullable=True)
    baseline_ports          = Column(JSONB,   nullable=True)
    baseline_scan_count     = Column(Integer, default=0, nullable=False)
    primary_ip_locked       = Column(Boolean, default=False, nullable=False)
    dhcp_hostname           = Column(String,  nullable=True)
    dhcp_vendor_class       = Column(String,  nullable=True)
    dhcp_fingerprint        = Column(String,  nullable=True)

class IPHistory(Base):
    __tablename__ = "ip_history"
    __table_args__ = (UniqueConstraint("mac_address", "ip_address", name="uq_ip_history_mac_ip"),)
    id                = Column(Integer, primary_key=True, autoincrement=True)
    mac_address       = Column(String, nullable=False, index=True)
    ip_address        = Column(String, nullable=False)
    first_seen        = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen         = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    seen_while_online = Column(Boolean, default=False)

engine  = create_engine(DATABASE_URL, pool_pre_ping=True)
Session = sessionmaker(bind=engine)

_sniffer_queue: queue.Queue = queue.Queue()
_dhcp_queue:    queue.Queue = queue.Queue(maxsize=500)
_upsert_locks: dict[str, threading.Lock] = {}
_upsert_locks_lock = threading.Lock()

# Track the last time each MAC was seen by the sniffer within the current sweep
# window, so we don't falsely increment miss counts for devices the sniffer saw.
_sniffer_seen_this_interval: set[str] = set()
_sniffer_seen_lock = threading.Lock()

# Track MACs for which an "offline" event has already been written and which
# have not come back online since. Used to suppress duplicate offline events for
# devices that are continuously offline (e.g. plugin-controlled standby devices).
# Intentionally in-memory only — resets on probe restart.
_confirmed_offline_macs: set[str] = set()
_confirmed_offline_lock = threading.Lock()

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
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS primary_ip_locked BOOLEAN NOT NULL DEFAULT FALSE"))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS suppress_presence_events BOOLEAN NOT NULL DEFAULT FALSE"))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS group_manual BOOLEAN NOT NULL DEFAULT FALSE"))
            conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS auto_group_optout BOOLEAN NOT NULL DEFAULT FALSE"))
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
            conn.execute(text("ALTER TABLE ip_history ADD COLUMN IF NOT EXISTS seen_while_online BOOLEAN DEFAULT FALSE"))
            conn.commit()
        except Exception:
            conn.rollback()

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

        # ── Hard pin enforcement (DB-level) ─────────────────────────────────
        # When primary_ip_locked=TRUE, the probe and sniffer must never
        # overwrite primary_ip or ip_address.  The CASE expressions in
        # upsert_seen_device are the primary guard; this trigger is the backstop
        # that survives any Python-side race or unexpected code path.
        #
        # Trigger fires whenever OLD.primary_ip_locked=TRUE (regardless of NEW):
        # it unconditionally restores primary_ip and ip_address from OLD.
        # The backend's two-step re-pin bypasses this correctly:
        #   Step 1 — SET locked=FALSE: trigger fires but primary_ip isn't being
        #            changed (NEW.primary_ip == OLD.primary_ip), no visible effect.
        #   Step 2 — SET primary_ip=X, locked=TRUE: OLD.locked=FALSE so trigger
        #            doesn't fire and the new pin is written normally.
        try:
            conn.execute(text("""
                CREATE OR REPLACE FUNCTION enforce_primary_ip_lock() RETURNS trigger AS $$
                BEGIN
                    IF OLD.primary_ip_locked THEN
                        NEW.primary_ip := OLD.primary_ip;
                        NEW.ip_address := OLD.ip_address;
                    END IF;
                    RETURN NEW;
                END;
                $$ LANGUAGE plpgsql
            """))
            conn.execute(text("""
                DROP TRIGGER IF EXISTS trg_enforce_primary_ip_lock ON devices
            """))
            conn.execute(text("""
                CREATE TRIGGER trg_enforce_primary_ip_lock
                    BEFORE UPDATE ON devices
                    FOR EACH ROW
                    EXECUTE FUNCTION enforce_primary_ip_lock()
            """))
            conn.commit()
            print("[DB] primary_ip_lock trigger installed.", flush=True)
        except Exception as e:
            print(f"[DB] Trigger install error: {e}", flush=True)
            conn.rollback()

    print("[DB] Migrations complete.", flush=True)

# ---------------------------------------------------------------------------
# IP History
# ---------------------------------------------------------------------------
def record_ip(mac: str, ip: str, seen_while_online: bool = False) -> bool:
    """
    Upserts the IP into ip_history.  Returns True only if this is a BRAND NEW
    mac+ip combination (first_seen == last_seen within 2s).
    seen_while_online=True means the device was already online at a different IP
    when this IP was observed (multi-homed), vs DHCP rotation (False).
    """
    if not _is_valid_ip(ip):
        return False
    now     = datetime.now(timezone.utc)
    session = Session()
    try:
        set_vals: dict = {"last_seen": now}
        if seen_while_online:
            set_vals["seen_while_online"] = True
        stmt = (
            pg_insert(IPHistory)
            .values(mac_address=mac, ip_address=ip, first_seen=now, last_seen=now,
                    seen_while_online=seen_while_online)
            .on_conflict_do_update(
                constraint="uq_ip_history_mac_ip",
                set_=set_vals,
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

def _primary_ip_is_stale(mac: str, primary_ip: str) -> bool:
    """
    Return True when the device's current primary IP has not been observed for
    several sweep cycles — i.e. the host has genuinely moved off it rather than
    just being multi-homed.  Used to decide whether a newly-seen IP should be
    promoted to primary (real move) or treated as a passive secondary (dual-homed
    host).  A missing history row is treated as NOT stale so a transient gap can
    never trigger ip_address flapping for an always-on multi-homed server.
    """
    if not primary_ip or not _is_valid_ip(primary_ip):
        return False
    threshold = max(SCAN_INTERVAL * 3, 180)
    s = Session()
    try:
        row = s.execute(
            text("SELECT last_seen FROM ip_history WHERE mac_address = :m AND ip_address = :ip"),
            {"m": mac, "ip": primary_ip},
        ).fetchone()
        if not row or not row[0]:
            return False
        age = (datetime.now(timezone.utc) - row[0]).total_seconds()
        return age > threshold
    except Exception:
        return False
    finally:
        s.close()


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
    Runs once immediately at startup (after a short settle delay) so that devices
    advertising .local names are resolved on the first scan cycle."""
    interval_s = MDNS_INTERVAL_MINUTES * 60
    print(f"[mdns] Scheduled loop started (interval={MDNS_INTERVAL_MINUTES}m)", flush=True)
    time.sleep(20)  # let sniffer/ARP settle first
    while True:
        try:
            print(f"[mdns] Running browse", flush=True)
            mdns_data = _mdns_browse()
            if mdns_data:
                _apply_mdns_enrichment(mdns_data)
        except Exception as e:
            print(f"[mdns] Loop error: {e}", flush=True)
        time.sleep(interval_s)


# ---------------------------------------------------------------------------
# Passive mDNS listener (continuous background thread)
# ---------------------------------------------------------------------------
def _mdns_passive_listener() -> None:
    """Continuously listen on the mDNS multicast group for spontaneous service announcements."""
    import socket as _sock, struct as _struct

    MDNS_ADDR = "224.0.0.251"
    MDNS_PORT = 5353
    print("[mdns-passive] Starting passive listener", flush=True)

    while True:
        ptr_records: dict = {}
        srv_records: dict = {}
        a_records:   dict = {}

        def _dec(data, offset, depth=0):
            if depth > 10: return "", offset
            labels, jumped, jump_ret = [], False, offset
            while offset < len(data):
                length = data[offset]
                if length == 0: offset += 1; break
                elif (length & 0xC0) == 0xC0:
                    if offset + 1 >= len(data): break
                    ptr = ((length & 0x3F) << 8) | data[offset + 1]
                    if not jumped: jump_ret = offset + 2
                    jumped = True
                    s, _ = _dec(data, ptr, depth + 1)
                    if s: labels.append(s)
                    break
                else:
                    end = offset + 1 + length
                    if end > len(data): break
                    labels.append(data[offset + 1:end].decode("utf-8", errors="replace"))
                    offset = end
            return ".".join(labels), (jump_ret if jumped else offset)

        def _parse(data):
            try:
                if len(data) < 12: return
                flags = _struct.unpack_from(">H", data, 2)[0]
                if not (flags & 0x8000): return  # skip queries
                qdcount, ancount, nscount, arcount = _struct.unpack_from(">HHHH", data, 4)
                offset = 12
                for _ in range(qdcount):
                    _, offset = _dec(data, offset); offset += 4
                for _ in range(ancount + nscount + arcount):
                    if offset + 10 > len(data): break
                    name, offset = _dec(data, offset)
                    if offset + 10 > len(data): break
                    rtype, _, _, rdlen = _struct.unpack_from(">HHIH", data, offset)
                    offset += 10
                    rs = offset; offset += rdlen
                    if rdlen == 0 or rs + rdlen > len(data): continue
                    n = name.lower().rstrip(".")
                    if rtype == 12:
                        tgt, _ = _dec(data, rs)
                        t = tgt.lower().rstrip(".")
                        if t:
                            lst = ptr_records.setdefault(n, [])
                            if t not in lst: lst.append(t)
                    elif rtype == 33 and rdlen >= 7:
                        tgt, _ = _dec(data, rs + 6)
                        srv_records[n] = tgt.lower().rstrip(".")
                    elif rtype == 1 and rdlen == 4:
                        a_records[n] = ".".join(str(b) for b in data[rs:rs + 4])
            except Exception:
                pass

        def _flush():
            result = {}
            for hn, ip in a_records.items():
                if _is_valid_ip(ip):
                    entry = result.setdefault(ip, {"mdns_name": None, "services": []})
                    if not entry["mdns_name"]:
                        entry["mdns_name"] = hn.removesuffix(".local")
            for svc_type, instances in ptr_records.items():
                if "._dns-sd." in svc_type: continue
                parts = svc_type.removesuffix(".local").split(".")
                label = ".".join(parts[-2:]) if len(parts) >= 2 else svc_type.removesuffix(".local")
                for inst in instances:
                    hn = srv_records.get(inst)
                    ip = None
                    if hn: ip = a_records.get(hn) or a_records.get(hn + ".local")
                    if ip and _is_valid_ip(ip):
                        entry = result.setdefault(ip, {"mdns_name": None, "services": []})
                        if label not in entry["services"]: entry["services"].append(label)
            if result:
                _apply_mdns_enrichment(result)
            ptr_records.clear(); srv_records.clear(); a_records.clear()

        s = None
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM, _sock.IPPROTO_UDP)
            s.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
            try: s.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEPORT, 1)
            except (AttributeError, OSError): pass
            s.bind(("", MDNS_PORT))
            mreq = _struct.pack("4sL", _sock.inet_aton(MDNS_ADDR), _sock.INADDR_ANY)
            s.setsockopt(_sock.IPPROTO_IP, _sock.IP_ADD_MEMBERSHIP, mreq)
            s.settimeout(30.0)
            pkt_count = 0
            while True:
                try:
                    data, _ = s.recvfrom(8192)
                    _parse(data)
                    pkt_count += 1
                    if pkt_count >= 100: _flush(); pkt_count = 0
                except _sock.timeout:
                    if ptr_records or a_records: _flush()
                except Exception: break
        except PermissionError as e:
            print(f"[mdns-passive] permission denied: {e}", flush=True)
            time.sleep(60)
        except Exception as e:
            print(f"[mdns-passive] error, restarting: {e}", flush=True)
            time.sleep(10)
        finally:
            if s:
                try:
                    mreq = _struct.pack("4sL", _sock.inet_aton(MDNS_ADDR), _sock.INADDR_ANY)
                    s.setsockopt(_sock.IPPROTO_IP, _sock.IP_DROP_MEMBERSHIP, mreq)
                except Exception: pass
                try: s.close()
                except Exception: pass


# ---------------------------------------------------------------------------
# SSDP/UPnP discovery helpers
# ---------------------------------------------------------------------------
def _parse_ssdp_message(text: str) -> dict | None:
    """Parse SSDP NOTIFY or HTTP 200 response headers into a service dict."""
    lines = text.splitlines()
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    st  = headers.get("st",  headers.get("nt",  ""))
    usn = headers.get("usn", "")
    if not (st or usn): return None
    return {
        "st":       st,
        "usn":      usn,
        "server":   headers.get("server",   ""),
        "location": headers.get("location", ""),
    }


def _apply_ssdp_enrichment(ssdp_data: dict[str, list[dict]]) -> None:
    """Store SSDP service discoveries in device.scan_results["ssdp_services"]."""
    if not ssdp_data:
        return
    session = Session()
    try:
        updated = 0
        now_iso = datetime.now(timezone.utc).isoformat()
        for ip, services in ssdp_data.items():
            dev = session.query(Device).filter(Device.ip_address == ip).first()
            if not dev:
                continue
            scan = dict(dev.scan_results) if dev.scan_results else {}
            existing = {s["usn"]: s for s in scan.get("ssdp_services", []) if s.get("usn")}
            changed = False
            for svc in services:
                usn = svc.get("usn", "")
                if not usn:
                    continue
                svc["last_seen"] = now_iso
                if usn not in existing or existing[usn] != svc:
                    existing[usn] = svc
                    changed = True
            if changed:
                scan["ssdp_services"] = list(existing.values())
                dev.scan_results = scan
                flag_modified(dev, "scan_results")
                updated += 1
        if updated:
            session.commit()
            print(f"[ssdp] Enriched {updated} device(s)", flush=True)
    except Exception as e:
        session.rollback()
        print(f"[ssdp] Enrichment error: {e}", flush=True)
    finally:
        session.close()


def _ssdp_browse(timeout: int = 6) -> dict[str, list[dict]]:
    """Send SSDP M-SEARCH and collect UPnP responses. Returns {ip: [service_dict]}."""
    import socket as _sock

    SSDP_ADDR = "239.255.255.255"
    SSDP_PORT = 1900
    request = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
        'MAN: "ssdp:discover"\r\n'
        f"MX: {max(1, timeout - 2)}\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode()

    result: dict[str, list[dict]] = {}
    s = None
    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM, _sock.IPPROTO_UDP)
        s.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
        s.setsockopt(_sock.IPPROTO_IP, _sock.IP_MULTICAST_TTL, 4)
        s.settimeout(0.5)
        # Bind to ephemeral port so unicast responses come back here
        s.bind(("", 0))
        s.sendto(request, (SSDP_ADDR, SSDP_PORT))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = s.recvfrom(8192)
                ip = addr[0]
                info = _parse_ssdp_message(data.decode("utf-8", errors="replace"))
                if info and info.get("usn"):
                    existing_usns = {sv["usn"] for sv in result.get(ip, [])}
                    if info["usn"] not in existing_usns:
                        result.setdefault(ip, []).append(info)
            except _sock.timeout:
                continue
            except Exception:
                break
    except Exception as e:
        print(f"[ssdp] browse error: {e}", flush=True)
    finally:
        if s:
            try: s.close()
            except Exception: pass

    total = sum(len(v) for v in result.values())
    if result:
        print(f"[ssdp] Discovered {total} service(s) on {len(result)} device(s)", flush=True)
    return result


def _ssdp_passive_listener() -> None:
    """Continuously listen for UPnP NOTIFY announcements on the SSDP multicast group."""
    import socket as _sock, struct as _struct

    SSDP_ADDR = "239.255.255.255"
    SSDP_PORT = 1900
    print("[ssdp-passive] Starting passive SSDP listener", flush=True)

    while True:
        pending: dict[str, list[dict]] = {}
        last_flush = time.monotonic()
        s = None
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM, _sock.IPPROTO_UDP)
            s.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
            try: s.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEPORT, 1)
            except (AttributeError, OSError): pass
            s.bind(("", SSDP_PORT))
            mreq = _struct.pack("4sL", _sock.inet_aton(SSDP_ADDR), _sock.INADDR_ANY)
            s.setsockopt(_sock.IPPROTO_IP, _sock.IP_ADD_MEMBERSHIP, mreq)
            s.settimeout(1.0)
            while True:
                try:
                    data, addr = s.recvfrom(8192)
                    text = data.decode("utf-8", errors="replace")
                    if "ssdp:byebye" in text.lower(): continue
                    info = _parse_ssdp_message(text)
                    if info and info.get("usn"):
                        ip = addr[0]
                        existing_usns = {sv["usn"] for sv in pending.get(ip, [])}
                        if info["usn"] not in existing_usns:
                            pending.setdefault(ip, []).append(info)
                except _sock.timeout:
                    pass
                except Exception:
                    break
                if pending and time.monotonic() - last_flush > 30:
                    _apply_ssdp_enrichment(pending)
                    pending.clear()
                    last_flush = time.monotonic()
        except PermissionError as e:
            print(f"[ssdp-passive] permission denied: {e}", flush=True)
            time.sleep(60)
        except Exception as e:
            print(f"[ssdp-passive] error, restarting: {e}", flush=True)
            time.sleep(10)
        finally:
            if s:
                try:
                    mreq = _struct.pack("4sL", _sock.inet_aton(SSDP_ADDR), _sock.INADDR_ANY)
                    s.setsockopt(_sock.IPPROTO_IP, _sock.IP_DROP_MEMBERSHIP, mreq)
                except Exception: pass
                try: s.close()
                except Exception: pass


# ---------------------------------------------------------------------------
# ARP sweep
# ---------------------------------------------------------------------------
def arp_scan(interface: str, ip_range: str) -> list[dict]:
    pkt    = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    result = srp(pkt, iface=interface, timeout=5, retry=ARP_SCAN_RETRY, verbose=0)[0]
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


def _scapy_syn_scan(ip: str, workers: int | None = None) -> list[int]:
    """
    SYN scan via Scapy raw sockets (requires CAP_NET_RAW — already granted in the probe container).
    Sends raw TCP SYN packets and collects SYN-ACK replies.
    The workers parameter is accepted for API compatibility but Scapy handles I/O internally.
    """
    try:
        from scapy.all import conf as scapy_conf
        scapy_conf.verb = 0
        # Build/send in batches to bound peak memory (65k Packet objects at once
        # is expensive); results are identical to a single large send.
        open_ports: list[int] = []
        batch = 4096
        for start in range(1, 65536, batch):
            end = min(start + batch, 65536)
            pkts = [IP(dst=ip) / TCP(dport=p, flags='S') for p in range(start, end)]
            answered, _ = sr(pkts, timeout=3, verbose=0)
            open_ports.extend(
                snt[TCP].dport
                for snt, rcv in answered
                if rcv.haslayer(TCP) and (rcv[TCP].flags & 0x12) == 0x12
            )
        return sorted(set(open_ports))
    except Exception as exc:
        print(f"[scan] Scapy SYN sweep error for {ip}: {exc}", flush=True)
        return []


def _tcp_connect_sweep(ip: str, workers: int | None = None) -> list[int]:
    """
    Primary port scanner using TCP connect.
    Default: PORT_SCAN_WORKERS (200) concurrent threads.
    Gateway uses GATEWAY_SCAN_WORKERS (default 50) to avoid overwhelming it.
    """
    import concurrent.futures
    import socket as _socket

    w         = workers if workers is not None else PORT_SCAN_WORKERS
    TIMEOUT   = 1.0
    # Hard cap: theoretical max is ceil(65535/w)*1.0s. Add generous margin then bail out
    # to avoid an indefinitely hung scan blocking the semaphore for hours.
    MAX_SWEEP_S = max(660, int((65535 / max(w, 1)) * 1.5 + 60))

    def _check(port: int) -> int | None:
        try:
            with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
                s.settimeout(TIMEOUT)
                return port if s.connect_ex((ip, port)) == 0 else None
        except Exception:
            return None

    open_ports: list[int] = []
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=w)
    try:
        futs = {ex.submit(_check, p): p for p in range(1, 65536)}
        try:
            for fut in concurrent.futures.as_completed(futs, timeout=MAX_SWEEP_S):
                try:
                    r = fut.result()
                    if r is not None:
                        open_ports.append(r)
                except Exception:
                    pass
        except concurrent.futures.TimeoutError:
            print(
                f"[scan] TCP sweep exceeded {MAX_SWEEP_S}s for {ip} — "
                f"returning partial results ({len(open_ports)} ports found so far)",
                flush=True,
            )
    except Exception as exc:
        print(f"[scan] TCP sweep error for {ip}: {exc}", flush=True)
    finally:
        # Wait for in-flight threads to finish — TIMEOUT=1.0s so this is bounded.
        # wait=False was leaking hundreds of open sockets on TimeoutError.
        ex.shutdown(wait=True, cancel_futures=True)
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
            is_gw = (ip == _get_default_gateway())
            workers = GATEWAY_SCAN_WORKERS if is_gw else PORT_SCAN_WORKERS
            method  = PORT_SCAN_METHOD
            print(f"[scan] {method} scan starting: {ip} ({mac}) workers={workers}", flush=True)
            if method == 'scapy_syn':
                fast_ports = _scapy_syn_scan(ip, workers=workers)
            else:
                fast_ports = _tcp_connect_sweep(ip, workers=workers)
            elapsed = round(time.monotonic() - t0, 1)
            print(f"[scan] {len(fast_ports)} open TCP port(s) on {ip} in {elapsed}s", flush=True)

            scan_results = {
                "scanned_at":    datetime.now(timezone.utc).isoformat(),
                "open_ports":    [{"port": p, "proto": "tcp", "service": ""} for p in fast_ports],
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
            if ENABLE_SERVICE_FINGERPRINTING:
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
    if not ENABLE_PORT_SCANNING:
        return
    if not _is_valid_ip(ip):
        return
    # Skip deep scan for ignored devices
    try:
        _s = Session()
        try:
            _dev = _s.get(Device, mac)
            if _dev and getattr(_dev, 'is_ignored', False):
                return
            # Skip non-primary members of a device group: grouped interfaces
            # belong to the same physical host, so scanning the primary alone is
            # sufficient. Override with the scan_grouped_members setting.
            if (_dev and getattr(_dev, 'group_id', None)
                    and not getattr(_dev, 'group_primary', False)
                    and not SCAN_GROUPED_MEMBERS):
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
# Device grouping helpers
# ---------------------------------------------------------------------------
_GENERIC_HOSTNAME_RE = re.compile(
    r'^(?:android[\-_]|iphone|ipad|localhost|dhcp|unknown|desktop[\-_]?|'
    r'workgroup|raspberrypi|my[\-_]pc|workpc|user[\-_]pc|my[\-_]laptop|'
    r'pc$|host$|node$|client$|device$)',
    re.IGNORECASE,
)


def _hostname_base(hostname: str) -> str:
    """Return the first DNS label in lowercase (strips .lan / .local / .home suffixes)."""
    if not hostname:
        return ""
    return hostname.split('.')[0].lower()


def _is_generic_hostname(hostname: str) -> bool:
    """Return True for hostnames that are too generic to reliably identify a device."""
    base = _hostname_base(hostname)
    if not base or len(base) < 3:
        return True
    # IP-literal hostnames (reverse-DNS echoing the address back, e.g.
    # "192-168-0-180.lan" or a bare numeric label) carry no identity — two
    # unrelated devices that lack real DNS names must never merge on them.
    if re.match(r'^\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}$', base) or re.match(r'^\d+$', base):
        return True
    return bool(_GENERIC_HOSTNAME_RE.match(base))


_host_ips_cache: tuple = (0.0, set())
_host_ips_lock = threading.Lock()


def _get_host_ipv4s(ttl: int = 120) -> set:
    """
    IPv4 addresses bound to the probe's active scanning interface only (cached `ttl`s).

    Scoped intentionally to INTERFACE (the LAN-facing NIC) rather than every
    interface on the host.  Scanning all interfaces would include Docker bridge
    addresses (docker0, br-xxx, compose networks, macvlan shims, VPN tuns, etc.)
    which can overlap with real LAN device IPs and falsely pin those devices online.

    The only address that genuinely can't be ARP-confirmed is the host's own IP
    on the interface the probe sweeps — that's all we need to protect.
    """
    global _host_ips_cache
    now = time.time()
    with _host_ips_lock:
        ts, cached = _host_ips_cache
        if cached and (now - ts) < ttl:
            return cached
    ips: set = set()
    try:
        from scapy.all import get_if_addr
        a = get_if_addr(INTERFACE)
        if a and a != "0.0.0.0" and _is_valid_ip(a):
            ips.add(a)
    except Exception:
        pass
    if not ips:
        try:
            out = subprocess.run(
                ["ip", "-4", "-o", "addr", "show", "dev", INTERFACE],
                capture_output=True, text=True, timeout=5,
            ).stdout
            for line in out.splitlines():
                parts = line.split()
                for i, tok in enumerate(parts):
                    if tok == "inet" and i + 1 < len(parts):
                        cand = parts[i + 1].split("/")[0]
                        if _is_valid_ip(cand):
                            ips.add(cand)
        except Exception:
            pass
    ips.discard("127.0.0.1")
    with _host_ips_lock:
        _host_ips_cache = (now, ips)
    return ips


def _is_locally_administered(mac: str) -> bool:
    """True for software/virtual MACs (locally-administered bit set), e.g. macvlan
    shims and bridges — used to prefer real hardware NICs as the group primary."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except Exception:
        return False


def _ip_sort_key(ip: str):
    try:
        return tuple(int(o) for o in ip.split("."))
    except Exception:
        return (999, 999, 999, 999)


def _choose_group_primary(members) -> str:
    """Pick the most "real" interface as the group's primary: a globally-unique
    (hardware) MAC beats a locally-administered one, an online member beats an
    offline one, then the lowest IP. Deterministic, so the primary never flaps."""
    def keyf(m):
        ip = (getattr(m, "primary_ip", None) or m.ip_address or "")
        return (
            0 if not _is_locally_administered(m.mac_address) else 1,
            0 if m.is_online else 1,
            _ip_sort_key(ip),
        )
    return min(members, key=keyf).mac_address


def retroactive_auto_group() -> None:
    """
    Periodically merge already-known devices that share the same base DNS hostname
    into a single group (one physical host, several interfaces — e.g. a server's
    real NIC plus a macvlan shim, or a laptop's wired + wireless NICs).

    Complements _try_auto_group_by_hostname, which only fires at first discovery
    against an *offline* peer. This pass also groups devices discovered long ago and
    matches online peers, so identical-hostname interfaces self-heal into one entity.
    It never disturbs a manually-curated group (group_manual) and skips any device
    the user has explicitly ungrouped (auto_group_optout).
    """
    if not AUTO_GROUP_BY_HOSTNAME:
        return
    import uuid as _uuid
    from collections import defaultdict
    s = Session()
    try:
        rows = s.execute(text("""
            SELECT mac_address, hostname, group_id, group_primary, group_manual,
                   is_online, ip_address, primary_ip
            FROM devices
            WHERE hostname IS NOT NULL AND hostname != ''
              AND COALESCE(auto_group_optout, false) = false
        """)).fetchall()

        buckets = defaultdict(list)
        for r in rows:
            base = _hostname_base(r.hostname)
            if not base or _is_generic_hostname(r.hostname):
                continue
            buckets[base].append(r)

        for base, members in buckets.items():
            if len(members) < 2:
                continue
            # Never touch a group the user built by hand.
            if any(m.group_manual for m in members):
                continue
            existing = {str(m.group_id) for m in members if m.group_id}
            gid = next(iter(existing)) if len(existing) == 1 else str(_uuid.uuid4())
            primary_mac = _choose_group_primary(members)

            already = (
                all(m.group_id and str(m.group_id) == gid for m in members)
                and sum(1 for m in members if m.group_primary) == 1
                and any(m.group_primary and m.mac_address == primary_mac for m in members)
            )
            if already:
                continue

            for m in members:
                s.execute(
                    text("UPDATE devices SET group_id = :g, group_primary = :p WHERE mac_address = :m"),
                    {"g": gid, "p": (m.mac_address == primary_mac), "m": m.mac_address},
                )
            s.commit()
            print(f"[group] Auto-grouped {[m.mac_address for m in members]} "
                  f"(base hostname='{base}', primary={primary_mac})", flush=True)
    except Exception as exc:
        s.rollback()
        print(f"[group] Retroactive auto-group error: {exc}", flush=True)
    finally:
        s.close()


def _try_auto_group_by_hostname(mac: str, hostname: str) -> bool:
    """
    Look for an offline device with the same base DNS hostname (first DNS label).
    Handles andrewlaptop == andrewlaptop.lan == andrewlaptop.local etc.

    Grouping is intentionally based on the *resolved DNS hostname* only — NOT the
    DHCP hostname.  Many unrelated devices (especially from the same vendor) send
    identical or generic DHCP hostnames, which previously caused completely
    different devices (different MAC, IP and DNS name) to be merged.  A genuine
    multi-interface device (e.g. a laptop's wired + wireless NICs) registers the
    same DNS hostname for every interface, so DNS-hostname matching is reliable.

    If AUTO_GROUP_BY_HOSTNAME is enabled, assign both to a shared group_id and
    return True (caller emits 'interface_joined' instead of 'joined').  If it is
    disabled a 'group_suggestion' event is written and False is returned.
    """
    base = _hostname_base(hostname)
    # Require a real, non-generic DNS hostname to group on.
    if not hostname or not base or _is_generic_hostname(hostname):
        return False
    import uuid as _uuid
    sess = Session()
    try:
        # Only match on the DNS hostname column, and only against devices that
        # also have a real DNS hostname (so a differing/absent DNS name on the
        # peer can never trigger a merge via DHCP-hostname coincidence).
        row = sess.execute(
            text("""
                SELECT mac_address, group_id, group_manual FROM devices
                WHERE hostname IS NOT NULL AND hostname != ''
                  AND LOWER(SPLIT_PART(hostname, '.', 1)) = :base
                  AND mac_address != :mac
                  AND is_online = false
                  AND COALESCE(auto_group_optout, false) = false
                LIMIT 1
            """),
            {"base": base, "mac": mac},
        ).fetchone()
        if not row:
            return False
        peer_mac, peer_gid, peer_manual = row[0], row[1], row[2]

        # Don't auto-merge into (or disturb) a user-curated manual group.
        if peer_manual:
            return False
        cur_manual = sess.execute(
            text("SELECT group_manual FROM devices WHERE mac_address = :m"),
            {"m": mac},
        ).scalar()
        if cur_manual:
            return False
        cur_optout = sess.execute(
            text("SELECT COALESCE(auto_group_optout, false) FROM devices WHERE mac_address = :m"),
            {"m": mac},
        ).scalar()
        if cur_optout:
            return False

        if not AUTO_GROUP_BY_HOSTNAME:
            _write_event(mac, "group_suggestion", {
                "peer_mac": peer_mac,
                "reason": f"Same base hostname '{base}' as offline device",
            })
            return False

        new_gid = str(peer_gid) if peer_gid else str(_uuid.uuid4())

        if not peer_gid:
            # Peer has no group yet — create one with peer as primary
            sess.execute(
                text("UPDATE devices SET group_id = :gid, group_primary = true WHERE mac_address = :m"),
                {"gid": new_gid, "m": peer_mac},
            )
        # Add new device to the group (non-primary)
        sess.execute(
            text("UPDATE devices SET group_id = :gid, group_primary = false WHERE mac_address = :m"),
            {"gid": new_gid, "m": mac},
        )
        sess.commit()
        print(f"[+] Auto-grouped {mac} with {peer_mac} (base DNS hostname='{base}')", flush=True)
        return True
    except Exception as exc:
        sess.rollback()
        print(f"[grouping] Error auto-grouping {mac}: {exc}", flush=True)
        return False
    finally:
        sess.close()


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

            # Guard against macvlan/proxy-ARP artifacts: if this IP is already the
            # primary IP of a *different* device, skip rather than polluting that
            # device's record with a spurious secondary-IP association.
            if not is_new and ip_changed:
                owner = session.execute(
                    text("SELECT mac_address FROM devices WHERE primary_ip = :ip AND mac_address != :mac"),
                    {"ip": ip, "mac": mac},
                ).fetchone()
                if owner:
                    print(f"[upsert] Skipping IP {ip} for {mac} — already primary IP of {owner[0]}", flush=True)
                    return

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

            # Use parameterized hostname to avoid SQL injection
            # The CASE expression is constructed safely: hostname value goes via bindparam
            hostname_val = hostname or ""

            # primary_ip CASE expressions depend on PRIMARY_IP_MODE:
            #   locked  (default): respect per-device primary_ip_locked flag
            #   dynamic (main-style): always adopt new IP when device returns from offline
            _hostname_case = (
                "CASE WHEN devices.hostname IS NOT NULL AND devices.hostname != '' "
                "THEN devices.hostname ELSE EXCLUDED.hostname END"
            )
            if PRIMARY_IP_MODE == "dynamic":
                _new_primary_ip_case = (
                    "CASE WHEN devices.primary_ip IS NOT NULL "
                    "THEN devices.primary_ip ELSE EXCLUDED.primary_ip END"
                )
                _existing_primary_ip_case = (
                    "CASE "
                    "WHEN devices.is_online = false THEN EXCLUDED.primary_ip "
                    "WHEN devices.primary_ip IS NOT NULL THEN devices.primary_ip "
                    "ELSE EXCLUDED.primary_ip END"
                )
            else:
                _new_primary_ip_case = (
                    "CASE WHEN devices.primary_ip_locked = true THEN devices.primary_ip "
                    "WHEN devices.primary_ip IS NOT NULL THEN devices.primary_ip "
                    "ELSE EXCLUDED.primary_ip END"
                )
                _existing_primary_ip_case = (
                    "CASE "
                    "WHEN devices.primary_ip_locked = true THEN devices.primary_ip "
                    "WHEN devices.is_online = false THEN EXCLUDED.primary_ip "
                    "WHEN devices.primary_ip IS NOT NULL THEN devices.primary_ip "
                    "ELSE EXCLUDED.primary_ip END"
                )

            if is_new:
                stmt = (
                    pg_insert(Device)
                    .values(
                        mac_address              = mac,
                        ip_address               = ip,
                        primary_ip               = ip,
                        hostname                 = hostname_val or None,
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
                            ip_address = text(
                                "CASE WHEN devices.primary_ip_locked "
                                "THEN devices.primary_ip ELSE :new_ip END"
                            ).bindparams(new_ip=ip),
                            primary_ip = text(_new_primary_ip_case),
                            is_online  = True,
                            last_seen  = text("CASE WHEN devices.is_online = false THEN NOW() ELSE devices.last_seen END"),
                            miss_count = 0,
                            hostname   = text(_hostname_case),
                        ),
                    )
                )
            else:
                # ── Sticky-primary / multi-homed handling ────────────────────
                # A single MAC can answer ARP for several IPs at once (a server
                # with two addresses on one NIC, a bridge, etc.). Without this,
                # every sweep overwrites ip_address with whichever IP was seen
                # last and emits an ip_change event, so the device's IP appears
                # to flap between its addresses forever. Resolve the primary in
                # Python (we already hold the per-MAC lock) and pin ip_address to
                # it; non-primary sightings become passive secondary IPs.
                cur_primary = existing.primary_ip or old_ip
                locked      = bool(getattr(existing, "primary_ip_locked", False))
                # The `existing` snapshot is read at the start of this function and
                # can be STALE: the backend pin (a separate process) may have just
                # committed primary_ip_locked=True after our read but before our
                # write. Re-read the lock state under a row lock (FOR UPDATE) so the
                # value is authoritative AND the row is held until our UPDATE
                # commits — this serialises us against the backend pin and removes
                # the race that let a freshly-pinned primary revert to a secondary.
                try:
                    _lk = session.execute(
                        text("SELECT primary_ip, primary_ip_locked "
                             "FROM devices WHERE mac_address = :m FOR UPDATE"),
                        {"m": mac},
                    ).fetchone()
                    if _lk is not None:
                        if _lk[0]:
                            cur_primary = _lk[0]
                        locked = bool(_lk[1])
                except Exception as _e:
                    print(f"[upsert] lock re-read failed for {mac}: {_e}", flush=True)
                # A user-pinned primary IP is the strongest, most explicit signal
                # of intent and must ALWAYS win — including in "dynamic" mode.
                # PRIMARY_IP_MODE only governs how UNpinned devices behave. Without
                # this guard, a pinned device that briefly blips offline/online has
                # its primary silently overwritten by whichever IP was seen on
                # return (e.g. a multi-homed host reverting from .2 back to .6),
                # even though the lock flag stays set.
                if locked and cur_primary:
                    new_primary = cur_primary
                elif PRIMARY_IP_MODE == "dynamic":
                    new_primary = ip if not was_online else (cur_primary or ip)
                elif not was_online:
                    new_primary = ip
                else:
                    new_primary = cur_primary or ip
                # While online, any IP other than the primary is a secondary
                # interface — unless the primary itself has gone stale, meaning
                # the host really moved and the new IP should take over.
                is_secondary_sighting = bool(was_online and ip != new_primary)
                if (is_secondary_sighting and not locked
                        and _primary_ip_is_stale(mac, new_primary)):
                    new_primary           = ip
                    is_secondary_sighting = False
                # For a PINNED device the pinned IP is authoritative for BOTH
                # primary_ip and the displayed ip_address. Without forcing
                # ip_to_store here, a sighting on the shim/secondary IP while the
                # device was briefly offline (was_online=False, so it is not
                # classed as a "secondary sighting") would still overwrite
                # ip_address with that IP — making the device appear to revert to
                # e.g. .6 even though the primary stayed pinned at .2.
                if locked and cur_primary:
                    ip_to_store = cur_primary
                else:
                    ip_to_store = new_primary if is_secondary_sighting else ip

                # Diagnostic: log whenever a sighting differs from the current
                # primary so the pin/secondary decision is visible in probe logs.
                # `locked` reflects the Python snapshot; the SQL UPDATE re-checks
                # the live lock, so this is purely informational.
                if ip != cur_primary:
                    print(
                        f"[upsert] {mac}: sighting {ip} differs from primary {cur_primary} "
                        f"(locked={locked}, was_online={was_online}, mode={PRIMARY_IP_MODE}, "
                        f"new_primary={new_primary}, ip_to_store={ip_to_store}, source={source})",
                        flush=True,
                    )

                stmt = (
                    pg_insert(Device)
                    .values(
                        mac_address  = mac,
                        ip_address   = ip_to_store,
                        primary_ip   = existing.primary_ip or ip,
                        hostname     = hostname_val or None,
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
                            # Enforce the user pin at the SQL level: read the LIVE
                            # committed primary_ip_locked during the UPDATE rather
                            # than trusting the Python-side `existing` snapshot
                            # (which could be stale under concurrency between the
                            # sniffer, the sweep and the backend pin). When the row
                            # is locked, BOTH the primary and the displayed IP stay
                            # pinned to the existing primary_ip; otherwise they take
                            # the values computed in Python above.
                            ip_address = text(
                                "CASE WHEN devices.primary_ip_locked "
                                "THEN devices.primary_ip ELSE :computed_ip END"
                            ).bindparams(computed_ip=ip_to_store),
                            primary_ip = text(
                                "CASE WHEN devices.primary_ip_locked "
                                "THEN devices.primary_ip ELSE :computed_primary END"
                            ).bindparams(computed_primary=new_primary),
                            is_online  = True,
                            last_seen  = text("CASE WHEN devices.is_online = false THEN NOW() ELSE devices.last_seen END"),
                            miss_count = 0,
                            hostname   = text(_hostname_case),
                        ),
                    )
                )

            session.execute(stmt)
            session.commit()

            if is_new:
                print(f"[+] New device via {source}: {ip} ({mac}) hostname={hostname} vendor={vendor}", flush=True)
                grouped = _try_auto_group_by_hostname(mac, hostname_val)
                _write_event(mac, "interface_joined" if grouped else "joined", {"ip": ip, "vendor": vendor or "Unknown"})
                # Prefer the resolved primary IP for consistency with the
                # reconnect and manual-rescan paths — important for multi-homed
                # or grouped hosts where the just-seen IP may be a secondary.
                _scan_ip = ip
                try:
                    _ns = Session()
                    try:
                        _nd = _ns.get(Device, mac)
                        if _nd and getattr(_nd, "primary_ip", None) and _is_valid_ip(_nd.primary_ip):
                            _scan_ip = _nd.primary_ip
                    finally:
                        _ns.close()
                except Exception:
                    pass
                trigger_deep_scan(_scan_ip, mac)
            else:
                if not was_online:
                    print(f"[~] Back online via {source}: {ip} ({mac})", flush=True)
                    # A device coming back online clears its "confirmed offline" state
                    # so a future genuine offline transition will be recorded.
                    with _confirmed_offline_lock:
                        _confirmed_offline_macs.discard(mac)
                    # Suppressed devices: keep status accurate but don't log the event.
                    if not getattr(existing, "suppress_presence_events", False):
                        _write_event(mac, "online", {"ip": ip, "source": source})
                if ip_changed:
                    if is_secondary_sighting:
                        # Multi-homed host answering on a non-primary IP. This is
                        # NOT an IP change — record it as a passive secondary and
                        # emit no event, so the timeline no longer flaps.
                        print(f"[~] Secondary IP {ip} for {mac} (primary stays {new_primary}, source={source})", flush=True)
                    elif new_primary != cur_primary:
                        # Genuine primary change: offline-return at a new IP, or the
                        # old primary went stale and this IP took over.
                        print(f"[~] Primary IP {cur_primary} → {new_primary} for {mac} (source={source})", flush=True)
                        _write_event(mac, "primary_ip_changed", {"old_ip": cur_primary, "new_ip": new_primary})
                    # else: ip_address realigned to an unchanged primary — no event.

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

    # Proactively trigger scan for any device returning from offline that still needs scanning.
    # Avoids waiting a full sweep cycle for the unscanned-retry loop to pick it up.
    if was_online is False and not is_new:
        _sr = Session()
        try:
            _dev_r = _sr.get(Device, mac)
            if _dev_r and not _dev_r.deep_scanned:
                trigger_deep_scan(_dev_r.primary_ip or ip, mac)
        except Exception:
            pass
        finally:
            _sr.close()

    # seen_while_online = True when the device was already online at a different IP
    # (multi-homed / dual-stack), vs DHCP rotation where device was offline.
    is_brand_new_ip = record_ip(mac, ip, seen_while_online=bool(was_online and ip_changed))

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
    if not ENABLE_HOSTNAME_RESOLUTION:
        return
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


# ---------------------------------------------------------------------------
# Sniffer
# ---------------------------------------------------------------------------
def process_arp_packet(packet) -> None:
    if not ENABLE_PASSIVE_SNIFFER:
        return
    if not packet.haslayer(ARP):
        return
    # Ignore ARP packets that the probe itself sent (e.g. ARP restore packets
    # sent after unblocking a device, which carry hwsrc=target_mac and would
    # falsely mark that device as "seen this interval").
    if packet.haslayer(Ether):
        ether_src = (packet[Ether].src or "").lower().strip()
        if _PROBE_OWN_MAC and ether_src == _PROBE_OWN_MAC:
            return
    arp = packet[ARP]
    mac = (arp.hwsrc or "").lower().strip()
    ip  = (arp.psrc  or "").strip()
    if not mac or not ip or mac == "ff:ff:ff:ff:ff:ff" or mac.startswith("01:"):
        return
    if not _is_valid_ip(ip):
        return
    if SNIFFER_SUBNET_FILTER:
        try:
            if ipaddress.ip_address(ip) not in ipaddress.ip_network(IP_RANGE, strict=False):
                return
        except ValueError:
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


# ---------------------------------------------------------------------------
# DHCP fingerprinting (passive — zero extra network traffic)
# ---------------------------------------------------------------------------
def process_dhcp_packet(packet) -> None:
    """Extract DHCP Options 12/55/60 from client broadcasts and queue for DB write."""
    if not ENABLE_PASSIVE_SNIFFER:
        return
    if not packet.haslayer(BOOTP) or not packet.haslayer(DHCP):
        return
    bootp = packet[BOOTP]
    if bootp.op != 1:
        return  # only client requests (op=1); ignore server replies

    # MAC from BOOTP hardware address field (more reliable than Ethernet src)
    mac_bytes = bytes(bootp.chaddr)[:6]
    mac = ':'.join(f'{b:02x}' for b in mac_bytes)
    if not mac or mac == '00:00:00:00:00:00' or mac == 'ff:ff:ff:ff:ff:ff':
        return

    opts: dict = {}
    for opt in packet[DHCP].options:
        if isinstance(opt, tuple) and len(opt) == 2:
            opts[opt[0]] = opt[1]

    msg_type = opts.get('message-type', 0)
    if msg_type not in (1, 3):  # Discover or Request only
        return

    def _decode(v) -> str | None:
        if v is None:
            return None
        if isinstance(v, bytes):
            return v.decode('utf-8', errors='replace').strip() or None
        return str(v).strip() or None

    hostname     = _decode(opts.get('hostname'))
    vendor_class = _decode(opts.get('vendor_class_id'))

    raw_pl = opts.get('param_req_list')
    if isinstance(raw_pl, bytes):
        opt55 = list(raw_pl)
    elif isinstance(raw_pl, (list, tuple)):
        opt55 = [int(x) for x in raw_pl]
    else:
        opt55 = []

    print(f"[dhcp] {mac}  type={'Discover' if msg_type==1 else 'Request'}"
          f"  vc={vendor_class!r}  host={hostname!r}  opt55_len={len(opt55)}", flush=True)
    try:
        _dhcp_queue.put_nowait((mac, hostname, vendor_class, opt55 if opt55 else None))
    except queue.Full:
        pass


# Matches hostnames auto-generated from IP addresses, e.g. "192-168-0-15.lan", "10.0.0.5"
_IP_DERIVED_RE = re.compile(r'^(\d{1,3}[.\-_]){3}\d{1,3}(\.[a-z]{1,12})?$', re.I)

def _is_ip_derived_hostname(h: str | None) -> bool:
    if not h:
        return True
    return bool(_IP_DERIVED_RE.match(h))


def _upsert_dhcp_info(mac: str, hostname: str | None, vendor_class: str | None, opt55: list[int] | None) -> None:
    """Write DHCP fingerprint data to the device row and optionally refine device_type."""
    fingerprint_str = ','.join(str(x) for x in opt55) if opt55 else None
    dtype, conf = _dhcp_cls.classify_from_dhcp(vendor_class, opt55)

    session = Session()
    try:
        device = session.get(Device, mac)
        if device is None:
            return  # device not seen by ARP yet; skip (no orphan rows)

        changed = False

        if hostname:
            if device.dhcp_hostname != hostname:
                device.dhcp_hostname = hostname
                changed = True
            # Replace hostname when it looks auto-generated from the IP address
            if _is_ip_derived_hostname(device.hostname) and hostname != device.hostname:
                conflict = session.query(Device).filter(
                    Device.hostname == hostname,
                    Device.mac_address != mac,
                ).first()
                if not conflict:
                    device.hostname = hostname
                    changed = True

        if vendor_class and device.dhcp_vendor_class != vendor_class:
            device.dhcp_vendor_class = vendor_class
            changed = True

        if fingerprint_str and device.dhcp_fingerprint != fingerprint_str:
            device.dhcp_fingerprint = fingerprint_str
            changed = True

        # Apply DHCP-inferred type only if no user override and confidence is sufficient
        if dtype != "unknown" and conf >= 0.75 and not device.device_type_override:
            # Don't overwrite an already-correct inference stored in scan_results
            current_sr_type = (device.scan_results or {}).get("device_type")
            if current_sr_type != dtype:
                sr = dict(device.scan_results or {})
                sr["device_type"]        = dtype
                sr["device_type_source"] = "dhcp"
                sr["device_type_conf"]   = conf
                device.scan_results = sr
                flag_modified(device, "scan_results")
                changed = True

        if changed:
            session.commit()
            dtype_msg = f"  → type={dtype}({conf:.0%})" if dtype != "unknown" else ""
            print(f"[dhcp] saved {mac}  vc={vendor_class!r}  host={hostname!r}{dtype_msg}", flush=True)
    except Exception as exc:
        session.rollback()
        print(f"[dhcp-worker] DB error for {mac}: {exc}", flush=True)
    finally:
        session.close()


def _dhcp_worker() -> None:
    while True:
        try:
            mac, hostname, vendor_class, opt55 = _dhcp_queue.get(timeout=1)
            _upsert_dhcp_info(mac, hostname, vendor_class, opt55)
            _dhcp_queue.task_done()
        except queue.Empty:
            continue
        except Exception as exc:
            print(f"[dhcp-worker] {exc}", flush=True)


def _dispatch_packet(packet) -> None:
    """Route captured packets to ARP or DHCP handler."""
    if packet.haslayer(ARP):
        process_arp_packet(packet)
    elif packet.haslayer(DHCP):
        process_dhcp_packet(packet)


def start_arp_sniffer() -> None:
    # Refresh own-MAC now that INTERFACE is finalised (settings loaded). Used to
    # ignore the probe's own ARP packets (e.g. unblock ARP-restore packets).
    global _PROBE_OWN_MAC
    own = _get_own_mac(INTERFACE)
    if own:
        _PROBE_OWN_MAC = own
        print(f"[*] Probe interface MAC: {_PROBE_OWN_MAC} (own ARP packets ignored)", flush=True)
    for i in range(SNIFFER_WORKERS):
        threading.Thread(target=_sniffer_worker, name=f"sniffer-worker-{i}", daemon=True).start()
    # One DHCP worker is plenty — DHCP traffic is very infrequent
    threading.Thread(target=_dhcp_worker, name="dhcp-worker", daemon=True).start()
    print(f"[*] Passive ARP+DHCP sniffer on {INTERFACE} ({SNIFFER_WORKERS} ARP workers)", flush=True)
    sniff(iface=INTERFACE, filter="arp or (udp and (port 67 or port 68))",
          store=False, prn=_dispatch_packet)

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

    # The probe shares the host's network namespace, so the host's own IPs (its
    # NIC, macvlan shims, bridges) never show up in the ARP sweep — a host doesn't
    # ARP for itself. Treat any device holding one of these as always-present so
    # the Docker host and its shim interfaces don't get marked offline despite
    # being trivially reachable.
    own_ips = _get_host_ipv4s()

    for dev in session.query(Device).all():
        dev_ip = (getattr(dev, "primary_ip", None) or dev.ip_address or "")
        if dev.mac_address in seen_this_cycle or (dev_ip and dev_ip in own_ips):
            dev.is_online = True
            dev.miss_count = 0
            continue

        suppressed = getattr(dev, "suppress_presence_events", False)

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

        # Suppressed devices: is_online is updated above for accurate status display
        # but no event is written and the confirmed-offline set is not touched.
        if suppressed:
            continue

        # Only write an offline event if the device has come online since the
        # last offline event was written. This suppresses repeated offline
        # events for devices that are continuously offline (e.g. a plugin keeps
        # resetting is_online=True between sweeps).
        with _confirmed_offline_lock:
            already_offline = dev.mac_address in _confirmed_offline_macs
            _confirmed_offline_macs.add(dev.mac_address)
        if not already_offline:
            _write_event(dev.mac_address, "offline", {
                "ip": confirm_ip or dev.ip_address,
                "source": "sweep",
                "confirmation": "icmp" if confirm_ip else None,
            })

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

    Nerva 1.4+ emits multiple lines per port when HTTP fingerprinting identifies
    a specific application on top of the generic protocol, e.g.:
        https://192.168.1.1:443 (tls)
        checkpoint-firewall://192.168.1.1:443 (tls)

    We collect ALL candidates per port, prefer the most specific (non-generic HTTP/S)
    scheme, and detect TLS from both the scheme name AND the (tls) annotation.
    """
    _TLS_SCHEMES  = {"https", "mqtts", "ldaps", "ftps", "imaps", "pop3s", "smtps", "rediss", "wss"}
    _HTTP_GENERIC = {"http", "https"}

    # port → list of (scheme, tls_flag)
    candidates: dict[int, list[tuple[str, bool]]] = {}

    for line in output.strip().splitlines():
        line = line.strip()
        if not line or "://" not in line:
            continue
        try:
            scheme, rest = line.split("://", 1)
            scheme = scheme.lower()
            tls = "(tls)" in line.lower() or scheme in _TLS_SCHEMES
            host_part = rest.split("/")[0].split(" ")[0]
            if ":" not in host_part:
                continue
            _, port_str = host_part.rsplit(":", 1)
            port = int(port_str)
            candidates.setdefault(port, []).append((scheme, tls))
        except (ValueError, IndexError):
            continue

    services: list[dict] = []
    for port, entries in sorted(candidates.items()):
        # Prefer specific fingerprints over generic http/https
        specific = [(s, t) for s, t in entries if s not in _HTTP_GENERIC]
        chosen_scheme, chosen_tls = specific[0] if specific else entries[0]
        # If any entry for this port indicates TLS, the port is TLS
        chosen_tls = chosen_tls or any(t for _, t in entries)
        services.append({"port": port, "service": chosen_scheme, "protocol": "tcp", "tls": chosen_tls})

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



# ---------------------------------------------------------------------------
# Nuclei template updater
# ---------------------------------------------------------------------------
def _nuclei_templates_exist() -> bool:
    templates_dir = "/root/nuclei-templates"
    return os.path.isdir(templates_dir) and bool(os.listdir(templates_dir))


def _nuclei_template_update_loop() -> None:
    """Background thread that periodically runs nuclei -update-templates."""
    global _last_nuclei_template_update
    # If templates dir is empty, download immediately without waiting
    if not _nuclei_templates_exist() and shutil.which("nuclei"):
        print("[nuclei] Templates directory empty — downloading now.", flush=True)
        try:
            result = subprocess.run(
                ["nuclei", "-update-templates"],
                capture_output=True, text=True, timeout=600,
            )
            if result.returncode == 0:
                print("[nuclei] Initial template download complete.", flush=True)
                _last_nuclei_template_update = datetime.now(timezone.utc)
            else:
                print(f"[nuclei] Initial download failed (exit {result.returncode})", flush=True)
        except Exception as exc:
            print(f"[nuclei] Initial download error: {exc}", flush=True)
    time.sleep(120)  # startup grace period before periodic loop
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
# CORS: the probe API is normally called server-side by the backend (httpx), not
# by browsers. Origins can be locked down via PROBE_ALLOWED_ORIGINS (comma-separated);
# defaults to "*" to preserve existing behaviour for direct/diagnostic access.
_PROBE_ALLOWED_ORIGINS = [
    o.strip() for o in os.environ.get("PROBE_ALLOWED_ORIGINS", "*").split(",") if o.strip()
] or ["*"]
probe_api.add_middleware(
    CORSMiddleware,
    allow_origins=_PROBE_ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Shared-secret authentication for backend -> probe calls. Enforced only when
# PROBE_API_SECRET is set (shared with the backend container). When unset, the
# probe accepts requests unauthenticated for backward compatibility. /health is
# always public so container healthchecks keep working.
PROBE_API_SECRET = os.environ.get("PROBE_API_SECRET", "").strip()
_PROBE_PUBLIC_PATHS = {"/health"}

@probe_api.middleware("http")
async def _probe_auth_middleware(request, call_next):
    if PROBE_API_SECRET and request.url.path not in _PROBE_PUBLIC_PATHS:
        if request.headers.get("X-Probe-Secret") != PROBE_API_SECRET:
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
    return await call_next(request)

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
        # If the client disconnected (GeneratorExit) or an error occurred while the
        # child is still running, terminate it so we don't leak long-running processes.
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except Exception:
                    proc.kill()
            except Exception:
                pass


@probe_api.get("/health")
def probe_health():
    with _scan_lock:
        active_port_scans = list(_scanning)
        scanning_count = len(active_port_scans)
    return {
        "ok": True,
        "status": "ok",
        "message": f"Probe running — scanning {IP_RANGE}, {scanning_count} active port scan(s)",
        "active_port_scans": active_port_scans,
        "version": VERSION,
        "dns_server": _DNS_SERVER,
        "config": {
            "scan_interval": SCAN_INTERVAL,
            "ip_range": IP_RANGE,
            "port_scan_workers": PORT_SCAN_WORKERS,
            "gateway_scan_workers": GATEWAY_SCAN_WORKERS,
            "os_confidence_threshold": OS_CONFIDENCE_THRESHOLD,
            "offline_miss_threshold": OFFLINE_MISS_THRESHOLD,
            "sniffer_workers": SNIFFER_WORKERS,
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

    def _expand_ports(spec: str) -> list[int]:
        out: list[int] = []
        for part in spec.split(','):
            part = part.strip()
            if not part:
                continue
            if '-' in part:
                a, b = part.split('-', 1)
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
        # Ookla speedtest CLI — multi-stream by default (Ookla has no single-stream flag)
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
                        # Emit final bandwidth values so UI shows correct peak
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
            raw = data.get("servers", [])
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
    broadcast = (body.get("broadcast") or "255.255.255.255").strip()
    if not mac:
        raise HTTPException(400, "mac required")
    # Validate broadcast target: must be a literal IPv4 address (limited or
    # subnet broadcast). Prevents sending magic packets to arbitrary hosts.
    import ipaddress as _ipa
    try:
        _ipa.IPv4Address(broadcast)
    except Exception:
        raise HTTPException(400, "Invalid broadcast address")
    # Normalise MAC and build magic packet
    import re, socket
    mac_clean = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(mac_clean) != 12:
        raise HTTPException(400, "Invalid MAC address")
    magic = bytes.fromhex("FF" * 6 + mac_clean * 16)

    # Build the set of broadcast targets. The global broadcast 255.255.255.255 is
    # frequently not routed to the correct NIC, so we ALSO send to the subnet-
    # directed broadcast derived from the probe's configured IP_RANGE (e.g.
    # 192.168.0.255). Magic packets go out on both common WoL ports (9 and 7).
    targets = [broadcast]
    try:
        net = _ipa.ip_network(IP_RANGE, strict=False)
        sub_bcast = str(net.broadcast_address)
        if sub_bcast not in targets:
            targets.append(sub_bcast)
    except Exception:
        pass

    _SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)
    sent, errors = [], []
    for tgt in targets:
        for port in (9, 7):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    # Bind to the probe interface so the broadcast egresses the
                    # LAN NIC rather than whatever the default route points at.
                    try:
                        s.setsockopt(socket.SOL_SOCKET, _SO_BINDTODEVICE, INTERFACE.encode())
                    except Exception:
                        pass
                    s.sendto(magic, (tgt, port))
                sent.append(f"{tgt}:{port}")
            except Exception as exc:
                errors.append(f"{tgt}:{port} -> {exc}")

    # Raw Layer-2 magic packets (etherwake style). Many NIC/BIOS WoL
    # implementations only wake on an Ethernet frame addressed directly to the
    # target MAC (EtherType 0x0842), NOT on a UDP/IP broadcast. We send both a
    # directed frame (dst = target MAC) and an L2 broadcast frame. This is the
    # key behaviour that makes dedicated WoL tools (e.g. Fing) succeed where a
    # plain UDP broadcast fails. Requires CAP_NET_RAW (granted to the probe).
    l2_sent, l2_errors = [], []
    src_mac = None
    try:
        from scapy.all import Ether, Raw, sendp, get_if_hwaddr
        target_mac = ":".join(mac_clean[i:i+2] for i in range(0, 12, 2))
        # CRITICAL: set a valid source MAC. If left unset, scapy may emit an
        # all-zero source MAC (00:00:00:00:00:00), which switches treat as a
        # malformed frame and silently drop — so the magic packet never reaches
        # the target. Use the probe interface's real hardware address.
        src_mac = _PROBE_OWN_MAC or _get_own_mac(INTERFACE)
        if not src_mac or src_mac == "00:00:00:00:00:00":
            try:
                src_mac = get_if_hwaddr(INTERFACE)
            except Exception:
                src_mac = None
        for dst in (target_mac, "ff:ff:ff:ff:ff:ff"):
            try:
                eth = Ether(dst=dst, type=0x0842)
                if src_mac:
                    eth.src = src_mac
                frame = eth / Raw(load=magic)
                # Burst the frame: a sleeping NIC's PHY may run at reduced link
                # speed and miss the first frame while it powers up the receiver.
                sendp(frame, iface=INTERFACE, count=5, inter=0.12, verbose=0)
                l2_sent.append(f"L2:{dst}")
            except Exception as exc:
                l2_errors.append(f"L2:{dst} -> {exc}")
    except Exception as exc:
        l2_errors.append(f"scapy unavailable: {exc}")

    sent.extend(l2_sent)
    errors.extend(l2_errors)

    print(f"[wol] mac={mac} iface={INTERFACE} src_mac={src_mac} ip_range={IP_RANGE} "
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


@probe_api.post("/ssdp/refresh")
def probe_ssdp_refresh():
    """Trigger an active SSDP M-SEARCH and store results."""
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
    """Detect network configuration from the host (probe runs on host network)."""
    import ipaddress as _ipaddress
    info = {
        "interface":  INTERFACE,
        "ip_range":   None,
        "gateway":    None,
        "dns_server": _DNS_SERVER,
    }
    # Detect gateway and interface from the host routing table
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
    # Derive the network CIDR from the detected interface
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
    # Fall back: if DNS not yet detected, use gateway
    if not info["dns_server"] and info["gateway"]:
        info["dns_server"] = info["gateway"]
    return info


@probe_api.post("/restart")
def probe_restart():
    """Gracefully exit so Docker restart policy brings the probe back up."""
    def _do():
        time.sleep(0.5)
        os.kill(os.getpid(), signal.SIGTERM)
    threading.Thread(target=_do, daemon=True).start()
    return {"ok": True, "restarting": True}


@probe_api.get("/nuclei/status")
def nuclei_status():
    templates_dir = "/root/nuclei-templates"
    exists = _nuclei_templates_exist()
    version = None
    try:
        with open(os.path.join(templates_dir, ".version")) as f:
            version = f.read().strip()
    except Exception:
        pass
    return {
        "exists": exists,
        "version": version,
        "last_updated": _last_nuclei_template_update.isoformat() if _last_nuclei_template_update else None,
        "binary_available": bool(shutil.which("nuclei")),
    }


_nuclei_update_lock = asyncio.Lock()


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
        global _last_nuclei_template_update
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
                    _last_nuclei_template_update = datetime.now(timezone.utc)
                    yield "data: [INFO] Templates updated successfully.\n\n"
                else:
                    yield f"data: [ERROR] nuclei exited with code {proc.returncode}\n\n"
            except Exception as exc:
                yield f"data: [ERROR] {exc}\n\n"
        yield "data: NUCLEI_UPDATE_DONE\n\n"

    return StreamingResponse(_stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


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
    """Re-fingerprint devices whose services are empty AND whose last deep scan
    was more than 24 hours ago (or never ran). This prevents re-running Nerva
    on every container restart for recently-scanned devices.
    Always uses the device's CURRENT ip_address, not the historical primary_ip."""
    time.sleep(15)  # let sniffer / ARP threads settle first
    now = datetime.now(timezone.utc)
    backfill_threshold = now - timedelta(hours=24)
    active = {t.name for t in threading.enumerate()}
    _nerva_backfill_sem = threading.Semaphore(3)

    def _run_nerva_fingerprint_limited(scan_ip, mac, ports):
        with _nerva_backfill_sem:
            _run_nerva_fingerprint(scan_ip, mac, ports)

    session = Session()
    count = 0
    try:
        devices = session.query(Device).filter(Device.deep_scanned == True).all()
        for dev in devices:
            sr = dev.scan_results or {}
            pipeline_stage = sr.get("pipeline_stage")
            services       = sr.get("services")

            # Only backfill if services are empty AND pipeline is stuck/incomplete
            needs_backfill = (
                pipeline_stage in ("services_done", "ports_done")
                and not services  # catches [] and None
                and sr.get("open_ports")
            )
            if not needs_backfill:
                continue

            # Cooldown: skip if scanned within the last 24 hours
            last_run = dev.deep_scan_last_run
            if last_run is not None and last_run > backfill_threshold:
                print(
                    f"[nerva] Backfill skipped (cooldown): {dev.mac_address} "
                    f"last scanned {(now - last_run).total_seconds() / 3600:.1f}h ago",
                    flush=True,
                )
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
                target=_run_nerva_fingerprint_limited,
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
# Hostname group backfill (runs once at startup)
# ---------------------------------------------------------------------------
def _backfill_hostname_groups() -> None:
    """
    Group already-stored devices that share a base DNS hostname but have no group
    yet.  Runs once at startup so existing devices are covered without needing
    rediscovery.

    Like _try_auto_group_by_hostname, this matches on the resolved DNS hostname
    ONLY (never the DHCP hostname) to avoid merging unrelated devices that happen
    to send the same/generic DHCP hostname.
    """
    if not AUTO_GROUP_BY_HOSTNAME:
        return
    import uuid as _uuid
    sess = Session()
    try:
        rows = sess.execute(text("""
            SELECT mac_address, hostname, dhcp_hostname, group_id, group_primary, is_online, last_seen, group_manual
            FROM devices
            WHERE hostname IS NOT NULL AND hostname != ''
        """)).fetchall()

        # base_hostname -> list of device dicts
        base_map: dict[str, list] = {}
        for row in rows:
            mac, hn, dhcp_hn, gid, gprimary, online, last_seen, gmanual = row
            # Leave user-curated (manual) groups untouched.
            if gmanual:
                continue
            base = _hostname_base(hn or '')
            if not base or _is_generic_hostname(base):
                continue
            base_map.setdefault(base, []).append({
                "mac": mac, "group_id": gid, "group_primary": bool(gprimary),
                "is_online": bool(online), "last_seen": last_seen,
            })

        assigned = 0
        for base, devs in base_map.items():
            if len(devs) < 2:
                continue
            # Already fully grouped in the same group — nothing to do
            gids = [str(d["group_id"]) for d in devs if d["group_id"]]
            if len(gids) == len(devs) and len(set(gids)) == 1:
                continue

            # Pick (or reuse) a group UUID
            new_gid = gids[0] if gids else str(_uuid.uuid4())

            # Choose primary: single online device wins; else most recently seen
            online_devs = [d for d in devs if d["is_online"]]
            if len(online_devs) == 1:
                primary_mac = online_devs[0]["mac"]
            else:
                primary_mac = max(
                    devs,
                    key=lambda d: d["last_seen"] or datetime.min.replace(tzinfo=timezone.utc),
                )["mac"]

            for d in devs:
                want_primary = (d["mac"] == primary_mac)
                if (d["group_id"] and str(d["group_id"]) == new_gid
                        and d["group_primary"] == want_primary):
                    continue
                sess.execute(
                    text("UPDATE devices SET group_id = :gid, group_primary = :pri WHERE mac_address = :mac"),
                    {"gid": new_gid, "pri": want_primary, "mac": d["mac"]},
                )
                assigned += 1

        if assigned:
            sess.commit()
            print(f"[grouping] Backfill: grouped {assigned} device(s) by base hostname", flush=True)
        else:
            print("[grouping] Backfill: no ungrouped hostname matches found", flush=True)
    except Exception as exc:
        sess.rollback()
        print(f"[grouping] Backfill error: {exc}", flush=True)
    finally:
        sess.close()


def _cleanup_bad_hostname_groups() -> None:
    """
    One-shot repair for groups created by the previous (over-eager) grouping
    logic, which merged devices on DHCP-hostname coincidence.

    A legitimate multi-interface group shares a single resolved DNS hostname.
    Any existing group whose members have *conflicting* DNS hostnames (≥2 distinct
    base DNS names), or no resolved DNS hostname at all, was almost certainly a
    bad DHCP-hostname merge — so we split it: members are regrouped by their DNS
    hostname base, and members with a unique/empty DNS name are ungrouped.
    """
    import uuid as _uuid
    sess = Session()
    try:
        rows = sess.execute(text("""
            SELECT mac_address, hostname, group_id, group_manual
            FROM devices
            WHERE group_id IS NOT NULL
        """)).fetchall()

        groups: dict[str, list] = {}
        group_is_manual: dict[str, bool] = {}
        for mac, hn, gid, gmanual in rows:
            key = str(gid)
            groups.setdefault(key, []).append({"mac": mac, "hostname": hn})
            if gmanual:
                group_is_manual[key] = True

        repaired = 0
        for gid, members in groups.items():
            if len(members) < 2:
                continue
            # Never touch user-curated (manual) groups — they may legitimately
            # span different DNS hostnames.
            if group_is_manual.get(gid):
                continue
            # Distinct, non-generic DNS hostname bases present in this group
            bases = {}
            for m in members:
                base = _hostname_base(m["hostname"] or "")
                if base and not _is_generic_hostname(base):
                    bases.setdefault(base, []).append(m["mac"])

            # A clean group has exactly one DNS base shared by its members.
            if len(bases) == 1:
                continue

            # Bad merge: dissolve and rebuild strictly by DNS base.
            for m in members:
                sess.execute(text(
                    "UPDATE devices SET group_id = NULL, group_primary = false WHERE mac_address = :mac"
                ), {"mac": m["mac"]})
                repaired += 1

            # Re-form a group only where ≥2 devices genuinely share a DNS base.
            for base, macs in bases.items():
                if len(macs) < 2:
                    continue
                new_gid = str(_uuid.uuid4())
                for i, mac in enumerate(macs):
                    sess.execute(text(
                        "UPDATE devices SET group_id = :gid, group_primary = :pri WHERE mac_address = :mac"
                    ), {"gid": new_gid, "pri": i == 0, "mac": mac})

        if repaired:
            sess.commit()
            print(f"[grouping] Cleanup: dissolved/repaired {repaired} mis-grouped device(s)", flush=True)
        else:
            print("[grouping] Cleanup: no bad hostname groups found", flush=True)
    except Exception as exc:
        sess.rollback()
        print(f"[grouping] Cleanup error: {exc}", flush=True)
    finally:
        sess.close()


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
    threading.Thread(target=refresh_missing_vendors,   daemon=True, name="vendor-refresh").start()
    threading.Thread(target=_startup_nerva_backfill,   daemon=True, name="nerva-backfill").start()
    def _group_maintenance():
        _cleanup_bad_hostname_groups()
        _backfill_hostname_groups()
    threading.Thread(target=_group_maintenance, daemon=True, name="group-backfill").start()
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

    _background_started = False

    while True:
        _load_settings_from_db()

        # Don't scan until the user has completed the setup wizard.
        try:
            _chk = Session()
            try:
                _sc = _chk.execute(text("SELECT value FROM settings WHERE key='setup_complete'")).fetchone()
                _setup_done = _sc and _sc[0] == "true"
            finally:
                _chk.close()
        except Exception:
            _setup_done = False

        if not _setup_done:
            print("[*] Waiting for setup wizard to complete before scanning…", flush=True)
            time.sleep(10)
            continue

        if not _background_started:
            if ENABLE_PASSIVE_SNIFFER:
                threading.Thread(target=start_arp_sniffer, daemon=True, name="arp-sniffer").start()
            if ENABLE_MDNS:
                threading.Thread(target=_mdns_loop, daemon=True, name="mdns-loop").start()
                threading.Thread(target=_mdns_passive_listener, daemon=True, name="mdns-passive").start()
                threading.Thread(target=_ssdp_passive_listener, daemon=True, name="ssdp-passive").start()
            _background_started = True

        with _sniffer_seen_lock:
            _sniffer_seen_this_interval.clear()

        session = Session()
        try:
            if ENABLE_ARP_SWEEP:
                found        = arp_scan(INTERFACE, IP_RANGE)
                active_macs: set[str] = set()
                for entry in found:
                    active_macs.add(entry["mac"])
                    upsert_seen_device(entry["mac"], entry["ip"], "sweep")
                update_presence_from_sweep(session, active_macs)
                session.commit()
                print(f"[*] Sweep done -- {len(active_macs)} online", flush=True)
            else:
                print("[*] ARP sweep disabled — skipping active sweep", flush=True)

            # Self-healing: merge same-hostname interfaces (real NIC + macvlan shim,
            # wired + wireless, etc.) discovered at any time into one device entity.
            retroactive_auto_group()

            # Retry any online devices that never got a completed deep scan
            if ENABLE_UNSCANNED_RETRY:
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
            if ENABLE_NIGHTLY_SCAN:
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
