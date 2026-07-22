import json
import queue
import threading
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Integer, JSON, String, UniqueConstraint,
    create_engine,
)
from sqlalchemy.dialects.postgresql import JSONB, insert as pg_insert  # noqa: F401 (re-exported)
from sqlalchemy.orm import declarative_base, sessionmaker, synonym
from sqlalchemy.orm.attributes import flag_modified

from probe_config import DATABASE_URL

Base = declarative_base()


# ---------------------------------------------------------------------------
# ORM models
# ---------------------------------------------------------------------------
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
    status_changed_at = Column(DateTime(timezone=True), nullable=True)
    statuschangedat   = synonym("status_changed_at")
    tags         = Column(JSON,    nullable=True)
    location     = Column(String,  nullable=True)
    notes        = Column(String,  nullable=True)
    is_blocked   = Column(Boolean, default=False, nullable=False)
    is_ignored   = Column(Boolean, default=False, nullable=False)
    vuln_last_scanned = Column(DateTime(timezone=True), nullable=True)
    vuln_severity     = Column(String,  nullable=True)
    scan_results = Column(JSON,    nullable=True)
    deep_scanned = Column(Boolean, default=False)
    miss_count   = Column(Integer, default=0)
    is_important = Column(Boolean, default=False, nullable=False)
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
    presence_last_seen_at   = Column(DateTime(timezone=True), nullable=True)


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

# ---------------------------------------------------------------------------
# Shared in-memory state (cross-module mutable singletons)
# ---------------------------------------------------------------------------
_sniffer_queue: queue.Queue = queue.Queue()
_dhcp_queue:    queue.Queue = queue.Queue(maxsize=500)

_upsert_locks:      dict[str, threading.Lock] = {}
_upsert_locks_lock = threading.Lock()

_pending_dhcp_lock   = threading.Lock()
_pending_dhcp_by_mac: dict[str, tuple] = {}

_sniffer_seen_this_interval: set[str] = set()
_sniffer_seen_lock = threading.Lock()

_confirmed_offline_macs: set[str] = set()
_confirmed_offline_lock = threading.Lock()

_offline_at:   dict[str, datetime] = {}
_offline_lock = threading.Lock()

_scan_lock = threading.Lock()
_scanning:  set[str] = set()

_host_ips_cache: tuple = (0.0, set())
_host_ips_lock  = threading.Lock()


def _get_mac_lock(mac: str) -> threading.Lock:
    with _upsert_locks_lock:
        if mac not in _upsert_locks:
            _upsert_locks[mac] = threading.Lock()
        return _upsert_locks[mac]


def _store_pending_dhcp(
    mac: str,
    hostname: str | None,
    vendor_class: str | None,
    opt55: list[int] | None,
) -> None:
    with _pending_dhcp_lock:
        _pending_dhcp_by_mac[mac] = (hostname, vendor_class, opt55)


def _pop_pending_dhcp(mac: str) -> tuple | None:
    with _pending_dhcp_lock:
        return _pending_dhcp_by_mac.pop(mac, None)


def _remember_name_source(device: Device, source_key: str, value: str | None) -> bool:
    """Persist a discovered hostname candidate in scan_results without clobbering other keys."""
    value = (value or "").strip()
    if not value:
        return False
    sr = dict(device.scan_results or {})
    if sr.get(source_key) == value:
        return False
    sr[source_key] = value
    device.scan_results = sr
    flag_modified(device, "scan_results")
    return True
