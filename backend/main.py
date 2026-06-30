from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Query, Security, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, Response, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import create_engine, text, or_
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from typing import Optional, List
import asyncio
from collections import defaultdict
import os
import json
import csv
import io
import re
import hashlib
import re as _re
import shutil
import socket
import subprocess
import threading
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, quote as _urlencode

import yaml as _yaml
import httpx
import bcrypt as _bcrypt
from jose import JWTError, jwt

from models import Base, Device, DeviceEvent, FingerprintEntry, Setting, TrafficStat, VulnReport
from _version import __version__ as VERSION
from plugin_engine import (
    PluginRegistry, PluginRunner, PluginEventBus, PluginScheduler,
    validate_manifest, PluginValidationError,
    encrypt_field, decrypt_field, get_decrypted_config,
    verify_webhook_signature,
)
from email_analysis import run_email_analysis
import container_updates as _cu

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://admin:password123@db:5432/inspectre")
# PROBE_API_URL is the name used in docker-compose; PROBE_URL is the legacy fallback.
PROBE_URL    = (
    os.environ.get("PROBE_API_URL")
    or os.environ.get("PROBE_URL")
    or "http://host.docker.internal:8666"
)

# Shared secret used to authenticate backend -> probe API calls. When set (via the
# PROBE_API_SECRET env var, which is shared with the probe container), the backend
# attaches it as an X-Probe-Secret header on every probe request. When unset, no
# header is sent and the probe accepts requests unauthenticated (backward compatible).
PROBE_API_SECRET = os.environ.get("PROBE_API_SECRET", "").strip()

def _probe_headers(extra: Optional[dict] = None) -> dict:
    """Return headers for a backend->probe request, including the shared secret."""
    headers = dict(extra) if extra else {}
    if PROBE_API_SECRET:
        headers["X-Probe-Secret"] = PROBE_API_SECRET
    return headers

def _probe_client(**kwargs):
    """httpx.AsyncClient pre-configured with the probe shared-secret header.

    Use this for ALL backend->probe calls so the X-Probe-Secret header is sent
    automatically. Never use it for calls to external/third-party services.
    """
    if PROBE_API_SECRET:
        headers = dict(kwargs.pop("headers", {}) or {})
        headers.setdefault("X-Probe-Secret", PROBE_API_SECRET)
        kwargs["headers"] = headers
    return httpx.AsyncClient(**kwargs)

# ---------------------------------------------------------------------------
# Auth configuration
# ---------------------------------------------------------------------------
_DEFAULT_SECRET_KEY = "CHANGE_ME_IN_PRODUCTION_use_a_long_random_string"
SECRET_KEY   = os.environ.get("SECRET_KEY", _DEFAULT_SECRET_KEY)
if SECRET_KEY == _DEFAULT_SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY is set to the insecure default placeholder. Refusing to start. "
        "Set the SECRET_KEY environment variable to a long, random secret "
        "(e.g. `openssl rand -hex 32`)."
    )
ALGORITHM    = "HS256"
TOKEN_EXPIRE_DEFAULT  = 60 * 24       # minutes — 24 hours
TOKEN_EXPIRE_REMEMBER = 60 * 24 * 30  # minutes — 30 days
bearer_scheme = HTTPBearer(auto_error=False)

engine       = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

# psycopg2 does not decode JSONB columns automatically unless explicitly registered.
from sqlalchemy import event as _sa_event
import psycopg2.extras as _pg_extras
@_sa_event.listens_for(engine, "connect")
def _register_jsonb(dbapi_conn, _rec):
    _pg_extras.register_default_jsonb(dbapi_conn, globally=False, loads=json.loads)

# ---------------------------------------------------------------------------
# Home Assistant MQTT Auto-Discovery manager
# ---------------------------------------------------------------------------
class HAMQTTManager:
    """Persistent MQTT client for Home Assistant entity publishing."""

    def __init__(self):
        self._client    = None
        self._connected = False
        self._dp        = "homeassistant"
        self._sp        = "inspectre"
        self._lock      = threading.Lock()

    @property
    def connected(self) -> bool:
        return self._connected

    def connect(self, host: str, port: int = 1883, user: str = "",
                password: str = "", discovery_prefix: str = "homeassistant",
                state_prefix: str = "inspectre"):
        self.disconnect()
        import paho.mqtt.client as _mqtt
        self._dp = (discovery_prefix or "homeassistant").strip("/")
        self._sp = (state_prefix     or "inspectre").strip("/")
        lwt     = f"{self._sp}/system/status"
        client  = _mqtt.Client(client_id="inspectre_ha", clean_session=True)
        client.will_set(lwt, "offline", retain=True, qos=1)
        if user:
            client.username_pw_set(user, password or "")

        def _on_connect(c, _u, _f, rc):
            if rc == 0:
                self._connected = True
                c.publish(lwt, "online", retain=True, qos=1)
                print(f"[ha-mqtt] Connected to {host}:{port}", flush=True)
            else:
                self._connected = False
                print(f"[ha-mqtt] Connect failed rc={rc}", flush=True)

        def _on_disconnect(c, _u, rc):
            self._connected = False
            if rc != 0:
                print(f"[ha-mqtt] Disconnected rc={rc}", flush=True)

        client.on_connect    = _on_connect
        client.on_disconnect = _on_disconnect
        client.reconnect_delay_set(min_delay=5, max_delay=60)
        client.connect(host, int(port), keepalive=60)
        client.loop_start()
        self._client = client

    def disconnect(self):
        with self._lock:
            if self._client:
                try:
                    self._client.publish(f"{self._sp}/system/status", "offline", retain=True)
                    self._client.loop_stop()
                    self._client.disconnect()
                except Exception:
                    pass
                self._client    = None
                self._connected = False

    def publish(self, topic: str, payload, retain: bool = False, qos: int = 0):
        if not self._client or not self._connected:
            return
        self._client.publish(topic, json.dumps(payload) if isinstance(payload, dict) else str(payload),
                             retain=retain, qos=qos)

    @staticmethod
    def _mid(mac: str) -> str:
        return mac.replace(":", "_").lower()

    def pub_system_discovery(self):
        dp, sp = self._dp, self._sp
        dev = {"identifiers": ["inspectre_system_service"], "name": "InSpectre",
               "manufacturer": "InSpectre", "model": "Network Scanner"}
        for comp, uid, extra in [
            ("sensor", "total_devices",        {"name": "Total Devices Online",    "icon": "mdi:devices",
                                                 "state_topic": f"{sp}/system/total_devices"}),
            ("sensor", "total_vulnerabilities",{"name": "Total Vulnerabilities",   "icon": "mdi:shield-alert",
                                                 "state_topic": f"{sp}/system/total_vulnerabilities"}),
            ("sensor", "scan_state",           {"name": "Scan Status",             "icon": "mdi:radar",
                                                 "state_topic": f"{sp}/system/scan_state"}),
            ("sensor", "last_scan",            {"name": "Last Scan",               "icon": "mdi:clock-check",
                                                 "device_class": "timestamp",
                                                 "state_topic": f"{sp}/system/last_scan"}),
        ]:
            self.publish(f"{dp}/{comp}/inspectre_system_{uid}/config",
                         {"unique_id": f"inspectre_system_{uid}", "device": dev, **extra}, retain=True)

    def pub_device_discovery(self, mac: str, name: str | None, ip: str | None):
        dp, sp, mid = self._dp, self._sp, self._mid(mac)
        dev = {"identifiers": [f"inspectre_{mid}"], "name": name or ip or mac,
               "manufacturer": "InSpectre", "connections": [["mac", mac]]}
        for comp, uid, extra in [
            ("binary_sensor", f"{mid}_presence", {"name": "Presence", "device_class": "connectivity",
                                                   "payload_on": "ON", "payload_off": "OFF",
                                                   "state_topic": f"{sp}/clients/{mid}/presence"}),
            ("binary_sensor", f"{mid}_new",      {"name": "New Device", "device_class": "problem",
                                                   "payload_on": "ON", "payload_off": "OFF",
                                                   "state_topic": f"{sp}/clients/{mid}/new"}),
            ("sensor", f"{mid}_ip",    {"name": "IP Address",   "icon": "mdi:ip-network",
                                         "state_topic": f"{sp}/clients/{mid}/ip"}),
            ("sensor", f"{mid}_ports", {"name": "Open Ports",   "icon": "mdi:lan",
                                         "state_topic": f"{sp}/clients/{mid}/open_ports"}),
            ("sensor", f"{mid}_vulns", {"name": "Vulnerabilities", "icon": "mdi:shield-alert",
                                         "state_topic": f"{sp}/clients/{mid}/vulnerabilities"}),
        ]:
            self.publish(f"{dp}/{comp}/inspectre_{uid}/config",
                         {"unique_id": f"inspectre_{uid}", "device": dev, **extra}, retain=True)

    def pub_device_state(self, mac: str, is_online: bool, ip: str | None = None,
                          open_ports: int | None = None, vulns: int | None = None,
                          is_new: bool | None = None):
        mid, sp = self._mid(mac), self._sp
        self.publish(f"{sp}/clients/{mid}/presence", "ON" if is_online else "OFF", retain=True)
        if ip         is not None: self.publish(f"{sp}/clients/{mid}/ip",              ip,           retain=True)
        if open_ports is not None: self.publish(f"{sp}/clients/{mid}/open_ports",  str(open_ports), retain=True)
        if vulns      is not None: self.publish(f"{sp}/clients/{mid}/vulnerabilities", str(vulns),  retain=True)
        if is_new     is not None: self.publish(f"{sp}/clients/{mid}/new",  "ON" if is_new else "OFF", retain=True)

    def pub_system_state(self, total_devices: int | None = None, total_vulns: int | None = None,
                          scan_state: str | None = None, last_scan: str | None = None):
        sp = self._sp
        if total_devices is not None: self.publish(f"{sp}/system/total_devices",         str(total_devices), retain=True)
        if total_vulns   is not None: self.publish(f"{sp}/system/total_vulnerabilities",  str(total_vulns),  retain=True)
        if scan_state    is not None: self.publish(f"{sp}/system/scan_state",             scan_state,        retain=True)
        if last_scan     is not None: self.publish(f"{sp}/system/last_scan",              last_scan,         retain=True)


_ha_mqtt = HAMQTTManager()

# ---------------------------------------------------------------------------
# Plugin engine singletons
# ---------------------------------------------------------------------------
_plugin_registry  = PluginRegistry()
_plugin_runner    = PluginRunner(_plugin_registry, _ha_mqtt)
_plugin_event_bus = PluginEventBus(_plugin_registry, _plugin_runner)
_plugin_scheduler = PluginScheduler(_plugin_registry, _plugin_runner, SessionLocal)

# In-memory dict: person_id -> asyncio.Task for timed auto-unblock
_person_timed_blocks: dict = {}


def _ha_startup_connect(db: "Session"):
    """Connect HA MQTT on startup and publish initial discovery + state for all devices.

    Reads config from the plugin store when available (new path), falls back to the
    legacy ha_mqtt_* settings keys (upgrade path for existing installs).
    """
    try:
        # ── New path: plugin config store ────────────────────────────────────
        plugin = _plugin_registry.get("home-assistant")
        if plugin and plugin.get("enabled") and plugin.get("config", {}).get("host"):
            cfg = get_decrypted_config(plugin["manifest"], plugin["config"])
            host = cfg.get("host", "").strip()
            if not host:
                return
            _ha_mqtt.connect(
                host             = host,
                port             = int(cfg.get("port") or 1883),
                user             = cfg.get("user", ""),
                password         = cfg.get("password", ""),
                discovery_prefix = cfg.get("discovery_prefix", "homeassistant"),
                state_prefix     = cfg.get("state_prefix",     "inspectre"),
            )
        else:
            # ── Legacy path: settings table ──────────────────────────────────
            s = {r.key: r.value for r in db.query(Setting).filter(
                Setting.key.in_(["ha_mqtt_enabled", "ha_mqtt_host", "ha_mqtt_port",
                                  "ha_mqtt_user", "ha_mqtt_password",
                                  "ha_mqtt_discovery_prefix", "ha_mqtt_state_prefix"])
            ).all()}
            if s.get("ha_mqtt_enabled") != "true" or not s.get("ha_mqtt_host", "").strip():
                return
            _ha_mqtt.connect(
                host             = s["ha_mqtt_host"].strip(),
                port             = int(s.get("ha_mqtt_port", "1883") or 1883),
                user             = s.get("ha_mqtt_user", ""),
                password         = s.get("ha_mqtt_password", ""),
                discovery_prefix = s.get("ha_mqtt_discovery_prefix", "homeassistant"),
                state_prefix     = s.get("ha_mqtt_state_prefix",     "inspectre"),
            )
        import time; time.sleep(1)  # brief wait for connect callback
        if not _ha_mqtt.connected:
            return
        _ha_mqtt.pub_system_discovery()
        NEW_SECS = 7 * 24 * 3600
        devices = db.execute(text("""
            SELECT mac_address, COALESCE(custom_name, hostname) AS name, ip_address,
                   is_online, scan_results, vuln_severity, is_acknowledged,
                   EXTRACT(EPOCH FROM (NOW() - first_seen)) AS age_secs
            FROM devices WHERE is_ignored = false
        """)).fetchall()
        for d in devices:
            mac, name, ip, online, scan_res, vsev, acked, age_secs = d
            ports   = len((scan_res or {}).get("open_ports", [])) if scan_res else 0
            sev_map = {"low": 1, "info": 1, "medium": 2, "high": 3, "critical": 3}
            vulns   = sev_map.get(vsev or "", 0)
            is_new  = not bool(acked) and (age_secs is not None and float(age_secs) < NEW_SECS)
            _ha_mqtt.pub_device_discovery(mac, name, ip)
            _ha_mqtt.pub_device_state(mac, bool(online), ip, ports, vulns, is_new)
        total_online = sum(1 for d in devices if d.is_online)
        total_vulns  = sum(1 for d in devices if (d.vuln_severity or "") not in ("", "none", "clean"))
        last_scan_r  = db.execute(text(
            "SELECT created_at FROM device_events WHERE type='scan_complete' ORDER BY id DESC LIMIT 1"
        )).fetchone()
        last_scan = last_scan_r[0].isoformat() if last_scan_r else None
        _ha_mqtt.pub_system_state(total_online, total_vulns, "idle", last_scan)
        print(f"[ha-mqtt] Published discovery for {len(devices)} device(s)", flush=True)
    except Exception as exc:
        print(f"[ha-mqtt] Startup error: {exc}", flush=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ---------------------------------------------------------------------------
# DB migration
# ---------------------------------------------------------------------------
def _migrate(db: Session):
    migrations = [
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS is_important BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS notes TEXT",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS tags VARCHAR",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS location VARCHAR",
        """
        CREATE TABLE IF NOT EXISTS device_events (
            id SERIAL PRIMARY KEY,
            mac_address VARCHAR NOT NULL REFERENCES devices(mac_address) ON DELETE CASCADE,
            type VARCHAR NOT NULL,
            detail JSONB,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_device_events_mac     ON device_events(mac_address)",
        "CREATE INDEX IF NOT EXISTS ix_device_events_type    ON device_events(type)",
        "CREATE INDEX IF NOT EXISTS ix_device_events_created ON device_events(created_at)",
        # Phase 3 — vuln reports
        """
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
        """,
        "CREATE INDEX IF NOT EXISTS ix_vuln_reports_mac       ON vuln_reports(mac_address)",
        "CREATE INDEX IF NOT EXISTS ix_vuln_reports_scanned   ON vuln_reports(scanned_at)",
        "CREATE INDEX IF NOT EXISTS ix_vuln_reports_severity  ON vuln_reports(severity)",
        # vuln_last_scanned / vuln_severity columns on devices
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS vuln_last_scanned TIMESTAMPTZ",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS vuln_severity VARCHAR",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS is_blocked BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE devices ALTER COLUMN is_blocked SET DEFAULT FALSE",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS zone VARCHAR",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS is_ignored BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS suppress_presence_events BOOLEAN NOT NULL DEFAULT FALSE",
        # Nuclei migration: add scan_args column (replaces nmap_args semantically)
        "ALTER TABLE vuln_reports ADD COLUMN IF NOT EXISTS scan_args VARCHAR",
        # Ensure nmap_args always includes -p- (full port scan); only updates if
        # the value is still an unmodified old default (no -p flag at all).
        "UPDATE settings SET value = value || ' -p-' WHERE key = 'nmap_args' AND value NOT LIKE '%-p%'",
        # saved_views table for server-side persisted filter views
        """
        CREATE TABLE IF NOT EXISTS saved_views (
            id          SERIAL PRIMARY KEY,
            name        VARCHAR NOT NULL UNIQUE,
            description VARCHAR,
            filters     JSONB NOT NULL DEFAULT '{}',
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        # alert_suppressions table for per-device per-type alert muting
        """
        CREATE TABLE IF NOT EXISTS alert_suppressions (
            id          SERIAL PRIMARY KEY,
            mac_address VARCHAR REFERENCES devices(mac_address) ON DELETE CASCADE,
            event_type  VARCHAR,
            reason      VARCHAR,
            expires_at  TIMESTAMPTZ,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_alert_suppressions_mac  ON alert_suppressions(mac_address)",
        "CREATE INDEX IF NOT EXISTS ix_alert_suppressions_type ON alert_suppressions(event_type)",
        # Block schedules — time-based internet blocking rules per device or network-wide
        """
        CREATE TABLE IF NOT EXISTS block_schedules (
            id           SERIAL PRIMARY KEY,
            mac_address  VARCHAR(17),
            label        VARCHAR(100),
            days_of_week VARCHAR(50) NOT NULL DEFAULT 'mon,tue,wed,thu,fri,sat,sun',
            start_time   VARCHAR(5)  NOT NULL,
            end_time     VARCHAR(5)  NOT NULL,
            enabled      BOOLEAN     NOT NULL DEFAULT TRUE,
            created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_block_schedules_mac ON block_schedules(mac_address)",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS is_schedule_blocked BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE block_schedules ADD COLUMN IF NOT EXISTS mac_addresses TEXT[] DEFAULT '{}'",
        "ALTER TABLE block_schedules ADD COLUMN IF NOT EXISTS tags TEXT DEFAULT ''",
        # Phase 6 — traffic monitoring stat buckets
        """
        CREATE TABLE IF NOT EXISTS traffic_stats (
            id            SERIAL PRIMARY KEY,
            mac_address   VARCHAR NOT NULL,
            ip_address    VARCHAR,
            bucket_ts     TIMESTAMPTZ NOT NULL,
            bytes_in      BIGINT NOT NULL DEFAULT 0,
            bytes_out     BIGINT NOT NULL DEFAULT 0,
            packets_in    INTEGER NOT NULL DEFAULT 0,
            packets_out   INTEGER NOT NULL DEFAULT 0,
            lan_bytes     BIGINT NOT NULL DEFAULT 0,
            wan_bytes     BIGINT NOT NULL DEFAULT 0,
            dns_queries   JSONB,
            tls_sni       JSONB,
            http_hosts    JSONB,
            top_ips       JSONB,
            top_ports     JSONB,
            top_countries JSONB,
            protocols     JSONB,
            unusual_ports JSONB,
            created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_traffic_stats_mac    ON traffic_stats(mac_address)",
        "CREATE INDEX IF NOT EXISTS ix_traffic_stats_bucket ON traffic_stats(bucket_ts)",
        # Phase 7 — scan performance & port baseline
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS hostname_last_attempted TIMESTAMPTZ",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS deep_scan_last_run TIMESTAMPTZ",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS baseline_ports JSONB",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS baseline_scan_count INTEGER NOT NULL DEFAULT 0",
        # Phase 8 — speed test history + auto-block settings
        """
        CREATE TABLE IF NOT EXISTS speedtest_results (
            id            SERIAL PRIMARY KEY,
            tested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            server        VARCHAR,
            ping_ms       REAL,
            download_mbps REAL,
            upload_mbps   REAL,
            raw_output    TEXT
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_speedtest_results_tested ON speedtest_results(tested_at)",
        # Users table for authentication
        """
        CREATE TABLE IF NOT EXISTS users (
            id           SERIAL PRIMARY KEY,
            username     VARCHAR(64) NOT NULL UNIQUE,
            password_hash VARCHAR(256) NOT NULL,
            is_admin     BOOLEAN NOT NULL DEFAULT TRUE,
            created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_login   TIMESTAMPTZ
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_users_username ON users(username)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS status_changed_at TIMESTAMPTZ",
        # Migrate old aggressive nmap defaults to safer values (including the interim --max-rate 300 default)
        "UPDATE settings SET value = '-sS -T3 --max-rate 100' WHERE key = 'nmap_args' AND value IN ('-sT -O --osscan-limit -T4', '-sT -O --osscan-limit -T4 -p-', '-O --osscan-limit -sV --version-intensity 5 -T4 -p-', '-sS -T3 --max-rate 300')",
        # Fix: --max-rate 100 with 65535 ports takes ~655s, exceeding the 900s subprocess timeout — raise to 200 (328s)
        "UPDATE settings SET value = '-sS -T4' WHERE key = 'nmap_args' AND value IN ('-sS -T3 --max-rate 100', '-sS -T4 --max-rate 200', '-sS -T4 --max-rate 200 --host-timeout 360s')",
        # scan_type: which nmap mode to use for this device (auto-detected at discovery)
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS scan_type VARCHAR NOT NULL DEFAULT 'syn'",
        # Container event timeline — tracks running/stopped events by container name
        """CREATE TABLE IF NOT EXISTS container_events (
            id     SERIAL PRIMARY KEY,
            name   VARCHAR NOT NULL,
            status VARCHAR NOT NULL,
            ts     TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        "CREATE INDEX IF NOT EXISTS ix_container_events_name ON container_events(name)",
        "CREATE INDEX IF NOT EXISTS ix_container_events_ts   ON container_events(ts)",
        # Multi-host container monitoring — Docker and Proxmox
        """CREATE TABLE IF NOT EXISTS container_hosts (
            id         SERIAL PRIMARY KEY,
            name       TEXT NOT NULL,
            type       TEXT NOT NULL DEFAULT 'docker_local',
            url        TEXT,
            auth_user  TEXT,
            auth_token TEXT,
            tls_verify BOOLEAN NOT NULL DEFAULT false,
            enabled    BOOLEAN NOT NULL DEFAULT true,
            node       TEXT NOT NULL DEFAULT 'pve',
            local_ip   TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        "ALTER TABLE container_hosts ADD COLUMN IF NOT EXISTS local_ip TEXT",
        # Persistent Trivy scan results (survives backend restarts)
        """CREATE TABLE IF NOT EXISTS container_vuln_results (
            name       TEXT NOT NULL PRIMARY KEY,
            image      TEXT NOT NULL,
            vulns      JSONB NOT NULL DEFAULT '[]',
            scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        # IP history: differentiate DHCP rotation from multi-homed
        "ALTER TABLE ip_history ADD COLUMN IF NOT EXISTS seen_while_online BOOLEAN",
        # User-pinned primary IP (probe's source of truth for locked devices)
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS primary_ip        VARCHAR",
        # Prevent probe from overriding user-pinned primary IPs
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS primary_ip_locked BOOLEAN NOT NULL DEFAULT FALSE",
        # DHCP fingerprinting — passively captured by probe sniffer
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS dhcp_hostname     VARCHAR",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS dhcp_vendor_class VARCHAR",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS dhcp_fingerprint  VARCHAR",
        # Fingerbank API identification result
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS fingerbank_result JSONB",
        # Phase 9 — device grouping (same physical device, different interface)
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS group_id      UUID",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS group_primary BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS group_manual  BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS auto_group_optout BOOLEAN NOT NULL DEFAULT FALSE",
        "CREATE INDEX IF NOT EXISTS ix_devices_group_id ON devices(group_id)",
        # Phase 10 — device acknowledgement
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS is_acknowledged BOOLEAN NOT NULL DEFAULT FALSE",
        # Notification channels and profiles
        """CREATE TABLE IF NOT EXISTS notification_channels (
            id         SERIAL PRIMARY KEY,
            name       TEXT NOT NULL,
            service    TEXT NOT NULL,
            config     JSONB NOT NULL DEFAULT '{}',
            enabled    BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        """CREATE TABLE IF NOT EXISTS notification_profiles (
            id              SERIAL PRIMARY KEY,
            name            TEXT NOT NULL,
            events          JSONB NOT NULL DEFAULT '{}',
            browser_enabled BOOLEAN NOT NULL DEFAULT FALSE,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        """CREATE TABLE IF NOT EXISTS notification_profile_channels (
            profile_id INTEGER NOT NULL REFERENCES notification_profiles(id) ON DELETE CASCADE,
            channel_id INTEGER NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
            PRIMARY KEY (profile_id, channel_id)
        )""",
        "CREATE INDEX IF NOT EXISTS ix_npc_profile ON notification_profile_channels(profile_id)",
        "CREATE INDEX IF NOT EXISTS ix_npc_channel ON notification_profile_channels(channel_id)",
        # Plugin registry table
        """CREATE TABLE IF NOT EXISTS plugins (
            plugin_id     TEXT        NOT NULL PRIMARY KEY,
            display_name  TEXT        NOT NULL,
            version       TEXT        NOT NULL DEFAULT '1.0.0',
            enabled       BOOLEAN     NOT NULL DEFAULT false,
            manifest      JSONB       NOT NULL DEFAULT '{}',
            config        JSONB       NOT NULL DEFAULT '{}',
            install_source TEXT       NOT NULL DEFAULT 'builtin',
            status        TEXT        NOT NULL DEFAULT 'disabled',
            last_error    TEXT,
            installed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_polled   TIMESTAMPTZ
        )""",
        "CREATE INDEX IF NOT EXISTS ix_plugins_source ON plugins(install_source)",
        # Per-device enrichment data stored by plugins
        """CREATE TABLE IF NOT EXISTS plugin_device_data (
            plugin_id   TEXT        NOT NULL,
            mac_address TEXT        NOT NULL,
            data        JSONB       NOT NULL DEFAULT '{}',
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (plugin_id, mac_address)
        )""",
        "CREATE INDEX IF NOT EXISTS ix_plugin_device_data_mac ON plugin_device_data(mac_address)",
        # Person presence
        """CREATE TABLE IF NOT EXISTS persons (
            id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name        VARCHAR(100) NOT NULL,
            photo       TEXT,
            primary_mac VARCHAR(17),
            notes       TEXT,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        """CREATE TABLE IF NOT EXISTS person_devices (
            person_id   UUID NOT NULL REFERENCES persons(id) ON DELETE CASCADE,
            mac_address VARCHAR(17) NOT NULL REFERENCES devices(mac_address) ON DELETE CASCADE,
            PRIMARY KEY (person_id, mac_address)
        )""",
        "CREATE INDEX IF NOT EXISTS ix_person_devices_mac ON person_devices(mac_address)",
        "ALTER TABLE block_schedules ADD COLUMN IF NOT EXISTS person_id UUID REFERENCES persons(id) ON DELETE SET NULL",
        "ALTER TABLE block_schedules ADD COLUMN IF NOT EXISTS person_ids TEXT[] DEFAULT '{}'",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS person_id UUID REFERENCES persons(id) ON DELETE SET NULL",
        "CREATE INDEX IF NOT EXISTS ix_devices_person_id ON devices(person_id)",
    ]
    for sql in migrations:
        try:
            db.execute(text(sql))
        except Exception:
            db.rollback()
    db.commit()

    # Install the primary-IP lock trigger as a DB-level backstop against
    # the probe ever overwriting a user-pinned IP.
    # The trigger fires whenever OLD.primary_ip_locked=TRUE (regardless of NEW),
    # unconditionally restoring primary_ip and ip_address from the OLD row.
    # The backend's two-step re-pin still works:
    #   Step 1 — SET locked=FALSE: trigger fires but primary_ip isn't changing
    #            (NEW.primary_ip == OLD.primary_ip), so no visible effect.
    #   Step 2 — SET primary_ip=X, locked=TRUE: OLD.locked=FALSE, trigger
    #            doesn't fire, the new pin is written normally.
    try:
        db.execute(text("""
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
        db.execute(text("DROP TRIGGER IF EXISTS trg_enforce_primary_ip_lock ON devices"))
        db.execute(text("""
            CREATE TRIGGER trg_enforce_primary_ip_lock
                BEFORE UPDATE ON devices
                FOR EACH ROW
                EXECUTE FUNCTION enforce_primary_ip_lock()
        """))
        db.commit()
    except Exception as _te:
        print(f"[migrate] primary_ip_lock trigger (non-fatal): {_te}", flush=True)
        db.rollback()
    # Container update management tables (container_update_status, container_backups)
    _cu.migrate(db)


# ---------------------------------------------------------------------------
# Default settings
# ---------------------------------------------------------------------------
DEFAULT_SETTINGS = {
    "scan_interval":           ("60",    "How often to sweep the network, in seconds."),
    "offline_miss_threshold":  ("3",     "Number of missed sweeps before a device is marked offline."),
    "sniffer_workers":         ("4",     "Number of parallel scanner threads."),
    "ip_range":                ("192.168.0.0/24", "CIDR range to scan."),
    "arp_scan_retry":          ("1", "ARP sweep retry rounds (0 = single pass, 1 = two rounds). Higher values increase broadcast traffic but may catch more sleeping devices. The passive sniffer catches most devices that miss sweeps."),
    "primary_ip_mode":         ("locked", "How the probe updates a device's primary IP. locked: respects the per-device IP lock flag — locked devices never have their primary IP auto-changed. dynamic: always adopts the current IP as primary when a device returns from offline (mirrors InSpectre-main behaviour)."),
    "notifications_enabled":              ("true",  "Show popup toasts when new devices appear or go offline."),
    "browser_notifications_enabled":      ("false", "Show OS-level browser notifications for device events."),
    "pushbullet_api_key":                 ("",      "Pushbullet API access token for push notifications."),
    "vuln_scan_templates":      (
        "cve,exposure,misconfig,default-login,network",
        "Comma-separated Nuclei template tags used for vulnerability scanning."
    ),
    "vuln_scan_schedule":      ("disabled", "Scheduled vulnerability scan interval. Options: disabled, 6h, 12h, 24h, weekly."),
    "vuln_scan_targets":       ("important", "Devices to include in scheduled scans. Options: all, important."),
    "vuln_scan_on_new_device": ("false", "Automatically run a vulnerability scan when a new device is first discovered."),
    "nuclei_template_update_interval": ("24h", "How often to update Nuclei templates. Options: disabled, 12h, 24h, 48h, weekly."),
    # Alert delivery
    "alert_on_port_change":    ("true",   "Send an alert when a device's open ports change."),
    "alert_on_new_device":     ("false",  "Send an alert when a new device is discovered."),
    "alert_on_offline":        ("false",  "Send an alert when a watched device goes offline."),
    "alert_on_vuln":           ("false",  "Send an alert when a vulnerability scan finds issues."),
    "alert_webhook_url":       ("",       "HTTP POST webhook URL for alerts (leave blank to disable)."),
    "ntfy_url":                ("https://ntfy.sh", "ntfy server base URL."),
    "ntfy_topic":              ("",       "ntfy topic name (leave blank to disable ntfy alerts)."),
    "gotify_url":              ("",       "Gotify server URL (leave blank to disable)."),
    "gotify_token":            ("",       "Gotify application token."),
    "network_paused":          ("false",  "Whether internet access is paused for the whole network via ARP blocking."),
    # Phase 7 — scan performance & port baseline
    "nightly_scan_start":            ("2",     "Hour (0-23) when the nightly deep-scan window opens."),
    "nightly_scan_end":              ("4",     "Hour (0-23) when the nightly deep-scan window closes."),
    "offline_rescan_hours":          ("24",     "Hours a device must be offline before triggering a rescan on return."),
    "baseline_scan_count_threshold": ("3",     "Consecutive matching scans required to confirm a port baseline."),
    "vuln_scan_on_port_change":      ("false", "Auto-trigger a vulnerability scan when a new port is detected above baseline."),
    # Phase 6 — traffic monitoring
    "traffic_enabled":         ("true",   "Enable per-device traffic monitoring feature."),
    "traffic_retention_days":  ("30",     "Number of days to retain traffic_stats rows before deletion."),
    "traffic_max_sessions":    ("10",     "Maximum number of concurrent traffic monitor sessions."),
    "traffic_geoip_path":      ("/opt/geoip/GeoLite2-Country.mmdb", "Path to MaxMind GeoLite2-Country mmdb file on the probe."),
    # Phase 8 — speed test
    "speedtest_schedule":      ("disabled", "Scheduled speed test interval. Options: disabled, 30m, 1h, 6h, 24h."),
    # Phase 8 — auto-block
    "auto_block_new_devices":    ("false", "Automatically block newly discovered devices until manually approved."),
    "auto_block_vuln_severity":  ("none",  "Minimum vuln severity to trigger auto-block. Options: none, medium, high, critical."),
    # Blocking method
    "block_method":    ("arp",  "Active blocking method: arp (probe ARP poisoning), dns (AdGuard Home / Pi-hole), infrastructure (TP-Link Omada / UniFi)."),
    "block_plugin_id": ("",    "Plugin ID used for blocking when block_method is not arp. Must be an enabled plugin with blocking capability and block_client/unblock_client actions defined."),
    # Phase 9 — device grouping
    "auto_group_by_hostname":    ("true",  "Automatically group devices with the same hostname as the same physical device on a different interface (e.g. laptop switching between WiFi and Ethernet). When disabled, a suggestion event is written instead."),
    "scan_grouped_members":      ("false", "Also port-scan and vulnerability-scan the IP of every interface in a device group. By default only the group's primary interface is scanned, since grouped interfaces belong to the same physical host. Enable to scan each interface IP separately."),
    # Network / probe identity
    "dns_server":                ("",      "LAN DNS server IP (auto-detected if blank). Set this to your router's IP for best hostname resolution."),
    "probe_interface":           ("",      "Network interface the probe uses for scanning (e.g. eth0, eno1). Auto-detected on startup if blank; changes apply immediately via Settings → Apply."),
    # Fingerbank device identification
    "fingerbank_api_key":        ("",      "Fingerbank API key for cloud-based DHCP device identification. Get a free key at fingerbank.org. Leave blank to disable."),
    # New device surfacing
    "float_new_to_top":          ("true",  "Surface unacknowledged new devices and containers to the top of the list."),
    # Setup wizard
    "setup_complete":            ("false", "Whether the initial setup wizard has been completed."),
    # Docker monitoring
    "docker_enabled":            ("false", "Enable Docker container monitoring."),
    "docker_host":               ("unix:///var/run/docker.sock", "Docker host — socket path (unix:///var/run/docker.sock) or TCP URL (tcp://host:2375)."),
    "docker_tls_verify":         ("false", "Enable TLS verification for Docker TCP connections."),
    "trivy_db_update_frequency": ("1d",   "How often to refresh the Trivy vulnerability database. Options: disabled, 1d, 2d, 7d, 30d."),
    "docker_scan_on_new":        ("false", "Automatically run a Trivy vuln scan when a new container is created."),
    "docker_scan_on_update":     ("false", "Automatically run a Trivy vuln scan when a container is recreated with an updated image."),
    # Container update management
    "container_auto_update":           ("disabled", "What to do when an update is detected. Options: disabled, notify, scan_then_update, auto."),
    "container_update_block_critical": ("true",     "Block container updates if the new image contains critical-severity CVEs."),
    "container_backup_enabled":        ("true",     "Automatically save a full config backup before any container update."),
    "container_update_health_timeout": ("30",       "Seconds to wait for a container health check after an update before triggering rollback."),
    "container_update_stagger_seconds":("30",       "Delay in seconds between sequential container updates when running an auto-update batch."),
    "container_update_pin_labels":     ("true",     "Honour the com.inspectre.update.pin=true Docker label to exclude containers from auto-updates."),
    "container_check_enabled": ("false", "Enable scheduled container image update checks."),
    "container_check_hour":    ("3",     "Hour of day (0-23, UTC) to run container update checks."),
    "container_check_days":    ("[]",    "JSON array of JS day-of-week ints (0=Sun…6=Sat) to run checks. Empty = every day."),
    # Notification — speed test alert thresholds
    "speedtest_expected_download":   ("0",   "Expected/contracted download speed in Mbps. Set to 0 to disable speed test alerts."),
    "speedtest_expected_upload":     ("0",   "Expected/contracted upload speed in Mbps. Set to 0 to disable upload speed alerts."),
    "speedtest_alert_threshold":     ("80",  "Speed must drop below this percentage of expected before a speedtest.degraded_download alert fires."),
    # Notification — device returned
    "device_returned_days":          ("7",   "Days a device must be absent before a device.returned notification fires when it rejoins."),
    # Notification — traffic
    "traffic_suspicious_countries":  ("",    "Comma-separated ISO-3166 country codes to flag (e.g. CN,RU,KP). Leave blank to disable."),
    # Here Be Dragons — advanced probe pipeline controls
    "enable_arp_sweep":              ("true",  "Run active ARP broadcast sweeps to discover devices on the configured subnet."),
    "enable_passive_sniffer":        ("true",  "Run the passive ARP sniffer that listens for ARP traffic. Disable to stop all passive packet capture. Takes effect immediately."),
    "sniffer_subnet_filter":         ("true",  "Restrict the passive sniffer to the configured IP range only. Disable if you want the sniffer to capture ARP traffic from all subnets on the interface."),
    "enable_hostname_resolution":    ("true",  "Attempt DNS hostname resolution for discovered devices. Disable to stop all reverse-DNS lookups."),
    "hostname_cooldown_hours":       ("24",    "Minimum hours between hostname resolution retries for each device. Lower values increase DNS query frequency."),
    "enable_port_scanning":          ("true",  "Run TCP port scans on discovered devices. Disable to stop all port scanning activity."),
    "port_scan_method":              ("tcp_connect", "Port scan method: tcp_connect (standard socket, no special privileges) or scapy_syn (raw SYN packets, requires CAP_NET_RAW — already granted in the default probe container)."),
    "port_scan_workers":             ("200",   "Number of concurrent TCP threads used per port scan (tcp_connect method only). Lower values reduce network load but increase scan time."),
    "gateway_scan_workers":          ("50",    "Number of concurrent TCP threads when port scanning the default gateway. Kept lower than regular scans to avoid overwhelming the gateway device."),
    "enable_service_fingerprinting": ("true",  "Run Nerva service fingerprinting after each port scan to identify services on open ports."),
    "enable_mdns":                   ("true",  "Run mDNS discovery to find device names and services advertised over the local mDNS/Bonjour multicast group."),
    "enable_nightly_scan":           ("true",  "Rescan all online devices during the configured nightly scan window."),
    "enable_unscanned_retry":        ("true",  "On each sweep cycle, retry port-scanning any device that has never been successfully scanned. Disable if new devices are causing too many concurrent scans."),
    # Home Assistant MQTT Auto-Discovery integration
    "ha_mqtt_enabled":          ("false",          "Enable Home Assistant MQTT Auto-Discovery integration."),
    "ha_mqtt_host":             ("",               "MQTT broker hostname or IP for HA integration."),
    "ha_mqtt_port":             ("1883",           "MQTT broker port for HA integration."),
    "ha_mqtt_user":             ("",               "MQTT username for HA integration (optional)."),
    "ha_mqtt_password":         ("",               "MQTT password for HA integration (optional)."),
    "ha_mqtt_discovery_prefix": ("homeassistant",  "HA MQTT discovery prefix (default: homeassistant)."),
    "ha_mqtt_state_prefix":     ("inspectre",      "InSpectre MQTT state topic prefix (default: inspectre)."),
    # Appliance auto-update (VM/Pi builds only — ignored on non-appliance installs)
    "timezone":              ("UTC",    "System timezone for log timestamps (appliance builds). IANA format e.g. Europe/London."),
    "auto_update_enabled":   ("false",  "Enable scheduled automatic container updates (appliance builds only)."),
    "auto_update_hour":      ("3",      "Hour of day (0-23) to run scheduled auto-updates."),
    "auto_update_days":      ("[]",     "JSON array of weekday integers to run auto-updates (0=Sun…6=Sat). Empty array = every day."),
}


def _seed_settings(db: Session):
    for key, (value, description) in DEFAULT_SETTINGS.items():
        if not db.get(Setting, key):
            db.add(Setting(key=key, value=value, description=description))
    db.commit()


def _migrate_legacy_docker_host(db: Session):
    """One-time migration: if docker_enabled=true and no hosts exist, create a default host entry."""
    try:
        existing = db.execute(text("SELECT COUNT(*) FROM container_hosts")).scalar()
        if existing and existing > 0:
            return
        s_enabled = db.get(Setting, "docker_enabled")
        if not s_enabled or s_enabled.value != "true":
            return
        s_host = db.get(Setting, "docker_host")
        s_tls  = db.get(Setting, "docker_tls_verify")
        url    = (s_host.value if s_host else None) or "unix:///var/run/docker.sock"
        htype  = "docker_remote" if url.startswith("tcp://") else "docker_local"
        tls    = (s_tls and s_tls.value == "true")
        db.execute(text("""
            INSERT INTO container_hosts (name, type, url, tls_verify, enabled)
            VALUES (:name, :type, :url, :tls, true)
        """), {"name": "Local Docker", "type": htype, "url": url, "tls": tls})
        db.commit()
        print("[hosts] Migrated legacy docker settings to container_hosts table.", flush=True)
    except Exception as e:
        print(f"[hosts] Legacy migration failed (non-fatal): {e}", flush=True)
        db.rollback()


# ---------------------------------------------------------------------------
# Shared helper — save a vuln scan RESULT payload to DB
# ---------------------------------------------------------------------------
def _save_vuln_result(mac: str, ip: str, data: dict, scripts: str):
    from models import VulnReport
    db2 = SessionLocal()
    try:
        dev = db2.get(Device, mac)
        if not dev:
            return
        report = VulnReport(
            mac_address = mac,
            ip_address  = ip,
            duration_s  = data.get("duration_s"),
            severity    = data.get("severity", "clean"),
            vuln_count  = data.get("vuln_count", 0),
            findings    = data.get("findings"),
            raw_output  = data.get("raw_output"),
            scan_args   = scripts or None,
        )
        db2.add(report)
        dev.vuln_last_scanned = datetime.now(timezone.utc)
        dev.vuln_severity     = data.get("severity", "clean")
        db2.commit()
        _add_event(db2, mac, "vuln_scan_complete", {
            "severity":   data.get("severity"),
            "vuln_count": data.get("vuln_count", 0),
        })
        db2.commit()
    except Exception as exc:
        db2.rollback()
        print(f"[vuln] Save error {mac}: {exc}", flush=True)
    finally:
        db2.close()


# ---------------------------------------------------------------------------
# Scheduled vuln scanner
# ---------------------------------------------------------------------------
_last_scheduled_vuln_scan: datetime | None = datetime.now(timezone.utc)
_last_vuln_scan_day: int | None = None  # weekday (0=Mon) last processed for weekly spreading


async def _run_single_vuln_scan(mac: str, ip: str, scripts: str):
    probe_url = f"{PROBE_URL}/stream/vuln-scan/{ip}"
    params    = {"templates": scripts} if scripts else {}
    try:
        async with _probe_client(timeout=None) as client:
            async with client.stream("GET", probe_url, params=params) as resp:
                if resp.status_code != 200:
                    print(f"[scheduler] Vuln scan {ip} HTTP {resp.status_code}", flush=True)
                    return
                async for raw_line in resp.aiter_lines():
                    if raw_line.startswith("data: RESULT:"):
                        payload_str = raw_line[len("data: RESULT:"):]
                        try:
                            data = json.loads(payload_str)
                            _save_vuln_result(mac, ip, data, scripts)
                            print(f"[scheduler] Vuln scan done: {ip} ({mac}) severity={data.get('severity')}", flush=True)
                        except Exception as exc:
                            print(f"[scheduler] Parse error {mac}: {exc}", flush=True)
                        return
    except httpx.ConnectError:
        print(f"[scheduler] Cannot reach probe for {ip}", flush=True)
    except Exception as exc:
        print(f"[scheduler] Scan error {ip}: {exc}", flush=True)


def _scan_grouped_members_enabled(db) -> bool:
    """True when grouped (non-primary) interface IPs should also be scanned."""
    s = db.get(Setting, "scan_grouped_members")
    return bool(s and (s.value or "").strip().lower() in ("true", "1", "yes"))


def _exclude_grouped_secondaries(q, db):
    """Filter out non-primary group members from a Device query unless the
    scan_grouped_members setting is enabled (grouped interfaces share a host)."""
    if _scan_grouped_members_enabled(db):
        return q
    return q.filter(or_(Device.group_id == None, Device.group_primary == True))


async def _run_scheduled_vuln_scans():
    db = SessionLocal()
    try:
        settings_s = db.get(Setting, "vuln_scan_templates")
        scripts    = (settings_s.value or "").strip() if settings_s else ""
        targets_s  = db.get(Setting, "vuln_scan_targets")
        targets    = targets_s.value if targets_s else "important"
        q = db.query(Device).filter(Device.is_online == True, Device.ip_address != None, Device.is_ignored == False)
        if targets == "important":
            q = q.filter(Device.is_important == True)
        q = _exclude_grouped_secondaries(q, db)
        devices = [(d.mac_address, d.ip_address) for d in q.all()]
    finally:
        db.close()

    print(f"[scheduler] Starting scheduled vuln scan: {len(devices)} device(s)", flush=True)
    for mac, ip in devices:
        await _run_single_vuln_scan(mac, ip, scripts)
        await asyncio.sleep(10)


async def _run_scheduled_vuln_scans_for_day(day_of_week: int):
    """Weekly mode: scan only the devices assigned to this day bucket (hash(mac) % 7 == day)."""
    db = SessionLocal()
    try:
        settings_s = db.get(Setting, "vuln_scan_templates")
        scripts    = (settings_s.value or "").strip() if settings_s else ""
        targets_s  = db.get(Setting, "vuln_scan_targets")
        targets    = targets_s.value if targets_s else "important"
        q = db.query(Device).filter(Device.is_online == True, Device.ip_address != None, Device.is_ignored == False)
        if targets == "important":
            q = q.filter(Device.is_important == True)
        q = _exclude_grouped_secondaries(q, db)
        all_devices = [(d.mac_address, d.ip_address) for d in q.all()]
    finally:
        db.close()

    devices = [
        (mac, ip) for mac, ip in all_devices
        if int(hashlib.md5(mac.encode()).hexdigest(), 16) % 7 == day_of_week
    ]
    print(f"[scheduler] Weekly scan day {day_of_week}: {len(devices)}/{len(all_devices)} device(s)", flush=True)
    for mac, ip in devices:
        await _run_single_vuln_scan(mac, ip, scripts)
        await asyncio.sleep(10)


async def _run_all_vuln_scans():
    """Manual 'scan all' — ignores the vuln_scan_targets setting and scans every eligible device."""
    db = SessionLocal()
    try:
        settings_s = db.get(Setting, "vuln_scan_templates")
        scripts    = (settings_s.value or "").strip() if settings_s else ""
        _q_all = db.query(Device).filter(Device.is_online == True,
                                         Device.ip_address != None,
                                         Device.is_ignored == False)
        _q_all = _exclude_grouped_secondaries(_q_all, db)
        devices    = [(d.mac_address, d.ip_address) for d in _q_all.all()]
    finally:
        db.close()

    print(f"[scan-all] Starting manual vuln scan: {len(devices)} device(s)", flush=True)
    for mac, ip in devices:
        await _run_single_vuln_scan(mac, ip, scripts)
        await asyncio.sleep(10)


async def _scheduled_vuln_scan_loop():
    global _last_scheduled_vuln_scan, _last_vuln_scan_day
    await asyncio.sleep(30)  # startup grace period
    while True:
        try:
            db = SessionLocal()
            try:
                sched_s  = db.get(Setting, "vuln_scan_schedule")
                schedule = sched_s.value if sched_s else "disabled"
            finally:
                db.close()

            if schedule == "weekly":
                today = datetime.now(timezone.utc).weekday()
                if _last_vuln_scan_day is None:
                    # Record startup day without scanning — spreading begins the next calendar day
                    _last_vuln_scan_day = today
                elif _last_vuln_scan_day != today:
                    await _run_scheduled_vuln_scans_for_day(today)
                    _last_vuln_scan_day = today
            elif schedule != "disabled":
                intervals = {"6h": 21600, "12h": 43200, "24h": 86400}
                interval  = intervals.get(schedule, 86400)
                now       = datetime.now(timezone.utc)
                if _last_scheduled_vuln_scan is None or (now - _last_scheduled_vuln_scan).total_seconds() >= interval:
                    await _run_scheduled_vuln_scans()
                    _last_scheduled_vuln_scan = now
        except Exception as exc:
            print(f"[scheduler] Loop error: {exc}", flush=True)
        await asyncio.sleep(900)  # check every 15 minutes


# ---------------------------------------------------------------------------
# Notification infrastructure
# ---------------------------------------------------------------------------

HIGH_RISK_PORTS = {21, 23, 137, 138, 139, 445, 512, 513, 514, 3389, 5900}

# (event_type, label, category, description) — served to the frontend for profile editors
NOTIFICATION_EVENT_DEFS = [
    ("device.new",                  "New Device",               "Devices",         "A new device appeared on the network"),
    ("device.online.watched",       "Watched Device Online",    "Devices",         "A watched device came back online"),
    ("device.offline.watched",      "Watched Device Offline",   "Devices",         "A watched device went offline"),
    ("device.online.all",           "Any Device Online",        "Devices",         "Any device came online (includes watched)"),
    ("device.offline.all",          "Any Device Offline",       "Devices",         "Any device went offline (includes watched)"),
    ("device.returned",             "Device Returned",          "Devices",         "A device reappeared after a long absence"),
    ("device.auto_blocked",         "Device Auto-Blocked",      "Devices",         "A device was automatically blocked"),
    ("vuln.critical",               "Critical Vulnerability",   "Vulnerabilities", "Critical-severity vulnerability found on a network device"),
    ("vuln.high",                   "High Vulnerability",       "Vulnerabilities", "High-severity vulnerability found on a network device"),
    ("container.vuln_critical",     "Container Critical Vuln",  "Vulnerabilities", "Critical vulnerability found in a container image"),
    ("container.vuln_high",         "Container High Vuln",      "Vulnerabilities", "High vulnerability found in a container image"),
    ("port.high_risk",              "High-Risk Port",           "Network",         "Telnet, FTP, SMB, RDP, VNC or similar high-risk port opened"),
    ("port.opened",                 "New Port Opened",          "Network",         "A new port opened above a device's confirmed baseline"),
    ("speedtest.degraded_download", "Download Speed Degraded",  "Speed Test",      "Download speed fell below the configured threshold"),
    ("block.network_pause",         "Network Paused",           "Blocking",        "Internet access was blocked for the whole network"),
    ("block.schedule_start",        "Block Schedule Started",   "Blocking",        "A block schedule became active"),
    ("block.schedule_end",          "Block Schedule Ended",     "Blocking",        "A block schedule deactivated"),
    ("container.crashed",           "Container Crashed",        "Containers",      "A container exited with a non-zero exit code"),
    ("container.update_available",  "Container Update Available","Containers",      "A newer image version is available for a container"),
    ("container.updated",           "Container Updated",         "Containers",      "A container was successfully updated to a new image version"),
    ("container.update_blocked",    "Container Update Blocked",  "Containers",      "A container update was blocked due to critical CVEs in the new image"),
    ("container.update_failed",     "Container Update Failed",   "Containers",      "A container update failed and the original was automatically restored"),
    ("traffic.unusual_port",        "Unusual Port Traffic",     "Traffic",         "A device communicated on an unusual port"),
    ("traffic.suspicious_country",  "Suspicious Country Traffic","Traffic",        "A device communicated with a flagged country"),
    ("person.home",                 "Person Arrived Home",      "Person Presence", "A tracked person's device came online (person is home)"),
    ("person.away",                 "Person Left Home",         "Person Presence", "A tracked person's device went offline (person is away)"),
    ("person.blocked",              "Person Blocked",           "Person Presence", "All of a person's devices were manually blocked"),
    ("person.unblocked",            "Person Unblocked",         "Person Presence", "A person's devices were unblocked"),
]

_last_alert_event_id: int = 0
_last_network_paused: str = ""
_pending_browser_notifications: list = []
_traffic_notif_cooldowns: dict = {}   # (mac, event_type) → datetime of last notification
_main_loop: asyncio.AbstractEventLoop | None = None


# ---------------------------------------------------------------------------
# Live updates (Server-Sent Events)
# ---------------------------------------------------------------------------
# A lightweight pub/sub fan-out so the frontend can react to changes the moment
# they happen instead of polling every few seconds.  Any code path (sync request
# handler running in a threadpool, async task, or the DB watcher loop) can call
# _sse_publish(); subscribers each hold an asyncio.Queue drained by the
# /events/stream endpoint.
_sse_clients: "set[asyncio.Queue]" = set()
_last_sse_event_id: int = 0


def _sse_publish(event: str, data: dict | None = None) -> None:
    """
    Broadcast an SSE message to every connected client.  Thread-safe: callable
    from sync endpoints (threadpool) as well as the event loop.  `event` is the
    SSE event name (e.g. 'devices', 'schedules', 'persons'); `data` is a small
    JSON-serialisable hint payload.
    """
    if not _sse_clients or _main_loop is None or _main_loop.is_closed():
        return
    payload = {"event": event, "data": data or {}}

    def _fan_out():
        for q in list(_sse_clients):
            try:
                q.put_nowait(payload)
            except Exception:
                pass

    try:
        _main_loop.call_soon_threadsafe(_fan_out)
    except RuntimeError:
        pass


async def _sse_event_watcher() -> None:
    """
    Single background loop that turns new `device_events` rows into SSE
    broadcasts.  Covers everything the probe writes (presence, blocks, scans,
    IP changes, etc.) without each client polling the API.  Backend-originated
    mutations (schedules, persons, groups) publish directly via _sse_publish().
    """
    global _last_sse_event_id
    await asyncio.sleep(5)  # startup grace
    db = SessionLocal()
    try:
        row = db.execute(text("SELECT COALESCE(MAX(id), 0) FROM device_events")).scalar()
        _last_sse_event_id = int(row or 0)
    except Exception:
        _last_sse_event_id = 0
    finally:
        db.close()

    while True:
        try:
            if _sse_clients:
                db = SessionLocal()
                try:
                    rows = db.execute(text("""
                        SELECT id, mac_address, type
                        FROM device_events
                        WHERE id > :last_id
                        ORDER BY id ASC
                        LIMIT 200
                    """), {"last_id": _last_sse_event_id}).fetchall()
                finally:
                    db.close()
                if rows:
                    types = set()
                    for eid, mac, etype in rows:
                        _last_sse_event_id = max(_last_sse_event_id, int(eid))
                        types.add(etype)
                    _sse_publish("devices", {"types": sorted(types)})
                    # Presence / block changes also affect the Person Presence page.
                    if types & {"online", "offline", "joined", "interface_joined",
                                "blocked", "unblocked", "ip_change"}:
                        _sse_publish("persons", {"types": sorted(types)})
        except Exception:
            pass
        await asyncio.sleep(2)


def _build_apprise_url(service: str, config: dict) -> str | None:
    """Construct an Apprise notification URL from a service name and config dict."""
    try:
        if service == "ntfy":
            server = (config.get("server") or "https://ntfy.sh").rstrip("/")
            topic  = config.get("topic", "").strip()
            if not topic:
                return None
            p      = urlparse(server)
            scheme = "ntfys" if p.scheme == "https" else "ntfy"
            host   = p.netloc or p.path
            user   = config.get("user", "").strip()
            pw     = config.get("password", "").strip()
            auth   = f"{_urlencode(user, safe='')}:{_urlencode(pw, safe='')}@" if user else ""
            return f"{scheme}://{auth}{host}/{topic}"

        if service == "gotify":
            server = (config.get("server") or "").rstrip("/")
            token  = config.get("token", "").strip()
            if not server or not token:
                return None
            p      = urlparse(server)
            scheme = "gotifys" if p.scheme == "https" else "gotify"
            host   = p.netloc or p.path
            return f"{scheme}://{host}/{token}"

        if service == "pushbullet":
            key = config.get("api_key", "").strip()
            return f"pbul://{key}" if key else None

        if service == "telegram":
            bot   = config.get("bot_token", "").strip()
            chat  = config.get("chat_id", "").strip()
            return f"tgram://{bot}/{chat}/" if bot and chat else None

        if service == "discord":
            wid  = config.get("webhook_id",    "").strip()
            wtok = config.get("webhook_token",  "").strip()
            return f"discord://{wid}/{wtok}" if wid and wtok else None

        if service == "pushover":
            ukey  = config.get("user_key", "").strip()
            token = config.get("api_token", "").strip()
            return f"pover://{ukey}@{token}" if ukey and token else None

        if service == "slack":
            ta = config.get("token_a", "").strip()
            tb = config.get("token_b", "").strip()
            tc = config.get("token_c", "").strip()
            return f"slack://{ta}/{tb}/{tc}" if ta and tb and tc else None

        if service == "email":
            smtp_host = config.get("smtp_host", "").strip()
            smtp_user = config.get("smtp_user", "").strip()
            smtp_pass = config.get("smtp_password", "").strip()
            to_email  = config.get("to_email", "").strip()
            port      = config.get("smtp_port", "587")
            secure    = config.get("secure", True)
            if not all([smtp_host, smtp_user, smtp_pass, to_email]):
                return None
            scheme = "mailtos" if secure else "mailto"
            return (f"{scheme}://{_urlencode(smtp_user, safe='')}:"
                    f"{_urlencode(smtp_pass, safe='')}@{smtp_host}:{port}/"
                    f"{_urlencode(to_email, safe='')}")

        if service == "webhook":
            url = config.get("url", "").strip()
            if not url:
                return None
            p    = urlparse(url)
            scheme = "jsons" if p.scheme == "https" else "json"
            rest = p.netloc + p.path
            if p.query:
                rest += f"?{p.query}"
            return f"{scheme}://{rest}"

        if service == "matrix":
            user     = config.get("user",     "").strip()
            password = config.get("password", "").strip()
            raw_host = config.get("host",     "").strip()
            room     = config.get("room",     "").strip()
            port     = config.get("port",     "").strip()
            secure   = bool(config.get("secure", True))
            if not user or not password or not raw_host:
                return None
            if raw_host.lower().startswith("https://"):
                secure   = True
                raw_host = raw_host[8:].rstrip("/")
            elif raw_host.lower().startswith("http://"):
                secure   = False
                raw_host = raw_host[7:].rstrip("/")
            scheme   = "matrixs" if secure else "matrix"
            port_str = f":{port}" if port else ""
            room_str = f"/{_urlencode(room, safe='#:')}" if room else ""
            return (f"{scheme}://{_urlencode(user, safe='')}:"
                    f"{_urlencode(password, safe='')}@{raw_host}{port_str}{room_str}")

        if service == "msteams":
            wh = config.get("webhook_url", "").strip()
            m  = _re.search(
                r"webhookb2/([^@]+)@([^/]+)/IncomingWebhook/([^/]+)/([^/?]+)", wh)
            return f"msteams://{m.group(1)}/{m.group(2)}/{m.group(3)}/{m.group(4)}" if m else None

        if service == "signal":
            from_phone = config.get("from_phone", "").strip()
            to_phone   = config.get("to_phone",   "").strip()
            host       = (config.get("host", "") or "localhost").strip()
            port       = (config.get("port", "") or "8080").strip()
            if not from_phone or not to_phone:
                return None
            return (f"signal://{_urlencode(from_phone, safe='+')}"
                    f"@{host}:{port}/{_urlencode(to_phone, safe='+')}")

        if service == "whatsapp":
            token    = config.get("token",    "").strip()
            phone_id = config.get("phone_id", "").strip()
            to_phone = config.get("to_phone", "").strip()
            if not all([token, phone_id, to_phone]):
                return None
            return f"whatsapp://{_urlencode(token, safe='')}@{phone_id}/{_urlencode(to_phone, safe='+')}"

        if service == "mqtt":
            raw_host = config.get("host",     "").strip()
            topic    = config.get("topic",    "").strip()
            user     = config.get("user",     "").strip()
            password = config.get("password", "").strip()
            port     = config.get("port",     "").strip()
            secure   = bool(config.get("secure", False))
            if not raw_host or not topic:
                return None
            if raw_host.lower().startswith("mqtts://"):
                secure   = True
                raw_host = raw_host[8:].rstrip("/")
            elif raw_host.lower().startswith("mqtt://"):
                raw_host = raw_host[7:].rstrip("/")
            if port == "8883":
                secure = True
            scheme   = "mqtts" if secure else "mqtt"
            auth     = ""
            if user:
                auth = (f"{_urlencode(user, safe='')}:{_urlencode(password, safe='')}@"
                        if password else f"{_urlencode(user, safe='')}@")
            port_str = f":{port}" if port else ""
            return f"{scheme}://{auth}{raw_host}{port_str}/{_urlencode(topic, safe='/')}"

        if service == "ifttt":
            key   = config.get("webhook_key", "").strip()
            event = config.get("event_id",    "").strip()
            return f"ifttt://{key}@{event}" if key and event else None

    except Exception:
        return None
    return None


def _ha_build_url(config: dict) -> tuple[str, str]:
    """Return (url, token) for the HA service REST endpoint, or raise ValueError."""
    raw_host = config.get("host", "").strip()
    token    = config.get("token", "").strip()
    if not raw_host or not token:
        raise ValueError("Home Assistant requires 'host' and 'token'")
    port   = str(config.get("port", "") or "").strip()
    secure = bool(config.get("secure", False))
    # notifier may be "domain/service" or just a short name (assumed notify domain)
    notifier = (config.get("notifier", "") or "persistent_notification/create").strip()
    if "/" not in notifier:
        notifier = f"notify/{notifier}"
    if raw_host.lower().startswith("https://"):
        secure, raw_host = True, raw_host[8:].rstrip("/")
    elif raw_host.lower().startswith("http://"):
        secure, raw_host = False, raw_host[7:].rstrip("/")
    if port == "443":
        secure = True
    scheme   = "https" if secure else "http"
    port_str = f":{port}" if port else ""
    return f"{scheme}://{raw_host}{port_str}/api/services/{notifier}", token


async def _notify_home_assistant(config: dict, title: str, body: str) -> None:
    url, token = _ha_build_url(config)
    async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
        resp = await client.post(
            url,
            json={"message": body, "title": title},
            headers={"Authorization": f"Bearer {token}"},
        )
        resp.raise_for_status()


async def _notification_dispatch(event_type: str, title: str, body: str,
                                  device_mac: str | None = None):
    """Dispatch a notification event through all matching profiles and their channels."""
    import apprise as _apprise
    db = SessionLocal()
    try:
        profiles = db.execute(text("""
            SELECT id FROM notification_profiles
            WHERE (events->>:ev)::boolean = true
        """), {"ev": event_type}).fetchall()

        if not profiles:
            return

        channels_to_send: dict = {}   # ch_id → (service, config_dict)
        for (profile_id,) in profiles:
            rows = db.execute(text("""
                SELECT nc.id, nc.service, nc.config
                FROM notification_channels nc
                JOIN notification_profile_channels npc ON npc.channel_id = nc.id
                WHERE npc.profile_id = :pid AND nc.enabled = TRUE
            """), {"pid": profile_id}).fetchall()
            for ch_id, svc, cfg in rows:
                if ch_id not in channels_to_send:
                    channels_to_send[ch_id] = (svc, cfg if isinstance(cfg, dict) else {})
    finally:
        db.close()

    # Virtual channels: toast and browser queue to the pending poll endpoint
    toast_notify   = any(svc == "toast"   for svc, _ in channels_to_send.values())
    browser_notify = any(svc == "browser" for svc, _ in channels_to_send.values())

    if toast_notify or browser_notify:
        _pending_browser_notifications.append({
            "event_type": event_type, "title": title, "body": body,
            "toast": toast_notify, "browser": browser_notify,
            "ts": datetime.now(timezone.utc).isoformat(),
        })
        if len(_pending_browser_notifications) > 200:
            _pending_browser_notifications.pop(0)

    urls = []
    for ch_id, (svc, cfg) in channels_to_send.items():
        if svc in ("toast", "browser"):
            continue
        if svc == "home_assistant":
            try:
                await _notify_home_assistant(cfg, title, body)
            except Exception as exc:
                print(f"[notify] Home Assistant error: {exc}", flush=True)
            continue
        url = _build_apprise_url(svc, cfg)
        if url:
            urls.append(url)

    if urls:
        try:
            a = _apprise.Apprise()
            for url in urls:
                a.add(url)
            await asyncio.to_thread(a.notify, title=title, body=body)
        except Exception as exc:
            print(f"[notify] Apprise error: {exc}", flush=True)


def _is_suppressed(mac: str, event_type: str, cache: dict) -> bool:
    """Check if an alert for (mac, event_type) is suppressed. Uses cache to avoid N+1 queries."""
    key = (mac, event_type)
    if key in cache:
        return cache[key]
    db = SessionLocal()
    try:
        row = db.execute(text("""
            SELECT id FROM alert_suppressions
            WHERE (mac_address = :mac OR mac_address IS NULL)
              AND (event_type = :type OR event_type IS NULL)
              AND (expires_at IS NULL OR expires_at > NOW())
            LIMIT 1
        """), {"mac": mac, "type": event_type}).fetchone()
        result = row is not None
        cache[key] = result
        return result
    finally:
        db.close()


async def _notification_loop():
    global _last_alert_event_id, _last_network_paused
    await asyncio.sleep(20)  # startup grace

    db = SessionLocal()
    try:
        row = db.execute(text("SELECT COALESCE(MAX(id), 0) FROM device_events")).scalar()
        _last_alert_event_id = int(row or 0)
        s = db.get(Setting, "network_paused")
        _last_network_paused = s.value if s else "false"
    except Exception:
        pass
    finally:
        db.close()

    while True:
        try:
            db = SessionLocal()
            try:
                settings = {s.key: s.value for s in db.query(Setting).all()}

                # Network pause detection
                network_paused = settings.get("network_paused", "false")
                if network_paused == "true" and _last_network_paused != "true":
                    asyncio.ensure_future(_notification_dispatch(
                        "block.network_pause", "Network Paused",
                        "Internet access has been blocked for the whole network",
                    ))
                _last_network_paused = network_paused

                vuln_on_new    = settings.get("vuln_scan_on_new_device",  "false") == "true"
                vuln_on_port   = settings.get("vuln_scan_on_port_change", "false") == "true"
                auto_block_new = settings.get("auto_block_new_devices",   "false") == "true"
                auto_block_sev = settings.get("auto_block_vuln_severity", "none")
                returned_days  = int(settings.get("device_returned_days", "7") or "7")
                SEV_ORDER      = ["none", "info", "clean", "low", "medium", "high", "critical"]

                rows = db.execute(text("""
                    SELECT de.id, de.mac_address, de.type, de.detail, de.created_at,
                           COALESCE(d.custom_name, d.hostname, d.ip_address, de.mac_address) AS name,
                           d.ip_address, d.is_important,
                           COALESCE(d.is_ignored, false) AS is_ignored,
                           d.scan_results, d.vuln_severity
                    FROM device_events de
                    JOIN devices d ON d.mac_address = de.mac_address
                    WHERE de.id > :last_id
                      AND de.type = ANY(:types)
                    ORDER BY de.id ASC
                    LIMIT 100
                """), {
                    "last_id": _last_alert_event_id,
                    "types":   ["joined", "interface_joined", "online", "offline",
                                "vuln_scan_complete", "port_opened", "blocked", "unblocked"],
                }).fetchall()

                dispatches:      list = []  # (event_type, title, body, mac)
                vuln_scans:      list = []
                devices_to_block: list = []
                suppression_cache: dict = {}

                for row in rows:
                    eid, mac, etype, detail, created_at, name, ip, is_important, is_ignored, scan_results, vuln_severity = row
                    _last_alert_event_id = max(_last_alert_event_id, eid)
                    if is_ignored:
                        continue
                    d = detail or {}

                    if etype in ("joined", "interface_joined"):
                        dispatches.append(("device.new", "New Device",
                                           f"{name} ({ip}) appeared on the network", mac))
                        if auto_block_new:
                            devices_to_block.append((mac, ip))
                        if vuln_on_new and ip:
                            scripts_s = db.get(Setting, "vuln_scan_templates")
                            vuln_scans.append((mac, ip, (scripts_s.value or "").strip() if scripts_s else ""))

                    elif etype == "online":
                        dispatches.append(("device.online.all", "Device Online",
                                           f"{name} ({ip}) is back online", mac))
                        if is_important:
                            dispatches.append(("device.online.watched", "Watched Device Online",
                                               f"{name} ({ip}) is back online", mac))
                        # device.returned: look up when it last went offline
                        off_row = db.execute(text("""
                            SELECT created_at FROM device_events
                            WHERE mac_address = :mac AND type = 'offline'
                            ORDER BY id DESC LIMIT 1
                        """), {"mac": mac}).fetchone()
                        if off_row:
                            off_at = off_row[0]
                            if off_at.tzinfo is None:
                                off_at = off_at.replace(tzinfo=timezone.utc)
                            days_absent = (datetime.now(timezone.utc) - off_at).days
                            if days_absent >= returned_days:
                                dispatches.append(("device.returned", "Device Returned",
                                                   f"{name} ({ip}) reappeared after {days_absent} days", mac))
                        # person.home: check if this mac belongs to a person now home
                        person_row = db.execute(text("""
                            SELECT p.id::text, p.name FROM persons p
                            JOIN person_devices pd ON pd.person_id = p.id
                            WHERE pd.mac_address = :mac LIMIT 1
                        """), {"mac": mac}).fetchone()
                        if person_row:
                            pid, pname = person_row
                            # Person is home if at least one of their devices is online
                            any_online = db.execute(text("""
                                SELECT 1 FROM person_devices pd
                                JOIN devices d ON d.mac_address = pd.mac_address
                                WHERE pd.person_id = :pid AND d.is_online = true LIMIT 1
                            """), {"pid": pid}).fetchone()
                            if any_online:
                                dispatches.append(("person.home", "Person Arrived Home",
                                                   f"{pname} is now home", None))

                    elif etype == "offline":
                        dispatches.append(("device.offline.all", "Device Offline",
                                           f"{name} ({ip}) went offline", mac))
                        if is_important:
                            dispatches.append(("device.offline.watched", "Watched Device Offline",
                                               f"{name} ({ip}) went offline", mac))
                        # person.away: check if this mac belongs to a person now away
                        person_row = db.execute(text("""
                            SELECT p.id::text, p.name FROM persons p
                            JOIN person_devices pd ON pd.person_id = p.id
                            WHERE pd.mac_address = :mac LIMIT 1
                        """), {"mac": mac}).fetchone()
                        if person_row:
                            pid, pname = person_row
                            # Person is away if none of their devices are online
                            any_online = db.execute(text("""
                                SELECT 1 FROM person_devices pd
                                JOIN devices d ON d.mac_address = pd.mac_address
                                WHERE pd.person_id = :pid AND d.is_online = true LIMIT 1
                            """), {"pid": pid}).fetchone()
                            if not any_online:
                                dispatches.append(("person.away", "Person Left Home",
                                                   f"{pname} is away (all devices offline)", None))

                    elif etype == "vuln_scan_complete":
                        severity = d.get("severity", "clean")
                        count    = d.get("vuln_count", 0)
                        if severity == "critical":
                            dispatches.append(("vuln.critical", "Critical Vulnerability",
                                               f"{name} ({ip}): {count} critical finding(s)", mac))
                        elif severity == "high":
                            dispatches.append(("vuln.high", "High Vulnerability",
                                               f"{name} ({ip}): {count} high-severity finding(s)", mac))
                        if auto_block_sev != "none":
                            try:
                                if SEV_ORDER.index(severity) >= SEV_ORDER.index(auto_block_sev):
                                    devices_to_block.append((mac, ip))
                            except ValueError:
                                pass

                    elif etype == "port_opened":
                        port = d.get("port")
                        sev  = d.get("severity", "info")
                        if port and int(port) in HIGH_RISK_PORTS:
                            dispatches.append(("port.high_risk", "High-Risk Port",
                                               f"{name} ({ip}): port {port} is high-risk", mac))
                        dispatches.append(("port.opened", "New Port Detected",
                                           f"{name} ({ip}): port {port} [{sev}] opened above baseline", mac))
                        if vuln_on_port and ip:
                            scripts_s = db.get(Setting, "vuln_scan_templates")
                            vuln_scans.append((mac, ip, (scripts_s.value or "").strip() if scripts_s else ""))

                    elif etype == "blocked":
                        reason = d.get("reason", "")
                        if reason == "schedule":
                            dispatches.append(("block.schedule_start", "Block Schedule Started",
                                               f"Block schedule activated for {name}", mac))
                        elif reason in ("auto", "auto_block"):
                            dispatches.append(("device.auto_blocked", "Device Auto-Blocked",
                                               f"{name} ({ip}) was automatically blocked", mac))

                    elif etype == "unblocked":
                        if d.get("reason") == "schedule_end":
                            dispatches.append(("block.schedule_end", "Block Schedule Ended",
                                               f"Block schedule deactivated for {name}", mac))

                    # ── Plugin event bus dispatch ─────────────────────────────
                    _sev_map     = {"low": 1, "info": 1, "medium": 2, "high": 3, "critical": 3}
                    _ports_count = len((scan_results or {}).get("open_ports", [])) if scan_results else 0
                    _vuln_count  = _sev_map.get(vuln_severity or "", 0)
                    _pe_ctx = {
                        "mac":   mac,
                        "name":  name,
                        "ip":    ip,
                        "ports": _ports_count,
                        "vulns": _vuln_count,
                    }
                    _pe_type = None
                    if etype in ("joined", "interface_joined"):
                        _pe_type = "device.new"
                    elif etype == "online":
                        _pe_type = "device.online"
                    elif etype == "offline":
                        _pe_type = "device.offline"
                    elif etype == "port_opened":
                        _pe_ctx["ports"] = _ports_count
                        _pe_type = "port.opened"
                    elif etype == "vuln_scan_complete":
                        severity_str = d.get("severity", "clean")
                        if severity_str not in ("clean", "none", ""):
                            _pe_ctx["vulns"] = d.get("vuln_count", _vuln_count)
                            _pe_type = "vuln.found"
                    elif etype == "renamed":
                        # renamed is not in the standard event hook vocab — call HA directly
                        if _ha_mqtt.connected:
                            try:
                                _ha_mqtt.pub_device_discovery(mac, name, ip)
                            except Exception as _ha_exc:
                                print(f"[ha-mqtt] Renamed dispatch error: {_ha_exc}", flush=True)
                    if _pe_type:
                        asyncio.ensure_future(_plugin_event_bus.notify(_pe_type, _pe_ctx))

            finally:
                db.close()

            # ── HA MQTT system stats after processing batch ──────────────────
            if _ha_mqtt.connected:
                try:
                    _ha_db = SessionLocal()
                    try:
                        _tot_on   = _ha_db.execute(text("SELECT COUNT(*) FROM devices WHERE is_online=true")).scalar() or 0
                        _tot_vuln = _ha_db.execute(text(
                            "SELECT COUNT(*) FROM devices WHERE vuln_severity IS NOT NULL AND vuln_severity NOT IN ('none','clean')"
                        )).scalar() or 0
                        _ls_row   = _ha_db.execute(text(
                            "SELECT created_at FROM device_events WHERE type='scan_complete' ORDER BY id DESC LIMIT 1"
                        )).fetchone()
                        _ha_mqtt.pub_system_state(_tot_on, _tot_vuln, "idle",
                                                   _ls_row[0].isoformat() if _ls_row else None)
                    finally:
                        _ha_db.close()
                except Exception as _ha_exc:
                    print(f"[ha-mqtt] System stats error: {_ha_exc}", flush=True)

            for event_type, title, body, mac in dispatches:
                if not _is_suppressed(mac, event_type, suppression_cache):
                    asyncio.ensure_future(_notification_dispatch(event_type, title, body, mac))

            for mac, ip, scripts in vuln_scans:
                asyncio.ensure_future(_run_single_vuln_scan(mac, ip, scripts))

            for mac, ip in devices_to_block:
                try:
                    await _execute_block_bg(mac, ip, "block")
                    db2 = SessionLocal()
                    try:
                        db2.execute(text("UPDATE devices SET is_blocked=true WHERE mac_address=:mac"), {"mac": mac})
                        _add_event(db2, mac, "blocked", {"reason": "auto", "ip": ip})
                        db2.commit()
                    finally:
                        db2.close()
                    asyncio.ensure_future(_plugin_event_bus.notify("device.blocked", {"mac": mac, "ip": ip or ""}))
                    print(f"[notify] Auto-blocked {mac}", flush=True)
                except Exception as exc:
                    print(f"[notify] Auto-block {mac}: {exc}", flush=True)

        except Exception as exc:
            print(f"[notify] Loop error: {exc}", flush=True)

        await asyncio.sleep(30)


app = FastAPI(title="InSpectre API", version="1.0.0")
app.include_router(_cu.router)

_CORS_ORIGINS = [o.strip() for o in os.environ.get(
    "CORS_ORIGINS",
    "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000"
).split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
)

# Paths that do NOT require a valid JWT (auth + setup wizard + FastAPI docs)
_PUBLIC_PATHS = frozenset([
    "/",
    "/health",
    "/auth/login",
    "/setup/status",
    "/setup/create-user",
    "/setup/network-info",
    "/setup/apply-network",
    "/setup/complete",
    "/setup/restore-from-backup",
    "/docs",
    "/redoc",
    "/openapi.json",
])

@app.middleware("http")
async def _auth_middleware(request: Request, call_next):
    """Reject unauthenticated requests to all non-public paths."""
    # Always pass CORS preflight and public endpoints through
    if request.method == "OPTIONS" or request.url.path in _PUBLIC_PATHS:
        return await call_next(request)

    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:] if auth_header.startswith("Bearer ") else ""
    # EventSource (used for /events/stream) cannot set custom headers, so allow
    # the bearer token to be supplied as a query parameter as a fallback.
    if not token:
        token = request.query_params.get("token", "")
    if not token:
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)

    # _decode_token is defined later in this file — valid at call time
    username = _decode_token(token)
    if not username:
        return JSONResponse({"detail": "Invalid or expired token"}, status_code=401)

    return await call_next(request)


@app.middleware("http")
async def _sse_mutation_notifier(request: Request, call_next):
    """
    After any successful mutating request, broadcast a hint on the SSE stream so
    connected clients refresh the affected view immediately.  Covers
    schedules / persons / device groups; device presence & block state are
    already streamed by _sse_event_watcher from device_events.
    """
    response = await call_next(request)
    try:
        if (request.method in ("POST", "PUT", "PATCH", "DELETE")
                and 200 <= response.status_code < 300):
            path = request.url.path
            if "/block-schedules" in path:
                _sse_publish("schedules", {})
                _sse_publish("devices", {})
            elif "/persons" in path:
                _sse_publish("persons", {})
                _sse_publish("devices", {})
            elif "/group" in path:
                _sse_publish("devices", {})
            elif "/metadata" in path or path.startswith("/devices/"):
                _sse_publish("devices", {})
    except Exception:
        pass
    return response


# ---------------------------------------------------------------------------
# Traffic stats flush loop — polls probe every 5 min and writes to DB
# ---------------------------------------------------------------------------
async def _check_traffic_notifications(sessions: list):
    """Fire traffic-based notifications with a 24-hour per-device cooldown."""
    db = SessionLocal()
    try:
        susp_s = db.get(Setting, "traffic_suspicious_countries")
        susp_countries = {c.strip().upper() for c in (susp_s.value or "").split(",") if c.strip()} if susp_s else set()
    finally:
        db.close()

    now = datetime.now(timezone.utc)
    COOLDOWN = 86400  # seconds

    for session in sessions:
        mac = session.get("mac", "").lower()
        if not mac:
            continue
        for bucket in session.get("history", []):
            unusual_ports = bucket.get("unusual_ports") or []
            if unusual_ports:
                key = (mac, "traffic.unusual_port")
                last = _traffic_notif_cooldowns.get(key)
                if last is None or (now - last).total_seconds() > COOLDOWN:
                    _traffic_notif_cooldowns[key] = now
                    ports_str = ", ".join(str(p) for p in unusual_ports[:5])
                    asyncio.ensure_future(_notification_dispatch(
                        "traffic.unusual_port", "Unusual Traffic Pattern",
                        f"Device {mac}: traffic on unusual ports ({ports_str})",
                    ))
                break  # one check per mac per cycle

            if susp_countries:
                top_countries = bucket.get("top_countries") or {}
                if isinstance(top_countries, str):
                    try:
                        top_countries = json.loads(top_countries)
                    except Exception:
                        top_countries = {}
                flagged = [c for c in top_countries if c.upper() in susp_countries]
                if flagged:
                    key = (mac, "traffic.suspicious_country")
                    last = _traffic_notif_cooldowns.get(key)
                    if last is None or (now - last).total_seconds() > COOLDOWN:
                        _traffic_notif_cooldowns[key] = now
                        asyncio.ensure_future(_notification_dispatch(
                            "traffic.suspicious_country", "Suspicious Country Traffic",
                            f"Device {mac}: traffic detected to {', '.join(flagged)}",
                        ))
                    break


async def _traffic_flush_loop():
    await asyncio.sleep(60)  # startup grace
    while True:
        try:
            async with _probe_client(timeout=10.0) as client:
                resp = await client.get(f"{PROBE_URL}/traffic/stats")
                if resp.status_code == 200:
                    data = resp.json()
                    sessions = data.get("sessions", [])
                    if sessions:
                        db = SessionLocal()
                        try:
                            _flush_traffic_sessions(db, sessions)
                        finally:
                            db.close()
                        await _check_traffic_notifications(sessions)
        except httpx.ConnectError:
            pass
        except Exception as exc:
            print(f"[traffic_flush] error: {exc}", flush=True)

        # Daily retention cleanup
        try:
            db = SessionLocal()
            try:
                ret_s = db.get(Setting, "traffic_retention_days")
                days  = int(ret_s.value) if ret_s else 30
                cutoff = datetime.now(timezone.utc) - timedelta(days=days)
                db.execute(text("DELETE FROM traffic_stats WHERE created_at < :cutoff"), {"cutoff": cutoff})
                db.commit()
            finally:
                db.close()
        except Exception as exc:
            print(f"[traffic_flush] retention cleanup error: {exc}", flush=True)

        await asyncio.sleep(300)  # 5-minute poll


_last_speedtest_slot: datetime | None = None

_SPEEDTEST_EPOCH = datetime(2020, 1, 1, tzinfo=timezone.utc)

def _speedtest_current_slot(interval_s: int) -> datetime:
    elapsed = (datetime.now(timezone.utc) - _SPEEDTEST_EPOCH).total_seconds()
    return _SPEEDTEST_EPOCH + timedelta(seconds=int(elapsed // interval_s) * interval_s)

async def _speedtest_schedule_loop():
    global _last_speedtest_slot
    await asyncio.sleep(120)
    INTERVALS = {"30m": 1800, "1h": 3600, "6h": 21600, "24h": 86400}
    while True:
        try:
            db = SessionLocal()
            try:
                sched_s = db.get(Setting, "speedtest_schedule")
                sched   = sched_s.value if sched_s else "disabled"
            finally:
                db.close()
            interval = INTERVALS.get(sched)
            if interval:
                slot = _speedtest_current_slot(interval)
                if _last_speedtest_slot is None:
                    # On startup, record the current slot without running — next slot fires the test
                    _last_speedtest_slot = slot
                elif slot > _last_speedtest_slot:
                    await _run_speedtest_and_save()
                    _last_speedtest_slot = slot
        except Exception as exc:
            print(f"[speedtest] schedule loop error: {exc}", flush=True)
        await asyncio.sleep(300)


async def _run_speedtest_and_save():
    try:
        result: dict = {}
        raw_lines: list[str] = []
        async with _probe_client(timeout=180) as client:
            async with client.stream("GET", f"{PROBE_URL}/stream/tools/speedtest") as resp:
                async for line in resp.aiter_lines():
                    if line.startswith("data: RESULT:"):
                        result = json.loads(line[len("data: RESULT:"):])
                    elif line.startswith("data: "):
                        raw_lines.append(line[6:])
        if result.get("download_mbps") is not None or result.get("upload_mbps") is not None:
            db = SessionLocal()
            try:
                db.execute(text(
                    "INSERT INTO speedtest_results (server, ping_ms, download_mbps, upload_mbps, raw_output) "
                    "VALUES (:server, :ping, :dl, :ul, :raw)"
                ), {
                    "server": result.get("server"),
                    "ping":   result.get("ping_ms"),
                    "dl":     result.get("download_mbps"),
                    "ul":     result.get("upload_mbps"),
                    "raw":    "\n".join(raw_lines),
                })
                db.commit()
            finally:
                db.close()
            print(f"[speedtest] completed — DL: {result.get('download_mbps')} Mbps, UL: {result.get('upload_mbps')} Mbps", flush=True)
            dl = result.get("download_mbps")
            if dl is not None:
                db2 = SessionLocal()
                try:
                    exp_s = db2.get(Setting, "speedtest_expected_download")
                    thr_s = db2.get(Setting, "speedtest_alert_threshold")
                    exp_dl    = float(exp_s.value) if exp_s and exp_s.value else 0.0
                    threshold = float(thr_s.value) if thr_s and thr_s.value else 80.0
                finally:
                    db2.close()
                if exp_dl > 0 and dl < exp_dl * threshold / 100:
                    pct = int(dl / exp_dl * 100)
                    asyncio.ensure_future(_notification_dispatch(
                        "speedtest.degraded_download", "Download Speed Degraded",
                        f"Download {dl:.1f} Mbps is {pct}% of expected {exp_dl:.0f} Mbps",
                    ))
    except Exception as exc:
        print(f"[speedtest] scheduled run error: {exc}", flush=True)


def _flush_traffic_sessions(db, sessions: list) -> None:
    for s in sessions:
        mac = s.get("mac", "").lower()
        ip  = s.get("target_ip")
        if not mac:
            continue
        # Batch-query existing timestamps to avoid N+1 queries
        history = s.get("history", [])
        if not history:
            continue
        ts_candidates = []
        for bucket in history:
            ts_str = bucket.get("ts")
            if not ts_str:
                continue
            try:
                ts_candidates.append((datetime.fromisoformat(ts_str), bucket))
            except Exception:
                continue
        if not ts_candidates:
            continue
        existing_ts = set()
        try:
            rows = db.execute(
                text("SELECT bucket_ts FROM traffic_stats WHERE mac_address=:mac AND bucket_ts = ANY(:ts)"),
                {"mac": mac, "ts": [t for t, _ in ts_candidates]},
            ).fetchall()
            existing_ts = {r[0] for r in rows}
        except Exception:
            pass
        # Flush completed historical buckets (use pre-fetched existing_ts to skip N+1 queries)
        for bucket in history:
            ts_str = bucket.get("ts")
            if not ts_str:
                continue
            try:
                ts = datetime.fromisoformat(ts_str)
            except Exception:
                continue
            # Use timezone-aware comparison; strip tz if existing_ts has naive datetimes
            ts_key = ts.replace(tzinfo=None) if ts.tzinfo else ts
            if any(
                (e.replace(tzinfo=None) if hasattr(e, 'replace') else e) == ts_key
                for e in existing_ts
            ):
                continue
            row = TrafficStat(
                mac_address   = mac,
                ip_address    = ip,
                bucket_ts     = ts,
                bytes_in      = bucket.get("bytes_in", 0),
                bytes_out     = bucket.get("bytes_out", 0),
                packets_in    = bucket.get("packets_in", 0),
                packets_out   = bucket.get("packets_out", 0),
                lan_bytes     = bucket.get("lan_bytes", 0),
                wan_bytes     = bucket.get("wan_bytes", 0),
                dns_queries   = bucket.get("dns_queries"),
                tls_sni       = bucket.get("tls_sni"),
                http_hosts    = bucket.get("http_hosts"),
                top_ips       = bucket.get("top_ips"),
                top_ports     = bucket.get("top_ports"),
                top_countries = bucket.get("top_countries"),
                protocols     = bucket.get("protocols"),
                unusual_ports = bucket.get("unusual_ports"),
            )
            db.add(row)
    db.commit()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def _hash_password(password: str) -> str:
    return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt()).decode()

def _verify_password(plain: str, hashed: str) -> bool:
    return _bcrypt.checkpw(plain.encode(), hashed.encode())

def _create_token(username: str, expire_minutes: int | None = None) -> str:
    minutes = expire_minutes or TOKEN_EXPIRE_DEFAULT
    expire = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    return jwt.encode({"sub": username, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)

def _decode_token(token: str) -> str | None:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None

def _has_any_user(db: Session) -> bool:
    try:
        row = db.execute(text("SELECT id FROM users LIMIT 1")).fetchone()
        return row is not None
    except Exception:
        return False

def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
    db: Session = Depends(get_db),
) -> str:
    """Dependency that returns the username of the authenticated user or raises 401."""
    token = credentials.credentials if credentials else None
    if not token:
        raise HTTPException(401, "Not authenticated")
    username = _decode_token(token)
    if not username:
        raise HTTPException(401, "Invalid or expired token")
    row = db.execute(text("SELECT username FROM users WHERE username = :u"), {"u": username}).fetchone()
    if not row:
        raise HTTPException(401, "User not found")
    return username

def get_current_user_optional(
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
    db: Session = Depends(get_db),
) -> str | None:
    """Like get_current_user but returns None instead of raising (used for setup check)."""
    if not _has_any_user(db):
        return "__setup__"  # sentinel: setup not done, allow access
    token = credentials.credentials if credentials else None
    if not token:
        return None
    return _decode_token(token)


def _seed_default_user(db: Session) -> None:
    """
    Fallback only: if setup is marked complete but no users exist (e.g. users table
    was wiped, or the wizard was skipped on an older deployment), create admin/admin
    so the instance isn't permanently locked out.

    Does NOT run when setup_complete = false — in that case the wizard handles
    user creation and this would conflict with it.
    """
    try:
        if _has_any_user(db):
            return
        s = db.get(Setting, "setup_complete")
        if not s or s.value != "true":
            return  # Wizard hasn't run yet — let it create the first user
        db.execute(
            text("""INSERT INTO users (username, password_hash, is_admin, must_change_password)
                    VALUES (:u, :h, TRUE, TRUE)
                    ON CONFLICT (username) DO NOTHING"""),
            {"u": "admin", "h": _hash_password("admin")},
        )
        db.commit()
        print("[startup] No users found — created default admin/admin. Please change the password.", flush=True)
    except Exception as e:
        db.rollback()
        print(f"[startup] Could not seed default user: {e}", flush=True)


# ---------------------------------------------------------------------------
# Fingerbank device identification
# ---------------------------------------------------------------------------
_FB_URL = "https://api.fingerbank.org/api/v2/combinations/interrogate"

_FB_TYPE_MAP: list[tuple[list[str], str]] = [
    # Mobile — most specific first to avoid "android tv" matching android→phone
    (["iphone"],                                                    "phone"),
    (["ipad"],                                                      "tablet"),
    (["android tablet", "galaxy tab", "kindle fire"],               "tablet"),
    (["android", "mobile device", "smartphone"],                    "phone"),
    # PCs
    (["macbook", "imac", "mac mini", "mac pro"],                    "laptop"),
    (["laptop", "notebook"],                                        "laptop"),
    (["mac os", "macos", "os x"],                                   "laptop"),
    (["windows", "microsoft windows"],                              "desktop"),
    (["linux"],                                                     "desktop"),
    # Network infrastructure
    (["router", "gateway", "openwrt", "dd-wrt", "pfsense",
      "opnsense", "mikrotik", "routeros", "firewall"],              "router"),
    (["access point", "wireless ap", "wireless access point"],      "ap"),
    (["network switch", "managed switch", "unmanaged switch",
      "gigabit switch", "easy smart switch", "smart switch plus",
      "poe switch"],                                                 "switch"),
    # Streaming — before TV so "fire tv" etc match streamer not tv
    (["roku", "fire tv", "firetv", "chromecast", "apple tv",
      "streaming stick", "streaming device"],                       "streamer"),
    # TVs
    (["smart tv", "television", "android tv", "google tv",
      "qled", "oled tv"],                                           "tv"),
    # Consoles
    (["playstation", "xbox", "nintendo", "game console",
      "steam deck"],                                                 "console"),
    # IoT — before camera/printer so order doesn't matter
    (["raspberry pi"],                                              "iot"),
    (["iot", "smart home", "internet of things", "thermostat",
      "smart plug", "smart bulb", "smart light"],                   "iot"),
    # Printers
    (["printer", "network printer", "laser printer", "inkjet",
      "all-in-one printer"],                                        "printer"),
    # Cameras
    (["ip camera", "security camera", "network camera", "nvr",
      "cctv", "hikvision", "dahua", "reolink"],                    "camera"),
    (["camera"],                                                    "camera"),
    # VoIP
    (["voip", "sip phone", "ip phone", "desk phone"],              "voip"),
    # NAS / Server
    (["nas", "network attached", "network storage",
      "synology", "qnap", "truenas", "freenas"],                   "nas"),
    (["server"],                                                    "server"),
]


def _fingerbank_to_type(device_name: str, parents: list[str]) -> str | None:
    all_names = [device_name.lower()] + [p.lower() for p in parents]
    for keywords, dtype in _FB_TYPE_MAP:
        if any(kw in name for name in all_names for kw in keywords):
            return dtype
    return None


async def _fingerbank_query(mac: str, dhcp_fingerprint: str | None, dhcp_vendor: str | None,
                            dhcp_hostname: str | None, api_key: str) -> dict:
    """
    Call Fingerbank API. Returns a result dict always — includes an 'error' key on failure
    so callers can surface the reason without swallowing it.
    Sends whatever DHCP signals are available; at least one must be present.
    """
    body: dict = {}
    if dhcp_fingerprint:
        body["dhcp_fingerprint"] = dhcp_fingerprint
    if dhcp_vendor:
        body["dhcp_vendor"] = dhcp_vendor
    if dhcp_hostname:
        body["hostname"] = dhcp_hostname
    body["mac"] = mac

    if len(body) == 1:  # only mac — nothing useful to send
        return {"error": "No DHCP data available to query", "queried_at": datetime.now(timezone.utc).isoformat(), "dhcp_fp_used": None}

    print(f"[fingerbank] querying {mac}  fp={dhcp_fingerprint!r}  vc={dhcp_vendor!r}", flush=True)

    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            resp = await client.post(
                _FB_URL,
                params={"key": api_key},
                headers={"Authorization": f"Token {api_key}"},
                json=body,
            )
        print(f"[fingerbank] {mac} → HTTP {resp.status_code}", flush=True)

        if resp.status_code == 200:
            data = resp.json()
            dev = data.get("device") or {}

            # Parents may be a nested tree or a flat list — handle both
            def _collect_names(node, depth=0) -> list[str]:
                if not node or depth > 8:
                    return []
                names = []
                if isinstance(node, dict):
                    n = (node.get("name") or "").strip()
                    if n:
                        names.append(n)
                    for p in (node.get("parents") or []):
                        names += _collect_names(p, depth + 1)
                elif isinstance(node, list):
                    for item in node:
                        names += _collect_names(item, depth)
                return names

            parent_names = _collect_names(dev.get("parents"))
            device_name  = (dev.get("name") or "").strip() or None
            score        = data.get("score")
            mapped_type  = _fingerbank_to_type(device_name or "", parent_names)

            print(f"[fingerbank] {mac} → {device_name!r} score={score} type={mapped_type} "
                  f"parents={parent_names}", flush=True)
            return {
                "device_name":  device_name,
                "score":        score,
                "parents":      parent_names,
                "mapped_type":  mapped_type,
                "queried_at":   datetime.now(timezone.utc).isoformat(),
                "dhcp_fp_used": dhcp_fingerprint,
            }

        # Non-200 — log body so we can see the error message from Fingerbank
        body_text = resp.text[:400]
        ts = datetime.now(timezone.utc).isoformat()
        if resp.status_code == 401:
            msg = f"HTTP 401 Unauthorized — check your API key. Response: {body_text}"
            print(f"[fingerbank] {mac} error: {msg}", flush=True)
            # Permanent: bad key won't fix itself — stop retrying automatically
            return {"error": msg, "status": "auth_error", "queried_at": ts, "dhcp_fp_used": dhcp_fingerprint}
        elif resp.status_code == 404:
            msg = "No match found in Fingerbank database"
            print(f"[fingerbank] {mac}: {msg}", flush=True)
            # Permanent: Fingerbank has no entry for this device — don't retry
            return {"error": msg, "status": "no_match", "queried_at": ts, "dhcp_fp_used": dhcp_fingerprint}
        else:
            msg = f"HTTP {resp.status_code}. Response: {body_text}"
            print(f"[fingerbank] {mac} error: {msg}", flush=True)
            # Transient (429, 5xx, etc.) — loop will retry on next cycle
            return {"error": msg, "status": "error", "queried_at": ts, "dhcp_fp_used": dhcp_fingerprint}

    except Exception as exc:
        msg = f"Request failed: {exc}"
        print(f"[fingerbank] {mac} exception: {msg}", flush=True)
        # Transient — retry
        return {"error": msg, "status": "error", "queried_at": datetime.now(timezone.utc).isoformat(), "dhcp_fp_used": dhcp_fingerprint}


async def _fingerbank_loop():
    await asyncio.sleep(30)  # startup grace — let DHCP data arrive first
    while True:
        try:
            db = SessionLocal()
            try:
                key_row = db.get(Setting, "fingerbank_api_key")
                api_key = (key_row.value or "").strip() if key_row else ""
                if api_key:
                    # Query devices that have never been looked up, or had a transient error.
                    # Permanent outcomes (no_match, auth_error) and successes are never re-queried
                    # automatically — only the manual "Fetch now" button can override those.
                    rows = db.execute(text("""
                        SELECT mac_address FROM devices
                        WHERE (dhcp_fingerprint IS NOT NULL
                               OR dhcp_vendor_class IS NOT NULL
                               OR dhcp_hostname    IS NOT NULL)
                          AND (
                            fingerbank_result IS NULL
                            OR fingerbank_result->>'status' = 'error'
                          )
                        ORDER BY last_seen DESC
                    """)).fetchall()
                    if rows:
                        print(f"[fingerbank] loop: {len(rows)} device(s) to query", flush=True)
                    for (mac,) in rows:
                        device = db.get(Device, mac)
                        if not device:
                            continue
                        result = await _fingerbank_query(
                            mac, device.dhcp_fingerprint,
                            device.dhcp_vendor_class, device.dhcp_hostname, api_key
                        )
                        device.fingerbank_result = result
                        from sqlalchemy.orm.attributes import flag_modified
                        flag_modified(device, "fingerbank_result")
                        db.commit()
                        await asyncio.sleep(0.5)
            finally:
                db.close()
        except Exception as exc:
            print(f"[fingerbank-loop] unhandled error: {exc}", flush=True)
        await asyncio.sleep(60)  # check for new DHCP arrivals every minute


def _migrate_legacy_notifications(db: Session):
    """One-time: create notification channels from old settings if the table is empty."""
    count = db.execute(text("SELECT COUNT(*) FROM notification_channels")).scalar()
    if count:
        return

    channels = []
    ntfy_topic = db.get(Setting, "ntfy_topic")
    if ntfy_topic and ntfy_topic.value.strip():
        ntfy_url_s = db.get(Setting, "ntfy_url")
        server = ntfy_url_s.value.strip() if ntfy_url_s else "https://ntfy.sh"
        channels.append(("ntfy (migrated)", "ntfy", {"server": server, "topic": ntfy_topic.value.strip()}))

    gotify_url_s  = db.get(Setting, "gotify_url")
    gotify_tok_s  = db.get(Setting, "gotify_token")
    if gotify_url_s and gotify_url_s.value.strip() and gotify_tok_s and gotify_tok_s.value.strip():
        channels.append(("Gotify (migrated)", "gotify",
                         {"server": gotify_url_s.value.strip(), "token": gotify_tok_s.value.strip()}))

    pb_s = db.get(Setting, "pushbullet_api_key")
    if pb_s and pb_s.value.strip():
        channels.append(("Pushbullet (migrated)", "pushbullet", {"api_key": pb_s.value.strip()}))

    wh_s = db.get(Setting, "alert_webhook_url")
    if wh_s and wh_s.value.strip():
        channels.append(("Webhook (migrated)", "webhook", {"url": wh_s.value.strip()}))

    if not channels:
        return

    for name, svc, cfg in channels:
        db.execute(text(
            "INSERT INTO notification_channels (name, service, config) VALUES (:n, :s, :c)"
        ), {"n": name, "s": svc, "c": json.dumps(cfg)})
    db.commit()

    events: dict = {}
    def _flag(key):
        s = db.get(Setting, key)
        return s and s.value == "true"
    if _flag("alert_on_new_device"):
        events["device.new"] = True
    if _flag("alert_on_offline"):
        events["device.offline.watched"] = True
    if _flag("alert_on_vuln"):
        events.update({"vuln.critical": True, "vuln.high": True})
    if _flag("alert_on_port_change"):
        events["port.opened"] = True

    result = db.execute(text("""
        INSERT INTO notification_profiles (name, events)
        VALUES ('Migrated Alerts', :ev) RETURNING id
    """), {"ev": json.dumps(events)})
    profile_id = result.scalar()
    ch_ids = db.execute(text("SELECT id FROM notification_channels")).scalars().all()
    for cid in ch_ids:
        db.execute(text(
            "INSERT INTO notification_profile_channels (profile_id, channel_id) VALUES (:p, :c)"
        ), {"p": profile_id, "c": cid})
    db.commit()
    print(f"[notify] Migrated {len(channels)} legacy notification channel(s)", flush=True)


def _migrate_legacy_ha_mqtt(db: Session):
    """One-time migration: copy ha_mqtt_* settings into the home-assistant plugin config."""
    try:
        row = db.execute(
            text("SELECT config FROM plugins WHERE plugin_id = 'home-assistant'")
        ).fetchone()
        if row and isinstance(row.config, dict) and row.config.get("host"):
            return  # Already migrated

        def _s(key, default=""):
            r = db.get(Setting, key)
            return r.value if r else default

        host = _s("ha_mqtt_host").strip()
        if not host:
            return  # Nothing to migrate

        password = _s("ha_mqtt_password")
        config = {
            "host":             host,
            "port":             _s("ha_mqtt_port", "1883"),
            "user":             _s("ha_mqtt_user"),
            "password":         encrypt_field(password) if password else "",
            "discovery_prefix": _s("ha_mqtt_discovery_prefix", "homeassistant"),
            "state_prefix":     _s("ha_mqtt_state_prefix", "inspectre"),
        }
        enabled = _s("ha_mqtt_enabled", "false") == "true"
        new_status = "active" if enabled else "disabled"
        db.execute(
            text("""
                UPDATE plugins
                SET config  = CAST(:config AS jsonb),
                    enabled = :enabled,
                    status  = :status
                WHERE plugin_id = 'home-assistant'
            """),
            {"config": json.dumps(config), "enabled": enabled, "status": new_status},
        )
        db.commit()
        print("[plugins] Migrated ha_mqtt_* settings to home-assistant plugin config", flush=True)
    except Exception as exc:
        print(f"[plugins] HA migration (non-fatal): {exc}", flush=True)
        db.rollback()


async def _run_appliance_update_task():
    """Run a full appliance update in a thread so it doesn't block the event loop."""
    global _auto_update_running
    if _auto_update_running:
        return
    _auto_update_running = True
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _do_appliance_update)
    finally:
        _auto_update_running = False


def _do_appliance_update():
    """Synchronous update worker — pulls and recreates non-self containers, then
    triggers the helper container for the backend's own self-update."""
    try:
        import appliance_update as _au
        client  = _au.make_client()
        results = {}
        for name in _au.NON_SELF_CONTAINERS:
            try:
                results[name] = _au.update_container(client, name)
            except Exception as exc:
                results[name] = {"name": name, "error": str(exc)}
        # Self-update: launch the inspectre-updater helper container.
        try:
            updater_img = "thefunkygibbon/inspectre-web:latest"
            client.containers.run(
                updater_img,
                command=["python", "-m", "appliance_update"],
                name=_au.UPDATER_CONTAINER,
                detach=True,
                remove=True,
                volumes={"/var/run/docker.sock": {"bind": "/var/run/docker.sock", "mode": "rw"}},
                environment={"DATABASE_URL": os.environ.get("DATABASE_URL", "")},
            )
            results[_au.WEB_CONTAINER] = {"name": _au.WEB_CONTAINER, "triggered": True}
        except Exception as exc:
            results[_au.WEB_CONTAINER] = {"name": _au.WEB_CONTAINER, "self_update_error": str(exc)}
        _au.write_status("ok", results)
        print(f"[auto-update] complete: {results}", flush=True)
    except Exception as exc:
        print(f"[auto-update] FAILED: {exc}", flush=True)
        try:
            import appliance_update as _au
            _au.write_status("error", {"error": str(exc)})
        except Exception:
            pass


async def _auto_update_schedule_loop():
    """Scheduled loop that fires the appliance update at the configured hour/days."""
    await asyncio.sleep(60)  # startup grace period
    last_run_date = None
    while True:
        try:
            if _is_appliance():
                db = SessionLocal()
                try:
                    def _s(key, default=""):
                        row = db.get(Setting, key)
                        return row.value if row else default
                    enabled = _s("auto_update_enabled", "false") == "true"
                    hour    = int(_s("auto_update_hour", "3"))
                    days_raw = _s("auto_update_days", "[]")
                    try:
                        days = json.loads(days_raw)
                    except Exception:
                        days = []
                finally:
                    db.close()

                if enabled:
                    now      = datetime.now(timezone.utc)
                    today    = now.weekday()  # 0=Mon…6=Sun (Python convention)
                    # Convert Python weekday (0=Mon) to JS/cron dow (0=Sun…6=Sat)
                    js_dow   = (today + 1) % 7
                    right_hour   = now.hour == hour
                    right_day    = not days or js_dow in days
                    already_ran  = last_run_date == now.date()
                    if right_hour and right_day and not already_ran and not _auto_update_running:
                        last_run_date = now.date()
                        asyncio.ensure_future(_run_appliance_update_task())
        except Exception as exc:
            print(f"[auto-update-scheduler] error: {exc}", flush=True)
        await asyncio.sleep(300)  # check every 5 minutes


@app.on_event("startup")
async def on_startup():
    global _main_loop
    _main_loop = asyncio.get_event_loop()
    db = SessionLocal()
    try:
        _migrate(db)
        _seed_settings(db)
        _seed_default_user(db)
        _migrate_legacy_docker_host(db)
        try:
            _migrate_legacy_notifications(db)
        except Exception as exc:
            print(f"[startup] notifications migration failed (non-fatal): {exc}", flush=True)
            db.rollback()
        _migrate_legacy_ha_mqtt(db)
        _plugin_registry.load_all(db)
        _ha_startup_connect(db)
    except Exception as exc:
        print(f"[startup] CRITICAL startup error: {exc}", flush=True)
    finally:
        db.close()
    asyncio.ensure_future(_scheduled_vuln_scan_loop())
    asyncio.ensure_future(_notification_loop())
    asyncio.ensure_future(_sse_event_watcher())
    asyncio.ensure_future(_block_schedule_loop())
    asyncio.ensure_future(_traffic_flush_loop())
    asyncio.ensure_future(_speedtest_schedule_loop())
    asyncio.ensure_future(_trivy_db_update_loop())
    asyncio.ensure_future(_docker_event_loop())
    asyncio.ensure_future(_fingerbank_loop())
    asyncio.ensure_future(_plugin_scheduler.run())
    asyncio.ensure_future(_auto_update_schedule_loop())
    _cu.init(
        session_local        = SessionLocal,
        get_enabled_hosts    = _get_enabled_hosts,
        make_docker_client   = _make_docker_client,
        fmt_container        = _fmt_container,
        add_host_meta        = _add_docker_host_meta,
        gen_compose_yaml     = _generate_compose_yaml,
        parse_proxmox_id     = _parse_proxmox_id,
        notification_dispatch = _notification_dispatch,
        main_loop_getter     = lambda: _main_loop,
    )
    asyncio.ensure_future(_cu.container_update_check_loop())


@app.get("/events/stream")
async def events_stream(request: Request):
    """
    Server-Sent Events stream for live UI updates.  The browser opens one
    EventSource per tab; the backend pushes named events ('devices', 'persons',
    'schedules', 'persons'…) whenever the underlying data changes, so pages
    refresh on real changes instead of polling on a timer.  A periodic heartbeat
    keeps the connection (and any proxies) alive.
    """
    queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    _sse_clients.add(queue)

    async def _gen():
        try:
            # Tell the client we're live so it can do an initial load.
            yield "event: ready\ndata: {}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=15.0)
                except asyncio.TimeoutError:
                    # Heartbeat comment — ignored by EventSource, keeps proxy open.
                    yield ": ping\n\n"
                    continue
                try:
                    data = json.dumps(msg.get("data", {}))
                except Exception:
                    data = "{}"
                yield f"event: {msg.get('event', 'message')}\ndata: {data}\n\n"
        finally:
            _sse_clients.discard(queue)

    return StreamingResponse(
        _gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class ContainerHostCreate(BaseModel):
    name:       str
    type:       str = "docker_local"   # docker_local | docker_remote | proxmox
    url:        Optional[str] = None
    auth_user:  Optional[str] = None
    auth_token: Optional[str] = None
    tls_verify: bool = False
    enabled:    bool = True
    node:       str  = "pve"
    local_ip:   Optional[str] = None

class ContainerHostUpdate(BaseModel):
    name:       Optional[str]  = None
    type:       Optional[str]  = None
    url:        Optional[str]  = None
    auth_user:  Optional[str]  = None
    auth_token: Optional[str]  = None
    tls_verify: Optional[bool] = None
    enabled:    Optional[bool] = None
    node:       Optional[str]  = None
    local_ip:   Optional[str]  = None

class DeviceUpdate(BaseModel):
    custom_name: Optional[str] = None
    hostname:    Optional[str] = None

class SettingUpdate(BaseModel):
    value: str

class PluginConfigSave(BaseModel):
    config: dict
    
class IdentityUpdate(BaseModel):
    vendor_override:      Optional[str] = None
    device_type_override: Optional[str] = None


class MetadataUpdate(BaseModel):
    notes:        Optional[str]  = None
    tags:         Optional[str]  = None
    location:     Optional[str]  = None
    is_important: Optional[bool] = None
    zone:         Optional[str]  = None
    is_ignored:   Optional[bool] = None
    suppress_presence_events: Optional[bool] = None
    person_id:    Optional[str]  = None   # UUID string or empty string to unassign


class PrimaryIPUpdate(BaseModel):
    ip_address: str

class BlockScheduleCreate(BaseModel):
    mac_address:   Optional[str]      = None
    mac_addresses: List[str]          = []
    tags:          str                = ""
    label:         Optional[str]      = None
    days_of_week:  str                = "mon,tue,wed,thu,fri,sat,sun"
    start_time:    str
    end_time:      str
    enabled:       bool               = True
    person_id:     Optional[str]      = None
    person_ids:    List[str]          = []

class BlockScheduleUpdate(BaseModel):
    label:         Optional[str]       = None
    days_of_week:  Optional[str]       = None
    start_time:    Optional[str]       = None
    end_time:      Optional[str]       = None
    enabled:       Optional[bool]      = None
    mac_addresses: Optional[List[str]] = None
    tags:          Optional[str]       = None
    person_id:     Optional[str]       = None   # UUID string or empty string to clear
    person_ids:    Optional[List[str]] = None

class LoginRequest(BaseModel):
    username: str
    password: str
    remember_me: bool = False

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class SetupUserRequest(BaseModel):
    username: str
    password: str

class SetupNetworkRequest(BaseModel):
    ip_range:    Optional[str] = None
    dns_server:  Optional[str] = None
    gateway:     Optional[str] = None

class SetupCompleteRequest(BaseModel):
    vuln_scan_enabled:    bool   = False
    vuln_scan_schedule:   str    = "disabled"
    vuln_scan_on_new:     bool   = False
    notifications_enabled: bool  = True
    ntfy_topic:           str    = ""
    ntfy_url:             str    = "https://ntfy.sh"
    gotify_url:           str    = ""
    gotify_token:         str    = ""
    pushbullet_api_key:   str    = ""
    alert_webhook_url:    str    = ""
    docker_enabled:       bool   = False
    docker_host:          str    = "unix:///var/run/docker.sock"
    fingerbank_api_key:   str    = ""
    # Appliance-only fields (ignored on non-appliance builds)
    timezone:             str    = "UTC"
    auto_update_enabled:  bool   = False
    auto_update_hour:     int    = 3
    auto_update_days:     list   = []


# ---------------------------------------------------------------------------
# Hostname resolution helpers
# ---------------------------------------------------------------------------
def _strip_fqdn(name: str) -> str:
    return name.rstrip('.') if name else ''


def _resolve_hostname(ip: str) -> str | None:
    try:
        result = socket.gethostbyaddr(ip)
        candidate = _strip_fqdn(result[0])
        if candidate and candidate != ip:
            return candidate
    except Exception:
        pass
    try:
        out = subprocess.run(["avahi-resolve", "-a", ip], capture_output=True, text=True, timeout=3)
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                candidate = _strip_fqdn(parts[1])
                if candidate and candidate != ip:
                    return candidate
    except Exception:
        pass
    try:
        out = subprocess.run(["nmblookup", "-A", ip], capture_output=True, text=True, timeout=4)
        for line in out.stdout.splitlines():
            if '<00>' in line and '<GROUP>' not in line:
                parts = line.strip().split()
                if parts:
                    candidate = parts[0].strip()
                    if candidate and candidate not in ('WORKGROUP', ip, 'Looking'):
                        return candidate
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Identity scoring & device type inference
# ---------------------------------------------------------------------------
def _identity_score(d: Device) -> dict:
    score   = 0
    reasons = []
    vendor = getattr(d, 'vendor_override', None) or d.vendor
    if vendor and vendor.lower() not in ("unknown", ""):
        score += 20; reasons.append("vendor_known")
    if d.hostname:
        score += 20; reasons.append("hostname_known")
    if d.custom_name:
        score += 10; reasons.append("named_by_user")
    if d.deep_scanned:
        score += 20; reasons.append("deep_scanned")
    scan  = d.scan_results or {}
    ports = scan.get("open_ports") or []
    if ports:
        score += 15; reasons.append("ports_identified")
    if scan.get("os_matches"):
        score += 15; reasons.append("os_identified")
    if getattr(d, 'dhcp_vendor_class', None) or getattr(d, 'dhcp_fingerprint', None):
        score += 10; reasons.append("dhcp_fingerprinted")
    fb = getattr(d, 'fingerbank_result', None)
    if fb and (fb.get('score') or 0) >= 50:
        score += 15; reasons.append("fingerbank_identified")
    return {"score": min(score, 100), "reasons": reasons}


def _infer_device_type(d: Device) -> str | None:
    if getattr(d, 'device_type_override', None):
        return d.device_type_override
    # Fingerbank result is the most authoritative signal when confidence >= 50
    fb = getattr(d, 'fingerbank_result', None)
    if fb and not fb.get('error') and (fb.get('score') or 0) >= 50 and fb.get('mapped_type'):
        return fb['mapped_type']
    # DHCP-inferred type from probe's local classifier
    scan     = d.scan_results or {}
    dhcp_type = scan.get("device_type")
    if dhcp_type and scan.get("device_type_source") == "dhcp":
        return dhcp_type
    # Local heuristics — combine DNS hostname, DHCP hostname, DHCP vendor class, OUI vendor
    hostname = (d.hostname or d.custom_name or "").lower()
    dhcp_hn  = (getattr(d, 'dhcp_hostname',     None) or "").lower()
    dhcp_vc  = (getattr(d, 'dhcp_vendor_class', None) or "").lower()
    vendor   = (getattr(d, 'vendor_override',   None) or d.vendor or "").lower()
    combined = f"{hostname} {dhcp_hn} {dhcp_vc} {vendor}"
    ports    = {p.get("port") for p in (scan.get("open_ports") or []) if p.get("port")}
    os_guess = (scan.get("os_matches") or [{}])[0].get("name", "").lower() if scan.get("os_matches") else ""
    if any(k in combined for k in ("cam", "camera", "nvr", "reolink", "dahua", "hikvision", "arlo", "ring", "nest-cam")):
        return "camera"
    if any(k in combined for k in ("iphone", "ipad", "android", "pixel", "galaxy", "oneplus", "xiaomi", "redmi")):
        return "phone"
    if "android" in os_guess or "ios" in os_guess:
        return "phone"
    if any(k in combined for k in ("shelly", "tasmota", "sonoff", "gosund", "esphome")):
        return "iot"
    if any(k in combined for k in ("espressif", "tuya", "meross", "bouffalo")):
        return "iot"
    if any(k in combined for k in ("access point", "wireless ap", "unifi", "ubnt", "airos")):
        return "ap"
    if any(k in combined for k in ("router", "gateway", "openwrt", "dd-wrt", "pfsense", "opnsense")):
        return "router"
    if any(k in vendor for k in ("ubiquiti", "tp-link", "netgear", "asus", "linksys")) and {80, 443, 22} & ports:
        return "router"
    if any(k in combined for k in ("nas", "synology", "qnap", "truenas", "openmediavault")):
        return "nas"
    if {445, 139, 2049} & ports:
        return "nas"
    if any(k in combined for k in ("printer", "jetdirect")):
        return "printer"
    if {9100, 515, 631} & ports:
        return "printer"
    if any(k in combined for k in ("roku", "firetv", "fire tv", "chromecast", "appletv", "apple tv")):
        return "streamer"
    if any(k in combined for k in ("smart tv", "androidtv", "android tv", "google tv")):
        return "tv"
    if any(k in combined for k in ("playstation", "xbox", "nintendo")):
        return "console"
    if any(k in vendor for k in ("sony interactive", "microsoft xbox")):
        return "console"
    if "windows" in os_guess or {3389} & ports:
        return "desktop"
    if "linux" in os_guess and {22} & ports and len(ports) > 3:
        return "server"
    return None


_GENERIC_BRAND = re.compile(
    r'^(Generic|Unknown|Internet of Things|Phone|Tablet|Mobile|Android|'
    r'Windows|Linux|IoT|Smart Home|Network|Networking|Wireless)',
    re.I,
)

def _infer_vendor(d: Device) -> str | None:
    """Return vendor name, falling back to Fingerbank hierarchy when OUI lookup is empty."""
    if getattr(d, 'vendor_override', None):
        return d.vendor_override
    if d.vendor and d.vendor.lower() not in ('unknown', ''):
        return d.vendor
    fb = getattr(d, 'fingerbank_result', None) or {}
    if fb.get('error'):
        return None
    for p in (fb.get('parents') or []):
        if p and not _GENERIC_BRAND.match(p):
            tok = p.split()[0]  # "OnePlus Android" → "OnePlus", "TP-Link TL-SG108E" → "TP-Link"
            if tok and len(tok) > 2:
                return tok
    dn = (fb.get('device_name') or '').strip()
    if dn:
        tok = dn.split()[0]
        if tok and len(tok) > 2:
            return tok
    return None


# ---------------------------------------------------------------------------
# _to_dict
# ---------------------------------------------------------------------------
def _to_dict(d: Device) -> dict:
    id_score = _identity_score(d)
    inferred = _infer_device_type(d)
    return {
        "mac_address":          d.mac_address,
        "ip_address":           d.ip_address,
        "primary_ip":           getattr(d, "primary_ip", None) or d.ip_address,
        "hostname":             d.hostname,
        "vendor":               d.vendor,
        "vendor_override":      getattr(d, 'vendor_override', None),
        "vendor_inferred":      _infer_vendor(d),
        "device_type_override": getattr(d, 'device_type_override', None),
        "custom_name":          d.custom_name,
        "is_online":            d.is_online,
        "deep_scanned":         d.deep_scanned,
        "miss_count":           getattr(d, 'miss_count', 0),
        "is_important":         bool(getattr(d, 'is_important', False)),
        "notes":                getattr(d, 'notes', None),
        "tags":                 getattr(d, 'tags', None),
        "location":             getattr(d, 'location', None),
        "first_seen":           d.first_seen.isoformat()  if d.first_seen  else None,
        "last_seen":            d.last_seen.isoformat()   if d.last_seen   else None,
        "status_changed_at":    d.status_changed_at.isoformat() if getattr(d, 'status_changed_at', None) else None,
        "scan_results":         d.scan_results,
        "services":             (d.scan_results or {}).get("services"),
        "pipeline_stage":       (d.scan_results or {}).get("pipeline_stage"),
        "display_name":         d.custom_name or d.hostname or d.ip_address,
        "identity_score":       id_score["score"],
        "identity_reasons":     id_score["reasons"],
        "device_type":          getattr(d, 'device_type_override', None) or inferred,
        "device_type_inferred": inferred,
        "vuln_last_scanned": d.vuln_last_scanned.isoformat() if d.vuln_last_scanned else None,
        "vuln_severity":     d.vuln_severity,
        "deep_scan_last_run":    d.deep_scan_last_run.isoformat() if getattr(d, 'deep_scan_last_run', None) else None,
        "baseline_ports":        getattr(d, 'baseline_ports', None),
        "baseline_scan_count":   getattr(d, 'baseline_scan_count', 0) or 0,
        "is_blocked":            bool(getattr(d, 'is_blocked', False)),
        "zone":                  getattr(d, 'zone', None),
        "is_ignored":            bool(getattr(d, 'is_ignored', False)),
        "suppress_presence_events": bool(getattr(d, 'suppress_presence_events', False)),
        "primary_ip_locked":     bool(getattr(d, 'primary_ip_locked', False)),
        "dhcp_hostname":         getattr(d, 'dhcp_hostname', None),
        "dhcp_vendor_class":     getattr(d, 'dhcp_vendor_class', None),
        "dhcp_fingerprint":      getattr(d, 'dhcp_fingerprint', None),
        "fingerbank_result":     getattr(d, 'fingerbank_result', None),
        # Populated by list_devices; single-device endpoints return defaults
        "is_virtual_interface":  False,
        "virtual_of":            None,
        "secondary_ips":         [],
        "group_id":                str(getattr(d, "group_id", None)) if getattr(d, "group_id", None) else None,
        "group_primary":           bool(getattr(d, "group_primary", False)),
        "group_members":           [],
        "group_size":              1,
        "is_group_representative": False,
        "is_acknowledged":         bool(getattr(d, "is_acknowledged", False)),
        "person_id":               str(getattr(d, "person_id", None)) if getattr(d, "person_id", None) else None,
        "person_name":             None,  # populated by list_devices
    }


# ---------------------------------------------------------------------------
# Fingerprint helpers
# ---------------------------------------------------------------------------
def _oui(mac: str) -> str:
    return mac.replace(':', '').replace('-', '').lower()[:6]


def _match_fingerprints(device: Device, fingerprints: list[FingerprintEntry]) -> FingerprintEntry | None:
    device_oui   = _oui(device.mac_address)
    device_ports = set()
    if device.scan_results:
        device_ports = {p.get('port') for p in (device.scan_results.get('open_ports') or []) if p.get('port')}
    best_score = 0
    best_fp    = None
    for fp in fingerprints:
        score = 0
        if fp.oui_prefix and fp.oui_prefix.lower() == device_oui:
            score += 3
        if fp.open_ports:
            score += len(device_ports & set(fp.open_ports))
        if score > best_score or (
            score == best_score and score > 0 and best_fp is not None and
            (fp.confidence_score, fp.hit_count) > (best_fp.confidence_score, best_fp.hit_count)
        ):
            if score > 0:
                best_score = score
                best_fp    = fp
    return best_fp


def _upsert_manual_fingerprint(db: Session, device: Device, vendor_name: Optional[str], device_type: Optional[str]):
    oui = _oui(device.mac_address) if device.mac_address else None
    open_ports = None
    if device.scan_results:
        ports = [p.get('port') for p in (device.scan_results.get('open_ports') or []) if p.get('port')]
        open_ports = ports if ports else None
    effective_type   = (device_type   or "").strip() or None
    effective_vendor = (vendor_name   or "").strip() or None
    existing = None
    if oui:
        q = db.query(FingerprintEntry).filter(
            FingerprintEntry.oui_prefix == oui,
            FingerprintEntry.source == 'manual',
        )
        if effective_type:
            q = q.filter(FingerprintEntry.device_type == effective_type)
        existing = q.first()
    if existing:
        if effective_vendor: existing.vendor_name = effective_vendor
        if effective_type:   existing.device_type = effective_type
        if open_ports:       existing.open_ports  = open_ports
        existing.hit_count        += 1
        existing.confidence_score  = 1.0
    else:
        db.add(FingerprintEntry(
            oui_prefix=oui, hostname_pattern=None, open_ports=open_ports,
            device_type=effective_type or "unknown", vendor_name=effective_vendor,
            confidence_score=1.0, hit_count=1, source='manual',
        ))


# ---------------------------------------------------------------------------
# Event helper
# ---------------------------------------------------------------------------
def _add_event(db: Session, mac: str, event_type: str, detail: dict = None):
    try:
        db.add(DeviceEvent(mac_address=mac, type=event_type, detail=detail))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Routes — root
# ---------------------------------------------------------------------------
@app.get("/")
def root():
    return {"message": "InSpectre API", "version": VERSION}


# ---------------------------------------------------------------------------
# Health check — no auth required
# ---------------------------------------------------------------------------
@app.get("/health")
async def health_check(db: Session = Depends(get_db)):
    """Return connectivity status of all platform components."""
    result = {
        "backend": {"ok": True, "message": "Running"},
        "database": {"ok": False, "message": ""},
        "probe":    {"ok": False, "message": ""},
        "setup_complete": False,
        "active_scans": {"port": [], "vuln": []},
    }

    def _resolve_device_name(mac: str) -> str:
        try:
            row = db.execute(
                text("SELECT custom_name, hostname, ip_address FROM devices WHERE LOWER(mac_address) = :m"),
                {"m": mac.lower()}
            ).fetchone()
            if row:
                return row[0] or row[1] or row[2] or mac
        except Exception:
            pass
        return mac

    # Check database
    try:
        row = db.execute(text("SELECT COUNT(*) FROM devices")).scalar()
        result["database"] = {"ok": True, "message": f"{row} devices in DB"}
    except Exception as e:
        result["database"] = {"ok": False, "message": str(e)[:120]}

    # Check probe
    try:
        async with _probe_client(timeout=5.0) as client:
            resp = await client.get(f"{PROBE_URL}/health")
            if resp.status_code == 200:
                probe_data = resp.json()
                result["probe"] = {"ok": True, "message": probe_data.get("message", "Running")}
                for mac in probe_data.get("active_port_scans", []):
                    result["active_scans"]["port"].append({"mac": mac, "name": _resolve_device_name(mac)})
            else:
                result["probe"] = {"ok": False, "message": f"HTTP {resp.status_code}"}
    except httpx.ConnectError:
        result["probe"] = {"ok": False, "message": f"Cannot reach probe at {PROBE_URL}"}
    except Exception as e:
        result["probe"] = {"ok": False, "message": str(e)[:120]}

    # Active vuln scans (tracked by backend)
    for mac in list(_nuclei_subs.keys()):
        result["active_scans"]["vuln"].append({"mac": mac, "name": _resolve_device_name(mac)})

    # Check setup complete
    try:
        s = db.get(Setting, "setup_complete")
        result["setup_complete"] = (s.value if s else "false") == "true"
    except Exception:
        pass

    result["all_ok"] = all(v["ok"] for v in [result["backend"], result["database"], result["probe"]])
    return result


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------
@app.post("/auth/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    row = db.execute(
        text("SELECT username, password_hash, must_change_password FROM users WHERE username = :u"),
        {"u": payload.username}
    ).fetchone()
    if not row or not _verify_password(payload.password, row[1]):
        raise HTTPException(401, "Invalid username or password")
    db.execute(
        text("UPDATE users SET last_login = NOW() WHERE username = :u"),
        {"u": payload.username}
    )
    db.commit()
    token = _create_token(
        payload.username,
        TOKEN_EXPIRE_REMEMBER if payload.remember_me else TOKEN_EXPIRE_DEFAULT,
    )
    return {"token": token, "username": payload.username, "must_change_password": bool(row[2])}


@app.get("/auth/me")
def auth_me(username: str = Depends(get_current_user), db: Session = Depends(get_db)):
    row = db.execute(
        text("SELECT must_change_password FROM users WHERE username = :u"), {"u": username}
    ).fetchone()
    must_change = bool(row[0]) if row else False
    return {"username": username, "authenticated": True, "must_change_password": must_change}


@app.post("/auth/change-password")
def change_password(
    payload: ChangePasswordRequest,
    username: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    row = db.execute(
        text("SELECT password_hash FROM users WHERE username = :u"), {"u": username}
    ).fetchone()
    if not row or not _verify_password(payload.current_password, row[0]):
        raise HTTPException(401, "Current password is incorrect")
    if len(payload.new_password) < 8:
        raise HTTPException(400, "New password must be at least 8 characters")
    new_hash = _hash_password(payload.new_password)
    db.execute(
        text("UPDATE users SET password_hash = :h, must_change_password = FALSE WHERE username = :u"),
        {"h": new_hash, "u": username}
    )
    db.commit()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Appliance / system info routes
# ---------------------------------------------------------------------------

_APPLIANCE_JSON_PATH = "/opt/inspectre/appliance.json"
_auto_update_running = False


def _is_appliance() -> bool:
    return os.path.exists(_APPLIANCE_JSON_PATH)


def _read_appliance_meta() -> dict:
    try:
        with open(_APPLIANCE_JSON_PATH) as f:
            return json.loads(f.read())
    except Exception:
        return {}


@app.get("/system/info")
def get_system_info(db: Session = Depends(get_db), username: str = Depends(get_current_user)):
    """Return appliance metadata and auto-update configuration."""
    def _s(key, default=""):
        row = db.get(Setting, key)
        return row.value if row else default

    is_appl = _is_appliance()
    meta    = _read_appliance_meta() if is_appl else {}

    days_raw = _s("auto_update_days", "[]")
    try:
        days = json.loads(days_raw)
    except Exception:
        days = []

    return {
        "is_appliance":   is_appl,
        "appliance_type": meta.get("type"),
        "timezone":       _s("timezone", "UTC"),
        "auto_update": {
            "enabled": _s("auto_update_enabled", "false") == "true",
            "hour":    int(_s("auto_update_hour", "3")),
            "days":    days,
            "updater": {
                "last_run":    _s("auto_update_last_run") or None,
                "last_status": _s("auto_update_last_status") or None,
                "running":     _auto_update_running,
                "last_logs":   _s("auto_update_last_detail") or None,
            },
        },
    }


class AutoUpdateRequest(BaseModel):
    enabled: bool
    hour:    int  = 3
    days:    list = []


@app.post("/system/auto-update")
def set_auto_update(
    payload:  AutoUpdateRequest,
    username: str     = Depends(get_current_user),
    db:       Session = Depends(get_db),
):
    """Save auto-update schedule settings."""
    to_save = {
        "auto_update_enabled": "true" if payload.enabled else "false",
        "auto_update_hour":    str(max(0, min(23, payload.hour))),
        "auto_update_days":    json.dumps(payload.days),
    }
    for key, value in to_save.items():
        s = db.get(Setting, key)
        if s:
            s.value = value
        else:
            db.add(Setting(key=key, value=value))
    db.commit()
    return {"ok": True}


@app.post("/system/auto-update/run")
async def run_auto_update_now(username: str = Depends(get_current_user)):
    """Trigger an immediate appliance update (appliance builds only)."""
    if not _is_appliance():
        raise HTTPException(403, "Not an appliance build")
    asyncio.ensure_future(_run_appliance_update_task())
    return {"ok": True, "message": "Update triggered"}


# ---------------------------------------------------------------------------
# Setup wizard routes (no auth required — only usable before setup is done)
# ---------------------------------------------------------------------------
@app.get("/setup/status")
def setup_status(db: Session = Depends(get_db)):
    """Returns whether setup is complete and whether any users exist."""
    has_user = _has_any_user(db)
    s = db.get(Setting, "setup_complete")
    setup_done = (s.value if s else "false") == "true"
    # Auto-heal: a user already exists but setup_complete was never set to true.
    # This happens when restoring a DB or if the wizard flow was interrupted.
    if has_user and not setup_done:
        if s:
            s.value = "true"
        else:
            db.add(Setting(key="setup_complete", value="true",
                           description="Whether the initial setup wizard has been completed."))
        db.commit()
        setup_done = True
    is_appliance = os.path.exists("/opt/inspectre/appliance.json")
    return {"setup_complete": setup_done, "has_user": has_user, "is_appliance": is_appliance}


@app.post("/setup/create-user")
def setup_create_user(payload: SetupUserRequest, db: Session = Depends(get_db)):
    """Create the first admin user. Only works if no users exist yet."""
    if _has_any_user(db):
        raise HTTPException(403, "Setup already completed — users exist")
    if len(payload.username.strip()) < 3:
        raise HTTPException(400, "Username must be at least 3 characters")
    if len(payload.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    pw_hash = _hash_password(payload.password)
    try:
        db.execute(
            text("INSERT INTO users (username, password_hash, is_admin) VALUES (:u, :h, TRUE)"),
            {"u": payload.username.strip().lower(), "h": pw_hash}
        )
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"Could not create user: {e}")
    token = _create_token(payload.username.strip().lower())
    return {"ok": True, "token": token, "username": payload.username.strip().lower()}


@app.get("/setup/network-info")
async def setup_network_info():
    """Proxy network detection to the probe — it runs on the host network so its
    interface/route/IP info reflects the real LAN, not the Docker bridge."""
    try:
        async with _probe_client(timeout=5.0) as client:
            r = await client.get(f"{PROBE_URL}/network/info")
            r.raise_for_status()
            return r.json()
    except Exception:
        # Probe unreachable — return empty values; user can fill in manually
        return {"ip_range": None, "gateway": None, "dns_server": None, "interface": None}


@app.post("/setup/apply-network")
def setup_apply_network(payload: SetupNetworkRequest, db: Session = Depends(get_db)):
    """Save network settings confirmed in the wizard."""
    updates: dict[str, str] = {}
    if payload.ip_range:
        updates["ip_range"] = payload.ip_range
    if payload.dns_server:
        updates["dns_server"] = payload.dns_server  # stored for reference
    for key, value in updates.items():
        s = db.get(Setting, key)
        if s:
            s.value = value
        else:
            db.add(Setting(key=key, value=value))
    db.commit()
    return {"ok": True, "applied": updates}


@app.post("/setup/complete")
def setup_complete(
    payload: SetupCompleteRequest,
    username: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Finalise setup: apply notification/vuln settings and mark setup complete."""
    to_save = {
        "setup_complete":            "true",
        "notifications_enabled":     "true" if payload.notifications_enabled else "false",
        "vuln_scan_on_new_device":   "true" if payload.vuln_scan_on_new else "false",
        "vuln_scan_schedule":        payload.vuln_scan_schedule if payload.vuln_scan_enabled else "disabled",
        "docker_enabled":            "true" if payload.docker_enabled else "false",
    }
    if payload.ntfy_topic:
        to_save["ntfy_topic"] = payload.ntfy_topic
    if payload.ntfy_url:
        to_save["ntfy_url"] = payload.ntfy_url
    if payload.docker_host:
        to_save["docker_host"] = payload.docker_host
    if payload.fingerbank_api_key:
        to_save["fingerbank_api_key"] = payload.fingerbank_api_key
    if os.path.exists("/opt/inspectre/appliance.json"):
        to_save["timezone"]            = payload.timezone or "UTC"
        to_save["auto_update_enabled"] = "true" if payload.auto_update_enabled else "false"
        to_save["auto_update_hour"]    = str(max(0, min(23, payload.auto_update_hour)))
        to_save["auto_update_days"]    = json.dumps(payload.auto_update_days)
    for key, value in to_save.items():
        s = db.get(Setting, key)
        if s:
            s.value = value
        else:
            db.add(Setting(key=key, value=value))
    db.commit()

    # Write notification channel directly to notification_channels so it appears
    # in the Notifications settings panel immediately without requiring a restart.
    # Build list of (service, display_name, config_dict) tuples from wizard input.
    new_channels = []
    if payload.ntfy_topic.strip():
        new_channels.append(("ntfy", "ntfy", {
            "server": (payload.ntfy_url or "https://ntfy.sh").strip(),
            "topic":  payload.ntfy_topic.strip(),
        }))
    if payload.gotify_url.strip() and payload.gotify_token.strip():
        new_channels.append(("gotify", "Gotify", {
            "server": payload.gotify_url.strip(),
            "token":  payload.gotify_token.strip(),
        }))
    if payload.pushbullet_api_key.strip():
        new_channels.append(("pushbullet", "Pushbullet", {
            "api_key": payload.pushbullet_api_key.strip(),
        }))
    if payload.alert_webhook_url.strip():
        new_channels.append(("webhook", "Webhook", {
            "url": payload.alert_webhook_url.strip(),
        }))

    for svc, name, cfg in new_channels:
        # Replace any existing channel of the same service type so re-running
        # the wizard doesn't create duplicates.
        db.execute(text("DELETE FROM notification_channels WHERE service = :s"), {"s": svc})
        db.execute(
            text("INSERT INTO notification_channels (name, service, config, enabled) VALUES (:n, :s, :c, true)"),
            {"n": name, "s": svc, "c": json.dumps(cfg)},
        )
    if new_channels:
        db.commit()

    return {"ok": True, "setup_complete": True}


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------
def _is_locally_admin_mac(mac: str) -> bool:
    """Return True if MAC has the locally-administered bit set (e.g. macvlan, VMs, containers)."""
    try:
        return bool(int(mac.split(':')[0], 16) & 0x02)
    except Exception:
        return False


@app.get("/devices/meta/zones")
def get_device_zones(db: Session = Depends(get_db)):
    try:
        rows = db.execute(
            text("SELECT DISTINCT zone FROM devices WHERE zone IS NOT NULL ORDER BY zone")
        ).fetchall()
        return [r[0] for r in rows]
    except Exception:
        return []


@app.get("/devices")
def list_devices(
    online_only: bool = False,
    include_ignored: bool = True,
    vendor: Optional[str] = None,
    hostname: Optional[str] = None,
    zone: Optional[str] = None,
    has_vulns: Optional[bool] = None,
    severity: Optional[str] = None,
    port: Optional[int] = None,
    is_important: Optional[bool] = None,
    sort_by: Optional[str] = None,
    sort_dir: Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(Device)
    if online_only:
        q = q.filter(Device.is_online == True)
    if not include_ignored:
        q = q.filter(Device.is_ignored == False)
    if vendor:
        q = q.filter(Device.vendor.ilike(f"%{vendor}%"))
    if hostname:
        q = q.filter(
            (Device.hostname.ilike(f"%{hostname}%")) |
            (Device.custom_name.ilike(f"%{hostname}%"))
        )
    if zone:
        q = q.filter(Device.zone == zone)
    if has_vulns is True:
        q = q.filter(Device.vuln_severity != None, Device.vuln_severity != 'clean')
    if severity:
        q = q.filter(Device.vuln_severity == severity)
    if is_important is True:
        q = q.filter(Device.is_important == True)
    if port is not None:
        q = q.filter(text(f"scan_results->'open_ports' @> '[{{\"port\": {int(port)}}}]'::jsonb"))

    valid_sorts = {"last_seen", "first_seen", "hostname", "ip_address"}
    sort_col = sort_by if sort_by in valid_sorts else "last_seen"
    col_map = {
        "last_seen":  Device.last_seen,
        "first_seen": Device.first_seen,
        "hostname":   Device.hostname,
        "ip_address": Device.ip_address,
    }
    col = col_map.get(sort_col, Device.last_seen)
    if sort_dir == "asc":
        q = q.order_by(col.asc().nulls_last(), Device.mac_address.asc())
    else:
        q = q.order_by(col.desc().nulls_last(), Device.mac_address.asc())

    devices = q.all()

    # Identify virtual interfaces: locally-administered MACs that share one or more IPs with
    # a real (globally-administered) MAC.  This covers macvlan, container, and VM interfaces
    # that appear alongside the physical NIC at the same IP addresses.
    try:
        ip_rows = db.execute(text("SELECT mac_address, ip_address FROM ip_history")).fetchall()
    except Exception:
        ip_rows = []

    ip_to_macs: dict[str, set] = {}
    for row in ip_rows:
        if row[1]:
            ip_to_macs.setdefault(row[1], set()).add(row[0])
    # Also include current / primary IPs not yet in history
    for d in devices:
        for addr in filter(None, [d.ip_address, getattr(d, 'primary_ip', None)]):
            ip_to_macs.setdefault(addr, set()).add(d.mac_address)

    mac_set = {d.mac_address for d in devices}
    online_macs = {d.mac_address for d in devices if d.is_online}

    # Map of CURRENT IPs (current/primary IP only, not full history) → MACs.
    # Virtual interfaces (macvlan / container / VM) share the *current* IP with
    # the physical NIC concurrently. We deliberately do NOT use full ip_history
    # here: a phone using MAC randomisation has a locally-administered MAC, and
    # if its old DHCP lease IP was later reassigned to another device, a history
    # based match would wrongly flag the phone as a "virtual interface" and hide
    # it from the device list.
    current_ip_to_macs: dict[str, set] = {}
    for d in devices:
        for addr in filter(None, [d.ip_address, getattr(d, 'primary_ip', None)]):
            current_ip_to_macs.setdefault(addr, set()).add(d.mac_address)

    virtual_of: dict[str, str] = {}
    for d in devices:
        if not _is_locally_admin_mac(d.mac_address):
            continue
        my_ips = {ip for ip, macs in current_ip_to_macs.items() if d.mac_address in macs}
        for ip in my_ips:
            for other_mac in current_ip_to_macs.get(ip, set()):
                # A genuine virtual interface shares its CURRENT IP with a real
                # (globally-administered) device that is also currently online.
                if (other_mac != d.mac_address
                        and other_mac in mac_set
                        and other_mac in online_macs
                        and not _is_locally_admin_mac(other_mac)):
                    virtual_of[d.mac_address] = other_mac
                    break
            if d.mac_address in virtual_of:
                break

    # Collect active secondary IPs (multi-homed: seen while device was online at another IP)
    try:
        sec_rows = db.execute(text("""
            SELECT mac_address, ip_address
            FROM ip_history
            WHERE seen_while_online = true
              AND last_seen > NOW() - INTERVAL '7 days'
        """)).fetchall()
    except Exception:
        sec_rows = []
    secondary_ip_map: dict[str, list[str]] = {}
    for row in sec_rows:
        secondary_ip_map.setdefault(row[0], []).append(row[1])

    # Build a set of IPs "owned" by virtual interfaces for each real MAC, so those
    # IPs are excluded from the real device's secondary_ips (fixes macvlan/switch ghost IPs).
    virtual_ips_for: dict[str, set] = {}
    for v_mac, real_mac in virtual_of.items():
        for ip, macs in ip_to_macs.items():
            if v_mac in macs:
                virtual_ips_for.setdefault(real_mac, set()).add(ip)

    # Build group representative info from already-loaded devices
    group_map: dict[str, list] = {}  # group_id_str -> list[Device]
    for d in devices:
        gid = getattr(d, "group_id", None)
        if gid:
            group_map.setdefault(str(gid), []).append(d)

    group_representative: dict[str, str] = {}  # group_id_str -> mac
    group_any_online:      dict[str, bool] = {}  # group_id_str -> any member online
    for gid_str, members in group_map.items():
        online_members  = [m for m in members if m.is_online]
        primary_members = [m for m in members if getattr(m, "group_primary", False)]
        # The user-selected primary always represents the group, so its
        # name / IP / MAC are what appear in the device list. Fall back to an
        # online member, then to any member, when no primary is set.
        if primary_members:
            rep = primary_members[0].mac_address
        elif online_members:
            rep = online_members[0].mac_address
        else:
            rep = members[0].mac_address
        group_representative[gid_str] = rep
        group_any_online[gid_str]     = bool(online_members)

    hidden_macs: set = {
        m.mac_address
        for gid_str, members in group_map.items()
        for m in members
        if m.mac_address != group_representative.get(gid_str)
    }

    # Build person name lookup
    try:
        person_rows = db.execute(text("SELECT id::text, name FROM persons")).fetchall()
        person_name_map = {r[0]: r[1] for r in person_rows}
    except Exception:
        person_name_map = {}

    result = []
    for d in devices:
        if d.mac_address in hidden_macs:
            continue
        dct = _to_dict(d)
        dct['is_virtual_interface'] = d.mac_address in virtual_of
        dct['virtual_of']           = virtual_of.get(d.mac_address)
        primary   = dct.get('primary_ip') or d.ip_address
        excl_virt = virtual_ips_for.get(d.mac_address, set())
        dct['secondary_ips'] = [
            ip for ip in secondary_ip_map.get(d.mac_address, [])
            if ip != primary and ip not in excl_virt
        ]
        gid = getattr(d, "group_id", None)
        if gid:
            gid_str = str(gid)
            members = group_map.get(gid_str, [])
            dct["group_members"] = [
                {
                    "mac_address":   m.mac_address,
                    "group_primary": bool(getattr(m, "group_primary", False)),
                    "is_online":     m.is_online,
                    "display_name":  m.custom_name or m.hostname or m.ip_address,
                    "ip_address":    m.ip_address,
                }
                for m in members
            ]
            dct["group_size"]              = len(members)
            dct["is_group_representative"] = True
            # A grouped device is one physical host on multiple interfaces, so it
            # is "online" whenever ANY member interface is up — this prevents the
            # representative flapping offline when the host switches interfaces.
            dct["is_online"] = group_any_online.get(gid_str, dct.get("is_online"))
        pid = dct.get("person_id")
        if pid:
            dct["person_name"] = person_name_map.get(pid)
        result.append(dct)
    return result


@app.get("/devices/ip-management")
def get_ip_management(db: Session = Depends(get_db)):
    devices = db.query(Device).order_by(Device.last_seen.desc()).all()
    history_rows = db.execute(
        text("SELECT mac_address, ip_address, first_seen, last_seen, seen_while_online FROM ip_history ORDER BY mac_address, last_seen DESC")
    ).fetchall()
    ip_map: dict = {}
    for r in history_rows:
        ip_map.setdefault(r[0], []).append({
            "ip":              r[1],
            "first_seen":      r[2].isoformat() if r[2] else None,
            "last_seen":       r[3].isoformat() if r[3] else None,
            "seen_while_online": bool(r[4]),
        })
    result = []
    for d in devices:
        dct = _to_dict(d)
        dct["effective_ip"] = getattr(d, "primary_ip", None) or d.ip_address
        dct["ips"] = ip_map.get(d.mac_address, [])
        result.append(dct)
    return result


@app.get("/devices/{mac}")
def get_device(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    result = _to_dict(d)
    if d.group_id:
        try:
            rows = db.execute(
                text("""
                    SELECT mac_address, hostname, custom_name, ip_address, is_online, group_primary
                    FROM devices WHERE group_id = :gid
                """),
                {"gid": d.group_id},
            ).fetchall()
            result["group_members"] = [
                {
                    "mac_address":   r[0],
                    "group_primary": bool(r[5]),
                    "is_online":     bool(r[4]),
                    "display_name":  r[2] or r[1] or r[3] or r[0],
                    "ip_address":    r[3],
                }
                for r in rows
            ]
            result["group_size"]              = len(rows)
            result["is_group_representative"] = True
        except Exception:
            pass
    latest = (
        db.query(VulnReport)
        .filter(VulnReport.mac_address == mac.lower())
        .order_by(VulnReport.scanned_at.desc())
        .first()
    )
    result["latest_vuln_findings"] = latest.findings if latest else []
    return result


@app.patch("/devices/{mac}")
def update_device(mac: str, payload: DeviceUpdate, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    old_name = d.custom_name
    if payload.custom_name is not None:
        d.custom_name = payload.custom_name
    if payload.hostname is not None:
        d.hostname = payload.hostname
    if payload.custom_name is not None and payload.custom_name != old_name:
        _add_event(db, mac.lower(), 'renamed', {'old': old_name, 'new': payload.custom_name})
    db.commit(); db.refresh(d)
    return _to_dict(d)


@app.patch("/devices/{mac}/identity")
def update_identity(mac: str, payload: IdentityUpdate, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    if payload.vendor_override is not None:
        d.vendor_override = payload.vendor_override or None
    if payload.device_type_override is not None:
        d.device_type_override = payload.device_type_override or None
    _upsert_manual_fingerprint(db, device=d, vendor_name=d.vendor_override, device_type=d.device_type_override)
    db.commit(); db.refresh(d)
    return _to_dict(d)


@app.patch("/devices/{mac}/metadata")
def update_metadata(mac: str, payload: MetadataUpdate, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    if payload.notes    is not None: d.notes    = payload.notes    or None
    if payload.tags     is not None: d.tags     = payload.tags     or None
    if payload.location is not None: d.location = payload.location or None
    if payload.zone     is not None: d.zone     = payload.zone     or None
    if payload.is_important is not None:
        old_imp = bool(getattr(d, 'is_important', False))
        d.is_important = payload.is_important
        if payload.is_important != old_imp:
            _add_event(db, mac.lower(), 'marked_important', {'important': payload.is_important})
    if payload.tags is not None:
        _add_event(db, mac.lower(), 'tagged', {'tags': payload.tags})
    if payload.is_ignored is not None:
        d.is_ignored = payload.is_ignored
    if payload.suppress_presence_events is not None:
        d.suppress_presence_events = payload.suppress_presence_events
    if payload.person_id is not None:
        d.person_id = payload.person_id or None  # empty string → unassign
    db.commit(); db.refresh(d)
    return _to_dict(d)


@app.post("/devices/{mac}/acknowledge")
def acknowledge_device(mac: str, db: Session = Depends(get_db)):
    """Mark a new device as acknowledged, removing it from the 'new' surfacing list."""
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    d.is_acknowledged = True
    db.commit()
    if _ha_mqtt.connected:
        sev_map = {"low": 1, "info": 1, "medium": 2, "high": 3, "critical": 3}
        ports = len((d.scan_results or {}).get("open_ports", [])) if d.scan_results else 0
        vulns = sev_map.get(d.vuln_severity or "", 0)
        _ha_mqtt.pub_device_state(d.mac_address, bool(d.is_online), d.ip_address, ports, vulns, is_new=False)
    return {"ok": True}


@app.post("/devices/{mac}/resolve-name")
async def resolve_name(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    ip = d.ip_address
    name = None
    if ip:
        try:
            async with _probe_client(timeout=15.0) as client:
                r = await client.get(f"{PROBE_URL}/resolve/{ip}")
                if r.status_code == 200:
                    name = r.json().get("hostname")
        except Exception:
            pass
    if name and not d.custom_name:
        d.hostname = name
        db.commit(); db.refresh(d)
    return {"mac": mac, "resolved": name, "device": _to_dict(d)}


@app.post("/devices/resolve-all-names")
async def resolve_all_names(db: Session = Depends(get_db)):
    devices = db.query(Device).filter(
        Device.is_ignored == False,
        Device.ip_address != None,
        Device.ip_address != "",
    ).all()
    updated = 0
    failed = 0
    async with _probe_client(timeout=15.0) as client:
        for d in devices:
            ip = d.ip_address
            if not ip:
                continue
            try:
                r = await client.get(f"{PROBE_URL}/resolve/{ip}")
                if r.status_code == 200:
                    name = r.json().get("hostname")
                    if name and not d.custom_name:
                        d.hostname = name
                        updated += 1
            except Exception:
                failed += 1
    db.commit()
    return {"updated": updated, "failed": failed, "total": len(devices)}


@app.post("/devices/{mac}/rescan")
async def rescan_device(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    d.deep_scanned = False
    db.commit()
    # Ask the probe to start scanning immediately rather than waiting for the next sweep
    try:
        async with _probe_client(timeout=10.0) as client:
            await client.post(f"{PROBE_URL}/rescan/{mac.lower()}")
    except Exception:
        pass  # probe will pick it up on next sweep if unreachable
    return {"mac": mac, "queued": True}


@app.post("/devices/{mac}/reset-baseline")
def reset_baseline(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    d.baseline_ports      = None
    d.baseline_scan_count = 0
    db.commit(); db.refresh(d)
    return _to_dict(d)


@app.post("/devices/{mac}/fingerbank/lookup")
async def fingerbank_lookup(mac: str, db: Session = Depends(get_db)):
    """Immediately trigger a Fingerbank lookup for a single device. Returns the raw result."""
    mac = mac.lower()
    device = db.get(Device, mac)
    if not device:
        raise HTTPException(404, "Device not found")
    if not device.dhcp_fingerprint:
        raise HTTPException(422, "No DHCP fingerprint captured for this device yet")
    key_row = db.get(Setting, "fingerbank_api_key")
    api_key = (key_row.value or "").strip() if key_row else ""
    if not api_key:
        raise HTTPException(422, "No Fingerbank API key configured in Settings → Scanner → Device Identification")
    result = await _fingerbank_query(
        mac, device.dhcp_fingerprint,
        device.dhcp_vendor_class, device.dhcp_hostname, api_key
    )
    device.fingerbank_result = result
    from sqlalchemy.orm.attributes import flag_modified
    flag_modified(device, "fingerbank_result")
    db.commit()
    return {"result": result, "device": _to_dict(device)}


@app.delete("/devices/{mac}")
def delete_device(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    db.execute(text("DELETE FROM device_events WHERE mac_address = :mac"), {"mac": mac.lower()})
    db.execute(text("DELETE FROM ip_history WHERE mac_address = :mac"), {"mac": mac.lower()})
    db.execute(text("DELETE FROM vuln_reports WHERE mac_address = :mac"), {"mac": mac.lower()})
    db.execute(text("DELETE FROM traffic_stats WHERE mac_address = :mac"), {"mac": mac.lower()})
    db.execute(text("DELETE FROM alert_suppressions WHERE mac_address = :mac"), {"mac": mac.lower()})
    db.delete(d)
    db.commit()
    return {"ok": True, "mac": mac.lower()}


@app.get("/devices/{mac}/scan")
def get_scan_results(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    if not d.deep_scanned:
        return {"status": "pending", "message": "Deep scan not yet completed"}
    return {"status": "complete", "mac": mac, "data": d.scan_results}


@app.get("/devices/{mac}/ip-history")
def get_ip_history(mac: str, db: Session = Depends(get_db)):
    try:
        rows = db.execute(
            text("SELECT ip_address, first_seen, last_seen FROM ip_history WHERE mac_address = :mac ORDER BY last_seen DESC"),
            {"mac": mac.lower()}
        ).fetchall()
        return [{"ip": r[0], "first_seen": r[1].isoformat() if r[1] else None, "last_seen": r[2].isoformat() if r[2] else None} for r in rows]
    except Exception:
        return []


@app.get("/export/ips-csv")
def export_ips_csv(db: Session = Depends(get_db)):
    """Export all IP history as CSV."""
    import io, csv
    rows = db.execute(text("""
        SELECT d.mac_address, COALESCE(d.custom_name, d.hostname, d.ip_address) AS name,
               h.ip_address, h.first_seen, h.last_seen, h.seen_while_online,
               d.primary_ip, d.primary_ip_locked, d.is_online
        FROM ip_history h
        JOIN devices d ON d.mac_address = h.mac_address
        ORDER BY d.mac_address, h.last_seen DESC
    """)).fetchall()

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["mac_address", "device_name", "ip_address", "first_seen", "last_seen", "seen_while_online", "primary_ip", "primary_ip_locked", "is_online"])
    for r in rows:
        w.writerow([r[0], r[1], r[2],
                    r[3].isoformat() if r[3] else "",
                    r[4].isoformat() if r[4] else "",
                    r[5], r[6], r[7], r[8]])

    from fastapi.responses import StreamingResponse as _SR
    return _SR(iter([buf.getvalue()]), media_type="text/csv",
               headers={"Content-Disposition": "attachment; filename=inspectre-ip-management.csv"})


@app.post("/devices/{mac}/set-primary-ip")
async def set_primary_ip(mac: str, payload: PrimaryIPUpdate, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")

    target_ip = (payload.ip_address or "").strip()
    if not target_ip:
        raise HTTPException(400, "ip_address is required")

    row = db.execute(
        text("SELECT 1 FROM ip_history WHERE mac_address = :mac AND ip_address = :ip LIMIT 1"),
        {"mac": mac.lower(), "ip": target_ip}
    ).fetchone()
    if not row and d.ip_address != target_ip:
        raise HTTPException(404, "IP not found in device history")

    old_primary = d.primary_ip or d.ip_address

    # The probe installs a BEFORE UPDATE trigger that reverts primary_ip/ip_address
    # when both OLD.primary_ip_locked AND NEW.primary_ip_locked are TRUE — to stop
    # the probe overwriting a user pin.  Re-pinning an already-locked device hits
    # that condition.  Work around it with two updates in the same transaction:
    #   1. Unlock (OLD=T→NEW=F): trigger condition False, write succeeds.
    #   2. Re-pin (OLD=F→NEW=T): trigger condition False, write succeeds.
    # Both updates are invisible outside this transaction so no race with the probe.
    db.execute(
        text("UPDATE devices SET primary_ip_locked = FALSE WHERE mac_address = :mac"),
        {"mac": mac.lower()},
    )
    db.execute(
        text("""UPDATE devices
                   SET primary_ip   = :ip,
                       ip_address   = :ip,
                       primary_ip_locked = TRUE,
                       deep_scanned = FALSE,
                       scan_results = NULL
                 WHERE mac_address  = :mac"""),
        {"ip": target_ip, "mac": mac.lower()},
    )
    _add_event(db, mac.lower(), 'primary_ip_changed', {'old_primary_ip': old_primary, 'new_primary_ip': target_ip})
    db.commit()
    db.refresh(d)

    # Verify the pin was written correctly — the DB trigger or a concurrent
    # update could silently prevent it.
    if d.primary_ip != target_ip or not d.primary_ip_locked:
        print(
            f"[set-primary-ip] WARN: pin verification failed for {mac}: "
            f"expected primary={target_ip} locked=True, "
            f"got primary={d.primary_ip} locked={d.primary_ip_locked}",
            flush=True,
        )
        raise HTTPException(500, "Pin did not take effect — the device may have a conflicting lock. Please try again.")

    result = {"ok": True, "device": _to_dict(d)}

    async def _trigger_rescan():
        try:
            async with _probe_client(timeout=3.0) as client:
                await client.post(f"{PROBE_URL}/rescan/{mac.lower()}")
        except Exception:
            pass
    asyncio.ensure_future(_trigger_rescan())

    return result


@app.post("/devices/{mac}/unpin-ip")
def unpin_primary_ip(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    d.primary_ip_locked = False
    db.commit()
    db.refresh(d)
    return {"ok": True, "device": _to_dict(d)}


@app.get("/devices/{mac}/events")
def get_device_events(
    mac: str,
    type: Optional[str] = Query(default=None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(default=0),
    db: Session = Depends(get_db),
):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    # If the device is in a group, include events from all group members
    group_id = getattr(d, "group_id", None)
    if group_id:
        try:
            macs = [r[0] for r in db.execute(
                text("SELECT mac_address FROM devices WHERE group_id = :gid"),
                {"gid": group_id},
            ).fetchall()]
        except Exception:
            macs = [mac.lower()]
    else:
        macs = [mac.lower()]
    try:
        rows = db.execute(
            text("""
                SELECT id, mac_address, type, detail, created_at
                FROM device_events
                WHERE mac_address = ANY(:macs)
                  AND (:type IS NULL OR type = :type)
                ORDER BY created_at DESC
                LIMIT :limit OFFSET :offset
            """),
            {"macs": macs, "type": type, "limit": limit, "offset": offset}
        ).fetchall()
        return [
            {
                "id":          r[0],
                "mac_address": r[1],
                "type":        r[2],
                "detail":      r[3],
                "created_at":  r[4].isoformat() if r[4] else None,
            }
            for r in rows
        ]
    except Exception:
        return []


@app.get("/devices/{mac}/identity-score")
def get_identity_score(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    return {"mac": mac, "score": _identity_score(d), "device_type": _infer_device_type(d)}


# ---------------------------------------------------------------------------
# Phase 9 — Device grouping
# ---------------------------------------------------------------------------

class GroupAddRequest(BaseModel):
    target_mac: str


@app.get("/devices/{mac}/group")
def get_device_group(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    group_id = getattr(d, "group_id", None)
    if not group_id:
        return {"group_id": None, "members": []}
    rows = db.execute(
        text("""
            SELECT mac_address, hostname, custom_name, ip_address, is_online, group_primary
            FROM devices WHERE group_id = :gid
        """),
        {"gid": group_id},
    ).fetchall()
    return {
        "group_id": str(group_id),
        "members": [
            {
                "mac_address":   r[0],
                "hostname":      r[1],
                "custom_name":   r[2],
                "ip_address":    r[3],
                "is_online":     r[4],
                "group_primary": bool(r[5]),
                "display_name":  r[2] or r[1] or r[3] or r[0],
            }
            for r in rows
        ],
    }


@app.post("/devices/{mac}/group/add")
def add_to_group(mac: str, body: GroupAddRequest, db: Session = Depends(get_db)):
    import uuid as _uuid
    mac1 = mac.lower()
    mac2 = body.target_mac.lower()
    if mac1 == mac2:
        raise HTTPException(400, "Cannot group a device with itself")
    d1 = db.get(Device, mac1)
    d2 = db.get(Device, mac2)
    if not d1 or not d2:
        raise HTTPException(404, "Device not found")
    g1 = getattr(d1, "group_id", None)
    g2 = getattr(d2, "group_id", None)
    if g1 and g2 and str(g1) == str(g2):
        return {"ok": True, "group_id": str(g1)}
    # Prefer an existing group_id; if both have different groups, merge into g1
    new_gid = str(g1 or g2 or _uuid.uuid4())
    db.execute(
        text("UPDATE devices SET group_id = :gid WHERE mac_address = ANY(:macs)"),
        {"gid": new_gid, "macs": [mac1, mac2]},
    )
    # If g2 had a group, pull all its members into the new group
    if g2 and str(g2) != new_gid:
        db.execute(
            text("UPDATE devices SET group_id = :gid WHERE group_id = :old"),
            {"gid": new_gid, "old": str(g2)},
        )
    # Ensure exactly one primary exists: prefer the existing primary, else set mac1
    primaries = db.execute(
        text("SELECT mac_address FROM devices WHERE group_id = :gid AND group_primary = true"),
        {"gid": new_gid},
    ).fetchall()
    if not primaries:
        db.execute(
            text("UPDATE devices SET group_primary = true WHERE mac_address = :mac"),
            {"mac": mac1},
        )
    # Mark the whole group as manually curated so auto-grouping cleanup never
    # dissolves it (manual groups may legitimately span different DNS hostnames).
    db.execute(
        text("UPDATE devices SET group_manual = true, auto_group_optout = false WHERE group_id = :gid"),
        {"gid": new_gid},
    )
    db.commit()
    return {"ok": True, "group_id": new_gid}


@app.post("/devices/{mac}/group/remove")
def remove_from_group(mac: str, db: Session = Depends(get_db)):
    mac_lower = mac.lower()
    d = db.get(Device, mac_lower)
    if not d:
        raise HTTPException(404, "Device not found")
    group_id = getattr(d, "group_id", None)
    if not group_id:
        return {"ok": True}
    db.execute(
        text("UPDATE devices SET group_id = NULL, group_primary = FALSE, group_manual = FALSE, auto_group_optout = TRUE WHERE mac_address = :mac"),
        {"mac": mac_lower},
    )
    # If only one member remains, dissolve the group
    remaining = db.execute(
        text("SELECT COUNT(*) FROM devices WHERE group_id = :gid"),
        {"gid": group_id},
    ).scalar() or 0
    if remaining <= 1:
        db.execute(
            text("UPDATE devices SET group_id = NULL, group_primary = FALSE, group_manual = FALSE WHERE group_id = :gid"),
            {"gid": group_id},
        )
    db.commit()
    return {"ok": True}


@app.put("/devices/{mac}/group/primary")
def set_group_primary(mac: str, db: Session = Depends(get_db)):
    mac_lower = mac.lower()
    d = db.get(Device, mac_lower)
    if not d:
        raise HTTPException(404, "Device not found")
    group_id = getattr(d, "group_id", None)
    if not group_id:
        raise HTTPException(400, "Device is not in a group")
    db.execute(
        text("UPDATE devices SET group_primary = FALSE WHERE group_id = :gid"),
        {"gid": group_id},
    )
    db.execute(
        text("UPDATE devices SET group_primary = TRUE WHERE mac_address = :mac"),
        {"mac": mac_lower},
    )
    db.execute(
        text("UPDATE devices SET group_manual = TRUE WHERE group_id = :gid"),
        {"gid": group_id},
    )
    db.commit()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Phase 3 — Vulnerability scanning (proxied through the probe container)
# ---------------------------------------------------------------------------
# Per-mac broadcast state: multiple browser connections can subscribe to the
# same running scan (handles drawer close/reopen mid-scan).
_nuclei_subs:  dict[str, list[asyncio.Queue]] = {}  # mac → subscriber queues
_nuclei_lines: dict[str, list[str]] = {}            # mac → buffered output lines


@app.get("/devices/{mac}/vuln-scan")
async def stream_vuln_scan(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    if not d.ip_address:
        raise HTTPException(400, "Device has no IP address")

    templates_setting = db.get(Setting, "vuln_scan_templates")
    templates = (templates_setting.value or "").strip() if templates_setting else ""

    ip        = getattr(d, "primary_ip", None) or d.ip_address
    mac_lower = mac.lower()

    # Create a queue for this connection
    q: asyncio.Queue[str | None] = asyncio.Queue()

    if mac_lower in _nuclei_subs:
        # Scan already running — replay buffered lines then subscribe for new ones
        for line in _nuclei_lines.get(mac_lower, []):
            await q.put(line)
        _nuclei_subs[mac_lower].append(q)
    else:
        # Start a new scan — initialise broadcast state first
        _nuclei_subs[mac_lower]  = [q]
        _nuclei_lines[mac_lower] = []

        probe_url = f"{PROBE_URL}/stream/vuln-scan/{ip}"
        params    = {"templates": templates, "mac": mac_lower}

        async def _probe_reader() -> None:
            async def _broadcast(line: str) -> None:
                _nuclei_lines.setdefault(mac_lower, []).append(line)
                for sub_q in list(_nuclei_subs.get(mac_lower, [])):
                    await sub_q.put(line)

            try:
                async with _probe_client(timeout=None) as client:
                    async with client.stream("GET", probe_url, params=params) as resp:
                        if resp.status_code != 200:
                            body = await resp.aread()
                            await _broadcast(f"data: [ERROR] Probe returned HTTP {resp.status_code}: {body.decode()[:200]}\n\n")
                            return
                        async for raw_line in resp.aiter_lines():
                            await _broadcast(f"{raw_line}\n")
                            if raw_line.startswith("data: RESULT:"):
                                payload_str = raw_line[len("data: RESULT:"):]
                                try:
                                    data = json.loads(payload_str)
                                    _save_vuln_result(mac_lower, ip, data, templates)
                                except Exception as exc:
                                    await _broadcast(f"data: [WARN] Could not save report: {exc}\n\n")
            except httpx.ConnectError:
                await _broadcast(f"data: [ERROR] Cannot reach probe at {PROBE_URL} — is it running?\n\n")
            except Exception as exc:
                await _broadcast(f"data: [ERROR] Proxy error: {exc}\n\n")
            finally:
                # Signal all current subscribers that the stream is done, then clean up
                for sub_q in _nuclei_subs.pop(mac_lower, []):
                    await sub_q.put(None)
                _nuclei_lines.pop(mac_lower, None)

        asyncio.create_task(_probe_reader())

    async def _event_stream():
        while True:
            try:
                line = await asyncio.wait_for(q.get(), timeout=30)
            except asyncio.TimeoutError:
                yield ": heartbeat\n\n"
                continue
            if line is None:
                break
            yield line

    return StreamingResponse(
        _event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/devices/{mac}/vuln-scan-status")
def vuln_scan_status(mac: str):
    """Returns whether a nuclei scan is currently running for this device."""
    return {"scanning": mac.lower() in _nuclei_subs}


@app.get("/devices/{mac}/vuln-reports")
def get_vuln_reports(mac: str, limit: int = Query(10, ge=1, le=100), db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    reports = (
        db.query(VulnReport)
        .filter(VulnReport.mac_address == mac.lower())
        .order_by(VulnReport.scanned_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id":         r.id,
            "ip_address": r.ip_address,
            "scanned_at": r.scanned_at.isoformat() if r.scanned_at else None,
            "duration_s": r.duration_s,
            "severity":   r.severity,
            "vuln_count": r.vuln_count,
            "findings":   r.findings or [],
            "scan_args":  r.scan_args,
        }
        for r in reports
    ]


@app.get("/devices/{mac}/vuln-reports/{report_id}")
def get_vuln_report_detail(mac: str, report_id: int, db: Session = Depends(get_db)):
    r = db.query(VulnReport).filter(
        VulnReport.id == report_id,
        VulnReport.mac_address == mac.lower()
    ).first()
    if not r:
        raise HTTPException(404, "Report not found")
    return {
        "id":           r.id,
        "ip_address":   r.ip_address,
        "scanned_at":   r.scanned_at.isoformat() if r.scanned_at else None,
        "duration_s":   r.duration_s,
        "severity":     r.severity,
        "vuln_count":   r.vuln_count,
        "findings":     r.findings or [],
        "raw_output":   r.raw_output,
        "scan_args":    r.scan_args,
    }


@app.delete("/devices/{mac}/vuln-reports/{report_id}")
def delete_vuln_report(mac: str, report_id: int, db: Session = Depends(get_db)):
    r = db.query(VulnReport).filter(
        VulnReport.id == report_id,
        VulnReport.mac_address == mac.lower()
    ).first()
    if not r:
        raise HTTPException(404, "Report not found")
    db.delete(r)
    db.commit()
    return {"deleted": report_id}


@app.get("/vuln-reports")
def list_all_vuln_reports(
    severity: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db)
):
    q = db.query(VulnReport)
    if severity:
        q = q.filter(VulnReport.severity == severity)
    reports = q.order_by(VulnReport.scanned_at.desc()).limit(limit).all()
    return [
        {
            "id":          r.id,
            "mac_address": r.mac_address,
            "ip_address":  r.ip_address,
            "scanned_at":  r.scanned_at.isoformat() if r.scanned_at else None,
            "severity":    r.severity,
            "vuln_count":  r.vuln_count,
            "findings":    r.findings or [],
        }
        for r in reports
    ]


@app.get("/vulns/summary")
def vuln_summary(db: Session = Depends(get_db)):
    sev_rows = db.execute(text("""
        SELECT vuln_severity, COUNT(*) AS cnt
        FROM devices
        WHERE vuln_severity IS NOT NULL
        GROUP BY vuln_severity
    """)).fetchall()
    sev_counts = {r[0]: int(r[1]) for r in sev_rows}

    top_rows = db.execute(text("""
        SELECT DISTINCT ON (d.mac_address)
               d.mac_address, d.custom_name, d.hostname, d.ip_address,
               d.vuln_severity, vr.vuln_count, vr.scanned_at
        FROM devices d
        JOIN vuln_reports vr ON vr.mac_address = d.mac_address
        WHERE d.vuln_severity IS NOT NULL AND d.vuln_severity NOT IN ('clean', 'info')
        ORDER BY d.mac_address, vr.scanned_at DESC
    """)).fetchall()

    def sev_rank(s):
        return {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(s or '', 9)

    top_rows = sorted(top_rows, key=lambda r: sev_rank(r[4]))[:8]
    top_vulnerable = [
        {
            "mac_address":  r[0],
            "display_name": r[1] or r[2] or r[3] or r[0],
            "ip_address":   r[3],
            "severity":     r[4],
            "vuln_count":   r[5],
            "scanned_at":   r[6].isoformat() if r[6] else None,
        }
        for r in top_rows
    ]

    recent_rows = db.execute(text("""
        SELECT d.mac_address,
               COALESCE(d.custom_name, d.hostname, d.ip_address, d.mac_address) AS display_name,
               d.ip_address, vr.severity, vr.vuln_count, vr.scanned_at
        FROM vuln_reports vr
        JOIN devices d ON d.mac_address = vr.mac_address
        ORDER BY vr.scanned_at DESC
        LIMIT 20
    """)).fetchall()
    recent_scans = [
        {
            "mac_address":  r[0],
            "display_name": r[1],
            "ip_address":   r[2],
            "severity":     r[3],
            "vuln_count":   r[4],
            "scanned_at":   r[5].isoformat() if r[5] else None,
        }
        for r in recent_rows
    ]

    total_scanned = db.execute(text(
        "SELECT COUNT(*) FROM devices WHERE vuln_last_scanned IS NOT NULL"
    )).scalar() or 0
    total_devices = db.execute(text("SELECT COUNT(*) FROM devices")).scalar() or 0

    return {
        "severity_counts": sev_counts,
        "total_scanned":   int(total_scanned),
        "total_devices":   int(total_devices),
        "top_vulnerable":  top_vulnerable,
        "recent_scans":    recent_scans,
    }


# ---------------------------------------------------------------------------
# Device services endpoint
# ---------------------------------------------------------------------------
@app.get("/devices/{mac}/services")
def get_device_services(mac: str, db: Session = Depends(get_db)):
    device = db.execute(
        text("SELECT scan_results FROM devices WHERE mac_address = :mac"),
        {"mac": mac.lower()}
    ).fetchone()
    if not device or not device[0]:
        return {"services": [], "pipeline_stage": None}
    scan = device[0]
    ports = scan.get("open_ports") or []
    nerva = {s["port"]: s for s in (scan.get("services") or [])}
    merged = []
    for p in ports:
        port_num = p.get("port")
        entry = {
            "port":      port_num,
            "proto":     p.get("proto", "tcp"),
            "service":   p.get("service") or nerva.get(port_num, {}).get("service", ""),
            "product":   p.get("product", ""),
            "version":   p.get("version", ""),
            "tls":       p.get("tls") or nerva.get(port_num, {}).get("tls", False),
            "extrainfo": p.get("extrainfo", ""),
        }
        merged.append(entry)
    return {
        "services": sorted(merged, key=lambda x: x["port"] or 0),
        "pipeline_stage": scan.get("pipeline_stage"),
    }


@app.post("/devices/{mac}/mdns-refresh")
async def refresh_device_mdns(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    try:
        async with _probe_client(timeout=35.0) as client:
            resp = await client.post(f"{PROBE_URL}/mdns/refresh")
            resp.raise_for_status()
    except httpx.ConnectError:
        raise HTTPException(502, f"Cannot reach probe at {PROBE_URL}")
    except Exception as e:
        raise HTTPException(502, f"mDNS refresh failed: {e}")
    db.refresh(d)
    mdns_services = (d.scan_results or {}).get("mdns_services", []) if d.scan_results else []
    return {"mdns_services": mdns_services}


@app.post("/network/mdns-scan")
async def network_mdns_scan():
    """Trigger a network-wide active mDNS browse."""
    try:
        async with _probe_client(timeout=25.0) as client:
            resp = await client.post(f"{PROBE_URL}/mdns/refresh")
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        raise HTTPException(502, f"Cannot reach probe at {PROBE_URL}")
    except Exception as e:
        raise HTTPException(502, f"mDNS scan failed: {e}")


@app.post("/network/ssdp-scan")
async def network_ssdp_scan():
    """Trigger a network-wide active SSDP M-SEARCH."""
    try:
        async with _probe_client(timeout=20.0) as client:
            resp = await client.post(f"{PROBE_URL}/ssdp/refresh")
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        raise HTTPException(502, f"Cannot reach probe at {PROBE_URL}")
    except Exception as e:
        raise HTTPException(502, f"SSDP scan failed: {e}")


# ---------------------------------------------------------------------------
# Zone management
# ---------------------------------------------------------------------------
@app.get("/zones")
def list_zones(db: Session = Depends(get_db)):
    try:
        rows = db.execute(text("""
            SELECT
                COALESCE(zone, 'Unassigned') AS zone,
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE is_online = true) AS online
            FROM devices
            GROUP BY zone
            ORDER BY zone
        """)).fetchall()
        return [{"zone": r[0], "total": int(r[1]), "online": int(r[2])} for r in rows]
    except Exception as e:
        raise HTTPException(500, str(e))


class ZoneAssign(BaseModel):
    mac_addresses: List[str]
    zone: Optional[str] = None


@app.post("/zones/assign")
def assign_zone(body: ZoneAssign, db: Session = Depends(get_db)):
    try:
        db.execute(
            text("UPDATE devices SET zone = :zone WHERE mac_address = ANY(:macs)"),
            {"zone": body.zone, "macs": [m.lower() for m in body.mac_addresses]},
        )
        db.commit()
        return {"updated": len(body.mac_addresses)}
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))


class ZoneRename(BaseModel):
    old_name: str
    new_name: str


@app.post("/zones/rename")
def rename_zone(body: ZoneRename, db: Session = Depends(get_db)):
    try:
        result = db.execute(
            text("UPDATE devices SET zone = :new WHERE zone = :old"),
            {"new": body.new_name, "old": body.old_name},
        )
        db.commit()
        return {"updated": result.rowcount}
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))


# ---------------------------------------------------------------------------
# Saved views
# ---------------------------------------------------------------------------
class SavedViewCreate(BaseModel):
    name: str
    description: Optional[str] = None
    filters: dict = {}


@app.get("/saved-views")
def list_saved_views(db: Session = Depends(get_db)):
    try:
        rows = db.execute(text(
            "SELECT id, name, description, filters, created_at, updated_at FROM saved_views ORDER BY name"
        )).fetchall()
        return [
            {
                "id": r[0], "name": r[1], "description": r[2],
                "filters": r[3] or {},
                "created_at": r[4].isoformat() if r[4] else None,
                "updated_at": r[5].isoformat() if r[5] else None,
            }
            for r in rows
        ]
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/saved-views/{view_id}")
def get_saved_view(view_id: int, db: Session = Depends(get_db)):
    row = db.execute(
        text("SELECT id, name, description, filters, created_at, updated_at FROM saved_views WHERE id = :id"),
        {"id": view_id}
    ).fetchone()
    if not row:
        raise HTTPException(404, "View not found")
    return {
        "id": row[0], "name": row[1], "description": row[2],
        "filters": row[3] or {},
        "created_at": row[4].isoformat() if row[4] else None,
        "updated_at": row[5].isoformat() if row[5] else None,
    }


@app.post("/saved-views", status_code=201)
def create_saved_view(body: SavedViewCreate, db: Session = Depends(get_db)):
    try:
        row = db.execute(
            text("""
                INSERT INTO saved_views (name, description, filters)
                VALUES (:name, :description, cast(:filters AS jsonb))
                RETURNING id, name, description, filters, created_at, updated_at
            """),
            {"name": body.name, "description": body.description, "filters": json.dumps(body.filters)}
        ).fetchone()
        db.commit()
        return {
            "id": row[0], "name": row[1], "description": row[2],
            "filters": row[3] or {},
            "created_at": row[4].isoformat() if row[4] else None,
            "updated_at": row[5].isoformat() if row[5] else None,
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))


@app.put("/saved-views/{view_id}")
def update_saved_view(view_id: int, body: SavedViewCreate, db: Session = Depends(get_db)):
    try:
        row = db.execute(
            text("""
                UPDATE saved_views
                SET name = :name, description = :description,
                    filters = cast(:filters AS jsonb), updated_at = NOW()
                WHERE id = :id
                RETURNING id, name, description, filters, created_at, updated_at
            """),
            {"id": view_id, "name": body.name, "description": body.description, "filters": json.dumps(body.filters)}
        ).fetchone()
        if not row:
            raise HTTPException(404, "View not found")
        db.commit()
        return {
            "id": row[0], "name": row[1], "description": row[2],
            "filters": row[3] or {},
            "created_at": row[4].isoformat() if row[4] else None,
            "updated_at": row[5].isoformat() if row[5] else None,
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))


@app.delete("/saved-views/{view_id}", status_code=204)
def delete_saved_view(view_id: int, db: Session = Depends(get_db)):
    db.execute(text("DELETE FROM saved_views WHERE id = :id"), {"id": view_id})
    db.commit()


# ---------------------------------------------------------------------------
# Alert suppressions
# ---------------------------------------------------------------------------
class SuppressionCreate(BaseModel):
    mac_address: Optional[str] = None
    event_type:  Optional[str] = None
    reason:      Optional[str] = None
    expires_at:  Optional[str] = None


@app.get("/suppressions")
def list_suppressions(mac: Optional[str] = None, db: Session = Depends(get_db)):
    try:
        if mac:
            rows = db.execute(text("""
                SELECT id, mac_address, event_type, reason, expires_at, created_at
                FROM alert_suppressions
                WHERE mac_address = :mac
                ORDER BY created_at DESC
            """), {"mac": mac.lower()}).fetchall()
        else:
            rows = db.execute(text("""
                SELECT id, mac_address, event_type, reason, expires_at, created_at
                FROM alert_suppressions
                ORDER BY created_at DESC
            """)).fetchall()
        return [
            {
                "id": r[0], "mac_address": r[1], "event_type": r[2],
                "reason": r[3],
                "expires_at": r[4].isoformat() if r[4] else None,
                "created_at": r[5].isoformat() if r[5] else None,
            }
            for r in rows
        ]
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/suppressions", status_code=201)
def create_suppression(body: SuppressionCreate, db: Session = Depends(get_db)):
    try:
        expires = None
        if body.expires_at:
            from datetime import datetime
            expires = datetime.fromisoformat(body.expires_at.replace("Z", "+00:00"))
        row = db.execute(
            text("""
                INSERT INTO alert_suppressions (mac_address, event_type, reason, expires_at)
                VALUES (:mac, :type, :reason, :expires)
                RETURNING id, mac_address, event_type, reason, expires_at, created_at
            """),
            {
                "mac": body.mac_address.lower() if body.mac_address else None,
                "type": body.event_type,
                "reason": body.reason,
                "expires": expires,
            }
        ).fetchone()
        db.commit()
        return {
            "id": row[0], "mac_address": row[1], "event_type": row[2],
            "reason": row[3],
            "expires_at": row[4].isoformat() if row[4] else None,
            "created_at": row[5].isoformat() if row[5] else None,
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))


@app.delete("/suppressions/{suppression_id}", status_code=204)
def delete_suppression(suppression_id: int, db: Session = Depends(get_db)):
    db.execute(text("DELETE FROM alert_suppressions WHERE id = :id"), {"id": suppression_id})
    db.commit()


# ---------------------------------------------------------------------------
# Vuln trend + top devices (for dashboard)
# ---------------------------------------------------------------------------
@app.post("/vulns/scan-all")
async def trigger_scan_all():
    asyncio.ensure_future(_run_all_vuln_scans())
    return {"status": "started", "message": "Vulnerability scan initiated for all eligible devices"}


@app.get("/vulns/trend")
def get_vuln_trend(days: int = Query(default=30, le=90), db: Session = Depends(get_db)):
    try:
        rows = db.execute(text("""
            SELECT
                date_trunc('day', scanned_at)::date AS day,
                severity,
                COUNT(*) AS count
            FROM vuln_reports
            WHERE scanned_at >= NOW() - (INTERVAL '1 day' * :days)
            GROUP BY day, severity
            ORDER BY day ASC, severity
        """), {"days": days}).fetchall()
        by_day: dict = defaultdict(dict)
        for row in rows:
            by_day[str(row[0])][row[1]] = int(row[2])
        return [{"date": d, **severities} for d, severities in sorted(by_day.items())]
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/vulns/top-devices")
def get_top_vulnerable_devices(limit: int = Query(default=10, le=50), db: Session = Depends(get_db)):
    try:
        rows = db.execute(text("""
            SELECT DISTINCT ON (d.mac_address)
                d.mac_address,
                COALESCE(d.custom_name, d.hostname, d.ip_address) AS name,
                d.ip_address,
                d.vuln_severity,
                vr.vuln_count,
                vr.scanned_at,
                vr.findings
            FROM devices d
            JOIN vuln_reports vr ON vr.mac_address = d.mac_address
            WHERE d.vuln_severity IN ('critical', 'high', 'medium')
            ORDER BY d.mac_address, vr.scanned_at DESC
        """)).fetchall()
        def sev_rank(s):
            return {'critical': 1, 'high': 2, 'medium': 3}.get(s or '', 9)
        rows_sorted = sorted(rows, key=lambda r: sev_rank(r[3]))[:limit]
        return [
            {
                "mac": r[0], "name": r[1], "ip": r[2],
                "severity": r[3], "vuln_count": r[4],
                "scanned_at": r[5].isoformat() if r[5] else None,
                "top_findings": (r[6] or [])[:3],
            }
            for r in rows_sorted
        ]
    except Exception as e:
        raise HTTPException(500, str(e))


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------
@app.get("/events")
def get_all_events(limit: int = Query(100, ge=1, le=1000), event_type: Optional[str] = None, db: Session = Depends(get_db)):
    try:
        params: dict = {"limit": limit}
        extra = ""
        if event_type:
            extra = " AND de.type = :event_type"
            params["event_type"] = event_type
        rows = db.execute(text(f"""
            SELECT de.id, de.mac_address, de.type, de.detail, de.created_at,
                   COALESCE(d.custom_name, d.hostname, d.ip_address, de.mac_address) AS display_name,
                   d.ip_address, d.vendor
            FROM device_events de
            JOIN devices d ON d.mac_address = de.mac_address
            WHERE 1=1{extra}
            ORDER BY de.created_at DESC
            LIMIT :limit
        """), params).fetchall()
        return [{"id": r[0], "mac_address": r[1], "type": r[2], "detail": r[3],
                 "created_at": r[4].isoformat() if r[4] else None, "display_name": r[5],
                 "ip_address": r[6], "vendor": r[7]} for r in rows]
    except Exception:
        return []


@app.get("/events/status")
def get_status_events(limit: int = Query(100, ge=1, le=1000), db: Session = Depends(get_db)):
    try:
        rows = db.execute(text("""
            SELECT de.id, de.mac_address, de.type, de.detail, de.created_at,
                   COALESCE(d.custom_name, d.hostname, d.ip_address, de.mac_address) AS display_name,
                   d.ip_address, d.vendor
            FROM device_events de
            JOIN devices d ON d.mac_address = de.mac_address
            WHERE de.type IN ('online', 'offline')
            ORDER BY de.created_at DESC
            LIMIT :limit
        """), {"limit": limit}).fetchall()
        return [{"id": r[0], "mac_address": r[1], "type": r[2], "detail": r[3],
                 "created_at": r[4].isoformat() if r[4] else None, "display_name": r[5],
                 "ip_address": r[6], "vendor": r[7]} for r in rows]
    except Exception:
        return []


@app.get("/changes")
def get_change_feed(limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db)):
    CHANGE_TYPES = ["joined", "online", "offline", "ip_change", "scan_complete",
                    "renamed", "tagged", "marked_important", "port_change", "hostname_change",
                    "vuln_scan_complete", "service_fingerprint_complete"]
    try:
        rows = db.execute(text("""
            SELECT de.id, de.mac_address, de.type, de.detail, de.created_at,
                   COALESCE(d.custom_name, d.hostname, d.ip_address, de.mac_address) AS display_name,
                   d.ip_address, d.vendor, d.is_online, d.device_type_override
            FROM device_events de
            JOIN devices d ON d.mac_address = de.mac_address
            WHERE de.type = ANY(:types)
            ORDER BY de.created_at DESC
            LIMIT :limit
        """), {"types": CHANGE_TYPES, "limit": limit}).fetchall()
        return [{"id": r[0], "mac_address": r[1], "type": r[2], "detail": r[3],
                 "created_at": r[4].isoformat() if r[4] else None, "display_name": r[5],
                 "ip_address": r[6], "vendor": r[7], "is_online": r[8], "device_type": r[9]} for r in rows]
    except Exception:
        return []


@app.get("/dashboard/summary")
def dashboard_summary(db: Session = Depends(get_db)):
    try:
        recent_rows = db.execute(text("""
            SELECT de.type, de.detail, de.created_at,
                   COALESCE(d.custom_name, d.hostname, d.ip_address, de.mac_address),
                   de.mac_address, d.ip_address
            FROM device_events de
            JOIN devices d ON d.mac_address = de.mac_address
            ORDER BY de.created_at DESC LIMIT 20
        """)).fetchall()
        recent = [{"type": r[0], "detail": r[1], "created_at": r[2].isoformat() if r[2] else None,
                   "display_name": r[3], "mac_address": r[4], "ip_address": r[5]} for r in recent_rows]
        unnamed   = db.execute(text("SELECT COUNT(*) FROM devices WHERE custom_name IS NULL AND hostname IS NULL")).scalar()
        unknown_v = db.execute(text("SELECT COUNT(*) FROM devices WHERE (vendor IS NULL OR vendor='Unknown') AND vendor_override IS NULL")).scalar()
        unscanned = db.execute(text("SELECT COUNT(*) FROM devices WHERE deep_scanned = FALSE AND is_online = TRUE")).scalar()
        low_conf  = db.execute(text("SELECT COUNT(*) FROM devices WHERE hostname IS NULL AND (vendor IS NULL OR vendor='Unknown') AND scan_results IS NULL")).scalar()
        vuln_devices = db.execute(text("SELECT COUNT(DISTINCT mac_address) FROM vuln_reports WHERE severity NOT IN ('clean','info')")).scalar()
        return {
            "recent_changes": recent,
            "attention": {
                "unnamed_devices":  unnamed,
                "unknown_vendor":   unknown_v,
                "not_deep_scanned": unscanned,
                "low_confidence":   low_conf,
                "vuln_devices":     vuln_devices,
            }
        }
    except Exception:
        return {"recent_changes": [], "attention": {}}


# ---------------------------------------------------------------------------
# Vendors
# ---------------------------------------------------------------------------
@app.get("/vendors", response_model=List[str])
def list_vendors(db: Session = Depends(get_db)):
    try:
        rows = db.execute(text(
            "SELECT DISTINCT vendor_override FROM devices WHERE vendor_override IS NOT NULL AND vendor_override != '' "
            "UNION "
            "SELECT DISTINCT vendor FROM devices WHERE vendor IS NOT NULL AND vendor != '' "
            "ORDER BY 1"
        )).fetchall()
        return sorted({r[0] for r in rows if r[0]}, key=lambda s: s.lower())
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------
@app.get("/stats")
def stats(db: Session = Depends(get_db)):
    total     = db.query(Device).count()
    online    = db.query(Device).filter(Device.is_online == True).count()
    offline   = db.query(Device).filter(Device.is_online == False).count()
    scanned   = db.query(Device).filter(Device.deep_scanned == True).count()
    important = db.query(Device).filter(Device.is_important == True).count()
    vuln_high = db.execute(text(
        "SELECT COUNT(DISTINCT mac_address) FROM vuln_reports WHERE severity IN ('critical','high')"
    )).scalar()
    return {"total_devices": total, "online": online, "offline": offline,
            "deep_scanned": scanned, "important": important, "vuln_high": int(vuln_high or 0)}


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
@app.get("/settings")
def get_settings(db: Session = Depends(get_db)):
    _seed_settings(db)
    return [{"key": s.key, "value": s.value, "description": s.description} for s in db.query(Setting).all()]

@app.put("/settings/{key}")
def update_setting(key: str, payload: SettingUpdate, db: Session = Depends(get_db)):
    s = db.get(Setting, key)
    if not s:
        raise HTTPException(404, "Setting not found")
    if key == "block_plugin_id" and payload.value:
        plugin = _plugin_registry.get(payload.value)
        if not plugin:
            raise HTTPException(400, f"Plugin '{payload.value}' not found")
        if not plugin.get("enabled"):
            raise HTTPException(400, f"Plugin '{payload.value}' is not enabled")
        caps = plugin["manifest"].get("capabilities", [])
        if "blocking" not in caps:
            raise HTTPException(400, f"Plugin '{payload.value}' does not declare the 'blocking' capability")
        actions = plugin["manifest"].get("actions") or {}
        if "block_client" not in actions or "unblock_client" not in actions:
            raise HTTPException(400, f"Plugin '{payload.value}' must define both block_client and unblock_client actions")
    s.value = payload.value
    db.commit()
    return {"key": key, "value": s.value}


@app.post("/settings/reset")
def reset_settings(db: Session = Depends(get_db)):
    for key, (value, _) in DEFAULT_SETTINGS.items():
        s = db.get(Setting, key)
        if s:
            s.value = value
    db.commit()
    _seed_settings(db)
    return {"reset": True}


@app.post("/settings/apply")
async def apply_settings(db: Session = Depends(get_db)):
    _seed_settings(db)
    settings = {s.key: s.value for s in db.query(Setting).all()}
    payload = {}

    if "scan_interval" in settings:
        payload["scan_interval"] = int(settings["scan_interval"])
    if "offline_miss_threshold" in settings:
        payload["offline_miss_threshold"] = int(settings["offline_miss_threshold"])
    if "sniffer_workers" in settings:
        payload["sniffer_workers"] = int(settings["sniffer_workers"])
    if "arp_scan_retry" in settings:
        payload["arp_scan_retry"] = int(settings["arp_scan_retry"])
    if "primary_ip_mode" in settings:
        payload["primary_ip_mode"] = settings["primary_ip_mode"]
    if "ip_range" in settings:
        payload["ip_range"] = settings["ip_range"]
    if "nuclei_template_update_interval" in settings:
        payload["nuclei_template_update_interval"] = settings["nuclei_template_update_interval"]
    # Here Be Dragons — forward immediately to probe
    for key in (
        "enable_arp_sweep", "enable_passive_sniffer", "sniffer_subnet_filter",
        "enable_hostname_resolution", "hostname_cooldown_hours",
        "enable_port_scanning", "port_scan_method", "port_scan_workers", "gateway_scan_workers",
        "enable_service_fingerprinting", "enable_mdns",
        "enable_nightly_scan", "enable_unscanned_retry",
        "probe_interface", "dns_server",
        "auto_group_by_hostname", "scan_grouped_members",
    ):
        if key in settings:
            payload[key] = settings[key]

    try:
        async with _probe_client(timeout=15.0) as client:
            resp = await client.post(f"{PROBE_URL}/config/reload", json=payload)
            body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"raw": resp.text}
            if resp.status_code >= 400:
                raise HTTPException(resp.status_code, f"Probe rejected settings apply: {body}")
            return {"applied": True, "probe_response": body}
    except httpx.ConnectError:
        raise HTTPException(502, f"Cannot reach probe at {PROBE_URL}")


@app.post("/settings/restart-probe")
async def restart_probe(username: str = Depends(get_current_user)):
    """Tell the probe to exit — Docker restart policy brings it back."""
    try:
        async with _probe_client(timeout=5.0) as client:
            r = await client.post(f"{PROBE_URL}/restart")
            r.raise_for_status()
            return {"ok": True}
    except httpx.ConnectError:
        raise HTTPException(502, f"Cannot reach probe at {PROBE_URL}")
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.post("/settings/restart-backend")
async def restart_backend(username: str = Depends(get_current_user)):
    """Exit this process — Docker restart policy brings it back."""
    import signal as _sig
    def _do():
        import time as _t
        _t.sleep(0.5)
        os.kill(os.getpid(), _sig.SIGTERM)
    import threading as _th
    _th.Thread(target=_do, daemon=True).start()
    return {"ok": True, "restarting": True}


# ---------------------------------------------------------------------------
# Notification channels & profiles CRUD
# ---------------------------------------------------------------------------

class ChannelCreate(BaseModel):
    name: str
    service: str
    config: dict
    enabled: bool = True

class ProfileCreate(BaseModel):
    name: str
    events: dict
    channel_ids: List[int] = []


def _channel_row(row) -> dict:
    return {
        "id": row.id, "name": row.name, "service": row.service,
        "config": row.config if isinstance(row.config, dict) else {},
        "enabled": row.enabled,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@app.get("/notifications/events")
def list_notification_events():
    categories: dict = {}
    for event_type, label, category, desc in NOTIFICATION_EVENT_DEFS:
        categories.setdefault(category, []).append(
            {"type": event_type, "label": label, "description": desc}
        )
    return [{"category": cat, "events": evts} for cat, evts in categories.items()]


@app.get("/ha-mqtt/status")
def ha_mqtt_status():
    return {"connected": _ha_mqtt.connected}


@app.post("/ha-mqtt/reconnect")
def ha_mqtt_reconnect(db: Session = Depends(get_db)):
    try:
        _ha_startup_connect(db)
        return {"connected": _ha_mqtt.connected}
    except Exception as exc:
        raise HTTPException(500, f"HA MQTT reconnect failed: {exc}")


@app.post("/ha-mqtt/disconnect")
def ha_mqtt_disconnect():
    _ha_mqtt.disconnect()
    return {"connected": False}


# ---------------------------------------------------------------------------
# Plugin management endpoints
# ---------------------------------------------------------------------------

def _redact_plugin_config(manifest: dict, config: dict) -> dict:
    redacted = dict(config)
    for field in manifest.get("config_schema", []):
        if field.get("type") == "password" and redacted.get(field["key"]):
            redacted[field["key"]] = "**redacted**"
    return redacted


def _get_block_method_settings(db: Session) -> tuple[str, str]:
    method_row    = db.get(Setting, "block_method")
    plugin_id_row = db.get(Setting, "block_plugin_id")
    method    = (method_row.value    if method_row    else None) or "arp"
    plugin_id = (plugin_id_row.value if plugin_id_row else None) or ""
    return method, plugin_id


async def _execute_block(mac: str, ip: Optional[str], db: Session, action: str) -> None:
    """
    Unified blocking coordinator (synchronous path, raises HTTPException on failure).
    action: "block" or "unblock"
    """
    method, plugin_id = _get_block_method_settings(db)

    if method == "arp":
        try:
            async with _probe_client(timeout=15.0) as client:
                if action == "block":
                    resp = await client.post(f"{PROBE_URL}/block/{mac.lower()}")
                else:
                    resp = await client.delete(f"{PROBE_URL}/block/{mac.lower()}")
                if resp.status_code >= 400:
                    raise HTTPException(502, f"Probe error: {resp.text[:200]}")
        except httpx.ConnectError:
            raise HTTPException(502, f"Cannot reach probe at {PROBE_URL}")
    else:
        if not plugin_id:
            raise HTTPException(400, "block_plugin_id is not configured")
        plugin = _plugin_registry.get(plugin_id)
        if not plugin or not plugin.get("enabled"):
            raise HTTPException(400, f"Blocking plugin '{plugin_id}' is not enabled")
        action_name = "block_client" if action == "block" else "unblock_client"
        if action_name not in (plugin["manifest"].get("actions") or {}):
            raise HTTPException(400, f"Plugin '{plugin_id}' has no '{action_name}' action")
        mac_lower = mac.lower()
        mac_dash  = mac_lower.replace(":", "-").upper()
        print(f"[block-coord] {action} via plugin '{plugin_id}': mac={mac_lower} mac_dash={mac_dash} ip={ip}", flush=True)
        result = await _plugin_runner.execute_action(
            plugin_id, action_name, {"mac": mac_lower, "mac_dash": mac_dash, "ip": ip or ""}
        )
        print(f"[block-coord] {action} result: ok={result.get('ok')} error={result.get('error')} status={result.get('status_code')} api_code={result.get('api_error_code')}", flush=True)
        if not result.get("ok"):
            raise HTTPException(502, f"Plugin block failed: {result.get('error', 'unknown error')}")


async def _execute_block_bg(mac: str, ip: Optional[str], action: str) -> None:
    """
    Blocking coordinator for background loops — logs failures instead of raising.
    action: "block" or "unblock"
    """
    db = SessionLocal()
    try:
        method, plugin_id = _get_block_method_settings(db)
    finally:
        db.close()

    if method == "arp":
        try:
            async with _probe_client(timeout=10) as c:
                if action == "block":
                    await c.post(f"{PROBE_URL}/block/{mac.lower()}")
                else:
                    await c.delete(f"{PROBE_URL}/block/{mac.lower()}")
        except Exception as exc:
            print(f"[block-coord] ARP {action} {mac}: {exc}", flush=True)
    else:
        if not plugin_id:
            print(f"[block-coord] block_plugin_id not configured — skipping {action} for {mac}", flush=True)
            return
        plugin = _plugin_registry.get(plugin_id)
        if not plugin or not plugin.get("enabled"):
            print(f"[block-coord] Plugin '{plugin_id}' not enabled — skipping {action} for {mac}", flush=True)
            return
        action_name = "block_client" if action == "block" else "unblock_client"
        if action_name not in (plugin["manifest"].get("actions") or {}):
            print(f"[block-coord] Plugin '{plugin_id}' has no '{action_name}' action — skipping {mac}", flush=True)
            return
        mac_lower = mac.lower()
        mac_dash  = mac_lower.replace(":", "-").upper()
        try:
            result = await _plugin_runner.execute_action(
                plugin_id, action_name, {"mac": mac_lower, "mac_dash": mac_dash, "ip": ip or ""}
            )
            if not result.get("ok"):
                print(f"[block-coord] Plugin {action} {mac}: {result.get('error')}", flush=True)
        except Exception as exc:
            print(f"[block-coord] Plugin {action} {mac}: {exc}", flush=True)


def _plugin_to_dict(plugin_info: dict) -> dict:
    manifest = plugin_info["manifest"]
    return {
        "id":                plugin_info["id"],
        "name":              manifest.get("name"),
        "version":           manifest.get("version"),
        "author":            manifest.get("author"),
        "description":       manifest.get("description"),
        "icon":              manifest.get("icon"),
        "homepage":          manifest.get("homepage"),
        "capabilities":      manifest.get("capabilities", []),
        "source":            plugin_info["source"],
        "enabled":           plugin_info["enabled"],
        "status":            plugin_info["status"],
        "last_error":        plugin_info["last_error"],
        "last_polled":       plugin_info.get("last_polled"),
        "last_device_count": plugin_info.get("last_device_count"),
        "config":            _redact_plugin_config(manifest, plugin_info.get("config") or {}),
        "manifest":          manifest,
    }


@app.get("/plugins")
def list_plugins(username: str = Depends(get_current_user)):
    return [_plugin_to_dict(p) for p in _plugin_registry.list_all()]


@app.get("/plugins/{plugin_id}")
def get_plugin(plugin_id: str, username: str = Depends(get_current_user)):
    plugin = _plugin_registry.get(plugin_id)
    if not plugin:
        raise HTTPException(404, "Plugin not found")
    return _plugin_to_dict({"id": plugin_id, **plugin})


@app.post("/plugins/upload", status_code=201)
async def upload_plugin(
    file: UploadFile = File(...),
    username: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    content = await file.read()
    fname   = file.filename or ""
    try:
        if fname.endswith((".yaml", ".yml")):
            try:
                import yaml as _yaml
                manifest = _yaml.safe_load(content)
            except ImportError:
                raise HTTPException(
                    400, "YAML support requires pyyaml — upload as JSON instead"
                )
        else:
            manifest = json.loads(content)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, f"Could not parse manifest: {exc}")

    try:
        validate_manifest(manifest)
    except PluginValidationError as exc:
        raise HTTPException(400, str(exc))

    pid = manifest["id"]
    existing = _plugin_registry.get(pid)
    if existing and existing["source"] == "builtin":
        raise HTTPException(400, f"Plugin ID '{pid}' conflicts with a built-in plugin")

    try:
        _plugin_registry.add_uploaded(manifest)
        db.execute(
            text("""
                INSERT INTO plugins
                    (plugin_id, display_name, version, enabled,
                     manifest, config, install_source, status)
                VALUES (:pid, :name, :ver, false,
                        CAST(:manifest AS jsonb), CAST('{}' AS jsonb), 'uploaded', 'disabled')
                ON CONFLICT (plugin_id) DO UPDATE
                    SET manifest = EXCLUDED.manifest,
                        display_name = EXCLUDED.display_name,
                        version = EXCLUDED.version
            """),
            {
                "pid":      pid,
                "name":     manifest.get("name", pid),
                "ver":      manifest.get("version", "1.0.0"),
                "manifest": json.dumps(manifest),
            },
        )
        db.commit()
    except PluginValidationError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        db.rollback()
        _plugin_registry.remove(pid)
        raise HTTPException(500, f"Database error: {exc}")

    return {"id": pid, "name": manifest.get("name"), "status": "disabled"}


@app.put("/plugins/{plugin_id}/config")
def save_plugin_config(
    plugin_id: str,
    payload: PluginConfigSave,
    username: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    plugin = _plugin_registry.get(plugin_id)
    if not plugin:
        raise HTTPException(404, "Plugin not found")

    manifest      = plugin["manifest"]
    existing_cfg  = plugin.get("config") or {}
    password_keys = {
        f["key"] for f in manifest.get("config_schema", [])
        if f.get("type") == "password"
    }

    encrypted = dict(payload.config)
    for key in password_keys:
        val = encrypted.get(key, "")
        if val == "**redacted**":
            encrypted[key] = existing_cfg.get(key, "")  # keep existing encrypted value
        elif val:
            encrypted[key] = encrypt_field(val)

    # For the HA plugin: keep legacy settings table in sync
    if plugin_id == "home-assistant":
        ha_mapping = {
            "host":             "ha_mqtt_host",
            "port":             "ha_mqtt_port",
            "user":             "ha_mqtt_user",
            "password":         "ha_mqtt_password",
            "discovery_prefix": "ha_mqtt_discovery_prefix",
            "state_prefix":     "ha_mqtt_state_prefix",
        }
        for cfg_key, setting_key in ha_mapping.items():
            val = encrypted.get(cfg_key, "")
            if cfg_key == "password" and val:
                val = decrypt_field(val)  # settings table stores plaintext
            s = db.get(Setting, setting_key)
            if s:
                s.value = str(val)
            else:
                db.add(Setting(key=setting_key, value=str(val), description=""))

    try:
        db.execute(
            text("UPDATE plugins SET config = CAST(:cfg AS jsonb) WHERE plugin_id = :pid"),
            {"cfg": json.dumps(encrypted), "pid": plugin_id},
        )
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(500, f"Failed to save plugin config: {exc}")
    _plugin_registry.update_config(plugin_id, encrypted)
    _plugin_runner.clear_session(plugin_id)
    return {"ok": True}


@app.patch("/plugins/{plugin_id}/enable")
def enable_plugin(
    plugin_id: str,
    username: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    plugin = _plugin_registry.get(plugin_id)
    if not plugin:
        raise HTTPException(404, "Plugin not found")

    db.execute(
        text("UPDATE plugins SET enabled = true, status = 'active' WHERE plugin_id = :pid"),
        {"pid": plugin_id},
    )
    # For HA plugin: keep legacy enabled setting in sync and start connection
    if plugin_id == "home-assistant":
        s = db.get(Setting, "ha_mqtt_enabled")
        if s:
            s.value = "true"
        else:
            db.add(Setting(key="ha_mqtt_enabled", value="true", description=""))
    db.commit()
    _plugin_registry.set_enabled(plugin_id, True, "active")

    if plugin_id == "home-assistant":
        db2 = SessionLocal()
        try:
            _ha_startup_connect(db2)
        finally:
            db2.close()

    return {"ok": True, "enabled": True}


@app.patch("/plugins/{plugin_id}/disable")
def disable_plugin(
    plugin_id: str,
    username: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    plugin = _plugin_registry.get(plugin_id)
    if not plugin:
        raise HTTPException(404, "Plugin not found")

    db.execute(
        text("UPDATE plugins SET enabled = false, status = 'disabled' WHERE plugin_id = :pid"),
        {"pid": plugin_id},
    )
    if plugin_id == "home-assistant":
        s = db.get(Setting, "ha_mqtt_enabled")
        if s:
            s.value = "false"
        _ha_mqtt.disconnect()
    db.commit()
    _plugin_registry.set_enabled(plugin_id, False, "disabled")
    _plugin_runner.clear_session(plugin_id)
    return {"ok": True, "enabled": False}


@app.delete("/plugins/{plugin_id}")
def delete_plugin(
    plugin_id: str,
    username: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    plugin = _plugin_registry.get(plugin_id)
    if not plugin:
        raise HTTPException(404, "Plugin not found")
    if plugin["source"] == "builtin":
        raise HTTPException(400, "Built-in plugins cannot be deleted — disable them instead")

    db.execute(text("DELETE FROM plugins WHERE plugin_id = :pid"), {"pid": plugin_id})
    db.execute(text("DELETE FROM plugin_device_data WHERE plugin_id = :pid"), {"pid": plugin_id})
    db.commit()
    _plugin_registry.remove(plugin_id)
    return {"ok": True}


@app.post("/plugins/{plugin_id}/test")
async def test_plugin_connection(
    plugin_id: str,
    username: str = Depends(get_current_user),
):
    plugin = _plugin_registry.get(plugin_id)
    if not plugin:
        raise HTTPException(404, "Plugin not found")
    result = await _plugin_runner.execute_action(plugin_id, "test_connection")
    return result


@app.post("/plugins/{plugin_id}/poll")
async def poll_plugin_now(
    plugin_id: str,
    username: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Manually trigger the plugin's polling action and upsert discovered devices immediately."""
    plugin = _plugin_registry.get(plugin_id)
    if not plugin:
        raise HTTPException(404, "Plugin not found")
    polling = plugin["manifest"].get("polling") or {}
    action  = polling.get("action")
    actions = polling.get("actions") or ([action] if action else [])
    if not actions:
        raise HTTPException(400, "This plugin has no polling action configured")
    await _plugin_scheduler._poll_plugin(plugin_id, actions)
    updated = _plugin_registry.get(plugin_id)
    ok = updated.get("status") == "active"
    return {
        "ok":                ok,
        "status":            updated.get("status"),
        "error":             updated.get("last_error") if not ok else None,
        "last_device_count": updated.get("last_device_count"),
    }


@app.get("/plugins/{plugin_id}/data")
def get_plugin_data(
    plugin_id: str,
    username: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = db.execute(
        text("""
            SELECT mac_address, data, updated_at
            FROM plugin_device_data
            WHERE plugin_id = :pid
            ORDER BY updated_at DESC
        """),
        {"pid": plugin_id},
    ).fetchall()
    return [
        {
            "mac":        r.mac_address,
            "data":       r.data,
            "updated_at": r.updated_at.isoformat() if r.updated_at else None,
        }
        for r in rows
    ]


@app.post("/plugins/{plugin_id}/webhook")
async def plugin_webhook(plugin_id: str, request: Request, db: Session = Depends(get_db)):
    plugin = _plugin_registry.get(plugin_id)
    if not plugin or not plugin.get("enabled"):
        raise HTTPException(404, "Plugin not found or disabled")

    body_bytes = await request.body()

    # Optional HMAC-SHA256 signature validation
    cfg = get_decrypted_config(plugin["manifest"], plugin.get("config") or {})
    secret = cfg.get("webhook_secret", "")
    if secret:
        sig_header = request.headers.get("X-Hub-Signature-256", "")
        if not verify_webhook_signature(body_bytes, secret, sig_header):
            raise HTTPException(403, "Invalid webhook signature")

    try:
        payload = json.loads(body_bytes) if body_bytes else {}
    except Exception:
        raise HTTPException(400, "Invalid JSON payload")

    # Find the action marked trigger=webhook
    actions = plugin["manifest"].get("actions") or {}
    action_def = next(
        (a for a in actions.values() if a.get("trigger") == "webhook"),
        None,
    )
    if not action_def:
        raise HTTPException(422, "No webhook-triggered action defined in plugin manifest")

    action_name = next(k for k, v in actions.items() if v is action_def)

    result = await _plugin_runner.execute_action(plugin_id, action_name, payload)
    if not result.get("ok"):
        raise HTTPException(502, result.get("error", "Plugin action failed"))

    # Feed discovered devices into the event bus
    for dev in (result.get("devices") or []):
        mac = dev.get("mac_address", "")
        if mac:
            event = "device.online" if dev.get("is_online", True) else "device.offline"
            asyncio.ensure_future(_plugin_event_bus.notify(event, {
                "mac": mac, "ip": dev.get("ip_address", ""), "name": dev.get("hostname", ""),
            }))

    return {"ok": True, "devices_received": len(result.get("devices") or [])}


@app.get("/notifications/channels")
def list_channels(db: Session = Depends(get_db)):
    rows = db.execute(text("SELECT * FROM notification_channels ORDER BY created_at")).fetchall()
    result = []
    for r in rows:
        result.append({
            "id": r.id, "name": r.name, "service": r.service,
            "config": r.config if isinstance(r.config, dict) else {},
            "enabled": r.enabled,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        })
    return result


@app.post("/notifications/channels", status_code=201)
def create_channel(payload: ChannelCreate, db: Session = Depends(get_db)):
    if payload.service == "home_assistant":
        try:
            _ha_build_url(payload.config)
        except ValueError as e:
            raise HTTPException(400, str(e))
    elif payload.service not in ("toast", "browser"):
        if not _build_apprise_url(payload.service, payload.config):
            raise HTTPException(400, "Invalid channel configuration — could not build a notification URL")
    result = db.execute(text("""
        INSERT INTO notification_channels (name, service, config, enabled)
        VALUES (:n, :s, :c, :e) RETURNING id, name, service, config, enabled, created_at
    """), {"n": payload.name, "s": payload.service,
           "c": json.dumps(payload.config), "e": payload.enabled})
    db.commit()
    row = db.execute(text("SELECT * FROM notification_channels WHERE id = :id"),
                     {"id": result.fetchone()[0]}).fetchone()
    return {
        "id": row.id, "name": row.name, "service": row.service,
        "config": row.config if isinstance(row.config, dict) else {},
        "enabled": row.enabled,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@app.put("/notifications/channels/{channel_id}")
def update_channel(channel_id: int, payload: ChannelCreate, db: Session = Depends(get_db)):
    row = db.execute(text("SELECT id FROM notification_channels WHERE id = :id"),
                     {"id": channel_id}).fetchone()
    if not row:
        raise HTTPException(404, "Channel not found")
    if payload.service == "home_assistant":
        try:
            _ha_build_url(payload.config)
        except ValueError as e:
            raise HTTPException(400, str(e))
    elif payload.service not in ("toast", "browser"):
        if not _build_apprise_url(payload.service, payload.config):
            raise HTTPException(400, "Invalid channel configuration")
    db.execute(text("""
        UPDATE notification_channels SET name=:n, service=:s, config=:c, enabled=:e
        WHERE id=:id
    """), {"n": payload.name, "s": payload.service,
           "c": json.dumps(payload.config), "e": payload.enabled, "id": channel_id})
    db.commit()
    row = db.execute(text("SELECT * FROM notification_channels WHERE id = :id"),
                     {"id": channel_id}).fetchone()
    return {
        "id": row.id, "name": row.name, "service": row.service,
        "config": row.config if isinstance(row.config, dict) else {},
        "enabled": row.enabled,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@app.delete("/notifications/channels/{channel_id}")
def delete_channel(channel_id: int, db: Session = Depends(get_db)):
    db.execute(text("DELETE FROM notification_channels WHERE id = :id"), {"id": channel_id})
    db.commit()
    return {"deleted": True}


@app.post("/notifications/channels/{channel_id}/test")
async def test_channel(channel_id: int, db: Session = Depends(get_db)):
    row = db.execute(text("SELECT service, config FROM notification_channels WHERE id = :id"),
                     {"id": channel_id}).fetchone()
    if not row:
        raise HTTPException(404, "Channel not found")
    svc, cfg = row
    if svc in ("toast", "browser"):
        return {"sent": True}
    config = cfg if isinstance(cfg, dict) else (json.loads(cfg) if isinstance(cfg, str) else {})
    if svc == "home_assistant":
        try:
            await _notify_home_assistant(config, "InSpectre Test", "This is a test notification from InSpectre.")
            return {"sent": True}
        except Exception as exc:
            print(f"[notify-test] home_assistant error: {type(exc).__name__}: {exc}", flush=True)
            raise HTTPException(502, f"Home Assistant notification failed: {exc}")
    url = _build_apprise_url(svc, config)
    if not url:
        present = list(config.keys())
        raise HTTPException(400, f"Cannot build notification URL for '{svc}' — config keys: {present}. Re-save the channel.")
    try:
        import apprise as _apprise
        import logging as _logging
        _al = _logging.getLogger("apprise")
        _al.setLevel(_logging.DEBUG)
        _buf: list = []
        _h = _logging.StreamHandler(type("_S", (), {"write": lambda s, m: _buf.append(m), "flush": lambda s: None})())
        _h.setLevel(_logging.WARNING)
        _al.addHandler(_h)
        a = _apprise.Apprise()
        added = a.add(url)
        if not added:
            raise HTTPException(400, f"Apprise did not recognise the '{svc}' URL — check credentials or missing dependency")
        ok = await asyncio.to_thread(a.notify,
                                     title="InSpectre Test",
                                     body="This is a test notification from InSpectre.")
        _al.removeHandler(_h)
        if not ok:
            detail = " | ".join(_buf[-3:]) if _buf else "check credentials and connectivity"
            raise HTTPException(502, f"Apprise could not send to {svc}: {detail}")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, f"Notification error ({svc}): {exc}")
    return {"sent": True}


@app.get("/notifications/profiles")
def list_profiles(db: Session = Depends(get_db)):
    profiles = db.execute(text("SELECT * FROM notification_profiles ORDER BY created_at")).fetchall()
    result = []
    for p in profiles:
        ch_ids = db.execute(text(
            "SELECT channel_id FROM notification_profile_channels WHERE profile_id = :pid"
        ), {"pid": p.id}).scalars().all()
        result.append({
            "id": p.id, "name": p.name,
            "events": p.events if isinstance(p.events, dict) else {},
            "channel_ids": list(ch_ids),
            "created_at": p.created_at.isoformat() if p.created_at else None,
        })
    return result


@app.post("/notifications/profiles", status_code=201)
def create_profile(payload: ProfileCreate, db: Session = Depends(get_db)):
    result = db.execute(text("""
        INSERT INTO notification_profiles (name, events)
        VALUES (:n, :e) RETURNING id
    """), {"n": payload.name, "e": json.dumps(payload.events)})
    profile_id = result.scalar()
    for cid in payload.channel_ids:
        db.execute(text("""
            INSERT INTO notification_profile_channels (profile_id, channel_id)
            VALUES (:p, :c) ON CONFLICT DO NOTHING
        """), {"p": profile_id, "c": cid})
    db.commit()
    return {"id": profile_id, "name": payload.name, "events": payload.events,
            "channel_ids": payload.channel_ids}


@app.put("/notifications/profiles/{profile_id}")
def update_profile(profile_id: int, payload: ProfileCreate, db: Session = Depends(get_db)):
    row = db.execute(text("SELECT id FROM notification_profiles WHERE id = :id"),
                     {"id": profile_id}).fetchone()
    if not row:
        raise HTTPException(404, "Profile not found")
    db.execute(text("""
        UPDATE notification_profiles SET name=:n, events=:e WHERE id=:id
    """), {"n": payload.name, "e": json.dumps(payload.events), "id": profile_id})
    db.execute(text("DELETE FROM notification_profile_channels WHERE profile_id=:pid"),
               {"pid": profile_id})
    for cid in payload.channel_ids:
        db.execute(text("""
            INSERT INTO notification_profile_channels (profile_id, channel_id)
            VALUES (:p, :c) ON CONFLICT DO NOTHING
        """), {"p": profile_id, "c": cid})
    db.commit()
    return {"id": profile_id, "name": payload.name, "events": payload.events,
            "channel_ids": payload.channel_ids}


@app.delete("/notifications/profiles/{profile_id}")
def delete_profile(profile_id: int, db: Session = Depends(get_db)):
    db.execute(text("DELETE FROM notification_profiles WHERE id = :id"), {"id": profile_id})
    db.commit()
    return {"deleted": True}


@app.get("/notifications/pending")
def get_pending_notifications():
    """Return and clear the queue of pending browser notifications."""
    items = list(_pending_browser_notifications)
    _pending_browser_notifications.clear()
    return {"notifications": items}


# ---------------------------------------------------------------------------
# Fingerprints
# ---------------------------------------------------------------------------
@app.get("/fingerprints")
def get_fingerprints(db: Session = Depends(get_db)):
    fps = db.query(FingerprintEntry).order_by(FingerprintEntry.updated_at.desc()).all()
    return [
        {"id": fp.id, "oui_prefix": fp.oui_prefix, "hostname_pattern": fp.hostname_pattern,
         "open_ports": fp.open_ports, "device_type": fp.device_type, "vendor_name": fp.vendor_name,
         "confidence_score": fp.confidence_score, "hit_count": fp.hit_count, "source": fp.source,
         "created_at": fp.created_at.isoformat() if fp.created_at else None,
         "updated_at": fp.updated_at.isoformat() if fp.updated_at else None}
        for fp in fps
    ]


@app.get("/fingerprints/stats")
def fingerprint_stats(db: Session = Depends(get_db)):
    total     = db.query(FingerprintEntry).count()
    manual    = db.query(FingerprintEntry).filter(FingerprintEntry.source == 'manual').count()
    community = db.query(FingerprintEntry).filter(FingerprintEntry.source == 'community').count()
    auto      = db.query(FingerprintEntry).filter(FingerprintEntry.source == 'auto').count()
    return {"total": total, "manual": manual, "community": community, "auto": auto}


@app.delete("/fingerprints/{fid}")
def delete_fingerprint(fid: int, db: Session = Depends(get_db)):
    fp = db.get(FingerprintEntry, fid)
    if not fp:
        raise HTTPException(404, "Fingerprint not found")
    db.delete(fp); db.commit()
    return {"deleted": fid}


# ---------------------------------------------------------------------------
# Export / Import
# ---------------------------------------------------------------------------
@app.get("/export/devices")
def export_devices_csv(db: Session = Depends(get_db)):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["mac_address", "ip_address", "hostname", "vendor", "vendor_override",
                     "device_type_override", "custom_name", "is_online", "is_important",
                     "location", "tags", "notes", "first_seen", "last_seen",
                     "vuln_severity", "vuln_last_scanned"])
    for d in db.query(Device).all():
        writer.writerow([d.mac_address, d.ip_address, d.hostname, d.vendor,
                         getattr(d, 'vendor_override', None), getattr(d, 'device_type_override', None),
                         d.custom_name, d.is_online, getattr(d, 'is_important', False),
                         getattr(d, 'location', None), getattr(d, 'tags', None),
                         getattr(d, 'notes', None), d.first_seen, d.last_seen,
                         getattr(d, 'vuln_severity', None), getattr(d, 'vuln_last_scanned', None)])
    buf.seek(0)
    return StreamingResponse(buf, media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=inspectre-devices.csv"})


@app.get("/reports/inventory.csv")
def export_inventory(db: Session = Depends(get_db)):
    devices = db.query(Device).order_by(Device.last_seen.desc()).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["MAC", "IP", "Hostname", "Custom Name", "Vendor", "Device Type",
                "Online", "First Seen", "Last Seen", "Deep Scanned",
                "Important", "Tags", "Location", "Notes", "Identity Score",
                "Vuln Severity", "Vuln Last Scanned"])
    for d in devices:
        score = _identity_score(d)["score"]
        dtype = getattr(d, 'device_type_override', None) or _infer_device_type(d) or ""
        w.writerow([d.mac_address, d.ip_address or "", d.hostname or "",
                    d.custom_name or "", d.vendor or "", dtype,
                    d.is_online, d.first_seen, d.last_seen, d.deep_scanned,
                    bool(getattr(d, 'is_important', False)),
                    getattr(d, 'tags', None) or "", getattr(d, 'location', None) or "",
                    getattr(d, 'notes', None) or "", score,
                    getattr(d, 'vuln_severity', None) or "",
                    getattr(d, 'vuln_last_scanned', None) or ""])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=inspectre-inventory.csv"})


@app.get("/reports/events.csv")
def export_events_csv(limit: int = Query(1000, ge=1, le=10000), db: Session = Depends(get_db)):
    rows = db.execute(text("""
        SELECT de.created_at, de.type, de.mac_address,
               COALESCE(d.custom_name, d.hostname, d.ip_address, de.mac_address),
               d.ip_address, d.vendor, de.detail::text
        FROM device_events de
        JOIN devices d ON d.mac_address = de.mac_address
        ORDER BY de.created_at DESC LIMIT :limit
    """), {"limit": limit}).fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Timestamp", "Event", "MAC", "Device Name", "IP", "Vendor", "Detail"])
    for r in rows:
        w.writerow([r[0], r[1], r[2], r[3], r[4], r[5], r[6]])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=inspectre-events.csv"})


@app.get("/export/fingerprints")
def export_fingerprints_json(db: Session = Depends(get_db)):
    fps = db.query(FingerprintEntry).all()
    data = [
        {"oui_prefix": fp.oui_prefix, "hostname_pattern": fp.hostname_pattern,
         "open_ports": fp.open_ports, "device_type": fp.device_type,
         "vendor_name": fp.vendor_name, "confidence_score": fp.confidence_score,
         "hit_count": fp.hit_count, "source": fp.source}
        for fp in fps
    ]
    return Response(content=json.dumps(data, indent=2), media_type="application/json",
                    headers={"Content-Disposition": "attachment; filename=inspectre-fingerprints.json"})


@app.post("/import/fingerprints")
async def import_fingerprints_json(file: UploadFile = File(...), db: Session = Depends(get_db)):
    content = await file.read()
    try:
        entries = json.loads(content)
        if not isinstance(entries, list):
            raise ValueError("Expected a JSON array")
    except Exception as exc:
        raise HTTPException(400, f"Invalid JSON: {exc}")
    inserted = merged = 0
    for entry in entries:
        device_type = entry.get("device_type", "").strip()
        if not device_type: continue
        oui_prefix       = (entry.get("oui_prefix") or "").strip().lower() or None
        vendor_name      = (entry.get("vendor_name") or "").strip() or None
        open_ports       = entry.get("open_ports") or None
        hostname_pattern = (entry.get("hostname_pattern") or "").strip() or None
        confidence       = float(entry.get("confidence_score", 1.0))
        hit_count        = int(entry.get("hit_count", 1))
        source           = entry.get("source", "community")
        existing = None
        if oui_prefix:
            existing = (
                db.query(FingerprintEntry)
                .filter(FingerprintEntry.oui_prefix == oui_prefix,
                        FingerprintEntry.device_type == device_type)
                .first()
            )
        if existing:
            existing.hit_count        += hit_count
            existing.confidence_score  = max(existing.confidence_score, confidence)
            if vendor_name and not existing.vendor_name:
                existing.vendor_name = vendor_name
            merged += 1
        else:
            db.add(FingerprintEntry(
                oui_prefix=oui_prefix, hostname_pattern=hostname_pattern,
                open_ports=open_ports, device_type=device_type,
                vendor_name=vendor_name, confidence_score=confidence,
                hit_count=hit_count,
                source=source if source in ('manual', 'community', 'auto') else 'community',
            ))
            inserted += 1
    db.commit()
    all_fps = db.query(FingerprintEntry).all()
    devices = db.query(Device).filter(
        (Device.device_type_override == None) | (Device.device_type_override == "")
    ).all()
    corrected = 0
    for device in devices:
        best = _match_fingerprints(device, all_fps)
        if best:
            device.device_type_override = best.device_type
            if best.vendor_name and not device.vendor_override:
                device.vendor_override = best.vendor_name
            corrected += 1
            best.hit_count += 1
    db.commit()
    return {"inserted": inserted, "merged": merged, "corrected": corrected}


# ---------------------------------------------------------------------------
# Database backup / restore
# ---------------------------------------------------------------------------
def _encrypt_backup(plaintext: bytes, password: str) -> bytes:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt  = os.urandom(16)
    key   = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000).derive(password.encode())
    nonce = os.urandom(12)
    ct    = AESGCM(key).encrypt(nonce, plaintext, None)  # 16-byte GCM tag appended by library
    return b"IENC1" + salt + nonce + ct

def _decrypt_backup(data: bytes, password: str) -> bytes:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not data.startswith(b"IENC1"):
        raise ValueError("Not an encrypted backup")
    salt  = data[5:21]
    nonce = data[21:33]
    ct    = data[33:]
    key   = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000).derive(password.encode())
    return AESGCM(key).decrypt(nonce, ct, None)  # raises InvalidTag on wrong password


@app.post("/export/backup")
def export_backup(password: str = Form(""), db: Session = Depends(get_db)):
    """Export all user data as a portable JSON backup (version 2)."""

    def _rows(sql, *params):
        return db.execute(text(sql), *params).fetchall()

    # Devices
    devices = [_to_dict(d) for d in db.query(Device).all()]

    # Device events
    events = [
        {"id": r[0], "mac_address": r[1], "type": r[2],
         "detail": r[3], "created_at": r[4].isoformat() if r[4] else None}
        for r in _rows(
            "SELECT id, mac_address, type, detail, created_at "
            "FROM device_events ORDER BY created_at"
        )
    ]

    # Vulnerability reports
    vuln_reports = [
        {"id": r[0], "mac_address": r[1], "ip_address": r[2],
         "scanned_at": r[3].isoformat() if r[3] else None,
         "duration_s": r[4], "severity": r[5], "vuln_count": r[6],
         "findings": r[7], "raw_output": r[8], "scan_args": r[9]}
        for r in _rows(
            "SELECT id, mac_address, ip_address, scanned_at, duration_s, "
            "severity, vuln_count, findings, raw_output, scan_args "
            "FROM vuln_reports ORDER BY scanned_at"
        )
    ]

    # IP history
    ip_history = [
        {"id": r[0], "mac_address": r[1], "ip_address": r[2],
         "first_seen": r[3].isoformat() if r[3] else None,
         "last_seen": r[4].isoformat() if r[4] else None}
        for r in _rows(
            "SELECT id, mac_address, ip_address, first_seen, last_seen FROM ip_history"
        )
    ]

    # Settings
    settings = [{"key": s.key, "value": s.value} for s in db.query(Setting).all()]

    # Fingerprints
    fps = [
        {"oui_prefix": f.oui_prefix, "device_type": f.device_type,
         "vendor_name": f.vendor_name, "open_ports": f.open_ports,
         "hostname_pattern": f.hostname_pattern,
         "confidence_score": f.confidence_score, "source": f.source}
        for f in db.query(FingerprintEntry).all()
    ]

    # Users (password hashes included so credentials survive restore)
    users = [
        {"username": r[0], "password_hash": r[1],
         "is_admin": r[2], "must_change_password": r[3]}
        for r in _rows(
            "SELECT username, password_hash, is_admin, must_change_password FROM users"
        )
    ]

    # Alert suppressions
    suppressions = []
    try:
        suppressions = [
            {"id": r[0], "mac_address": r[1], "event_type": r[2],
             "reason": r[3],
             "expires_at": r[4].isoformat() if r[4] else None,
             "created_at": r[5].isoformat() if r[5] else None}
            for r in _rows(
                "SELECT id, mac_address, event_type, reason, expires_at, created_at "
                "FROM alert_suppressions"
            )
        ]
    except Exception:
        pass

    # Saved views
    saved_views = []
    try:
        saved_views = [
            {"id": r[0], "name": r[1], "description": r[2], "filters": r[3],
             "created_at": r[4].isoformat() if r[4] else None,
             "updated_at": r[5].isoformat() if r[5] else None}
            for r in _rows(
                "SELECT id, name, description, filters, created_at, updated_at "
                "FROM saved_views"
            )
        ]
    except Exception:
        pass

    # Block schedules
    block_schedules = []
    try:
        block_schedules = [
            {"id": r[0], "mac_address": r[1], "label": r[2],
             "days_of_week": r[3], "start_time": r[4], "end_time": r[5],
             "enabled": r[6], "mac_addresses": r[7], "tags": r[8]}
            for r in _rows(
                "SELECT id, mac_address, label, days_of_week, start_time, end_time, "
                "enabled, mac_addresses, tags FROM block_schedules"
            )
        ]
    except Exception:
        pass

    # Speedtest history
    speedtest_results = []
    try:
        speedtest_results = [
            {"id": r[0], "tested_at": r[1].isoformat() if r[1] else None,
             "server": r[2], "ping_ms": r[3], "download_mbps": r[4],
             "upload_mbps": r[5], "raw_output": r[6]}
            for r in _rows(
                "SELECT id, tested_at, server, ping_ms, download_mbps, upload_mbps, raw_output "
                "FROM speedtest_results ORDER BY tested_at"
            )
        ]
    except Exception:
        pass

    payload = {
        "version": 2,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "devices": devices,
        "device_events": events,
        "vuln_reports": vuln_reports,
        "ip_history": ip_history,
        "settings": settings,
        "fingerprints": fps,
        "users": users,
        "alert_suppressions": suppressions,
        "saved_views": saved_views,
        "block_schedules": block_schedules,
        "speedtest_results": speedtest_results,
    }
    raw = json.dumps(payload, indent=2, default=str).encode()
    if password:
        content  = _encrypt_backup(raw, password)
        fname    = "inspectre_backup.ienc"
        mimetype = "application/octet-stream"
    else:
        content  = raw
        fname    = "inspectre_backup.json"
        mimetype = "application/json"
    return Response(
        content=content,
        media_type=mimetype,
        headers={"Content-Disposition": f"attachment; filename={fname}"},
    )


def _do_restore(payload: dict, db: Session) -> dict:
    """Full restore from a v1 or v2 backup payload. Returns stats dict."""
    from datetime import datetime as _dt_cls

    def _dt(val):
        if not val:
            return None
        try:
            return _dt_cls.fromisoformat(val)
        except Exception:
            return None

    def _json(val):
        if val is None:
            return None
        return val if isinstance(val, str) else json.dumps(val)

    stats = {
        "version": payload.get("version", 1),
        "settings": 0, "fingerprints": 0, "devices": 0,
        "device_events": 0, "vuln_reports": 0, "ip_history": 0,
        "users": 0, "alert_suppressions": 0, "saved_views": 0,
        "block_schedules": 0, "speedtest_results": 0,
    }

    # Settings — restore ALL keys without skipping
    for s in payload.get("settings", []):
        key, value = s.get("key"), s.get("value")
        if not key:
            continue
        existing = db.get(Setting, key)
        if existing:
            existing.value = str(value) if value is not None else ""
        else:
            db.add(Setting(key=key, value=str(value) if value is not None else "",
                           description="Restored from backup"))
        stats["settings"] += 1

    # Fingerprints — merge by (oui_prefix, device_type)
    for fp in payload.get("fingerprints", []):
        device_type = (fp.get("device_type") or "").strip()
        if not device_type:
            continue
        oui = (fp.get("oui_prefix") or "").strip().lower() or None
        existing = None
        if oui:
            existing = db.query(FingerprintEntry).filter(
                FingerprintEntry.oui_prefix == oui,
                FingerprintEntry.device_type == device_type,
            ).first()
        if not existing:
            db.add(FingerprintEntry(
                oui_prefix=oui, device_type=device_type,
                vendor_name=fp.get("vendor_name"),
                open_ports=fp.get("open_ports"),
                hostname_pattern=fp.get("hostname_pattern"),
                confidence_score=float(fp.get("confidence_score", 1.0)),
                source=fp.get("source", "backup"), hit_count=1,
            ))
            stats["fingerprints"] += 1

    # Devices — upsert by mac_address (ORM)
    for d in payload.get("devices", []):
        mac = (d.get("mac_address") or "").strip().lower()
        if not mac:
            continue
        fields = dict(
            ip_address=d.get("ip_address"),
            hostname=d.get("hostname"),
            vendor=d.get("vendor"),
            custom_name=d.get("custom_name"),
            device_type_override=d.get("device_type_override"),
            vendor_override=d.get("vendor_override"),
            is_online=bool(d.get("is_online", False)),
            first_seen=_dt(d.get("first_seen")),
            last_seen=_dt(d.get("last_seen")),
            status_changed_at=_dt(d.get("status_changed_at")),
            scan_results=d.get("scan_results"),
            deep_scanned=bool(d.get("deep_scanned", False)),
            miss_count=int(d.get("miss_count") or 0),
            is_important=bool(d.get("is_important", False)),
            notes=d.get("notes"),
            tags=d.get("tags"),
            location=d.get("location"),
            vuln_last_scanned=_dt(d.get("vuln_last_scanned")),
            vuln_severity=d.get("vuln_severity"),
            is_blocked=bool(d.get("is_blocked", False)),
            zone=d.get("zone"),
            is_ignored=bool(d.get("is_ignored", False)),
            suppress_presence_events=bool(d.get("suppress_presence_events", False)),
            deep_scan_last_run=_dt(d.get("deep_scan_last_run")),
            baseline_ports=d.get("baseline_ports"),
            baseline_scan_count=int(d.get("baseline_scan_count") or 0),
            group_id=d.get("group_id"),
            group_primary=bool(d.get("group_primary", False)),
        )
        existing = db.get(Device, mac)
        if existing:
            for k, v in fields.items():
                setattr(existing, k, v)
        else:
            db.add(Device(mac_address=mac, **fields))
        stats["devices"] += 1

    db.flush()  # devices must be visible for FK checks below

    # Device events — insert by id, skip unknown MACs
    for ev in payload.get("device_events", []):
        ev_id = ev.get("id")
        mac = (ev.get("mac_address") or "").strip().lower()
        ev_type = ev.get("type")
        if not mac or not ev_type:
            continue
        sp = db.begin_nested()
        try:
            if ev_id is not None:
                db.execute(text(
                    "INSERT INTO device_events (id, mac_address, type, detail, created_at) "
                    "SELECT :id, :mac, :etype, :detail::jsonb, :ts "
                    "WHERE EXISTS (SELECT 1 FROM devices WHERE mac_address = :mac) "
                    "ON CONFLICT (id) DO NOTHING"
                ), {"id": ev_id, "mac": mac, "etype": ev_type,
                    "detail": _json(ev.get("detail")), "ts": ev.get("created_at")})
            else:
                db.execute(text(
                    "INSERT INTO device_events (mac_address, type, detail, created_at) "
                    "SELECT :mac, :etype, :detail::jsonb, :ts "
                    "WHERE EXISTS (SELECT 1 FROM devices WHERE mac_address = :mac)"
                ), {"mac": mac, "etype": ev_type,
                    "detail": _json(ev.get("detail")), "ts": ev.get("created_at")})
            sp.commit()
            stats["device_events"] += 1
        except Exception:
            sp.rollback()

    # Vuln reports — insert by id, skip unknown MACs
    for vr in payload.get("vuln_reports", []):
        vr_id = vr.get("id")
        mac = (vr.get("mac_address") or "").strip().lower()
        if not mac or vr_id is None:
            continue
        sp = db.begin_nested()
        try:
            db.execute(text(
                "INSERT INTO vuln_reports "
                "(id, mac_address, ip_address, scanned_at, duration_s, severity, "
                " vuln_count, findings, raw_output, scan_args) "
                "SELECT :id, :mac, :ip, :scanned_at, :duration_s, :severity, "
                "       :vuln_count, :findings::jsonb, :raw_output, :scan_args "
                "WHERE EXISTS (SELECT 1 FROM devices WHERE mac_address = :mac) "
                "ON CONFLICT (id) DO NOTHING"
            ), {"id": vr_id, "mac": mac, "ip": vr.get("ip_address"),
                "scanned_at": vr.get("scanned_at"), "duration_s": vr.get("duration_s"),
                "severity": vr.get("severity", "clean"),
                "vuln_count": int(vr.get("vuln_count") or 0),
                "findings": _json(vr.get("findings")),
                "raw_output": vr.get("raw_output"), "scan_args": vr.get("scan_args")})
            sp.commit()
            stats["vuln_reports"] += 1
        except Exception:
            sp.rollback()

    # IP history — insert by id, skip unknown MACs
    for ih in payload.get("ip_history", []):
        ih_id = ih.get("id")
        mac = (ih.get("mac_address") or "").strip().lower()
        ip = ih.get("ip_address")
        if not mac or not ip or ih_id is None:
            continue
        sp = db.begin_nested()
        try:
            db.execute(text(
                "INSERT INTO ip_history (id, mac_address, ip_address, first_seen, last_seen) "
                "SELECT :id, :mac, :ip, :first_seen, :last_seen "
                "WHERE EXISTS (SELECT 1 FROM devices WHERE mac_address = :mac) "
                "ON CONFLICT (id) DO NOTHING"
            ), {"id": ih_id, "mac": mac, "ip": ip,
                "first_seen": ih.get("first_seen"), "last_seen": ih.get("last_seen")})
            sp.commit()
            stats["ip_history"] += 1
        except Exception:
            sp.rollback()

    # Users — upsert by username, restoring password hash
    for u in payload.get("users", []):
        username = (u.get("username") or "").strip()
        password_hash = u.get("password_hash")
        if not username or not password_hash:
            continue
        sp = db.begin_nested()
        try:
            db.execute(text(
                "INSERT INTO users (username, password_hash, is_admin, must_change_password) "
                "VALUES (:u, :h, :admin, :mcp) "
                "ON CONFLICT (username) DO UPDATE "
                "SET password_hash = EXCLUDED.password_hash, "
                "    is_admin = EXCLUDED.is_admin, "
                "    must_change_password = EXCLUDED.must_change_password"
            ), {"u": username, "h": password_hash,
                "admin": bool(u.get("is_admin", False)),
                "mcp": bool(u.get("must_change_password", False))})
            sp.commit()
            stats["users"] += 1
        except Exception:
            sp.rollback()

    # Alert suppressions
    for sup in payload.get("alert_suppressions", []):
        sup_id = sup.get("id")
        event_type = sup.get("event_type")
        if not event_type or sup_id is None:
            continue
        sp = db.begin_nested()
        try:
            db.execute(text(
                "INSERT INTO alert_suppressions "
                "(id, mac_address, event_type, reason, expires_at, created_at) "
                "VALUES (:id, :mac, :event_type, :reason, :expires_at, :created_at) "
                "ON CONFLICT (id) DO NOTHING"
            ), {"id": sup_id,
                "mac": (sup.get("mac_address") or "").strip().lower() or None,
                "event_type": event_type, "reason": sup.get("reason"),
                "expires_at": sup.get("expires_at"), "created_at": sup.get("created_at")})
            sp.commit()
            stats["alert_suppressions"] += 1
        except Exception:
            sp.rollback()

    # Saved views — upsert by name
    for sv in payload.get("saved_views", []):
        sv_name = (sv.get("name") or "").strip()
        if not sv_name:
            continue
        sp = db.begin_nested()
        try:
            db.execute(text(
                "INSERT INTO saved_views (name, description, filters, created_at, updated_at) "
                "VALUES (:name, :desc, :filters::jsonb, :created_at, :updated_at) "
                "ON CONFLICT (name) DO UPDATE "
                "SET description = EXCLUDED.description, filters = EXCLUDED.filters, "
                "    updated_at = EXCLUDED.updated_at"
            ), {"name": sv_name, "desc": sv.get("description"),
                "filters": _json(sv.get("filters") or {}),
                "created_at": sv.get("created_at"), "updated_at": sv.get("updated_at")})
            sp.commit()
            stats["saved_views"] += 1
        except Exception:
            sp.rollback()

    # Block schedules
    for bs in payload.get("block_schedules", []):
        bs_id = bs.get("id")
        if bs_id is None:
            continue
        sp = db.begin_nested()
        try:
            db.execute(text(
                "INSERT INTO block_schedules "
                "(id, mac_address, label, days_of_week, start_time, end_time, "
                " enabled, mac_addresses, tags) "
                "VALUES (:id, :mac, :label, :dow, :start_time, :end_time, "
                "        :enabled, :mac_addresses, :tags) "
                "ON CONFLICT (id) DO NOTHING"
            ), {"id": bs_id, "mac": bs.get("mac_address"), "label": bs.get("label"),
                "dow": bs.get("days_of_week", "mon,tue,wed,thu,fri,sat,sun"),
                "start_time": bs.get("start_time", "00:00"),
                "end_time": bs.get("end_time", "00:00"),
                "enabled": bool(bs.get("enabled", True)),
                "mac_addresses": bs.get("mac_addresses"),
                "tags": bs.get("tags", "")})
            sp.commit()
            stats["block_schedules"] += 1
        except Exception:
            sp.rollback()

    # Speedtest results
    for sr in payload.get("speedtest_results", []):
        sr_id = sr.get("id")
        if sr_id is None:
            continue
        sp = db.begin_nested()
        try:
            db.execute(text(
                "INSERT INTO speedtest_results "
                "(id, tested_at, server, ping_ms, download_mbps, upload_mbps, raw_output) "
                "VALUES (:id, :tested_at, :server, :ping_ms, :download_mbps, :upload_mbps, :raw_output) "
                "ON CONFLICT (id) DO NOTHING"
            ), {"id": sr_id, "tested_at": sr.get("tested_at"), "server": sr.get("server"),
                "ping_ms": sr.get("ping_ms"), "download_mbps": sr.get("download_mbps"),
                "upload_mbps": sr.get("upload_mbps"), "raw_output": sr.get("raw_output")})
            sp.commit()
            stats["speedtest_results"] += 1
        except Exception:
            sp.rollback()

    db.commit()

    # Reset SERIAL sequences so new inserts don't collide with restored IDs
    for tbl, col in [
        ("device_events", "id"), ("vuln_reports", "id"), ("ip_history", "id"),
        ("alert_suppressions", "id"), ("saved_views", "id"), ("block_schedules", "id"),
        ("speedtest_results", "id"),
    ]:
        try:
            db.execute(text(
                f"SELECT setval(pg_get_serial_sequence('{tbl}', '{col}'), "
                f"COALESCE((SELECT MAX({col}) FROM {tbl}), 0) + 1, false)"
            ))
        except Exception:
            pass
    db.commit()

    return stats


@app.post("/import/restore")
async def import_restore(file: UploadFile = File(...), password: str = Form(""), db: Session = Depends(get_db)):
    """Full restore from a v1 or v2 backup JSON (plain or encrypted)."""
    content = await file.read()
    if content[:5] == b"IENC1":
        if not password:
            raise HTTPException(400, "This backup is encrypted — enter the password before restoring")
        try:
            content = _decrypt_backup(content, password)
        except Exception:
            raise HTTPException(400, "Decryption failed — wrong password")
    try:
        payload = json.loads(content)
    except Exception as exc:
        raise HTTPException(400, f"Invalid JSON: {exc}")
    if not isinstance(payload, dict) or payload.get("version") not in (1, 2):
        raise HTTPException(400, "Unrecognised backup format (expected version 1 or 2)")
    return _do_restore(payload, db)


@app.post("/setup/restore-from-backup")
async def setup_restore_from_backup(file: UploadFile = File(...), password: str = Form(""), db: Session = Depends(get_db)):
    """Public endpoint: restore from backup during initial setup wizard.
    Restores all data including credentials and marks setup_complete = true."""
    content = await file.read()
    if content[:5] == b"IENC1":
        if not password:
            raise HTTPException(400, "This backup is encrypted — enter the password before restoring")
        try:
            content = _decrypt_backup(content, password)
        except Exception:
            raise HTTPException(400, "Decryption failed — wrong password")
    try:
        payload = json.loads(content)
    except Exception as exc:
        raise HTTPException(400, f"Invalid JSON: {exc}")
    if not isinstance(payload, dict) or payload.get("version") not in (1, 2):
        raise HTTPException(400, "Unrecognised backup format (expected version 1 or 2)")

    stats = _do_restore(payload, db)

    # Mark setup complete so the wizard doesn't reappear
    s = db.get(Setting, "setup_complete")
    if s:
        s.value = "true"
    else:
        db.add(Setting(key="setup_complete", value="true"))
    db.commit()

    return {"ok": True, "restored": stats}


# ---------------------------------------------------------------------------
# SSE streaming (ping / traceroute) — proxied through probe
# ---------------------------------------------------------------------------
@app.get("/devices/{mac}/ping")
async def stream_ping(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")

    target_ip = getattr(d, 'primary_ip', None) or d.ip_address

    async def _gen():
        try:
            async with _probe_client(timeout=None) as client:
                async with client.stream("GET", f"{PROBE_URL}/stream/ping/{target_ip}") as resp:
                    async for line in resp.aiter_lines():
                        yield f"{line}\n"
        except httpx.ConnectError:
            yield f"data: [ERROR] Cannot reach probe at {PROBE_URL}\n\n"
        except Exception as e:
            yield f"data: [ERROR] {e}\n\n"

    return StreamingResponse(_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/devices/{mac}/block")
async def block_device(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    await _execute_block(mac, d.ip_address, db, "block")
    d.is_blocked = True
    _add_event(db, mac.lower(), "blocked", {"ip": d.ip_address})
    db.commit(); db.refresh(d)
    asyncio.ensure_future(_plugin_event_bus.notify("device.blocked", {"mac": mac.lower(), "ip": d.ip_address or ""}))
    return _to_dict(d)


@app.post("/devices/{mac}/unblock")
async def unblock_device(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    await _execute_block(mac, d.ip_address, db, "unblock")
    d.is_blocked = False
    _add_event(db, mac.lower(), "unblocked", {"ip": d.ip_address})
    db.commit(); db.refresh(d)
    asyncio.ensure_future(_plugin_event_bus.notify("device.unblocked", {"mac": mac.lower(), "ip": d.ip_address or ""}))
    return _to_dict(d)


@app.get("/devices/{mac}/traceroute")
async def stream_traceroute(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")

    trace_ip = getattr(d, 'primary_ip', None) or d.ip_address

    async def _gen():
        try:
            async with _probe_client(timeout=None) as client:
                async with client.stream("GET", f"{PROBE_URL}/stream/traceroute/{trace_ip}") as resp:
                    async for line in resp.aiter_lines():
                        yield f"{line}\n"
        except httpx.ConnectError:
            yield f"data: [ERROR] Cannot reach probe at {PROBE_URL}\n\n"
        except Exception as e:
            yield f"data: [ERROR] {e}\n\n"

    return StreamingResponse(_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------------------
# Network Tools
# ---------------------------------------------------------------------------
import re as _re
import ssl as _ssl
import ipaddress as _ipaddress

_HOST_RE  = _re.compile(r'^[a-zA-Z0-9._\-]{1,253}$')
_PORTS_RE = _re.compile(r'^[\d,\-]{1,100}$')


def _validate_tool_host(host: str):
    if not host or not _HOST_RE.match(host):
        raise HTTPException(400, "Invalid host")


def _reject_ssrf_target(host: str):
    """Block SSRF to dangerous local ranges (loopback, link-local incl. cloud
    metadata 169.254.169.254, multicast, reserved). Private/LAN ranges remain
    allowed because inspecting LAN hosts is a core feature of this tool."""
    if not host:
        raise HTTPException(400, "Invalid host")
    candidates = []
    try:
        candidates = [_ipaddress.ip_address(host)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None)
            for info in infos:
                try:
                    candidates.append(_ipaddress.ip_address(info[4][0]))
                except ValueError:
                    continue
        except socket.gaierror:
            return  # let the actual request surface the DNS error
    for addr in candidates:
        if (addr.is_loopback or addr.is_link_local or addr.is_multicast
                or addr.is_reserved or addr.is_unspecified):
            raise HTTPException(400, "Refusing to connect to a restricted address")


def _validate_tool_url(url: str):
    if not url or not (url.startswith("http://") or url.startswith("https://")):
        raise HTTPException(400, "URL must start with http:// or https://")
    if len(url) > 2048:
        raise HTTPException(400, "URL too long")
    try:
        parsed = urlparse(url)
    except Exception:
        raise HTTPException(400, "Invalid URL")
    if not parsed.hostname:
        raise HTTPException(400, "Invalid URL host")
    _reject_ssrf_target(parsed.hostname)


@app.get("/tools/ping")
async def tools_ping(host: str = Query(...)):
    _validate_tool_host(host)

    async def _gen():
        try:
            async with _probe_client(timeout=None) as client:
                async with client.stream("GET", f"{PROBE_URL}/stream/tools/ping",
                                         params={"host": host}) as resp:
                    async for line in resp.aiter_lines():
                        yield f"{line}\n"
        except httpx.ConnectError:
            yield f"data: [ERROR] Cannot reach probe at {PROBE_URL}\n\n"
        except Exception as e:
            yield f"data: [ERROR] {e}\n\n"

    return StreamingResponse(_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/tools/traceroute")
async def tools_traceroute(host: str = Query(...)):
    _validate_tool_host(host)

    async def _gen():
        try:
            async with _probe_client(timeout=None) as client:
                async with client.stream("GET", f"{PROBE_URL}/stream/tools/traceroute",
                                         params={"host": host}) as resp:
                    async for line in resp.aiter_lines():
                        yield f"{line}\n"
        except httpx.ConnectError:
            yield f"data: [ERROR] Cannot reach probe at {PROBE_URL}\n\n"
        except Exception as e:
            yield f"data: [ERROR] {e}\n\n"

    return StreamingResponse(_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/tools/portscan")
async def tools_portscan(host: str = Query(...), ports: str = Query("1-1024")):
    _validate_tool_host(host)
    if not _PORTS_RE.match(ports):
        raise HTTPException(400, "Invalid ports specification")

    async def _gen():
        try:
            async with _probe_client(timeout=None) as client:
                async with client.stream("GET", f"{PROBE_URL}/stream/tools/portscan",
                                         params={"host": host, "ports": ports}) as resp:
                    async for line in resp.aiter_lines():
                        yield f"{line}\n"
        except httpx.ConnectError:
            yield f"data: [ERROR] Cannot reach probe at {PROBE_URL}\n\n"
        except Exception as e:
            yield f"data: [ERROR] {e}\n\n"

    return StreamingResponse(_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/tools/dns")
async def tools_dns(host: str = Query(...), type: str = Query("A")):
    import dns.resolver
    _validate_tool_host(host)
    ALL_TYPES = ["A", "AAAA", "MX", "CNAME", "TXT", "NS", "SOA", "PTR", "SRV", "CAA", "DNSKEY", "DS", "NAPTR"]
    valid_types = set(ALL_TYPES)
    qtype = type.upper()

    if qtype == "ALL":
        results = []
        for t in ALL_TYPES:
            try:
                answers = dns.resolver.resolve(host, t, lifetime=5)
                for r in answers:
                    results.append({"type": t, "value": str(r), "ttl": answers.rrset.ttl})
            except Exception:
                pass
        return {"host": host, "type": "ALL", "all_records": results, "error": None}

    if qtype not in valid_types:
        raise HTTPException(400, f"Type must be one of: {', '.join(sorted(valid_types))} or ALL")
    try:
        answers = dns.resolver.resolve(host, qtype, lifetime=10)
        return {"host": host, "type": qtype,
                "records": [str(r) for r in answers],
                "ttl": answers.rrset.ttl, "error": None}
    except dns.resolver.NXDOMAIN:
        return {"host": host, "type": qtype, "records": [], "ttl": None,
                "error": "NXDOMAIN — domain does not exist"}
    except dns.resolver.NoAnswer:
        return {"host": host, "type": qtype, "records": [], "ttl": None,
                "error": "No records of that type found"}
    except Exception as e:
        return {"host": host, "type": qtype, "records": [], "ttl": None, "error": str(e)}


@app.get("/tools/rdns")
async def tools_rdns(ip: str = Query(...)):
    try:
        _ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "Invalid IP address")
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return {"ip": ip, "hostname": hostname, "error": None}
    except socket.herror:
        return {"ip": ip, "hostname": None, "error": "No reverse DNS record found"}
    except Exception as e:
        return {"ip": ip, "hostname": None, "error": str(e)}


@app.get("/tools/dns-propagation")
async def tools_dns_propagation(host: str = Query(...), type: str = Query("A")):
    import dns.resolver
    _validate_tool_host(host)
    qtype = type.upper()
    if qtype not in {"A", "AAAA", "MX", "CNAME", "TXT", "NS"}:
        raise HTTPException(400, "Invalid record type")

    servers = {
        "Google (8.8.8.8)":         "8.8.8.8",
        "Google (8.8.4.4)":         "8.8.4.4",
        "Cloudflare (1.1.1.1)":     "1.1.1.1",
        "Cloudflare (1.0.0.1)":     "1.0.0.1",
        "OpenDNS (208.67.222.222)": "208.67.222.222",
        "OpenDNS (208.67.220.220)": "208.67.220.220",
        "Quad9 (9.9.9.9)":          "9.9.9.9",
        "AdGuard (94.140.14.14)":   "94.140.14.14",
    }

    async def _query(name: str, ns_ip: str) -> dict:
        def _resolve():
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [ns_ip]
            resolver.timeout = 4
            resolver.lifetime = 4
            return [str(r) for r in resolver.resolve(host, qtype)]
        try:
            records = await asyncio.get_event_loop().run_in_executor(None, _resolve)
            return {"name": name, "ip": ns_ip, "records": records, "error": None}
        except dns.resolver.NXDOMAIN:
            return {"name": name, "ip": ns_ip, "records": [], "error": "NXDOMAIN"}
        except dns.resolver.NoAnswer:
            return {"name": name, "ip": ns_ip, "records": [], "error": "No answer"}
        except Exception as e:
            return {"name": name, "ip": ns_ip, "records": [], "error": str(e)[:80]}

    results = await asyncio.gather(*[_query(n, ip) for n, ip in servers.items()])
    return {"host": host, "type": qtype, "results": results}


@app.get("/tools/http-headers")
async def tools_http_headers(url: str = Query(...)):
    _validate_tool_url(url)
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False, verify=False) as client:
            resp = await client.get(url)
            return {
                "url": url,
                "status": resp.status_code,
                "reason": resp.reason_phrase,
                "headers": dict(resp.headers),
                "redirect": resp.headers.get("location"),
            }
    except httpx.ConnectError as e:
        raise HTTPException(502, f"Connection failed: {e}")
    except httpx.TimeoutException:
        raise HTTPException(504, "Request timed out")
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/tools/ssl")
async def tools_ssl(host: str = Query(...), port: int = Query(443)):
    _validate_tool_host(host)
    if not (1 <= port <= 65535):
        raise HTTPException(400, "Invalid port")

    def _check() -> dict:
        import socket as _sock
        ctx = _ssl.create_default_context()
        try:
            with ctx.wrap_socket(_sock.socket(), server_hostname=host) as s:
                s.settimeout(10)
                s.connect((host, port))
                cert = s.getpeercert()
                cipher = s.cipher()
                return {
                    "host": host, "port": port, "valid": True,
                    "subject": {k: v for tup in cert.get("subject", []) for k, v in tup},
                    "issuer":  {k: v for tup in cert.get("issuer",  []) for k, v in tup},
                    "not_before": cert.get("notBefore"),
                    "not_after":  cert.get("notAfter"),
                    "san": [v for t, v in cert.get("subjectAltName", []) if t == "DNS"],
                    "serial": cert.get("serialNumber"),
                    "version": cert.get("version"),
                    "cipher": cipher[0] if cipher else None,
                    "protocol": cipher[1] if cipher else None,
                    "error": None,
                }
        except _ssl.SSLCertVerificationError as e:
            return {"host": host, "port": port, "valid": False,
                    "subject": {}, "issuer": {}, "not_before": None, "not_after": None,
                    "san": [], "serial": None, "version": None, "cipher": None,
                    "protocol": None, "error": f"Certificate verification failed: {e}"}
        except ConnectionRefusedError:
            raise HTTPException(502, f"Connection refused to {host}:{port}")
        except _sock.timeout:
            raise HTTPException(504, "Connection timed out")
        except Exception as e:
            raise HTTPException(500, str(e))

    try:
        return await asyncio.get_event_loop().run_in_executor(None, _check)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/tools/geo")
async def tools_geo(ip: str = Query(...)):
    try:
        _ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "Invalid IP address")
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"},
            )
            return resp.json()
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/tools/whois")
async def tools_whois(host: str = Query(...)):
    _validate_tool_host(host)
    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: subprocess.run(["whois", host],
                                   capture_output=True, text=True, timeout=20)
        )
        output = (result.stdout or result.stderr or "").strip()
        return {"host": host, "output": output[:8000]}
    except FileNotFoundError:
        raise HTTPException(501, "whois binary not available")
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "WHOIS query timed out")
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/tools/email")
async def tools_email(domain: str = Query(...)):
    import dns.resolver as _dns_res
    _validate_tool_host(domain)
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, run_email_analysis, domain)
        data = result.to_dict()
        try:
            data["nameservers"] = [str(r) for r in _dns_res.resolve(domain, "NS", lifetime=8)]
        except Exception:
            data["nameservers"] = []
        return data
    except Exception as exc:
        raise HTTPException(500, str(exc))


# ---------------------------------------------------------------------------
# ARP lookup + Wake-on-LAN (proxied to probe)
# ---------------------------------------------------------------------------
@app.get("/tools/arp-lookup")
async def tools_arp_lookup(query: str = Query(...)):
    try:
        async with _probe_client(timeout=10) as client:
            resp = await client.get(f"{PROBE_URL}/tools/arp-table")
            data = resp.json()
        entries = data.get("entries", [])
        q = query.strip().lower()
        matches = [e for e in entries if q in e.get("ip", "").lower() or q in e.get("mac", "").lower()]
        return {"query": query, "matches": matches, "total": len(entries)}
    except Exception as exc:
        return {"query": query, "matches": [], "error": str(exc)}


class WolPayload(BaseModel):
    mac: str
    broadcast: Optional[str] = "255.255.255.255"

@app.post("/tools/wake-on-lan")
async def tools_wake_on_lan(payload: WolPayload):
    try:
        async with _probe_client(timeout=10) as client:
            resp = await client.post(f"{PROBE_URL}/tools/wake-on-lan",
                                     json={"mac": payload.mac, "broadcast": payload.broadcast})
            return resp.json()
    except Exception as exc:
        raise HTTPException(500, str(exc))


# ---------------------------------------------------------------------------
# DNS over HTTPS tester
# ---------------------------------------------------------------------------
@app.get("/tools/doh")
async def tools_doh(host: str = Query(...), type: str = Query("A")):
    _validate_tool_host(host)
    qtype = type.upper()
    resolvers = {
        "Cloudflare (1.1.1.1)": "https://cloudflare-dns.com/dns-query",
        "Google (8.8.8.8)":     "https://dns.google/resolve",
        # Use IP directly for Quad9 to avoid DNS resolution issues in containers
        "Quad9 (9.9.9.9)":      "https://9.9.9.9/dns-query",
    }
    results = []
    async with httpx.AsyncClient(timeout=10, verify=False) as client:
        for name, url in resolvers.items():
            try:
                resp = await client.get(url, params={"name": host, "type": qtype},
                                        headers={"accept": "application/dns-json"})
                if not resp.content:
                    results.append({"name": name, "records": [], "error": "Empty response"})
                    continue
                data = resp.json()
                answers = [a.get("data", "") for a in data.get("Answer", []) if a.get("type")]
                results.append({"name": name, "records": answers, "status": data.get("Status", -1), "error": None})
            except Exception as e:
                results.append({"name": name, "records": [], "error": str(e)})
    return {"host": host, "type": qtype, "results": results}


# ---------------------------------------------------------------------------
# DNSSEC validator
# ---------------------------------------------------------------------------
@app.get("/tools/dnssec")
async def tools_dnssec(host: str = Query(...)):
    import dns.resolver, dns.dnssec, dns.rdatatype, dns.name
    _validate_tool_host(host)
    chain = []
    try:
        # Check DS record at parent
        try:
            ds_ans = dns.resolver.resolve(host, "DS", lifetime=8)
            chain.append({"record": "DS", "present": True,
                          "values": [str(r) for r in ds_ans][:3]})
        except Exception:
            chain.append({"record": "DS", "present": False, "values": []})

        # Check DNSKEY
        try:
            dk_ans = dns.resolver.resolve(host, "DNSKEY", lifetime=8)
            chain.append({"record": "DNSKEY", "present": True,
                          "values": [f"flags={r.flags} protocol={r.protocol} algorithm={r.algorithm}" for r in dk_ans][:3]})
        except Exception:
            chain.append({"record": "DNSKEY", "present": False, "values": []})

        # Check RRSIG on A record
        try:
            rrsig_ans = dns.resolver.resolve(host, "RRSIG", lifetime=8)
            chain.append({"record": "RRSIG", "present": True,
                          "values": [str(r)[:80] for r in rrsig_ans][:2]})
        except Exception:
            chain.append({"record": "RRSIG", "present": False, "values": []})

        signed = all(r["present"] for r in chain)
        return {"host": host, "signed": signed, "chain": chain, "error": None}
    except Exception as exc:
        return {"host": host, "signed": False, "chain": chain, "error": str(exc)}


# ---------------------------------------------------------------------------
# Reverse DNS bulk lookup (CIDR)
# ---------------------------------------------------------------------------
@app.get("/tools/rdns-bulk")
async def tools_rdns_bulk(cidr: str = Query(...)):
    import ipaddress as _ipa
    try:
        net = _ipa.ip_network(cidr, strict=False)
    except ValueError:
        raise HTTPException(400, "Invalid CIDR")
    if net.num_addresses > 256:
        raise HTTPException(400, "Maximum /24 subnet (256 hosts)")
    results = []
    for ip in net.hosts():
        ip_str = str(ip)
        try:
            hostname = socket.gethostbyaddr(ip_str)[0]
            results.append({"ip": ip_str, "hostname": hostname})
        except Exception:
            results.append({"ip": ip_str, "hostname": None})
    return {"cidr": cidr, "results": results}


# ---------------------------------------------------------------------------
# Redirect chain follower
# ---------------------------------------------------------------------------
@app.get("/tools/redirect-chain")
async def tools_redirect_chain(url: str = Query(...)):
    chain = []
    current = url
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=10,
                                     headers={"User-Agent": "InSpectre/1.0"}) as client:
            for _ in range(15):
                t0 = asyncio.get_event_loop().time()
                resp = await client.get(current)
                ms   = round((asyncio.get_event_loop().time() - t0) * 1000)
                chain.append({"url": current, "status": resp.status_code, "ms": ms,
                               "location": resp.headers.get("location")})
                if resp.status_code not in (301, 302, 303, 307, 308):
                    break
                next_url = resp.headers.get("location", "")
                if not next_url:
                    break
                if next_url.startswith("/"):
                    from urllib.parse import urlparse
                    p = urlparse(current)
                    next_url = f"{p.scheme}://{p.netloc}{next_url}"
                current = next_url
        return {"chain": chain, "hops": len(chain), "final": current}
    except Exception as exc:
        return {"chain": chain, "hops": len(chain), "final": current, "error": str(exc)}


# ---------------------------------------------------------------------------
# HTTP response timing
# ---------------------------------------------------------------------------
@app.get("/tools/http-timing")
async def tools_http_timing(url: str = Query(...)):
    import time
    steps: list[dict] = []
    try:
        t_start = time.perf_counter()
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "InSpectre/1.0"})
            t_end = time.perf_counter()
        total_ms = round((t_end - t_start) * 1000)
        return {
            "url": url,
            "status": resp.status_code,
            "total_ms": total_ms,
            "content_length": int(resp.headers.get("content-length", 0) or 0),
            "server": resp.headers.get("server"),
            "error": None,
        }
    except Exception as exc:
        return {"url": url, "total_ms": None, "error": str(exc)}


# ---------------------------------------------------------------------------
# TLS version & cipher suite tester (via nmap ssl-enum-ciphers)
# ---------------------------------------------------------------------------
@app.get("/tools/tls-versions")
async def tools_tls_versions(host: str = Query(...), port: int = Query(443)):
    _validate_tool_host(host)
    try:
        proc = await asyncio.create_subprocess_exec(
            "nmap", "--script", "ssl-enum-ciphers", "-p", str(port), host,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
        output = stdout.decode(errors="replace")
        # Parse TLS versions and ciphers from nmap pipe-prefixed output
        # Lines look like: "|   TLSv1.2:", "|       TLS_ECDHE_RSA... - A", "|   least strength: A"
        versions: dict[str, dict] = {}
        cur_ver   = None
        in_ciphers = False
        for raw_line in output.splitlines():
            # Strip leading whitespace and pipe characters (nmap output prefix)
            line = raw_line.strip().lstrip("|").strip()
            if not line:
                continue
            ver_line = line.rstrip(":")
            if ver_line.startswith("TLSv") or ver_line.startswith("SSLv"):
                cur_ver    = ver_line
                in_ciphers = False
                versions[cur_ver] = {"ciphers": [], "grade": None}
            elif cur_ver and line.lower().startswith("ciphers"):
                in_ciphers = True
            elif cur_ver and line.lower().startswith("compressors"):
                in_ciphers = False
            elif cur_ver and line.lower().startswith("cipher preference"):
                in_ciphers = False
            elif cur_ver and in_ciphers and line.startswith("TLS_"):
                # Line format: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A"
                versions[cur_ver]["ciphers"].append(line)
            elif cur_ver and "least strength" in line.lower():
                grade = line.split(":")[-1].strip()
                versions[cur_ver]["grade"] = grade
        return {"host": host, "port": port, "versions": versions, "raw": output[:3000]}
    except asyncio.TimeoutError:
        return {"host": host, "port": port, "versions": {}, "error": "Scan timed out"}
    except FileNotFoundError:
        return {"host": host, "port": port, "versions": {}, "error": "nmap not available on backend"}
    except Exception as exc:
        return {"host": host, "port": port, "versions": {}, "error": str(exc)}


# ---------------------------------------------------------------------------
# BGP / ASN lookup via RIPE Stat (stat.ripe.net) — no auth, highly reliable
# ---------------------------------------------------------------------------
@app.get("/tools/bgp")
async def tools_bgp(query: str = Query(...)):
    try:
        async with httpx.AsyncClient(timeout=15, headers={"User-Agent": "InSpectre/1.0"}) as client:
            q = query.strip()
            if q.upper().startswith("AS"):
                asn_num = q[2:] if q[2:].isdigit() else q[2:]
                resp    = await client.get(
                    f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn_num}&sourceapp=InSpectre"
                )
                raw = resp.json()
                asn_data = raw.get("data", {})
                holder  = asn_data.get("holder", "")
                block   = asn_data.get("block", {})
                return {"data": {
                    "asn":         int(asn_num) if asn_num.isdigit() else None,
                    "name":        holder,
                    "country_code": block.get("country", ""),
                    "description_short": asn_data.get("description", holder),
                    "resource":    f"AS{asn_num}",
                    "prefixes":    [],
                }}
            else:
                # IP lookup — use RIPE prefix-overview + routing-status
                resp = await client.get(
                    f"https://stat.ripe.net/data/prefix-overview/data.json?resource={q}&sourceapp=InSpectre"
                )
                raw  = resp.json()
                data = raw.get("data", {})
                asns = data.get("asns", [])
                asn_info = asns[0] if asns else {}
                return {"data": {
                    "ip":          q,
                    "asn":         asn_info.get("asn"),
                    "name":        asn_info.get("holder", ""),
                    "description_short": asn_info.get("holder", ""),
                    "country_code": "",
                    "rir_allocation": {"prefix": data.get("resource", "")},
                    "prefixes":    [{"prefix": data.get("resource", "")}] if data.get("resource") else [],
                }}
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# SMTP banner grab
# ---------------------------------------------------------------------------
@app.get("/tools/smtp-banner")
async def tools_smtp_banner(host: str = Query(...), port: int = Query(25)):
    _validate_tool_host(host)
    lines: list[str] = []
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=10
        )
        try:
            # Read banner
            banner = (await asyncio.wait_for(reader.readline(), timeout=5)).decode(errors="replace").strip()
            lines.append(banner)
            # Send EHLO
            writer.write(b"EHLO inspectre.local\r\n")
            await writer.drain()
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=5)
                decoded = line.decode(errors="replace").strip()
                if not decoded:
                    break
                lines.append(decoded)
                if decoded[:3].isdigit() and decoded[3] != "-":
                    break
        finally:
            writer.close()
        return {"host": host, "port": port, "banner": banner, "ehlo": lines[1:], "error": None}
    except asyncio.TimeoutError:
        return {"host": host, "port": port, "banner": None, "ehlo": lines, "error": "Connection timed out"}
    except Exception as exc:
        return {"host": host, "port": port, "banner": None, "ehlo": lines, "error": str(exc)}


# ---------------------------------------------------------------------------
# BIMI checker
# ---------------------------------------------------------------------------
@app.get("/tools/bimi")
async def tools_bimi(domain: str = Query(...)):
    import dns.resolver
    _validate_tool_host(domain)
    result: dict = {"domain": domain}
    try:
        recs = dns.resolver.resolve(f"default._bimi.{domain}", "TXT", lifetime=8)
        txt  = " ".join(str(r).strip('"') for r in recs)
        result["present"] = True
        result["record"]  = txt
        # Extract l= (logo URL) and a= (VMC URL)
        for part in txt.split(";"):
            part = part.strip()
            if part.startswith("l="):
                result["logo_url"] = part[2:].strip()
            elif part.startswith("a="):
                result["vmc_url"] = part[2:].strip()
    except dns.resolver.NXDOMAIN:
        result["present"] = False
        result["record"]  = None
    except dns.resolver.NoAnswer:
        result["present"] = False
        result["record"]  = None
    except Exception as exc:
        result["present"] = False
        result["error"] = str(exc)
    return result


# ---------------------------------------------------------------------------
# Email blacklist (DNSBL) checker
# ---------------------------------------------------------------------------
DNSBL_LISTS = [
    ("Spamhaus ZEN",     "zen.spamhaus.org"),
    ("Spamhaus SBL",     "sbl.spamhaus.org"),
    ("Barracuda",        "b.barracudacentral.org"),
    ("SORBS SPAM",       "spam.sorbs.net"),
    ("UCEProtect L1",    "dnsbl-1.uceprotect.net"),
    ("SpamCop",          "bl.spamcop.net"),
    ("NordSpam",         "combined.njabl.org"),
]

@app.get("/tools/dnsbl")
async def tools_dnsbl(ip: str = Query(...)):
    try:
        _ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "Invalid IP address")
    reversed_ip = ".".join(reversed(ip.split(".")))
    results = []
    for name, bl in DNSBL_LISTS:
        query = f"{reversed_ip}.{bl}"
        try:
            socket.gethostbyname(query)
            results.append({"list": name, "listed": True, "query": query})
        except socket.gaierror:
            results.append({"list": name, "listed": False, "query": query})
        except Exception as exc:
            results.append({"list": name, "listed": None, "query": query, "error": str(exc)})
    listed = sum(1 for r in results if r.get("listed"))
    return {"ip": ip, "listed_count": listed, "total": len(results), "results": results}


# ---------------------------------------------------------------------------
# Speedtest — stream proxy, server list, results, and delete
# ---------------------------------------------------------------------------
@app.get("/tools/speedtest")
async def stream_speedtest_proxy(server_id: str = ""):
    probe_url = f"{PROBE_URL}/stream/tools/speedtest"
    params: dict = {}
    if server_id:
        params["server_id"] = server_id
    raw_lines: list[str] = []

    async def _gen():
        try:
            async with _probe_client(timeout=None) as client:
                async with client.stream("GET", probe_url, params=params) as resp:
                    if resp.status_code != 200:
                        yield f"data: ERROR Probe returned {resp.status_code}\n\n"
                        return
                    async for line in resp.aiter_lines():
                        if line:
                            raw_lines.append(line)
                            yield f"{line}\n"
                            if line.startswith("data: RESULT:"):
                                payload_str = line[len("data: RESULT:"):]
                                try:
                                    data = json.loads(payload_str)
                                    if data.get("download_mbps") is not None or data.get("upload_mbps") is not None:
                                        db2 = SessionLocal()
                                        try:
                                            db2.execute(text(
                                                "INSERT INTO speedtest_results (server, ping_ms, download_mbps, upload_mbps, raw_output) "
                                                "VALUES (:server, :ping, :dl, :ul, :raw)"
                                            ), {
                                                "server": data.get("server"),
                                                "ping":   data.get("ping_ms"),
                                                "dl":     data.get("download_mbps"),
                                                "ul":     data.get("upload_mbps"),
                                                "raw":    "\n".join(l[6:] for l in raw_lines if l.startswith("data: ")),
                                            })
                                            db2.commit()
                                        finally:
                                            db2.close()
                                except Exception:
                                    pass
        except httpx.ConnectError:
            yield f"data: ERROR Cannot reach probe at {PROBE_URL}\n\n"
        except Exception as exc:
            yield f"data: ERROR {exc}\n\n"

    return StreamingResponse(
        _gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/tools/speedtest-servers")
async def get_speedtest_servers():
    try:
        async with _probe_client(timeout=60) as client:
            resp = await client.get(f"{PROBE_URL}/tools/speedtest-servers")
            return resp.json()
    except Exception as exc:
        return {"servers": [], "error": str(exc)}


@app.get("/speedtest/results")
def get_speedtest_results(db: Session = Depends(get_db)):
    rows = db.execute(text(
        "SELECT id, tested_at, server, ping_ms, download_mbps, upload_mbps "
        "FROM speedtest_results ORDER BY tested_at DESC LIMIT 20"
    )).fetchall()
    return [{"id": r[0], "tested_at": r[1].isoformat() if r[1] else None,
             "server": r[2], "ping_ms": r[3], "download_mbps": r[4], "upload_mbps": r[5]}
            for r in rows]


@app.delete("/speedtest/results/{result_id}")
def delete_speedtest_result(result_id: int, db: Session = Depends(get_db)):
    db.execute(text("DELETE FROM speedtest_results WHERE id = :id"), {"id": result_id})
    db.commit()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Block schedules — CRUD
# ---------------------------------------------------------------------------
def _schedule_row_to_dict(row) -> dict:
    return {
        "id":            row[0],
        "mac_address":   row[1],
        "label":         row[2],
        "days_of_week":  row[3],
        "start_time":    row[4],
        "end_time":      row[5],
        "enabled":       row[6],
        "created_at":    row[7].isoformat() if row[7] else None,
        "mac_addresses": list(row[8]) if row[8] else [],
        "tags":          row[9] or "",
        "person_id":     str(row[10]) if len(row) > 10 and row[10] else None,
        "person_ids":    list(row[11]) if len(row) > 11 and row[11] else [],
    }


@app.get("/block-schedules")
def list_block_schedules(db: Session = Depends(get_db)):
    rows = db.execute(text(
        "SELECT id, mac_address, label, days_of_week, start_time, end_time, enabled, created_at, mac_addresses, tags, person_id, person_ids "
        "FROM block_schedules ORDER BY created_at DESC"
    )).fetchall()
    return [_schedule_row_to_dict(r) for r in rows]


@app.post("/block-schedules", status_code=201)
def create_block_schedule(payload: BlockScheduleCreate, db: Session = Depends(get_db)):
    if not payload.start_time or not payload.end_time:
        raise HTTPException(400, "start_time and end_time are required")
    person_id  = payload.person_id or None
    # Merge single person_id into person_ids for backward compat
    person_ids = list(set(payload.person_ids or []))
    if person_id and person_id not in person_ids:
        person_ids.append(person_id)
    # If any person_ids, set person_id to first one for backward compat display
    if person_ids and not person_id:
        person_id = person_ids[0]
    row = db.execute(text(
        "INSERT INTO block_schedules (mac_address, label, days_of_week, start_time, end_time, enabled, mac_addresses, tags, person_id, person_ids) "
        "VALUES (:mac, :label, :days, :start, :end, :enabled, :mac_addresses, :tags, :person_id, :person_ids) "
        "RETURNING id, mac_address, label, days_of_week, start_time, end_time, enabled, created_at, mac_addresses, tags, person_id, person_ids"
    ), {
        "mac":           payload.mac_address,
        "label":         payload.label or "",
        "days":          payload.days_of_week,
        "start":         payload.start_time,
        "end":           payload.end_time,
        "enabled":       payload.enabled,
        "mac_addresses": payload.mac_addresses or [],
        "tags":          payload.tags or "",
        "person_id":     person_id,
        "person_ids":    person_ids,
    }).fetchone()
    db.commit()
    return _schedule_row_to_dict(row)


@app.patch("/block-schedules/{schedule_id}")
def update_block_schedule(schedule_id: int, payload: BlockScheduleUpdate, db: Session = Depends(get_db)):
    existing = db.execute(text(
        "SELECT id FROM block_schedules WHERE id = :id"
    ), {"id": schedule_id}).fetchone()
    if not existing:
        raise HTTPException(404, "Schedule not found")
    updates = {}
    if payload.label         is not None: updates["label"]         = payload.label
    if payload.days_of_week  is not None: updates["days_of_week"]  = payload.days_of_week
    if payload.start_time    is not None: updates["start_time"]    = payload.start_time
    if payload.end_time      is not None: updates["end_time"]      = payload.end_time
    if payload.enabled       is not None: updates["enabled"]       = payload.enabled
    if payload.mac_addresses is not None: updates["mac_addresses"] = payload.mac_addresses
    if payload.tags          is not None: updates["tags"]          = payload.tags
    if payload.person_id     is not None: updates["person_id"]     = payload.person_id or None
    if payload.person_ids    is not None:
        pids = list(set(payload.person_ids))
        updates["person_ids"] = pids
        # keep person_id in sync with first entry
        if pids and payload.person_id is None:
            updates["person_id"] = pids[0]
        elif not pids:
            updates["person_id"] = None
    if updates:
        set_clause = ", ".join(f"{k} = :{k}" for k in updates)
        updates["id"] = schedule_id
        db.execute(text(f"UPDATE block_schedules SET {set_clause} WHERE id = :id"), updates)
        db.commit()
    row = db.execute(text(
        "SELECT id, mac_address, label, days_of_week, start_time, end_time, enabled, created_at, mac_addresses, tags, person_id, person_ids "
        "FROM block_schedules WHERE id = :id"
    ), {"id": schedule_id}).fetchone()
    return _schedule_row_to_dict(row)


@app.delete("/block-schedules/{schedule_id}", status_code=204)
def delete_block_schedule(schedule_id: int, db: Session = Depends(get_db)):
    db.execute(text("DELETE FROM block_schedules WHERE id = :id"), {"id": schedule_id})
    db.commit()


# ---------------------------------------------------------------------------
# Person Presence API
# ---------------------------------------------------------------------------

def _person_row_to_dict(row, devices=None, schedules=None) -> dict:
    """Convert a persons row to a dict. devices and schedules are pre-fetched lists."""
    pid = str(row[0])
    primary_mac = row[2]
    devs = devices or []
    is_home = False
    if primary_mac:
        is_home = any(d["mac_address"] == primary_mac and d.get("is_online") for d in devs)
    elif devs:
        is_home = any(d.get("is_online") for d in devs)
    is_blocked = bool(devs) and all(d.get("is_blocked", False) for d in devs)
    timed_block_remaining = None
    task = _person_timed_blocks.get(pid)
    if task and not task.done():
        timed_block_remaining = True  # active timed block
    # Derive last status change from the most recent device status_changed_at
    status_changed_at = None
    for d in devs:
        sc = d.get("status_changed_at")
        if sc and (status_changed_at is None or sc > status_changed_at):
            status_changed_at = sc
    return {
        "id":                    pid,
        "name":                  row[1],
        "primary_mac":           primary_mac,
        "photo":                 row[3],
        "notes":                 row[4],
        "created_at":            row[5].isoformat() if row[5] else None,
        "updated_at":            row[6].isoformat() if row[6] else None,
        "is_home":               is_home,
        "is_blocked":            is_blocked,
        "has_timed_block":       timed_block_remaining is not None,
        "last_status_changed_at": status_changed_at,
        "devices":               devs,
        "schedules":             schedules or [],
    }


@app.get("/persons")
def list_persons(db: Session = Depends(get_db)):
    persons = db.execute(text(
        "SELECT id::text, name, primary_mac, photo, notes, created_at, updated_at FROM persons ORDER BY name"
    )).fetchall()
    # Fetch all devices assigned to any person in one query
    dev_rows = db.execute(text("""
        SELECT pd.person_id::text, d.mac_address, d.is_online,
               COALESCE(d.custom_name, d.hostname, d.ip_address) AS display_name,
               d.ip_address, d.device_type_override, d.vendor, d.is_blocked,
               d.status_changed_at
        FROM person_devices pd
        JOIN devices d ON d.mac_address = pd.mac_address
    """)).fetchall()
    devs_by_person: dict = {}
    for r in dev_rows:
        devs_by_person.setdefault(r[0], []).append({
            "mac_address":        r[1], "is_online": r[2], "display_name": r[3],
            "ip_address":         r[4], "device_type": r[5], "vendor": r[6], "is_blocked": bool(r[7]),
            "status_changed_at":  r[8].isoformat() if r[8] else None,
        })
    # Fetch person-targeted schedules (both person_id and person_ids)
    try:
        sched_rows = db.execute(text(
            "SELECT id, person_id::text, label, days_of_week, start_time, end_time, enabled, person_ids "
            "FROM block_schedules WHERE person_id IS NOT NULL OR array_length(person_ids, 1) > 0"
        )).fetchall()
    except Exception:
        sched_rows = []
    scheds_by_person: dict = {}
    for r in sched_rows:
        sched = {
            "id": r[0], "label": r[2], "days_of_week": r[3],
            "start_time": r[4], "end_time": r[5], "enabled": r[6],
            "person_ids": list(r[7]) if r[7] else [],
        }
        # Add to each targeted person's list
        effective_pids = list(r[7]) if r[7] else []
        if r[1] and r[1] not in effective_pids:
            effective_pids.append(r[1])
        for pid in effective_pids:
            scheds_by_person.setdefault(pid, []).append(sched)
    return [
        _person_row_to_dict(p, devs_by_person.get(str(p[0]), []), scheds_by_person.get(str(p[0]), []))
        for p in persons
    ]


class PersonCreate(BaseModel):
    name:        str
    primary_mac: Optional[str] = None
    photo:       Optional[str] = None   # base64 data URI
    notes:       Optional[str] = None


class PersonUpdate(BaseModel):
    name:        Optional[str] = None
    primary_mac: Optional[str] = None  # empty string to clear
    photo:       Optional[str] = None  # empty string to clear
    notes:       Optional[str] = None


@app.post("/persons", status_code=201)
def create_person(payload: PersonCreate, db: Session = Depends(get_db)):
    if not payload.name.strip():
        raise HTTPException(400, "name is required")
    row = db.execute(text(
        "INSERT INTO persons (name, primary_mac, photo, notes) "
        "VALUES (:name, :primary_mac, :photo, :notes) "
        "RETURNING id::text, name, primary_mac, photo, notes, created_at, updated_at"
    ), {
        "name":        payload.name.strip(),
        "primary_mac": payload.primary_mac or None,
        "photo":       payload.photo or None,
        "notes":       payload.notes or None,
    }).fetchone()
    db.commit()
    return _person_row_to_dict(row)


@app.get("/persons/timeline")
def get_persons_timeline(days: int = Query(7, ge=1, le=365), db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=days)

    persons = db.execute(text(
        "SELECT id::text, name, primary_mac, photo FROM persons ORDER BY name"
    )).fetchall()

    if not persons:
        return {"window_start": window_start.isoformat(), "window_end": now.isoformat(),
                "days": days, "persons": []}

    # Resolve which MAC to track for each person (primary_mac or first assigned device)
    person_macs: dict = {}
    for p in persons:
        pid = p[0]
        if p[2]:
            person_macs[pid] = p[2]
        else:
            row = db.execute(text(
                "SELECT mac_address FROM person_devices WHERE person_id = :pid LIMIT 1"
            ), {"pid": pid}).fetchone()
            if row:
                person_macs[pid] = row[0]

    all_macs = list(set(person_macs.values()))
    events_by_mac: dict = {}
    prior_by_mac:  dict = {}

    if all_macs:
        mac_params = {f"mac{i}": m for i, m in enumerate(all_macs)}
        mac_in     = ", ".join(f":mac{i}" for i in range(len(all_macs)))

        for r in db.execute(text(f"""
            SELECT mac_address, type, created_at FROM device_events
            WHERE mac_address IN ({mac_in})
              AND type IN ('online', 'offline', 'joined')
              AND created_at >= :window_start
            ORDER BY mac_address, created_at ASC
        """), {"window_start": window_start, **mac_params}).fetchall():
            events_by_mac.setdefault(r[0], []).append({"type": r[1], "ts": r[2]})

        for r in db.execute(text(f"""
            SELECT DISTINCT ON (mac_address) mac_address, type
            FROM device_events
            WHERE mac_address IN ({mac_in})
              AND type IN ('online', 'offline', 'joined')
              AND created_at < :window_start
            ORDER BY mac_address, created_at DESC
        """), {"window_start": window_start, **mac_params}).fetchall():
            prior_by_mac[r[0]] = "online" if r[1] in ("online", "joined") else "offline"

    def build_segments(mac):
        evts    = events_by_mac.get(mac, [])
        initial = prior_by_mac.get(mac, "unknown")
        segs    = []
        ss      = window_start
        st      = initial
        home_ms = 0.0
        known_ms = 0.0

        for ev in evts:
            se = ev["ts"]
            if se > ss:
                segs.append({"from": ss.isoformat(), "to": se.isoformat(), "status": st})
                dur = (se - ss).total_seconds() * 1000
                if st == "online":
                    home_ms += dur
                if st != "unknown":
                    known_ms += dur
            ss = se
            st = "online" if ev["type"] in ("online", "joined") else "offline"

        segs.append({"from": ss.isoformat(), "to": now.isoformat(), "status": st})
        final_dur = (now - ss).total_seconds() * 1000
        if st == "online":
            home_ms += final_dur
        if st != "unknown":
            known_ms += final_dur

        # Percentage is computed over the period we actually have data for
        # (i.e. since the device/person was first known), not the whole window.
        home_pct   = round((home_ms / known_ms) * 100) if known_ms > 0 else 0
        return segs, home_pct

    result = []
    for p in persons:
        pid = p[0]
        mac = person_macs.get(pid)
        if mac:
            segs, pct = build_segments(mac)
        else:
            segs, pct = [], 0
        result.append({
            "id":          pid,
            "name":        p[1],
            "photo":       p[3],
            "primary_mac": p[2],
            "segments":    segs,
            "at_home_pct": pct,
        })

    return {
        "window_start": window_start.isoformat(),
        "window_end":   now.isoformat(),
        "days":         days,
        "persons":      result,
    }


@app.get("/persons/{person_id}")
def get_person(person_id: str, db: Session = Depends(get_db)):
    row = db.execute(text(
        "SELECT id::text, name, primary_mac, photo, notes, created_at, updated_at "
        "FROM persons WHERE id = :id"
    ), {"id": person_id}).fetchone()
    if not row:
        raise HTTPException(404, "Person not found")
    dev_rows = db.execute(text("""
        SELECT pd.person_id::text, d.mac_address, d.is_online,
               COALESCE(d.custom_name, d.hostname, d.ip_address) AS display_name,
               d.ip_address, d.device_type_override, d.vendor, d.is_blocked
        FROM person_devices pd
        JOIN devices d ON d.mac_address = pd.mac_address
        WHERE pd.person_id = :pid
    """), {"pid": person_id}).fetchall()
    devs = [{"mac_address": r[1], "is_online": r[2], "display_name": r[3],
             "ip_address": r[4], "device_type": r[5], "vendor": r[6], "is_blocked": bool(r[7])} for r in dev_rows]
    try:
        sched_rows = db.execute(text(
            "SELECT id, person_id::text, label, days_of_week, start_time, end_time, enabled, person_ids "
            "FROM block_schedules WHERE person_id = :pid OR :pid = ANY(person_ids::text[])"
        ), {"pid": person_id}).fetchall()
        scheds = [{"id": r[0], "label": r[2], "days_of_week": r[3],
                   "start_time": r[4], "end_time": r[5], "enabled": r[6],
                   "person_ids": list(r[7]) if r[7] else []} for r in sched_rows]
    except Exception:
        scheds = []
    return _person_row_to_dict(row, devs, scheds)


@app.patch("/persons/{person_id}")
def update_person(person_id: str, payload: PersonUpdate, db: Session = Depends(get_db)):
    existing = db.execute(text("SELECT id FROM persons WHERE id = :id"), {"id": person_id}).fetchone()
    if not existing:
        raise HTTPException(404, "Person not found")
    updates: dict = {"updated_at": "NOW()"}
    if payload.name        is not None: updates["name"]        = payload.name.strip()
    if payload.primary_mac is not None: updates["primary_mac"] = payload.primary_mac or None
    if payload.photo       is not None: updates["photo"]       = payload.photo or None
    if payload.notes       is not None: updates["notes"]       = payload.notes or None
    set_parts = []
    params: dict = {"id": person_id}
    for k, v in updates.items():
        if k == "updated_at":
            set_parts.append("updated_at = NOW()")
        else:
            set_parts.append(f"{k} = :{k}")
            params[k] = v
    db.execute(text(f"UPDATE persons SET {', '.join(set_parts)} WHERE id = :id"), params)
    db.commit()
    return get_person(person_id, db)


@app.delete("/persons/{person_id}", status_code=204)
def delete_person(person_id: str, db: Session = Depends(get_db)):
    # Unassign all devices belonging to this person
    db.execute(text("UPDATE devices SET person_id = NULL WHERE person_id = :id"), {"id": person_id})
    db.execute(text("DELETE FROM persons WHERE id = :id"), {"id": person_id})
    db.commit()


class PersonDeviceAdd(BaseModel):
    mac_address:  str
    set_primary:  bool = False


@app.post("/persons/{person_id}/devices", status_code=201)
def add_person_device(person_id: str, payload: PersonDeviceAdd, db: Session = Depends(get_db)):
    mac = payload.mac_address.lower()
    existing_person = db.execute(text("SELECT id FROM persons WHERE id = :id"), {"id": person_id}).fetchone()
    if not existing_person:
        raise HTTPException(404, "Person not found")
    existing_device = db.execute(text("SELECT mac_address FROM devices WHERE mac_address = :mac"), {"mac": mac}).fetchone()
    if not existing_device:
        raise HTTPException(404, "Device not found")
    db.execute(text(
        "INSERT INTO person_devices (person_id, mac_address) VALUES (:pid, :mac) ON CONFLICT DO NOTHING"
    ), {"pid": person_id, "mac": mac})
    # Update devices.person_id for quick lookup
    db.execute(text("UPDATE devices SET person_id = :pid WHERE mac_address = :mac"), {"pid": person_id, "mac": mac})
    if payload.set_primary:
        db.execute(text("UPDATE persons SET primary_mac = :mac, updated_at = NOW() WHERE id = :pid"), {"mac": mac, "pid": person_id})
    db.commit()
    return get_person(person_id, db)


@app.delete("/persons/{person_id}/devices/{mac}", status_code=204)
def remove_person_device(person_id: str, mac: str, db: Session = Depends(get_db)):
    mac = mac.lower()
    db.execute(text(
        "DELETE FROM person_devices WHERE person_id = :pid AND mac_address = :mac"
    ), {"pid": person_id, "mac": mac})
    db.execute(text(
        "UPDATE devices SET person_id = NULL WHERE mac_address = :mac AND person_id = :pid"
    ), {"mac": mac, "pid": person_id})
    # If this was the primary device, clear it
    db.execute(text(
        "UPDATE persons SET primary_mac = NULL, updated_at = NOW() WHERE id = :pid AND primary_mac = :mac"
    ), {"pid": person_id, "mac": mac})
    db.commit()


class PersonBlockRequest(BaseModel):
    duration_minutes: Optional[int] = None  # None = indefinite; 30, 60, 360, 1440 for timed


@app.post("/persons/{person_id}/block")
async def block_person(person_id: str, payload: PersonBlockRequest = PersonBlockRequest(), db: Session = Depends(get_db)):
    # Fetch person name for notification
    prow = db.execute(text("SELECT name FROM persons WHERE id = :pid"), {"pid": person_id}).fetchone()
    person_name = prow[0] if prow else "Person"
    rows = db.execute(text(
        "SELECT d.mac_address, d.ip_address FROM person_devices pd "
        "JOIN devices d ON d.mac_address = pd.mac_address WHERE pd.person_id = :pid"
    ), {"pid": person_id}).fetchall()
    if not rows:
        raise HTTPException(404, "Person not found or has no devices")
    for r in rows:
        mac, ip = r[0], r[1]
        d = db.get(Device, mac)
        if d and not d.is_blocked:
            await _execute_block(mac, ip, db, "block")
            d.is_blocked = True
            _add_event(db, mac, "blocked", {"ip": ip, "reason": "person_block"})
    db.commit()
    asyncio.ensure_future(_notification_dispatch(
        "person.blocked", "Person Blocked",
        f"{person_name}'s devices have been blocked"
    ))
    # Cancel any existing timed block and start a new one if duration given
    existing = _person_timed_blocks.pop(person_id, None)
    if existing and not existing.done():
        existing.cancel()
    if payload.duration_minutes:
        macs = [r[0] for r in rows]
        async def _auto_unblock(pid: str, mac_list: list, delay_s: int, pn: str):
            await asyncio.sleep(delay_s)
            _db = SessionLocal()
            try:
                for mac in mac_list:
                    dd = _db.get(Device, mac)
                    if dd and dd.is_blocked:
                        await _execute_block(mac, dd.ip_address, _db, "unblock")
                        dd.is_blocked = False
                        _add_event(_db, mac, "unblocked", {"ip": dd.ip_address, "reason": "person_timed_unblock"})
                _db.commit()
            finally:
                _db.close()
            _person_timed_blocks.pop(pid, None)
            asyncio.ensure_future(_notification_dispatch(
                "person.unblocked", "Person Unblocked",
                f"{pn}'s devices have been automatically unblocked"
            ))
        _person_timed_blocks[person_id] = asyncio.ensure_future(
            _auto_unblock(person_id, macs, payload.duration_minutes * 60, person_name)
        )
    return {"ok": True, "macs": [r[0] for r in rows], "duration_minutes": payload.duration_minutes}


@app.post("/persons/{person_id}/unblock")
async def unblock_person(person_id: str, db: Session = Depends(get_db)):
    prow = db.execute(text("SELECT name FROM persons WHERE id = :pid"), {"pid": person_id}).fetchone()
    person_name = prow[0] if prow else "Person"
    existing = _person_timed_blocks.pop(person_id, None)
    if existing and not existing.done():
        existing.cancel()
    rows = db.execute(text(
        "SELECT d.mac_address, d.ip_address FROM person_devices pd "
        "JOIN devices d ON d.mac_address = pd.mac_address WHERE pd.person_id = :pid"
    ), {"pid": person_id}).fetchall()
    for r in rows:
        mac, ip = r[0], r[1]
        d = db.get(Device, mac)
        if d and d.is_blocked:
            await _execute_block(mac, ip, db, "unblock")
            d.is_blocked = False
            _add_event(db, mac, "unblocked", {"ip": ip, "reason": "person_unblock"})
    db.commit()
    asyncio.ensure_future(_notification_dispatch(
        "person.unblocked", "Person Unblocked",
        f"{person_name}'s devices have been unblocked"
    ))
    return {"ok": True, "macs": [r[0] for r in rows]}


# ---------------------------------------------------------------------------
# Network pause / resume (ARP-blocks all non-ignored devices)
# ---------------------------------------------------------------------------
@app.get("/network/status")
def network_status(db: Session = Depends(get_db)):
    setting = db.get(Setting, "network_paused")
    paused = (setting.value if setting else "false") == "true"
    blocked_count = db.execute(text("SELECT COUNT(*) FROM devices WHERE is_blocked = TRUE")).scalar()
    return {"paused": paused, "blocked_count": int(blocked_count or 0)}


@app.post("/network/pause")
async def network_pause(db: Session = Depends(get_db)):
    devices = db.execute(text(
        "SELECT mac_address, ip_address FROM devices WHERE is_ignored = FALSE AND is_blocked = FALSE AND ip_address IS NOT NULL"
    )).fetchall()
    errors = []
    async def _block_one(mac: str, ip: str):
        try:
            async with _probe_client(timeout=10.0) as client:
                await client.post(f"{PROBE_URL}/block/{mac.lower()}")
        except Exception as e:
            errors.append(str(e))
    await asyncio.gather(*[_block_one(r[0], r[1]) for r in devices])
    db.execute(text("UPDATE devices SET is_blocked = TRUE WHERE is_ignored = FALSE AND ip_address IS NOT NULL"))
    setting = db.get(Setting, "network_paused")
    if setting:
        setting.value = "true"
    else:
        db.execute(text("INSERT INTO settings (key, value) VALUES ('network_paused', 'true')"))
    db.commit()
    return {"paused": True, "blocked": len(devices), "errors": errors}


@app.post("/network/resume")
async def network_resume(db: Session = Depends(get_db)):
    devices = db.execute(text(
        "SELECT mac_address, ip_address FROM devices WHERE is_blocked = TRUE AND ip_address IS NOT NULL"
    )).fetchall()
    errors = []
    async def _unblock_one(mac: str):
        try:
            async with _probe_client(timeout=10.0) as client:
                await client.delete(f"{PROBE_URL}/block/{mac.lower()}")
        except Exception as e:
            errors.append(str(e))
    await asyncio.gather(*[_unblock_one(r[0]) for r in devices])
    db.execute(text("UPDATE devices SET is_blocked = FALSE, is_schedule_blocked = FALSE WHERE is_blocked = TRUE"))
    setting = db.get(Setting, "network_paused")
    if setting:
        setting.value = "false"
    else:
        db.execute(text("INSERT INTO settings (key, value) VALUES ('network_paused', 'false')"))
    db.commit()
    return {"paused": False, "unblocked": len(devices), "errors": errors}


# ---------------------------------------------------------------------------
# Device online/offline timeline
# ---------------------------------------------------------------------------
@app.get("/timeline")
def get_timeline(days: int = Query(7, ge=1, le=365), db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=days)

    # Fetch all online/offline/joined events for all devices in the window
    # plus the most recent event before the window to know starting state
    rows = db.execute(text("""
        SELECT de.mac_address, de.type, de.created_at,
               COALESCE(d.custom_name, d.hostname, d.ip_address, de.mac_address) AS display_name,
               d.ip_address, d.is_online
        FROM device_events de
        JOIN devices d ON d.mac_address = de.mac_address
        WHERE de.type IN ('online', 'offline', 'joined')
          AND de.created_at >= :window_start
          AND d.is_ignored = FALSE
        ORDER BY de.mac_address, de.created_at ASC
    """), {"window_start": window_start}).fetchall()

    # Also get the last event before window for each device (to know initial state)
    prior_rows = db.execute(text("""
        SELECT DISTINCT ON (de.mac_address)
               de.mac_address, de.type, de.created_at
        FROM device_events de
        JOIN devices d ON d.mac_address = de.mac_address
        WHERE de.type IN ('online', 'offline', 'joined')
          AND de.created_at < :window_start
          AND d.is_ignored = FALSE
        ORDER BY de.mac_address, de.created_at DESC
    """), {"window_start": window_start}).fetchall()

    # Get all relevant devices (those with events in window or active devices)
    device_info = db.execute(text("""
        SELECT mac_address,
               COALESCE(custom_name, hostname, ip_address, mac_address) AS display_name,
               ip_address, is_online
        FROM devices WHERE is_ignored = FALSE
        ORDER BY display_name
    """)).fetchall()

    prior_state: dict = {}
    for r in prior_rows:
        mac, etype, ts = r[0], r[1], r[2]
        prior_state[mac] = "online" if etype in ("online", "joined") else "offline"

    # Group events by device
    events_by_mac: dict = {}
    for r in rows:
        mac = r[0]
        events_by_mac.setdefault(mac, []).append({
            "type": r[1], "ts": r[2]
        })

    # Only include devices that have events in window or are currently known
    seen_macs = set(events_by_mac.keys()) | set(prior_state.keys())
    device_map = {r[0]: {"name": r[1], "ip": r[2], "is_online": r[3]} for r in device_info}

    result_devices = []
    for mac, info in device_map.items():
        if mac not in seen_macs:
            continue

        evts = events_by_mac.get(mac, [])
        initial = prior_state.get(mac, "unknown")

        # Build segments
        segments = []
        seg_start = window_start
        seg_status = initial

        for ev in evts:
            seg_end = ev["ts"]
            if seg_end > seg_start:
                segments.append({
                    "from": seg_start.isoformat(),
                    "to":   seg_end.isoformat(),
                    "status": seg_status,
                })
            seg_start = seg_end
            seg_status = "online" if ev["type"] in ("online", "joined") else "offline"

        # Final segment up to now
        segments.append({
            "from": seg_start.isoformat(),
            "to":   now.isoformat(),
            "status": seg_status,
        })

        result_devices.append({
            "mac":        mac,
            "name":       info["name"],
            "ip":         info["ip"],
            "is_online":  info["is_online"],
            "segments":   segments,
        })

    # Sort: online first, then by name
    result_devices.sort(key=lambda d: (0 if d["is_online"] else 1, d["name"] or ""))

    return {
        "window_start": window_start.isoformat(),
        "window_end":   now.isoformat(),
        "days":         days,
        "devices":      result_devices,
    }


@app.get("/devices/{mac}/timeline")
def get_device_timeline(mac: str, days: int = Query(7, ge=1, le=365), db: Session = Depends(get_db)):
    now          = datetime.now(timezone.utc)
    window_start = now - timedelta(days=days)

    rows = db.execute(text("""
        SELECT type, created_at FROM device_events
        WHERE mac_address = :mac
          AND type IN ('online', 'offline', 'joined')
          AND created_at >= :window_start
        ORDER BY created_at ASC
    """), {"mac": mac, "window_start": window_start}).fetchall()

    prior = db.execute(text("""
        SELECT type FROM device_events
        WHERE mac_address = :mac
          AND type IN ('online', 'offline', 'joined')
          AND created_at < :window_start
        ORDER BY created_at DESC LIMIT 1
    """), {"mac": mac, "window_start": window_start}).fetchone()

    initial = "online" if (prior and prior[0] in ("online", "joined")) else "unknown" if not prior else "offline"
    segments = []
    seg_start  = window_start
    seg_status = initial

    for r in rows:
        etype, ts = r[0], r[1]
        new_status = "online" if etype in ("online", "joined") else "offline"
        if new_status != seg_status:
            segments.append({"from": seg_start.isoformat(), "to": ts.isoformat(), "status": seg_status})
            seg_start  = ts
            seg_status = new_status

    segments.append({"from": seg_start.isoformat(), "to": now.isoformat(), "status": seg_status})

    return {
        "mac":          mac,
        "window_start": window_start.isoformat(),
        "window_end":   now.isoformat(),
        "days":         days,
        "segments":     segments,
    }


# ---------------------------------------------------------------------------
# Block schedule enforcement background loop
# ---------------------------------------------------------------------------
_DAY_ABBREVS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def _schedule_active_now(days_of_week: str, start_time: str, end_time: str) -> bool:
    """Return True if current local time falls within the schedule window."""
    now_local = datetime.now()
    current_day = _DAY_ABBREVS[now_local.weekday()]
    allowed_days = [d.strip().lower() for d in days_of_week.split(",")]
    if current_day not in allowed_days:
        return False
    try:
        sh, sm = map(int, start_time.split(":"))
        eh, em = map(int, end_time.split(":"))
        start_mins = sh * 60 + sm
        end_mins   = eh * 60 + em
        now_mins   = now_local.hour * 60 + now_local.minute
        if end_mins > start_mins:
            return start_mins <= now_mins < end_mins
        else:
            # overnight schedule
            return now_mins >= start_mins or now_mins < end_mins
    except Exception:
        return False


async def _block_schedule_loop():
    await asyncio.sleep(15)  # wait for startup to settle
    while True:
        try:
            db = SessionLocal()
            try:
                # Try to select with person_ids; fall back if column missing
                try:
                    schedules = db.execute(text(
                        "SELECT id, mac_address, days_of_week, start_time, end_time, mac_addresses, tags, person_id, person_ids "
                        "FROM block_schedules WHERE enabled = TRUE"
                    )).fetchall()
                    has_person_ids_col = True
                except Exception:
                    schedules = db.execute(text(
                        "SELECT id, mac_address, days_of_week, start_time, end_time, mac_addresses, tags, person_id "
                        "FROM block_schedules WHERE enabled = TRUE"
                    )).fetchall()
                    has_person_ids_col = False

                # Build set of (mac_or_None, should_be_blocked) from all schedules
                device_should_block: dict = {}  # mac -> bool (True = schedule says block)

                for sched in schedules:
                    try:
                        if has_person_ids_col:
                            sched_id, mac, days, start, end, mac_addresses, sched_tags, person_id, person_ids = sched
                        else:
                            sched_id, mac, days, start, end, mac_addresses, sched_tags, person_id = sched
                            person_ids = []
                        active = _schedule_active_now(days, start, end)

                        # Determine target MACs
                        target_macs = None  # None = network-wide

                        # Build effective person_ids list
                        effective_pids = [str(p) for p in (person_ids or [])] if person_ids else []
                        if person_id and str(person_id) not in effective_pids:
                            effective_pids.append(str(person_id))

                        if effective_pids:
                            # Expand all persons to their devices (cast to text for safety)
                            target_macs = []
                            for pid in effective_pids:
                                person_macs = db.execute(text(
                                    "SELECT mac_address FROM person_devices WHERE person_id::text = :pid"
                                ), {"pid": pid}).scalars().all()
                                target_macs.extend(person_macs)
                            target_macs = list(set(target_macs))
                            print(f"[sched] id={sched_id} persons={effective_pids} active={active} macs={target_macs}", flush=True)
                        elif mac_addresses:
                            target_macs = list(mac_addresses)
                        elif sched_tags:
                            tag_list = [t.strip().lower() for t in sched_tags.split(',') if t.strip()]
                            all_devices = db.execute(text(
                                "SELECT mac_address, tags FROM devices WHERE is_ignored = FALSE AND tags IS NOT NULL"
                            )).fetchall()
                            target_macs = []
                            for dev_mac, dev_tags in all_devices:
                                if dev_tags:
                                    dev_tag_list = [t.strip().lower() for t in dev_tags.split(',') if t.strip()]
                                    if any(t in dev_tag_list for t in tag_list):
                                        target_macs.append(dev_mac)
                        elif mac:
                            target_macs = [mac]

                        if target_macs is not None:
                            for m in target_macs:
                                if m not in device_should_block:
                                    device_should_block[m] = False
                                if active:
                                    device_should_block[m] = True
                        else:
                            # Network-wide: apply to all non-ignored devices
                            all_macs = db.execute(text(
                                "SELECT mac_address FROM devices WHERE is_ignored = FALSE"
                            )).scalars().all()
                            for m in all_macs:
                                if m not in device_should_block:
                                    device_should_block[m] = False
                                if active:
                                    device_should_block[m] = True
                    except Exception as sched_exc:
                        print(f"[block_schedule_loop] schedule error id={sched[0] if sched else '?'}: {sched_exc}", flush=True)

                # Apply changes
                for mac, should_block in device_should_block.items():
                    try:
                        dev = db.execute(text(
                            "SELECT is_blocked, is_schedule_blocked, ip_address FROM devices WHERE mac_address = :mac"
                        ), {"mac": mac}).fetchone()
                        if not dev:
                            continue
                        is_blocked, is_sched_blocked, ip = dev

                        if should_block and not is_sched_blocked:
                            print(f"[sched] blocking {mac} ({ip}) via schedule", flush=True)
                            await _execute_block_bg(mac, ip, "block")
                            db.execute(text(
                                "UPDATE devices SET is_blocked = TRUE, is_schedule_blocked = TRUE WHERE mac_address = :mac"
                            ), {"mac": mac})
                            _add_event(db, mac, "blocked", {"ip": ip, "reason": "schedule"})
                            asyncio.ensure_future(_plugin_event_bus.notify("device.blocked", {"mac": mac, "ip": ip or ""}))

                        elif not should_block and is_sched_blocked:
                            print(f"[sched] unblocking {mac} ({ip}) schedule ended", flush=True)
                            await _execute_block_bg(mac, ip, "unblock")
                            db.execute(text(
                                "UPDATE devices SET is_blocked = FALSE, is_schedule_blocked = FALSE WHERE mac_address = :mac"
                            ), {"mac": mac})
                            _add_event(db, mac, "unblocked", {"ip": ip, "reason": "schedule_end"})
                            asyncio.ensure_future(_plugin_event_bus.notify("device.unblocked", {"mac": mac, "ip": ip or ""}))
                    except Exception as mac_exc:
                        print(f"[block_schedule_loop] apply error {mac}: {mac_exc}", flush=True)

                db.commit()
            finally:
                db.close()
        except Exception as exc:
            print(f"[block_schedule_loop] outer error: {exc}", flush=True)

        await asyncio.sleep(60)


# ---------------------------------------------------------------------------
# Traffic monitoring API
# ---------------------------------------------------------------------------

@app.post("/traffic/start/{mac}")
async def traffic_start(mac: str, db: Session = Depends(get_db)):
    mac = mac.lower()
    te = db.get(Setting, "traffic_enabled")
    if te and te.value == "false":
        raise HTTPException(403, "Traffic monitoring is disabled in settings")
    device = db.get(Device, mac)
    if not device:
        raise HTTPException(404, "Device not found")
    ip = device.ip_address
    if not ip:
        raise HTTPException(422, "Device has no IP address")
    # Enforce max concurrent sessions
    max_s = db.get(Setting, "traffic_max_sessions")
    max_sessions = int(max_s.value) if max_s and max_s.value else 10
    try:
        async with _probe_client(timeout=5.0) as client:
            active_resp = await client.get(f"{PROBE_URL}/traffic/stats")
        if active_resp.status_code == 200:
            active_count = len(active_resp.json().get("sessions", []))
            if active_count >= max_sessions:
                raise HTTPException(429, f"Max concurrent traffic sessions ({max_sessions}) reached")
    except (httpx.ConnectError, httpx.TimeoutException):
        pass
    try:
        async with _probe_client(timeout=10.0) as client:
            resp = await client.post(f"{PROBE_URL}/traffic/start/{ip}")
        if resp.status_code == 409:
            raise HTTPException(409, resp.json().get("detail", "Conflict"))
        if resp.status_code not in (200, 201):
            raise HTTPException(502, f"Probe returned {resp.status_code}")
        return resp.json()
    except HTTPException:
        raise
    except httpx.ConnectError:
        raise HTTPException(503, "Cannot reach probe")


@app.delete("/traffic/stop/{mac}")
async def traffic_stop(mac: str, db: Session = Depends(get_db)):
    mac = mac.lower()
    device = db.get(Device, mac)
    if not device:
        raise HTTPException(404, "Device not found")
    ip = device.ip_address
    if not ip:
        return {"ok": True, "was_monitoring": False}
    try:
        async with _probe_client(timeout=10.0) as client:
            resp = await client.delete(f"{PROBE_URL}/traffic/stop/{ip}")
        if resp.status_code not in (200, 204):
            raise HTTPException(502, f"Probe returned {resp.status_code}")
        return resp.json()
    except HTTPException:
        raise
    except httpx.ConnectError:
        raise HTTPException(503, "Cannot reach probe")


@app.get("/traffic/active")
async def traffic_active():
    try:
        async with _probe_client(timeout=8.0) as client:
            resp = await client.get(f"{PROBE_URL}/traffic/stats")
        if resp.status_code != 200:
            return {"sessions": []}
        return resp.json()
    except Exception:
        return {"sessions": []}


@app.get("/traffic/live/{mac}")
async def traffic_live(mac: str, db: Session = Depends(get_db)):
    mac = mac.lower()
    device = db.get(Device, mac)
    if not device:
        raise HTTPException(404, "Device not found")
    try:
        async with _probe_client(timeout=8.0) as client:
            resp = await client.get(f"{PROBE_URL}/traffic/stats/{mac}")
        if resp.status_code == 404:
            raise HTTPException(404, "No active monitor for this device")
        if resp.status_code != 200:
            raise HTTPException(502, f"Probe returned {resp.status_code}")
        return resp.json()
    except HTTPException:
        raise
    except httpx.ConnectError:
        raise HTTPException(503, "Cannot reach probe")


@app.get("/traffic/history/{mac}")
async def traffic_history(mac: str, days: int = 7, db: Session = Depends(get_db)):
    mac = mac.lower()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    rows = db.execute(
        text("""
            SELECT bucket_ts, bytes_in, bytes_out, packets_in, packets_out,
                   lan_bytes, wan_bytes, dns_queries, tls_sni, http_hosts,
                   top_ips, top_ports, top_countries, protocols, unusual_ports
            FROM traffic_stats
            WHERE mac_address = :mac AND bucket_ts >= :cutoff
            ORDER BY bucket_ts ASC
        """),
        {"mac": mac, "cutoff": cutoff},
    ).fetchall()
    keys = ["ts", "bytes_in", "bytes_out", "packets_in", "packets_out",
            "lan_bytes", "wan_bytes", "dns_queries", "tls_sni", "http_hosts",
            "top_ips", "top_ports", "top_countries", "protocols", "unusual_ports"]
    return {"mac": mac, "history": [dict(zip(keys, r)) for r in rows]}


@app.get("/traffic/top-domains/{mac}")
async def traffic_top_domains(mac: str, days: int = 7, limit: int = 20, db: Session = Depends(get_db)):
    mac = mac.lower()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    rows = db.execute(
        text("""
            SELECT tls_sni, http_hosts, dns_queries
            FROM traffic_stats
            WHERE mac_address = :mac AND bucket_ts >= :cutoff
        """),
        {"mac": mac, "cutoff": cutoff},
    ).fetchall()
    agg: dict = {}
    for row in rows:
        for col in row:
            if not col:
                continue
            for item in col:
                k = item.get("k") if isinstance(item, dict) else None
                v = item.get("v", 1) if isinstance(item, dict) else 1
                if k:
                    agg[k] = agg.get(k, 0) + v
    top = sorted(agg.items(), key=lambda x: x[1], reverse=True)[:limit]
    return {"mac": mac, "top_domains": [{"domain": k, "count": v} for k, v in top]}


@app.get("/traffic/summary")
async def traffic_summary(db: Session = Depends(get_db)):
    cutoff = datetime.now(timezone.utc) - timedelta(days=1)
    row = db.execute(
        text("""
            SELECT
                COUNT(DISTINCT mac_address) AS devices_monitored,
                COALESCE(SUM(bytes_in + bytes_out), 0) AS total_bytes,
                COALESCE(SUM(bytes_in), 0) AS total_bytes_in,
                COALESCE(SUM(bytes_out), 0) AS total_bytes_out,
                COALESCE(SUM(wan_bytes), 0) AS total_wan_bytes,
                COALESCE(SUM(lan_bytes), 0) AS total_lan_bytes
            FROM traffic_stats
            WHERE bucket_ts >= :cutoff
        """),
        {"cutoff": cutoff},
    ).fetchone()
    active_count = 0
    try:
        async with _probe_client(timeout=5.0) as client:
            r = await client.get(f"{PROBE_URL}/traffic/stats")
            if r.status_code == 200:
                active_count = len(r.json().get("sessions", []))
    except Exception:
        pass

    return {
        "active_sessions":   active_count,
        "devices_monitored": row[0] if row else 0,
        "total_bytes":       row[1] if row else 0,
        "total_bytes_in":    row[2] if row else 0,
        "total_bytes_out":   row[3] if row else 0,
        "total_wan_bytes":   row[4] if row else 0,
        "total_lan_bytes":   row[5] if row else 0,
    }


@app.get("/traffic/stream/{mac}")
async def traffic_stream(mac: str):
    """Proxy the probe's SSE stream for a device traffic monitor."""
    mac = mac.lower()

    async def _generate():
        try:
            async with _probe_client(timeout=None) as client:
                async with client.stream("GET", f"{PROBE_URL}/traffic/stream/{mac}") as resp:
                    if resp.status_code != 200:
                        yield f"data: {{\"error\": \"probe {resp.status_code}\"}}\n\n"
                        return
                    async for line in resp.aiter_lines():
                        yield line + "\n"
        except Exception as exc:
            yield f"data: {{\"error\": \"{exc}\"}}\n\n"

    return StreamingResponse(_generate(), media_type="text/event-stream")


# ---------------------------------------------------------------------------
# Docker container monitoring
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Container Hosts — CRUD + helpers
# ---------------------------------------------------------------------------

def _row_to_host(row) -> dict:
    return {
        "id":         row.id,
        "name":       row.name,
        "type":       row.type,
        "url":        row.url,
        "auth_user":  row.auth_user,
        "auth_token": "***" if row.auth_token else None,  # never expose token
        "tls_verify": row.tls_verify,
        "enabled":    row.enabled,
        "node":       row.node,
        "local_ip":   row.local_ip,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@app.get("/container-hosts")
async def list_container_hosts(db: Session = Depends(get_db)):
    rows = db.execute(text("SELECT * FROM container_hosts ORDER BY id")).fetchall()
    return [_row_to_host(r) for r in rows]


@app.post("/container-hosts", status_code=201)
async def create_container_host(body: ContainerHostCreate, db: Session = Depends(get_db)):
    row = db.execute(text("""
        INSERT INTO container_hosts (name, type, url, auth_user, auth_token, tls_verify, enabled, node, local_ip)
        VALUES (:name, :type, :url, :au, :at, :tls, :enabled, :node, :local_ip)
        RETURNING *
    """), {
        "name": body.name, "type": body.type, "url": body.url or None,
        "au": body.auth_user or None, "at": body.auth_token or None,
        "tls": body.tls_verify, "enabled": body.enabled, "node": body.node or "pve",
        "local_ip": body.local_ip or None,
    }).fetchone()
    db.commit()
    if body.enabled:
        _schedule_trivy_db_download_if_missing()
    return _row_to_host(row)


@app.put("/container-hosts/{host_id}")
async def update_container_host(host_id: int, body: ContainerHostUpdate, db: Session = Depends(get_db)):
    row = db.execute(text("SELECT * FROM container_hosts WHERE id = :id"), {"id": host_id}).fetchone()
    if not row:
        raise HTTPException(404, "Host not found.")
    fields = {}
    if body.name       is not None: fields["name"]       = body.name
    if body.type       is not None: fields["type"]       = body.type
    if body.url        is not None: fields["url"]        = body.url or None
    if body.auth_user  is not None: fields["auth_user"]  = body.auth_user or None
    if body.tls_verify is not None: fields["tls_verify"] = body.tls_verify
    if body.enabled    is not None: fields["enabled"]    = body.enabled
    if body.node       is not None: fields["node"]       = body.node or "pve"
    if body.local_ip   is not None: fields["local_ip"]   = body.local_ip or None
    # Only update auth_token if explicitly supplied and not masked
    if body.auth_token is not None and body.auth_token != "***":
        fields["auth_token"] = body.auth_token or None
    if not fields:
        return _row_to_host(row)
    set_clause = ", ".join(f"{k} = :{k}" for k in fields)
    fields["id"] = host_id
    updated = db.execute(text(f"UPDATE container_hosts SET {set_clause} WHERE id = :id RETURNING *"), fields).fetchone()
    db.commit()
    if fields.get("enabled"):
        _schedule_trivy_db_download_if_missing()
    return _row_to_host(updated)


@app.delete("/container-hosts/{host_id}", status_code=204)
async def delete_container_host(host_id: int, db: Session = Depends(get_db)):
    db.execute(text("DELETE FROM container_hosts WHERE id = :id"), {"id": host_id})
    db.commit()


@app.post("/container-hosts/{host_id}/test")
async def test_container_host(host_id: int, db: Session = Depends(get_db)):
    row = db.execute(text("SELECT * FROM container_hosts WHERE id = :id"), {"id": host_id}).fetchone()
    if not row:
        raise HTTPException(404, "Host not found.")

    def _do_test():
        if row.type == "proxmox":
            resp = _proxmox_request(row, "GET", "/api2/json/version")
            return {"ok": True, "detail": f"Proxmox VE {resp.get('data', {}).get('version', '?')}"}
        else:
            client = _make_docker_client(row.url or "unix:///var/run/docker.sock")
            try:
                v = client.version()
                return {"ok": True, "detail": f"Docker {v.get('Version','?')} (API {v.get('ApiVersion','?')})"}
            finally:
                client.close()

    try:
        return await asyncio.to_thread(_do_test)
    except Exception as e:
        return {"ok": False, "detail": str(e)}


def _get_enabled_hosts(db: Session) -> list:
    """Return all enabled container_hosts rows as dicts (with real auth_token)."""
    rows = db.execute(text("SELECT * FROM container_hosts WHERE enabled = true ORDER BY id")).fetchall()
    return [
        {
            "id":         r.id, "name": r.name, "type": r.type,
            "url":        r.url, "auth_user": r.auth_user, "auth_token": r.auth_token,
            "tls_verify": r.tls_verify, "node": r.node, "local_ip": r.local_ip,
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Proxmox helpers
# ---------------------------------------------------------------------------

def _proxmox_request(host, method: str, path: str, **kwargs):
    """Make an authenticated httpx request to a Proxmox VE API.
    host may be a dict or an SQLAlchemy row-like object."""
    if isinstance(host, dict):
        base   = (host.get("url") or "").rstrip("/")
        user   = host.get("auth_user") or ""
        token  = host.get("auth_token") or ""
        verify = host.get("tls_verify", False)
    else:
        base   = (getattr(host, "url",        None) or "").rstrip("/")
        user   = getattr(host, "auth_user",   None) or ""
        token  = getattr(host, "auth_token",  None) or ""
        verify = getattr(host, "tls_verify",  False)
    if not base:
        raise ValueError("Proxmox URL not configured.")
    headers = {}
    if user and token:
        headers["Authorization"] = f"PVEAPIToken={user}={token}"
    with httpx.Client(verify=verify, timeout=15) as client:
        resp = client.request(method, f"{base}{path}", headers=headers, **kwargs)
        resp.raise_for_status()
        return resp.json()

# Keep alias for backward compat within this file
_proxmox_request_row = _proxmox_request


def _fmt_proxmox_container(data: dict, vmid: int, node: str, host: dict, vm_type: str = "lxc") -> dict:
    """Normalise a Proxmox LXC/QEMU container to the same shape as a Docker container."""
    status = data.get("status", "stopped")
    docker_status = "running" if status == "running" else ("paused" if status == "paused" else "exited")
    uptime_secs = data.get("uptime", 0)
    uptime_str = ""
    if uptime_secs:
        h, m = divmod(uptime_secs // 60, 60)
        d, h = divmod(h, 24)
        uptime_str = (f"{d}d " if d else "") + (f"{h}h " if h else "") + f"{m}m"
    template = data.get("ostemplate", data.get("template", ""))
    image = template.split(":")[0].split("/")[-1] if template else f"{vm_type}-{vmid}"
    return {
        "id":             f"px-{host['id']}-{node}-{vmid}",
        "short_id":       str(vmid),
        "name":           data.get("name", f"ct-{vmid}"),
        "image":          image,
        "image_id":       template,
        "status":         docker_status,
        "state": {
            "status":      status,
            "running":     status == "running",
            "paused":      status == "paused",
            "restarting":  False,
            "started_at":  "",
            "finished_at": "",
            "exit_code":   0,
        },
        "ports":          [],
        "networks":       [],
        "mounts":         [],
        "env":            [],
        "labels":         {"proxmox.vmid": str(vmid), "proxmox.node": node, "proxmox.type": vm_type},
        "created":        "",
        "restart_policy": "",
        "platform":       "linux",
        "command":        [],
        "hostname":       data.get("hostname", data.get("name", "")),
        "working_dir":    "",
        "uptime":         uptime_str,
        "host_id":        host["id"],
        "host_name":      host["name"],
        "host_type":      "proxmox",
        "vmid":           vmid,
        "node":           node,
    }


def _fetch_containers_for_host(host: dict) -> list:
    """Fetch and normalise containers from a single host (Docker or Proxmox)."""
    htype = host["type"]
    host_url = host["url"] or "unix:///var/run/docker.sock"

    if htype == "proxmox":
        containers = []
        try:
            nodes_resp = _proxmox_request(host, "GET", "/api2/json/nodes")
            nodes = [n["node"] for n in nodes_resp.get("data", [])]
        except Exception:
            nodes = [host.get("node", "pve")]
        for node in nodes:
            try:
                lxc_resp = _proxmox_request(host, "GET", f"/api2/json/nodes/{node}/lxc")
                for item in lxc_resp.get("data", []):
                    vmid = int(item.get("vmid", 0))
                    if vmid:
                        containers.append(_fmt_proxmox_container(item, vmid, node, host, "lxc"))
            except Exception:
                pass
        return containers

    # Docker (local or remote)
    client = _make_docker_client(host_url)
    try:
        result = []
        for c in client.containers.list(all=True):
            result.append(_add_docker_host_meta(_fmt_container(c), host, host_url))
        return result
    finally:
        client.close()


def _docker_enabled(db: Session) -> bool:
    """Returns True if any container host is enabled (hosts table or legacy setting)."""
    try:
        count = db.execute(text("SELECT COUNT(*) FROM container_hosts WHERE enabled = true")).scalar()
        if count and count > 0:
            return True
    except Exception:
        pass
    s = db.get(Setting, "docker_enabled")
    return (s.value if s else "false") == "true"

def _get_docker_host(db: Session) -> str:
    s = db.get(Setting, "docker_host")
    return (s.value if s else None) or "unix:///var/run/docker.sock"

def _make_docker_client(host: str):
    try:
        import docker as _docker
        return _docker.DockerClient(base_url=host)
    except ImportError:
        raise HTTPException(503, "Docker SDK not installed in backend.")
    except Exception as e:
        raise HTTPException(503, f"Cannot connect to Docker at '{host}': {e}")

def _fmt_container(c) -> dict:
    attrs      = c.attrs or {}
    state      = attrs.get("State", {})
    config     = attrs.get("Config", {})
    host_cfg   = attrs.get("HostConfig", {})
    net        = attrs.get("NetworkSettings", {})

    ports = []
    for cport, bindings in (net.get("Ports") or {}).items():
        if bindings:
            for b in bindings:
                ports.append({"host_ip": b.get("HostIp",""), "host_port": b.get("HostPort",""), "container_port": cport})
        else:
            ports.append({"host_ip": "", "host_port": "", "container_port": cport})

    mounts = [
        {"type": m.get("Type",""), "source": m.get("Source",""), "destination": m.get("Destination",""), "mode": m.get("Mode","")}
        for m in (attrs.get("Mounts") or [])
    ]

    finished = state.get("FinishedAt","")

    return {
        "id":             c.id,
        "short_id":       c.short_id,
        "name":           c.name.lstrip("/"),
        "image":          (config.get("Image") or ""),
        "image_id":       attrs.get("Image",""),
        "status":         c.status,
        "state": {
            "status":      state.get("Status",""),
            "running":     state.get("Running", False),
            "paused":      state.get("Paused", False),
            "restarting":  state.get("Restarting", False),
            "started_at":  state.get("StartedAt",""),
            "finished_at": finished if finished and finished != "0001-01-01T00:00:00Z" else "",
            "exit_code":   state.get("ExitCode", 0),
        },
        "ports":          ports,
        "networks":       list((net.get("Networks") or {}).keys()),
        "mounts":         mounts,
        "env":            config.get("Env") or [],
        "created":        attrs.get("Created",""),
        "labels":         config.get("Labels") or {},
        "restart_policy": (host_cfg.get("RestartPolicy") or {}).get("Name",""),
        "platform":       attrs.get("Platform",""),
        "command":        config.get("Cmd") or [],
        "hostname":       config.get("Hostname",""),
        "working_dir":    config.get("WorkingDir",""),
    }


def _add_docker_host_meta(container: dict, host: dict, host_url: str) -> dict:
    container["host_id"] = host["id"]
    container["host_name"] = host["name"]
    container["host_type"] = host["type"]
    container["host_url"] = host_url
    container["host_local_ip"] = host.get("local_ip")  # Store local_ip for port links
    return container


@app.get("/docker/stats")
async def docker_stats(db: Session = Depends(get_db)):
    hosts = _get_enabled_hosts(db)
    if not hosts:
        raise HTTPException(503, "No container hosts configured. Add one in Settings → Containers.")

    def _do_host(h):
        return _fetch_containers_for_host(h)

    tasks = [asyncio.to_thread(_do_host, h) for h in hosts]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_containers = []
    for r in results:
        if not isinstance(r, Exception):
            all_containers.extend(r)

    counts = {}
    for c in all_containers:
        st = c.get("status", "exited")
        counts[st] = counts.get(st, 0) + 1

    return {
        "total":          len(all_containers),
        "running":        counts.get("running", 0),
        "stopped":        counts.get("exited", 0) + counts.get("created", 0) + counts.get("dead", 0),
        "paused":         counts.get("paused", 0),
        "restarting":     counts.get("restarting", 0),
        "hosts":          len(hosts),
        "connected":      True,
    }


@app.get("/docker/containers")
async def list_docker_containers(db: Session = Depends(get_db)):
    hosts = _get_enabled_hosts(db)
    if not hosts:
        raise HTTPException(503, "No container hosts configured. Add one in Settings → Containers.")

    tasks = [asyncio.to_thread(_fetch_containers_for_host, h) for h in hosts]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_containers = []
    for r in results:
        if not isinstance(r, Exception):
            all_containers.extend(r)

    return all_containers


def _parse_proxmox_id(container_id: str):
    """Parse 'px-{host_id}-{node}-{vmid}' → (host_id, node, vmid) or None."""
    if not container_id.startswith("px-"):
        return None
    parts = container_id.split("-", 3)
    if len(parts) != 4:
        return None
    try:
        return int(parts[1]), parts[2], int(parts[3])
    except ValueError:
        return None


def _get_host_row(db: Session, host_id: int) -> dict:
    row = db.execute(text("SELECT * FROM container_hosts WHERE id = :id"), {"id": host_id}).fetchone()
    if not row:
        raise HTTPException(404, f"Container host {host_id} not found.")
    return {"id": row.id, "name": row.name, "type": row.type, "url": row.url,
            "auth_user": row.auth_user, "auth_token": row.auth_token,
            "tls_verify": row.tls_verify, "node": row.node}


def _proxmox_action(host: dict, node: str, vmid: int, action: str) -> dict:
    """Run a lifecycle action on a Proxmox LXC and return updated container info."""
    import time
    pve_action = "reboot" if action == "restart" else action
    _proxmox_request(host, "POST", f"/api2/json/nodes/{node}/lxc/{vmid}/status/{pve_action}")
    time.sleep(1)
    status_resp = _proxmox_request(host, "GET", f"/api2/json/nodes/{node}/lxc/{vmid}/status/current")
    return _fmt_proxmox_container(status_resp.get("data", {}), vmid, node, host)


@app.get("/docker/containers/{container_id}")
async def get_docker_container(container_id: str, db: Session = Depends(get_db)):
    px = _parse_proxmox_id(container_id)
    if px:
        host_id, node, vmid = px
        host = _get_host_row(db, host_id)
        def _do():
            r = _proxmox_request(host, "GET", f"/api2/json/nodes/{node}/lxc/{vmid}/status/current")
            return _fmt_proxmox_container(r.get("data", {}), vmid, node, host)
        try:
            return await asyncio.to_thread(_do)
        except Exception as e:
            raise HTTPException(503, str(e))

    hosts = _get_enabled_hosts(db)
    docker_hosts = [h for h in hosts if h["type"] != "proxmox"]
    if not docker_hosts:
        raise HTTPException(503, "No Docker hosts configured.")
    host_url = docker_hosts[0]["url"] or "unix:///var/run/docker.sock"

    def _do():
        client = _make_docker_client(host_url)
        try:
            c = client.containers.get(container_id)
            return _add_docker_host_meta(_fmt_container(c), docker_hosts[0], host_url)
        finally:
            client.close()

    try:
        return await asyncio.to_thread(_do)
    except HTTPException:
        raise
    except Exception as e:
        code = 404 if "404" in str(e) or "Not Found" in str(e) else 503
        raise HTTPException(code, str(e))


@app.post("/docker/containers/{container_id}/start")
async def docker_start(container_id: str, db: Session = Depends(get_db)):
    px = _parse_proxmox_id(container_id)
    if px:
        host_id, node, vmid = px
        host = _get_host_row(db, host_id)
        try:
            return await asyncio.to_thread(_proxmox_action, host, node, vmid, "start")
        except Exception as e:
            raise HTTPException(400, str(e))

    hosts = _get_enabled_hosts(db)
    docker_hosts = [h for h in hosts if h["type"] != "proxmox"]
    if not docker_hosts:
        raise HTTPException(503, "No Docker hosts.")
    host_url = docker_hosts[0]["url"] or "unix:///var/run/docker.sock"

    def _do():
        client = _make_docker_client(host_url)
        try:
            c = client.containers.get(container_id)
            c.start(); c.reload()
            return _add_docker_host_meta(_fmt_container(c), docker_hosts[0], host_url)
        finally:
            client.close()

    try:
        return await asyncio.to_thread(_do)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, str(e))


@app.post("/docker/containers/{container_id}/stop")
async def docker_stop(container_id: str, db: Session = Depends(get_db)):
    px = _parse_proxmox_id(container_id)
    if px:
        host_id, node, vmid = px
        host = _get_host_row(db, host_id)
        try:
            return await asyncio.to_thread(_proxmox_action, host, node, vmid, "stop")
        except Exception as e:
            raise HTTPException(400, str(e))

    hosts = _get_enabled_hosts(db)
    docker_hosts = [h for h in hosts if h["type"] != "proxmox"]
    if not docker_hosts:
        raise HTTPException(503, "No Docker hosts.")
    host_url = docker_hosts[0]["url"] or "unix:///var/run/docker.sock"

    def _do():
        client = _make_docker_client(host_url)
        try:
            c = client.containers.get(container_id)
            c.stop(timeout=10); c.reload()
            return _add_docker_host_meta(_fmt_container(c), docker_hosts[0], host_url)
        finally:
            client.close()

    try:
        return await asyncio.to_thread(_do)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, str(e))


@app.post("/docker/containers/{container_id}/restart")
async def docker_restart(container_id: str, db: Session = Depends(get_db)):
    px = _parse_proxmox_id(container_id)
    if px:
        host_id, node, vmid = px
        host = _get_host_row(db, host_id)
        try:
            return await asyncio.to_thread(_proxmox_action, host, node, vmid, "restart")
        except Exception as e:
            raise HTTPException(400, str(e))

    hosts = _get_enabled_hosts(db)
    docker_hosts = [h for h in hosts if h["type"] != "proxmox"]
    if not docker_hosts:
        raise HTTPException(503, "No Docker hosts.")
    host_url = docker_hosts[0]["url"] or "unix:///var/run/docker.sock"

    def _do():
        client = _make_docker_client(host_url)
        try:
            c = client.containers.get(container_id)
            c.restart(timeout=10); c.reload()
            return _add_docker_host_meta(_fmt_container(c), docker_hosts[0], host_url)
        finally:
            client.close()

    try:
        return await asyncio.to_thread(_do)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, str(e))


@app.delete("/docker/containers/{container_id}")
async def docker_delete(container_id: str, db: Session = Depends(get_db)):
    """Delete (remove) a container."""
    px = _parse_proxmox_id(container_id)
    if px:
        host_id, node, vmid = px
        host = _get_host_row(db, host_id)
        try:
            # Delete Proxmox LXC
            _proxmox_request(host, "DELETE", f"/api2/json/nodes/{node}/lxc/{vmid}")
            return {"status": "deleted"}
        except Exception as e:
            raise HTTPException(400, str(e))

    hosts = _get_enabled_hosts(db)
    docker_hosts = [h for h in hosts if h["type"] != "proxmox"]
    if not docker_hosts:
        raise HTTPException(503, "No Docker hosts.")
    host_url = docker_hosts[0]["url"] or "unix:///var/run/docker.sock"

    def _do():
        client = _make_docker_client(host_url)
        try:
            c = client.containers.get(container_id)
            # Stop if running
            if c.status != "exited":
                c.stop(timeout=10)
            # Remove container
            c.remove(force=True)
            return {"status": "deleted", "container_id": container_id}
        finally:
            client.close()

    try:
        return await asyncio.to_thread(_do)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, str(e))


@app.post("/docker/containers/{container_id}/update")
async def docker_update(container_id: str, db: Session = Depends(get_db)):
    """Update container by pulling latest image and recreating it (Watchtower-like)."""
    px = _parse_proxmox_id(container_id)
    if px:
        raise HTTPException(400, "Update is not supported for Proxmox containers.")

    hosts = _get_enabled_hosts(db)
    docker_hosts = [h for h in hosts if h["type"] != "proxmox"]
    if not docker_hosts:
        raise HTTPException(503, "No Docker hosts.")
    host_url = docker_hosts[0]["url"] or "unix:///var/run/docker.sock"

    def _do():
        client = _make_docker_client(host_url)
        try:
            c = client.containers.get(container_id)
            # Store current container config before deletion
            image_name = c.image.tags[0] if c.image.tags else str(c.image.id)
            
            # Pull latest image
            try:
                client.images.pull(image_name)
            except Exception as pull_err:
                # If pull fails, continue anyway - might use cached image
                pass
            
            # Get current container config
            attrs = c.attrs or {}
            config = attrs.get("Config", {})
            host_cfg = attrs.get("HostConfig", {})
            
            # Stop container
            if c.status != "exited":
                c.stop(timeout=10)
            
            # Remove old container
            c.remove(force=True)
            
            # Create new container with same config
            new_c = client.containers.create(
                image=image_name,
                command=config.get("Cmd"),
                environment=config.get("Env"),
                labels=config.get("Labels"),
                hostname=config.get("Hostname"),
                working_dir=config.get("WorkingDir"),
                name=c.name.lstrip("/"),
                ports=None,  # Will be handled by port bindings in host_config
                volumes=None,  # Will be handled by binds in host_config
                restart_policy={"Name": host_cfg.get("RestartPolicy", {}).get("Name", "no")},
                host_config=client.api.create_host_config(
                    port_bindings={
                        p.split("/")[0]: int(b.get("HostPort", 0)) 
                        for p, bindings in (attrs.get("NetworkSettings", {}).get("Ports") or {}).items()
                        if bindings
                        for b in bindings
                    },
                    binds={
                        m.get("Source", ""): {"bind": m.get("Destination", ""), "mode": m.get("Mode", "rw")}
                        for m in (attrs.get("Mounts") or [])
                        if m.get("Type") == "bind"
                    },
                ),
            )
            
            # Start new container
            new_c.start()
            new_c.reload()
            return _add_docker_host_meta(_fmt_container(new_c), docker_hosts[0], host_url)
        finally:
            client.close()

    try:
        return await asyncio.to_thread(_do)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, str(e))


@app.get("/docker/containers/{container_id}/logs")
async def stream_docker_logs(container_id: str, tail: int = 100, db: Session = Depends(get_db)):
    """Stream container logs as SSE."""
    if container_id.startswith("px-"):
        raise HTTPException(400, "Log streaming is not yet available for Proxmox containers.")
    if not _docker_enabled(db):
        raise HTTPException(503, "No container hosts configured.")
    docker_hosts = [h for h in _get_enabled_hosts(db) if h["type"] != "proxmox"]
    host = docker_hosts[0]["url"] if docker_hosts else _get_docker_host(db)

    line_queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_event_loop()

    def _stream():
        try:
            client = _make_docker_client(host)
            c = client.containers.get(container_id)
            for raw in c.logs(stream=True, follow=True, tail=tail, timestamps=True):
                line = raw.decode("utf-8", errors="replace").rstrip("\n")
                loop.call_soon_threadsafe(line_queue.put_nowait, line)
        except Exception as exc:
            loop.call_soon_threadsafe(line_queue.put_nowait, f"[ERROR] {exc}")
        finally:
            loop.call_soon_threadsafe(line_queue.put_nowait, None)

    threading.Thread(target=_stream, daemon=True).start()

    async def _gen():
        while True:
            try:
                line = await asyncio.wait_for(line_queue.get(), timeout=120)
            except asyncio.TimeoutError:
                break
            if line is None:
                break
            yield f"data: {line}\n\n"

    return StreamingResponse(_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def _parse_trivy_json(data: dict) -> list:
    """Flatten Trivy JSON output into a list of structured vulnerability dicts."""
    vulns = []
    for result in data.get("Results", []):
        target = result.get("Target", "")
        for v in (result.get("Vulnerabilities") or []):
            cvss_score = None
            for src in (v.get("CVSS") or {}).values():
                score = src.get("V3Score") or src.get("V2Score")
                if score:
                    cvss_score = score
                    break
            vulns.append({
                "id":        v.get("VulnerabilityID", ""),
                "severity":  v.get("Severity", "UNKNOWN").lower(),
                "pkg":       v.get("PkgName", ""),
                "installed": v.get("InstalledVersion", ""),
                "fixed":     v.get("FixedVersion", ""),
                "title":     v.get("Title", ""),
                "cvss":      cvss_score,
                "target":    target,
            })
    return vulns


# ---------------------------------------------------------------------------
# Compose file generation
# ---------------------------------------------------------------------------

def _generate_compose_yaml(c) -> tuple[str, dict]:
    """Return (yaml_string, meta) for a container object.

    meta contains:
      compose_managed: bool — whether container was started via docker compose
      project:         str | None
      service:         str | None
    """
    attrs    = c.attrs or {}
    cfg      = attrs.get("Config", {})
    hcfg     = attrs.get("HostConfig", {})
    net_sets = attrs.get("NetworkSettings", {})
    name     = c.name.lstrip("/")
    labels   = cfg.get("Labels") or {}

    compose_managed = bool(labels.get("com.docker.compose.project"))
    meta = {
        "compose_managed": compose_managed,
        "project":  labels.get("com.docker.compose.project"),
        "service":  labels.get("com.docker.compose.service"),
    }

    svc: dict = {}

    # image
    svc["image"] = cfg.get("Image") or ""

    # container_name
    svc["container_name"] = name

    # restart
    rp      = hcfg.get("RestartPolicy") or {}
    rp_name = rp.get("Name", "no") or "no"
    if rp_name not in ("no", ""):
        if rp_name == "on-failure":
            max_r = rp.get("MaximumRetryCount") or 0
            svc["restart"] = f"on-failure:{max_r}" if max_r else "on-failure"
        else:
            svc["restart"] = rp_name

    # ports
    ports = []
    for cport, bindings in (net_sets.get("Ports") or {}).items():
        if bindings:
            for b in bindings:
                hip   = b.get("HostIp", "") or ""
                hport = b.get("HostPort", "") or ""
                if hip and hip not in ("0.0.0.0", "::", ""):
                    ports.append(f"{hip}:{hport}:{cport}" if hport else cport)
                else:
                    ports.append(f"{hport}:{cport}" if hport else cport)
        else:
            # exposed but not published
            ports.append(cport)
    if ports:
        svc["ports"] = ports

    # volumes / bind mounts
    volumes  = []
    tmpfs    = []
    top_vols = {}
    for m in (attrs.get("Mounts") or []):
        mtype = m.get("Type", "bind")
        src   = m.get("Source", "") or ""
        dst   = m.get("Destination", "") or ""
        mode  = m.get("Mode", "") or ""
        if mtype == "tmpfs":
            tmpfs.append(dst)
        elif mtype == "volume":
            vol_name = m.get("Name") or src
            v = f"{vol_name}:{dst}"
            if mode and mode not in ("", "rw"):
                v += f":{mode}"
            volumes.append(v)
            if vol_name:
                top_vols[vol_name] = None  # mark for top-level volumes block
        else:  # bind
            v = f"{src}:{dst}"
            if mode and mode not in ("", "rw", "z"):
                v += f":{mode}"
            volumes.append(v)
    if volumes:
        svc["volumes"] = volumes
    if tmpfs:
        svc["tmpfs"] = tmpfs

    # environment (skip empty, mask nothing — user can see their own config)
    env = [e for e in (cfg.get("Env") or []) if e and "=" in e]
    if env:
        svc["environment"] = env

    # entrypoint
    ep = cfg.get("Entrypoint")
    if ep:
        svc["entrypoint"] = ep[0] if len(ep) == 1 else ep

    # command (skip if identical to entrypoint)
    cmd = cfg.get("Cmd")
    if cmd and cmd != ep:
        svc["command"] = cmd[0] if len(cmd) == 1 else cmd

    # hostname (skip docker-assigned default = first 12 chars of ID)
    hn = cfg.get("Hostname") or ""
    cid = attrs.get("Id", "") or ""
    if hn and hn != cid[:12]:
        svc["hostname"] = hn

    # working dir
    wd = cfg.get("WorkingDir") or ""
    if wd:
        svc["working_dir"] = wd

    # user
    user = cfg.get("User") or ""
    if user:
        svc["user"] = user

    # network_mode / networks
    networks    = net_sets.get("Networks") or {}
    net_names   = list(networks.keys())
    _std_nets   = {"bridge", "host", "none"}
    custom_nets = [n for n in net_names if n not in _std_nets]
    _hc_net_mode = (hcfg.get("NetworkMode") or "").lower()
    if _hc_net_mode == "host" or "host" in net_names:
        svc["network_mode"] = "host"
    elif _hc_net_mode == "none":
        svc["network_mode"] = "none"
    elif _hc_net_mode.startswith("container:"):
        _parent_ref = hcfg["NetworkMode"].split(":", 1)[1]
        try:
            _parent = c.client.containers.get(_parent_ref)
            _parent_name = _parent.name.lstrip("/")
        except Exception:
            _parent_name = _parent_ref  # fall back to raw ID/name
        svc["network_mode"] = f"container:{_parent_name}"
    elif custom_nets:
        net_block = {}
        for n in custom_nets:
            aliases = (networks.get(n) or {}).get("Aliases") or []
            # strip docker-assigned aliases (container name + short ID)
            real_aliases = [a for a in aliases if a not in (name, cid[:12])]
            net_block[n] = {"aliases": real_aliases} if real_aliases else {}
        svc["networks"] = net_block

    # extra_hosts
    extra_hosts = [h for h in (hcfg.get("ExtraHosts") or []) if h]
    if extra_hosts:
        svc["extra_hosts"] = extra_hosts

    # capabilities
    cap_add  = hcfg.get("CapAdd")  or []
    cap_drop = hcfg.get("CapDrop") or []
    if cap_add:
        svc["cap_add"]  = cap_add
    if cap_drop:
        svc["cap_drop"] = cap_drop

    if hcfg.get("Privileged"):
        svc["privileged"] = True

    # devices
    devs = [
        f"{d['PathOnHost']}:{d['PathInContainer']}"
        for d in (hcfg.get("Devices") or [])
        if d.get("PathOnHost")
    ]
    if devs:
        svc["devices"] = devs

    # dns
    dns = [d for d in (hcfg.get("Dns") or []) if d]
    if dns:
        svc["dns"] = dns

    # resource limits
    mem = hcfg.get("Memory") or 0
    if mem:
        if mem >= 1024 ** 3:
            svc["mem_limit"] = f"{mem // 1024**3}g"
        elif mem >= 1024 ** 2:
            svc["mem_limit"] = f"{mem // 1024**2}m"
        else:
            svc["mem_limit"] = f"{mem // 1024}k"

    nano = hcfg.get("NanoCpus") or 0
    if nano:
        svc["cpus"] = round(nano / 1e9, 4)

    # sysctls
    sysctls = hcfg.get("Sysctls") or {}
    if sysctls:
        svc["sysctls"] = sysctls

    # logging
    log_cfg = hcfg.get("LogConfig") or {}
    log_driver = log_cfg.get("Type") or ""
    if log_driver and log_driver not in ("json-file", ""):
        log_block: dict = {"driver": log_driver}
        log_opts = log_cfg.get("Config") or {}
        if log_opts:
            log_block["options"] = log_opts
        svc["logging"] = log_block

    # build compose document
    compose: dict = {"services": {name: svc}}

    if top_vols:
        compose["volumes"] = {v: None for v in top_vols}

    if custom_nets and "network_mode" not in svc:
        compose["networks"] = {n: {"external": True} for n in custom_nets}

    yaml_str = _yaml.dump(compose, default_flow_style=False, sort_keys=False, allow_unicode=True)
    return yaml_str, meta


@app.get("/docker/containers/{container_id}/compose")
async def get_container_compose(container_id: str, db: Session = Depends(get_db)):
    """Return a docker-compose.yml snippet generated from the container's live config."""
    if container_id.startswith("px-"):
        raise HTTPException(400, "Compose generation is not available for Proxmox containers.")
    if not _docker_enabled(db):
        raise HTTPException(503, "No container hosts configured.")

    hosts      = _get_enabled_hosts(db)
    docker_h   = [h for h in hosts if h["type"] != "proxmox"]
    if not docker_h:
        raise HTTPException(503, "No Docker hosts configured.")
    host_url   = docker_h[0]["url"] or "unix:///var/run/docker.sock"

    def _do():
        client = _make_docker_client(host_url)
        try:
            c = client.containers.get(container_id)
            return _generate_compose_yaml(c)
        finally:
            client.close()

    try:
        yaml_str, meta = await asyncio.to_thread(_do)
        return {"yaml": yaml_str, **meta}
    except HTTPException:
        raise
    except Exception as e:
        code = 404 if "404" in str(e) or "Not Found" in str(e) else 503
        raise HTTPException(code, str(e))


@app.get("/docker/containers/{container_id}/trivy-scan")
async def stream_docker_trivy_scan(container_id: str, db: Session = Depends(get_db)):
    """Stream a Trivy vulnerability scan of the container image as SSE."""
    if container_id.startswith("px-"):
        raise HTTPException(400, "Trivy image scanning is not available for Proxmox containers.")
    if not _docker_enabled(db):
        raise HTTPException(503, "No container hosts configured.")
    # Resolve the Docker host for this container
    hosts = _get_enabled_hosts(db)
    docker_hosts = [h for h in hosts if h["type"] != "proxmox"]
    host = docker_hosts[0]["url"] if docker_hosts else _get_docker_host(db)

    def _get_container_info():
        client = _make_docker_client(host)
        try:
            c = client.containers.get(container_id)
            image = (c.attrs.get("Config") or {}).get("Image", "")
            name  = c.name.lstrip("/")
            return image, name
        finally:
            client.close()

    try:
        image, container_name = await asyncio.to_thread(_get_container_info)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, str(e))

    if not image:
        raise HTTPException(400, "Could not determine container image.")

    line_queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_event_loop()

    def _run():
        if not shutil.which("trivy"):
            loop.call_soon_threadsafe(line_queue.put_nowait,
                "LOG: [ERROR] Trivy is not installed in this container.")
            loop.call_soon_threadsafe(line_queue.put_nowait, "TRIVY_DONE")
            loop.call_soon_threadsafe(line_queue.put_nowait, None)
            return
        try:
            proc = subprocess.Popen(
                ["trivy", "image", "--format", "json", "--no-progress", "--scanners", "vuln", image],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            )
            stdout_data = proc.stdout.read()
            proc.wait()

            scanned_at = datetime.now(timezone.utc).isoformat()
            if proc.returncode == 0 and stdout_data.strip():
                try:
                    vulns = _parse_trivy_json(json.loads(stdout_data))
                except Exception as parse_err:
                    vulns = []
                    loop.call_soon_threadsafe(line_queue.put_nowait,
                        f"LOG: [ERROR] Could not parse Trivy output: {parse_err}")
            else:
                vulns = []
                if proc.returncode != 0:
                    loop.call_soon_threadsafe(line_queue.put_nowait,
                        f"LOG: [ERROR] Trivy exited with code {proc.returncode}")

            _save_trivy_result(container_name, image, vulns, scanned_at)
            result_payload = json.dumps({"vulns": vulns, "image": image, "scanned_at": scanned_at})
            loop.call_soon_threadsafe(line_queue.put_nowait, f"TRIVY_RESULT:{result_payload}")
        except Exception as exc:
            loop.call_soon_threadsafe(line_queue.put_nowait, f"LOG: [ERROR] {exc}")
        finally:
            loop.call_soon_threadsafe(line_queue.put_nowait, "TRIVY_DONE")
            loop.call_soon_threadsafe(line_queue.put_nowait, None)

    threading.Thread(target=_run, daemon=True).start()

    async def _gen():
        while True:
            try:
                line = await asyncio.wait_for(line_queue.get(), timeout=300)
            except asyncio.TimeoutError:
                yield "data: TRIVY_DONE\n\n"
                break
            if line is None:
                break
            yield f"data: {line}\n\n"

    return StreamingResponse(_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------------------
# Trivy DB helpers
# ---------------------------------------------------------------------------
_TRIVY_DB_META = "/root/.cache/trivy/db/metadata.json"
_TRIVY_FREQ_SECONDS = {"1d": 86400, "2d": 172800, "7d": 604800, "30d": 2592000}
_trivy_db_update_lock = asyncio.Lock()


def _trivy_db_status() -> dict:
    """Return metadata from the on-disk Trivy DB, or exists=False if absent."""
    try:
        with open(_TRIVY_DB_META) as f:
            meta = json.load(f)
        return {
            "exists": True,
            "updated_at":    meta.get("UpdatedAt"),
            "next_update":   meta.get("NextUpdate"),
            "downloaded_at": meta.get("DownloadedAt"),
        }
    except Exception:
        return {"exists": False, "updated_at": None, "next_update": None, "downloaded_at": None}


async def _run_trivy_db_download():
    """Download/refresh the Trivy DB, streaming output to callers via an asyncio.Queue."""
    if _trivy_db_update_lock.locked() or not shutil.which("trivy"):
        return
    async with _trivy_db_update_lock:
        try:
            proc = await asyncio.create_subprocess_exec(
                "trivy", "image", "--download-db-only",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            if proc.stdout:
                async for raw in proc.stdout:
                    line = raw.decode(errors="replace").rstrip()
                    if line:
                        print(f"[trivy_db] {line}", flush=True)
            await proc.wait()
            if proc.returncode == 0:
                print("[trivy_db] Vulnerability DB updated.", flush=True)
            else:
                print(f"[trivy_db] Update exited with code {proc.returncode}.", flush=True)
        except Exception as exc:
            print(f"[trivy_db] Update failed: {exc}", flush=True)


def _schedule_trivy_db_download_if_missing():
    """Fire-and-forget: download DB if it doesn't exist yet."""
    if not _trivy_db_status()["exists"] and shutil.which("trivy"):
        asyncio.ensure_future(_run_trivy_db_download())


# ---------------------------------------------------------------------------
# Trivy DB update background loop
# ---------------------------------------------------------------------------
async def _trivy_db_update_loop():
    """Periodically refreshes the Trivy vulnerability database."""
    await asyncio.sleep(60)  # startup grace — let the container settle
    # Immediate download if DB is absent (e.g. fresh volume)
    if not _trivy_db_status()["exists"] and shutil.which("trivy"):
        print("[trivy_db] DB not found — downloading now.", flush=True)
        await _run_trivy_db_download()
    while True:
        db = SessionLocal()
        try:
            s = db.get(Setting, "trivy_db_update_frequency")
            freq = s.value.strip() if s and s.value else "1d"
        except Exception:
            freq = "1d"
        finally:
            db.close()

        interval = _TRIVY_FREQ_SECONDS.get(freq, 0)
        if interval > 0 and shutil.which("trivy"):
            await _run_trivy_db_download()

        await asyncio.sleep(interval if interval > 0 else 86400)


# ---------------------------------------------------------------------------
# Trivy DB status + force-update endpoints
# ---------------------------------------------------------------------------
@app.get("/trivy/db-status")
async def trivy_db_status_endpoint(_user: str = Depends(get_current_user)):
    status = _trivy_db_status()
    status["updating"] = _trivy_db_update_lock.locked()
    return status


@app.get("/trivy/db-update")
async def trivy_db_update_stream(_user: str = Depends(get_current_user)):
    """SSE stream that triggers a Trivy DB download and streams its output."""
    if not shutil.which("trivy"):
        async def _no_trivy():
            yield "data: [ERROR] Trivy binary not found in container.\n\n"
            yield "data: TRIVY_DB_DONE\n\n"
        return StreamingResponse(_no_trivy(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    async def _stream():
        if _trivy_db_update_lock.locked():
            yield "data: [INFO] Update already in progress — please wait.\n\n"
            yield "data: TRIVY_DB_DONE\n\n"
            return
        async with _trivy_db_update_lock:
            try:
                yield "data: [INFO] Starting Trivy vulnerability DB download…\n\n"
                proc = await asyncio.create_subprocess_exec(
                    "trivy", "image", "--download-db-only",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                if proc.stdout:
                    async for raw in proc.stdout:
                        line = raw.decode(errors="replace").rstrip()
                        if line:
                            yield f"data: {line}\n\n"
                await proc.wait()
                if proc.returncode == 0:
                    yield "data: [INFO] Trivy DB updated successfully.\n\n"
                else:
                    yield f"data: [ERROR] Update exited with code {proc.returncode}.\n\n"
            except Exception as exc:
                yield f"data: [ERROR] {exc}\n\n"
        yield "data: TRIVY_DB_DONE\n\n"

    return StreamingResponse(_stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------------------
# Nuclei template status + force-update endpoints (proxy to probe)
# ---------------------------------------------------------------------------
@app.get("/nuclei/template-status")
async def nuclei_template_status(_user: str = Depends(get_current_user)):
    try:
        async with _probe_client(timeout=10) as client:
            r = await client.get(f"{PROBE_URL}/nuclei/status")
            return r.json()
    except Exception:
        return {"exists": False, "version": None, "last_updated": None, "binary_available": False}


@app.get("/nuclei/template-update")
async def nuclei_template_update_stream(_user: str = Depends(get_current_user)):
    """SSE proxy: streams Nuclei template update output from the probe."""
    async def _proxy():
        try:
            async with _probe_client(timeout=None) as client:
                async with client.stream("GET", f"{PROBE_URL}/nuclei/update") as r:
                    async for line in r.aiter_lines():
                        if line:
                            yield f"{line}\n"
                        else:
                            yield "\n"
        except Exception as exc:
            yield f"data: [ERROR] Could not reach probe: {exc}\n\n"
            yield "data: NUCLEI_UPDATE_DONE\n\n"

    return StreamingResponse(_proxy(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------------------
# Docker event watcher (auto-scan on new/updated containers)
# ---------------------------------------------------------------------------
_container_vuln_scans: dict = {}   # name -> {scanning: bool, image: str} (in-memory scan state only)


def _save_trivy_result(name: str, image: str, vulns: list, scanned_at: str):
    """Persist a Trivy scan result to the database so it survives restarts."""
    try:
        db = SessionLocal()
        db.execute(text("""
            INSERT INTO container_vuln_results (name, image, vulns, scanned_at)
            VALUES (:name, :image, cast(:vulns as jsonb), :scanned_at)
            ON CONFLICT (name) DO UPDATE
                SET image = EXCLUDED.image,
                    vulns = EXCLUDED.vulns,
                    scanned_at = EXCLUDED.scanned_at
        """), {"name": name, "image": image, "vulns": json.dumps(vulns), "scanned_at": scanned_at})
        db.commit()
    except Exception as e:
        print(f"[trivy] DB save failed for {name}: {e}", flush=True)
    finally:
        db.close()


def _run_trivy_for_container(name: str, image: str):
    """Run Trivy synchronously and persist results to the database."""
    _container_vuln_scans[name] = {"scanning": True, "image": image}
    if not shutil.which("trivy"):
        _container_vuln_scans[name]["scanning"] = False
        return
    try:
        proc = subprocess.Popen(
            ["trivy", "image", "--format", "json", "--no-progress", "--scanners", "vuln", image],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        stdout_data = proc.stdout.read()
        proc.wait()
        scanned_at = datetime.now(timezone.utc).isoformat()
        if proc.returncode == 0 and stdout_data.strip():
            try:
                vulns = _parse_trivy_json(json.loads(stdout_data))
            except Exception:
                vulns = []
        else:
            vulns = []
        _save_trivy_result(name, image, vulns, scanned_at)
        if vulns and _main_loop and not _main_loop.is_closed():
            severities = {v.get("severity", "").upper() for v in vulns}
            if "CRITICAL" in severities:
                crit = sum(1 for v in vulns if v.get("severity", "").upper() == "CRITICAL")
                asyncio.run_coroutine_threadsafe(
                    _notification_dispatch("container.vuln_critical", "Container Critical Vulnerability",
                                           f"{name}: {crit} critical vulnerability/ies found"),
                    _main_loop,
                )
            elif "HIGH" in severities:
                high = sum(1 for v in vulns if v.get("severity", "").upper() == "HIGH")
                asyncio.run_coroutine_threadsafe(
                    _notification_dispatch("container.vuln_high", "Container High Vulnerability",
                                           f"{name}: {high} high-severity vulnerability/ies found"),
                    _main_loop,
                )
    except Exception as exc:
        print(f"[trivy] {name}: {exc}", flush=True)
    finally:
        _container_vuln_scans[name]["scanning"] = False


def _record_container_event(name: str, status: str):
    """Persist a container start/stop event to the DB for timeline tracking."""
    try:
        db = SessionLocal()
        db.execute(text("INSERT INTO container_events (name, status) VALUES (:n, :s)"),
                   {"n": name, "s": status})
        db.commit()
    except Exception as e:
        print(f"[container_events] DB write failed: {e}", flush=True)
    finally:
        db.close()


async def _docker_event_loop():
    """Watch Docker events: auto-scan containers and record timeline events."""
    await asyncio.sleep(45)  # startup grace
    while True:
        db = SessionLocal()
        try:
            enabled = _docker_enabled(db)
            scan_on_new    = db.get(Setting, "docker_scan_on_new")
            scan_on_update = db.get(Setting, "docker_scan_on_update")
            do_new    = enabled and scan_on_new    and scan_on_new.value    == "true"
            do_update = enabled and scan_on_update and scan_on_update.value == "true"
            if enabled:
                docker_hosts = [h for h in _get_enabled_hosts(db) if h["type"] != "proxmox"]
                host = docker_hosts[0]["url"] if docker_hosts else _get_docker_host(db)
            else:
                host = None
        except Exception:
            enabled = False
            host = None
            do_new = do_update = False
        finally:
            db.close()

        if not enabled:
            await asyncio.sleep(30)
            continue

        try:
            def _watch():
                client = _make_docker_client(host)
                seen_images: dict = {}

                # Record current state as baseline
                try:
                    for c in client.containers.list(all=True):
                        cname  = c.name.lstrip("/")
                        seen_images[cname] = c.image.tags[0] if c.image.tags else c.image.id
                except Exception:
                    pass

                try:
                    for event in client.events(decode=True):
                        action = event.get("Action", "")
                        actor  = event.get("Actor", {})
                        attrs  = actor.get("Attributes", {})
                        cname  = attrs.get("name", "")
                        image  = attrs.get("image", "")

                        # Timeline recording
                        if action == "start":
                            threading.Thread(target=_record_container_event,
                                             args=(cname, "running"), daemon=True).start()
                        elif action in ("die", "stop", "kill", "pause"):
                            status = "paused" if action == "pause" else "stopped"
                            threading.Thread(target=_record_container_event,
                                             args=(cname, status), daemon=True).start()
                            if action == "die":
                                exit_code = attrs.get("exitCode", "0")
                                if exit_code != "0" and _main_loop and not _main_loop.is_closed():
                                    asyncio.run_coroutine_threadsafe(
                                        _notification_dispatch(
                                            "container.crashed", "Container Crashed",
                                            f"Container {cname!r} exited with code {exit_code}",
                                        ),
                                        _main_loop,
                                    )

                        # Auto-scan logic
                        if action == "create" and do_new:
                            threading.Thread(target=_run_trivy_for_container,
                                             args=(cname, image), daemon=True).start()
                        elif action == "start" and do_update:
                            prev = seen_images.get(cname)
                            if prev and prev != image:
                                threading.Thread(target=_run_trivy_for_container,
                                                 args=(cname, image), daemon=True).start()

                        if action in ("create", "start"):
                            seen_images[cname] = image
                except Exception:
                    pass
                finally:
                    client.close()

            await asyncio.to_thread(_watch)
        except Exception as e:
            print(f"[docker_events] {e}", flush=True)

        await asyncio.sleep(10)


@app.get("/docker/auto-scan/{name}")
async def docker_auto_scan_result(name: str, db: Session = Depends(get_db)):
    """Return the stored Trivy scan result for a container name."""
    # If a scan is actively running, report that
    mem = _container_vuln_scans.get(name)
    if mem and mem.get("scanning"):
        return {"scanning": True, "vulns": [], "image": mem.get("image", ""), "scanned_at": None}
    # Read persisted result from DB
    row = db.execute(
        text("SELECT image, vulns, scanned_at FROM container_vuln_results WHERE name = :name"),
        {"name": name},
    ).fetchone()
    if row is None:
        raise HTTPException(404, "No scan data for this container.")
    vulns = row.vulns if isinstance(row.vulns, list) else json.loads(row.vulns or "[]")
    return {
        "scanning": False,
        "image": row.image,
        "vulns": vulns,
        "scanned_at": row.scanned_at.isoformat() if row.scanned_at else None,
    }


@app.get("/docker/vuln-summary")
async def docker_vuln_summary(db: Session = Depends(get_db)):
    """Return aggregated Trivy scan results for all containers (in-memory)."""
    if not _docker_enabled(db):
        raise HTTPException(503, "Docker monitoring is disabled.")

    rows = db.execute(
        text("SELECT name, image, vulns, scanned_at FROM container_vuln_results ORDER BY scanned_at DESC")
    ).fetchall()
    result = []
    for row in rows:
        vulns = row.vulns if isinstance(row.vulns, list) else json.loads(row.vulns or "[]")
        scanning = _container_vuln_scans.get(row.name, {}).get("scanning", False)
        scanned_at = row.scanned_at.isoformat() if row.scanned_at else None
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in vulns:
            sev = v.get("severity", "").lower()
            if sev in counts:
                counts[sev] += 1
        if counts["critical"] > 0:        severity = "critical"
        elif counts["high"] > 0:          severity = "high"
        elif counts["medium"] > 0:        severity = "medium"
        elif counts["low"] > 0:           severity = "low"
        elif scanned_at:                  severity = "clean"
        else:                             severity = None
        result.append({
            "name":       row.name,
            "image":      row.image,
            "scanning":   scanning,
            "severity":   severity,
            "counts":     counts,
            "vulns":      vulns,
            "scanned_at": scanned_at,
        })
    return result


@app.post("/docker/scan-all")
async def docker_scan_all(db: Session = Depends(get_db)):
    """Trigger Trivy scans on all running containers."""
    if not _docker_enabled(db):
        raise HTTPException(503, "Docker monitoring is disabled.")
    host = _get_docker_host(db)

    def _get_containers():
        client = _make_docker_client(host)
        try:
            return [(c.name.lstrip("/"), (c.image.tags[0] if c.image.tags else c.image.id))
                    for c in client.containers.list()]
        finally:
            client.close()

    try:
        containers = await asyncio.to_thread(_get_containers)
    except Exception as e:
        raise HTTPException(503, str(e))

    # Run scans sequentially in a single thread — parallel Trivy processes compete
    # for the shared vulnerability DB and fail silently, returning empty results.
    def _run_all():
        for name, image in containers:
            _run_trivy_for_container(name, image)

    threading.Thread(target=_run_all, daemon=True).start()

    return {"started": len(containers), "containers": [n for n, _ in containers]}


@app.get("/docker/timeline")
async def docker_timeline(days: int = Query(7, ge=1, le=365), db: Session = Depends(get_db)):
    """Return container uptime timeline data keyed by container NAME."""
    if not _docker_enabled(db):
        raise HTTPException(503, "Docker monitoring is disabled.")

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=days)

    rows = db.execute(
        text("SELECT name, status, ts FROM container_events WHERE ts >= :start ORDER BY name, ts"),
        {"start": window_start},
    ).fetchall()

    # Also get current state from Docker daemon
    host = _get_docker_host(db)
    current_states: dict = {}
    try:
        def _get_states():
            client = _make_docker_client(host)
            try:
                return {c.name.lstrip("/"): c.status for c in client.containers.list(all=True)}
            finally:
                client.close()
        current_states = await asyncio.to_thread(_get_states)
    except Exception:
        pass

    # Group events by name
    events_by_name: dict = defaultdict(list)
    for name, status, ts in rows:
        events_by_name[name].append({"status": status, "ts": ts})

    # Build segments from events
    containers_out = []
    all_names = set(events_by_name.keys()) | set(current_states.keys())

    for name in sorted(all_names):
        evts = sorted(events_by_name.get(name, []), key=lambda e: e["ts"])
        segs = []

        # If we have events, build segments
        if evts:
            # Segment before first event
            first_ts = evts[0]["ts"]
            if first_ts > window_start:
                segs.append({"from": window_start.isoformat(), "to": first_ts.isoformat(), "status": "unknown"})

            for i, ev in enumerate(evts):
                seg_start = ev["ts"]
                seg_end   = evts[i + 1]["ts"] if i + 1 < len(evts) else now
                seg_status = "running" if ev["status"] == "running" else "stopped"
                segs.append({"from": seg_start.isoformat(), "to": seg_end.isoformat(), "status": seg_status})
        else:
            # No history — use current state for whole window
            cur = current_states.get(name, "unknown")
            seg_status = "running" if cur == "running" else "stopped" if cur in ("exited","created","dead","paused") else "unknown"
            segs.append({"from": window_start.isoformat(), "to": now.isoformat(), "status": seg_status})

        cur_status = current_states.get(name, "unknown")
        containers_out.append({
            "name":       name,
            "is_running": cur_status == "running",
            "segments":   segs,
        })

    return {
        "window_start": window_start.isoformat(),
        "window_end":   now.isoformat(),
        "containers":   containers_out,
    }
