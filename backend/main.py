from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Query, Security, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, Response, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import create_engine, text
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
import shutil
import socket
import subprocess
import threading
from datetime import datetime, timezone, timedelta

import httpx
import bcrypt as _bcrypt
from jose import JWTError, jwt

from models import Base, Device, DeviceEvent, FingerprintEntry, Setting, TrafficStat, VulnReport

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://admin:password123@db:5432/inspectre")
# PROBE_API_URL is the name used in docker-compose; PROBE_URL is the legacy fallback.
PROBE_URL    = (
    os.environ.get("PROBE_API_URL")
    or os.environ.get("PROBE_URL")
    or "http://host.docker.internal:8666"
)

# ---------------------------------------------------------------------------
# Auth configuration
# ---------------------------------------------------------------------------
SECRET_KEY   = os.environ.get("SECRET_KEY", "CHANGE_ME_IN_PRODUCTION_use_a_long_random_string")
ALGORITHM    = "HS256"
TOKEN_EXPIRE = 60 * 24  # minutes — 24 hours
bearer_scheme = HTTPBearer(auto_error=False)

engine       = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

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
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        # Persistent Trivy scan results (survives backend restarts)
        """CREATE TABLE IF NOT EXISTS container_vuln_results (
            name       TEXT NOT NULL PRIMARY KEY,
            image      TEXT NOT NULL,
            vulns      JSONB NOT NULL DEFAULT '[]',
            scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        # IP history: differentiate DHCP rotation from multi-homed
        "ALTER TABLE ip_history ADD COLUMN IF NOT EXISTS seen_while_online BOOLEAN",
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
        "CREATE INDEX IF NOT EXISTS ix_devices_group_id ON devices(group_id)",
    ]
    for sql in migrations:
        try:
            db.execute(text(sql))
        except Exception:
            db.rollback()
    db.commit()


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
    "offline_rescan_hours":          ("4",     "Hours a device must be offline before triggering a rescan on return."),
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
    "auto_block_new_devices":    ("false", "Automatically ARP-block newly discovered devices until manually approved."),
    "auto_block_vuln_severity":  ("none",  "Minimum vuln severity to trigger auto-block. Options: none, medium, high, critical."),
    # Phase 9 — device grouping
    "auto_group_by_hostname":    ("true",  "Automatically group devices with the same hostname as the same physical device on a different interface (e.g. laptop switching between WiFi and Ethernet). When disabled, a suggestion event is written instead."),
    # Network / probe identity
    "dns_server":                ("",      "LAN DNS server IP (auto-detected if blank). Set this to your router's IP for best hostname resolution."),
    "probe_interface":           ("",      "Network interface the probe uses for scanning (e.g. eth0, eno1). Auto-detected on startup if blank; changes apply immediately via Settings → Apply."),
    # Fingerbank device identification
    "fingerbank_api_key":        ("",      "Fingerbank API key for cloud-based DHCP device identification. Get a free key at fingerbank.org. Leave blank to disable."),
    # Setup wizard
    "setup_complete":            ("false", "Whether the initial setup wizard has been completed."),
    # Docker monitoring
    "docker_enabled":            ("false", "Enable Docker container monitoring."),
    "docker_host":               ("unix:///var/run/docker.sock", "Docker host — socket path (unix:///var/run/docker.sock) or TCP URL (tcp://host:2375)."),
    "docker_tls_verify":         ("false", "Enable TLS verification for Docker TCP connections."),
    "trivy_db_update_hours":     ("24",   "How often (hours) to refresh the Trivy vulnerability database. Set to 0 to disable automatic updates."),
    "docker_scan_on_new":        ("false", "Automatically run a Trivy vuln scan when a new container is created."),
    "docker_scan_on_update":     ("false", "Automatically run a Trivy vuln scan when a container is recreated with an updated image."),
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
_last_scheduled_vuln_scan: datetime | None = None


async def _run_single_vuln_scan(mac: str, ip: str, scripts: str):
    probe_url = f"{PROBE_URL}/stream/vuln-scan/{ip}"
    params    = {"templates": scripts} if scripts else {}
    try:
        async with httpx.AsyncClient(timeout=None) as client:
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
        devices = [(d.mac_address, d.ip_address) for d in q.all()]
    finally:
        db.close()

    print(f"[scheduler] Starting scheduled vuln scan: {len(devices)} device(s)", flush=True)
    for mac, ip in devices:
        await _run_single_vuln_scan(mac, ip, scripts)
        await asyncio.sleep(10)


async def _run_all_vuln_scans():
    """Manual 'scan all' — ignores the vuln_scan_targets setting and scans every eligible device."""
    db = SessionLocal()
    try:
        settings_s = db.get(Setting, "vuln_scan_templates")
        scripts    = (settings_s.value or "").strip() if settings_s else ""
        devices    = [(d.mac_address, d.ip_address)
                      for d in db.query(Device)
                                 .filter(Device.is_online == True,
                                         Device.ip_address != None,
                                         Device.is_ignored == False)
                                 .all()]
    finally:
        db.close()

    print(f"[scan-all] Starting manual vuln scan: {len(devices)} device(s)", flush=True)
    for mac, ip in devices:
        await _run_single_vuln_scan(mac, ip, scripts)
        await asyncio.sleep(10)


async def _scheduled_vuln_scan_loop():
    global _last_scheduled_vuln_scan
    await asyncio.sleep(30)  # startup grace period
    while True:
        try:
            db = SessionLocal()
            try:
                sched_s   = db.get(Setting, "vuln_scan_schedule")
                schedule  = sched_s.value if sched_s else "disabled"
            finally:
                db.close()

            if schedule != "disabled":
                intervals = {"6h": 21600, "12h": 43200, "24h": 86400, "weekly": 604800}
                interval  = intervals.get(schedule, 86400)
                now       = datetime.now(timezone.utc)
                if _last_scheduled_vuln_scan is None or (now - _last_scheduled_vuln_scan).total_seconds() >= interval:
                    await _run_scheduled_vuln_scans()
                    _last_scheduled_vuln_scan = now
        except Exception as exc:
            print(f"[scheduler] Loop error: {exc}", flush=True)
        await asyncio.sleep(900)  # check every 15 minutes


# ---------------------------------------------------------------------------
# Alert dispatch
# ---------------------------------------------------------------------------
_last_alert_event_id: int = 0


async def _send_webhook(url: str, message: str, alert_type: str):
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(url, json={"message": message, "type": alert_type, "source": "InSpectre"})
    except Exception as exc:
        print(f"[alerts] Webhook error: {exc}", flush=True)


async def _send_ntfy(url: str, message: str):
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(url, content=message.encode(),
                              headers={"Title": "InSpectre Alert", "Priority": "default"})
    except Exception as exc:
        print(f"[alerts] ntfy error: {exc}", flush=True)


async def _send_gotify(base_url: str, token: str, message: str):
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(
                f"{base_url.rstrip('/')}/message",
                params={"token": token},
                json={"title": "InSpectre Alert", "message": message, "priority": 5},
            )
    except Exception as exc:
        print(f"[alerts] Gotify error: {exc}", flush=True)


async def _send_pushbullet(api_key: str, title: str, body: str):
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(
                "https://api.pushbullet.com/v2/pushes",
                json={"type": "note", "title": title, "body": body},
                headers={"Access-Token": api_key, "Content-Type": "application/json"},
            )
    except Exception as exc:
        print(f"[alerts] Pushbullet error: {exc}", flush=True)


async def _dispatch_alerts(settings: dict, message: str, alert_type: str):
    tasks = []
    if settings.get("alert_webhook_url", "").strip():
        tasks.append(_send_webhook(settings["alert_webhook_url"].strip(), message, alert_type))
    ntfy_topic = settings.get("ntfy_topic", "").strip()
    if ntfy_topic:
        ntfy_base = settings.get("ntfy_url", "https://ntfy.sh").rstrip("/")
        tasks.append(_send_ntfy(f"{ntfy_base}/{ntfy_topic}", message))
    gotify_url   = settings.get("gotify_url", "").strip()
    gotify_token = settings.get("gotify_token", "").strip()
    if gotify_url and gotify_token:
        tasks.append(_send_gotify(gotify_url, gotify_token, message))
    pb_key = settings.get("pushbullet_api_key", "").strip()
    if pb_key:
        title = {"new_device": "New device on network", "device_offline": "Device went offline",
                 "vuln_found": "Vulnerability found"}.get(alert_type, "InSpectre Alert")
        tasks.append(_send_pushbullet(pb_key, title, message))
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


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


async def _alert_dispatch_loop():
    global _last_alert_event_id
    await asyncio.sleep(20)  # startup grace

    # Initialise _last_alert_event_id to current max so we don't replay history
    db = SessionLocal()
    try:
        row = db.execute(text("SELECT COALESCE(MAX(id), 0) FROM device_events")).scalar()
        _last_alert_event_id = int(row or 0)
    except Exception:
        pass
    finally:
        db.close()

    while True:
        try:
            db = SessionLocal()
            try:
                settings = {s.key: s.value for s in db.query(Setting).all()}
                alert_new              = settings.get("alert_on_new_device",      "false") == "true"
                alert_offline          = settings.get("alert_on_offline",         "false") == "true"
                alert_vuln             = settings.get("alert_on_vuln",            "false") == "true"
                alert_port_change      = settings.get("alert_on_port_change",     "true")  == "true"
                vuln_on_new_device     = settings.get("vuln_scan_on_new_device",  "false") == "true"
                vuln_on_port_change    = settings.get("vuln_scan_on_port_change", "false") == "true"
                auto_block_new         = settings.get("auto_block_new_devices",   "false") == "true"
                auto_block_sev         = settings.get("auto_block_vuln_severity", "none")
                SEV_ORDER = ["none", "info", "clean", "low", "medium", "high", "critical"]

                if alert_new or alert_offline or alert_vuln or alert_port_change or vuln_on_new_device or vuln_on_port_change or auto_block_new or auto_block_sev != "none":
                    rows = db.execute(text("""
                        SELECT de.id, de.mac_address, de.type, de.detail, de.created_at,
                               COALESCE(d.custom_name, d.hostname, d.ip_address, de.mac_address) AS name,
                               d.ip_address, d.is_important,
                               COALESCE(d.is_ignored, false) AS is_ignored
                        FROM device_events de
                        JOIN devices d ON d.mac_address = de.mac_address
                        WHERE de.id > :last_id
                          AND de.type = ANY(:types)
                        ORDER BY de.id ASC
                        LIMIT 50
                    """), {
                        "last_id": _last_alert_event_id,
                        "types":   ["joined", "interface_joined", "offline", "vuln_scan_complete", "port_change", "port_opened", "port_closed"],
                    }).fetchall()
                else:
                    rows = []

                pending_alerts = []
                vuln_scans_to_run = []
                devices_to_block: list[str] = []
                suppression_cache: dict = {}
                for row in rows:
                    eid, mac, etype, detail, created_at, name, ip, is_important, is_ignored = row
                    if is_ignored:
                        _last_alert_event_id = max(_last_alert_event_id, eid)
                        continue
                    _last_alert_event_id = max(_last_alert_event_id, eid)
                    if _is_suppressed(mac, etype, suppression_cache):
                        continue
                    if etype == "joined":
                        if alert_new:
                            pending_alerts.append((f"New device detected: {name} ({ip})", "new_device"))
                        if auto_block_new:
                            devices_to_block.append(mac)
                        if vuln_on_new_device and ip:
                            scripts_s = db.get(Setting, "vuln_scan_templates")
                            scripts   = (scripts_s.value or "").strip() if scripts_s else ""
                            vuln_scans_to_run.append((mac, ip, scripts))
                    elif etype == "interface_joined":
                        if alert_new:
                            pending_alerts.append((f"Grouped device rejoined on new interface: {name} ({ip})", "new_device"))
                        if vuln_on_new_device and ip:
                            scripts_s = db.get(Setting, "vuln_scan_templates")
                            scripts   = (scripts_s.value or "").strip() if scripts_s else ""
                            vuln_scans_to_run.append((mac, ip, scripts))
                    elif etype == "offline" and alert_offline and is_important:
                        pending_alerts.append((f"Watched device offline: {name} ({ip})", "device_offline"))
                    elif etype == "vuln_scan_complete":
                        severity = (detail or {}).get("severity", "unknown")
                        if alert_vuln and severity not in ("clean", "info"):
                            count = (detail or {}).get("vuln_count", 0)
                            pending_alerts.append((
                                f"Vulnerabilities found on {name} ({ip}): {severity} severity, {count} finding(s)",
                                "vuln_found",
                            ))
                        if auto_block_sev != "none" and SEV_ORDER.index(severity) >= SEV_ORDER.index(auto_block_sev):
                            devices_to_block.append(mac)
                    elif etype == "port_change" and alert_port_change:
                        d = detail or {}
                        added   = d.get("added", [])
                        removed = d.get("removed", [])
                        parts = []
                        if added:
                            parts.append(f"Opened: {', '.join(str(p['port']) for p in added)}")
                        if removed:
                            parts.append(f"Closed: {', '.join(str(p['port']) for p in removed)}")
                        if parts:
                            pending_alerts.append((
                                f"Port change on {name} — " + "; ".join(parts),
                                "port_change",
                            ))
                    elif etype == "port_opened":
                        d = detail or {}
                        port     = d.get("port", "?")
                        severity = d.get("severity", "info")
                        if alert_port_change:
                            pending_alerts.append((
                                f"New port detected on {name} ({ip}) — port {port} [{severity}]",
                                "port_change",
                            ))
                        if vuln_on_port_change and ip:
                            scripts_s = db.get(Setting, "vuln_scan_templates")
                            scripts   = (scripts_s.value or "").strip() if scripts_s else ""
                            vuln_scans_to_run.append((mac, ip, scripts))
                    elif etype == "port_closed" and alert_port_change:
                        d    = detail or {}
                        port = d.get("port", "?")
                        pending_alerts.append((
                            f"Port closed on {name} ({ip}) — port {port} [baseline drift]",
                            "port_change",
                        ))

            finally:
                db.close()

            for message, alert_type in pending_alerts:
                await _dispatch_alerts(settings, message, alert_type)
            for mac, ip, scripts in vuln_scans_to_run:
                print(f"[alerts] Auto vuln scan triggered for new device {ip} ({mac})", flush=True)
                asyncio.ensure_future(_run_single_vuln_scan(mac, ip, scripts))
            for mac in devices_to_block:
                try:
                    async with httpx.AsyncClient(timeout=10) as c:
                        await c.post(f"{PROBE_URL}/block/{mac}")
                    db2 = SessionLocal()
                    try:
                        db2.execute(text("UPDATE devices SET is_blocked=true WHERE mac_address=:mac"), {"mac": mac})
                        db2.commit()
                    finally:
                        db2.close()
                    print(f"[alerts] Auto-blocked {mac}", flush=True)
                except Exception as exc:
                    print(f"[alerts] Auto-block failed for {mac}: {exc}", flush=True)

        except Exception as exc:
            print(f"[alerts] Dispatch loop error: {exc}", flush=True)

        await asyncio.sleep(30)


app = FastAPI(title="InSpectre API", version="1.0.0")

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
    if not auth_header.startswith("Bearer "):
        return JSONResponse({"detail": "Not authenticated"}, status_code=401)

    # _decode_token is defined later in this file — valid at call time
    username = _decode_token(auth_header[7:])
    if not username:
        return JSONResponse({"detail": "Invalid or expired token"}, status_code=401)

    return await call_next(request)


# ---------------------------------------------------------------------------
# Traffic stats flush loop — polls probe every 5 min and writes to DB
# ---------------------------------------------------------------------------
async def _traffic_flush_loop():
    await asyncio.sleep(60)  # startup grace
    while True:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
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


_last_speedtest_run: datetime | None = None

async def _speedtest_schedule_loop():
    global _last_speedtest_run
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
                now = datetime.now(timezone.utc)
                if _last_speedtest_run is None or (now - _last_speedtest_run).total_seconds() >= interval:
                    await _run_speedtest_and_save()
                    _last_speedtest_run = now
        except Exception as exc:
            print(f"[speedtest] schedule loop error: {exc}", flush=True)
        await asyncio.sleep(300)


async def _run_speedtest_and_save():
    try:
        result: dict = {}
        raw_lines: list[str] = []
        async with httpx.AsyncClient(timeout=180) as client:
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

def _create_token(username: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE)
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


@app.on_event("startup")
async def on_startup():
    db = SessionLocal()
    try:
        _migrate(db)
        _seed_settings(db)
        _seed_default_user(db)
        _migrate_legacy_docker_host(db)
    finally:
        db.close()
    asyncio.ensure_future(_scheduled_vuln_scan_loop())
    asyncio.ensure_future(_alert_dispatch_loop())
    asyncio.ensure_future(_block_schedule_loop())
    asyncio.ensure_future(_traffic_flush_loop())
    asyncio.ensure_future(_speedtest_schedule_loop())
    asyncio.ensure_future(_trivy_db_update_loop())
    asyncio.ensure_future(_docker_event_loop())
    asyncio.ensure_future(_fingerbank_loop())


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

class ContainerHostUpdate(BaseModel):
    name:       Optional[str]  = None
    type:       Optional[str]  = None
    url:        Optional[str]  = None
    auth_user:  Optional[str]  = None
    auth_token: Optional[str]  = None
    tls_verify: Optional[bool] = None
    enabled:    Optional[bool] = None
    node:       Optional[str]  = None

class DeviceUpdate(BaseModel):
    custom_name: Optional[str] = None
    hostname:    Optional[str] = None

class SettingUpdate(BaseModel):
    value: str
    
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


class PrimaryIPUpdate(BaseModel):
    ip_address: str

class NotifyPayload(BaseModel):
    title: str
    body: str

class TestNotifyPayload(BaseModel):
    api_key: Optional[str] = None

class BlockScheduleCreate(BaseModel):
    mac_address:   Optional[str]      = None
    mac_addresses: List[str]          = []
    tags:          str                = ""
    label:         Optional[str]      = None
    days_of_week:  str                = "mon,tue,wed,thu,fri,sat,sun"
    start_time:    str
    end_time:      str
    enabled:       bool               = True

class BlockScheduleUpdate(BaseModel):
    label:         Optional[str]       = None
    days_of_week:  Optional[str]       = None
    start_time:    Optional[str]       = None
    end_time:      Optional[str]       = None
    enabled:       Optional[bool]      = None
    mac_addresses: Optional[List[str]] = None
    tags:          Optional[str]       = None

class LoginRequest(BaseModel):
    username: str
    password: str

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
    docker_enabled:       bool   = False
    docker_host:          str    = "unix:///var/run/docker.sock"
    fingerbank_api_key:   str    = ""


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
    return {"message": "InSpectre API", "version": "1.0.0"}


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
    }

    # Check database
    try:
        row = db.execute(text("SELECT COUNT(*) FROM devices")).scalar()
        result["database"] = {"ok": True, "message": f"{row} devices in DB"}
    except Exception as e:
        result["database"] = {"ok": False, "message": str(e)[:120]}

    # Check probe
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{PROBE_URL}/health")
            if resp.status_code == 200:
                probe_data = resp.json()
                result["probe"] = {"ok": True, "message": probe_data.get("message", "Running")}
            else:
                result["probe"] = {"ok": False, "message": f"HTTP {resp.status_code}"}
    except httpx.ConnectError:
        result["probe"] = {"ok": False, "message": f"Cannot reach probe at {PROBE_URL}"}
    except Exception as e:
        result["probe"] = {"ok": False, "message": str(e)[:120]}

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
    token = _create_token(payload.username)
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
    return {"setup_complete": setup_done, "has_user": has_user}


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
        async with httpx.AsyncClient(timeout=5.0) as client:
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
    for key, value in to_save.items():
        s = db.get(Setting, key)
        if s:
            s.value = value
        else:
            db.add(Setting(key=key, value=value))
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
    virtual_of: dict[str, str] = {}
    for d in devices:
        if not _is_locally_admin_mac(d.mac_address):
            continue
        my_ips = {ip for ip, macs in ip_to_macs.items() if d.mac_address in macs}
        for ip in my_ips:
            for other_mac in ip_to_macs.get(ip, set()):
                if (other_mac != d.mac_address
                        and other_mac in mac_set
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
    for gid_str, members in group_map.items():
        online_members  = [m for m in members if m.is_online]
        primary_members = [m for m in members if getattr(m, "group_primary", False)]
        if len(online_members) == 1:
            rep = online_members[0].mac_address
        elif len(online_members) > 1:
            rep = primary_members[0].mac_address if primary_members else online_members[0].mac_address
        elif primary_members:
            rep = primary_members[0].mac_address
        else:
            rep = members[0].mac_address
        group_representative[gid_str] = rep

    hidden_macs: set = {
        m.mac_address
        for gid_str, members in group_map.items()
        for m in members
        if m.mac_address != group_representative.get(gid_str)
    }

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
    db.commit(); db.refresh(d)
    return _to_dict(d)


@app.post("/devices/{mac}/resolve-name")
def resolve_name(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    name = _resolve_hostname(d.ip_address)
    if name:
        d.hostname = name
        db.commit(); db.refresh(d)
    return {"mac": mac, "resolved": name, "device": _to_dict(d)}


@app.post("/devices/{mac}/rescan")
async def rescan_device(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    d.deep_scanned = False
    db.commit()
    # Ask the probe to start scanning immediately rather than waiting for the next sweep
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
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


@app.post("/devices/{mac}/set-primary-ip")
def set_primary_ip(mac: str, payload: PrimaryIPUpdate, db: Session = Depends(get_db)):
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

    old_primary = getattr(d, 'primary_ip', None) or d.ip_address
    d.primary_ip = target_ip
    d.primary_ip_locked = True
    d.ip_address = target_ip
    d.deep_scanned = False
    d.scan_results = None
    _add_event(db, mac.lower(), 'primary_ip_changed', {'old_primary_ip': old_primary, 'new_primary_ip': target_ip})
    db.commit()
    db.refresh(d)

    try:
        httpx.post(f"{PROBE_URL}/rescan/{mac.lower()}", timeout=10.0)
    except Exception:
        pass

    return {"ok": True, "device": _to_dict(d)}


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
        text("UPDATE devices SET group_id = NULL, group_primary = FALSE WHERE mac_address = :mac"),
        {"mac": mac_lower},
    )
    # If only one member remains, dissolve the group
    remaining = db.execute(
        text("SELECT COUNT(*) FROM devices WHERE group_id = :gid"),
        {"gid": group_id},
    ).scalar() or 0
    if remaining <= 1:
        db.execute(
            text("UPDATE devices SET group_id = NULL, group_primary = FALSE WHERE group_id = :gid"),
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
                async with httpx.AsyncClient(timeout=None) as client:
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
        async with httpx.AsyncClient(timeout=35.0) as client:
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
        async with httpx.AsyncClient(timeout=25.0) as client:
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
        async with httpx.AsyncClient(timeout=20.0) as client:
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
        "auto_group_by_hostname",
    ):
        if key in settings:
            payload[key] = settings[key]

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
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
        async with httpx.AsyncClient(timeout=5.0) as client:
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
# Notifications
# ---------------------------------------------------------------------------
@app.post("/notify/pushbullet")
async def send_pushbullet_notify(payload: NotifyPayload, db: Session = Depends(get_db)):
    s   = db.get(Setting, "pushbullet_api_key")
    key = (s.value or "").strip() if s else ""
    if not key:
        raise HTTPException(400, "Pushbullet API key not configured")
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                "https://api.pushbullet.com/v2/pushes",
                json={"type": "note", "title": payload.title, "body": payload.body},
                headers={"Access-Token": key, "Content-Type": "application/json"},
            )
    except httpx.ConnectError:
        raise HTTPException(502, "Cannot reach Pushbullet API")
    if resp.status_code == 401:
        raise HTTPException(401, "Invalid Pushbullet API key")
    if resp.status_code >= 400:
        raise HTTPException(502, f"Pushbullet error {resp.status_code}")
    return {"sent": True}


@app.post("/notify/test")
async def test_pushbullet_notify(payload: TestNotifyPayload, db: Session = Depends(get_db)):
    key = (payload.api_key or "").strip()
    if not key:
        s   = db.get(Setting, "pushbullet_api_key")
        key = (s.value or "").strip() if s else ""
    if not key:
        raise HTTPException(400, "No Pushbullet API key configured")
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                "https://api.pushbullet.com/v2/pushes",
                json={"type": "note", "title": "InSpectre Test", "body": "Push notifications are working!"},
                headers={"Access-Token": key, "Content-Type": "application/json"},
            )
    except httpx.ConnectError:
        raise HTTPException(502, "Cannot reach Pushbullet API")
    if resp.status_code == 401:
        raise HTTPException(401, "Invalid API key — check your Pushbullet access token")
    if resp.status_code >= 400:
        raise HTTPException(502, f"Pushbullet error {resp.status_code}: {resp.text[:200]}")
    return {"sent": True}


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
            async with httpx.AsyncClient(timeout=None) as client:
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
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(f"{PROBE_URL}/block/{mac.lower()}")
            if resp.status_code >= 400:
                body = resp.text
                raise HTTPException(502, f"Probe error: {body[:200]}")
    except httpx.ConnectError:
        raise HTTPException(502, f"Cannot reach probe at {PROBE_URL}")
    d.is_blocked = True
    _add_event(db, mac.lower(), "blocked", {"ip": d.ip_address})
    db.commit(); db.refresh(d)
    return _to_dict(d)


@app.post("/devices/{mac}/unblock")
async def unblock_device(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.delete(f"{PROBE_URL}/block/{mac.lower()}")
            if resp.status_code >= 400:
                body = resp.text
                raise HTTPException(502, f"Probe error: {body[:200]}")
    except httpx.ConnectError:
        raise HTTPException(502, f"Cannot reach probe at {PROBE_URL}")
    d.is_blocked = False
    _add_event(db, mac.lower(), "unblocked", {"ip": d.ip_address})
    db.commit(); db.refresh(d)
    return _to_dict(d)


@app.get("/devices/{mac}/traceroute")
async def stream_traceroute(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")

    trace_ip = getattr(d, 'primary_ip', None) or d.ip_address

    async def _gen():
        try:
            async with httpx.AsyncClient(timeout=None) as client:
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


def _validate_tool_url(url: str):
    if not url or not (url.startswith("http://") or url.startswith("https://")):
        raise HTTPException(400, "URL must start with http:// or https://")
    if len(url) > 2048:
        raise HTTPException(400, "URL too long")


@app.get("/tools/ping")
async def tools_ping(host: str = Query(...)):
    _validate_tool_host(host)

    async def _gen():
        try:
            async with httpx.AsyncClient(timeout=None) as client:
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
            async with httpx.AsyncClient(timeout=None) as client:
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
            async with httpx.AsyncClient(timeout=None) as client:
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
    import dns.resolver
    _validate_tool_host(domain)

    def _resolve(name: str, qtype: str) -> list[str]:
        try:
            return [str(r) for r in dns.resolver.resolve(name, qtype, lifetime=8)]
        except Exception:
            return []

    out: dict = {"domain": domain}
    out["mx"]          = sorted(_resolve(domain, "MX"))
    out["spf"]         = [r.strip('"') for r in _resolve(domain, "TXT") if "v=spf" in r.lower()]
    out["dmarc"]       = [r.strip('"') for r in _resolve(f"_dmarc.{domain}", "TXT")]
    out["nameservers"] = _resolve(domain, "NS")

    dkim: dict = {}
    for sel in ["default", "google", "mail", "k1", "selector1", "selector2", "dkim"]:
        recs = _resolve(f"{sel}._domainkey.{domain}", "TXT")
        if recs:
            dkim[sel] = [r.strip('"') for r in recs]
    out["dkim"] = dkim
    return out


# ---------------------------------------------------------------------------
# ARP lookup + Wake-on-LAN (proxied to probe)
# ---------------------------------------------------------------------------
@app.get("/tools/arp-lookup")
async def tools_arp_lookup(query: str = Query(...)):
    try:
        async with httpx.AsyncClient(timeout=10) as client:
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
        async with httpx.AsyncClient(timeout=10) as client:
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
            async with httpx.AsyncClient(timeout=None) as client:
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
        async with httpx.AsyncClient(timeout=60) as client:
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
    }


@app.get("/block-schedules")
def list_block_schedules(db: Session = Depends(get_db)):
    rows = db.execute(text(
        "SELECT id, mac_address, label, days_of_week, start_time, end_time, enabled, created_at, mac_addresses, tags "
        "FROM block_schedules ORDER BY created_at DESC"
    )).fetchall()
    return [_schedule_row_to_dict(r) for r in rows]


@app.post("/block-schedules", status_code=201)
def create_block_schedule(payload: BlockScheduleCreate, db: Session = Depends(get_db)):
    if not payload.start_time or not payload.end_time:
        raise HTTPException(400, "start_time and end_time are required")
    row = db.execute(text(
        "INSERT INTO block_schedules (mac_address, label, days_of_week, start_time, end_time, enabled, mac_addresses, tags) "
        "VALUES (:mac, :label, :days, :start, :end, :enabled, :mac_addresses, :tags) "
        "RETURNING id, mac_address, label, days_of_week, start_time, end_time, enabled, created_at, mac_addresses, tags"
    ), {
        "mac":          payload.mac_address,
        "label":        payload.label or "",
        "days":         payload.days_of_week,
        "start":        payload.start_time,
        "end":          payload.end_time,
        "enabled":      payload.enabled,
        "mac_addresses": payload.mac_addresses or [],
        "tags":         payload.tags or "",
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
    if payload.label        is not None: updates["label"]        = payload.label
    if payload.days_of_week is not None: updates["days_of_week"] = payload.days_of_week
    if payload.start_time   is not None: updates["start_time"]   = payload.start_time
    if payload.end_time     is not None: updates["end_time"]     = payload.end_time
    if payload.enabled      is not None: updates["enabled"]      = payload.enabled
    if payload.mac_addresses is not None: updates["mac_addresses"] = payload.mac_addresses
    if payload.tags          is not None: updates["tags"]          = payload.tags
    if updates:
        set_clause = ", ".join(f"{k} = :{k}" for k in updates)
        updates["id"] = schedule_id
        db.execute(text(f"UPDATE block_schedules SET {set_clause} WHERE id = :id"), updates)
        db.commit()
    row = db.execute(text(
        "SELECT id, mac_address, label, days_of_week, start_time, end_time, enabled, created_at, mac_addresses, tags "
        "FROM block_schedules WHERE id = :id"
    ), {"id": schedule_id}).fetchone()
    return _schedule_row_to_dict(row)


@app.delete("/block-schedules/{schedule_id}", status_code=204)
def delete_block_schedule(schedule_id: int, db: Session = Depends(get_db)):
    db.execute(text("DELETE FROM block_schedules WHERE id = :id"), {"id": schedule_id})
    db.commit()


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
            async with httpx.AsyncClient(timeout=10.0) as client:
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
            async with httpx.AsyncClient(timeout=10.0) as client:
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
                schedules = db.execute(text(
                    "SELECT id, mac_address, days_of_week, start_time, end_time, mac_addresses, tags "
                    "FROM block_schedules WHERE enabled = TRUE"
                )).fetchall()

                # Build set of (mac_or_None, should_be_blocked) from all schedules
                # mac_address=None means network-wide
                device_should_block: dict = {}  # mac -> bool (True = schedule says block)

                for sched in schedules:
                    _, mac, days, start, end, mac_addresses, sched_tags = sched
                    active = _schedule_active_now(days, start, end)

                    # Determine target MACs
                    target_macs = None  # None = network-wide
                    if mac_addresses:
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

                # Apply changes
                for mac, should_block in device_should_block.items():
                    dev = db.execute(text(
                        "SELECT is_blocked, is_schedule_blocked, ip_address FROM devices WHERE mac_address = :mac"
                    ), {"mac": mac}).fetchone()
                    if not dev:
                        continue
                    is_blocked, is_sched_blocked, ip = dev

                    if should_block and not is_sched_blocked:
                        # Need to block
                        try:
                            async with httpx.AsyncClient(timeout=8.0) as client:
                                await client.post(f"{PROBE_URL}/block/{mac.lower()}")
                        except Exception:
                            pass
                        db.execute(text(
                            "UPDATE devices SET is_blocked = TRUE, is_schedule_blocked = TRUE WHERE mac_address = :mac"
                        ), {"mac": mac})
                        _add_event(db, mac, "blocked", {"ip": ip, "reason": "schedule"})

                    elif not should_block and is_sched_blocked:
                        # Schedule says unblock (only if blocked by schedule, not manually)
                        try:
                            async with httpx.AsyncClient(timeout=8.0) as client:
                                await client.delete(f"{PROBE_URL}/block/{mac.lower()}")
                        except Exception:
                            pass
                        db.execute(text(
                            "UPDATE devices SET is_blocked = FALSE, is_schedule_blocked = FALSE WHERE mac_address = :mac"
                        ), {"mac": mac})
                        _add_event(db, mac, "unblocked", {"ip": ip, "reason": "schedule_end"})

                db.commit()
            finally:
                db.close()
        except Exception as exc:
            print(f"[block_schedule_loop] error: {exc}", flush=True)

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
        async with httpx.AsyncClient(timeout=5.0) as client:
            active_resp = await client.get(f"{PROBE_URL}/traffic/stats")
        if active_resp.status_code == 200:
            active_count = len(active_resp.json().get("sessions", []))
            if active_count >= max_sessions:
                raise HTTPException(429, f"Max concurrent traffic sessions ({max_sessions}) reached")
    except (httpx.ConnectError, httpx.TimeoutException):
        pass
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
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
        async with httpx.AsyncClient(timeout=10.0) as client:
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
        async with httpx.AsyncClient(timeout=8.0) as client:
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
        async with httpx.AsyncClient(timeout=8.0) as client:
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
        async with httpx.AsyncClient(timeout=5.0) as client:
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
            async with httpx.AsyncClient(timeout=None) as client:
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
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@app.get("/container-hosts")
async def list_container_hosts(db: Session = Depends(get_db)):
    rows = db.execute(text("SELECT * FROM container_hosts ORDER BY id")).fetchall()
    return [_row_to_host(r) for r in rows]


@app.post("/container-hosts", status_code=201)
async def create_container_host(body: ContainerHostCreate, db: Session = Depends(get_db)):
    row = db.execute(text("""
        INSERT INTO container_hosts (name, type, url, auth_user, auth_token, tls_verify, enabled, node)
        VALUES (:name, :type, :url, :au, :at, :tls, :enabled, :node)
        RETURNING *
    """), {
        "name": body.name, "type": body.type, "url": body.url or None,
        "au": body.auth_user or None, "at": body.auth_token or None,
        "tls": body.tls_verify, "enabled": body.enabled, "node": body.node or "pve",
    }).fetchone()
    db.commit()
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
    # Only update auth_token if explicitly supplied and not masked
    if body.auth_token is not None and body.auth_token != "***":
        fields["auth_token"] = body.auth_token or None
    if not fields:
        return _row_to_host(row)
    set_clause = ", ".join(f"{k} = :{k}" for k in fields)
    fields["id"] = host_id
    updated = db.execute(text(f"UPDATE container_hosts SET {set_clause} WHERE id = :id RETURNING *"), fields).fetchone()
    db.commit()
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
            "tls_verify": r.tls_verify, "node": r.node,
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
            d = _fmt_container(c)
            d["host_id"]   = host["id"]
            d["host_name"] = host["name"]
            d["host_type"] = htype
            d["host_url"]  = host_url
            result.append(d)
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
            d = _fmt_container(c)
            d["host_id"] = docker_hosts[0]["id"]; d["host_name"] = docker_hosts[0]["name"]
            return d
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
            return _fmt_container(c)
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
            return _fmt_container(c)
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
            return _fmt_container(c)
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
# Trivy DB update background loop
# ---------------------------------------------------------------------------
async def _trivy_db_update_loop():
    """Periodically refreshes the Trivy vulnerability database."""
    await asyncio.sleep(60)  # startup grace
    while True:
        db = SessionLocal()
        try:
            s = db.get(Setting, "trivy_db_update_hours")
            hours = int(s.value) if s and s.value else 24
        except Exception:
            hours = 24
        finally:
            db.close()

        if hours > 0 and shutil.which("trivy"):
            try:
                proc = await asyncio.create_subprocess_exec(
                    "trivy", "image", "--download-db-only", "--no-progress",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await proc.wait()
                print("[trivy_db] Vulnerability DB updated.", flush=True)
            except Exception as e:
                print(f"[trivy_db] Update failed: {e}", flush=True)

        await asyncio.sleep(max(hours, 1) * 3600 if hours > 0 else 86400)


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
