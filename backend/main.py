from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Query, Security, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, Response, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from typing import Optional, List
import asyncio
import os
import json
import csv
import io
import socket
import subprocess
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
    "os_confidence_threshold": ("85",    "Minimum nmap OS-match confidence (%) to record."),
    "sniffer_workers":         ("4",     "Number of parallel scanner threads."),
    "ip_range":                ("192.168.0.0/24", "CIDR range to scan."),
    "nmap_args":               ("-sT -O --osscan-limit -T4", "nmap flags for port discovery. Service version detection (-sV) runs automatically on found ports as a separate pass."),
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
    # Network / probe identity
    "dns_server":                ("",      "LAN DNS server IP (auto-detected if blank). Set this to your router's IP for best hostname resolution."),
    "probe_interface":           ("",      "Network interface the probe uses for scanning (e.g. eth0, eno1). Requires probe restart to change."),
    # Setup wizard
    "setup_complete":            ("false", "Whether the initial setup wizard has been completed."),
}


def _seed_settings(db: Session):
    for key, (value, description) in DEFAULT_SETTINGS.items():
        if not db.get(Setting, key):
            db.add(Setting(key=key, value=value, description=description))
    db.commit()


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
                        "types":   ["joined", "offline", "vuln_scan_complete", "port_change", "port_opened", "port_closed"],
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
        if result:
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


@app.on_event("startup")
async def on_startup():
    db = SessionLocal()
    try:
        _migrate(db)
        _seed_settings(db)
        _seed_default_user(db)
    finally:
        db.close()
    asyncio.ensure_future(_scheduled_vuln_scan_loop())
    asyncio.ensure_future(_alert_dispatch_loop())
    asyncio.ensure_future(_block_schedule_loop())
    asyncio.ensure_future(_traffic_flush_loop())
    asyncio.ensure_future(_speedtest_schedule_loop())


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
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
    return {"score": min(score, 100), "reasons": reasons}


def _infer_device_type(d: Device) -> str | None:
    if getattr(d, 'device_type_override', None):
        return d.device_type_override
    hostname = (d.hostname or d.custom_name or "").lower()
    vendor   = (getattr(d, 'vendor_override', None) or d.vendor or "").lower()
    scan     = d.scan_results or {}
    ports    = {p.get("port") for p in (scan.get("open_ports") or []) if p.get("port")}
    os_guess = (scan.get("os_matches") or [{}])[0].get("name", "").lower() if scan.get("os_matches") else ""
    if any(k in hostname for k in ("cam", "camera", "nvr", "reolink", "dahua", "hikvision", "arlo", "ring", "nest")):
        return "camera"
    if any(k in vendor for k in ("reolink", "hikvision", "dahua", "axis", "hanwha")):
        return "camera"
    if any(k in hostname for k in ("iphone", "android", "phone", "pixel", "galaxy", "ipad", "tablet", "redmi", "oneplus")):
        return "phone"
    if "android" in os_guess or "ios" in os_guess:
        return "phone"
    if any(k in hostname for k in ("shelly", "plug", "switch", "tasmota", "sonoff", "gosund", "kasa", "tapo")):
        return "smart_plug"
    if any(k in vendor for k in ("espressif", "tuya", "tapo", "shelly", "meross", "gosund")):
        return "iot"
    if any(k in hostname for k in ("ap.", "access", "router", "gateway", "ubnt", "unifi", "openwrt", "airos")):
        return "access_point"
    if any(k in vendor for k in ("ubiquiti", "tp-link", "netgear", "asus", "linksys", "openwrt")):
        if {80, 443, 22} & ports:
            return "router"
    if any(k in hostname for k in ("nas", "synology", "qnap", "server", "truenas", "plex", "jellyfin")):
        return "nas"
    if {445, 139, 2049} & ports:
        return "nas"
    if any(k in hostname for k in ("printer", "print", "hp", "epson", "canon", "brother")):
        return "printer"
    if {9100, 515, 631} & ports:
        return "printer"
    if any(k in hostname for k in ("tv", "roku", "firetv", "appletv", "chromecast", "shield", "androidtv")):
        return "tv"
    if any(k in vendor for k in ("sony interactive", "microsoft xbox", "nintendo")):
        return "console"
    if any(k in vendor for k in ("tado", "philips", "ikea", "meross", "bouffalo")):
        return "smart_home"
    if "windows" in os_guess or {3389, 445} & ports:
        return "computer"
    if "linux" in os_guess and {22} & ports and len(ports) > 3:
        return "server"
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
        # Populated by list_devices; single-device endpoints return defaults
        "is_virtual_interface":  False,
        "virtual_of":            None,
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
    }
    if payload.ntfy_topic:
        to_save["ntfy_topic"] = payload.ntfy_topic
    if payload.ntfy_url:
        to_save["ntfy_url"] = payload.ntfy_url
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

    result = []
    for d in devices:
        dct = _to_dict(d)
        dct['is_virtual_interface'] = d.mac_address in virtual_of
        dct['virtual_of']           = virtual_of.get(d.mac_address)
        result.append(dct)
    return result


@app.get("/devices/{mac}")
def get_device(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    result = _to_dict(d)
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
    try:
        rows = db.execute(
            text("""
                SELECT id, type, detail, created_at
                FROM device_events
                WHERE mac_address = :mac
                  AND (:type IS NULL OR type = :type)
                ORDER BY created_at DESC
                LIMIT :limit OFFSET :offset
            """),
            {"mac": mac.lower(), "type": type, "limit": limit, "offset": offset}
        ).fetchall()
        return [{"id": r[0], "type": r[1], "detail": r[2], "created_at": r[3].isoformat() if r[3] else None} for r in rows]
    except Exception:
        return []


@app.get("/devices/{mac}/identity-score")
def get_identity_score(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    return {"mac": mac, "score": _identity_score(d), "device_type": _infer_device_type(d)}


# ---------------------------------------------------------------------------
# Phase 3 — Vulnerability scanning (proxied through the probe container)
# ---------------------------------------------------------------------------
@app.get("/devices/{mac}/vuln-scan")
async def stream_vuln_scan(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    if not d.ip_address:
        raise HTTPException(400, "Device has no IP address")

    templates_setting = db.get(Setting, "vuln_scan_templates")
    templates = (templates_setting.value or "").strip() if templates_setting else ""

    # Use primary_ip — it's the stable address. ip_address can be temporarily
    # updated to a secondary IP by the sniffer, which would break the probe lookup.
    ip        = getattr(d, "primary_ip", None) or d.ip_address
    mac_lower = mac.lower()
    probe_url = f"{PROBE_URL}/stream/vuln-scan/{ip}"
    params    = {"templates": templates, "mac": mac_lower}

    # Queue bridges the probe reader (background task) and the browser stream.
    # The reader runs as an independent asyncio task so the result is always
    # saved even if the browser navigates away before the scan finishes.
    line_queue: asyncio.Queue[str | None] = asyncio.Queue()

    async def _probe_reader() -> None:
        try:
            async with httpx.AsyncClient(timeout=None) as client:
                async with client.stream("GET", probe_url, params=params) as resp:
                    if resp.status_code != 200:
                        body = await resp.aread()
                        await line_queue.put(f"data: [ERROR] Probe returned HTTP {resp.status_code}: {body.decode()[:200]}\n\n")
                        return
                    async for raw_line in resp.aiter_lines():
                        await line_queue.put(f"{raw_line}\n")
                        if raw_line.startswith("data: RESULT:"):
                            payload_str = raw_line[len("data: RESULT:"):]
                            try:
                                data = json.loads(payload_str)
                                _save_vuln_result(mac_lower, ip, data, templates)
                            except Exception as exc:
                                await line_queue.put(f"data: [WARN] Could not save report: {exc}\n\n")
        except httpx.ConnectError:
            await line_queue.put(f"data: [ERROR] Cannot reach probe at {PROBE_URL} — is it running?\n\n")
        except Exception as exc:
            await line_queue.put(f"data: [ERROR] Proxy error: {exc}\n\n")
        finally:
            await line_queue.put(None)  # sentinel: stream finished

    asyncio.create_task(_probe_reader())

    async def _event_stream():
        while True:
            try:
                line = await asyncio.wait_for(line_queue.get(), timeout=30)
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
    asyncio.ensure_future(_run_scheduled_vuln_scans())
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
        from collections import defaultdict
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
    if "os_confidence_threshold" in settings:
        payload["os_confidence_threshold"] = int(settings["os_confidence_threshold"])
    if "sniffer_workers" in settings:
        payload["sniffer_workers"] = int(settings["sniffer_workers"])
    if "ip_range" in settings:
        payload["ip_range"] = settings["ip_range"]
    if "nmap_args" in settings:
        payload["nmap_args"] = settings["nmap_args"]
    if "nuclei_template_update_interval" in settings:
        payload["nuclei_template_update_interval"] = settings["nuclei_template_update_interval"]

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(f"{PROBE_URL}/config/reload", json=payload)
            body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"raw": resp.text}
            if resp.status_code >= 400:
                raise HTTPException(resp.status_code, f"Probe rejected settings apply: {body}")
            return {"applied": True, "probe_response": body}
    except httpx.ConnectError:
        raise HTTPException(502, f"Cannot reach probe at {PROBE_URL}")


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
@app.get("/export/backup")
def export_backup(db: Session = Depends(get_db)):
    """Export all user data as a portable JSON backup."""
    devices = [_to_dict(d) for d in db.query(Device).all()]
    settings = [{"key": s.key, "value": s.value} for s in db.query(Setting).all()]
    fps = [{"oui_prefix": f.oui_prefix, "device_type": f.device_type, "vendor_name": f.vendor_name,
            "open_ports": f.open_ports, "hostname_pattern": f.hostname_pattern,
            "confidence_score": f.confidence_score, "source": f.source}
           for f in db.query(FingerprintEntry).all()]
    payload = {
        "version": 1,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "devices": devices,
        "settings": settings,
        "fingerprints": fps,
    }
    content = json.dumps(payload, indent=2, default=str)
    return Response(
        content=content.encode(),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=inspectre_backup.json"},
    )


@app.post("/import/restore")
async def import_restore(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Restore settings and fingerprints from a backup JSON (devices are merged, not overwritten)."""
    content = await file.read()
    try:
        payload = json.loads(content)
    except Exception as exc:
        raise HTTPException(400, f"Invalid JSON: {exc}")
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise HTTPException(400, "Unrecognised backup format")

    stats = {"settings": 0, "fingerprints_merged": 0, "devices_skipped": 0}

    # Restore settings (skip sensitive delivery keys)
    SKIP_KEYS = {"pushbullet_api_key", "gotify_token", "alert_webhook_url", "ntfy_topic"}
    for s in payload.get("settings", []):
        key, value = s.get("key"), s.get("value")
        if not key or key in SKIP_KEYS:
            continue
        existing = db.get(Setting, key)
        if existing:
            existing.value = value
        else:
            db.add(Setting(key=key, value=value, description="Restored from backup"))
        stats["settings"] += 1

    # Restore fingerprints (merge)
    for fp in payload.get("fingerprints", []):
        device_type = fp.get("device_type", "").strip()
        if not device_type:
            continue
        oui = (fp.get("oui_prefix") or "").strip().lower() or None
        existing = None
        if oui:
            existing = db.query(FingerprintEntry).filter(
                FingerprintEntry.oui_prefix == oui,
                FingerprintEntry.device_type == device_type
            ).first()
        if not existing:
            db.add(FingerprintEntry(
                oui_prefix=oui,
                device_type=device_type,
                vendor_name=fp.get("vendor_name"),
                open_ports=fp.get("open_ports"),
                hostname_pattern=fp.get("hostname_pattern"),
                confidence_score=float(fp.get("confidence_score", 1.0)),
                source=fp.get("source", "backup"),
                hit_count=1,
            ))
            stats["fingerprints_merged"] += 1

    db.commit()
    stats["devices_skipped"] = len(payload.get("devices", []))
    return stats


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
    params    = {}
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
        async with httpx.AsyncClient(timeout=30) as client:
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
    device = db.get(Device, mac)
    if not device:
        raise HTTPException(404, "Device not found")
    ip = device.ip_address
    if not ip:
        raise HTTPException(422, "Device has no IP address")
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
