from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, Response
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
from datetime import datetime, timezone

import httpx

from models import Base, Device, DeviceEvent, FingerprintEntry, Setting, VulnReport

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://admin:password123@db:5432/inspectre")
# PROBE_API_URL is the name used in docker-compose; PROBE_URL is the legacy fallback.
PROBE_URL    = (
    os.environ.get("PROBE_API_URL")
    or os.environ.get("PROBE_URL")
    or "http://host.docker.internal:8666"
)

engine       = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

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
    "nmap_args":               ("-O --osscan-limit -sV --version-intensity 5 -T4 -p-", "Extra arguments passed to nmap."),
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
        q = db.query(Device).filter(Device.is_online == True, Device.ip_address != None)
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
                alert_new          = settings.get("alert_on_new_device",    "false") == "true"
                alert_offline      = settings.get("alert_on_offline",       "false") == "true"
                alert_vuln         = settings.get("alert_on_vuln",          "false") == "true"
                alert_port_change  = settings.get("alert_on_port_change",   "true")  == "true"
                vuln_on_new_device = settings.get("vuln_scan_on_new_device","false") == "true"

                if alert_new or alert_offline or alert_vuln or alert_port_change or vuln_on_new_device:
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
                        "types":   ["joined", "offline", "vuln_scan_complete", "port_change"],
                    }).fetchall()
                else:
                    rows = []

                pending_alerts = []
                vuln_scans_to_run = []
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
                        if vuln_on_new_device and ip:
                            scripts_s = db.get(Setting, "vuln_scan_templates")
                            scripts   = (scripts_s.value or "").strip() if scripts_s else ""
                            vuln_scans_to_run.append((mac, ip, scripts))
                    elif etype == "offline" and alert_offline and is_important:
                        pending_alerts.append((f"Watched device offline: {name} ({ip})", "device_offline"))
                    elif etype == "vuln_scan_complete" and alert_vuln:
                        severity = (detail or {}).get("severity", "unknown")
                        if severity not in ("clean", "info"):
                            count = (detail or {}).get("vuln_count", 0)
                            pending_alerts.append((
                                f"Vulnerabilities found on {name} ({ip}): {severity} severity, {count} finding(s)",
                                "vuln_found",
                            ))
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

            finally:
                db.close()

            for message, alert_type in pending_alerts:
                await _dispatch_alerts(settings, message, alert_type)
            for mac, ip, scripts in vuln_scans_to_run:
                print(f"[alerts] Auto vuln scan triggered for new device {ip} ({mac})", flush=True)
                asyncio.ensure_future(_run_single_vuln_scan(mac, ip, scripts))

        except Exception as exc:
            print(f"[alerts] Dispatch loop error: {exc}", flush=True)

        await asyncio.sleep(30)


app = FastAPI(title="InSpectre API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def on_startup():
    db = SessionLocal()
    try:
        _migrate(db)
        _seed_settings(db)
    finally:
        db.close()
    asyncio.ensure_future(_scheduled_vuln_scan_loop())
    asyncio.ensure_future(_alert_dispatch_loop())


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


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
    return _to_dict(d)


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
def rescan_device(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    d.deep_scanned = False
    db.commit()
    return {"mac": mac, "queued": True}


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
# SSE streaming (ping / traceroute) — proxied through probe
# ---------------------------------------------------------------------------
@app.get("/devices/{mac}/ping")
async def stream_ping(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")

    async def _gen():
        try:
            async with httpx.AsyncClient(timeout=None) as client:
                async with client.stream("GET", f"{PROBE_URL}/stream/ping/{d.ip_address}") as resp:
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

    async def _gen():
        try:
            async with httpx.AsyncClient(timeout=None) as client:
                async with client.stream("GET", f"{PROBE_URL}/stream/traceroute/{d.ip_address}") as resp:
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
    valid_types = {"A", "AAAA", "MX", "CNAME", "TXT", "NS", "SOA", "PTR"}
    qtype = type.upper()
    if qtype not in valid_types:
        raise HTTPException(400, f"Type must be one of: {', '.join(sorted(valid_types))}")
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
