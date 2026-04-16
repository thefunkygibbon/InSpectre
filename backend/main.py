from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, Response
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from typing import Optional, List
import os
import json
import csv
import io
import socket
import subprocess

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
    "nmap_args":               ("-O --osscan-limit -sV --version-intensity 5 -T4", "Extra arguments passed to nmap."),
    "notifications_enabled":   ("true",  "Show popup toasts when new devices appear or go offline."),
    "vuln_scan_scripts":       (
        "vulners,http-vuln-cve2017-5638,http-shellshock,smb-vuln-ms17-010,"
        "smb-vuln-cve-2020-0796,ssl-heartbleed,ssl-poodle,ftp-vsftpd-backdoor,ftp-anon",
        "Comma-separated Nmap NSE scripts used for vulnerability scanning."
    ),
}


def _seed_settings(db: Session):
    for key, (value, description) in DEFAULT_SETTINGS.items():
        if not db.get(Setting, key):
            db.add(Setting(key=key, value=value, description=description))
    db.commit()


app = FastAPI(title="InSpectre API", version="0.7.2")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    db = SessionLocal()
    try:
        _migrate(db)
        _seed_settings(db)
    finally:
        db.close()


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


class PrimaryIPUpdate(BaseModel):
    ip_address: str


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
        "display_name":         d.custom_name or d.hostname or d.ip_address,
        "identity_score":       id_score["score"],
        "identity_reasons":     id_score["reasons"],
        "device_type":          getattr(d, 'device_type_override', None) or inferred,
        "device_type_inferred": inferred,
        "vuln_last_scanned": d.vuln_last_scanned.isoformat() if d.vuln_last_scanned else None,
        "vuln_severity":     d.vuln_severity,
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
    return {"message": "InSpectre API", "version": "0.7.2"}


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------
@app.get("/devices")
def list_devices(online_only: bool = False, db: Session = Depends(get_db)):
    q = db.query(Device)
    if online_only:
        q = q.filter(Device.is_online == True)
    return [_to_dict(d) for d in q.order_by(Device.last_seen.desc(), Device.mac_address.asc()).all()]


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
    if payload.is_important is not None:
        old_imp = bool(getattr(d, 'is_important', False))
        d.is_important = payload.is_important
        if payload.is_important != old_imp:
            _add_event(db, mac.lower(), 'marked_important', {'important': payload.is_important})
    if payload.tags is not None:
        _add_event(db, mac.lower(), 'tagged', {'tags': payload.tags})
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
def get_device_events(mac: str, limit: int = Query(50, ge=1, le=500), db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    try:
        rows = db.execute(
            text("SELECT id, type, detail, created_at FROM device_events WHERE mac_address = :mac ORDER BY created_at DESC LIMIT :limit"),
            {"mac": mac.lower(), "limit": limit}
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

# ... keep the rest of your existing backend file unchanged until the Settings section ...

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

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(f"{PROBE_URL}/config/reload", json=payload)
            body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"raw": resp.text}
            if resp.status_code >= 400:
                raise HTTPException(resp.status_code, f"Probe rejected settings apply: {body}")
            return {"applied": True, "probe_response": body}
    except httpx.ConnectError:
        raise HTTPException(502, f"Cannot reach probe at {PROBE_URL}")
