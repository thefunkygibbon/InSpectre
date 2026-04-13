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
    or "http://host-gateway:8001"
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


app = FastAPI(title="InSpectre API", version="0.7.1")
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


class IdentityUpdate(BaseModel):
    vendor_override:      Optional[str] = None
    device_type_override: Optional[str] = None


class MetadataUpdate(BaseModel):
    notes:        Optional[str]  = None
    tags:         Optional[str]  = None
    location:     Optional[str]  = None
    is_important: Optional[bool] = None


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
        # Phase 3
        "vuln_last_scanned":    getattr(d, 'vuln_last_scanned', None) and d.vuln_last_scanned.isoformat(),
        "vuln_severity":        getattr(d, 'vuln_severity', None),
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
    return {"message": "InSpectre API", "version": "0.7.1"}


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


# ---------------------------------------------------------------------------
# Phase 3 — Vulnerability scanning (proxied through the probe container)
#
# The probe runs on --network=host so nmap can actually reach LAN devices.
# The backend cannot (Docker bridge network), so we proxy the SSE stream
# from probe's  GET /stream/vuln-scan/{ip}  endpoint, intercept the final
# RESULT line to persist it in the DB, then forward every line on to the
# browser unchanged.
# ---------------------------------------------------------------------------
@app.get("/devices/{mac}/vuln-scan")
async def stream_vuln_scan(mac: str, db: Session = Depends(get_db)):
    """
    SSE — streams live nmap vuln-script output sourced from the probe.
    The final data line is  RESULT:{...json...}  which we persist before
    forwarding; the browser uses it to update the device's severity badge.
    """
    from datetime import datetime, timezone

    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    if not d.ip_address:
        raise HTTPException(400, "Device has no IP address")

    scripts_setting = db.get(Setting, "vuln_scan_scripts")
    scripts = (scripts_setting.value or "").strip() if scripts_setting else ""

    ip        = d.ip_address
    mac_lower = mac.lower()
    probe_url = f"{PROBE_URL}/stream/vuln-scan/{ip}"
    params    = {"scripts": scripts} if scripts else {}

    async def _event_stream():
        result_saved = False
        try:
            async with httpx.AsyncClient(timeout=None) as client:
                async with client.stream("GET", probe_url, params=params) as resp:
                    if resp.status_code != 200:
                        body = await resp.aread()
                        yield f"data: [ERROR] Probe returned HTTP {resp.status_code}: {body.decode()[:200]}\n\n"
                        return

                    async for raw_line in resp.aiter_lines():
                        # raw_line is the full SSE line including the "data: " prefix
                        yield f"{raw_line}\n"

                        # Intercept RESULT line to persist to DB
                        if raw_line.startswith("data: RESULT:"):
                            payload_str = raw_line[len("data: RESULT:"):]
                            try:
                                data = json.loads(payload_str)
                                db2  = SessionLocal()
                                try:
                                    dev = db2.get(Device, mac_lower)
                                    if dev:
                                        report = VulnReport(
                                            mac_address = mac_lower,
                                            ip_address  = ip,
                                            duration_s  = data.get("duration_s"),
                                            severity    = data.get("severity", "clean"),
                                            vuln_count  = data.get("vuln_count", 0),
                                            findings    = data.get("findings"),
                                            raw_output  = data.get("raw_output"),
                                            nmap_args   = scripts or None,
                                        )
                                        db2.add(report)
                                        dev.vuln_last_scanned = datetime.now(timezone.utc)
                                        dev.vuln_severity     = data.get("severity", "clean")
                                        db2.commit()
                                        _add_event(db2, mac_lower, "vuln_scan_complete", {
                                            "severity":   data.get("severity"),
                                            "vuln_count": data.get("vuln_count", 0),
                                        })
                                        db2.commit()
                                        result_saved = True
                                finally:
                                    db2.close()
                            except Exception as exc:
                                yield f"data: [WARN] Could not save report: {exc}\n\n"

        except httpx.ConnectError:
            yield f"data: [ERROR] Cannot reach probe at {PROBE_URL} — is it running?\n\n"
        except Exception as exc:
            yield f"data: [ERROR] Proxy error: {exc}\n\n"

        if not result_saved:
            yield "data: [WARN] No RESULT line received from probe\n\n"

    return StreamingResponse(
        _event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/devices/{mac}/vuln-reports")
def get_vuln_reports(mac: str, limit: int = Query(10, ge=1, le=100), db: Session = Depends(get_db)):
    """Return the N most recent vuln scan reports for a device."""
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
            "nmap_args":  r.nmap_args,
        }
        for r in reports
    ]


@app.get("/devices/{mac}/vuln-reports/{report_id}")
def get_vuln_report_detail(mac: str, report_id: int, db: Session = Depends(get_db)):
    """Return a single vuln report including raw_output."""
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
        "nmap_args":    r.nmap_args,
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
    """Global vuln report list, optionally filtered by severity."""
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
                    "vuln_scan_complete"]
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
def update_setting(key: str, payload: dict, db: Session = Depends(get_db)):
    s = db.get(Setting, key)
    if not s:
        raise HTTPException(404, "Setting not found")
    s.value = str(payload.get("value", s.value))
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
