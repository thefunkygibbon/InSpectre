import csv
import io
import json
import os
import re
import shutil
import subprocess
import asyncio
from typing import Optional, AsyncIterator, List

import httpx
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from models import Base, Device, FingerprintEntry, Setting

VERSION = "0.7.0"

DATABASE_URL  = os.environ.get("DATABASE_URL",  "postgresql://admin:password123@db:5432/inspectre")
PROBE_API_URL = os.environ.get("PROBE_API_URL", "http://host.docker.internal:8001")

engine       = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

app = FastAPI(title="InSpectre API", version=VERSION)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── default settings seed ─────────────────────────────────────────────────────

DEFAULT_SETTINGS = [
    {"key": "scan_interval",           "value": "60",   "description": "Seconds between ARP sweep cycles"},
    {"key": "offline_miss_threshold",  "value": "3",    "description": "Missed sweeps before a device is marked offline"},
    {"key": "os_confidence_threshold", "value": "75",   "description": "Minimum OS detection confidence % to display"},
    {"key": "sniffer_workers",         "value": "4",    "description": "Number of parallel deep-scan worker threads"},
    {"key": "ip_range",                "value": "",     "description": "CIDR range to scan, e.g. 192.168.1.0/24 (blank = auto-detect)"},
    {"key": "nmap_args",               "value": "-T4",  "description": "Extra arguments passed to nmap deep scans"},
    {"key": "notifications_enabled",   "value": "true", "description": "Show popup toasts when devices appear or go offline"},
]


def _seed_settings(db: Session):
    """Insert default settings rows if the table is empty."""
    if db.query(Setting).count() == 0:
        for s in DEFAULT_SETTINGS:
            db.add(Setting(key=s["key"], value=s["value"], description=s["description"]))
        db.commit()


# seed on startup
with SessionLocal() as _startup_db:
    _seed_settings(_startup_db)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Pydantic models ───────────────────────────────────────────────────────────

class DeviceUpdate(BaseModel):
    custom_name:          Optional[str] = None
    hostname:             Optional[str] = None
    vendor:               Optional[str] = None
    device_type_override: Optional[str] = None
    vendor_override:      Optional[str] = None


class IdentityUpdate(BaseModel):
    vendor_override:      Optional[str] = None
    device_type_override: Optional[str] = None


class SettingUpdate(BaseModel):
    value: str


class FingerprintImportRow(BaseModel):
    oui_prefix:       Optional[str]       = None
    hostname_pattern: Optional[str]       = None
    open_ports:       Optional[List[int]] = None
    device_type:      str
    vendor_name:      Optional[str]       = None
    confidence_score: float               = 1.0
    hit_count:        int                 = 1
    source:           str                 = "community"


# ── helpers ───────────────────────────────────────────────────────────────────

def _get_device_or_404(mac: str, db: Session) -> Device:
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    return d


def _normalise_mac(mac: str) -> str:
    return mac.lower().replace(':', '').replace('-', '').replace('.', '')


async def _stream_subprocess(cmd: list[str]) -> AsyncIterator[str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    assert proc.stdout is not None
    async for raw in proc.stdout:
        line = raw.decode(errors="replace").rstrip()
        if line:
            yield f"data: {line}\n\n"
    await proc.wait()
    yield "data: __done__\n\n"


def _upsert_fingerprint(
    db: Session,
    *,
    source_mac:       str,
    oui_prefix:       Optional[str],
    open_ports:       Optional[list],
    device_type:      str,
    vendor_name:      Optional[str],
    source:           str = "manual",
    confidence_score: float = 1.0,
    hit_count_add:    int = 1,
) -> FingerprintEntry:
    existing = None
    if oui_prefix:
        existing = (
            db.query(FingerprintEntry)
            .filter(
                FingerprintEntry.oui_prefix == oui_prefix,
                FingerprintEntry.device_type == device_type,
            )
            .first()
        )

    if existing:
        existing.hit_count        += hit_count_add
        existing.vendor_name       = vendor_name or existing.vendor_name
        existing.source_mac        = source_mac
        # bump confidence toward supplied value if higher
        if confidence_score > existing.confidence_score:
            existing.confidence_score = confidence_score
        if open_ports:
            merged = list(set((existing.open_ports or []) + open_ports))
            existing.open_ports = merged
        db.commit()
        db.refresh(existing)
        return existing
    else:
        entry = FingerprintEntry(
            oui_prefix       = oui_prefix,
            open_ports       = open_ports or [],
            device_type      = device_type,
            vendor_name      = vendor_name,
            confidence_score = confidence_score,
            hit_count        = hit_count_add,
            source           = source,
            source_mac       = source_mac,
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)
        return entry


# ── root ──────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"message": "InSpectre API is online", "version": VERSION}


# ── devices ───────────────────────────────────────────────────────────────────

@app.get("/devices")
def list_devices(online_only: bool = False, db: Session = Depends(get_db)):
    q = db.query(Device)
    if online_only:
        q = q.filter(Device.is_online == True)
    return [_to_dict(d) for d in q.order_by(Device.last_seen.desc()).all()]


@app.get("/devices/{mac}")
def get_device(mac: str, db: Session = Depends(get_db)):
    return _to_dict(_get_device_or_404(mac, db))


@app.patch("/devices/{mac}")
def update_device(mac: str, payload: DeviceUpdate, db: Session = Depends(get_db)):
    d = _get_device_or_404(mac, db)
    if payload.custom_name is not None:
        d.custom_name = payload.custom_name or None
    if payload.hostname is not None:
        d.hostname = payload.hostname or None
    if payload.vendor is not None:
        d.vendor = payload.vendor or None
    if payload.device_type_override is not None:
        d.device_type_override = payload.device_type_override or None
    if payload.vendor_override is not None:
        d.vendor_override = payload.vendor_override or None
    db.commit()
    db.refresh(d)
    return _to_dict(d)


@app.patch("/devices/{mac}/identity")
def update_identity(mac: str, payload: IdentityUpdate, db: Session = Depends(get_db)):
    d = _get_device_or_404(mac, db)
    if payload.vendor_override is not None:
        d.vendor_override = payload.vendor_override or None
    if payload.device_type_override is not None:
        d.device_type_override = payload.device_type_override or None
    db.commit()
    db.refresh(d)

    if payload.device_type_override:
        normalised = _normalise_mac(mac)
        oui        = normalised[:6] if len(normalised) >= 6 else None
        ports      = None
        if d.scan_results and isinstance(d.scan_results.get('open_ports'), list):
            ports = [p.get('port') for p in d.scan_results['open_ports'] if p.get('port')]

        _upsert_fingerprint(
            db,
            source_mac  = mac.lower(),
            oui_prefix  = oui,
            open_ports  = ports,
            device_type = payload.device_type_override,
            vendor_name = payload.vendor_override or d.vendor or None,
        )

    return _to_dict(d)


# ── settings ──────────────────────────────────────────────────────────────────

@app.get("/settings")
def get_settings(db: Session = Depends(get_db)):
    """Return all settings rows.  Seeded with defaults on first call."""
    _seed_settings(db)
    return [
        {"key": s.key, "value": s.value, "description": s.description}
        for s in db.query(Setting).order_by(Setting.key).all()
    ]


@app.put("/settings/{key}")
def update_setting(key: str, payload: SettingUpdate, db: Session = Depends(get_db)):
    s = db.get(Setting, key)
    if not s:
        raise HTTPException(404, f"Unknown setting key: {key}")
    s.value = payload.value
    db.commit()
    db.refresh(s)
    return {"key": s.key, "value": s.value}


@app.post("/settings/reset")
def reset_settings(db: Session = Depends(get_db)):
    """Restore every setting to its factory default."""
    for d in DEFAULT_SETTINGS:
        s = db.get(Setting, d["key"])
        if s:
            s.value = d["value"]
        else:
            db.add(Setting(key=d["key"], value=d["value"], description=d["description"]))
    db.commit()
    return {"ok": True}


# ── fingerprint DB ────────────────────────────────────────────────────────────

@app.get("/fingerprints")
def list_fingerprints(
    device_type: Optional[str] = None,
    source:      Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(FingerprintEntry)
    if device_type:
        q = q.filter(FingerprintEntry.device_type == device_type)
    if source:
        q = q.filter(FingerprintEntry.source == source)
    return [_fp_to_dict(e) for e in q.order_by(FingerprintEntry.hit_count.desc()).all()]


@app.get("/fingerprints/stats")
def fingerprint_stats(db: Session = Depends(get_db)):
    from sqlalchemy import func
    total  = db.query(func.count(FingerprintEntry.id)).scalar()
    manual = db.query(func.count(FingerprintEntry.id)).filter(FingerprintEntry.source == 'manual').scalar()
    auto   = db.query(func.count(FingerprintEntry.id)).filter(FingerprintEntry.source == 'auto').scalar()
    comm   = db.query(func.count(FingerprintEntry.id)).filter(FingerprintEntry.source == 'community').scalar()
    return {"total": total, "manual": manual, "auto": auto, "community": comm}


@app.delete("/fingerprints/{fp_id}")
def delete_fingerprint(fp_id: int, db: Session = Depends(get_db)):
    entry = db.get(FingerprintEntry, fp_id)
    if not entry:
        raise HTTPException(404, "Fingerprint entry not found")
    db.delete(entry)
    db.commit()
    return {"ok": True, "deleted_id": fp_id}


# ── export / import ───────────────────────────────────────────────────────────

@app.get("/export/devices")
def export_devices_csv(db: Session = Depends(get_db)):
    """
    Export every device as a CSV file download.
    Columns: mac_address, ip_address, hostname, vendor, vendor_override,
             device_type_override, custom_name, is_online, first_seen, last_seen
    """
    devices = db.query(Device).order_by(Device.last_seen.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "mac_address", "ip_address", "hostname", "vendor", "vendor_override",
        "device_type_override", "custom_name", "is_online", "first_seen", "last_seen",
    ])
    for d in devices:
        writer.writerow([
            d.mac_address,
            d.ip_address or "",
            d.hostname or "",
            d.vendor or "",
            getattr(d, "vendor_override", "") or "",
            getattr(d, "device_type_override", "") or "",
            d.custom_name or "",
            "yes" if d.is_online else "no",
            d.first_seen.isoformat() if d.first_seen else "",
            d.last_seen.isoformat()  if d.last_seen  else "",
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=inspectre-devices.csv"},
    )


@app.get("/export/fingerprints")
def export_fingerprints_json(db: Session = Depends(get_db)):
    """
    Export the trained fingerprint DB as a JSON file download.
    The source_mac field is intentionally omitted for privacy —
    this file is safe to share with other InSpectre users.
    """
    entries = db.query(FingerprintEntry).order_by(FingerprintEntry.hit_count.desc()).all()
    rows = []
    for e in entries:
        rows.append({
            "oui_prefix":       e.oui_prefix,
            "hostname_pattern": e.hostname_pattern,
            "open_ports":       e.open_ports,
            "device_type":      e.device_type,
            "vendor_name":      e.vendor_name,
            "confidence_score": e.confidence_score,
            "hit_count":        e.hit_count,
            "source":           e.source,
            # source_mac intentionally excluded
        })

    payload = json.dumps({"version": VERSION, "entries": rows}, indent=2)
    return StreamingResponse(
        iter([payload]),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=inspectre-fingerprints.json"},
    )


@app.post("/import/fingerprints")
async def import_fingerprints_json(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Import a fingerprint DB JSON file (as produced by /export/fingerprints).

    Merge strategy:
      - If an entry with the same (oui_prefix, device_type) already exists,
        increment hit_count by the imported value and update vendor_name if blank.
      - Otherwise insert a new row with source='community'.

    After import, any device whose current device_type_override is blank and
    whose OUI now has a high-confidence fingerprint entry will be automatically
    corrected (device_type_override set).
    """
    raw = await file.read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(400, f"Invalid JSON: {exc}")

    entries = data if isinstance(data, list) else data.get("entries", [])
    if not entries:
        raise HTTPException(400, "No fingerprint entries found in file")

    inserted  = 0
    merged    = 0
    corrected = 0

    for row in entries:
        try:
            validated = FingerprintImportRow(**row)
        except Exception:
            continue  # skip malformed rows

        result_before = db.query(FingerprintEntry).filter(
            FingerprintEntry.oui_prefix  == validated.oui_prefix,
            FingerprintEntry.device_type == validated.device_type,
        ).first()

        was_new = result_before is None

        _upsert_fingerprint(
            db,
            source_mac       = "import",
            oui_prefix       = validated.oui_prefix,
            open_ports       = validated.open_ports,
            device_type      = validated.device_type,
            vendor_name      = validated.vendor_name,
            source           = "community",
            confidence_score = validated.confidence_score,
            hit_count_add    = validated.hit_count,
        )

        if was_new:
            inserted += 1
        else:
            merged += 1

    # ── auto-correct unclassified devices whose OUI now matches a fingerprint ──
    all_fps = db.query(FingerprintEntry).filter(
        FingerprintEntry.oui_prefix != None,
        FingerprintEntry.confidence_score >= 0.8,
    ).order_by(FingerprintEntry.hit_count.desc()).all()

    # Build best-match map: oui_prefix -> FingerprintEntry with highest hit_count
    best: dict[str, FingerprintEntry] = {}
    for fp in all_fps:
        if fp.oui_prefix and fp.oui_prefix not in best:
            best[fp.oui_prefix] = fp

    unclassified = db.query(Device).filter(
        Device.device_type_override == None,
    ).all()

    for device in unclassified:
        oui = _normalise_mac(device.mac_address)[:6]
        if oui in best:
            fp = best[oui]
            device.device_type_override = fp.device_type
            if not getattr(device, "vendor_override", None) and fp.vendor_name:
                device.vendor_override = fp.vendor_name
            corrected += 1

    db.commit()

    return {
        "ok":        True,
        "inserted":  inserted,
        "merged":    merged,
        "corrected": corrected,
    }


# ── other device endpoints ────────────────────────────────────────────────────

@app.post("/devices/{mac}/resolve-name")
async def resolve_name(mac: str, db: Session = Depends(get_db)):
    d = _get_device_or_404(mac, db)
    if not d.ip_address:
        raise HTTPException(422, "Device has no IP address recorded")

    hostname = None
    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            resp = await client.get(f"{PROBE_API_URL}/resolve/{d.ip_address}")
            if resp.status_code == 200:
                data     = resp.json()
                hostname = data.get("hostname") or None
    except Exception as e:
        raise HTTPException(
            503,
            f"Could not reach probe API at {PROBE_API_URL}. Detail: {e}"
        )

    if hostname:
        d.hostname = hostname
        db.commit()
        db.refresh(d)

    return _to_dict(d)


@app.post("/devices/{mac}/rescan")
async def request_rescan(mac: str, db: Session = Depends(get_db)):
    d = _get_device_or_404(mac, db)
    if not d.ip_address:
        raise HTTPException(422, "Device has no IP address recorded")

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(f"{PROBE_API_URL}/rescan/{mac.lower()}")
            if resp.status_code not in (200, 404):
                raise HTTPException(resp.status_code, resp.text)
    except HTTPException:
        raise
    except Exception:
        pass

    d.deep_scanned = False
    db.commit()
    return {"queued": True, "mac": mac}


@app.get("/devices/{mac}/ip-history")
def get_ip_history(mac: str, db: Session = Depends(get_db)):
    d = _get_device_or_404(mac, db)
    if d.ip_address:
        return [{"ip": d.ip_address, "first_seen": d.first_seen, "last_seen": d.last_seen}]
    return []


@app.get("/devices/{mac}/scan")
def get_scan_results(mac: str, db: Session = Depends(get_db)):
    d = _get_device_or_404(mac, db)
    if not d.deep_scanned:
        return {"status": "pending", "message": "Deep scan not yet completed"}
    return {"status": "complete", "mac": mac, "data": d.scan_results}


@app.get("/stats")
def stats(db: Session = Depends(get_db)):
    total   = db.query(Device).count()
    online  = db.query(Device).filter(Device.is_online == True).count()
    offline = total - online
    scanned = db.query(Device).filter(Device.deep_scanned == True).count()
    return {"total_devices": total, "online": online, "offline": offline, "deep_scanned": scanned}


@app.get("/alerts")
def get_alerts(unseen_only: bool = False):
    return []


@app.get("/alerts/unseen-count")
def get_unseen_count():
    return {"count": 0}


@app.post("/alerts/mark-all-seen")
def mark_all_seen():
    return {"ok": True}


@app.delete("/alerts")
def clear_alerts():
    return {"ok": True}


# ── streaming endpoints ────────────────────────────────────────────────────────

@app.get("/devices/{mac}/ping")
async def stream_ping(mac: str, count: int = 4, db: Session = Depends(get_db)):
    d    = _get_device_or_404(mac, db)
    ip   = d.ip_address
    if not ip:
        raise HTTPException(422, "Device has no IP address recorded")
    count    = max(1, min(count, 20))
    ping_bin = shutil.which("ping")
    if not ping_bin:
        raise HTTPException(503, "ping binary not found in container")
    return StreamingResponse(
        _stream_subprocess([ping_bin, "-c", str(count), ip]),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/devices/{mac}/traceroute")
async def stream_traceroute(mac: str, db: Session = Depends(get_db)):
    d  = _get_device_or_404(mac, db)
    ip = d.ip_address
    if not ip:
        raise HTTPException(422, "Device has no IP address recorded")
    tr_bin = shutil.which("traceroute") or shutil.which("tracepath")
    if not tr_bin:
        raise HTTPException(503, "traceroute/tracepath not found in container")
    return StreamingResponse(
        _stream_subprocess([tr_bin, ip]),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/devices/{mac}/vuln-scan")
async def stream_vuln_scan(mac: str, db: Session = Depends(get_db)):
    d  = _get_device_or_404(mac, db)
    ip = d.ip_address
    if not ip:
        raise HTTPException(422, "Device has no IP address recorded")
    nmap_bin = shutil.which("nmap")
    if nmap_bin:
        cmd = [nmap_bin, "-sV", "--script=vuln", "-T4", "--open", ip]
    else:
        cmd = ["nmap", "-sV", "-T4", ip]
    return StreamingResponse(
        _stream_subprocess(cmd),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── serialisers ────────────────────────────────────────────────────────────────

def _to_dict(d: Device) -> dict:
    return {
        "mac_address":          d.mac_address,
        "ip_address":           d.ip_address,
        "hostname":             d.hostname,
        "vendor":               d.vendor,
        "custom_name":          d.custom_name,
        "is_online":            d.is_online,
        "deep_scanned":         d.deep_scanned,
        "first_seen":           d.first_seen.isoformat() if d.first_seen else None,
        "last_seen":            d.last_seen.isoformat()  if d.last_seen  else None,
        "scan_results":         d.scan_results,
        "device_type_override": getattr(d, 'device_type_override', None),
        "vendor_override":      getattr(d, 'vendor_override',      None),
    }


def _fp_to_dict(e: FingerprintEntry) -> dict:
    return {
        "id":               e.id,
        "oui_prefix":       e.oui_prefix,
        "hostname_pattern": e.hostname_pattern,
        "open_ports":       e.open_ports,
        "device_type":      e.device_type,
        "vendor_name":      e.vendor_name,
        "confidence_score": e.confidence_score,
        "hit_count":        e.hit_count,
        "source":           e.source,
        "created_at":       e.created_at.isoformat() if e.created_at else None,
        "updated_at":       e.updated_at.isoformat() if e.updated_at else None,
    }
