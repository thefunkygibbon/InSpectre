from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from typing import Optional, List
import os
import socket
import subprocess

from models import Base, Device

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://admin:password123@db:5432/inspectre")
engine       = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

app = FastAPI(title="InSpectre API", version="0.4.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class DeviceUpdate(BaseModel):
    custom_name: Optional[str] = None
    hostname:    Optional[str] = None

class IdentityUpdate(BaseModel):
    vendor_override:      Optional[str] = None
    device_type_override: Optional[str] = None

# ---------------------------------------------------------------------------
# Hostname resolution helpers
# ---------------------------------------------------------------------------
def _strip_fqdn(name: str) -> str:
    return name.rstrip('.') if name else ''

def _resolve_hostname(ip: str) -> str | None:
    """Multi-strategy hostname resolution — reverse DNS, mDNS, NetBIOS."""
    try:
        result = socket.gethostbyaddr(ip)
        candidate = _strip_fqdn(result[0])
        if candidate and candidate != ip:
            return candidate
    except Exception:
        pass

    try:
        out = subprocess.run(
            ["avahi-resolve", "-a", ip],
            capture_output=True, text=True, timeout=3
        )
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                candidate = _strip_fqdn(parts[1])
                if candidate and candidate != ip:
                    return candidate
    except Exception:
        pass

    try:
        out = subprocess.run(
            ["nmblookup", "-A", ip],
            capture_output=True, text=True, timeout=4
        )
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
# Routes
# ---------------------------------------------------------------------------
@app.get("/")
def root():
    return {"message": "InSpectre API", "version": "0.4.0"}

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
    if payload.custom_name is not None:
        d.custom_name = payload.custom_name
    if payload.hostname is not None:
        d.hostname = payload.hostname
    db.commit()
    db.refresh(d)
    return _to_dict(d)

@app.patch("/devices/{mac}/identity")
def update_identity(mac: str, payload: IdentityUpdate, db: Session = Depends(get_db)):
    """Set vendor_override and/or device_type_override on a device."""
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    if payload.vendor_override is not None:
        d.vendor_override = payload.vendor_override or None
    if payload.device_type_override is not None:
        d.device_type_override = payload.device_type_override or None
    db.commit()
    db.refresh(d)
    return _to_dict(d)

@app.post("/devices/{mac}/resolve-name")
def resolve_name(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    name = _resolve_hostname(d.ip_address)
    if name:
        d.hostname = name
        db.commit()
        db.refresh(d)
    return {"mac": mac, "resolved": name, "device": _to_dict(d)}

@app.post("/devices/{mac}/rescan")
def rescan_device(mac: str, db: Session = Depends(get_db)):
    """Reset deep_scanned so the probe queues a fresh nmap on the next sweep."""
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
    """Return IP address history for a device (stub if table not yet created)."""
    from sqlalchemy import text
    try:
        rows = db.execute(
            text("SELECT ip_address, first_seen, last_seen FROM ip_history WHERE mac_address = :mac ORDER BY last_seen DESC"),
            {"mac": mac.lower()}
        ).fetchall()
        return [{"ip": r[0], "first_seen": r[1].isoformat() if r[1] else None, "last_seen": r[2].isoformat() if r[2] else None} for r in rows]
    except Exception:
        return []

@app.get("/vendors", response_model=List[str])
def list_vendors(db: Session = Depends(get_db)):
    """
    Return a deduplicated, sorted list of all vendor names currently in the
    database (combining both the raw vendor field and any vendor_override
    values).  Used by the frontend autocomplete datalist.
    """
    from sqlalchemy import text
    try:
        # Pull vendor_override first (user-corrected names), then raw vendor
        rows = db.execute(text(
            "SELECT DISTINCT vendor_override FROM devices WHERE vendor_override IS NOT NULL AND vendor_override != '' "
            "UNION "
            "SELECT DISTINCT vendor FROM devices WHERE vendor IS NOT NULL AND vendor != '' "
            "ORDER BY 1"
        )).fetchall()
        return sorted({r[0] for r in rows if r[0]}, key=lambda s: s.lower())
    except Exception:
        return []

@app.get("/stats")
def stats(db: Session = Depends(get_db)):
    total   = db.query(Device).count()
    online  = db.query(Device).filter(Device.is_online == True).count()
    offline = db.query(Device).filter(Device.is_online == False).count()
    scanned = db.query(Device).filter(Device.deep_scanned == True).count()
    return {
        "total_devices": total,
        "online":        online,
        "offline":       offline,
        "deep_scanned":  scanned,
    }

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
@app.get("/settings")
def get_settings(db: Session = Depends(get_db)):
    from models import Setting
    return [{"key": s.key, "value": s.value, "description": s.description} for s in db.query(Setting).all()]

@app.put("/settings/{key}")
def update_setting(key: str, payload: dict, db: Session = Depends(get_db)):
    from models import Setting
    s = db.get(Setting, key)
    if not s:
        raise HTTPException(404, "Setting not found")
    s.value = str(payload.get("value", s.value))
    db.commit()
    return {"key": key, "value": s.value}

@app.post("/settings/reset")
def reset_settings(db: Session = Depends(get_db)):
    from models import Setting
    defaults = {
        "scan_interval": "60",
        "offline_miss_threshold": "3",
        "os_confidence_threshold": "85",
        "sniffer_workers": "4",
        "ip_range": "192.168.0.0/24",
        "nmap_args": "-O --osscan-limit -sV --version-intensity 5 -T4",
    }
    for k, v in defaults.items():
        s = db.get(Setting, k)
        if s:
            s.value = v
    db.commit()
    return {"reset": True}

# ---------------------------------------------------------------------------
# Fingerprints (stubs — Phase 3)
# ---------------------------------------------------------------------------
@app.get("/fingerprints")
def get_fingerprints():
    return []

@app.get("/fingerprints/stats")
def fingerprint_stats():
    return {"total": 0}

@app.delete("/fingerprints/{fid}")
def delete_fingerprint(fid: int):
    raise HTTPException(404, "Not found")

@app.get("/export/devices")
def export_devices_csv(db: Session = Depends(get_db)):
    from fastapi.responses import StreamingResponse
    import csv, io
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["mac_address","ip_address","hostname","vendor","custom_name","is_online","first_seen","last_seen"])
    for d in db.query(Device).all():
        writer.writerow([d.mac_address, d.ip_address, d.hostname, d.vendor, d.custom_name, d.is_online, d.first_seen, d.last_seen])
    buf.seek(0)
    return StreamingResponse(buf, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=devices.csv"})

@app.get("/export/fingerprints")
def export_fingerprints_json():
    from fastapi.responses import JSONResponse
    return JSONResponse(content=[], headers={"Content-Disposition": "attachment; filename=fingerprints.json"})

@app.post("/import/fingerprints")
def import_fingerprints_json():
    return {"imported": 0}

def _to_dict(d: Device) -> dict:
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
        "first_seen":           d.first_seen.isoformat()  if d.first_seen  else None,
        "last_seen":            d.last_seen.isoformat()   if d.last_seen   else None,
        "scan_results":         d.scan_results,
        "display_name":         d.custom_name or d.hostname or d.ip_address,
    }
