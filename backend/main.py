import os
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from models import Base, Device, Setting

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://admin:password123@db:5432/inspectre")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

# Safe migrations for deployments upgrading from earlier schema
with engine.connect() as conn:
    try:
        conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS deep_scanned BOOLEAN DEFAULT FALSE"))
        conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS miss_count INTEGER DEFAULT 0"))
        conn.commit()
    except Exception:
        pass

# Default settings seeded on first run
DEFAULT_SETTINGS = [
    ("scan_interval",        "60",              "Seconds between active ARP sweeps"),
    ("offline_miss_threshold","3",              "Missed sweeps before a device is marked offline"),
    ("os_confidence_threshold","85",            "Minimum nmap OS match accuracy % to store"),
    ("sniffer_workers",      "4",               "Worker threads draining the passive ARP sniffer queue"),
    ("nmap_args",            "-O --osscan-limit -sV --version-intensity 5 -T4",
                                                "Raw nmap argument string for deep scans"),
    ("ip_range",             os.environ.get("IP_RANGE", "192.168.0.0/24"),
                                                "Subnet to sweep, e.g. 192.168.0.0/24"),
]

with SessionLocal() as seed_session:
    for key, value, description in DEFAULT_SETTINGS:
        existing = seed_session.get(Setting, key)
        if not existing:
            seed_session.add(Setting(key=key, value=value, description=description))
    seed_session.commit()

app = FastAPI(title="InSpectre API", version="0.4.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------
class DeviceUpdate(BaseModel):
    custom_name: Optional[str] = None
    hostname: Optional[str] = None


class SettingUpdate(BaseModel):
    value: str


# ---------------------------------------------------------------------------
# DB dependency
# ---------------------------------------------------------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Root
# ---------------------------------------------------------------------------
@app.get("/")
def root():
    return {"message": "InSpectre API is online", "version": "0.4.0"}


# ---------------------------------------------------------------------------
# Settings endpoints
# ---------------------------------------------------------------------------
@app.get("/settings")
def list_settings(db: Session = Depends(get_db)):
    """Return all settings as a flat key→value map plus metadata."""
    rows = db.query(Setting).order_by(Setting.key).all()
    return [
        {
            "key": s.key,
            "value": s.value,
            "description": s.description,
            "updated_at": s.updated_at.isoformat() if s.updated_at else None,
        }
        for s in rows
    ]


@app.get("/settings/{key}")
def get_setting(key: str, db: Session = Depends(get_db)):
    s = db.get(Setting, key)
    if not s:
        raise HTTPException(status_code=404, detail=f"Setting '{key}' not found")
    return {"key": s.key, "value": s.value, "description": s.description,
            "updated_at": s.updated_at.isoformat() if s.updated_at else None}


@app.patch("/settings/{key}")
def update_setting(key: str, payload: SettingUpdate, db: Session = Depends(get_db)):
    s = db.get(Setting, key)
    if not s:
        raise HTTPException(status_code=404, detail=f"Setting '{key}' not found")
    s.value = payload.value
    s.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(s)
    return {"key": s.key, "value": s.value, "description": s.description,
            "updated_at": s.updated_at.isoformat() if s.updated_at else None}


@app.post("/settings/reset")
def reset_settings(db: Session = Depends(get_db)):
    """Reset all settings to their compiled-in defaults."""
    for key, value, description in DEFAULT_SETTINGS:
        s = db.get(Setting, key)
        if s:
            s.value = value
            s.updated_at = datetime.now(timezone.utc)
        else:
            db.add(Setting(key=key, value=value, description=description))
    db.commit()
    return {"status": "reset", "message": "All settings restored to defaults"}


# ---------------------------------------------------------------------------
# Device endpoints
# ---------------------------------------------------------------------------
@app.get("/devices")
def list_devices(online_only: bool = False, db: Session = Depends(get_db)):
    q = db.query(Device)
    if online_only:
        q = q.filter(Device.is_online == True)
    return [_device_to_dict(d) for d in q.order_by(Device.last_seen.desc()).all()]


@app.get("/devices/{mac}")
def get_device(mac: str, db: Session = Depends(get_db)):
    device = db.get(Device, mac.lower())
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return _device_to_dict(device)


@app.patch("/devices/{mac}")
def update_device(mac: str, payload: DeviceUpdate, db: Session = Depends(get_db)):
    device = db.get(Device, mac.lower())
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if payload.custom_name is not None:
        device.custom_name = payload.custom_name
    if payload.hostname is not None:
        device.hostname = payload.hostname
    db.commit()
    db.refresh(device)
    return _device_to_dict(device)


@app.get("/devices/{mac}/scan")
def get_scan_results(mac: str, db: Session = Depends(get_db)):
    device = db.get(Device, mac.lower())
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if not device.deep_scanned:
        return {"status": "pending", "message": "Deep scan not yet completed for this device"}
    return {"status": "complete", "mac": mac.lower(), "data": device.scan_results}


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------
@app.get("/stats")
def stats(db: Session = Depends(get_db)):
    total   = db.query(Device).count()
    online  = db.query(Device).filter(Device.is_online == True).count()
    offline = db.query(Device).filter(Device.is_online == False).count()
    scanned = db.query(Device).filter(Device.deep_scanned == True).count()
    return {"total_devices": total, "online": online, "offline": offline, "deep_scanned": scanned}


# ---------------------------------------------------------------------------
# Setup status (used by frontend on first load)
# ---------------------------------------------------------------------------
@app.get("/setup/status")
def setup_status(db: Session = Depends(get_db)):
    def _get(key: str) -> Any:
        s = db.get(Setting, key)
        return s.value if s else None
    return {
        "ip_range":               _get("ip_range"),
        "scan_interval_seconds":  int(_get("scan_interval") or 60),
        "offline_miss_threshold": int(_get("offline_miss_threshold") or 3),
        "os_confidence_threshold":int(_get("os_confidence_threshold") or 85),
        "probe_mode":             "active+passive",
        "jwt_enabled":            False,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _device_to_dict(d: Device) -> dict:
    return {
        "mac_address":  d.mac_address,
        "ip_address":   d.ip_address,
        "hostname":     d.hostname,
        "vendor":       d.vendor,
        "custom_name":  d.custom_name,
        "is_online":    d.is_online,
        "deep_scanned": d.deep_scanned,
        "miss_count":   d.miss_count,
        "first_seen":   d.first_seen.isoformat() if d.first_seen else None,
        "last_seen":    d.last_seen.isoformat() if d.last_seen else None,
        "scan_results": d.scan_results,
    }
