import os
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from models import Base, Device

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://admin:password123@db:5432/inspectre")
PROBE_INTERFACE = os.environ.get("INTERFACE")
PROBE_IP_RANGE = os.environ.get("IP_RANGE")
SCAN_INTERVAL = os.environ.get("SCAN_INTERVAL", "60")
OFFLINE_MISS_THRESHOLD = os.environ.get("OFFLINE_MISS_THRESHOLD", "3")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

with engine.connect() as conn:
    try:
        conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS deep_scanned BOOLEAN DEFAULT FALSE"))
        conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS miss_count INTEGER DEFAULT 0"))
        conn.commit()
    except Exception:
        pass

app = FastAPI(title="InSpectre API", version="0.3.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class DeviceUpdate(BaseModel):
    custom_name: Optional[str] = None
    hostname: Optional[str] = None


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/")
def root():
    return {"message": "InSpectre API is online", "version": "0.3.0"}


@app.get("/setup/status")
def setup_status():
    return {
        "configured_interface": PROBE_INTERFACE,
        "configured_ip_range": PROBE_IP_RANGE,
        "scan_interval_seconds": int(SCAN_INTERVAL),
        "offline_miss_threshold": int(OFFLINE_MISS_THRESHOLD),
        "probe_mode": "active+passive",
        "jwt_enabled": False,
    }


@app.get("/devices")
def list_devices(online_only: bool = False, db: Session = Depends(get_db)):
    q = db.query(Device)
    if online_only:
        q = q.filter(Device.is_online == True)
    devices = q.order_by(Device.last_seen.desc()).all()
    return [_device_to_dict(d) for d in devices]


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


@app.get("/stats")
def stats(db: Session = Depends(get_db)):
    total = db.query(Device).count()
    online = db.query(Device).filter(Device.is_online == True).count()
    scanned = db.query(Device).filter(Device.deep_scanned == True).count()
    offline = db.query(Device).filter(Device.is_online == False).count()
    return {
        "total_devices": total,
        "online": online,
        "offline": offline,
        "deep_scanned": scanned,
    }


def _device_to_dict(d: Device) -> dict:
    return {
        "mac_address": d.mac_address,
        "ip_address": d.ip_address,
        "hostname": d.hostname,
        "vendor": d.vendor,
        "custom_name": d.custom_name,
        "is_online": d.is_online,
        "deep_scanned": d.deep_scanned,
        "miss_count": d.miss_count,
        "first_seen": d.first_seen.isoformat() if d.first_seen else None,
        "last_seen": d.last_seen.isoformat() if d.last_seen else None,
        "scan_results": d.scan_results,
    }
