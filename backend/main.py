from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from typing import Optional
import os
import socket
import subprocess

from models import Base, Device

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://admin:password123@db:5432/inspectre")
engine       = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

app = FastAPI(title="InSpectre API", version="0.3.0")
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

# ---------------------------------------------------------------------------
# Hostname resolution helpers (mirrors probe logic so API can re-resolve)
# ---------------------------------------------------------------------------
def _strip_fqdn(name: str) -> str:
    return name.rstrip('.') if name else ''

def _resolve_hostname(ip: str) -> str | None:
    """Multi-strategy hostname resolution — reverse DNS, mDNS, NetBIOS."""
    # 1. Reverse DNS
    try:
        result = socket.gethostbyaddr(ip)
        candidate = _strip_fqdn(result[0])
        if candidate and candidate != ip:
            return candidate
    except Exception:
        pass

    # 2. mDNS (avahi)
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

    # 3. NetBIOS (nmblookup)
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
    return {"message": "InSpectre API", "version": "0.3.0"}

@app.get("/devices")
def list_devices(online_only: bool = False, db: Session = Depends(get_db)):
    q = db.query(Device)
    if online_only:
        q = q.filter(Device.is_online == True)
    return [_to_dict(d) for d in q.order_by(Device.last_seen.desc()).all()]

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

@app.post("/devices/{mac}/resolve-name")
def resolve_name(mac: str, db: Session = Depends(get_db)):
    """Trigger an on-demand hostname resolution for a device."""
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    name = _resolve_hostname(d.ip_address)
    if name:
        d.hostname = name
        db.commit()
        db.refresh(d)
    return {"mac": mac, "resolved": name, "device": _to_dict(d)}

@app.get("/devices/{mac}/scan")
def get_scan_results(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    if not d.deep_scanned:
        return {"status": "pending", "message": "Deep scan not yet completed"}
    return {"status": "complete", "mac": mac, "data": d.scan_results}

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

def _to_dict(d: Device) -> dict:
    return {
        "mac_address":  d.mac_address,
        "ip_address":   d.ip_address,
        "hostname":     d.hostname,
        "vendor":       d.vendor,
        "custom_name":  d.custom_name,
        "is_online":    d.is_online,
        "deep_scanned": d.deep_scanned,
        "miss_count":   getattr(d, 'miss_count', 0),
        "first_seen":   d.first_seen.isoformat() if d.first_seen else None,
        "last_seen":    d.last_seen.isoformat()  if d.last_seen  else None,
        "scan_results": d.scan_results,
        # Convenience field: best available display name
        "display_name": d.custom_name or d.hostname or d.ip_address,
    }
