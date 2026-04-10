from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from typing import Optional
import os
import socket
import subprocess
import httpx

from models import Base, Device, IPHistory, Setting

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://admin:password123@db:5432/inspectre")
PROBE_URL    = os.environ.get("PROBE_URL",    "http://localhost:8001")

engine       = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

# Safe migration: add ip_history table if this is an existing DB
with engine.connect() as _conn:
    _conn.execute(text("""
        CREATE TABLE IF NOT EXISTS ip_history (
            id          SERIAL PRIMARY KEY,
            mac_address VARCHAR NOT NULL,
            ip_address  VARCHAR NOT NULL,
            first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CONSTRAINT uq_ip_history_mac_ip UNIQUE (mac_address, ip_address)
        )
    """))
    _conn.execute(text("CREATE INDEX IF NOT EXISTS ix_ip_history_mac ON ip_history (mac_address)"))
    _conn.commit()

app = FastAPI(title="InSpectre API", version="0.4.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Default settings
# ---------------------------------------------------------------------------
DEFAULT_SETTINGS = [
    {"key": "scan_interval",           "value": "60",                                          "description": "Seconds between ARP sweep cycles."},
    {"key": "offline_miss_threshold",  "value": "3",                                           "description": "Consecutive missed sweeps before a device is marked offline."},
    {"key": "os_confidence_threshold", "value": "85",                                          "description": "Minimum nmap OS confidence % to record a match."},
    {"key": "sniffer_workers",         "value": "4",                                           "description": "Worker threads for the passive ARP sniffer."},
    {"key": "ip_range",                "value": os.environ.get("IP_RANGE", "192.168.0.0/24"),  "description": "CIDR range to scan."},
    {"key": "nmap_args",               "value": "-O --osscan-limit -sV --version-intensity 5 -T4", "description": "Arguments passed to nmap during deep scans."},
]

def seed_default_settings(db: Session) -> None:
    for s in DEFAULT_SETTINGS:
        if not db.get(Setting, s["key"]):
            db.add(Setting(key=s["key"], value=s["value"], description=s["description"]))
    db.commit()

with SessionLocal() as _db:
    seed_default_settings(_db)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class DeviceUpdate(BaseModel):
    custom_name: Optional[str] = None
    hostname:    Optional[str] = None

class SettingUpdate(BaseModel):
    value: str


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
                    if candidate not in ('WORKGROUP', ip, 'Looking'):
                        return candidate
    except Exception:
        pass
    return None


def _get_device_ip(mac: str, db: Session) -> str:
    """Look up a device's current IP, raise 404/409 if not found/offline."""
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    if not d.ip_address:
        raise HTTPException(409, "Device has no recorded IP address")
    return d.ip_address


def _proxy_sse(probe_url: str):
    """
    Open a streaming GET to the probe's internal API and re-yield
    each SSE chunk directly — zero buffering.
    """
    def generator():
        try:
            with httpx.stream("GET", probe_url, timeout=120) as resp:
                if resp.status_code != 200:
                    yield f"data: ERROR — probe returned {resp.status_code}\n\n"
                    yield "event: done\ndata: {}\n\n"
                    return
                for chunk in resp.iter_bytes():
                    if chunk:
                        yield chunk
        except httpx.ConnectError:
            yield b"data: ERROR — cannot reach probe (is the probe container running?)\n\n"
            yield b"event: done\ndata: {}\n\n"
        except Exception as e:
            yield f"data: ERROR — {e}\n\n".encode()
            yield b"event: done\ndata: {}\n\n"
    return generator()


# ---------------------------------------------------------------------------
# Routes — devices
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
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    d.deep_scanned = False
    d.scan_results = None
    db.commit()
    db.refresh(d)
    return {"mac": mac, "status": "queued", "message": "Rescan queued.", "device": _to_dict(d)}

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
    rows = (
        db.query(IPHistory)
        .filter(IPHistory.mac_address == mac.lower())
        .order_by(IPHistory.last_seen.desc())
        .all()
    )
    return [{"ip": r.ip_address, "first_seen": r.first_seen.isoformat(), "last_seen": r.last_seen.isoformat()} for r in rows]

@app.get("/devices/{mac}/ping")
def ping_device(mac: str, db: Session = Depends(get_db)):
    """SSE stream — proxies ping output from the probe container."""
    ip = _get_device_ip(mac, db)
    return StreamingResponse(
        _proxy_sse(f"{PROBE_URL}/stream/ping/{ip}"),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

@app.get("/devices/{mac}/traceroute")
def traceroute_device(mac: str, db: Session = Depends(get_db)):
    """SSE stream — proxies traceroute output from the probe container."""
    ip = _get_device_ip(mac, db)
    return StreamingResponse(
        _proxy_sse(f"{PROBE_URL}/stream/traceroute/{ip}"),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

@app.get("/stats")
def stats(db: Session = Depends(get_db)):
    total   = db.query(Device).count()
    online  = db.query(Device).filter(Device.is_online == True).count()
    offline = db.query(Device).filter(Device.is_online == False).count()
    scanned = db.query(Device).filter(Device.deep_scanned == True).count()
    return {"total_devices": total, "online": online, "offline": offline, "deep_scanned": scanned}


# ---------------------------------------------------------------------------
# Routes — settings
# ---------------------------------------------------------------------------
@app.get("/settings")
def get_settings(db: Session = Depends(get_db)):
    rows = db.query(Setting).order_by(Setting.key).all()
    return [_setting_dict(s) for s in rows]

@app.put("/settings/{key}")
def update_setting(key: str, payload: SettingUpdate, db: Session = Depends(get_db)):
    s = db.get(Setting, key)
    if s:
        s.value = payload.value
    else:
        s = Setting(key=key, value=payload.value)
        db.add(s)
    db.commit()
    db.refresh(s)
    return _setting_dict(s)

@app.post("/settings/reset")
def reset_settings(db: Session = Depends(get_db)):
    for default in DEFAULT_SETTINGS:
        s = db.get(Setting, default["key"])
        if s:
            s.value = default["value"]
        else:
            db.add(Setting(key=default["key"], value=default["value"], description=default["description"]))
    db.commit()
    rows = db.query(Setting).order_by(Setting.key).all()
    return [_setting_dict(s) for s in rows]


# ---------------------------------------------------------------------------
# Serialisers
# ---------------------------------------------------------------------------
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
        "display_name": d.custom_name or d.hostname or d.ip_address,
    }

def _setting_dict(s: Setting) -> dict:
    return {
        "key":         s.key,
        "value":       s.value,
        "description": s.description or '',
        "updated_at":  s.updated_at.isoformat() if s.updated_at else None,
    }
