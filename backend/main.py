import os
import re
import shutil
import subprocess
import asyncio
from typing import Optional, AsyncIterator

import httpx
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from models import Base, Device

VERSION = "0.5.0"

DATABASE_URL  = os.environ.get("DATABASE_URL",  "postgresql://admin:password123@db:5432/inspectre")
# URL of the probe's internal HTTP API.  The probe runs with network_mode:host
# so from the backend (bridge network) we reach it via host.docker.internal.
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


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class DeviceUpdate(BaseModel):
    custom_name:          Optional[str] = None
    hostname:             Optional[str] = None
    vendor:               Optional[str] = None
    device_type_override: Optional[str] = None
    vendor_override:      Optional[str] = None


# ── helpers ───────────────────────────────────────────────────────────────────

def _get_device_or_404(mac: str, db: Session) -> Device:
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    return d


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


# ── read endpoints ─────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"message": "InSpectre API is online", "version": VERSION}


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


@app.post("/devices/{mac}/resolve-name")
async def resolve_name(mac: str, db: Session = Depends(get_db)):
    """
    Re-resolve the hostname for this device.
    Delegates to the probe's /resolve/{ip} endpoint because the probe has
    host networking and can reach LAN DNS servers; the backend cannot.
    """
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
            f"Could not reach probe API at {PROBE_API_URL}. "
            f"Make sure the probe container is running. Detail: {e}"
        )

    if hostname:
        d.hostname = hostname
        db.commit()
        db.refresh(d)

    return _to_dict(d)


@app.post("/devices/{mac}/rescan")
async def request_rescan(mac: str, db: Session = Depends(get_db)):
    """Immediately trigger a fresh nmap deep scan via the probe."""
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


# ── serialiser ─────────────────────────────────────────────────────────────────

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
