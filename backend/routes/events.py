from fastapi import APIRouter, Depends, Request, Query
from fastapi.responses import StreamingResponse, JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session
from typing import Optional, List
import asyncio, json
from database import get_db, SessionLocal
from auth_utils import get_current_user
from models import Device, Setting
import state

router = APIRouter()


@router.get("/events/stream")
async def events_stream(request: Request):
    """
    Server-Sent Events stream for live UI updates.  The browser opens one
    EventSource per tab; the backend pushes named events ('devices', 'persons',
    'schedules', 'persons'…) whenever the underlying data changes, so pages
    refresh on real changes instead of polling on a timer.  A periodic heartbeat
    keeps the connection (and any proxies) alive.
    """
    queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    state._sse_clients.add(queue)

    async def _gen():
        try:
            # Tell the client we're live so it can do an initial load.
            yield "event: ready\ndata: {}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=15.0)
                except asyncio.TimeoutError:
                    # Heartbeat comment — ignored by EventSource, keeps proxy open.
                    yield ": ping\n\n"
                    continue
                try:
                    data = json.dumps(msg.get("data", {}))
                except Exception:
                    data = "{}"
                yield f"event: {msg.get('event', 'message')}\ndata: {data}\n\n"
        finally:
            state._sse_clients.discard(queue)

    return StreamingResponse(
        _gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/events")
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


@router.get("/events/status")
def get_status_events(limit: int = Query(100, ge=1, le=1000), db: Session = Depends(get_db)):
    try:
        rows = db.execute(text("""
            SELECT de.id, de.mac_address, de.type, de.detail, de.created_at,
                   COALESCE(d.custom_name, d.hostname, d.ip_address, de.mac_address) AS display_name,
                   d.ip_address, d.vendor
            FROM device_events de
            JOIN devices d ON d.mac_address = de.mac_address
            WHERE de.type IN ('online', 'offline')
            ORDER BY de.created_at DESC
            LIMIT :limit
        """), {"limit": limit}).fetchall()
        return [{"id": r[0], "mac_address": r[1], "type": r[2], "detail": r[3],
                 "created_at": r[4].isoformat() if r[4] else None, "display_name": r[5],
                 "ip_address": r[6], "vendor": r[7]} for r in rows]
    except Exception:
        return []


@router.get("/changes")
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


@router.get("/dashboard/summary")
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


@router.get("/vendors", response_model=List[str])
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


@router.get("/stats")
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
