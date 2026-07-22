from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
import asyncio
from database import get_db
from auth_utils import get_current_user
from models import Device, Setting
from config import PROBE_URL
from probe_client import _probe_client, _execute_block_bg
from notifications_core import _notification_dispatch
import state

router = APIRouter()


@router.get("/network/status")
def network_status(db: Session = Depends(get_db)):
    setting = db.get(Setting, "network_paused")
    paused = (setting.value if setting else "false") == "true"
    blocked_count = db.execute(text("SELECT COUNT(*) FROM devices WHERE is_blocked = TRUE")).scalar()
    return {"paused": paused, "blocked_count": int(blocked_count or 0)}


@router.post("/network/pause")
async def network_pause(db: Session = Depends(get_db)):
    devices = db.execute(text(
        "SELECT mac_address, ip_address FROM devices WHERE is_ignored = FALSE AND is_blocked = FALSE AND ip_address IS NOT NULL"
    )).fetchall()
    errors = []
    async def _block_one(mac: str, ip: str):
        try:
            async with _probe_client(timeout=10.0) as client:
                await client.post(f"{PROBE_URL}/block/{mac.lower()}")
        except Exception as e:
            errors.append(str(e))
    await asyncio.gather(*[_block_one(r[0], r[1]) for r in devices])
    db.execute(text("UPDATE devices SET is_blocked = TRUE WHERE is_ignored = FALSE AND ip_address IS NOT NULL"))
    setting = db.get(Setting, "network_paused")
    if setting:
        setting.value = "true"
    else:
        db.execute(text("INSERT INTO settings (key, value) VALUES ('network_paused', 'true')"))
    db.commit()
    return {"paused": True, "blocked": len(devices), "errors": errors}


@router.post("/network/resume")
async def network_resume(db: Session = Depends(get_db)):
    devices = db.execute(text(
        "SELECT mac_address, ip_address FROM devices WHERE is_blocked = TRUE AND ip_address IS NOT NULL"
    )).fetchall()
    errors = []
    async def _unblock_one(mac: str):
        try:
            async with _probe_client(timeout=10.0) as client:
                await client.delete(f"{PROBE_URL}/block/{mac.lower()}")
        except Exception as e:
            errors.append(str(e))
    await asyncio.gather(*[_unblock_one(r[0]) for r in devices])
    db.execute(text("UPDATE devices SET is_blocked = FALSE, is_schedule_blocked = FALSE WHERE is_blocked = TRUE"))
    setting = db.get(Setting, "network_paused")
    if setting:
        setting.value = "false"
    else:
        db.execute(text("INSERT INTO settings (key, value) VALUES ('network_paused', 'false')"))
    db.commit()
    return {"paused": False, "unblocked": len(devices), "errors": errors}
