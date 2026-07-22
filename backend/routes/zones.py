from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
from typing import Optional
from database import get_db
from auth_utils import get_current_user
from models import Device, Setting
from schemas import ZoneAssign, ZoneRename
from device_utils import _add_event

router = APIRouter()


@router.get("/zones")
def list_zones(db: Session = Depends(get_db)):
    try:
        rows = db.execute(text("""
            SELECT
                COALESCE(zone, 'Unassigned') AS zone,
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE is_online = true) AS online
            FROM devices
            GROUP BY zone
            ORDER BY zone
        """)).fetchall()
        return [{"zone": r[0], "total": int(r[1]), "online": int(r[2])} for r in rows]
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/zones/assign")
def assign_zone(body: ZoneAssign, db: Session = Depends(get_db)):
    try:
        db.execute(
            text("UPDATE devices SET zone = :zone WHERE mac_address = ANY(:macs)"),
            {"zone": body.zone, "macs": [m.lower() for m in body.mac_addresses]},
        )
        db.commit()
        return {"updated": len(body.mac_addresses)}
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))


@router.post("/zones/rename")
def rename_zone(body: ZoneRename, db: Session = Depends(get_db)):
    try:
        result = db.execute(
            text("UPDATE devices SET zone = :new WHERE zone = :old"),
            {"new": body.new_name, "old": body.old_name},
        )
        db.commit()
        return {"updated": result.rowcount}
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))
