from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy import text
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime, timezone
import json
from database import get_db
from auth_utils import get_current_user
from schemas import SuppressionCreate

router = APIRouter()


@router.get("/suppressions")
def list_suppressions(mac: Optional[str] = None, db: Session = Depends(get_db)):
    try:
        if mac:
            rows = db.execute(text("""
                SELECT id, mac_address, event_type, reason, expires_at, created_at
                FROM alert_suppressions
                WHERE mac_address = :mac
                ORDER BY created_at DESC
            """), {"mac": mac.lower()}).fetchall()
        else:
            rows = db.execute(text("""
                SELECT id, mac_address, event_type, reason, expires_at, created_at
                FROM alert_suppressions
                ORDER BY created_at DESC
            """)).fetchall()
        return [
            {
                "id": r[0], "mac_address": r[1], "event_type": r[2],
                "reason": r[3],
                "expires_at": r[4].isoformat() if r[4] else None,
                "created_at": r[5].isoformat() if r[5] else None,
            }
            for r in rows
        ]
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/suppressions", status_code=201)
def create_suppression(body: SuppressionCreate, db: Session = Depends(get_db)):
    try:
        expires = None
        if body.expires_at:
            from datetime import datetime
            expires = datetime.fromisoformat(body.expires_at.replace("Z", "+00:00"))
        row = db.execute(
            text("""
                INSERT INTO alert_suppressions (mac_address, event_type, reason, expires_at)
                VALUES (:mac, :type, :reason, :expires)
                RETURNING id, mac_address, event_type, reason, expires_at, created_at
            """),
            {
                "mac": body.mac_address.lower() if body.mac_address else None,
                "type": body.event_type,
                "reason": body.reason,
                "expires": expires,
            }
        ).fetchone()
        db.commit()
        return {
            "id": row[0], "mac_address": row[1], "event_type": row[2],
            "reason": row[3],
            "expires_at": row[4].isoformat() if row[4] else None,
            "created_at": row[5].isoformat() if row[5] else None,
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))


@router.delete("/suppressions/{suppression_id}", status_code=204)
def delete_suppression(suppression_id: int, db: Session = Depends(get_db)):
    db.execute(text("DELETE FROM alert_suppressions WHERE id = :id"), {"id": suppression_id})
    db.commit()
