from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy import text
from sqlalchemy.orm import Session
from typing import Optional, List
import json
from database import get_db
from auth_utils import get_current_user
from schemas import BlockScheduleCreate, BlockScheduleUpdate

router = APIRouter()


def _schedule_row_to_dict(row) -> dict:
    return {
        "id":            row[0],
        "mac_address":   row[1],
        "label":         row[2],
        "days_of_week":  row[3],
        "start_time":    row[4],
        "end_time":      row[5],
        "enabled":       row[6],
        "created_at":    row[7].isoformat() if row[7] else None,
        "mac_addresses": list(row[8]) if row[8] else [],
        "tags":          row[9] or "",
        "person_id":     str(row[10]) if len(row) > 10 and row[10] else None,
        "person_ids":    list(row[11]) if len(row) > 11 and row[11] else [],
    }


@router.get("/block-schedules")
def list_block_schedules(db: Session = Depends(get_db)):
    rows = db.execute(text(
        "SELECT id, mac_address, label, days_of_week, start_time, end_time, enabled, created_at, mac_addresses, tags, person_id, person_ids "
        "FROM block_schedules ORDER BY created_at DESC"
    )).fetchall()
    return [_schedule_row_to_dict(r) for r in rows]


@router.post("/block-schedules", status_code=201)
def create_block_schedule(payload: BlockScheduleCreate, db: Session = Depends(get_db)):
    if not payload.start_time or not payload.end_time:
        raise HTTPException(400, "start_time and end_time are required")
    person_id  = payload.person_id or None
    # Merge single person_id into person_ids for backward compat
    person_ids = list(set(payload.person_ids or []))
    if person_id and person_id not in person_ids:
        person_ids.append(person_id)
    # If any person_ids, set person_id to first one for backward compat display
    if person_ids and not person_id:
        person_id = person_ids[0]
    row = db.execute(text(
        "INSERT INTO block_schedules (mac_address, label, days_of_week, start_time, end_time, enabled, mac_addresses, tags, person_id, person_ids) "
        "VALUES (:mac, :label, :days, :start, :end, :enabled, :mac_addresses, :tags, :person_id, :person_ids) "
        "RETURNING id, mac_address, label, days_of_week, start_time, end_time, enabled, created_at, mac_addresses, tags, person_id, person_ids"
    ), {
        "mac":           payload.mac_address,
        "label":         payload.label or "",
        "days":          payload.days_of_week,
        "start":         payload.start_time,
        "end":           payload.end_time,
        "enabled":       payload.enabled,
        "mac_addresses": payload.mac_addresses or [],
        "tags":          payload.tags or "",
        "person_id":     person_id,
        "person_ids":    person_ids,
    }).fetchone()
    db.commit()
    return _schedule_row_to_dict(row)


@router.patch("/block-schedules/{schedule_id}")
def update_block_schedule(schedule_id: int, payload: BlockScheduleUpdate, db: Session = Depends(get_db)):
    existing = db.execute(text(
        "SELECT id FROM block_schedules WHERE id = :id"
    ), {"id": schedule_id}).fetchone()
    if not existing:
        raise HTTPException(404, "Schedule not found")
    updates = {}
    if payload.label         is not None: updates["label"]         = payload.label
    if payload.days_of_week  is not None: updates["days_of_week"]  = payload.days_of_week
    if payload.start_time    is not None: updates["start_time"]    = payload.start_time
    if payload.end_time      is not None: updates["end_time"]      = payload.end_time
    if payload.enabled       is not None: updates["enabled"]       = payload.enabled
    if payload.mac_addresses is not None: updates["mac_addresses"] = payload.mac_addresses
    if payload.tags          is not None: updates["tags"]          = payload.tags
    if payload.person_id     is not None: updates["person_id"]     = payload.person_id or None
    if payload.person_ids    is not None:
        pids = list(set(payload.person_ids))
        updates["person_ids"] = pids
        # keep person_id in sync with first entry
        if pids and payload.person_id is None:
            updates["person_id"] = pids[0]
        elif not pids:
            updates["person_id"] = None
    if updates:
        set_clause = ", ".join(f"{k} = :{k}" for k in updates)
        updates["id"] = schedule_id
        db.execute(text(f"UPDATE block_schedules SET {set_clause} WHERE id = :id"), updates)
        db.commit()
    row = db.execute(text(
        "SELECT id, mac_address, label, days_of_week, start_time, end_time, enabled, created_at, mac_addresses, tags, person_id, person_ids "
        "FROM block_schedules WHERE id = :id"
    ), {"id": schedule_id}).fetchone()
    return _schedule_row_to_dict(row)


@router.delete("/block-schedules/{schedule_id}", status_code=204)
def delete_block_schedule(schedule_id: int, db: Session = Depends(get_db)):
    db.execute(text("DELETE FROM block_schedules WHERE id = :id"), {"id": schedule_id})
    db.commit()
