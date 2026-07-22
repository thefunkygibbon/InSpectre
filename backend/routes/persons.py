from fastapi import APIRouter, HTTPException, Depends, status, Query
from sqlalchemy import text
from sqlalchemy.orm import Session
from typing import Optional, List
import asyncio, json
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from database import get_db, SessionLocal
from auth_utils import get_current_user
from models import Device, Setting
from schemas import PersonCreate, PersonUpdate, PersonDeviceAdd, PersonBlockRequest
from probe_client import _execute_block_bg
from notifications_core import _notification_dispatch
from device_utils import _add_event
import state

router = APIRouter()


def _fetch_person_devices(db: Session, person_id: str | None = None) -> dict:
    # Show only directly assigned MACs (not group siblings — they are the same physical
    # device and showing them separately is confusing).  is_online is group-level:
    # true if this device OR any of its grouped siblings is online.
    where = ""
    params = {}
    if person_id is not None:
        where = "WHERE pd.person_id::text = :pid"
        params["pid"] = person_id
    rows = db.execute(text(f"""
        SELECT
            pd.person_id::text,
            d.mac_address,
            CASE
                WHEN d.group_id IS NOT NULL THEN
                    EXISTS (SELECT 1 FROM devices sib
                            WHERE sib.group_id = d.group_id AND sib.is_online = true)
                ELSE d.is_online
            END AS is_online,
            COALESCE(d.custom_name, d.hostname, d.ip_address) AS display_name,
            d.ip_address,
            d.device_type_override AS device_type,
            COALESCE(d.vendor_override, d.vendor) AS vendor,
            d.is_blocked,
            CASE
                WHEN d.group_id IS NOT NULL THEN (
                    SELECT MAX(sib.status_changed_at) FROM devices sib
                    WHERE sib.group_id = d.group_id
                )
                ELSE d.status_changed_at
            END AS status_changed_at
        FROM person_devices pd
        JOIN devices d ON d.mac_address = pd.mac_address
        {where}
        ORDER BY pd.person_id::text, d.mac_address
    """), params).fetchall()
    devs_by_person: dict = {}
    for r in rows:
        devs_by_person.setdefault(r[0], []).append({
            "mac_address": r[1],
            "is_online": r[2],
            "display_name": r[3],
            "ip_address": r[4],
            "device_type": r[5],
            "vendor": r[6],
            "is_blocked": bool(r[7]),
            "status_changed_at": r[8].isoformat() if r[8] else None,
        })
    return devs_by_person


def _person_row_to_dict(row, devices=None, schedules=None) -> dict:
    """Convert a persons row to a dict. devices and schedules are pre-fetched lists."""
    pid = str(row[0])
    devs = devices or []
    primary_mac = row[2]
    if primary_mac:
        is_home = any(d.get("is_online") for d in devs if d.get("mac_address") == primary_mac)
    else:
        is_home = any(d.get("is_online") for d in devs)
    is_blocked = bool(devs) and all(d.get("is_blocked", False) for d in devs)
    timed_block_remaining = None
    task = state._person_timed_blocks.get(pid)
    if task and not task.done():
        timed_block_remaining = True  # active timed block
    # Derive last status change from the most recent device status_changed_at
    status_changed_at = None
    for d in devs:
        sc = d.get("status_changed_at")
        if sc and (status_changed_at is None or sc > status_changed_at):
            status_changed_at = sc
    return {
        "id":                    pid,
        "name":                  row[1],
        "primary_mac":           row[2],
        "photo":                 row[3],
        "notes":                 row[4],
        "created_at":            row[5].isoformat() if row[5] else None,
        "updated_at":            row[6].isoformat() if row[6] else None,
        "is_home":               is_home,
        "is_blocked":            is_blocked,
        "has_timed_block":       timed_block_remaining is not None,
        "last_status_changed_at": status_changed_at,
        "devices":               devs,
        "schedules":             schedules or [],
    }


@router.get("/persons")
def list_persons(db: Session = Depends(get_db)):
    persons = db.execute(text(
        "SELECT id::text, name, primary_mac, photo, notes, created_at, updated_at FROM persons ORDER BY name"
    )).fetchall()
    devs_by_person = _fetch_person_devices(db)
    # Fetch person-targeted schedules (both person_id and person_ids)
    try:
        sched_rows = db.execute(text(
            "SELECT id, person_id::text, label, days_of_week, start_time, end_time, enabled, person_ids "
            "FROM block_schedules WHERE person_id IS NOT NULL OR array_length(person_ids, 1) > 0"
        )).fetchall()
    except Exception:
        sched_rows = []
    scheds_by_person: dict = {}
    for r in sched_rows:
        sched = {
            "id": r[0], "label": r[2], "days_of_week": r[3],
            "start_time": r[4], "end_time": r[5], "enabled": r[6],
            "person_ids": list(r[7]) if r[7] else [],
        }
        # Add to each targeted person's list
        effective_pids = list(r[7]) if r[7] else []
        if r[1] and r[1] not in effective_pids:
            effective_pids.append(r[1])
        for pid in effective_pids:
            scheds_by_person.setdefault(pid, []).append(sched)
    return [
        _person_row_to_dict(p, devs_by_person.get(str(p[0]), []), scheds_by_person.get(str(p[0]), []))
        for p in persons
    ]


@router.post("/persons", status_code=201)
def create_person(payload: PersonCreate, db: Session = Depends(get_db)):
    if not payload.name.strip():
        raise HTTPException(400, "name is required")
    row = db.execute(text(
        "INSERT INTO persons (name, primary_mac, photo, notes) "
        "VALUES (:name, :primary_mac, :photo, :notes) "
        "RETURNING id::text, name, primary_mac, photo, notes, created_at, updated_at"
    ), {
        "name":        payload.name.strip(),
        "primary_mac": payload.primary_mac or None,
        "photo":       payload.photo or None,
        "notes":       payload.notes or None,
    }).fetchone()
    db.commit()
    return _person_row_to_dict(row)


@router.get("/persons/timeline")
def get_persons_timeline(days: int = Query(7, ge=1, le=365), db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=days)

    persons = db.execute(text(
        "SELECT id::text, name, primary_mac, photo FROM persons ORDER BY name"
    )).fetchall()

    if not persons:
        return {"window_start": window_start.isoformat(), "window_end": now.isoformat(),
                "days": days, "persons": []}

    devs_by_person = _fetch_person_devices(db)
    person_macs = {
        p[0]: [d["mac_address"] for d in devs_by_person.get(p[0], [])]
        for p in persons
    }

    # Expand each person's assigned MACs to include all group siblings so that
    # events from any interface (2.4 GHz, 5 GHz, etc.) are captured.
    assigned_macs_flat = sorted({mac for macs in person_macs.values() for mac in macs})
    expanded_person_macs: dict[str, list[str]] = {}
    if assigned_macs_flat:
        ap_params = {f"ap{i}": m for i, m in enumerate(assigned_macs_flat)}
        ap_in     = ", ".join(f":ap{i}" for i in range(len(assigned_macs_flat)))
        sib_rows  = db.execute(text(f"""
            SELECT d.mac_address AS assigned, sib.mac_address AS sibling
            FROM devices d
            JOIN devices sib ON d.group_id IS NOT NULL AND sib.group_id = d.group_id
            WHERE d.mac_address IN ({ap_in})
        """), ap_params).fetchall()
        sibling_map: dict[str, set] = {m: {m} for m in assigned_macs_flat}
        for assigned, sibling in sib_rows:
            sibling_map.setdefault(assigned, {assigned}).add(sibling)
        for pid, pmacs in person_macs.items():
            expanded: set = set()
            for m in pmacs:
                expanded |= sibling_map.get(m, {m})
            expanded_person_macs[pid] = sorted(expanded)
    else:
        expanded_person_macs = {pid: [] for pid in person_macs}

    all_macs = sorted({mac for macs in expanded_person_macs.values() for mac in macs})
    events_by_mac: dict = defaultdict(list)
    prior_by_mac: dict = {}

    if all_macs:
        mac_params = {f"mac{i}": m for i, m in enumerate(all_macs)}
        mac_in     = ", ".join(f":mac{i}" for i in range(len(all_macs)))

        rows = db.execute(text(f"""
            SELECT mac_address, type, created_at FROM device_events
            WHERE mac_address IN ({mac_in})
              AND type IN ('online', 'offline', 'joined')
              AND created_at >= :window_start
            ORDER BY mac_address, created_at ASC
        """), {"window_start": window_start, **mac_params}).fetchall()
        for r in rows:
            events_by_mac[r[0]].append({"type": r[1], "ts": r[2]})

        for r in db.execute(text(f"""
            SELECT DISTINCT ON (mac_address) mac_address, type
            FROM device_events
            WHERE mac_address IN ({mac_in})
              AND type IN ('online', 'offline', 'joined')
              AND created_at < :window_start
            ORDER BY mac_address, created_at DESC
        """), {"window_start": window_start, **mac_params}).fetchall():
            prior_by_mac[r[0]] = "online" if r[1] in ("online", "joined") else "offline"

    def _overall_state(states: dict) -> str:
        vals = list(states.values())
        if any(v == "online" for v in vals):
            return "online"
        if any(v == "offline" for v in vals):
            return "offline"
        return "unknown"

    # Merge offline gaps shorter than the probe's grace period in the history display.
    # We use presence_grace_seconds (the probe's offline threshold) rather than the
    # notification confirmation window — these two are now separate concerns.
    _grace_row = db.execute(text("SELECT value FROM settings WHERE key='presence_grace_seconds'")).fetchone()
    min_gap_seconds = int((_grace_row[0] if _grace_row else None) or 240)

    def build_segments(macs: list[str]):
        if not macs:
            return [], 0
        state_by_mac = {m: prior_by_mac.get(m, "unknown") for m in macs}
        merged_events = []
        for m in macs:
            for ev in events_by_mac.get(m, []):
                merged_events.append({"mac": m, "ts": ev["ts"], "type": ev["type"]})
        merged_events.sort(key=lambda x: x["ts"])

        segs = []
        seg_start = window_start
        seg_state = _overall_state(state_by_mac)
        idx = 0
        while idx < len(merged_events):
            ts = merged_events[idx]["ts"]
            # Apply all events at this timestamp first, then check if state changed.
            while idx < len(merged_events) and merged_events[idx]["ts"] == ts:
                ev = merged_events[idx]
                state_by_mac[ev["mac"]] = "online" if ev["type"] in ("online", "joined") else "offline"
                idx += 1
            new_state = _overall_state(state_by_mac)
            if new_state != seg_state:
                # Only create a segment boundary when the group-level state actually changes.
                if ts > seg_start:
                    segs.append({"from": seg_start.isoformat(), "to": ts.isoformat(), "status": seg_state})
                seg_start = ts
                seg_state = new_state
        segs.append({"from": seg_start.isoformat(), "to": now.isoformat(), "status": seg_state})

        # Merge short offline gaps: online → offline(< threshold) → online becomes one online segment.
        i = 0
        while i < len(segs) - 2:
            if (segs[i]["status"] == "online" and
                    segs[i + 1]["status"] == "offline" and
                    segs[i + 2]["status"] == "online"):
                t_from = datetime.fromisoformat(segs[i + 1]["from"])
                t_to   = datetime.fromisoformat(segs[i + 1]["to"])
                if (t_to - t_from).total_seconds() < min_gap_seconds:
                    segs[i] = {"from": segs[i]["from"], "to": segs[i + 2]["to"], "status": "online"}
                    segs.pop(i + 1)
                    segs.pop(i + 1)
                    continue
            i += 1

        home_ms  = sum(
            (datetime.fromisoformat(s["to"]) - datetime.fromisoformat(s["from"])).total_seconds() * 1000
            for s in segs if s["status"] == "online"
        )
        known_ms = sum(
            (datetime.fromisoformat(s["to"]) - datetime.fromisoformat(s["from"])).total_seconds() * 1000
            for s in segs if s["status"] != "unknown"
        )
        home_pct = round((home_ms / known_ms) * 100) if known_ms > 0 else 0
        return segs, home_pct

    result = []
    for p in persons:
        pid = p[0]
        segs, pct = build_segments(expanded_person_macs.get(pid, []))
        result.append({
            "id":          pid,
            "name":        p[1],
            "photo":       p[3],
            "primary_mac": p[2],
            "segments":    segs,
            "at_home_pct": pct,
        })

    return {
        "window_start": window_start.isoformat(),
        "window_end":   now.isoformat(),
        "days":         days,
        "persons":      result,
    }


@router.get("/persons/{person_id}")
def get_person(person_id: str, db: Session = Depends(get_db)):
    row = db.execute(text(
        "SELECT id::text, name, primary_mac, photo, notes, created_at, updated_at "
        "FROM persons WHERE id = :id"
    ), {"id": person_id}).fetchone()
    if not row:
        raise HTTPException(404, "Person not found")
    devs = _fetch_person_devices(db, person_id).get(person_id, [])
    try:
        sched_rows = db.execute(text(
            "SELECT id, person_id::text, label, days_of_week, start_time, end_time, enabled, person_ids "
            "FROM block_schedules WHERE person_id = :pid OR :pid = ANY(person_ids::text[])"
        ), {"pid": person_id}).fetchall()
        scheds = [{"id": r[0], "label": r[2], "days_of_week": r[3],
                   "start_time": r[4], "end_time": r[5], "enabled": r[6],
                   "person_ids": list(r[7]) if r[7] else []} for r in sched_rows]
    except Exception:
        scheds = []
    return _person_row_to_dict(row, devs, scheds)


@router.patch("/persons/{person_id}")
def update_person(person_id: str, payload: PersonUpdate, db: Session = Depends(get_db)):
    existing = db.execute(text("SELECT id FROM persons WHERE id = :id"), {"id": person_id}).fetchone()
    if not existing:
        raise HTTPException(404, "Person not found")
    updates: dict = {"updated_at": "NOW()"}
    if payload.name        is not None: updates["name"]        = payload.name.strip()
    if payload.primary_mac is not None: updates["primary_mac"] = payload.primary_mac or None
    if payload.photo       is not None: updates["photo"]       = payload.photo or None
    if payload.notes       is not None: updates["notes"]       = payload.notes or None
    set_parts = []
    params: dict = {"id": person_id}
    for k, v in updates.items():
        if k == "updated_at":
            set_parts.append("updated_at = NOW()")
        else:
            set_parts.append(f"{k} = :{k}")
            params[k] = v
    db.execute(text(f"UPDATE persons SET {', '.join(set_parts)} WHERE id = :id"), params)
    db.commit()
    return get_person(person_id, db)


@router.delete("/persons/{person_id}", status_code=204)
def delete_person(person_id: str, db: Session = Depends(get_db)):
    # Unassign all devices belonging to this person
    db.execute(text("UPDATE devices SET person_id = NULL WHERE person_id = :id"), {"id": person_id})
    db.execute(text("DELETE FROM persons WHERE id = :id"), {"id": person_id})
    db.commit()


@router.post("/persons/{person_id}/devices", status_code=201)
def add_person_device(person_id: str, payload: PersonDeviceAdd, db: Session = Depends(get_db)):
    mac = payload.mac_address.lower()
    existing_person = db.execute(text("SELECT id FROM persons WHERE id = :id"), {"id": person_id}).fetchone()
    if not existing_person:
        raise HTTPException(404, "Person not found")
    existing_device = db.execute(text("SELECT mac_address FROM devices WHERE mac_address = :mac"), {"mac": mac}).fetchone()
    if not existing_device:
        raise HTTPException(404, "Device not found")
    db.execute(text(
        "INSERT INTO person_devices (person_id, mac_address) VALUES (:pid, :mac) ON CONFLICT DO NOTHING"
    ), {"pid": person_id, "mac": mac})
    # Update devices.person_id for quick lookup
    db.execute(text("UPDATE devices SET person_id = :pid WHERE mac_address = :mac"), {"pid": person_id, "mac": mac})
    if payload.set_primary:
        db.execute(text("UPDATE persons SET primary_mac = :mac, updated_at = NOW() WHERE id = :pid"), {"mac": mac, "pid": person_id})
    db.commit()
    return get_person(person_id, db)


@router.delete("/persons/{person_id}/devices/{mac}", status_code=204)
def remove_person_device(person_id: str, mac: str, db: Session = Depends(get_db)):
    mac = mac.lower()
    db.execute(text(
        "DELETE FROM person_devices WHERE person_id = :pid AND mac_address = :mac"
    ), {"pid": person_id, "mac": mac})
    db.execute(text(
        "UPDATE devices SET person_id = NULL WHERE mac_address = :mac AND person_id = :pid"
    ), {"mac": mac, "pid": person_id})
    # If this was the primary device, clear it
    db.execute(text(
        "UPDATE persons SET primary_mac = NULL, updated_at = NOW() WHERE id = :pid AND primary_mac = :mac"
    ), {"pid": person_id, "mac": mac})
    db.commit()


@router.post("/persons/{person_id}/block")
async def block_person(person_id: str, payload: PersonBlockRequest = PersonBlockRequest(), db: Session = Depends(get_db)):
    from routes.devices import _execute_block
    # Fetch person name for notification
    prow = db.execute(text("SELECT name FROM persons WHERE id = :pid"), {"pid": person_id}).fetchone()
    person_name = prow[0] if prow else "Person"
    rows = db.execute(text(
        "SELECT d.mac_address, d.ip_address FROM person_devices pd "
        "JOIN devices d ON d.mac_address = pd.mac_address WHERE pd.person_id = :pid"
    ), {"pid": person_id}).fetchall()
    if not rows:
        raise HTTPException(404, "Person not found or has no devices")
    for r in rows:
        mac, ip = r[0], r[1]
        d = db.get(Device, mac)
        if d and not d.is_blocked:
            await _execute_block(mac, ip, db, "block")
            d.is_blocked = True
            _add_event(db, mac, "blocked", {"ip": ip, "reason": "person_block"})
    db.commit()
    asyncio.ensure_future(_notification_dispatch(
        "person.blocked", "Person Blocked",
        f"{person_name}'s devices have been blocked"
    ))
    # Cancel any existing timed block and start a new one if duration given
    existing = state._person_timed_blocks.pop(person_id, None)
    if existing and not existing.done():
        existing.cancel()
    if payload.duration_minutes:
        macs = [r[0] for r in rows]
        async def _auto_unblock(pid: str, mac_list: list, delay_s: int, pn: str):
            from routes.devices import _execute_block
            await asyncio.sleep(delay_s)
            _db = SessionLocal()
            try:
                for mac in mac_list:
                    dd = _db.get(Device, mac)
                    if dd and dd.is_blocked:
                        await _execute_block(mac, dd.ip_address, _db, "unblock")
                        dd.is_blocked = False
                        _add_event(_db, mac, "unblocked", {"ip": dd.ip_address, "reason": "person_timed_unblock"})
                _db.commit()
            finally:
                _db.close()
            state._person_timed_blocks.pop(pid, None)
            asyncio.ensure_future(_notification_dispatch(
                "person.unblocked", "Person Unblocked",
                f"{pn}'s devices have been automatically unblocked"
            ))
        state._person_timed_blocks[person_id] = asyncio.ensure_future(
            _auto_unblock(person_id, macs, payload.duration_minutes * 60, person_name)
        )
    return {"ok": True, "macs": [r[0] for r in rows], "duration_minutes": payload.duration_minutes}


@router.post("/persons/{person_id}/unblock")
async def unblock_person(person_id: str, db: Session = Depends(get_db)):
    from routes.devices import _execute_block
    prow = db.execute(text("SELECT name FROM persons WHERE id = :pid"), {"pid": person_id}).fetchone()
    person_name = prow[0] if prow else "Person"
    existing = state._person_timed_blocks.pop(person_id, None)
    if existing and not existing.done():
        existing.cancel()
    rows = db.execute(text(
        "SELECT d.mac_address, d.ip_address FROM person_devices pd "
        "JOIN devices d ON d.mac_address = pd.mac_address WHERE pd.person_id = :pid"
    ), {"pid": person_id}).fetchall()
    for r in rows:
        mac, ip = r[0], r[1]
        d = db.get(Device, mac)
        if d and d.is_blocked:
            await _execute_block(mac, ip, db, "unblock")
            d.is_blocked = False
            _add_event(db, mac, "unblocked", {"ip": ip, "reason": "person_unblock"})
    db.commit()
    asyncio.ensure_future(_notification_dispatch(
        "person.unblocked", "Person Unblocked",
        f"{person_name}'s devices have been unblocked"
    ))
    return {"ok": True, "macs": [r[0] for r in rows]}
