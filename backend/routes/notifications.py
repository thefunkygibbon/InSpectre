from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
import asyncio, json
from database import get_db
from auth_utils import get_current_user
from models import Setting
from schemas import ChannelCreate, ProfileCreate
from notifications_core import (
    NOTIFICATION_EVENT_DEFS,
    _notification_dispatch,
    _build_apprise_url,
    _ha_build_url,
    _notify_home_assistant,
)
import state
from ha_mqtt import _ha_startup_connect

router = APIRouter()


@router.get("/notifications/events")
def list_notification_events():
    categories: dict = {}
    for event_type, label, category, desc in NOTIFICATION_EVENT_DEFS:
        categories.setdefault(category, []).append(
            {"type": event_type, "label": label, "description": desc}
        )
    return [{"category": cat, "events": evts} for cat, evts in categories.items()]


@router.get("/ha-mqtt/status")
def ha_mqtt_status():
    return {"connected": state._ha_mqtt.connected}


@router.post("/ha-mqtt/reconnect")
def ha_mqtt_reconnect(db: Session = Depends(get_db)):
    try:
        _ha_startup_connect(db)
        return {"connected": state._ha_mqtt.connected}
    except Exception as exc:
        raise HTTPException(500, f"HA MQTT reconnect failed: {exc}")


@router.post("/ha-mqtt/disconnect")
def ha_mqtt_disconnect():
    state._ha_mqtt.disconnect()
    return {"connected": False}


@router.get("/notifications/channels")
def list_channels(db: Session = Depends(get_db)):
    rows = db.execute(text("SELECT * FROM notification_channels ORDER BY created_at")).fetchall()
    result = []
    for r in rows:
        result.append({
            "id": r.id, "name": r.name, "service": r.service,
            "config": r.config if isinstance(r.config, dict) else {},
            "enabled": r.enabled,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        })
    return result


@router.post("/notifications/channels", status_code=201)
def create_channel(payload: ChannelCreate, db: Session = Depends(get_db)):
    if payload.service == "home_assistant":
        try:
            _ha_build_url(payload.config)
        except ValueError as e:
            raise HTTPException(400, str(e))
    elif payload.service not in ("toast", "browser"):
        if not _build_apprise_url(payload.service, payload.config):
            raise HTTPException(400, "Invalid channel configuration — could not build a notification URL")
    result = db.execute(text("""
        INSERT INTO notification_channels (name, service, config, enabled)
        VALUES (:n, :s, :c, :e) RETURNING id, name, service, config, enabled, created_at
    """), {"n": payload.name, "s": payload.service,
           "c": json.dumps(payload.config), "e": payload.enabled})
    db.commit()
    row = db.execute(text("SELECT * FROM notification_channels WHERE id = :id"),
                     {"id": result.fetchone()[0]}).fetchone()
    return {
        "id": row.id, "name": row.name, "service": row.service,
        "config": row.config if isinstance(row.config, dict) else {},
        "enabled": row.enabled,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.put("/notifications/channels/{channel_id}")
def update_channel(channel_id: int, payload: ChannelCreate, db: Session = Depends(get_db)):
    row = db.execute(text("SELECT id FROM notification_channels WHERE id = :id"),
                     {"id": channel_id}).fetchone()
    if not row:
        raise HTTPException(404, "Channel not found")
    if payload.service == "home_assistant":
        try:
            _ha_build_url(payload.config)
        except ValueError as e:
            raise HTTPException(400, str(e))
    elif payload.service not in ("toast", "browser"):
        if not _build_apprise_url(payload.service, payload.config):
            raise HTTPException(400, "Invalid channel configuration")
    db.execute(text("""
        UPDATE notification_channels SET name=:n, service=:s, config=:c, enabled=:e
        WHERE id=:id
    """), {"n": payload.name, "s": payload.service,
           "c": json.dumps(payload.config), "e": payload.enabled, "id": channel_id})
    db.commit()
    row = db.execute(text("SELECT * FROM notification_channels WHERE id = :id"),
                     {"id": channel_id}).fetchone()
    return {
        "id": row.id, "name": row.name, "service": row.service,
        "config": row.config if isinstance(row.config, dict) else {},
        "enabled": row.enabled,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.delete("/notifications/channels/{channel_id}")
def delete_channel(channel_id: int, db: Session = Depends(get_db)):
    db.execute(text("DELETE FROM notification_channels WHERE id = :id"), {"id": channel_id})
    db.commit()
    return {"deleted": True}


@router.post("/notifications/channels/{channel_id}/test")
async def test_channel(channel_id: int, db: Session = Depends(get_db)):
    row = db.execute(text("SELECT service, config FROM notification_channels WHERE id = :id"),
                     {"id": channel_id}).fetchone()
    if not row:
        raise HTTPException(404, "Channel not found")
    svc, cfg = row
    if svc in ("toast", "browser"):
        return {"sent": True}
    config = cfg if isinstance(cfg, dict) else (json.loads(cfg) if isinstance(cfg, str) else {})
    if svc == "home_assistant":
        try:
            await _notify_home_assistant(config, "InSpectre Test", "This is a test notification from InSpectre.")
            return {"sent": True}
        except Exception as exc:
            print(f"[notify-test] home_assistant error: {type(exc).__name__}: {exc}", flush=True)
            raise HTTPException(502, f"Home Assistant notification failed: {exc}")
    url = _build_apprise_url(svc, config)
    if not url:
        present = list(config.keys())
        raise HTTPException(400, f"Cannot build notification URL for '{svc}' — config keys: {present}. Re-save the channel.")
    try:
        import apprise as _apprise
        import logging as _logging
        _al = _logging.getLogger("apprise")
        _al.setLevel(_logging.DEBUG)
        _buf: list = []
        _h = _logging.StreamHandler(type("_S", (), {"write": lambda s, m: _buf.append(m), "flush": lambda s: None})())
        _h.setLevel(_logging.WARNING)
        _al.addHandler(_h)
        a = _apprise.Apprise()
        added = a.add(url)
        if not added:
            raise HTTPException(400, f"Apprise did not recognise the '{svc}' URL — check credentials or missing dependency")
        ok = await asyncio.to_thread(a.notify,
                                     title="InSpectre Test",
                                     body="This is a test notification from InSpectre.")
        _al.removeHandler(_h)
        if not ok:
            detail = " | ".join(_buf[-3:]) if _buf else "check credentials and connectivity"
            raise HTTPException(502, f"Apprise could not send to {svc}: {detail}")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, f"Notification error ({svc}): {exc}")
    return {"sent": True}


@router.get("/notifications/profiles")
def list_profiles(db: Session = Depends(get_db)):
    profiles = db.execute(text("SELECT * FROM notification_profiles ORDER BY created_at")).fetchall()
    result = []
    for p in profiles:
        ch_ids = db.execute(text(
            "SELECT channel_id FROM notification_profile_channels WHERE profile_id = :pid"
        ), {"pid": p.id}).scalars().all()
        result.append({
            "id": p.id, "name": p.name,
            "events": p.events if isinstance(p.events, dict) else {},
            "channel_ids": list(ch_ids),
            "created_at": p.created_at.isoformat() if p.created_at else None,
        })
    return result


@router.post("/notifications/profiles", status_code=201)
def create_profile(payload: ProfileCreate, db: Session = Depends(get_db)):
    result = db.execute(text("""
        INSERT INTO notification_profiles (name, events)
        VALUES (:n, :e) RETURNING id
    """), {"n": payload.name, "e": json.dumps(payload.events)})
    profile_id = result.scalar()
    for cid in payload.channel_ids:
        db.execute(text("""
            INSERT INTO notification_profile_channels (profile_id, channel_id)
            VALUES (:p, :c) ON CONFLICT DO NOTHING
        """), {"p": profile_id, "c": cid})
    db.commit()
    return {"id": profile_id, "name": payload.name, "events": payload.events,
            "channel_ids": payload.channel_ids}


@router.put("/notifications/profiles/{profile_id}")
def update_profile(profile_id: int, payload: ProfileCreate, db: Session = Depends(get_db)):
    row = db.execute(text("SELECT id FROM notification_profiles WHERE id = :id"),
                     {"id": profile_id}).fetchone()
    if not row:
        raise HTTPException(404, "Profile not found")
    db.execute(text("""
        UPDATE notification_profiles SET name=:n, events=:e WHERE id=:id
    """), {"n": payload.name, "e": json.dumps(payload.events), "id": profile_id})
    db.execute(text("DELETE FROM notification_profile_channels WHERE profile_id=:pid"),
               {"pid": profile_id})
    for cid in payload.channel_ids:
        db.execute(text("""
            INSERT INTO notification_profile_channels (profile_id, channel_id)
            VALUES (:p, :c) ON CONFLICT DO NOTHING
        """), {"p": profile_id, "c": cid})
    db.commit()
    return {"id": profile_id, "name": payload.name, "events": payload.events,
            "channel_ids": payload.channel_ids}


@router.delete("/notifications/profiles/{profile_id}")
def delete_profile(profile_id: int, db: Session = Depends(get_db)):
    db.execute(text("DELETE FROM notification_profiles WHERE id = :id"), {"id": profile_id})
    db.commit()
    return {"deleted": True}


@router.get("/notifications/pending")
def get_pending_notifications():
    """Return and clear the queue of pending browser notifications."""
    items = list(state._pending_browser_notifications)
    state._pending_browser_notifications.clear()
    return {"notifications": items}
