import asyncio
from sqlalchemy import text

import state
from database import SessionLocal


def _sse_publish(event: str, data: dict | None = None) -> None:
    """
    Broadcast an SSE message to every connected client.  Thread-safe: callable
    from sync endpoints (threadpool) as well as the event loop.
    """
    if not state._sse_clients or state._main_loop is None or state._main_loop.is_closed():
        return
    payload = {"event": event, "data": data or {}}

    def _fan_out():
        for q in list(state._sse_clients):
            try:
                q.put_nowait(payload)
            except Exception:
                pass

    try:
        state._main_loop.call_soon_threadsafe(_fan_out)
    except RuntimeError:
        pass


async def _sse_event_watcher() -> None:
    """
    Background loop that turns new device_events rows into SSE broadcasts.
    Covers everything the probe writes without each client polling the API.
    """
    await asyncio.sleep(5)  # startup grace
    db = SessionLocal()
    try:
        row = db.execute(text("SELECT COALESCE(MAX(id), 0) FROM device_events")).scalar()
        state._last_sse_event_id = int(row or 0)
    except Exception:
        state._last_sse_event_id = 0
    finally:
        db.close()

    while True:
        try:
            if state._sse_clients:
                db = SessionLocal()
                try:
                    rows = db.execute(text("""
                        SELECT id, mac_address, type
                        FROM device_events
                        WHERE id > :last_id
                        ORDER BY id ASC
                        LIMIT 200
                    """), {"last_id": state._last_sse_event_id}).fetchall()
                finally:
                    db.close()
                if rows:
                    types = set()
                    for eid, mac, etype in rows:
                        state._last_sse_event_id = max(state._last_sse_event_id, int(eid))
                        types.add(etype)
                    _sse_publish("devices", {"types": sorted(types)})
                    if types & {"online", "offline", "joined", "interface_joined",
                                "blocked", "unblocked", "ip_change"}:
                        _sse_publish("persons", {"types": sorted(types)})
        except Exception:
            pass
        await asyncio.sleep(2)
