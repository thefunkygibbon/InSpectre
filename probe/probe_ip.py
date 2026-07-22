import json
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert as pg_insert

import probe_config as _cfg
from probe_models import Session, IPHistory


def record_ip(mac: str, ip: str, seen_while_online: bool = False) -> bool:
    """Upsert ip_history row. Returns True only for a brand-new mac+ip combination."""
    if not _cfg._is_valid_ip(ip):
        return False
    now = datetime.now(timezone.utc)
    session = Session()
    try:
        set_vals: dict = {"last_seen": now}
        if seen_while_online:
            set_vals["seen_while_online"] = True
        stmt = (
            pg_insert(IPHistory)
            .values(mac_address=mac, ip_address=ip, first_seen=now, last_seen=now,
                    seen_while_online=seen_while_online)
            .on_conflict_do_update(
                constraint="uq_ip_history_mac_ip",
                set_=set_vals,
            )
            .returning(IPHistory.first_seen, IPHistory.last_seen)
        )
        result = session.execute(stmt)
        row = result.fetchone()
        session.commit()
        if row:
            delta = abs((row.last_seen - row.first_seen).total_seconds())
            return delta < 2
        return False
    except Exception as e:
        session.rollback()
        print(f"[ip_history] record error {mac}/{ip}: {e}", flush=True)
        return False
    finally:
        session.close()


def _primary_ip_is_stale(mac: str, primary_ip: str) -> bool:
    """Return True when the device's current primary IP hasn't been seen for several cycles.
    Used to decide whether a newly-seen IP should be promoted to primary."""
    if not primary_ip or not _cfg._is_valid_ip(primary_ip):
        return False
    threshold = max(_cfg.SCAN_INTERVAL * 3, 180)
    s = Session()
    try:
        row = s.execute(
            text("SELECT last_seen FROM ip_history WHERE mac_address = :m AND ip_address = :ip"),
            {"m": mac, "ip": primary_ip},
        ).fetchone()
        if not row or not row[0]:
            return False
        age = (datetime.now(timezone.utc) - row[0]).total_seconds()
        return age > threshold
    except Exception:
        return False
    finally:
        s.close()


def _write_event(mac: str, event_type: str, detail: dict) -> None:
    """Write a device_events row. Silently swallows errors."""
    session = Session()
    try:
        session.execute(
            text("""
                INSERT INTO device_events (mac_address, type, detail, created_at)
                VALUES (:mac, :type, cast(:detail AS jsonb), NOW())
            """),
            {"mac": mac, "type": event_type, "detail": json.dumps(detail)},
        )
        session.commit()
    except Exception as e:
        session.rollback()
        print(f"[events] write error {mac}/{event_type}: {e}", flush=True)
    finally:
        session.close()
