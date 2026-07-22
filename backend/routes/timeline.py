from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime, timezone, timedelta
from database import get_db
from auth_utils import get_current_user
from models import Device
from device_utils import _to_dict

router = APIRouter()


@router.get("/timeline")
def get_timeline(days: int = Query(7, ge=1, le=365), db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(days=days)

    # Fetch all online/offline/joined events for all devices in the window
    # plus the most recent event before the window to know starting state
    rows = db.execute(text("""
        SELECT de.mac_address, de.type, de.created_at,
               COALESCE(d.custom_name, d.hostname, d.ip_address, de.mac_address) AS display_name,
               d.ip_address, d.is_online
        FROM device_events de
        JOIN devices d ON d.mac_address = de.mac_address
        WHERE de.type IN ('online', 'offline', 'joined')
          AND de.created_at >= :window_start
          AND d.is_ignored = FALSE
        ORDER BY de.mac_address, de.created_at ASC
    """), {"window_start": window_start}).fetchall()

    # Also get the last event before window for each device (to know initial state)
    prior_rows = db.execute(text("""
        SELECT DISTINCT ON (de.mac_address)
               de.mac_address, de.type, de.created_at
        FROM device_events de
        JOIN devices d ON d.mac_address = de.mac_address
        WHERE de.type IN ('online', 'offline', 'joined')
          AND de.created_at < :window_start
          AND d.is_ignored = FALSE
        ORDER BY de.mac_address, de.created_at DESC
    """), {"window_start": window_start}).fetchall()

    # Get all relevant devices (those with events in window or active devices)
    device_info = db.execute(text("""
        SELECT mac_address,
               COALESCE(custom_name, hostname, ip_address, mac_address) AS display_name,
               ip_address, is_online
        FROM devices WHERE is_ignored = FALSE
        ORDER BY display_name
    """)).fetchall()

    prior_state: dict = {}
    for r in prior_rows:
        mac, etype, ts = r[0], r[1], r[2]
        prior_state[mac] = "online" if etype in ("online", "joined") else "offline"

    # Group events by device
    events_by_mac: dict = {}
    for r in rows:
        mac = r[0]
        events_by_mac.setdefault(mac, []).append({
            "type": r[1], "ts": r[2]
        })

    # Only include devices that have events in window or are currently known
    seen_macs = set(events_by_mac.keys()) | set(prior_state.keys())
    device_map = {r[0]: {"name": r[1], "ip": r[2], "is_online": r[3]} for r in device_info}

    result_devices = []
    for mac, info in device_map.items():
        if mac not in seen_macs:
            continue

        evts = events_by_mac.get(mac, [])
        initial = prior_state.get(mac, "unknown")

        # Build segments
        segments = []
        seg_start = window_start
        seg_status = initial

        for ev in evts:
            seg_end = ev["ts"]
            if seg_end > seg_start:
                segments.append({
                    "from": seg_start.isoformat(),
                    "to":   seg_end.isoformat(),
                    "status": seg_status,
                })
            seg_start = seg_end
            seg_status = "online" if ev["type"] in ("online", "joined") else "offline"

        # Final segment up to now
        segments.append({
            "from": seg_start.isoformat(),
            "to":   now.isoformat(),
            "status": seg_status,
        })

        result_devices.append({
            "mac":        mac,
            "name":       info["name"],
            "ip":         info["ip"],
            "is_online":  info["is_online"],
            "segments":   segments,
        })

    # Sort: online first, then by name
    result_devices.sort(key=lambda d: (0 if d["is_online"] else 1, d["name"] or ""))

    return {
        "window_start": window_start.isoformat(),
        "window_end":   now.isoformat(),
        "days":         days,
        "devices":      result_devices,
    }


@router.get("/devices/{mac}/timeline")
def get_device_timeline(mac: str, days: int = Query(7, ge=1, le=365), db: Session = Depends(get_db)):
    now          = datetime.now(timezone.utc)
    window_start = now - timedelta(days=days)

    rows = db.execute(text("""
        SELECT type, created_at FROM device_events
        WHERE mac_address = :mac
          AND type IN ('online', 'offline', 'joined')
          AND created_at >= :window_start
        ORDER BY created_at ASC
    """), {"mac": mac, "window_start": window_start}).fetchall()

    prior = db.execute(text("""
        SELECT type FROM device_events
        WHERE mac_address = :mac
          AND type IN ('online', 'offline', 'joined')
          AND created_at < :window_start
        ORDER BY created_at DESC LIMIT 1
    """), {"mac": mac, "window_start": window_start}).fetchone()

    initial = "online" if (prior and prior[0] in ("online", "joined")) else "unknown" if not prior else "offline"
    segments = []
    seg_start  = window_start
    seg_status = initial

    for r in rows:
        etype, ts = r[0], r[1]
        new_status = "online" if etype in ("online", "joined") else "offline"
        if new_status != seg_status:
            segments.append({"from": seg_start.isoformat(), "to": ts.isoformat(), "status": seg_status})
            seg_start  = ts
            seg_status = new_status

    segments.append({"from": seg_start.isoformat(), "to": now.isoformat(), "status": seg_status})

    return {
        "mac":          mac,
        "window_start": window_start.isoformat(),
        "window_end":   now.isoformat(),
        "days":         days,
        "segments":     segments,
    }
