import asyncio
import hashlib
import json
from datetime import datetime, timezone

import httpx
from sqlalchemy import or_
from sqlalchemy.orm import Session

from database import SessionLocal
from models import Device, Setting, VulnReport
from probe_client import _probe_client
from config import PROBE_URL


_last_scheduled_vuln_scan: datetime | None = datetime.now(timezone.utc)
_last_vuln_scan_day: int | None = None


def _save_vuln_result(mac: str, ip: str, data: dict, scripts: str):
    from device_utils import _add_event
    db2 = SessionLocal()
    try:
        dev = db2.get(Device, mac)
        if not dev:
            return
        report = VulnReport(
            mac_address = mac,
            ip_address  = ip,
            duration_s  = data.get("duration_s"),
            severity    = data.get("severity", "clean"),
            vuln_count  = data.get("vuln_count", 0),
            findings    = data.get("findings"),
            raw_output  = data.get("raw_output"),
            scan_args   = scripts or None,
        )
        db2.add(report)
        dev.vuln_last_scanned = datetime.now(timezone.utc)
        dev.vuln_severity     = data.get("severity", "clean")
        db2.commit()
        _add_event(db2, mac, "vuln_scan_complete", {
            "severity":   data.get("severity"),
            "vuln_count": data.get("vuln_count", 0),
        })
        db2.commit()
    except Exception as exc:
        db2.rollback()
        print(f"[vuln] Save error {mac}: {exc}", flush=True)
    finally:
        db2.close()


async def _run_single_vuln_scan(mac: str, ip: str, scripts: str):
    probe_url = f"{PROBE_URL}/stream/vuln-scan/{ip}"
    params    = {"templates": scripts} if scripts else {}
    try:
        async with _probe_client(timeout=None) as client:
            async with client.stream("GET", probe_url, params=params) as resp:
                if resp.status_code != 200:
                    print(f"[scheduler] Vuln scan {ip} HTTP {resp.status_code}", flush=True)
                    return
                async for raw_line in resp.aiter_lines():
                    if raw_line.startswith("data: RESULT:"):
                        payload_str = raw_line[len("data: RESULT:"):]
                        try:
                            data = json.loads(payload_str)
                            _save_vuln_result(mac, ip, data, scripts)
                            print(f"[scheduler] Vuln scan done: {ip} ({mac}) severity={data.get('severity')}", flush=True)
                        except Exception as exc:
                            print(f"[scheduler] Parse error {mac}: {exc}", flush=True)
                        return
    except httpx.ConnectError:
        print(f"[scheduler] Cannot reach probe for {ip}", flush=True)
    except Exception as exc:
        print(f"[scheduler] Scan error {ip}: {exc}", flush=True)


def _scan_grouped_members_enabled(db: Session) -> bool:
    s = db.get(Setting, "scan_grouped_members")
    return bool(s and (s.value or "").strip().lower() in ("true", "1", "yes"))


def _exclude_grouped_secondaries(q, db: Session):
    if _scan_grouped_members_enabled(db):
        return q
    return q.filter(or_(Device.group_id == None, Device.group_primary == True))


async def _run_scheduled_vuln_scans():
    db = SessionLocal()
    try:
        settings_s = db.get(Setting, "vuln_scan_templates")
        scripts    = (settings_s.value or "").strip() if settings_s else ""
        targets_s  = db.get(Setting, "vuln_scan_targets")
        targets    = targets_s.value if targets_s else "important"
        q = db.query(Device).filter(Device.is_online == True, Device.ip_address != None, Device.is_ignored == False)
        if targets == "important":
            q = q.filter(Device.is_important == True)
        q = _exclude_grouped_secondaries(q, db)
        devices = [(d.mac_address, d.ip_address) for d in q.all()]
    finally:
        db.close()

    print(f"[scheduler] Starting scheduled vuln scan: {len(devices)} device(s)", flush=True)
    for mac, ip in devices:
        await _run_single_vuln_scan(mac, ip, scripts)
        await asyncio.sleep(10)


async def _run_scheduled_vuln_scans_for_day(day_of_week: int):
    db = SessionLocal()
    try:
        settings_s = db.get(Setting, "vuln_scan_templates")
        scripts    = (settings_s.value or "").strip() if settings_s else ""
        targets_s  = db.get(Setting, "vuln_scan_targets")
        targets    = targets_s.value if targets_s else "important"
        q = db.query(Device).filter(Device.is_online == True, Device.ip_address != None, Device.is_ignored == False)
        if targets == "important":
            q = q.filter(Device.is_important == True)
        q = _exclude_grouped_secondaries(q, db)
        all_devices = [(d.mac_address, d.ip_address) for d in q.all()]
    finally:
        db.close()

    devices = [
        (mac, ip) for mac, ip in all_devices
        if int(hashlib.md5(mac.encode()).hexdigest(), 16) % 7 == day_of_week
    ]
    print(f"[scheduler] Weekly scan day {day_of_week}: {len(devices)}/{len(all_devices)} device(s)", flush=True)
    for mac, ip in devices:
        await _run_single_vuln_scan(mac, ip, scripts)
        await asyncio.sleep(10)


async def _run_all_vuln_scans():
    """Manual 'scan all' — ignores the vuln_scan_targets setting and scans every eligible device."""
    db = SessionLocal()
    try:
        settings_s = db.get(Setting, "vuln_scan_templates")
        scripts    = (settings_s.value or "").strip() if settings_s else ""
        q = db.query(Device).filter(Device.is_online == True,
                                    Device.ip_address != None,
                                    Device.is_ignored == False)
        q = _exclude_grouped_secondaries(q, db)
        devices = [(d.mac_address, d.ip_address) for d in q.all()]
    finally:
        db.close()

    print(f"[scan-all] Starting manual vuln scan: {len(devices)} device(s)", flush=True)
    for mac, ip in devices:
        await _run_single_vuln_scan(mac, ip, scripts)
        await asyncio.sleep(10)


async def _scheduled_vuln_scan_loop():
    global _last_scheduled_vuln_scan, _last_vuln_scan_day
    await asyncio.sleep(30)
    while True:
        try:
            db = SessionLocal()
            try:
                sched_s  = db.get(Setting, "vuln_scan_schedule")
                schedule = sched_s.value if sched_s else "disabled"
            finally:
                db.close()

            if schedule == "weekly":
                today = datetime.now(timezone.utc).weekday()
                if _last_vuln_scan_day is None:
                    _last_vuln_scan_day = today
                elif _last_vuln_scan_day != today:
                    await _run_scheduled_vuln_scans_for_day(today)
                    _last_vuln_scan_day = today
            elif schedule != "disabled":
                intervals = {"6h": 21600, "12h": 43200, "24h": 86400}
                interval  = intervals.get(schedule, 86400)
                now       = datetime.now(timezone.utc)
                if _last_scheduled_vuln_scan is None or (now - _last_scheduled_vuln_scan).total_seconds() >= interval:
                    await _run_scheduled_vuln_scans()
                    _last_scheduled_vuln_scan = now
        except Exception as exc:
            print(f"[scheduler] Loop error: {exc}", flush=True)
        await asyncio.sleep(900)
