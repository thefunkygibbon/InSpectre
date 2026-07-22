from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Request, Form, Query
from fastapi.responses import StreamingResponse, Response
from sqlalchemy import text
from sqlalchemy.orm import Session
from typing import Optional, List
import asyncio, json, csv, io, os, zipfile, tempfile, shutil
from datetime import datetime, timezone
from database import get_db, SessionLocal
from auth_utils import get_current_user
from models import Device, Setting, FingerprintEntry, VulnReport
from device_utils import _to_dict, _infer_device_type, _infer_vendor, _identity_score
from fingerprint_utils import _oui, _match_fingerprints
from database import _migrate

router = APIRouter()


@router.get("/export/devices")
def export_devices_csv(db: Session = Depends(get_db)):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["mac_address", "ip_address", "hostname", "vendor", "vendor_override",
                     "device_type_override", "custom_name", "is_online", "is_important",
                     "location", "tags", "notes", "first_seen", "last_seen",
                     "vuln_severity", "vuln_last_scanned"])
    for d in db.query(Device).all():
        writer.writerow([d.mac_address, d.ip_address, d.hostname, d.vendor,
                         getattr(d, 'vendor_override', None), getattr(d, 'device_type_override', None),
                         d.custom_name, d.is_online, getattr(d, 'is_important', False),
                         getattr(d, 'location', None), getattr(d, 'tags', None),
                         getattr(d, 'notes', None), d.first_seen, d.last_seen,
                         getattr(d, 'vuln_severity', None), getattr(d, 'vuln_last_scanned', None)])
    buf.seek(0)
    return StreamingResponse(buf, media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=inspectre-devices.csv"})


@router.get("/reports/inventory.csv")
def export_inventory(db: Session = Depends(get_db)):
    devices = db.query(Device).order_by(Device.last_seen.desc()).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["MAC", "IP", "Hostname", "Custom Name", "Vendor", "Device Type",
                "Online", "First Seen", "Last Seen", "Deep Scanned",
                "Important", "Tags", "Location", "Notes", "Identity Score",
                "Vuln Severity", "Vuln Last Scanned"])
    for d in devices:
        score = _identity_score(d)["score"]
        dtype = getattr(d, 'device_type_override', None) or _infer_device_type(d) or ""
        w.writerow([d.mac_address, d.ip_address or "", d.hostname or "",
                    d.custom_name or "", d.vendor or "", dtype,
                    d.is_online, d.first_seen, d.last_seen, d.deep_scanned,
                    bool(getattr(d, 'is_important', False)),
                    getattr(d, 'tags', None) or "", getattr(d, 'location', None) or "",
                    getattr(d, 'notes', None) or "", score,
                    getattr(d, 'vuln_severity', None) or "",
                    getattr(d, 'vuln_last_scanned', None) or ""])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=inspectre-inventory.csv"})


@router.get("/reports/events.csv")
def export_events_csv(limit: int = Query(1000, ge=1, le=10000), db: Session = Depends(get_db)):
    rows = db.execute(text("""
        SELECT de.created_at, de.type, de.mac_address,
               COALESCE(d.custom_name, d.hostname, d.ip_address, de.mac_address),
               d.ip_address, d.vendor, de.detail::text
        FROM device_events de
        JOIN devices d ON d.mac_address = de.mac_address
        ORDER BY de.created_at DESC LIMIT :limit
    """), {"limit": limit}).fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Timestamp", "Event", "MAC", "Device Name", "IP", "Vendor", "Detail"])
    for r in rows:
        w.writerow([r[0], r[1], r[2], r[3], r[4], r[5], r[6]])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=inspectre-events.csv"})


@router.get("/export/fingerprints")
def export_fingerprints_json(db: Session = Depends(get_db)):
    fps = db.query(FingerprintEntry).all()
    data = [
        {"oui_prefix": fp.oui_prefix, "hostname_pattern": fp.hostname_pattern,
         "open_ports": fp.open_ports, "device_type": fp.device_type,
         "vendor_name": fp.vendor_name, "confidence_score": fp.confidence_score,
         "hit_count": fp.hit_count, "source": fp.source}
        for fp in fps
    ]
    return Response(content=json.dumps(data, indent=2), media_type="application/json",
                    headers={"Content-Disposition": "attachment; filename=inspectre-fingerprints.json"})


@router.post("/import/fingerprints")
async def import_fingerprints_json(file: UploadFile = File(...), db: Session = Depends(get_db)):
    content = await file.read()
    try:
        entries = json.loads(content)
        if not isinstance(entries, list):
            raise ValueError("Expected a JSON array")
    except Exception as exc:
        raise HTTPException(400, f"Invalid JSON: {exc}")
    inserted = merged = 0
    for entry in entries:
        device_type = entry.get("device_type", "").strip()
        if not device_type: continue
        oui_prefix       = (entry.get("oui_prefix") or "").strip().lower() or None
        vendor_name      = (entry.get("vendor_name") or "").strip() or None
        open_ports       = entry.get("open_ports") or None
        hostname_pattern = (entry.get("hostname_pattern") or "").strip() or None
        confidence       = float(entry.get("confidence_score", 1.0))
        hit_count        = int(entry.get("hit_count", 1))
        source           = entry.get("source", "community")
        existing = None
        if oui_prefix:
            existing = (
                db.query(FingerprintEntry)
                .filter(FingerprintEntry.oui_prefix == oui_prefix,
                        FingerprintEntry.device_type == device_type)
                .first()
            )
        if existing:
            existing.hit_count        += hit_count
            existing.confidence_score  = max(existing.confidence_score, confidence)
            if vendor_name and not existing.vendor_name:
                existing.vendor_name = vendor_name
            merged += 1
        else:
            db.add(FingerprintEntry(
                oui_prefix=oui_prefix, hostname_pattern=hostname_pattern,
                open_ports=open_ports, device_type=device_type,
                vendor_name=vendor_name, confidence_score=confidence,
                hit_count=hit_count,
                source=source if source in ('manual', 'community', 'auto') else 'community',
            ))
            inserted += 1
    db.commit()
    all_fps = db.query(FingerprintEntry).all()
    devices = db.query(Device).filter(
        (Device.device_type_override == None) | (Device.device_type_override == "")
    ).all()
    corrected = 0
    for device in devices:
        best = _match_fingerprints(device, all_fps)
        if best:
            device.device_type_override = best.device_type
            if best.vendor_name and not device.vendor_override:
                device.vendor_override = best.vendor_name
            corrected += 1
            best.hit_count += 1
    db.commit()
    return {"inserted": inserted, "merged": merged, "corrected": corrected}


# ---------------------------------------------------------------------------
# Database backup / restore
# ---------------------------------------------------------------------------
def _encrypt_backup(plaintext: bytes, password: str) -> bytes:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt  = os.urandom(16)
    key   = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000).derive(password.encode())
    nonce = os.urandom(12)
    ct    = AESGCM(key).encrypt(nonce, plaintext, None)  # 16-byte GCM tag appended by library
    return b"IENC1" + salt + nonce + ct

def _decrypt_backup(data: bytes, password: str) -> bytes:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not data.startswith(b"IENC1"):
        raise ValueError("Not an encrypted backup")
    salt  = data[5:21]
    nonce = data[21:33]
    ct    = data[33:]
    key   = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000).derive(password.encode())
    return AESGCM(key).decrypt(nonce, ct, None)  # raises InvalidTag on wrong password


@router.post("/export/backup")
def export_backup(password: str = Form(""), db: Session = Depends(get_db)):
    """Export all user data as a portable JSON backup (version 2)."""

    def _rows(sql, *params):
        return db.execute(text(sql), *params).fetchall()

    # Devices
    devices = [_to_dict(d) for d in db.query(Device).all()]

    # Device events
    events = [
        {"id": r[0], "mac_address": r[1], "type": r[2],
         "detail": r[3], "created_at": r[4].isoformat() if r[4] else None}
        for r in _rows(
            "SELECT id, mac_address, type, detail, created_at "
            "FROM device_events ORDER BY created_at"
        )
    ]

    # Vulnerability reports
    vuln_reports = [
        {"id": r[0], "mac_address": r[1], "ip_address": r[2],
         "scanned_at": r[3].isoformat() if r[3] else None,
         "duration_s": r[4], "severity": r[5], "vuln_count": r[6],
         "findings": r[7], "raw_output": r[8], "scan_args": r[9]}
        for r in _rows(
            "SELECT id, mac_address, ip_address, scanned_at, duration_s, "
            "severity, vuln_count, findings, raw_output, scan_args "
            "FROM vuln_reports ORDER BY scanned_at"
        )
    ]

    # IP history
    ip_history = [
        {"id": r[0], "mac_address": r[1], "ip_address": r[2],
         "first_seen": r[3].isoformat() if r[3] else None,
         "last_seen": r[4].isoformat() if r[4] else None}
        for r in _rows(
            "SELECT id, mac_address, ip_address, first_seen, last_seen FROM ip_history"
        )
    ]

    # Settings
    settings = [{"key": s.key, "value": s.value} for s in db.query(Setting).all()]

    # Fingerprints
    fps = [
        {"oui_prefix": f.oui_prefix, "device_type": f.device_type,
         "vendor_name": f.vendor_name, "open_ports": f.open_ports,
         "hostname_pattern": f.hostname_pattern,
         "confidence_score": f.confidence_score, "source": f.source}
        for f in db.query(FingerprintEntry).all()
    ]

    # Users (password hashes included so credentials survive restore)
    users = [
        {"username": r[0], "password_hash": r[1],
         "is_admin": r[2], "must_change_password": r[3]}
        for r in _rows(
            "SELECT username, password_hash, is_admin, must_change_password FROM users"
        )
    ]

    # Alert suppressions
    suppressions = []
    try:
        suppressions = [
            {"id": r[0], "mac_address": r[1], "event_type": r[2],
             "reason": r[3],
             "expires_at": r[4].isoformat() if r[4] else None,
             "created_at": r[5].isoformat() if r[5] else None}
            for r in _rows(
                "SELECT id, mac_address, event_type, reason, expires_at, created_at "
                "FROM alert_suppressions"
            )
        ]
    except Exception:
        pass

    # Saved views
    saved_views = []
    try:
        saved_views = [
            {"id": r[0], "name": r[1], "description": r[2], "filters": r[3],
             "created_at": r[4].isoformat() if r[4] else None,
             "updated_at": r[5].isoformat() if r[5] else None}
            for r in _rows(
                "SELECT id, name, description, filters, created_at, updated_at "
                "FROM saved_views"
            )
        ]
    except Exception:
        pass

    # Block schedules
    block_schedules = []
    try:
        block_schedules = [
            {"id": r[0], "mac_address": r[1], "label": r[2],
             "days_of_week": r[3], "start_time": r[4], "end_time": r[5],
             "enabled": r[6], "mac_addresses": r[7], "tags": r[8]}
            for r in _rows(
                "SELECT id, mac_address, label, days_of_week, start_time, end_time, "
                "enabled, mac_addresses, tags FROM block_schedules"
            )
        ]
    except Exception:
        pass

    # Speedtest history
    speedtest_results = []
    try:
        speedtest_results = [
            {"id": r[0], "tested_at": r[1].isoformat() if r[1] else None,
             "server": r[2], "ping_ms": r[3], "download_mbps": r[4],
             "upload_mbps": r[5], "raw_output": r[6]}
            for r in _rows(
                "SELECT id, tested_at, server, ping_ms, download_mbps, upload_mbps, raw_output "
                "FROM speedtest_results ORDER BY tested_at"
            )
        ]
    except Exception:
        pass

    payload = {
        "version": 2,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "devices": devices,
        "device_events": events,
        "vuln_reports": vuln_reports,
        "ip_history": ip_history,
        "settings": settings,
        "fingerprints": fps,
        "users": users,
        "alert_suppressions": suppressions,
        "saved_views": saved_views,
        "block_schedules": block_schedules,
        "speedtest_results": speedtest_results,
    }
    raw = json.dumps(payload, indent=2, default=str).encode()
    if password:
        content  = _encrypt_backup(raw, password)
        fname    = "inspectre_backup.ienc"
        mimetype = "application/octet-stream"
    else:
        content  = raw
        fname    = "inspectre_backup.json"
        mimetype = "application/json"
    return Response(
        content=content,
        media_type=mimetype,
        headers={"Content-Disposition": f"attachment; filename={fname}"},
    )


def _do_restore(payload: dict, db: Session) -> dict:
    """Full restore from a v1 or v2 backup payload. Returns stats dict."""
    from datetime import datetime as _dt_cls

    def _dt(val):
        if not val:
            return None
        try:
            return _dt_cls.fromisoformat(val)
        except Exception:
            return None

    def _json(val):
        if val is None:
            return None
        return val if isinstance(val, str) else json.dumps(val)

    stats = {
        "version": payload.get("version", 1),
        "settings": 0, "fingerprints": 0, "devices": 0,
        "device_events": 0, "vuln_reports": 0, "ip_history": 0,
        "users": 0, "alert_suppressions": 0, "saved_views": 0,
        "block_schedules": 0, "speedtest_results": 0,
    }

    # Settings — restore ALL keys without skipping
    for s in payload.get("settings", []):
        key, value = s.get("key"), s.get("value")
        if not key:
            continue
        existing = db.get(Setting, key)
        if existing:
            existing.value = str(value) if value is not None else ""
        else:
            db.add(Setting(key=key, value=str(value) if value is not None else "",
                           description="Restored from backup"))
        stats["settings"] += 1

    # Fingerprints — merge by (oui_prefix, device_type)
    for fp in payload.get("fingerprints", []):
        device_type = (fp.get("device_type") or "").strip()
        if not device_type:
            continue
        oui = (fp.get("oui_prefix") or "").strip().lower() or None
        existing = None
        if oui:
            existing = db.query(FingerprintEntry).filter(
                FingerprintEntry.oui_prefix == oui,
                FingerprintEntry.device_type == device_type,
            ).first()
        if not existing:
            db.add(FingerprintEntry(
                oui_prefix=oui, device_type=device_type,
                vendor_name=fp.get("vendor_name"),
                open_ports=fp.get("open_ports"),
                hostname_pattern=fp.get("hostname_pattern"),
                confidence_score=float(fp.get("confidence_score", 1.0)),
                source=fp.get("source", "backup"), hit_count=1,
            ))
            stats["fingerprints"] += 1

    # Devices — upsert by mac_address (ORM)
    for d in payload.get("devices", []):
        mac = (d.get("mac_address") or "").strip().lower()
        if not mac:
            continue
        fields = dict(
            ip_address=d.get("ip_address"),
            hostname=d.get("hostname"),
            vendor=d.get("vendor"),
            custom_name=d.get("custom_name"),
            device_type_override=d.get("device_type_override"),
            vendor_override=d.get("vendor_override"),
            is_online=bool(d.get("is_online", False)),
            first_seen=_dt(d.get("first_seen")),
            last_seen=_dt(d.get("last_seen")),
            status_changed_at=_dt(d.get("status_changed_at")),
            scan_results=d.get("scan_results"),
            deep_scanned=bool(d.get("deep_scanned", False)),
            miss_count=int(d.get("miss_count") or 0),
            is_important=bool(d.get("is_important", False)),
            notes=d.get("notes"),
            tags=d.get("tags"),
            location=d.get("location"),
            vuln_last_scanned=_dt(d.get("vuln_last_scanned")),
            vuln_severity=d.get("vuln_severity"),
            is_blocked=bool(d.get("is_blocked", False)),
            zone=d.get("zone"),
            is_ignored=bool(d.get("is_ignored", False)),
            suppress_presence_events=bool(d.get("suppress_presence_events", False)),
            deep_scan_last_run=_dt(d.get("deep_scan_last_run")),
            baseline_ports=d.get("baseline_ports"),
            baseline_scan_count=int(d.get("baseline_scan_count") or 0),
            group_id=d.get("group_id"),
            group_primary=bool(d.get("group_primary", False)),
        )
        existing = db.get(Device, mac)
        if existing:
            for k, v in fields.items():
                setattr(existing, k, v)
        else:
            db.add(Device(mac_address=mac, **fields))
        stats["devices"] += 1

    db.flush()  # devices must be visible for FK checks below

    # Device events — insert by id, skip unknown MACs
    for ev in payload.get("device_events", []):
        ev_id = ev.get("id")
        mac = (ev.get("mac_address") or "").strip().lower()
        ev_type = ev.get("type")
        if not mac or not ev_type:
            continue
        sp = db.begin_nested()
        try:
            if ev_id is not None:
                db.execute(text(
                    "INSERT INTO device_events (id, mac_address, type, detail, created_at) "
                    "SELECT :id, :mac, :etype, :detail::jsonb, :ts "
                    "WHERE EXISTS (SELECT 1 FROM devices WHERE mac_address = :mac) "
                    "ON CONFLICT (id) DO NOTHING"
                ), {"id": ev_id, "mac": mac, "etype": ev_type,
                    "detail": _json(ev.get("detail")), "ts": ev.get("created_at")})
            else:
                db.execute(text(
                    "INSERT INTO device_events (mac_address, type, detail, created_at) "
                    "SELECT :mac, :etype, :detail::jsonb, :ts "
                    "WHERE EXISTS (SELECT 1 FROM devices WHERE mac_address = :mac)"
                ), {"mac": mac, "etype": ev_type,
                    "detail": _json(ev.get("detail")), "ts": ev.get("created_at")})
            sp.commit()
            stats["device_events"] += 1
        except Exception:
            sp.rollback()

    # Vuln reports — insert by id, skip unknown MACs
    for vr in payload.get("vuln_reports", []):
        vr_id = vr.get("id")
        mac = (vr.get("mac_address") or "").strip().lower()
        if not mac or vr_id is None:
            continue
        sp = db.begin_nested()
        try:
            db.execute(text(
                "INSERT INTO vuln_reports "
                "(id, mac_address, ip_address, scanned_at, duration_s, severity, "
                " vuln_count, findings, raw_output, scan_args) "
                "SELECT :id, :mac, :ip, :scanned_at, :duration_s, :severity, "
                "       :vuln_count, :findings::jsonb, :raw_output, :scan_args "
                "WHERE EXISTS (SELECT 1 FROM devices WHERE mac_address = :mac) "
                "ON CONFLICT (id) DO NOTHING"
            ), {"id": vr_id, "mac": mac, "ip": vr.get("ip_address"),
                "scanned_at": vr.get("scanned_at"), "duration_s": vr.get("duration_s"),
                "severity": vr.get("severity", "clean"),
                "vuln_count": int(vr.get("vuln_count") or 0),
                "findings": _json(vr.get("findings")),
                "raw_output": vr.get("raw_output"), "scan_args": vr.get("scan_args")})
            sp.commit()
            stats["vuln_reports"] += 1
        except Exception:
            sp.rollback()

    # IP history — insert by id, skip unknown MACs
    for ih in payload.get("ip_history", []):
        ih_id = ih.get("id")
        mac = (ih.get("mac_address") or "").strip().lower()
        ip = ih.get("ip_address")
        if not mac or not ip or ih_id is None:
            continue
        sp = db.begin_nested()
        try:
            db.execute(text(
                "INSERT INTO ip_history (id, mac_address, ip_address, first_seen, last_seen) "
                "SELECT :id, :mac, :ip, :first_seen, :last_seen "
                "WHERE EXISTS (SELECT 1 FROM devices WHERE mac_address = :mac) "
                "ON CONFLICT (id) DO NOTHING"
            ), {"id": ih_id, "mac": mac, "ip": ip,
                "first_seen": ih.get("first_seen"), "last_seen": ih.get("last_seen")})
            sp.commit()
            stats["ip_history"] += 1
        except Exception:
            sp.rollback()

    # Users — upsert by username, restoring password hash
    for u in payload.get("users", []):
        username = (u.get("username") or "").strip()
        password_hash = u.get("password_hash")
        if not username or not password_hash:
            continue
        sp = db.begin_nested()
        try:
            db.execute(text(
                "INSERT INTO users (username, password_hash, is_admin, must_change_password) "
                "VALUES (:u, :h, :admin, :mcp) "
                "ON CONFLICT (username) DO UPDATE "
                "SET password_hash = EXCLUDED.password_hash, "
                "    is_admin = EXCLUDED.is_admin, "
                "    must_change_password = EXCLUDED.must_change_password"
            ), {"u": username, "h": password_hash,
                "admin": bool(u.get("is_admin", False)),
                "mcp": bool(u.get("must_change_password", False))})
            sp.commit()
            stats["users"] += 1
        except Exception:
            sp.rollback()

    # Alert suppressions
    for sup in payload.get("alert_suppressions", []):
        sup_id = sup.get("id")
        event_type = sup.get("event_type")
        if not event_type or sup_id is None:
            continue
        sp = db.begin_nested()
        try:
            db.execute(text(
                "INSERT INTO alert_suppressions "
                "(id, mac_address, event_type, reason, expires_at, created_at) "
                "VALUES (:id, :mac, :event_type, :reason, :expires_at, :created_at) "
                "ON CONFLICT (id) DO NOTHING"
            ), {"id": sup_id,
                "mac": (sup.get("mac_address") or "").strip().lower() or None,
                "event_type": event_type, "reason": sup.get("reason"),
                "expires_at": sup.get("expires_at"), "created_at": sup.get("created_at")})
            sp.commit()
            stats["alert_suppressions"] += 1
        except Exception:
            sp.rollback()

    # Saved views — upsert by name
    for sv in payload.get("saved_views", []):
        sv_name = (sv.get("name") or "").strip()
        if not sv_name:
            continue
        sp = db.begin_nested()
        try:
            db.execute(text(
                "INSERT INTO saved_views (name, description, filters, created_at, updated_at) "
                "VALUES (:name, :desc, :filters::jsonb, :created_at, :updated_at) "
                "ON CONFLICT (name) DO UPDATE "
                "SET description = EXCLUDED.description, filters = EXCLUDED.filters, "
                "    updated_at = EXCLUDED.updated_at"
            ), {"name": sv_name, "desc": sv.get("description"),
                "filters": _json(sv.get("filters") or {}),
                "created_at": sv.get("created_at"), "updated_at": sv.get("updated_at")})
            sp.commit()
            stats["saved_views"] += 1
        except Exception:
            sp.rollback()

    # Block schedules
    for bs in payload.get("block_schedules", []):
        bs_id = bs.get("id")
        if bs_id is None:
            continue
        sp = db.begin_nested()
        try:
            db.execute(text(
                "INSERT INTO block_schedules "
                "(id, mac_address, label, days_of_week, start_time, end_time, "
                " enabled, mac_addresses, tags) "
                "VALUES (:id, :mac, :label, :dow, :start_time, :end_time, "
                "        :enabled, :mac_addresses, :tags) "
                "ON CONFLICT (id) DO NOTHING"
            ), {"id": bs_id, "mac": bs.get("mac_address"), "label": bs.get("label"),
                "dow": bs.get("days_of_week", "mon,tue,wed,thu,fri,sat,sun"),
                "start_time": bs.get("start_time", "00:00"),
                "end_time": bs.get("end_time", "00:00"),
                "enabled": bool(bs.get("enabled", True)),
                "mac_addresses": bs.get("mac_addresses"),
                "tags": bs.get("tags", "")})
            sp.commit()
            stats["block_schedules"] += 1
        except Exception:
            sp.rollback()

    # Speedtest results
    for sr in payload.get("speedtest_results", []):
        sr_id = sr.get("id")
        if sr_id is None:
            continue
        sp = db.begin_nested()
        try:
            db.execute(text(
                "INSERT INTO speedtest_results "
                "(id, tested_at, server, ping_ms, download_mbps, upload_mbps, raw_output) "
                "VALUES (:id, :tested_at, :server, :ping_ms, :download_mbps, :upload_mbps, :raw_output) "
                "ON CONFLICT (id) DO NOTHING"
            ), {"id": sr_id, "tested_at": sr.get("tested_at"), "server": sr.get("server"),
                "ping_ms": sr.get("ping_ms"), "download_mbps": sr.get("download_mbps"),
                "upload_mbps": sr.get("upload_mbps"), "raw_output": sr.get("raw_output")})
            sp.commit()
            stats["speedtest_results"] += 1
        except Exception:
            sp.rollback()

    db.commit()

    # Reset SERIAL sequences so new inserts don't collide with restored IDs
    for tbl, col in [
        ("device_events", "id"), ("vuln_reports", "id"), ("ip_history", "id"),
        ("alert_suppressions", "id"), ("saved_views", "id"), ("block_schedules", "id"),
        ("speedtest_results", "id"),
    ]:
        try:
            db.execute(text(
                f"SELECT setval(pg_get_serial_sequence('{tbl}', '{col}'), "
                f"COALESCE((SELECT MAX({col}) FROM {tbl}), 0) + 1, false)"
            ))
        except Exception:
            pass
    db.commit()

    return stats


@router.post("/import/restore")
async def import_restore(file: UploadFile = File(...), password: str = Form(""), db: Session = Depends(get_db)):
    """Full restore from a v1 or v2 backup JSON (plain or encrypted)."""
    content = await file.read()
    if content[:5] == b"IENC1":
        if not password:
            raise HTTPException(400, "This backup is encrypted — enter the password before restoring")
        try:
            content = _decrypt_backup(content, password)
        except Exception:
            raise HTTPException(400, "Decryption failed — wrong password")
    try:
        payload = json.loads(content)
    except Exception as exc:
        raise HTTPException(400, f"Invalid JSON: {exc}")
    if not isinstance(payload, dict) or payload.get("version") not in (1, 2):
        raise HTTPException(400, "Unrecognised backup format (expected version 1 or 2)")
    return _do_restore(payload, db)


@router.post("/setup/restore-from-backup")
async def setup_restore_from_backup(file: UploadFile = File(...), password: str = Form(""), db: Session = Depends(get_db)):
    """Public endpoint: restore from backup during initial setup wizard.
    Restores all data including credentials and marks setup_complete = true."""
    content = await file.read()
    if content[:5] == b"IENC1":
        if not password:
            raise HTTPException(400, "This backup is encrypted — enter the password before restoring")
        try:
            content = _decrypt_backup(content, password)
        except Exception:
            raise HTTPException(400, "Decryption failed — wrong password")
    try:
        payload = json.loads(content)
    except Exception as exc:
        raise HTTPException(400, f"Invalid JSON: {exc}")
    if not isinstance(payload, dict) or payload.get("version") not in (1, 2):
        raise HTTPException(400, "Unrecognised backup format (expected version 1 or 2)")

    stats = _do_restore(payload, db)

    # Mark setup complete so the wizard doesn't reappear
    s = db.get(Setting, "setup_complete")
    if s:
        s.value = "true"
    else:
        db.add(Setting(key="setup_complete", value="true"))
    db.commit()

    return {"ok": True, "restored": stats}
