from fastapi import APIRouter, HTTPException, Depends, Query, Response
from fastapi.responses import StreamingResponse
from sqlalchemy import text, or_
from sqlalchemy.orm import Session
from typing import Optional, List
import asyncio, csv, io, json, hashlib
from datetime import datetime, timezone, timedelta
from database import get_db, SessionLocal
from auth_utils import get_current_user, get_current_user_optional
from models import Device, DeviceEvent, FingerprintEntry, Setting, VulnReport
from schemas import DeviceUpdate, IdentityUpdate, MetadataUpdate, PrimaryIPUpdate, GroupAddRequest
from device_utils import (
    _to_dict, _build_name_candidates, _add_event, _resolve_hostname,
    _infer_vendor, _infer_device_type, _identity_score, _apply_fingerbank_enrichment,
)
from fingerprint_utils import _oui, _upsert_manual_fingerprint, _fingerbank_query, _match_fingerprints
from probe_client import _probe_client, _execute_block_bg
from sse import _sse_publish
from config import PROBE_URL
import httpx
import state

router = APIRouter()


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------
def _is_locally_admin_mac(mac: str) -> bool:
    """Return True if MAC has the locally-administered bit set (e.g. macvlan, VMs, containers)."""
    try:
        return bool(int(mac.split(':')[0], 16) & 0x02)
    except Exception:
        return False


@router.get("/devices/meta/zones")
def get_device_zones(db: Session = Depends(get_db)):
    try:
        rows = db.execute(
            text("SELECT DISTINCT zone FROM devices WHERE zone IS NOT NULL ORDER BY zone")
        ).fetchall()
        return [r[0] for r in rows]
    except Exception:
        return []


@router.get("/devices")
def list_devices(
    online_only: bool = False,
    include_ignored: bool = True,
    vendor: Optional[str] = None,
    hostname: Optional[str] = None,
    zone: Optional[str] = None,
    has_vulns: Optional[bool] = None,
    severity: Optional[str] = None,
    port: Optional[int] = None,
    is_important: Optional[bool] = None,
    sort_by: Optional[str] = None,
    sort_dir: Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(Device)
    if online_only:
        q = q.filter(Device.is_online == True)
    if not include_ignored:
        q = q.filter(Device.is_ignored == False)
    if vendor:
        q = q.filter(Device.vendor.ilike(f"%{vendor}%"))
    if hostname:
        q = q.filter(
            (Device.hostname.ilike(f"%{hostname}%")) |
            (Device.custom_name.ilike(f"%{hostname}%"))
        )
    if zone:
        q = q.filter(Device.zone == zone)
    if has_vulns is True:
        q = q.filter(Device.vuln_severity != None, Device.vuln_severity != 'clean')
    if severity:
        q = q.filter(Device.vuln_severity == severity)
    if is_important is True:
        q = q.filter(Device.is_important == True)
    if port is not None:
        q = q.filter(text(f"scan_results->'open_ports' @> '[{{\"port\": {int(port)}}}]'::jsonb"))

    valid_sorts = {"last_seen", "first_seen", "hostname", "ip_address"}
    sort_col = sort_by if sort_by in valid_sorts else "last_seen"
    col_map = {
        "last_seen":  Device.last_seen,
        "first_seen": Device.first_seen,
        "hostname":   Device.hostname,
        "ip_address": Device.ip_address,
    }
    col = col_map.get(sort_col, Device.last_seen)
    if sort_dir == "asc":
        q = q.order_by(col.asc().nulls_last(), Device.mac_address.asc())
    else:
        q = q.order_by(col.desc().nulls_last(), Device.mac_address.asc())

    devices = q.all()

    # Identify virtual interfaces: locally-administered MACs that share one or more IPs with
    # a real (globally-administered) MAC.  This covers macvlan, container, and VM interfaces
    # that appear alongside the physical NIC at the same IP addresses.
    try:
        ip_rows = db.execute(text("SELECT mac_address, ip_address FROM ip_history")).fetchall()
    except Exception:
        ip_rows = []

    ip_to_macs: dict[str, set] = {}
    for row in ip_rows:
        if row[1]:
            ip_to_macs.setdefault(row[1], set()).add(row[0])
    # Also include current / primary IPs not yet in history
    for d in devices:
        for addr in filter(None, [d.ip_address, getattr(d, 'primary_ip', None)]):
            ip_to_macs.setdefault(addr, set()).add(d.mac_address)

    mac_set = {d.mac_address for d in devices}
    online_macs = {d.mac_address for d in devices if d.is_online}

    # Map of CURRENT IPs (current/primary IP only, not full history) → MACs.
    # Virtual interfaces (macvlan / container / VM) share the *current* IP with
    # the physical NIC concurrently. We deliberately do NOT use full ip_history
    # here: a phone using MAC randomisation has a locally-administered MAC, and
    # if its old DHCP lease IP was later reassigned to another device, a history
    # based match would wrongly flag the phone as a "virtual interface" and hide
    # it from the device list.
    current_ip_to_macs: dict[str, set] = {}
    for d in devices:
        for addr in filter(None, [d.ip_address, getattr(d, 'primary_ip', None)]):
            current_ip_to_macs.setdefault(addr, set()).add(d.mac_address)

    virtual_of: dict[str, str] = {}
    for d in devices:
        if not _is_locally_admin_mac(d.mac_address):
            continue
        my_ips = {ip for ip, macs in current_ip_to_macs.items() if d.mac_address in macs}
        for ip in my_ips:
            for other_mac in current_ip_to_macs.get(ip, set()):
                # A genuine virtual interface shares its CURRENT IP with a real
                # (globally-administered) device that is also currently online.
                if (other_mac != d.mac_address
                        and other_mac in mac_set
                        and other_mac in online_macs
                        and not _is_locally_admin_mac(other_mac)):
                    virtual_of[d.mac_address] = other_mac
                    break
            if d.mac_address in virtual_of:
                break

    # Collect active secondary IPs (multi-homed: seen while device was online at another IP)
    try:
        sec_rows = db.execute(text("""
            SELECT mac_address, ip_address
            FROM ip_history
            WHERE seen_while_online = true
              AND last_seen > NOW() - INTERVAL '7 days'
        """)).fetchall()
    except Exception:
        sec_rows = []
    secondary_ip_map: dict[str, list[str]] = {}
    for row in sec_rows:
        secondary_ip_map.setdefault(row[0], []).append(row[1])

    # Build a set of IPs "owned" by virtual interfaces for each real MAC, so those
    # IPs are excluded from the real device's secondary_ips (fixes macvlan/switch ghost IPs).
    virtual_ips_for: dict[str, set] = {}
    for v_mac, real_mac in virtual_of.items():
        for ip, macs in ip_to_macs.items():
            if v_mac in macs:
                virtual_ips_for.setdefault(real_mac, set()).add(ip)

    # Build group representative info from already-loaded devices
    group_map: dict[str, list] = {}  # group_id_str -> list[Device]
    for d in devices:
        gid = getattr(d, "group_id", None)
        if gid:
            group_map.setdefault(str(gid), []).append(d)

    group_representative: dict[str, str] = {}  # group_id_str -> mac
    group_any_online:      dict[str, bool] = {}  # group_id_str -> any member online
    for gid_str, members in group_map.items():
        online_members  = [m for m in members if m.is_online]
        primary_members = [m for m in members if getattr(m, "group_primary", False)]
        # The user-selected primary always represents the group, so its
        # name / IP / MAC are what appear in the device list. Fall back to an
        # online member, then to any member, when no primary is set.
        if primary_members:
            rep = primary_members[0].mac_address
        elif online_members:
            rep = online_members[0].mac_address
        else:
            rep = members[0].mac_address
        group_representative[gid_str] = rep
        group_any_online[gid_str]     = bool(online_members)

    hidden_macs: set = {
        m.mac_address
        for gid_str, members in group_map.items()
        for m in members
        if m.mac_address != group_representative.get(gid_str)
    }

    # Build person name lookup
    try:
        person_rows = db.execute(text("SELECT id::text, name FROM persons")).fetchall()
        person_name_map = {r[0]: r[1] for r in person_rows}
    except Exception:
        person_name_map = {}

    result = []
    for d in devices:
        if d.mac_address in hidden_macs:
            continue
        dct = _to_dict(d)
        dct['is_virtual_interface'] = d.mac_address in virtual_of
        dct['virtual_of']           = virtual_of.get(d.mac_address)
        primary   = dct.get('primary_ip') or d.ip_address
        excl_virt = virtual_ips_for.get(d.mac_address, set())
        dct['secondary_ips'] = [
            ip for ip in secondary_ip_map.get(d.mac_address, [])
            if ip != primary and ip not in excl_virt
        ]
        gid = getattr(d, "group_id", None)
        if gid:
            gid_str = str(gid)
            members = group_map.get(gid_str, [])
            dct["group_members"] = [
                {
                    "mac_address":   m.mac_address,
                    "group_primary": bool(getattr(m, "group_primary", False)),
                    "is_online":     m.is_online,
                    "display_name":  m.custom_name or m.hostname or m.ip_address,
                    "ip_address":    m.ip_address,
                }
                for m in members
            ]
            dct["group_size"]              = len(members)
            dct["is_group_representative"] = True
            # A grouped device is one physical host on multiple interfaces, so it
            # is "online" whenever ANY member interface is up — this prevents the
            # representative flapping offline when the host switches interfaces.
            dct["is_online"] = group_any_online.get(gid_str, dct.get("is_online"))
        pid = dct.get("person_id")
        if pid:
            dct["person_name"] = person_name_map.get(pid)
        result.append(dct)
    return result


@router.get("/devices/ip-management")
def get_ip_management(db: Session = Depends(get_db)):
    devices = db.query(Device).order_by(Device.last_seen.desc()).all()
    history_rows = db.execute(
        text("SELECT mac_address, ip_address, first_seen, last_seen, seen_while_online FROM ip_history ORDER BY mac_address, last_seen DESC")
    ).fetchall()
    ip_map: dict = {}
    for r in history_rows:
        ip_map.setdefault(r[0], []).append({
            "ip":              r[1],
            "first_seen":      r[2].isoformat() if r[2] else None,
            "last_seen":       r[3].isoformat() if r[3] else None,
            "seen_while_online": bool(r[4]),
        })
    result = []
    for d in devices:
        dct = _to_dict(d)
        dct["effective_ip"] = getattr(d, "primary_ip", None) or d.ip_address
        dct["ips"] = ip_map.get(d.mac_address, [])
        result.append(dct)
    return result


@router.get("/devices/{mac}")
def get_device(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    result = _to_dict(d)
    if d.group_id:
        try:
            rows = db.execute(
                text("""
                    SELECT mac_address, hostname, custom_name, ip_address, is_online, group_primary
                    FROM devices WHERE group_id = :gid
                """),
                {"gid": d.group_id},
            ).fetchall()
            result["group_members"] = [
                {
                    "mac_address":   r[0],
                    "group_primary": bool(r[5]),
                    "is_online":     bool(r[4]),
                    "display_name":  r[2] or r[1] or r[3] or r[0],
                    "ip_address":    r[3],
                }
                for r in rows
            ]
            result["group_size"]              = len(rows)
            result["is_group_representative"] = True
        except Exception:
            pass
    latest = (
        db.query(VulnReport)
        .filter(VulnReport.mac_address == mac.lower())
        .order_by(VulnReport.scanned_at.desc())
        .first()
    )
    result["latest_vuln_findings"] = latest.findings if latest else []
    result["name_candidates"] = _build_name_candidates(db, d)
    return result


@router.patch("/devices/{mac}")
def update_device(mac: str, payload: DeviceUpdate, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    old_name = d.custom_name
    if payload.custom_name is not None:
        d.custom_name = (payload.custom_name or '').strip() or None
    if payload.hostname is not None:
        d.hostname = (payload.hostname or '').strip() or None
    if payload.custom_name is not None and d.custom_name != old_name:
        _add_event(db, mac.lower(), 'renamed', {'old': old_name, 'new': d.custom_name})
    db.commit(); db.refresh(d)
    result = _to_dict(d)
    result['name_candidates'] = _build_name_candidates(db, d)
    return result


@router.patch("/devices/{mac}/identity")
def update_identity(mac: str, payload: IdentityUpdate, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    if payload.vendor_override is not None:
        d.vendor_override = payload.vendor_override or None
    if payload.device_type_override is not None:
        d.device_type_override = payload.device_type_override or None
    _upsert_manual_fingerprint(db, device=d, vendor_name=d.vendor_override, device_type=d.device_type_override)
    db.commit(); db.refresh(d)
    return _to_dict(d)


@router.patch("/devices/{mac}/metadata")
def update_metadata(mac: str, payload: MetadataUpdate, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    if payload.notes    is not None: d.notes    = payload.notes    or None
    if payload.tags     is not None: d.tags     = payload.tags     or None
    if payload.location is not None: d.location = payload.location or None
    if payload.zone     is not None: d.zone     = payload.zone     or None
    if payload.is_important is not None:
        old_imp = bool(getattr(d, 'is_important', False))
        d.is_important = payload.is_important
        if payload.is_important != old_imp:
            _add_event(db, mac.lower(), 'marked_important', {'important': payload.is_important})
    if payload.tags is not None:
        _add_event(db, mac.lower(), 'tagged', {'tags': payload.tags})
    if payload.is_ignored is not None:
        d.is_ignored = payload.is_ignored
    if payload.suppress_presence_events is not None:
        d.suppress_presence_events = payload.suppress_presence_events
    if payload.person_id is not None:
        d.person_id = payload.person_id or None  # empty string → unassign
    db.commit(); db.refresh(d)
    return _to_dict(d)


@router.post("/devices/{mac}/acknowledge")
def acknowledge_device(mac: str, db: Session = Depends(get_db)):
    """Mark a new device as acknowledged, removing it from the 'new' surfacing list."""
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    d.is_acknowledged = True
    db.commit()
    if state._ha_mqtt.connected:
        sev_map = {"low": 1, "info": 1, "medium": 2, "high": 3, "critical": 3}
        ports = len((d.scan_results or {}).get("open_ports", [])) if d.scan_results else 0
        vulns = sev_map.get(d.vuln_severity or "", 0)
        state._ha_mqtt.pub_device_state(d.mac_address, bool(d.is_online), d.ip_address, ports, vulns, is_new=False)
    return {"ok": True}


@router.post("/devices/{mac}/resolve-name")
async def resolve_name(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    ip = d.ip_address
    name = None
    if ip:
        try:
            async with _probe_client(timeout=15.0) as client:
                r = await client.get(f"{PROBE_URL}/resolve/{ip}")
                if r.status_code == 200:
                    name = r.json().get("hostname")
        except Exception:
            pass
    if name:
        scan = dict(d.scan_results or {})
        scan['rdns_hostname'] = name
        d.scan_results = scan
        if not d.custom_name:
            d.hostname = name
        db.commit(); db.refresh(d)
    detail = _to_dict(d)
    detail['name_candidates'] = _build_name_candidates(db, d)
    return {"mac": mac, "resolved": name, "device": detail}


@router.post("/devices/resolve-all-names")
async def resolve_all_names(db: Session = Depends(get_db)):
    devices = db.query(Device).filter(
        Device.is_ignored == False,
        Device.ip_address != None,
        Device.ip_address != "",
    ).all()
    updated = 0
    failed = 0
    async with _probe_client(timeout=15.0) as client:
        for d in devices:
            ip = d.ip_address
            if not ip:
                continue
            try:
                r = await client.get(f"{PROBE_URL}/resolve/{ip}")
                if r.status_code == 200:
                    name = r.json().get("hostname")
                    if name and not d.custom_name:
                        d.hostname = name
                        updated += 1
            except Exception:
                failed += 1
    db.commit()
    return {"updated": updated, "failed": failed, "total": len(devices)}


@router.post("/devices/{mac}/rescan")
async def rescan_device(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    d.deep_scanned = False
    db.commit()
    # Ask the probe to start scanning immediately rather than waiting for the next sweep
    try:
        async with _probe_client(timeout=10.0) as client:
            await client.post(f"{PROBE_URL}/rescan/{mac.lower()}")
    except Exception:
        pass  # probe will pick it up on next sweep if unreachable
    return {"mac": mac, "queued": True}


@router.post("/devices/{mac}/reset-baseline")
def reset_baseline(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    d.baseline_ports      = None
    d.baseline_scan_count = 0
    db.commit(); db.refresh(d)
    return _to_dict(d)


@router.post("/devices/{mac}/fingerbank/lookup")
async def fingerbank_lookup(mac: str, db: Session = Depends(get_db)):
    """Immediately trigger a Fingerbank lookup for a single device. Returns the raw result."""
    mac = mac.lower()
    device = db.get(Device, mac)
    if not device:
        raise HTTPException(404, "Device not found")
    if not device.dhcp_fingerprint:
        raise HTTPException(422, "No DHCP fingerprint captured for this device yet")
    key_row = db.get(Setting, "fingerbank_api_key")
    api_key = (key_row.value or "").strip() if key_row else ""
    if not api_key:
        raise HTTPException(422, "No Fingerbank API key configured in Settings → Scanner → Device Identification")
    result = await _fingerbank_query(
        mac, device.dhcp_fingerprint,
        device.dhcp_vendor_class, device.dhcp_hostname, api_key
    )
    device.fingerbank_result = result
    from sqlalchemy.orm.attributes import flag_modified
    flag_modified(device, "fingerbank_result")
    _apply_fingerbank_enrichment(device, result)
    db.commit()
    return {"result": result, "device": _to_dict(device)}


@router.delete("/devices/{mac}")
def delete_device(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    db.execute(text("DELETE FROM device_events WHERE mac_address = :mac"), {"mac": mac.lower()})
    db.execute(text("DELETE FROM ip_history WHERE mac_address = :mac"), {"mac": mac.lower()})
    db.execute(text("DELETE FROM vuln_reports WHERE mac_address = :mac"), {"mac": mac.lower()})
    db.execute(text("DELETE FROM traffic_stats WHERE mac_address = :mac"), {"mac": mac.lower()})
    db.execute(text("DELETE FROM alert_suppressions WHERE mac_address = :mac"), {"mac": mac.lower()})
    db.delete(d)
    db.commit()
    return {"ok": True, "mac": mac.lower()}


@router.get("/devices/{mac}/scan")
def get_scan_results(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    if not d.deep_scanned:
        return {"status": "pending", "message": "Deep scan not yet completed"}
    return {"status": "complete", "mac": mac, "data": d.scan_results}


@router.get("/devices/{mac}/ip-history")
def get_ip_history(mac: str, db: Session = Depends(get_db)):
    try:
        rows = db.execute(
            text("SELECT ip_address, first_seen, last_seen FROM ip_history WHERE mac_address = :mac ORDER BY last_seen DESC"),
            {"mac": mac.lower()}
        ).fetchall()
        return [{"ip": r[0], "first_seen": r[1].isoformat() if r[1] else None, "last_seen": r[2].isoformat() if r[2] else None} for r in rows]
    except Exception:
        return []


@router.get("/export/ips-csv")
def export_ips_csv(db: Session = Depends(get_db)):
    """Export all IP history as CSV."""
    import io, csv
    rows = db.execute(text("""
        SELECT d.mac_address, COALESCE(d.custom_name, d.hostname, d.ip_address) AS name,
               h.ip_address, h.first_seen, h.last_seen, h.seen_while_online,
               d.primary_ip, d.primary_ip_locked, d.is_online
        FROM ip_history h
        JOIN devices d ON d.mac_address = h.mac_address
        ORDER BY d.mac_address, h.last_seen DESC
    """)).fetchall()

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["mac_address", "device_name", "ip_address", "first_seen", "last_seen", "seen_while_online", "primary_ip", "primary_ip_locked", "is_online"])
    for r in rows:
        w.writerow([r[0], r[1], r[2],
                    r[3].isoformat() if r[3] else "",
                    r[4].isoformat() if r[4] else "",
                    r[5], r[6], r[7], r[8]])

    from fastapi.responses import StreamingResponse as _SR
    return _SR(iter([buf.getvalue()]), media_type="text/csv",
               headers={"Content-Disposition": "attachment; filename=inspectre-ip-management.csv"})


@router.post("/devices/{mac}/set-primary-ip")
async def set_primary_ip(mac: str, payload: PrimaryIPUpdate, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")

    target_ip = (payload.ip_address or "").strip()
    if not target_ip:
        raise HTTPException(400, "ip_address is required")

    row = db.execute(
        text("SELECT 1 FROM ip_history WHERE mac_address = :mac AND ip_address = :ip LIMIT 1"),
        {"mac": mac.lower(), "ip": target_ip}
    ).fetchone()
    if not row and d.ip_address != target_ip:
        raise HTTPException(404, "IP not found in device history")

    old_primary = d.primary_ip or d.ip_address

    # The probe installs a BEFORE UPDATE trigger that reverts primary_ip/ip_address
    # when both OLD.primary_ip_locked AND NEW.primary_ip_locked are TRUE — to stop
    # the probe overwriting a user pin.  Re-pinning an already-locked device hits
    # that condition.  Work around it with two updates in the same transaction:
    #   1. Unlock (OLD=T→NEW=F): trigger condition False, write succeeds.
    #   2. Re-pin (OLD=F→NEW=T): trigger condition False, write succeeds.
    # Both updates are invisible outside this transaction so no race with the probe.
    db.execute(
        text("UPDATE devices SET primary_ip_locked = FALSE WHERE mac_address = :mac"),
        {"mac": mac.lower()},
    )
    db.execute(
        text("""UPDATE devices
                   SET primary_ip   = :ip,
                       ip_address   = :ip,
                       primary_ip_locked = TRUE,
                       deep_scanned = FALSE,
                       scan_results = NULL
                 WHERE mac_address  = :mac"""),
        {"ip": target_ip, "mac": mac.lower()},
    )
    _add_event(db, mac.lower(), 'primary_ip_changed', {'old_primary_ip': old_primary, 'new_primary_ip': target_ip})
    db.commit()
    db.refresh(d)

    # Verify the pin was written correctly — the DB trigger or a concurrent
    # update could silently prevent it.
    if d.primary_ip != target_ip or not d.primary_ip_locked:
        print(
            f"[set-primary-ip] WARN: pin verification failed for {mac}: "
            f"expected primary={target_ip} locked=True, "
            f"got primary={d.primary_ip} locked={d.primary_ip_locked}",
            flush=True,
        )
        raise HTTPException(500, "Pin did not take effect — the device may have a conflicting lock. Please try again.")

    result = {"ok": True, "device": _to_dict(d)}

    async def _trigger_rescan():
        try:
            async with _probe_client(timeout=3.0) as client:
                await client.post(f"{PROBE_URL}/rescan/{mac.lower()}")
        except Exception:
            pass
    asyncio.ensure_future(_trigger_rescan())

    return result


@router.post("/devices/{mac}/unpin-ip")
def unpin_primary_ip(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    d.primary_ip_locked = False
    db.commit()
    db.refresh(d)
    return {"ok": True, "device": _to_dict(d)}


@router.get("/devices/{mac}/events")
def get_device_events(
    mac: str,
    type: Optional[str] = Query(default=None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(default=0),
    db: Session = Depends(get_db),
):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    # If the device is in a group, include events from all group members
    group_id = getattr(d, "group_id", None)
    if group_id:
        try:
            macs = [r[0] for r in db.execute(
                text("SELECT mac_address FROM devices WHERE group_id = :gid"),
                {"gid": group_id},
            ).fetchall()]
        except Exception:
            macs = [mac.lower()]
    else:
        macs = [mac.lower()]
    try:
        rows = db.execute(
            text("""
                SELECT id, mac_address, type, detail, created_at
                FROM device_events
                WHERE mac_address = ANY(:macs)
                  AND (:type IS NULL OR type = :type)
                ORDER BY created_at DESC
                LIMIT :limit OFFSET :offset
            """),
            {"macs": macs, "type": type, "limit": limit, "offset": offset}
        ).fetchall()
        return [
            {
                "id":          r[0],
                "mac_address": r[1],
                "type":        r[2],
                "detail":      r[3],
                "created_at":  r[4].isoformat() if r[4] else None,
            }
            for r in rows
        ]
    except Exception:
        return []


@router.get("/devices/{mac}/identity-score")
def get_identity_score(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    return {"mac": mac, "score": _identity_score(d), "device_type": _infer_device_type(d)}


# ---------------------------------------------------------------------------
# Phase 9 — Device grouping
# ---------------------------------------------------------------------------

@router.get("/devices/{mac}/group")
def get_device_group(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    group_id = getattr(d, "group_id", None)
    if not group_id:
        return {"group_id": None, "members": []}
    rows = db.execute(
        text("""
            SELECT mac_address, hostname, custom_name, ip_address, is_online, group_primary
            FROM devices WHERE group_id = :gid
        """),
        {"gid": group_id},
    ).fetchall()
    return {
        "group_id": str(group_id),
        "members": [
            {
                "mac_address":   r[0],
                "hostname":      r[1],
                "custom_name":   r[2],
                "ip_address":    r[3],
                "is_online":     r[4],
                "group_primary": bool(r[5]),
                "display_name":  r[2] or r[1] or r[3] or r[0],
            }
            for r in rows
        ],
    }


@router.post("/devices/{mac}/group/add")
def add_to_group(mac: str, body: GroupAddRequest, db: Session = Depends(get_db)):
    import uuid as _uuid
    mac1 = mac.lower()
    mac2 = body.target_mac.lower()
    if mac1 == mac2:
        raise HTTPException(400, "Cannot group a device with itself")
    d1 = db.get(Device, mac1)
    d2 = db.get(Device, mac2)
    if not d1 or not d2:
        raise HTTPException(404, "Device not found")
    g1 = getattr(d1, "group_id", None)
    g2 = getattr(d2, "group_id", None)
    if g1 and g2 and str(g1) == str(g2):
        return {"ok": True, "group_id": str(g1)}
    # Prefer an existing group_id; if both have different groups, merge into g1
    new_gid = str(g1 or g2 or _uuid.uuid4())
    db.execute(
        text("UPDATE devices SET group_id = :gid WHERE mac_address = ANY(:macs)"),
        {"gid": new_gid, "macs": [mac1, mac2]},
    )
    # If g2 had a group, pull all its members into the new group
    if g2 and str(g2) != new_gid:
        db.execute(
            text("UPDATE devices SET group_id = :gid WHERE group_id = :old"),
            {"gid": new_gid, "old": str(g2)},
        )
    # Ensure exactly one primary exists: prefer the existing primary, else set mac1
    primaries = db.execute(
        text("SELECT mac_address FROM devices WHERE group_id = :gid AND group_primary = true"),
        {"gid": new_gid},
    ).fetchall()
    if not primaries:
        db.execute(
            text("UPDATE devices SET group_primary = true WHERE mac_address = :mac"),
            {"mac": mac1},
        )
    # Mark the whole group as manually curated so auto-grouping cleanup never
    # dissolves it (manual groups may legitimately span different DNS hostnames).
    db.execute(
        text("UPDATE devices SET group_manual = true, auto_group_optout = false WHERE group_id = :gid"),
        {"gid": new_gid},
    )
    db.commit()
    return {"ok": True, "group_id": new_gid}


@router.post("/devices/{mac}/group/remove")
def remove_from_group(mac: str, db: Session = Depends(get_db)):
    mac_lower = mac.lower()
    d = db.get(Device, mac_lower)
    if not d:
        raise HTTPException(404, "Device not found")
    group_id = getattr(d, "group_id", None)
    if not group_id:
        return {"ok": True}
    db.execute(
        text("UPDATE devices SET group_id = NULL, group_primary = FALSE, group_manual = FALSE, auto_group_optout = TRUE WHERE mac_address = :mac"),
        {"mac": mac_lower},
    )
    # If only one member remains, dissolve the group
    remaining = db.execute(
        text("SELECT COUNT(*) FROM devices WHERE group_id = :gid"),
        {"gid": group_id},
    ).scalar() or 0
    if remaining <= 1:
        db.execute(
            text("UPDATE devices SET group_id = NULL, group_primary = FALSE, group_manual = FALSE WHERE group_id = :gid"),
            {"gid": group_id},
        )
    db.commit()
    return {"ok": True}


@router.put("/devices/{mac}/group/primary")
def set_group_primary(mac: str, db: Session = Depends(get_db)):
    mac_lower = mac.lower()
    d = db.get(Device, mac_lower)
    if not d:
        raise HTTPException(404, "Device not found")
    group_id = getattr(d, "group_id", None)
    if not group_id:
        raise HTTPException(400, "Device is not in a group")
    db.execute(
        text("UPDATE devices SET group_primary = FALSE WHERE group_id = :gid"),
        {"gid": group_id},
    )
    db.execute(
        text("UPDATE devices SET group_primary = TRUE WHERE mac_address = :mac"),
        {"mac": mac_lower},
    )
    db.execute(
        text("UPDATE devices SET group_manual = TRUE WHERE group_id = :gid"),
        {"gid": group_id},
    )
    db.commit()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Block helpers (local to this router)
# ---------------------------------------------------------------------------

def _get_block_method_settings(db: Session) -> tuple[str, str]:
    method_row    = db.get(Setting, "block_method")
    plugin_id_row = db.get(Setting, "block_plugin_id")
    method    = (method_row.value    if method_row    else None) or "arp"
    plugin_id = (plugin_id_row.value if plugin_id_row else None) or ""
    return method, plugin_id


async def _execute_block(mac: str, ip: Optional[str], db: Session, action: str) -> None:
    """
    Unified blocking coordinator (synchronous path, raises HTTPException on failure).
    action: "block" or "unblock"
    """
    method, plugin_id = _get_block_method_settings(db)

    if method == "arp":
        try:
            async with _probe_client(timeout=15.0) as client:
                if action == "block":
                    resp = await client.post(f"{PROBE_URL}/block/{mac.lower()}")
                else:
                    resp = await client.delete(f"{PROBE_URL}/block/{mac.lower()}")
                if resp.status_code >= 400:
                    raise HTTPException(502, f"Probe error: {resp.text[:200]}")
        except httpx.ConnectError:
            raise HTTPException(502, f"Cannot reach probe at {PROBE_URL}")
    else:
        if not plugin_id:
            raise HTTPException(400, "block_plugin_id is not configured")
        plugin = state._plugin_registry.get(plugin_id)
        if not plugin or not plugin.get("enabled"):
            raise HTTPException(400, f"Blocking plugin '{plugin_id}' is not enabled")
        action_name = "block_client" if action == "block" else "unblock_client"
        if action_name not in (plugin["manifest"].get("actions") or {}):
            raise HTTPException(400, f"Plugin '{plugin_id}' has no '{action_name}' action")
        mac_lower = mac.lower()
        mac_dash  = mac_lower.replace(":", "-").upper()
        print(f"[block-coord] {action} via plugin '{plugin_id}': mac={mac_lower} mac_dash={mac_dash} ip={ip}", flush=True)
        result = await state._plugin_runner.execute_action(
            plugin_id, action_name, {"mac": mac_lower, "mac_dash": mac_dash, "ip": ip or ""}
        )
        print(f"[block-coord] {action} result: ok={result.get('ok')} error={result.get('error')} status={result.get('status_code')} api_code={result.get('api_error_code')}", flush=True)
        if not result.get("ok"):
            raise HTTPException(502, f"Plugin block failed: {result.get('error', 'unknown error')}")


@router.get("/devices/{mac}/ping")
async def stream_ping(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")

    target_ip = getattr(d, 'primary_ip', None) or d.ip_address

    async def _gen():
        try:
            async with _probe_client(timeout=None) as client:
                async with client.stream("GET", f"{PROBE_URL}/stream/ping/{target_ip}") as resp:
                    async for line in resp.aiter_lines():
                        yield f"{line}\n"
        except httpx.ConnectError:
            yield f"data: [ERROR] Cannot reach probe at {PROBE_URL}\n\n"
        except Exception as e:
            yield f"data: [ERROR] {e}\n\n"

    return StreamingResponse(_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.post("/devices/{mac}/block")
async def block_device(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    await _execute_block(mac, d.ip_address, db, "block")
    d.is_blocked = True
    _add_event(db, mac.lower(), "blocked", {"ip": d.ip_address})
    db.commit(); db.refresh(d)
    asyncio.ensure_future(state._plugin_event_bus.notify("device.blocked", {"mac": mac.lower(), "ip": d.ip_address or ""}))
    return _to_dict(d)


@router.post("/devices/{mac}/unblock")
async def unblock_device(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    await _execute_block(mac, d.ip_address, db, "unblock")
    d.is_blocked = False
    _add_event(db, mac.lower(), "unblocked", {"ip": d.ip_address})
    db.commit(); db.refresh(d)
    asyncio.ensure_future(state._plugin_event_bus.notify("device.unblocked", {"mac": mac.lower(), "ip": d.ip_address or ""}))
    return _to_dict(d)


@router.get("/devices/{mac}/traceroute")
async def stream_traceroute(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")

    trace_ip = getattr(d, 'primary_ip', None) or d.ip_address

    async def _gen():
        try:
            async with _probe_client(timeout=None) as client:
                async with client.stream("GET", f"{PROBE_URL}/stream/traceroute/{trace_ip}") as resp:
                    async for line in resp.aiter_lines():
                        yield f"{line}\n"
        except httpx.ConnectError:
            yield f"data: [ERROR] Cannot reach probe at {PROBE_URL}\n\n"
        except Exception as e:
            yield f"data: [ERROR] {e}\n\n"

    return StreamingResponse(_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
