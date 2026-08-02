from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import text
from sqlalchemy.orm import Session
from typing import Optional, List
import asyncio, json, httpx
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from database import get_db
from auth_utils import get_current_user
from models import Device, VulnReport, Setting
from config import PROBE_URL
from probe_client import _probe_client
from vuln_utils import _run_single_vuln_scan, _run_all_vuln_scans, _save_vuln_result

router = APIRouter()

_nuclei_subs:  dict[str, list[asyncio.Queue]] = {}  # mac → subscriber queues
_nuclei_lines: dict[str, list[str]] = {}            # mac → buffered output lines


def _severity_rank(severity: str | None) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "clean": 5}.get(severity or "", 9)


def _grouped_vuln_view(db: Session) -> list[dict]:
    device_rows = db.execute(text("""
        SELECT mac_address, custom_name, hostname, ip_address, vuln_severity, vuln_last_scanned,
               group_id, group_primary
        FROM devices
    """)).fetchall()
    report_rows = db.execute(text("""
        SELECT DISTINCT ON (mac_address)
               id, mac_address, severity, vuln_count, scanned_at, findings
        FROM vuln_reports
        ORDER BY mac_address, scanned_at DESC, id DESC
    """)).fetchall()
    latest_report_by_mac = {row.mac_address: row for row in report_rows}

    grouped: dict[str, list] = defaultdict(list)
    for row in device_rows:
        group_key = str(row.group_id) if row.group_id else row.mac_address
        grouped[group_key].append(row)

    result = []
    for members in grouped.values():
        display = next((m for m in members if bool(m.group_primary)), None) or members[0]
        report_member = display if latest_report_by_mac.get(display.mac_address) else None
        if report_member is None:
            report_member = next(
                (
                    member for member in sorted(
                        members,
                        key=lambda m: (
                            latest_report_by_mac.get(m.mac_address).scanned_at if latest_report_by_mac.get(m.mac_address) else datetime.min.replace(tzinfo=timezone.utc),
                            bool(m.group_primary),
                        ),
                        reverse=True,
                    )
                    if latest_report_by_mac.get(member.mac_address)
                ),
                None,
            )

        group_severity = min(
            (_severity_rank(m.vuln_severity) for m in members if m.vuln_severity is not None),
            default=9,
        )
        severity = next((s for s in ("critical", "high", "medium", "low", "info", "clean") if _severity_rank(s) == group_severity), None)
        any_scanned_at = max(
            (m.vuln_last_scanned for m in members if m.vuln_last_scanned is not None),
            default=None,
        )
        report = latest_report_by_mac.get(report_member.mac_address) if report_member else None
        result.append({
            "display_mac": display.mac_address,
            "report_mac": report_member.mac_address if report_member else display.mac_address,
            "display_name": display.custom_name or display.hostname or display.ip_address or display.mac_address,
            "ip_address": display.ip_address,
            "severity": severity,
            "vuln_last_scanned": any_scanned_at,
            "report": report,
        })
    return result


@router.get("/devices/{mac}/vuln-scan")
async def stream_vuln_scan(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    if not d.ip_address:
        raise HTTPException(400, "Device has no IP address")

    templates_setting = db.get(Setting, "vuln_scan_templates")
    templates = (templates_setting.value or "").strip() if templates_setting else ""

    ip        = getattr(d, "primary_ip", None) or d.ip_address
    mac_lower = mac.lower()

    # Create a queue for this connection
    q: asyncio.Queue[str | None] = asyncio.Queue()

    if mac_lower in _nuclei_subs:
        # Scan already running — replay buffered lines then subscribe for new ones
        for line in _nuclei_lines.get(mac_lower, []):
            await q.put(line)
        _nuclei_subs[mac_lower].append(q)
    else:
        # Start a new scan — initialise broadcast state first
        _nuclei_subs[mac_lower]  = [q]
        _nuclei_lines[mac_lower] = []

        probe_url = f"{PROBE_URL}/stream/vuln-scan/{ip}"
        params    = {"templates": templates, "mac": mac_lower}

        async def _probe_reader() -> None:
            async def _broadcast(line: str) -> None:
                _nuclei_lines.setdefault(mac_lower, []).append(line)
                for sub_q in list(_nuclei_subs.get(mac_lower, [])):
                    await sub_q.put(line)

            try:
                async with _probe_client(timeout=None) as client:
                    async with client.stream("GET", probe_url, params=params) as resp:
                        if resp.status_code != 200:
                            body = await resp.aread()
                            await _broadcast(f"data: [ERROR] Probe returned HTTP {resp.status_code}: {body.decode()[:200]}\n\n")
                            return
                        async for raw_line in resp.aiter_lines():
                            await _broadcast(f"{raw_line}\n")
                            if raw_line.startswith("data: RESULT:"):
                                payload_str = raw_line[len("data: RESULT:"):]
                                try:
                                    data = json.loads(payload_str)
                                    _save_vuln_result(mac_lower, ip, data, templates)
                                except Exception as exc:
                                    await _broadcast(f"data: [WARN] Could not save report: {exc}\n\n")
            except httpx.ConnectError:
                await _broadcast(f"data: [ERROR] Cannot reach probe at {PROBE_URL} — is it running?\n\n")
            except Exception as exc:
                await _broadcast(f"data: [ERROR] Proxy error: {exc}\n\n")
            finally:
                # Signal all current subscribers that the stream is done, then clean up
                for sub_q in _nuclei_subs.pop(mac_lower, []):
                    await sub_q.put(None)
                _nuclei_lines.pop(mac_lower, None)

        asyncio.create_task(_probe_reader())

    async def _event_stream():
        while True:
            try:
                line = await asyncio.wait_for(q.get(), timeout=30)
            except asyncio.TimeoutError:
                yield ": heartbeat\n\n"
                continue
            if line is None:
                break
            yield line

    return StreamingResponse(
        _event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/devices/{mac}/vuln-scan-status")
def vuln_scan_status(mac: str):
    """Returns whether a nuclei scan is currently running for this device."""
    return {"scanning": mac.lower() in _nuclei_subs}


@router.get("/devices/{mac}/vuln-reports")
def get_vuln_reports(mac: str, limit: int = Query(10, ge=1, le=100), db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    reports = (
        db.query(VulnReport)
        .filter(VulnReport.mac_address == mac.lower())
        .order_by(VulnReport.scanned_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id":         r.id,
            "ip_address": r.ip_address,
            "scanned_at": r.scanned_at.isoformat() if r.scanned_at else None,
            "duration_s": r.duration_s,
            "severity":   r.severity,
            "vuln_count": r.vuln_count,
            "findings":   r.findings or [],
            "scan_args":  r.scan_args,
        }
        for r in reports
    ]


@router.get("/devices/{mac}/vuln-reports/{report_id}")
def get_vuln_report_detail(mac: str, report_id: int, db: Session = Depends(get_db)):
    r = db.query(VulnReport).filter(
        VulnReport.id == report_id,
        VulnReport.mac_address == mac.lower()
    ).first()
    if not r:
        raise HTTPException(404, "Report not found")
    return {
        "id":           r.id,
        "ip_address":   r.ip_address,
        "scanned_at":   r.scanned_at.isoformat() if r.scanned_at else None,
        "duration_s":   r.duration_s,
        "severity":     r.severity,
        "vuln_count":   r.vuln_count,
        "findings":     r.findings or [],
        "raw_output":   r.raw_output,
        "scan_args":    r.scan_args,
    }


@router.delete("/devices/{mac}/vuln-reports/{report_id}")
def delete_vuln_report(mac: str, report_id: int, db: Session = Depends(get_db)):
    r = db.query(VulnReport).filter(
        VulnReport.id == report_id,
        VulnReport.mac_address == mac.lower()
    ).first()
    if not r:
        raise HTTPException(404, "Report not found")
    db.delete(r)
    db.commit()
    return {"deleted": report_id}


@router.get("/vuln-reports")
def list_all_vuln_reports(
    severity: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db)
):
    q = db.query(VulnReport)
    if severity:
        q = q.filter(VulnReport.severity == severity)
    reports = q.order_by(VulnReport.scanned_at.desc()).limit(limit).all()
    return [
        {
            "id":          r.id,
            "mac_address": r.mac_address,
            "ip_address":  r.ip_address,
            "scanned_at":  r.scanned_at.isoformat() if r.scanned_at else None,
            "severity":    r.severity,
            "vuln_count":  r.vuln_count,
            "findings":    r.findings or [],
        }
        for r in reports
    ]


@router.get("/vulns/summary")
def vuln_summary(db: Session = Depends(get_db)):
    grouped = _grouped_vuln_view(db)

    sev_counts: dict[str, int] = defaultdict(int)
    for item in grouped:
        if item["severity"] is not None:
            sev_counts[item["severity"]] += 1

    top_rows = [
        item for item in grouped
        if item["severity"] not in (None, "clean", "info") and item["report"] is not None
    ]
    top_rows = sorted(top_rows, key=lambda item: (_severity_rank(item["severity"]), -(item["report"].vuln_count or 0)))[:8]
    top_vulnerable = [
        {
            "mac_address":  item["report_mac"],
            "display_name": item["display_name"],
            "ip_address":   item["ip_address"],
            "severity":     item["severity"],
            "vuln_count":   item["report"].vuln_count,
            "scanned_at":   item["report"].scanned_at.isoformat() if item["report"].scanned_at else None,
        }
        for item in top_rows
    ]

    recent_rows = sorted(
        [item for item in grouped if item["report"] is not None],
        key=lambda item: item["report"].scanned_at or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )[:20]
    recent_scans = [
        {
            "mac_address":  item["report_mac"],
            "display_name": item["display_name"],
            "ip_address":   item["ip_address"],
            "severity":     item["report"].severity,
            "vuln_count":   item["report"].vuln_count,
            "scanned_at":   item["report"].scanned_at.isoformat() if item["report"].scanned_at else None,
        }
        for item in recent_rows
    ]

    total_scanned = sum(1 for item in grouped if item["vuln_last_scanned"] is not None)
    total_devices = len(grouped)

    return {
        "severity_counts": dict(sev_counts),
        "total_scanned":   int(total_scanned),
        "total_devices":   int(total_devices),
        "top_vulnerable":  top_vulnerable,
        "recent_scans":    recent_scans,
    }


@router.post("/vulns/scan-all")
async def trigger_scan_all():
    asyncio.ensure_future(_run_all_vuln_scans())
    return {"status": "started", "message": "Vulnerability scan initiated for all eligible devices"}


@router.get("/vulns/trend")
def get_vuln_trend(days: int = Query(default=30, le=90), db: Session = Depends(get_db)):
    try:
        rows = db.execute(text("""
            SELECT
                date_trunc('day', scanned_at)::date AS day,
                severity,
                COUNT(*) AS count
            FROM vuln_reports
            WHERE scanned_at >= NOW() - (INTERVAL '1 day' * :days)
            GROUP BY day, severity
            ORDER BY day ASC, severity
        """), {"days": days}).fetchall()
        by_day: dict = defaultdict(dict)
        for row in rows:
            by_day[str(row[0])][row[1]] = int(row[2])
        return [{"date": d, **severities} for d, severities in sorted(by_day.items())]
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get("/vulns/top-devices")
def get_top_vulnerable_devices(limit: int = Query(default=10, le=50), db: Session = Depends(get_db)):
    try:
        rows = [
            item for item in _grouped_vuln_view(db)
            if item["severity"] in ("critical", "high", "medium") and item["report"] is not None
        ]
        rows_sorted = sorted(
            rows,
            key=lambda item: (_severity_rank(item["severity"]), -(item["report"].vuln_count or 0)),
        )[:limit]
        return [
            {
                "mac": item["report_mac"], "name": item["display_name"], "ip": item["ip_address"],
                "severity": item["severity"], "vuln_count": item["report"].vuln_count,
                "scanned_at": item["report"].scanned_at.isoformat() if item["report"].scanned_at else None,
                "top_findings": (item["report"].findings or [])[:3],
            }
            for item in rows_sorted
        ]
    except Exception as e:
        raise HTTPException(500, str(e))
