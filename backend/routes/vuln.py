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
    sev_rows = db.execute(text("""
        SELECT vuln_severity, COUNT(*) AS cnt
        FROM devices
        WHERE vuln_severity IS NOT NULL
        GROUP BY vuln_severity
    """)).fetchall()
    sev_counts = {r[0]: int(r[1]) for r in sev_rows}

    top_rows = db.execute(text("""
        SELECT DISTINCT ON (d.mac_address)
               d.mac_address, d.custom_name, d.hostname, d.ip_address,
               d.vuln_severity, vr.vuln_count, vr.scanned_at
        FROM devices d
        JOIN vuln_reports vr ON vr.mac_address = d.mac_address
        WHERE d.vuln_severity IS NOT NULL AND d.vuln_severity NOT IN ('clean', 'info')
        ORDER BY d.mac_address, vr.scanned_at DESC
    """)).fetchall()

    def sev_rank(s):
        return {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(s or '', 9)

    top_rows = sorted(top_rows, key=lambda r: sev_rank(r[4]))[:8]
    top_vulnerable = [
        {
            "mac_address":  r[0],
            "display_name": r[1] or r[2] or r[3] or r[0],
            "ip_address":   r[3],
            "severity":     r[4],
            "vuln_count":   r[5],
            "scanned_at":   r[6].isoformat() if r[6] else None,
        }
        for r in top_rows
    ]

    recent_rows = db.execute(text("""
        SELECT d.mac_address,
               COALESCE(d.custom_name, d.hostname, d.ip_address, d.mac_address) AS display_name,
               d.ip_address, vr.severity, vr.vuln_count, vr.scanned_at
        FROM vuln_reports vr
        JOIN devices d ON d.mac_address = vr.mac_address
        ORDER BY vr.scanned_at DESC
        LIMIT 20
    """)).fetchall()
    recent_scans = [
        {
            "mac_address":  r[0],
            "display_name": r[1],
            "ip_address":   r[2],
            "severity":     r[3],
            "vuln_count":   r[4],
            "scanned_at":   r[5].isoformat() if r[5] else None,
        }
        for r in recent_rows
    ]

    total_scanned = db.execute(text(
        "SELECT COUNT(*) FROM devices WHERE vuln_last_scanned IS NOT NULL"
    )).scalar() or 0
    total_devices = db.execute(text("SELECT COUNT(*) FROM devices")).scalar() or 0

    return {
        "severity_counts": sev_counts,
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
        rows = db.execute(text("""
            SELECT DISTINCT ON (d.mac_address)
                d.mac_address,
                COALESCE(d.custom_name, d.hostname, d.ip_address) AS name,
                d.ip_address,
                d.vuln_severity,
                vr.vuln_count,
                vr.scanned_at,
                vr.findings
            FROM devices d
            JOIN vuln_reports vr ON vr.mac_address = d.mac_address
            WHERE d.vuln_severity IN ('critical', 'high', 'medium')
            ORDER BY d.mac_address, vr.scanned_at DESC
        """)).fetchall()
        def sev_rank(s):
            return {'critical': 1, 'high': 2, 'medium': 3}.get(s or '', 9)
        rows_sorted = sorted(rows, key=lambda r: sev_rank(r[3]))[:limit]
        return [
            {
                "mac": r[0], "name": r[1], "ip": r[2],
                "severity": r[3], "vuln_count": r[4],
                "scanned_at": r[5].isoformat() if r[5] else None,
                "top_findings": (r[6] or [])[:3],
            }
            for r in rows_sorted
        ]
    except Exception as e:
        raise HTTPException(500, str(e))
