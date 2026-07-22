from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy import text
from sqlalchemy.orm import Session
from typing import Optional
import httpx
from datetime import datetime, timezone, timedelta
from database import get_db
from auth_utils import get_current_user
from models import Device, Setting
from config import PROBE_URL
from probe_client import _probe_client

router = APIRouter()


@router.post("/traffic/start/{mac}")
async def traffic_start(mac: str, db: Session = Depends(get_db)):
    mac = mac.lower()
    te = db.get(Setting, "traffic_enabled")
    if te and te.value == "false":
        raise HTTPException(403, "Traffic monitoring is disabled in settings")
    device = db.get(Device, mac)
    if not device:
        raise HTTPException(404, "Device not found")
    ip = device.ip_address
    if not ip:
        raise HTTPException(422, "Device has no IP address")
    # Enforce max concurrent sessions
    max_s = db.get(Setting, "traffic_max_sessions")
    max_sessions = int(max_s.value) if max_s and max_s.value else 10
    try:
        async with _probe_client(timeout=5.0) as client:
            active_resp = await client.get(f"{PROBE_URL}/traffic/stats")
        if active_resp.status_code == 200:
            active_count = len(active_resp.json().get("sessions", []))
            if active_count >= max_sessions:
                raise HTTPException(429, f"Max concurrent traffic sessions ({max_sessions}) reached")
    except (httpx.ConnectError, httpx.TimeoutException):
        pass
    try:
        async with _probe_client(timeout=10.0) as client:
            resp = await client.post(f"{PROBE_URL}/traffic/start/{ip}")
        if resp.status_code == 409:
            raise HTTPException(409, resp.json().get("detail", "Conflict"))
        if resp.status_code not in (200, 201):
            raise HTTPException(502, f"Probe returned {resp.status_code}")
        return resp.json()
    except HTTPException:
        raise
    except httpx.ConnectError:
        raise HTTPException(503, "Cannot reach probe")


@router.delete("/traffic/stop/{mac}")
async def traffic_stop(mac: str, db: Session = Depends(get_db)):
    mac = mac.lower()
    device = db.get(Device, mac)
    if not device:
        raise HTTPException(404, "Device not found")
    ip = device.ip_address
    if not ip:
        return {"ok": True, "was_monitoring": False}
    try:
        async with _probe_client(timeout=10.0) as client:
            resp = await client.delete(f"{PROBE_URL}/traffic/stop/{ip}")
        if resp.status_code not in (200, 204):
            raise HTTPException(502, f"Probe returned {resp.status_code}")
        return resp.json()
    except HTTPException:
        raise
    except httpx.ConnectError:
        raise HTTPException(503, "Cannot reach probe")


@router.get("/traffic/active")
async def traffic_active():
    try:
        async with _probe_client(timeout=8.0) as client:
            resp = await client.get(f"{PROBE_URL}/traffic/stats")
        if resp.status_code != 200:
            return {"sessions": []}
        return resp.json()
    except Exception:
        return {"sessions": []}


@router.get("/traffic/live/{mac}")
async def traffic_live(mac: str, db: Session = Depends(get_db)):
    mac = mac.lower()
    device = db.get(Device, mac)
    if not device:
        raise HTTPException(404, "Device not found")
    try:
        async with _probe_client(timeout=8.0) as client:
            resp = await client.get(f"{PROBE_URL}/traffic/stats/{mac}")
        if resp.status_code == 404:
            raise HTTPException(404, "No active monitor for this device")
        if resp.status_code != 200:
            raise HTTPException(502, f"Probe returned {resp.status_code}")
        return resp.json()
    except HTTPException:
        raise
    except httpx.ConnectError:
        raise HTTPException(503, "Cannot reach probe")


@router.get("/traffic/history/{mac}")
async def traffic_history(mac: str, days: int = 7, db: Session = Depends(get_db)):
    mac = mac.lower()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    rows = db.execute(
        text("""
            SELECT bucket_ts, bytes_in, bytes_out, packets_in, packets_out,
                   lan_bytes, wan_bytes, dns_queries, tls_sni, http_hosts,
                   top_ips, top_ports, top_countries, protocols, unusual_ports
            FROM traffic_stats
            WHERE mac_address = :mac AND bucket_ts >= :cutoff
            ORDER BY bucket_ts ASC
        """),
        {"mac": mac, "cutoff": cutoff},
    ).fetchall()
    keys = ["ts", "bytes_in", "bytes_out", "packets_in", "packets_out",
            "lan_bytes", "wan_bytes", "dns_queries", "tls_sni", "http_hosts",
            "top_ips", "top_ports", "top_countries", "protocols", "unusual_ports"]
    return {"mac": mac, "history": [dict(zip(keys, r)) for r in rows]}


@router.get("/traffic/top-domains/{mac}")
async def traffic_top_domains(mac: str, days: int = 7, limit: int = 20, db: Session = Depends(get_db)):
    mac = mac.lower()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    rows = db.execute(
        text("""
            SELECT tls_sni, http_hosts, dns_queries
            FROM traffic_stats
            WHERE mac_address = :mac AND bucket_ts >= :cutoff
        """),
        {"mac": mac, "cutoff": cutoff},
    ).fetchall()
    agg: dict = {}
    for row in rows:
        for col in row:
            if not col:
                continue
            for item in col:
                k = item.get("k") if isinstance(item, dict) else None
                v = item.get("v", 1) if isinstance(item, dict) else 1
                if k:
                    agg[k] = agg.get(k, 0) + v
    top = sorted(agg.items(), key=lambda x: x[1], reverse=True)[:limit]
    return {"mac": mac, "top_domains": [{"domain": k, "count": v} for k, v in top]}


@router.get("/traffic/summary")
async def traffic_summary(db: Session = Depends(get_db)):
    cutoff = datetime.now(timezone.utc) - timedelta(days=1)
    row = db.execute(
        text("""
            SELECT
                COUNT(DISTINCT mac_address) AS devices_monitored,
                COALESCE(SUM(bytes_in + bytes_out), 0) AS total_bytes,
                COALESCE(SUM(bytes_in), 0) AS total_bytes_in,
                COALESCE(SUM(bytes_out), 0) AS total_bytes_out,
                COALESCE(SUM(wan_bytes), 0) AS total_wan_bytes,
                COALESCE(SUM(lan_bytes), 0) AS total_lan_bytes
            FROM traffic_stats
            WHERE bucket_ts >= :cutoff
        """),
        {"cutoff": cutoff},
    ).fetchone()
    active_count = 0
    try:
        async with _probe_client(timeout=5.0) as client:
            r = await client.get(f"{PROBE_URL}/traffic/stats")
            if r.status_code == 200:
                active_count = len(r.json().get("sessions", []))
    except Exception:
        pass

    return {
        "active_sessions":   active_count,
        "devices_monitored": row[0] if row else 0,
        "total_bytes":       row[1] if row else 0,
        "total_bytes_in":    row[2] if row else 0,
        "total_bytes_out":   row[3] if row else 0,
        "total_wan_bytes":   row[4] if row else 0,
        "total_lan_bytes":   row[5] if row else 0,
    }


@router.get("/traffic/stream/{mac}")
async def traffic_stream(mac: str):
    """Proxy the probe's SSE stream for a device traffic monitor."""
    mac = mac.lower()

    async def _generate():
        try:
            async with _probe_client(timeout=None) as client:
                async with client.stream("GET", f"{PROBE_URL}/traffic/stream/{mac}") as resp:
                    if resp.status_code != 200:
                        yield f"data: {{\"error\": \"probe {resp.status_code}\"}}\n\n"
                        return
                    async for line in resp.aiter_lines():
                        yield line + "\n"
        except Exception as exc:
            yield f"data: {{\"error\": \"{exc}\"}}\n\n"

    return StreamingResponse(_generate(), media_type="text/event-stream")
