from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
import httpx
from database import get_db
from auth_utils import get_current_user
from models import Device
from config import PROBE_URL
from probe_client import _probe_client

router = APIRouter()


@router.get("/devices/{mac}/services")
def get_device_services(mac: str, db: Session = Depends(get_db)):
    device = db.execute(
        text("SELECT scan_results FROM devices WHERE mac_address = :mac"),
        {"mac": mac.lower()}
    ).fetchone()
    if not device or not device[0]:
        return {"services": [], "pipeline_stage": None}
    scan = device[0]
    ports = scan.get("open_ports") or []
    nerva = {s["port"]: s for s in (scan.get("services") or [])}
    merged = []
    for p in ports:
        port_num = p.get("port")
        entry = {
            "port":      port_num,
            "proto":     p.get("proto", "tcp"),
            "service":   p.get("service") or nerva.get(port_num, {}).get("service", ""),
            "product":   p.get("product", ""),
            "version":   p.get("version", ""),
            "tls":       p.get("tls") or nerva.get(port_num, {}).get("tls", False),
            "extrainfo": p.get("extrainfo", ""),
        }
        merged.append(entry)
    return {
        "services": sorted(merged, key=lambda x: x["port"] or 0),
        "pipeline_stage": scan.get("pipeline_stage"),
    }


@router.post("/devices/{mac}/mdns-refresh")
async def refresh_device_mdns(mac: str, db: Session = Depends(get_db)):
    d = db.get(Device, mac.lower())
    if not d:
        raise HTTPException(404, "Device not found")
    try:
        async with _probe_client(timeout=35.0) as client:
            resp = await client.post(f"{PROBE_URL}/mdns/refresh")
            resp.raise_for_status()
    except httpx.ConnectError:
        raise HTTPException(502, f"Cannot reach probe at {PROBE_URL}")
    except Exception as e:
        raise HTTPException(502, f"mDNS refresh failed: {e}")
    db.refresh(d)
    mdns_services = (d.scan_results or {}).get("mdns_services", []) if d.scan_results else []
    return {"mdns_services": mdns_services}


@router.post("/network/mdns-scan")
async def network_mdns_scan():
    """Trigger a network-wide active mDNS browse."""
    try:
        async with _probe_client(timeout=25.0) as client:
            resp = await client.post(f"{PROBE_URL}/mdns/refresh")
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        raise HTTPException(502, f"Cannot reach probe at {PROBE_URL}")
    except Exception as e:
        raise HTTPException(502, f"mDNS scan failed: {e}")


@router.post("/network/ssdp-scan")
async def network_ssdp_scan():
    """Trigger a network-wide active SSDP M-SEARCH."""
    try:
        async with _probe_client(timeout=20.0) as client:
            resp = await client.post(f"{PROBE_URL}/ssdp/refresh")
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        raise HTTPException(502, f"Cannot reach probe at {PROBE_URL}")
    except Exception as e:
        raise HTTPException(502, f"SSDP scan failed: {e}")
