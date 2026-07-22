from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
import asyncio, os, json
import httpx
from database import get_db, DEFAULT_SETTINGS, _seed_settings
from auth_utils import get_current_user
from models import Setting
from schemas import SettingUpdate
from config import PROBE_URL
from probe_client import _probe_client
import state

router = APIRouter()


@router.get("/settings")
def get_settings(db: Session = Depends(get_db)):
    _seed_settings(db)
    return [{"key": s.key, "value": s.value, "description": s.description} for s in db.query(Setting).all()]

@router.put("/settings/{key}")
def update_setting(key: str, payload: SettingUpdate, db: Session = Depends(get_db)):
    s = db.get(Setting, key)
    if not s:
        raise HTTPException(404, "Setting not found")
    if key == "block_plugin_id" and payload.value:
        plugin = state._plugin_registry.get(payload.value)
        if not plugin:
            raise HTTPException(400, f"Plugin '{payload.value}' not found")
        if not plugin.get("enabled"):
            raise HTTPException(400, f"Plugin '{payload.value}' is not enabled")
        caps = plugin["manifest"].get("capabilities", [])
        if "blocking" not in caps:
            raise HTTPException(400, f"Plugin '{payload.value}' does not declare the 'blocking' capability")
        actions = plugin["manifest"].get("actions") or {}
        if "block_client" not in actions or "unblock_client" not in actions:
            raise HTTPException(400, f"Plugin '{payload.value}' must define both block_client and unblock_client actions")
    s.value = payload.value
    db.commit()
    return {"key": key, "value": s.value}


@router.post("/settings/reset")
def reset_settings(db: Session = Depends(get_db)):
    for key, (value, _) in DEFAULT_SETTINGS.items():
        s = db.get(Setting, key)
        if s:
            s.value = value
    db.commit()
    _seed_settings(db)
    return {"reset": True}


@router.post("/settings/apply")
async def apply_settings(db: Session = Depends(get_db)):
    _seed_settings(db)
    settings = {s.key: s.value for s in db.query(Setting).all()}
    payload = {}

    if "scan_interval" in settings:
        payload["scan_interval"] = int(settings["scan_interval"])
    if "presence_grace_seconds" in settings:
        payload["presence_grace_seconds"] = int(settings["presence_grace_seconds"])
    if "offline_miss_threshold" in settings:
        payload["offline_miss_threshold"] = int(settings["offline_miss_threshold"])
    if "sniffer_workers" in settings:
        payload["sniffer_workers"] = int(settings["sniffer_workers"])
    if "arp_scan_retry" in settings:
        payload["arp_scan_retry"] = int(settings["arp_scan_retry"])
    if "primary_ip_mode" in settings:
        payload["primary_ip_mode"] = settings["primary_ip_mode"]
    if "ip_range" in settings:
        payload["ip_range"] = settings["ip_range"]
    if "nuclei_template_update_interval" in settings:
        payload["nuclei_template_update_interval"] = settings["nuclei_template_update_interval"]
    # Here Be Dragons — forward immediately to probe
    for key in (
        "enable_arp_sweep", "enable_passive_sniffer", "sniffer_subnet_filter",
        "enable_hostname_resolution", "hostname_cooldown_hours",
        "enable_port_scanning", "port_scan_method", "port_scan_workers", "gateway_scan_workers",
        "enable_service_fingerprinting", "enable_mdns",
        "enable_nightly_scan", "enable_unscanned_retry",
        "probe_interface", "dns_server",
        "auto_group_by_hostname", "scan_grouped_members",
    ):
        if key in settings:
            payload[key] = settings[key]

    try:
        async with _probe_client(timeout=15.0) as client:
            resp = await client.post(f"{PROBE_URL}/config/reload", json=payload)
            body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"raw": resp.text}
            if resp.status_code >= 400:
                raise HTTPException(resp.status_code, f"Probe rejected settings apply: {body}")
            return {"applied": True, "probe_response": body}
    except httpx.ConnectError:
        raise HTTPException(502, f"Cannot reach probe at {PROBE_URL}")


@router.post("/settings/restart-probe")
async def restart_probe(username: str = Depends(get_current_user)):
    """Tell the probe to exit — Docker restart policy brings it back."""
    try:
        async with _probe_client(timeout=5.0) as client:
            r = await client.post(f"{PROBE_URL}/restart")
            r.raise_for_status()
            return {"ok": True}
    except httpx.ConnectError:
        raise HTTPException(502, f"Cannot reach probe at {PROBE_URL}")
    except Exception as exc:
        raise HTTPException(500, str(exc))


@router.post("/settings/restart-backend")
async def restart_backend(username: str = Depends(get_current_user)):
    """Exit this process — Docker restart policy brings it back."""
    import signal as _sig
    def _do():
        import time as _t
        _t.sleep(0.5)
        os.kill(os.getpid(), _sig.SIGTERM)
    import threading as _th
    _th.Thread(target=_do, daemon=True).start()
    return {"ok": True, "restarting": True}
