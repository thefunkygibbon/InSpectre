from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
import json, os
from database import get_db
from auth_utils import get_current_user, _has_any_user, _hash_password, _create_token
from config import PROBE_URL
from probe_client import _probe_client
from models import Setting
from schemas import SetupUserRequest, SetupNetworkRequest, SetupCompleteRequest

router = APIRouter()


@router.get("/setup/status")
def setup_status(db: Session = Depends(get_db)):
    """Returns whether setup is complete and whether any users exist."""
    has_user = _has_any_user(db)
    s = db.get(Setting, "setup_complete")
    setup_done = (s.value if s else "false") == "true"
    # Auto-heal: a user already exists but setup_complete was never set to true.
    # This happens when restoring a DB or if the wizard flow was interrupted.
    if has_user and not setup_done:
        if s:
            s.value = "true"
        else:
            db.add(Setting(key="setup_complete", value="true",
                           description="Whether the initial setup wizard has been completed."))
        db.commit()
        setup_done = True
    is_appliance = os.path.exists("/opt/inspectre/appliance.json")
    return {"setup_complete": setup_done, "has_user": has_user, "is_appliance": is_appliance}


@router.post("/setup/create-user")
def setup_create_user(payload: SetupUserRequest, db: Session = Depends(get_db)):
    """Create the first admin user. Only works if no users exist yet."""
    if _has_any_user(db):
        raise HTTPException(403, "Setup already completed — users exist")
    if len(payload.username.strip()) < 3:
        raise HTTPException(400, "Username must be at least 3 characters")
    if len(payload.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    pw_hash = _hash_password(payload.password)
    try:
        db.execute(
            text("INSERT INTO users (username, password_hash, is_admin) VALUES (:u, :h, TRUE)"),
            {"u": payload.username.strip().lower(), "h": pw_hash}
        )
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(500, f"Could not create user: {e}")
    token = _create_token(payload.username.strip().lower())
    return {"ok": True, "token": token, "username": payload.username.strip().lower()}


@router.get("/setup/network-info")
async def setup_network_info():
    """Proxy network detection to the probe — it runs on the host network so its
    interface/route/IP info reflects the real LAN, not the Docker bridge."""
    try:
        async with _probe_client(timeout=5.0) as client:
            r = await client.get(f"{PROBE_URL}/network/info")
            r.raise_for_status()
            return r.json()
    except Exception:
        # Probe unreachable — return empty values; user can fill in manually
        return {"ip_range": None, "gateway": None, "dns_server": None, "interface": None}


@router.post("/setup/apply-network")
def setup_apply_network(payload: SetupNetworkRequest, db: Session = Depends(get_db)):
    """Save network settings confirmed in the wizard."""
    updates: dict[str, str] = {}
    if payload.ip_range:
        updates["ip_range"] = payload.ip_range
    if payload.dns_server:
        updates["dns_server"] = payload.dns_server  # stored for reference
    for key, value in updates.items():
        s = db.get(Setting, key)
        if s:
            s.value = value
        else:
            db.add(Setting(key=key, value=value))
    db.commit()
    return {"ok": True, "applied": updates}


@router.post("/setup/complete")
def setup_complete(
    payload: SetupCompleteRequest,
    username: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Finalise setup: apply notification/vuln settings and mark setup complete."""
    to_save = {
        "setup_complete":            "true",
        "notifications_enabled":     "true" if payload.notifications_enabled else "false",
        "vuln_scan_on_new_device":   "true" if payload.vuln_scan_on_new else "false",
        "vuln_scan_schedule":        payload.vuln_scan_schedule if payload.vuln_scan_enabled else "disabled",
        "docker_enabled":            "true" if payload.docker_enabled else "false",
    }
    if payload.ntfy_topic:
        to_save["ntfy_topic"] = payload.ntfy_topic
    if payload.ntfy_url:
        to_save["ntfy_url"] = payload.ntfy_url
    if payload.docker_host:
        to_save["docker_host"] = payload.docker_host
    if payload.fingerbank_api_key:
        to_save["fingerbank_api_key"] = payload.fingerbank_api_key
    if os.path.exists("/opt/inspectre/appliance.json"):
        to_save["timezone"]            = payload.timezone or "UTC"
        to_save["auto_update_enabled"] = "true" if payload.auto_update_enabled else "false"
        to_save["auto_update_hour"]    = str(max(0, min(23, payload.auto_update_hour)))
        to_save["auto_update_days"]    = json.dumps(payload.auto_update_days)
    for key, value in to_save.items():
        s = db.get(Setting, key)
        if s:
            s.value = value
        else:
            db.add(Setting(key=key, value=value))
    db.commit()

    # Write notification channel directly to notification_channels so it appears
    # in the Notifications settings panel immediately without requiring a restart.
    # Build list of (service, display_name, config_dict) tuples from wizard input.
    new_channels = []
    if payload.ntfy_topic.strip():
        new_channels.append(("ntfy", "ntfy", {
            "server": (payload.ntfy_url or "https://ntfy.sh").strip(),
            "topic":  payload.ntfy_topic.strip(),
        }))
    if payload.gotify_url.strip() and payload.gotify_token.strip():
        new_channels.append(("gotify", "Gotify", {
            "server": payload.gotify_url.strip(),
            "token":  payload.gotify_token.strip(),
        }))
    if payload.pushbullet_api_key.strip():
        new_channels.append(("pushbullet", "Pushbullet", {
            "api_key": payload.pushbullet_api_key.strip(),
        }))
    if payload.alert_webhook_url.strip():
        new_channels.append(("webhook", "Webhook", {
            "url": payload.alert_webhook_url.strip(),
        }))

    for svc, name, cfg in new_channels:
        # Replace any existing channel of the same service type so re-running
        # the wizard doesn't create duplicates.
        db.execute(text("DELETE FROM notification_channels WHERE service = :s"), {"s": svc})
        db.execute(
            text("INSERT INTO notification_channels (name, service, config, enabled) VALUES (:n, :s, :c, true)"),
            {"n": name, "s": svc, "c": json.dumps(cfg)},
        )
    if new_channels:
        db.commit()

    return {"ok": True, "setup_complete": True}
