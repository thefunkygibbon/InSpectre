from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Request
from sqlalchemy import text
from sqlalchemy.orm import Session
import asyncio, json, os, zipfile, io, tempfile
from database import get_db, SessionLocal
from auth_utils import get_current_user
from models import Setting
from schemas import PluginConfigSave
from plugin_engine import (
    validate_manifest, PluginValidationError,
    encrypt_field, decrypt_field, get_decrypted_config,
    verify_webhook_signature,
)
import state
from ha_mqtt import _ha_startup_connect

router = APIRouter()


def _redact_plugin_config(manifest: dict, config: dict) -> dict:
    redacted = dict(config)
    for field in manifest.get("config_schema", []):
        if field.get("type") == "password" and redacted.get(field["key"]):
            redacted[field["key"]] = "**redacted**"
    return redacted


def _plugin_to_dict(plugin_info: dict) -> dict:
    manifest = plugin_info["manifest"]
    return {
        "id":                plugin_info["id"],
        "name":              manifest.get("name"),
        "version":           manifest.get("version"),
        "author":            manifest.get("author"),
        "description":       manifest.get("description"),
        "icon":              manifest.get("icon"),
        "homepage":          manifest.get("homepage"),
        "capabilities":      manifest.get("capabilities", []),
        "source":            plugin_info["source"],
        "enabled":           plugin_info["enabled"],
        "status":            plugin_info["status"],
        "last_error":        plugin_info["last_error"],
        "last_polled":       plugin_info.get("last_polled"),
        "last_device_count": plugin_info.get("last_device_count"),
        "config":            _redact_plugin_config(manifest, plugin_info.get("config") or {}),
        "manifest":          manifest,
    }


@router.get("/plugins")
def list_plugins(username: str = Depends(get_current_user)):
    return [_plugin_to_dict(p) for p in state._plugin_registry.list_all()]


@router.get("/plugins/{plugin_id}")
def get_plugin(plugin_id: str, username: str = Depends(get_current_user)):
    plugin = state._plugin_registry.get(plugin_id)
    if not plugin:
        raise HTTPException(404, "Plugin not found")
    return _plugin_to_dict({"id": plugin_id, **plugin})


@router.post("/plugins/upload", status_code=201)
async def upload_plugin(
    file: UploadFile = File(...),
    username: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    content = await file.read()
    fname   = file.filename or ""
    try:
        if fname.endswith((".yaml", ".yml")):
            try:
                import yaml as _yaml
                manifest = _yaml.safe_load(content)
            except ImportError:
                raise HTTPException(
                    400, "YAML support requires pyyaml — upload as JSON instead"
                )
        else:
            manifest = json.loads(content)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, f"Could not parse manifest: {exc}")

    try:
        validate_manifest(manifest)
    except PluginValidationError as exc:
        raise HTTPException(400, str(exc))

    pid = manifest["id"]
    existing = state._plugin_registry.get(pid)
    if existing and existing["source"] == "builtin":
        raise HTTPException(400, f"Plugin ID '{pid}' conflicts with a built-in plugin")

    try:
        state._plugin_registry.add_uploaded(manifest)
        db.execute(
            text("""
                INSERT INTO plugins
                    (plugin_id, display_name, version, enabled,
                     manifest, config, install_source, status)
                VALUES (:pid, :name, :ver, false,
                        CAST(:manifest AS jsonb), CAST('{}' AS jsonb), 'uploaded', 'disabled')
                ON CONFLICT (plugin_id) DO UPDATE
                    SET manifest = EXCLUDED.manifest,
                        display_name = EXCLUDED.display_name,
                        version = EXCLUDED.version
            """),
            {
                "pid":      pid,
                "name":     manifest.get("name", pid),
                "ver":      manifest.get("version", "1.0.0"),
                "manifest": json.dumps(manifest),
            },
        )
        db.commit()
    except PluginValidationError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        db.rollback()
        state._plugin_registry.remove(pid)
        raise HTTPException(500, f"Database error: {exc}")

    return {"id": pid, "name": manifest.get("name"), "status": "disabled"}


@router.put("/plugins/{plugin_id}/config")
def save_plugin_config(
    plugin_id: str,
    payload: PluginConfigSave,
    username: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    plugin = state._plugin_registry.get(plugin_id)
    if not plugin:
        raise HTTPException(404, "Plugin not found")

    manifest      = plugin["manifest"]
    existing_cfg  = plugin.get("config") or {}
    password_keys = {
        f["key"] for f in manifest.get("config_schema", [])
        if f.get("type") == "password"
    }

    encrypted = dict(payload.config)
    for key in password_keys:
        val = encrypted.get(key, "")
        if val == "**redacted**":
            encrypted[key] = existing_cfg.get(key, "")  # keep existing encrypted value
        elif val:
            encrypted[key] = encrypt_field(val)

    # For the HA plugin: keep legacy settings table in sync
    if plugin_id == "home-assistant":
        ha_mapping = {
            "host":             "ha_mqtt_host",
            "port":             "ha_mqtt_port",
            "user":             "ha_mqtt_user",
            "password":         "ha_mqtt_password",
            "discovery_prefix": "ha_mqtt_discovery_prefix",
            "state_prefix":     "ha_mqtt_state_prefix",
        }
        for cfg_key, setting_key in ha_mapping.items():
            val = encrypted.get(cfg_key, "")
            if cfg_key == "password" and val:
                val = decrypt_field(val)  # settings table stores plaintext
            s = db.get(Setting, setting_key)
            if s:
                s.value = str(val)
            else:
                db.add(Setting(key=setting_key, value=str(val), description=""))

    try:
        db.execute(
            text("UPDATE plugins SET config = CAST(:cfg AS jsonb) WHERE plugin_id = :pid"),
            {"cfg": json.dumps(encrypted), "pid": plugin_id},
        )
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(500, f"Failed to save plugin config: {exc}")
    state._plugin_registry.update_config(plugin_id, encrypted)
    state._plugin_runner.clear_session(plugin_id)
    return {"ok": True}


@router.patch("/plugins/{plugin_id}/enable")
def enable_plugin(
    plugin_id: str,
    username: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    plugin = state._plugin_registry.get(plugin_id)
    if not plugin:
        raise HTTPException(404, "Plugin not found")

    db.execute(
        text("UPDATE plugins SET enabled = true, status = 'active' WHERE plugin_id = :pid"),
        {"pid": plugin_id},
    )
    # For HA plugin: keep legacy enabled setting in sync and start connection
    if plugin_id == "home-assistant":
        s = db.get(Setting, "ha_mqtt_enabled")
        if s:
            s.value = "true"
        else:
            db.add(Setting(key="ha_mqtt_enabled", value="true", description=""))
    db.commit()
    state._plugin_registry.set_enabled(plugin_id, True, "active")

    if plugin_id == "home-assistant":
        db2 = SessionLocal()
        try:
            _ha_startup_connect(db2)
        finally:
            db2.close()

    return {"ok": True, "enabled": True}


@router.patch("/plugins/{plugin_id}/disable")
def disable_plugin(
    plugin_id: str,
    username: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    plugin = state._plugin_registry.get(plugin_id)
    if not plugin:
        raise HTTPException(404, "Plugin not found")

    db.execute(
        text("UPDATE plugins SET enabled = false, status = 'disabled' WHERE plugin_id = :pid"),
        {"pid": plugin_id},
    )
    if plugin_id == "home-assistant":
        s = db.get(Setting, "ha_mqtt_enabled")
        if s:
            s.value = "false"
        state._ha_mqtt.disconnect()
    db.commit()
    state._plugin_registry.set_enabled(plugin_id, False, "disabled")
    state._plugin_runner.clear_session(plugin_id)
    return {"ok": True, "enabled": False}


@router.delete("/plugins/{plugin_id}")
def delete_plugin(
    plugin_id: str,
    username: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    plugin = state._plugin_registry.get(plugin_id)
    if not plugin:
        raise HTTPException(404, "Plugin not found")
    if plugin["source"] == "builtin":
        raise HTTPException(400, "Built-in plugins cannot be deleted — disable them instead")

    db.execute(text("DELETE FROM plugins WHERE plugin_id = :pid"), {"pid": plugin_id})
    db.execute(text("DELETE FROM plugin_device_data WHERE plugin_id = :pid"), {"pid": plugin_id})
    db.commit()
    state._plugin_registry.remove(plugin_id)
    return {"ok": True}


@router.post("/plugins/{plugin_id}/test")
async def test_plugin_connection(
    plugin_id: str,
    username: str = Depends(get_current_user),
):
    plugin = state._plugin_registry.get(plugin_id)
    if not plugin:
        raise HTTPException(404, "Plugin not found")
    result = await state._plugin_runner.execute_action(plugin_id, "test_connection")
    return result


@router.post("/plugins/{plugin_id}/poll")
async def poll_plugin_now(
    plugin_id: str,
    username: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Manually trigger the plugin's polling action and upsert discovered devices immediately."""
    plugin = state._plugin_registry.get(plugin_id)
    if not plugin:
        raise HTTPException(404, "Plugin not found")
    polling = plugin["manifest"].get("polling") or {}
    action  = polling.get("action")
    actions = polling.get("actions") or ([action] if action else [])
    if not actions:
        raise HTTPException(400, "This plugin has no polling action configured")
    await state._plugin_scheduler._poll_plugin(plugin_id, actions)
    updated = state._plugin_registry.get(plugin_id)
    ok = updated.get("status") == "active"
    return {
        "ok":                ok,
        "status":            updated.get("status"),
        "error":             updated.get("last_error") if not ok else None,
        "last_device_count": updated.get("last_device_count"),
    }


@router.get("/plugins/{plugin_id}/data")
def get_plugin_data(
    plugin_id: str,
    username: str = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = db.execute(
        text("""
            SELECT mac_address, data, updated_at
            FROM plugin_device_data
            WHERE plugin_id = :pid
            ORDER BY updated_at DESC
        """),
        {"pid": plugin_id},
    ).fetchall()
    return [
        {
            "mac":        r.mac_address,
            "data":       r.data,
            "updated_at": r.updated_at.isoformat() if r.updated_at else None,
        }
        for r in rows
    ]


@router.post("/plugins/{plugin_id}/webhook")
async def plugin_webhook(plugin_id: str, request: Request, db: Session = Depends(get_db)):
    plugin = state._plugin_registry.get(plugin_id)
    if not plugin or not plugin.get("enabled"):
        raise HTTPException(404, "Plugin not found or disabled")

    body_bytes = await request.body()

    # Optional HMAC-SHA256 signature validation
    cfg = get_decrypted_config(plugin["manifest"], plugin.get("config") or {})
    secret = cfg.get("webhook_secret", "")
    if secret:
        sig_header = request.headers.get("X-Hub-Signature-256", "")
        if not verify_webhook_signature(body_bytes, secret, sig_header):
            raise HTTPException(403, "Invalid webhook signature")

    try:
        payload = json.loads(body_bytes) if body_bytes else {}
    except Exception:
        raise HTTPException(400, "Invalid JSON payload")

    # Find the action marked trigger=webhook
    actions = plugin["manifest"].get("actions") or {}
    action_def = next(
        (a for a in actions.values() if a.get("trigger") == "webhook"),
        None,
    )
    if not action_def:
        raise HTTPException(422, "No webhook-triggered action defined in plugin manifest")

    action_name = next(k for k, v in actions.items() if v is action_def)

    result = await state._plugin_runner.execute_action(plugin_id, action_name, payload)
    if not result.get("ok"):
        raise HTTPException(502, result.get("error", "Plugin action failed"))

    # Feed discovered devices into the event bus
    for dev in (result.get("devices") or []):
        mac = dev.get("mac_address", "")
        if mac:
            event = "device.online" if dev.get("is_online", True) else "device.offline"
            asyncio.ensure_future(state._plugin_event_bus.notify(event, {
                "mac": mac, "ip": dev.get("ip_address", ""), "name": dev.get("hostname", ""),
            }))

    return {"ok": True, "devices_received": len(result.get("devices") or [])}
