"""
InSpectre Plugin Engine
-----------------------
PluginRegistry  — loads, validates, and maintains the in-memory plugin catalogue.
PluginRunner    — executes plugin actions (HTTP or delegated to HAMQTTManager).
PluginEventBus  — routes InSpectre events to matching plugin hooks.
PluginScheduler — polls plugins that have a polling block configured.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx
from sqlalchemy import text
from sqlalchemy.orm import Session

BUILTIN_DIR = os.path.join(os.path.dirname(__file__), "plugins", "builtin")

VALID_CAPABILITIES = frozenset([
    "discovery", "blocking", "enrichment", "dns",
    "presence", "traffic", "export", "notification",
])
VALID_FIELD_TYPES = frozenset([
    "string", "password", "integer", "boolean",
    "select", "multiline", "url",
])
VALID_EVENT_KEYS = frozenset([
    "device.new", "device.online", "device.offline",
    "port.opened", "vuln.found", "vuln.critical", "vuln.high",
])
VALID_AUTH_METHODS = frozenset([
    "none", "basic", "bearer", "cookie",
    "api-key-header", "api-key-param",
])
VALID_URL_SCHEMES = frozenset(["http", "https", "mqtt", "mqtts"])


# ---------------------------------------------------------------------------
# Encryption helpers (Fernet with SECRET_KEY-derived key)
# ---------------------------------------------------------------------------

def _get_secret_key() -> str:
    return os.environ.get("SECRET_KEY", "CHANGE_ME_IN_PRODUCTION_use_a_long_random_string")


def _fernet():
    from cryptography.fernet import Fernet
    key_bytes = hashlib.sha256(_get_secret_key().encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key_bytes))


def encrypt_field(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt_field(value: str) -> str:
    try:
        return _fernet().decrypt(value.encode()).decode()
    except Exception:
        return value  # Already plaintext (e.g. migrated from legacy settings)


def get_decrypted_config(manifest: dict, stored_config: dict) -> dict:
    result = dict(stored_config)
    password_keys = {
        f["key"] for f in manifest.get("config_schema", [])
        if f.get("type") == "password"
    }
    for key in password_keys:
        if key in result and result[key]:
            result[key] = decrypt_field(result[key])
    return result


# ---------------------------------------------------------------------------
# Manifest validation
# ---------------------------------------------------------------------------

class PluginValidationError(Exception):
    pass


def validate_manifest(m: dict):
    """Validate a plugin manifest dict. Raises PluginValidationError on failure."""
    for field in ("id", "name", "version", "capabilities", "config_schema"):
        if field not in m:
            raise PluginValidationError(f"Missing required field: '{field}'")

    pid = m["id"]
    if not re.match(r'^[a-z0-9][a-z0-9\-]*[a-z0-9]$', pid) and not re.match(r'^[a-z0-9]$', pid):
        raise PluginValidationError(
            "Plugin ID must be lowercase alphanumeric with optional hyphens (e.g. my-plugin)"
        )

    for cap in m.get("capabilities", []):
        if cap not in VALID_CAPABILITIES:
            raise PluginValidationError(
                f"Unknown capability '{cap}'. Valid: {sorted(VALID_CAPABILITIES)}"
            )

    for field in m.get("config_schema", []):
        if "key" not in field or "label" not in field:
            raise PluginValidationError("Each config_schema field must have 'key' and 'label'")
        ftype = field.get("type", "string")
        if ftype not in VALID_FIELD_TYPES:
            raise PluginValidationError(
                f"Unknown field type '{ftype}'. Valid: {sorted(VALID_FIELD_TYPES)}"
            )

    endpoints = m.get("endpoints") or {}
    base_url = endpoints.get("base_url", "")
    if base_url:
        clean = re.sub(r'\{[^}]+\}', 'x', base_url)
        scheme = urlparse(clean).scheme
        if scheme and scheme not in VALID_URL_SCHEMES:
            raise PluginValidationError(
                f"Invalid URL scheme '{scheme}'. Allowed: {sorted(VALID_URL_SCHEMES)}"
            )

    auth = endpoints.get("auth", "none")
    if auth not in VALID_AUTH_METHODS:
        raise PluginValidationError(
            f"Unknown auth method '{auth}'. Valid: {sorted(VALID_AUTH_METHODS)}"
        )

    for event_key in (m.get("event_hooks") or {}).keys():
        if event_key not in VALID_EVENT_KEYS:
            raise PluginValidationError(
                f"Unknown event hook '{event_key}'. Valid: {sorted(VALID_EVENT_KEYS)}"
            )


# ---------------------------------------------------------------------------
# PluginRegistry
# ---------------------------------------------------------------------------

class PluginRegistry:
    def __init__(self):
        self._plugins: dict[str, dict] = {}

    def load_all(self, db: Session):
        # ── Built-in plugins from disk ───────────────────────────────────────
        # Phase 1: parse & validate manifests from disk — always succeeds or skips
        builtins: list[dict] = []
        if os.path.isdir(BUILTIN_DIR):
            for fname in sorted(os.listdir(BUILTIN_DIR)):
                if not fname.endswith(".json"):
                    continue
                path = os.path.join(BUILTIN_DIR, fname)
                try:
                    with open(path) as f:
                        manifest = json.load(f)
                    validate_manifest(manifest)
                    builtins.append(manifest)
                except Exception as exc:
                    print(f"[plugins] Skipping invalid manifest {fname}: {exc}", flush=True)
        else:
            print(f"[plugins] WARNING: builtin dir not found: {BUILTIN_DIR}", flush=True)

        # Phase 2: register each builtin with defaults first, then try DB sync
        for manifest in builtins:
            pid = manifest["id"]
            # Always register with defaults so the plugin is visible even if DB fails
            self._plugins[pid] = {
                "manifest":   manifest,
                "config":     {},
                "source":     "builtin",
                "enabled":    False,
                "status":     "disabled",
                "last_error": None,
            }
            # Now try to read/write DB state
            try:
                row = db.execute(
                    text(
                        "SELECT config, enabled, status, last_error"
                        " FROM plugins WHERE plugin_id = :pid"
                    ),
                    {"pid": pid},
                ).fetchone()

                if row:
                    self._plugins[pid].update({
                        "config":     row.config or {},
                        "enabled":    bool(row.enabled),
                        "status":     row.status or "disabled",
                        "last_error": row.last_error,
                    })
                else:
                    db.execute(
                        text("""
                            INSERT INTO plugins
                                (plugin_id, display_name, version, enabled,
                                 manifest, config, install_source, status)
                            VALUES (:pid, :name, :ver, false,
                                    CAST(:manifest AS jsonb), CAST('{}' AS jsonb),
                                    'builtin', 'disabled')
                            ON CONFLICT (plugin_id) DO NOTHING
                        """),
                        {
                            "pid":      pid,
                            "name":     manifest.get("name", pid),
                            "ver":      manifest.get("version", "1.0.0"),
                            "manifest": json.dumps(manifest),
                        },
                    )
                    db.commit()
                print(f"[plugins] Loaded built-in: {pid}", flush=True)
            except Exception as exc:
                print(f"[plugins] DB sync failed for {pid} (plugin still registered): {exc}", flush=True)
                try:
                    db.rollback()
                except Exception:
                    pass

        # ── User-uploaded plugins from DB ─────────────────────────────────────
        try:
            rows = db.execute(
                text(
                    "SELECT plugin_id, manifest, config, enabled, status, last_error"
                    " FROM plugins WHERE install_source = 'uploaded'"
                )
            ).fetchall()
        except Exception as exc:
            print(f"[plugins] Could not load uploaded plugins (table missing?): {exc}", flush=True)
            rows = []
        for row in rows:
            try:
                manifest = (
                    row.manifest
                    if isinstance(row.manifest, dict)
                    else json.loads(row.manifest)
                )
                validate_manifest(manifest)
                self._plugins[row.plugin_id] = {
                    "manifest":   manifest,
                    "config":     row.config or {},
                    "source":     "uploaded",
                    "enabled":    bool(row.enabled),
                    "status":     row.status or "disabled",
                    "last_error": row.last_error,
                }
            except Exception as exc:
                print(
                    f"[plugins] Failed to reload uploaded plugin {row.plugin_id}: {exc}",
                    flush=True,
                )

    def get(self, plugin_id: str) -> Optional[dict]:
        return self._plugins.get(plugin_id)

    def list_all(self) -> list:
        return [{"id": pid, **info} for pid, info in self._plugins.items()]

    def update_config(self, plugin_id: str, config: dict):
        if plugin_id in self._plugins:
            self._plugins[plugin_id]["config"] = config

    def set_enabled(self, plugin_id: str, enabled: bool, status: Optional[str] = None):
        if plugin_id in self._plugins:
            self._plugins[plugin_id]["enabled"] = enabled
            if status is not None:
                self._plugins[plugin_id]["status"] = status

    def set_status(self, plugin_id: str, status: str, error: Optional[str] = None):
        if plugin_id in self._plugins:
            self._plugins[plugin_id]["status"] = status
            self._plugins[plugin_id]["last_error"] = error

    def add_uploaded(self, manifest: dict) -> str:
        validate_manifest(manifest)
        pid = manifest["id"]
        if pid in self._plugins and self._plugins[pid]["source"] == "builtin":
            raise PluginValidationError(
                f"Plugin ID '{pid}' conflicts with a built-in plugin"
            )
        self._plugins[pid] = {
            "manifest":   manifest,
            "config":     {},
            "source":     "uploaded",
            "enabled":    False,
            "status":     "disabled",
            "last_error": None,
        }
        return pid

    def remove(self, plugin_id: str):
        self._plugins.pop(plugin_id, None)


# ---------------------------------------------------------------------------
# PluginRunner
# ---------------------------------------------------------------------------

class PluginRunner:
    def __init__(self, registry: PluginRegistry, ha_mqtt=None):
        self._registry   = registry
        self._ha_mqtt    = ha_mqtt
        self._rate_limits: dict[str, float] = {}

    async def execute_action(
        self,
        plugin_id: str,
        action_name: str,
        context: Optional[dict] = None,
    ) -> dict:
        plugin = self._registry.get(plugin_id)
        if not plugin:
            return {"ok": False, "error": "Plugin not found"}

        manifest = plugin["manifest"]
        config   = get_decrypted_config(manifest, plugin.get("config") or {})

        # Delegate built-in MQTT plugin to HAMQTTManager
        if plugin_id == "home-assistant":
            return await self._execute_ha_action(action_name, config, context or {})

        actions = manifest.get("actions") or {}
        if action_name not in actions:
            return {"ok": False, "error": f"Action '{action_name}' not defined in manifest"}

        endpoints = manifest.get("endpoints") or {}
        base_url  = self._sub(endpoints.get("base_url", ""), config)
        path      = self._sub((actions[action_name]).get("path", ""), config)
        url       = base_url + path

        scheme = urlparse(url).scheme
        if scheme not in ("http", "https"):
            return {"ok": False, "error": f"Rejected URL scheme '{scheme}' — only http/https allowed"}

        # Rate limiting
        max_rate = (manifest.get("polling") or {}).get("max_rate_per_minute")
        if max_rate:
            now  = datetime.now(timezone.utc).timestamp()
            last = self._rate_limits.get(plugin_id, 0.0)
            if (now - last) < (60.0 / float(max_rate)):
                return {"ok": False, "error": "Rate limit exceeded"}
            self._rate_limits[plugin_id] = now

        method   = actions[action_name].get("method", "GET").upper()
        body_tpl = actions[action_name].get("body")
        body     = (
            json.loads(self._sub(json.dumps(body_tpl), config))
            if body_tpl
            else None
        )

        headers = dict(endpoints.get("headers") or {})
        self._apply_auth(headers, endpoints.get("auth", "none"), config)

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.request(method, url, json=body, headers=headers)
            resp.raise_for_status()
            data = resp.json() if resp.content else {}
            return {"ok": True, "data": data}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    async def _execute_ha_action(self, action_name: str, config: dict, context: dict) -> dict:
        ha = self._ha_mqtt
        if ha is None:
            return {"ok": False, "error": "HA MQTT manager not available"}

        if action_name == "test_connection":
            host = (config.get("host") or "").strip()
            if not host:
                return {"ok": False, "error": "No broker host configured"}
            try:
                ha.connect(
                    host             = host,
                    port             = int(config.get("port") or 1883),
                    user             = config.get("user", ""),
                    password         = config.get("password", ""),
                    discovery_prefix = config.get("discovery_prefix", "homeassistant"),
                    state_prefix     = config.get("state_prefix", "inspectre"),
                )
                import time
                time.sleep(1.5)
                ok = ha.connected
                return {"ok": ok, "error": None if ok else "MQTT connection refused or timed out"}
            except Exception as exc:
                return {"ok": False, "error": str(exc)}

        if not ha.connected:
            return {"ok": False, "error": "MQTT not connected — save config and use Test Connection first"}

        mac   = context.get("mac")
        name  = context.get("name")
        ip    = context.get("ip")
        ports = context.get("ports")
        vulns = context.get("vulns")

        try:
            if action_name == "publish_device_joined":
                ha.pub_device_discovery(mac, name, ip)
                ha.pub_device_state(mac, True, ip, ports, vulns, is_new=True)
            elif action_name == "publish_device_online":
                ha.pub_device_state(mac, True, ip, ports, vulns)
            elif action_name == "publish_device_offline":
                ha.pub_device_state(mac, False, ip)
            elif action_name == "publish_port_change":
                ha.pub_device_state(mac, True, open_ports=ports)
            elif action_name == "publish_vuln_change":
                ha.pub_device_state(mac, True, vulns=vulns)
            elif action_name == "publish_device_renamed":
                ha.pub_device_discovery(mac, name, ip)
            return {"ok": True}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    @staticmethod
    def _sub(template: str, config: dict) -> str:
        def replace(m):
            return str(config.get(m.group(1), m.group(0)))
        return re.sub(r'\{(\w+)\}', replace, template)

    @staticmethod
    def _apply_auth(headers: dict, method: str, config: dict):
        if method == "basic":
            import base64 as _b64
            creds = _b64.b64encode(
                f"{config.get('user', '')}:{config.get('password', '')}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {creds}"
        elif method == "bearer":
            headers["Authorization"] = f"Bearer {config.get('token', '')}"
        elif method == "api-key-header":
            key_name = config.get("api_key_header", "X-API-Key")
            headers[key_name] = config.get("api_key", "")


# ---------------------------------------------------------------------------
# PluginEventBus
# ---------------------------------------------------------------------------

class PluginEventBus:
    def __init__(self, registry: PluginRegistry, runner: PluginRunner):
        self._registry = registry
        self._runner   = runner

    async def notify(self, event_type: str, context: dict):
        for plugin_info in self._registry.list_all():
            if not plugin_info.get("enabled"):
                continue
            hooks       = plugin_info["manifest"].get("event_hooks") or {}
            action_name = hooks.get(event_type)
            if not action_name:
                continue
            pid = plugin_info["id"]
            try:
                asyncio.ensure_future(
                    self._runner.execute_action(pid, action_name, context)
                )
            except Exception as exc:
                print(f"[plugin-bus] {event_type} → {pid}: {exc}", flush=True)


# ---------------------------------------------------------------------------
# PluginScheduler
# ---------------------------------------------------------------------------

class PluginScheduler:
    def __init__(self, registry: PluginRegistry, runner: PluginRunner, db_factory):
        self._registry   = registry
        self._runner     = runner
        self._db_factory = db_factory
        self._last_poll: dict[str, float] = {}

    async def run(self):
        await asyncio.sleep(30)  # startup grace period
        while True:
            try:
                now = datetime.now(timezone.utc).timestamp()
                for plugin_info in self._registry.list_all():
                    if not plugin_info.get("enabled"):
                        continue
                    polling  = plugin_info["manifest"].get("polling") or {}
                    action   = polling.get("action")
                    if not action:
                        continue
                    interval = float(polling.get("interval_seconds") or 300)
                    pid      = plugin_info["id"]
                    if (now - self._last_poll.get(pid, 0.0)) >= interval:
                        self._last_poll[pid] = now
                        asyncio.ensure_future(self._poll_plugin(pid, action))
            except Exception as exc:
                print(f"[plugin-scheduler] {exc}", flush=True)
            await asyncio.sleep(30)

    async def _poll_plugin(self, plugin_id: str, action: str):
        result = await self._runner.execute_action(plugin_id, action)
        db = self._db_factory()
        try:
            if result.get("ok"):
                db.execute(
                    text(
                        "UPDATE plugins SET last_polled = NOW(), status = 'active',"
                        " last_error = NULL WHERE plugin_id = :pid"
                    ),
                    {"pid": plugin_id},
                )
                self._registry.set_status(plugin_id, "active")
            else:
                err = result.get("error", "Unknown error")
                db.execute(
                    text(
                        "UPDATE plugins SET last_polled = NOW(), status = 'error',"
                        " last_error = :err WHERE plugin_id = :pid"
                    ),
                    {"pid": plugin_id, "err": err},
                )
                self._registry.set_status(plugin_id, "error", err)
            db.commit()
        except Exception as exc:
            print(f"[plugin-scheduler] DB error for {plugin_id}: {exc}", flush=True)
            db.rollback()
        finally:
            db.close()
