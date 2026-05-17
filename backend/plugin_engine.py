"""
InSpectre Plugin Engine
-----------------------
PluginRegistry  — loads, validates, and maintains the in-memory plugin catalogue.
PluginRunner    — executes plugin actions (HTTP, file, SNMP, or delegated to HAMQTTManager).
PluginEventBus  — routes InSpectre events to matching plugin hooks.
PluginScheduler — polls plugins that have a polling block configured.
"""
from __future__ import annotations

import asyncio
import base64
import csv
import hashlib
import hmac
import io
import json
import os
import re
import time
from dataclasses import dataclass, field
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
    "select", "multiline", "url", "filepath",
])
VALID_EVENT_KEYS = frozenset([
    "device.new", "device.online", "device.offline",
    "port.opened", "vuln.found", "vuln.critical", "vuln.high",
])
VALID_AUTH_METHODS = frozenset([
    "none", "basic", "bearer", "cookie",
    "api-key-header", "api-key-param",
])
VALID_URL_SCHEMES = frozenset(["http", "https", "mqtt", "mqtts", "snmp", "snmps"])
VALID_FILE_FORMATS = frozenset(["dnsmasq", "isc_dhcp", "csv", "json"])

# InSpectre canonical device fields that data_mapping may write
INSPECTRE_DEVICE_FIELDS = frozenset([
    "mac_address", "ip_address", "hostname", "vendor",
    "device_type", "is_online", "vlan",
])

_MAX_CHAIN_DEPTH = 3

# Maps boolean response fields to (true_label, false_label) tag strings.
# e.g. Omada's "wireless": true  → tag "wireless", false → tag "wired"
BOOL_TAG_LABELS: dict[str, tuple[str, str]] = {
    "wireless": ("wireless", "wired"),
}


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
# MAC normalisation
# ---------------------------------------------------------------------------

def _normalise_mac(mac: str) -> Optional[str]:
    clean = re.sub(r'[:\-.\s]', '', mac.upper())
    if len(clean) != 12 or not re.match(r'^[0-9A-F]{12}$', clean):
        return None
    return ':'.join(clean[i:i+2] for i in range(0, 12, 2))


# ---------------------------------------------------------------------------
# Session store
# ---------------------------------------------------------------------------

@dataclass
class PluginSession:
    cookies: dict = field(default_factory=dict)
    bearer_token: Optional[str] = None
    token_expiry: Optional[float] = None   # unix timestamp; None = no expiry
    extras: dict = field(default_factory=dict)  # arbitrary extracted values

    def is_valid(self) -> bool:
        if self.token_expiry is not None:
            if time.time() >= self.token_expiry:
                return False
        return bool(self.cookies or self.bearer_token or self.extras)


# ---------------------------------------------------------------------------
# Manifest validation
# ---------------------------------------------------------------------------

class PluginValidationError(Exception):
    pass


def validate_manifest(m: dict):
    """Validate a plugin manifest dict. Raises PluginValidationError on failure."""
    for f in ("id", "name", "version", "capabilities", "config_schema"):
        if f not in m:
            raise PluginValidationError(f"Missing required field: '{f}'")

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

    for fld in m.get("config_schema", []):
        if "key" not in fld or "label" not in fld:
            raise PluginValidationError("Each config_schema field must have 'key' and 'label'")
        ftype = fld.get("type", "string")
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

    # Validate per-action fields
    for action_name, action_def in (m.get("actions") or {}).items():
        if not isinstance(action_def, dict):
            raise PluginValidationError(f"Action '{action_name}' must be a dict")
        dep = action_def.get("depends_on")
        if dep and dep not in (m.get("actions") or {}):
            raise PluginValidationError(
                f"Action '{action_name}' depends_on '{dep}' which is not defined"
            )
        fmt = action_def.get("file_format")
        if fmt and fmt not in VALID_FILE_FORMATS:
            raise PluginValidationError(
                f"Unknown file_format '{fmt}'. Valid: {sorted(VALID_FILE_FORMATS)}"
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
            self._plugins[pid] = {
                "manifest":   manifest,
                "config":     {},
                "source":     "builtin",
                "enabled":    False,
                "status":     "disabled",
                "last_error": None,
            }
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
        existing = self._plugins.get(pid, {})
        self._plugins[pid] = {
            "manifest":   manifest,
            "config":     existing.get("config") or {},
            "source":     "uploaded",
            "enabled":    existing.get("enabled", False),
            "status":     existing.get("status", "disabled"),
            "last_error": existing.get("last_error"),
        }
        return pid

    def remove(self, plugin_id: str):
        self._plugins.pop(plugin_id, None)


# ---------------------------------------------------------------------------
# PluginRunner
# ---------------------------------------------------------------------------

class PluginRunner:
    def __init__(self, registry: PluginRegistry, ha_mqtt=None):
        self._registry    = registry
        self._ha_mqtt     = ha_mqtt
        self._rate_limits: dict[str, float] = {}
        self._sessions:    dict[str, PluginSession] = {}
        self._logging_in:  set[str] = set()  # plugins currently mid-login; prevents recursive auto-login

    def clear_session(self, plugin_id: str):
        self._sessions.pop(plugin_id, None)

    # ── Public entry point ────────────────────────────────────────────────────

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

        if plugin_id == "home-assistant":
            return await self._execute_ha_action(action_name, config, context or {})

        actions = manifest.get("actions") or {}
        if action_name not in actions:
            return {"ok": False, "error": f"Action '{action_name}' not defined in manifest"}

        return await self._resolve_action(
            plugin_id, manifest, config, action_name, dict(context or {})
        )

    # ── Dependency chain resolver ─────────────────────────────────────────────

    async def _resolve_action(
        self,
        plugin_id: str,
        manifest: dict,
        config: dict,
        action_name: str,
        context: dict,
        _depth: int = 0,
    ) -> dict:
        if _depth > _MAX_CHAIN_DEPTH:
            return {"ok": False, "error": "Maximum action chain depth exceeded"}

        actions    = manifest.get("actions") or {}
        action_def = actions.get(action_name, {})
        dep_name   = action_def.get("depends_on")

        if dep_name:
            dep_result = await self._resolve_action(
                plugin_id, manifest, config, dep_name, context, _depth + 1
            )
            if not dep_result.get("ok"):
                return {
                    "ok": False,
                    "error": f"Dependency '{dep_name}' failed: {dep_result.get('error')}",
                }
            # Flatten dep result data into context for template substitution
            dep_data = dep_result.get("data")
            if isinstance(dep_data, dict):
                for k, v in dep_data.items():
                    context[f"{dep_name}.{k}"] = str(v) if not isinstance(v, (dict, list)) else json.dumps(v)
            elif isinstance(dep_data, list):
                for i, item in enumerate(dep_data[:10]):
                    if isinstance(item, dict):
                        for k, v in item.items():
                            context[f"{dep_name}.{i}.{k}"] = str(v) if not isinstance(v, (dict, list)) else json.dumps(v)
                # Convenience: first element's fields accessible without index too
                if dep_data and isinstance(dep_data[0], dict):
                    for k, v in dep_data[0].items():
                        context.setdefault(f"{dep_name}.{k}", str(v) if not isinstance(v, (dict, list)) else json.dumps(v))

        return await self._execute_single_action(
            plugin_id, manifest, config, action_name, context, _depth
        )

    # ── Single action executor ────────────────────────────────────────────────

    async def _execute_single_action(
        self,
        plugin_id: str,
        manifest: dict,
        config: dict,
        action_name: str,
        context: dict,
        _depth: int = 0,
    ) -> dict:
        actions    = manifest.get("actions") or {}
        action_def = actions.get(action_name, {})
        endpoints  = manifest.get("endpoints") or {}

        # ── File source ──────────────────────────────────────────────────────
        if action_def.get("source") == "file":
            return self._execute_file_action(action_def, config)

        # ── Build substitution context (merge session.extras so {omadacId}-style
        #    placeholders set by earlier dep actions are available in URLs/bodies)
        _pre_session = self._sessions.get(plugin_id)
        sub_ctx = dict(context)
        if _pre_session:
            sub_ctx.update(_pre_session.extras)

        # ── Build URL ────────────────────────────────────────────────────────
        base_url = self._sub(endpoints.get("base_url", ""), config, sub_ctx)
        path     = self._sub(action_def.get("path", ""), config, sub_ctx)
        url      = base_url + path

        parsed_scheme = urlparse(url).scheme

        # ── SNMP ─────────────────────────────────────────────────────────────
        if parsed_scheme in ("snmp", "snmps"):
            return await self._execute_snmp_action(url, action_def, config)

        # ── HTTP scheme gate ─────────────────────────────────────────────────
        if parsed_scheme not in ("http", "https"):
            return {"ok": False, "error": f"Rejected URL scheme '{parsed_scheme}'"}

        # ── Rate limiting ────────────────────────────────────────────────────
        max_rate = (manifest.get("polling") or {}).get("max_rate_per_minute")
        if max_rate:
            rate_key = f"{plugin_id}:{action_name}"
            now  = datetime.now(timezone.utc).timestamp()
            last = self._rate_limits.get(rate_key, 0.0)
            if (now - last) < (60.0 / float(max_rate)):
                return {"ok": False, "error": "Rate limit exceeded"}
            self._rate_limits[rate_key] = now

        # ── Session / auth ───────────────────────────────────────────────────
        auth_method = endpoints.get("auth", "none")
        session = self._sessions.get(plugin_id)

        # Auto-login if auth method requires a session and we don't have a valid one.
        # Guard with _logging_in to prevent recursive auto-login: pre-auth actions like
        # get_controller_id that run inside _auto_login's dep chain must NOT trigger
        # another auto-login themselves.
        if auth_method in ("bearer", "cookie") and action_name != "login":
            if (session is None or not session.is_valid()) and plugin_id not in self._logging_in:
                login_result = await self._auto_login(plugin_id, manifest, config, context)
                if not login_result.get("ok"):
                    return login_result
                session = self._sessions.get(plugin_id)
                # Rebuild sub_ctx and URL now that session.extras are populated
                sub_ctx = dict(context)
                if session:
                    sub_ctx.update(session.extras)
                url = (
                    self._sub(endpoints.get("base_url", ""), config, sub_ctx)
                    + self._sub(action_def.get("path", ""), config, sub_ctx)
                )

        method   = action_def.get("method", "GET").upper()
        body_tpl = action_def.get("body")
        body     = (
            json.loads(self._sub(json.dumps(body_tpl), config, sub_ctx))
            if body_tpl else None
        )

        headers = dict(endpoints.get("headers") or {})
        cookies: dict = {}

        if auth_method == "cookie" and session:
            cookies = dict(session.cookies)
        elif auth_method == "bearer" and session and session.bearer_token:
            headers["Authorization"] = f"Bearer {session.bearer_token}"
        else:
            self._apply_auth(headers, auth_method, config, session)

        # Inject session extras as custom headers per manifest session_headers map
        # e.g. {"loginToken": "Csrf-Token"} injects session.extras["loginToken"] as "Csrf-Token"
        session_header_map = endpoints.get("session_headers") or {}
        if session_header_map and session:
            for extras_key, header_name in session_header_map.items():
                val = session.extras.get(extras_key)
                if val:
                    headers[header_name] = str(val)

        # Resolve SSL verification: config key wins, then manifest endpoints default
        _ssl_raw = config.get("verify_ssl")
        if _ssl_raw is None:
            _ssl_raw = endpoints.get("verify_ssl", True)
        ssl_verify = _ssl_raw if isinstance(_ssl_raw, bool) else str(_ssl_raw).lower() not in ("false", "0", "no")

        # ── Execute HTTP request ─────────────────────────────────────────────
        result = await self._http_request(method, url, body, headers, cookies, ssl_verify)

        # ── 401/403 retry with fresh session ────────────────────────────────
        if not result.get("ok") and result.get("status_code") in (401, 403):
            self.clear_session(plugin_id)
            if action_name != "login" and auth_method in ("bearer", "cookie"):
                login_result = await self._auto_login(plugin_id, manifest, config, context)
                if login_result.get("ok"):
                    session = self._sessions.get(plugin_id)
                    # Rebuild URL and headers with fresh session extras
                    sub_ctx = dict(context)
                    if session:
                        sub_ctx.update(session.extras)
                    url = (
                        self._sub(endpoints.get("base_url", ""), config, sub_ctx)
                        + self._sub(action_def.get("path", ""), config, sub_ctx)
                    )
                    body = (
                        json.loads(self._sub(json.dumps(body_tpl), config, sub_ctx))
                        if body_tpl else None
                    )
                    if auth_method == "cookie" and session:
                        cookies = dict(session.cookies)
                    elif auth_method == "bearer" and session and session.bearer_token:
                        headers["Authorization"] = f"Bearer {session.bearer_token}"
                    if session_header_map and session:
                        for extras_key, header_name in session_header_map.items():
                            val = session.extras.get(extras_key)
                            if val:
                                headers[header_name] = str(val)
                    result = await self._http_request(method, url, body, headers, cookies, ssl_verify)

        if not result.get("ok"):
            return result

        # ── Extract session from any action that declares session_extract ─────
        # (not just "login" — e.g. get_controller_id may extract omadacId)
        if action_def.get("session_extract"):
            self._extract_session(plugin_id, action_def, result)

        # ── Auto-capture all response cookies for cookie-auth login actions ──
        # For auth:cookie plugins the login response sets the session cookie
        # (e.g. TPOMADA_SESSIONID). Capture all Set-Cookie values automatically
        # so the manifest doesn't need to name every cookie explicitly.
        if endpoints.get("auth") == "cookie" and action_name == "login":
            resp_cookies = result.get("_resp_cookies") or {}
            if resp_cookies:
                session = self._sessions.get(plugin_id) or PluginSession()
                session.cookies.update(resp_cookies)
                self._sessions[plugin_id] = session

        # ── Data mapping ─────────────────────────────────────────────────────
        response_mapping = action_def.get("response_mapping")
        if response_mapping:
            devices = self._apply_response_mapping(result.get("data"), response_mapping)
            result["devices"] = devices

        return result

    async def _http_request(
        self, method: str, url: str, body, headers: dict, cookies: dict, verify: bool = True
    ) -> dict:
        try:
            async with httpx.AsyncClient(
                timeout=15.0, cookies=cookies, verify=verify, follow_redirects=False
            ) as client:
                resp = await client.request(method, url, json=body, headers=headers)
            status = resp.status_code
            # Always capture cookies and headers before any error handling —
            # some controllers (e.g. Omada) return 302 after a successful login
            resp_cookies = dict(resp.cookies)
            resp_headers = dict(resp.headers)
            if status in (401, 403):
                return {"ok": False, "status_code": status, "error": f"HTTP {status}",
                        "_resp_cookies": resp_cookies, "_resp_headers": resp_headers}
            # 3xx redirects are treated as success so session cookies are captured;
            # only genuine 4xx/5xx (excluding 401/403 above) are errors
            if status >= 400:
                return {"ok": False, "status_code": status, "error": f"HTTP {status}",
                        "_resp_cookies": resp_cookies, "_resp_headers": resp_headers}
            try:
                data = resp.json() if resp.content else {}
            except Exception:
                data = {}
            return {"ok": True, "status_code": status, "data": data,
                    "_resp_cookies": resp_cookies, "_resp_headers": resp_headers}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    # ── Auto-login ────────────────────────────────────────────────────────────

    async def _auto_login(
        self, plugin_id: str, manifest: dict, config: dict, context: dict
    ) -> dict:
        actions = manifest.get("actions") or {}
        if "login" not in actions:
            return {"ok": False, "error": "No login action defined for session auth"}
        # Set flag so pre-auth dep actions (e.g. get_controller_id) don't recurse into auto-login
        self._logging_in.add(plugin_id)
        try:
            return await self._resolve_action(plugin_id, manifest, config, "login", dict(context))
        finally:
            self._logging_in.discard(plugin_id)

    # ── Session extraction ────────────────────────────────────────────────────

    def _extract_session(self, plugin_id: str, action_def: dict, result: dict):
        se_raw = action_def.get("session_extract")
        if not se_raw:
            return

        session = self._sessions.get(plugin_id) or PluginSession()

        # Support both a single extract dict and a list of extract dicts
        extracts = se_raw if isinstance(se_raw, list) else [se_raw]

        for se in extracts:
            source  = se.get("from", "response_body")
            key     = se.get("key", "")
            jpath   = se.get("json_path", "")
            ttl_fld = se.get("ttl_field", "")

            if source == "response_cookies":
                resp_cookies = result.get("_resp_cookies", {})
                if key:
                    # Specific named cookie
                    if key in resp_cookies:
                        store_as = se.get("store_as") or key
                        session.cookies[store_as] = resp_cookies[key]
                else:
                    # No key specified — capture all response cookies
                    session.cookies.update(resp_cookies)
            elif source == "response_headers":
                hdrs = result.get("_resp_headers", {})
                val = hdrs.get(key) or hdrs.get(key.lower())
                if val:
                    store_as = se.get("store_as") or key
                    session.extras[store_as] = val
                    if key.lower() in ("authorization", "x-auth-token"):
                        session.bearer_token = val.replace("Bearer ", "").strip()
            elif source == "response_body":
                data = result.get("data") or {}
                val = data
                for part in (jpath or key).split("."):
                    if isinstance(val, dict):
                        val = val.get(part)
                    else:
                        val = None
                        break
                if val is not None:
                    store_as = se.get("store_as") or jpath or key
                    session.extras[store_as] = val
                    session.bearer_token = str(val)
                    if ttl_fld:
                        ttl_val = data.get(ttl_fld)
                        if ttl_val:
                            try:
                                session.token_expiry = time.time() + float(ttl_val) - 30
                            except (ValueError, TypeError):
                                pass

        self._sessions[plugin_id] = session

    # ── File action ───────────────────────────────────────────────────────────

    def _execute_file_action(self, action_def: dict, config: dict) -> dict:
        file_key    = action_def.get("file_key", "filepath")
        file_format = action_def.get("file_format", "json")
        path        = config.get(file_key, "")
        if not path:
            return {"ok": False, "error": f"No file path configured (config key: '{file_key}')"}
        if not os.path.isfile(path):
            return {"ok": False, "error": f"File not found: {path}"}

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
        except Exception as exc:
            return {"ok": False, "error": f"Cannot read file: {exc}"}

        try:
            if file_format == "json":
                data = json.loads(raw)
            elif file_format == "csv":
                reader = csv.DictReader(io.StringIO(raw))
                data = list(reader)
            elif file_format == "dnsmasq":
                data = self._parse_dnsmasq(raw)
            elif file_format == "isc_dhcp":
                data = self._parse_isc_dhcp(raw)
            else:
                return {"ok": False, "error": f"Unknown file_format '{file_format}'"}
        except Exception as exc:
            return {"ok": False, "error": f"Parse error ({file_format}): {exc}"}

        result: dict = {"ok": True, "data": data}
        response_mapping = action_def.get("response_mapping")
        if response_mapping:
            result["devices"] = self._apply_response_mapping(data, response_mapping)
        return result

    @staticmethod
    def _parse_dnsmasq(raw: str) -> list:
        records = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            rec: dict = {
                "mac_address": parts[1],
                "ip_address":  parts[2],
            }
            if len(parts) >= 4 and parts[3] != "*":
                rec["hostname"] = parts[3]
            records.append(rec)
        return records

    @staticmethod
    def _parse_isc_dhcp(raw: str) -> list:
        records = []
        current: dict = {}
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("lease "):
                current = {"ip_address": line.split()[1]}
            elif line.startswith("hardware ethernet"):
                mac = line.split()[-1].rstrip(";")
                current["mac_address"] = mac
            elif line.startswith("client-hostname"):
                hostname = line.split(None, 1)[-1].strip('";')
                current["hostname"] = hostname
            elif line == "}" and current.get("mac_address"):
                records.append(current)
                current = {}
        return records

    # ── SNMP action ───────────────────────────────────────────────────────────

    async def _execute_snmp_action(self, url: str, action_def: dict, config: dict) -> dict:
        try:
            from pysnmp.hlapi.asyncio import (
                CommunityData, UdpTransportTarget, ContextData,
                ObjectType, ObjectIdentity, SnmpEngine, getCmd, nextCmd,
            )
        except ImportError:
            return {"ok": False, "error": "pysnmp not installed — add pysnmp to requirements.txt"}

        parsed   = urlparse(url)
        host     = parsed.hostname or config.get("host", "")
        port     = parsed.port or int(config.get("snmp_port", 161))
        community = config.get("community", "public")
        oid      = action_def.get("snmp_oid", "1.3.6.1.2.1.1")
        operation = action_def.get("snmp_operation", "GET").upper()

        engine = SnmpEngine()
        transport = UdpTransportTarget((host, port))
        auth = CommunityData(community)
        ctx  = ContextData()
        obj  = ObjectType(ObjectIdentity(oid))

        results = {}
        try:
            if operation == "GET":
                err_ind, err_stat, err_idx, var_binds = await getCmd(
                    engine, auth, transport, ctx, obj
                )
                if err_ind:
                    return {"ok": False, "error": str(err_ind)}
                for oid_obj, val in var_binds:
                    results[str(oid_obj)] = str(val)
            else:  # WALK
                async for err_ind, err_stat, err_idx, var_binds in nextCmd(
                    engine, auth, transport, ctx, obj, lexicographicMode=False
                ):
                    if err_ind:
                        break
                    for oid_obj, val in var_binds:
                        results[str(oid_obj)] = str(val)
        except Exception as exc:
            return {"ok": False, "error": f"SNMP error: {exc}"}

        result: dict = {"ok": True, "data": results}
        rm = action_def.get("response_mapping")
        if rm:
            result["devices"] = self._apply_response_mapping(results, rm)
        return result

    # ── HA MQTT delegation ────────────────────────────────────────────────────

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
                import time as _t; _t.sleep(1.5)
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

    # ── Data mapping ──────────────────────────────────────────────────────────

    @staticmethod
    def _apply_response_mapping(raw_data, mapping: dict) -> list:
        root_path = mapping.get("root_path", "")
        field_map = mapping.get("fields", {})

        data = raw_data
        if root_path:
            for part in root_path.split("."):
                if isinstance(data, dict):
                    data = data.get(part)
                else:
                    data = None
                    break
            if data is None:
                return []

        if not isinstance(data, list):
            data = [data] if data else []

        devices = []
        for item in data:
            if not isinstance(item, dict):
                continue
            device: dict = {}
            for plugin_field, inspectre_field in field_map.items():
                val = item.get(plugin_field)
                if val is None:
                    continue
                if inspectre_field == "mac_address":
                    val = _normalise_mac(str(val))
                    if not val:
                        continue
                elif inspectre_field == "is_online":
                    val = bool(val) if not isinstance(val, str) else val.lower() in ("true", "1", "yes", "online", "connected")
                device[inspectre_field] = val
            if device.get("mac_address"):
                devices.append(device)
        return devices

    # ── Template substitution ─────────────────────────────────────────────────

    @staticmethod
    def _sub(template: str, config: dict, context: Optional[dict] = None) -> str:
        merged = dict(config)
        if context:
            merged.update(context)

        def replace(m):
            key = m.group(1)
            return str(merged.get(key, m.group(0)))

        return re.sub(r'\{([\w.]+)\}', replace, template)

    # ── Auth helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _apply_auth(headers: dict, method: str, config: dict, session: Optional[PluginSession] = None):
        if method == "basic":
            import base64 as _b64
            creds = _b64.b64encode(
                f"{config.get('user', '')}:{config.get('password', '')}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {creds}"
        elif method == "bearer":
            token = (session.bearer_token if session else None) or config.get("token", "")
            headers["Authorization"] = f"Bearer {token}"
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

                # Upsert discovered devices
                devices = result.get("devices") or []
                plugin_info = self._registry.get(plugin_id)
                caps = set((plugin_info or {}).get("manifest", {}).get("capabilities", []))
                if devices and caps & {"discovery", "presence"}:
                    self._upsert_devices(db, plugin_id, devices)
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

    def _upsert_devices(self, db: Session, plugin_id: str, devices: list):
        for dev in devices:
            mac = (dev.get("mac_address") or "").lower().replace(":", "").strip()
            if len(mac) != 12:
                continue
            mac_fmt = ':'.join(mac[i:i+2] for i in range(0, 12, 2))
            try:
                # Upsert device (only fields we have; never overwrite user-set names)
                db.execute(text("""
                    INSERT INTO devices (mac_address, ip_address, hostname, is_online, first_seen, last_seen)
                    VALUES (:mac, :ip, :hostname, :online, NOW(), NOW())
                    ON CONFLICT (mac_address) DO UPDATE SET
                        ip_address = COALESCE(EXCLUDED.ip_address, devices.ip_address),
                        hostname   = CASE
                                        WHEN devices.custom_name IS NOT NULL THEN devices.hostname
                                        ELSE COALESCE(EXCLUDED.hostname, devices.hostname)
                                     END,
                        is_online  = EXCLUDED.is_online,
                        last_seen  = NOW()
                """), {
                    "mac":      mac_fmt,
                    "ip":       dev.get("ip_address"),
                    "hostname": dev.get("hostname"),
                    "online":   bool(dev.get("is_online", True)),
                })

                # Store full enrichment payload in plugin_device_data
                enrichment = {k: v for k, v in dev.items() if k not in INSPECTRE_DEVICE_FIELDS}
                if enrichment:
                    db.execute(text("""
                        INSERT INTO plugin_device_data (plugin_id, mac_address, data, updated_at)
                        VALUES (:pid, :mac, CAST(:data AS jsonb), NOW())
                        ON CONFLICT (plugin_id, mac_address) DO UPDATE SET
                            data       = CAST(EXCLUDED.data AS jsonb),
                            updated_at = NOW()
                    """), {
                        "pid":  plugin_id,
                        "mac":  mac_fmt,
                        "data": json.dumps(enrichment),
                    })

                # Write tag_fields from manifest's data_mapping back to devices.tags
                plugin_info = self._registry.get(plugin_id)
                tag_fields = (
                    (plugin_info or {})
                    .get("manifest", {})
                    .get("data_mapping", {})
                    .get("tag_fields", [])
                )
                if tag_fields:
                    new_tags = []
                    for tf in tag_fields:
                        val = dev.get(tf)
                        if val is None:
                            continue
                        if tf in BOOL_TAG_LABELS and isinstance(val, bool):
                            new_tags.append(BOOL_TAG_LABELS[tf][0 if val else 1])
                        elif str(val).strip():
                            new_tags.append(str(val).strip().lower())
                    if new_tags:
                        db.execute(text("""
                            UPDATE devices SET tags = CASE
                                WHEN tags IS NULL OR tags = '' THEN :new_tags
                                ELSE (
                                    SELECT string_agg(DISTINCT trim(t), ',')
                                    FROM unnest(string_to_array(tags || ',' || :new_tags, ',')) t
                                    WHERE trim(t) != ''
                                )
                            END
                            WHERE mac_address = :mac
                        """), {"mac": mac_fmt, "new_tags": ','.join(new_tags)})

            except Exception as exc:
                print(f"[plugin-scheduler] upsert failed for {mac_fmt}: {exc}", flush=True)
                db.rollback()


# ---------------------------------------------------------------------------
# Webhook helpers (used by main.py webhook endpoint)
# ---------------------------------------------------------------------------

def verify_webhook_signature(body_bytes: bytes, secret: str, header_value: str) -> bool:
    """Validate X-Hub-Signature-256: sha256=<hex> header."""
    expected = "sha256=" + hmac.new(
        secret.encode(), body_bytes, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, header_value or "")
