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
    "presence", "traffic", "export", "notification", "firewall",
])
VALID_FIELD_TYPES = frozenset([
    "string", "password", "integer", "boolean",
    "select", "multiline", "url", "filepath",
])
VALID_EVENT_KEYS = frozenset([
    "device.new", "device.online", "device.offline",
    "port.opened", "vuln.found", "vuln.critical", "vuln.high",
    "device.blocked", "device.unblocked",
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
                existing = self._plugins.get(row.plugin_id, {})
                if existing.get("source") == "builtin":
                    # Uploaded plugin shadows the builtin — uploaded manifest wins,
                    # but we preserve any config/state already loaded from the DB.
                    print(
                        f"[plugins] Uploaded plugin '{row.plugin_id}' overrides builtin"
                        f" — using uploaded manifest.",
                        flush=True,
                    )
                self._plugins[row.plugin_id] = {
                    "manifest":   manifest,
                    "config":     row.config or existing.get("config") or {},
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

    def set_poll_result(self, plugin_id: str, device_count: int, ts: datetime):
        if plugin_id in self._plugins:
            self._plugins[plugin_id]["last_polled"] = ts.isoformat()
            self._plugins[plugin_id]["last_device_count"] = device_count

    def add_uploaded(self, manifest: dict) -> str:
        """Register an uploaded plugin manifest in-memory.

        If the plugin ID matches a built-in, the uploaded manifest takes
        precedence (overrides the built-in) — allowing power users to ship
        a patched version without touching the container image.
        """
        validate_manifest(manifest)
        pid = manifest["id"]
        existing = self._plugins.get(pid, {})
        if existing.get("source") == "builtin":
            print(
                f"[plugins] add_uploaded: '{pid}' overrides built-in plugin.",
                flush=True,
            )
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
        if body_tpl:
            body = json.loads(self._sub(json.dumps(body_tpl), config, sub_ctx))
            body = self._apply_list_directives(body, sub_ctx)
        else:
            body = None

        headers = {
            k: self._sub(str(v), config, sub_ctx)
            for k, v in (endpoints.get("headers") or {}).items()
        }
        cookies: dict = {}

        if auth_method == "cookie" and session:
            cookies = dict(session.cookies)
        elif auth_method == "bearer" and session and session.bearer_token:
            headers["Authorization"] = f"Bearer {session.bearer_token}"
        else:
            self._apply_auth(headers, auth_method, config, session)

        # Inject session extras as custom headers per manifest session_headers map
        # e.g. {"loginToken": "Csrf-Token"} injects session.extras["loginToken"] as "Csrf-Token"
        # Check endpoints block first, fall back to top-level manifest key for backwards compat
        session_header_map = endpoints.get("session_headers") or manifest.get("session_headers") or {}
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
                    if body_tpl:
                        body = json.loads(self._sub(json.dumps(body_tpl), config, sub_ctx))
                        body = self._apply_list_directives(body, sub_ctx)
                    else:
                        body = None
                    if auth_method == "cookie" and session:
                        cookies = dict(session.cookies)
                    elif auth_method == "bearer" and session and session.bearer_token:
                        headers["Authorization"] = f"Bearer {session.bearer_token}"
                    retry_header_map = endpoints.get("session_headers") or manifest.get("session_headers") or {}
                    if retry_header_map and session:
                        for extras_key, header_name in retry_header_map.items():
                            val = session.extras.get(extras_key)
                            if val:
                                headers[header_name] = str(val)
                    result = await self._http_request(method, url, body, headers, cookies, ssl_verify)

        if not result.get("ok"):
            return result

        # ── API-level error check (for APIs that always return HTTP 200) ──────
        # e.g. Omada returns {"errorCode": -1001, "msg": "..."} on failure
        error_check = endpoints.get("error_check")
        if error_check:
            data = result.get("data") or {}
            check_path  = error_check.get("json_path", "errorCode")
            success_val = error_check.get("success_value", 0)
            msg_path    = error_check.get("message_path", "msg")
            code_val = data
            for part in check_path.split("."):
                code_val = code_val.get(part) if isinstance(code_val, dict) else None
            if code_val is not None and code_val != success_val:
                msg_val = data
                for part in msg_path.split("."):
                    msg_val = msg_val.get(part) if isinstance(msg_val, dict) else None
                err = str(msg_val) if msg_val else f"API error {code_val}"
                print(f"[plugin-runner] {plugin_id}/{action_name}: API error — {err} (code {code_val})", flush=True)
                return {"ok": False, "error": err, "api_error_code": code_val}

        # ── Verbose response logging for diagnosis ────────────────────────────
        if action_def.get("session_extract") or action_def.get("response_mapping"):
            raw = str(result.get("data", {}))
            print(f"[plugin-runner] {plugin_id}/{action_name}: response={raw[:600]}", flush=True)

        # ── Extract session from any action that declares session_extract ─────
        # (not just "login" — e.g. get_controller_id may extract omadacId)
        if action_def.get("session_extract"):
            self._extract_session(plugin_id, action_def, result, config)

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
            if devices:
                print(f"[plugin-runner] {plugin_id}/{action_name}: mapped {len(devices)} device(s)", flush=True)
            else:
                raw_snippet = str(result.get("data", {}))[:400]
                print(
                    f"[plugin-runner] {plugin_id}/{action_name}: 0 devices mapped"
                    f" (root_path={response_mapping.get('root_path', '')!r})"
                    f" raw={raw_snippet}",
                    flush=True,
                )

        return result

    async def _http_request(
        self, method: str, url: str, body, headers: dict, cookies: dict, verify: bool = True
    ) -> dict:
        try:
            print(f"[plugin-http] {method} {url}", flush=True)
            async with httpx.AsyncClient(
                timeout=15.0, cookies=cookies, verify=verify, follow_redirects=False
            ) as client:
                resp = await client.request(method, url, json=body, headers=headers)
            status = resp.status_code
            # Always capture cookies and headers before any error handling —
            # some controllers (e.g. Omada) return 302 after a successful login
            resp_cookies = dict(resp.cookies)
            resp_headers = dict(resp.headers)
            print(f"[plugin-http] → {status} ({len(resp.content)} bytes)", flush=True)
            if status in (401, 403):
                return {"ok": False, "status_code": status, "error": f"HTTP {status}",
                        "_resp_cookies": resp_cookies, "_resp_headers": resp_headers}
            # 3xx with no body = auth redirect (e.g. wrong endpoint or missing cookie auth)
            if 300 <= status < 400 and not resp.content:
                print(f"[plugin-http] redirect with empty body — wrong endpoint or auth method", flush=True)
                return {"ok": False, "status_code": status, "error": f"HTTP {status} redirect — check URL path and auth method",
                        "_resp_cookies": resp_cookies, "_resp_headers": resp_headers}
            if status >= 400:
                print(f"[plugin-http] error body: {resp.text[:500]}", flush=True)
                return {"ok": False, "status_code": status, "error": f"HTTP {status}",
                        "_resp_cookies": resp_cookies, "_resp_headers": resp_headers}
            try:
                data = resp.json() if resp.content else {}
            except Exception:
                data = {}
            return {"ok": True, "status_code": status, "data": data,
                    "_resp_cookies": resp_cookies, "_resp_headers": resp_headers}
        except Exception as exc:
            print(f"[plugin-http] → ERROR: {exc}", flush=True)
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

    def _extract_session(self, plugin_id: str, action_def: dict, result: dict, config: Optional[dict] = None):
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
                list_find = se.get("list_find")
                if list_find:
                    # Navigate to the list using list_path
                    list_path = se.get("list_path", "")
                    lst = data
                    for part in (list_path.split(".") if list_path else []):
                        if isinstance(lst, dict):
                            lst = lst.get(part)
                        elif isinstance(lst, list):
                            try:
                                lst = lst[int(part)]
                            except (ValueError, IndexError):
                                lst = None
                                break
                        else:
                            lst = None
                            break

                    val = None
                    if isinstance(lst, list):
                        find_field = list_find.get("field", "name")
                        config_key = list_find.get("config_key", "")
                        find_value = (config or {}).get(config_key, "") if config_key else ""
                        value_key  = se.get("value_key", "id")
                        fallback   = se.get("fallback", "first")

                        matched = None
                        if find_value:
                            for item in lst:
                                if isinstance(item, dict) and str(item.get(find_field, "")) == str(find_value):
                                    matched = item
                                    break

                        if matched is None and fallback == "first" and lst:
                            if find_value:
                                first_name = lst[0].get(find_field, "?") if isinstance(lst[0], dict) else "?"
                                print(
                                    f"[plugin-session] {plugin_id}: site '{find_value}' not found"
                                    f" in {len(lst)} site(s), falling back to first ('{first_name}')",
                                    flush=True,
                                )
                            matched = lst[0] if isinstance(lst[0], dict) else None

                        if matched is not None:
                            val = matched.get(value_key)
                            store_as = se.get("store_as") or value_key
                            print(
                                f"[plugin-session] {plugin_id}: stored {store_as}={val!r}"
                                f" (matched site: {matched.get(find_field, '?')!r})",
                                flush=True,
                            )
                    if val is not None:
                        store_as = se.get("store_as") or value_key or "value"
                        session.extras[store_as] = val
                else:
                    val = data
                    for part in (jpath or key).split("."):
                        if isinstance(val, dict):
                            val = val.get(part)
                        elif isinstance(val, list):
                            try:
                                val = val[int(part)]
                            except (ValueError, IndexError):
                                val = None
                                break
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
        root_path  = mapping.get("root_path", "")
        root_paths = mapping.get("root_paths")  # array: merge results from multiple paths
        field_map  = mapping.get("fields", {})

        # Normalise to a list of paths so the loop below handles both cases uniformly
        paths = root_paths if root_paths else ([root_path] if root_path else [""])

        seen_macs: set = set()
        all_devices: list = []

        for rp in paths:
            data = raw_data
            if rp:
                for part in rp.split("."):
                    if isinstance(data, dict):
                        data = data.get(part)
                    elif isinstance(data, list):
                        try:
                            data = data[int(part)]
                        except (ValueError, IndexError):
                            data = None
                            break
                    else:
                        data = None
                        break
                if data is None:
                    continue

            if not isinstance(data, list):
                data = [data] if data else []

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
                    mac = device["mac_address"]
                    if mac not in seen_macs:
                        seen_macs.add(mac)
                        all_devices.append(device)

        return all_devices

    @staticmethod
    def _apply_list_directives(body: dict, sub_ctx: dict) -> dict:
        """Process _list_append / _list_remove / _list_passthrough body directives.

        These allow a manifest action to non-destructively modify a list fetched
        from a preceding depends_on action (e.g. read-modify-write an access list).

        Directive format (as a value inside the body dict):
            {"_list_append":      "dep_action.ctx_key", "_value": "{ip}"}
            {"_list_remove":      "dep_action.ctx_key", "_value": "{ip}"}
            {"_list_passthrough": "dep_action.ctx_key"}
        """
        if not isinstance(body, dict):
            return body
        result = {}
        for key, val in body.items():
            if isinstance(val, dict) and (
                "_list_append" in val or "_list_remove" in val or "_list_passthrough" in val
            ):
                ctx_key = (
                    val.get("_list_append")
                    or val.get("_list_remove")
                    or val.get("_list_passthrough", "")
                )
                raw = sub_ctx.get(ctx_key, "[]")
                try:
                    current = json.loads(raw) if isinstance(raw, str) else list(raw)
                except (json.JSONDecodeError, TypeError):
                    current = []
                if not isinstance(current, list):
                    current = []
                item = val.get("_value", "")
                if "_list_append" in val:
                    if item and item not in current:
                        current = current + [item]
                elif "_list_remove" in val:
                    current = [x for x in current if x != item]
                # _list_passthrough: use current as-is
                result[key] = current
            else:
                result[key] = val
        return result

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
                    # Support both singular "action" and plural "actions"
                    action   = polling.get("action")
                    actions  = polling.get("actions") or ([action] if action else [])
                    if not actions:
                        continue
                    interval = float(polling.get("interval_seconds") or 300)
                    pid      = plugin_info["id"]
                    if (now - self._last_poll.get(pid, 0.0)) >= interval:
                        self._last_poll[pid] = now
                        asyncio.ensure_future(self._poll_plugin(pid, actions))
            except Exception as exc:
                print(f"[plugin-scheduler] {exc}", flush=True)
            await asyncio.sleep(30)

    async def _poll_plugin(self, plugin_id: str, actions: list):
        db = self._db_factory()
        now = datetime.now(timezone.utc)
        plugin_info = self._registry.get(plugin_id)
        caps = set((plugin_info or {}).get("manifest", {}).get("capabilities", []))
        has_presence = "presence" in caps

        # Run all polling actions and merge results (last write wins per MAC)
        all_devices: dict = {}
        any_ok   = False
        last_err = None

        for action in actions:
            result = await self._runner.execute_action(plugin_id, action)
            if result.get("ok"):
                any_ok = True
                for dev in (result.get("devices") or []):
                    mac = dev.get("mac_address")
                    if mac:
                        all_devices[mac] = dev
            else:
                last_err = result.get("error", "Unknown error")
                print(f"[plugin-scheduler] {plugin_id}/{action}: poll FAILED — {last_err}", flush=True)

        try:
            if any_ok:
                devices = list(all_devices.values())
                upserted = 0
                if devices and caps & {"discovery", "presence"}:
                    upserted = self._upsert_devices(db, plugin_id, devices, has_presence)
                print(
                    f"[plugin-scheduler] {plugin_id}: poll OK — {len(devices)} device(s) returned,"
                    f" {upserted} upserted",
                    flush=True,
                )
                db.execute(
                    text(
                        "UPDATE plugins SET last_polled = NOW(), status = 'active',"
                        " last_error = NULL WHERE plugin_id = :pid"
                    ),
                    {"pid": plugin_id},
                )
                self._registry.set_status(plugin_id, "active")
                self._registry.set_poll_result(plugin_id, len(devices), now)
            else:
                err = last_err or "Unknown error"
                print(f"[plugin-scheduler] {plugin_id}: all poll actions FAILED — {err}", flush=True)
                db.execute(
                    text(
                        "UPDATE plugins SET last_polled = NOW(), status = 'error',"
                        " last_error = :err WHERE plugin_id = :pid"
                    ),
                    {"pid": plugin_id, "err": err},
                )
                self._registry.set_status(plugin_id, "error", err)
                self._registry.set_poll_result(plugin_id, 0, now)
            db.commit()
        except Exception as exc:
            print(f"[plugin-scheduler] DB error for {plugin_id}: {exc}", flush=True)
            db.rollback()
        finally:
            db.close()

    def _upsert_devices(self, db: Session, plugin_id: str, devices: list, has_presence: bool = True) -> int:
        count = 0
        for dev in devices:
            # Strip all non-hex characters so both colon and dash separated MACs normalise correctly
            mac = re.sub(r'[^0-9a-f]', '', (dev.get("mac_address") or "").lower())
            if len(mac) != 12:
                continue
            # Skip devices with no IP — they can't be scanned or interacted with,
            # and the probe will add them properly once they appear on the network
            if not dev.get("ip_address"):
                continue
            mac_fmt = ':'.join(mac[i:i+2] for i in range(0, 12, 2))
            try:
                # Upsert device. Hostname priority (highest→lowest):
                #   1. User custom_name set → never touch hostname
                #   2. Device already has a hostname (from probe/ARP/DNS) → keep it
                #   3. No hostname yet → accept plugin-provided name as fallback only
                online_val = bool(dev.get("is_online")) if has_presence else False

                # Read current presence state so we can detect offline→online transitions
                # and write the corresponding event after the upsert.
                prior = db.execute(
                    text("SELECT is_online, suppress_presence_events FROM devices WHERE mac_address = :mac"),
                    {"mac": mac_fmt},
                ).fetchone()
                was_online = prior[0] if prior is not None else None
                suppress   = bool(prior[1]) if prior is not None else False

                if has_presence:
                    db.execute(text("""
                        INSERT INTO devices (mac_address, ip_address, hostname, is_online, first_seen, last_seen)
                        VALUES (:mac, :ip, :hostname, :online, NOW(), NOW())
                        ON CONFLICT (mac_address) DO UPDATE SET
                            ip_address = COALESCE(EXCLUDED.ip_address, devices.ip_address),
                            hostname   = CASE
                                            WHEN devices.custom_name IS NOT NULL THEN devices.hostname
                                            WHEN devices.hostname IS NOT NULL AND devices.hostname != '' THEN devices.hostname
                                            ELSE EXCLUDED.hostname
                                         END,
                            is_online  = EXCLUDED.is_online,
                            miss_count = CASE WHEN EXCLUDED.is_online = TRUE THEN 0 ELSE devices.miss_count END,
                            last_seen  = NOW()
                    """), {
                        "mac":      mac_fmt,
                        "ip":       dev.get("ip_address"),
                        "hostname": dev.get("hostname"),
                        "online":   online_val,
                    })

                    # Write an "online" event when a device transitions offline → online,
                    # unless the device has presence-event suppression enabled.
                    if online_val and was_online is False and not suppress:
                        db.execute(text(
                            "INSERT INTO device_events (mac_address, type, detail, created_at) "
                            "SELECT :mac, 'online', :detail::jsonb, NOW() "
                            "WHERE EXISTS (SELECT 1 FROM devices WHERE mac_address = :mac)"
                        ), {
                            "mac":    mac_fmt,
                            "detail": json.dumps({"source": plugin_id}),
                        })
                        print(f"[plugin-scheduler] {plugin_id}: online event written for {mac_fmt}", flush=True)
                else:
                    db.execute(text("""
                        INSERT INTO devices (mac_address, ip_address, hostname, is_online, first_seen, last_seen)
                        VALUES (:mac, :ip, :hostname, false, NOW(), NOW())
                        ON CONFLICT (mac_address) DO UPDATE SET
                            ip_address = COALESCE(EXCLUDED.ip_address, devices.ip_address),
                            hostname   = CASE
                                            WHEN devices.custom_name IS NOT NULL THEN devices.hostname
                                            WHEN devices.hostname IS NOT NULL AND devices.hostname != '' THEN devices.hostname
                                            ELSE EXCLUDED.hostname
                                         END,
                            last_seen  = NOW()
                    """), {
                        "mac":      mac_fmt,
                        "ip":       dev.get("ip_address"),
                        "hostname": dev.get("hostname"),
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

                count += 1
            except Exception as exc:
                print(f"[plugin-scheduler] upsert failed for {mac_fmt}: {exc}", flush=True)
                db.rollback()
        return count


# ---------------------------------------------------------------------------
# Webhook helpers (used by main.py webhook endpoint)
# ---------------------------------------------------------------------------

def verify_webhook_signature(body_bytes: bytes, secret: str, header_value: str) -> bool:
    """Validate X-Hub-Signature-256: sha256=<hex> header."""
    expected = "sha256=" + hmac.new(
        secret.encode(), body_bytes, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, header_value or "")
