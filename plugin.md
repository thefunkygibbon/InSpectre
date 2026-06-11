# InSpectre Plugin Developer Guide

This is the complete reference for writing InSpectre plugins.

> **Looking for ready-to-copy starting points?** See the
> [`examples/plugins/`](examples/plugins/) folder — it contains an annotated
> [`TEMPLATE.yaml`](examples/plugins/TEMPLATE.yaml) and working examples.

---

## Contents

1. [Concept: plugins are declarative](#1-concept-plugins-are-declarative)
2. [Quick start](#2-quick-start)
3. [Manifest reference](#3-manifest-reference)
4. [Config schema](#4-config-schema)
5. [Endpoints & authentication](#5-endpoints--authentication)
6. [Actions](#6-actions)
7. [Template substitution](#7-template-substitution)
8. [Dependency chains (`depends_on`)](#8-dependency-chains-depends_on)
9. [Session extraction (`session_extract`)](#9-session-extraction-session_extract)
10. [Response mapping → devices](#10-response-mapping--devices)
11. [What happens to mapped devices](#11-what-happens-to-mapped-devices)
12. [Event hooks](#12-event-hooks)
13. [Polling](#13-polling)
14. [The blocking contract](#14-the-blocking-contract)
15. [File & SNMP plugins](#15-file--snmp-plugins)
16. [Webhook-triggered actions](#16-webhook-triggered-actions)
17. [Overriding a built-in plugin](#17-overriding-a-built-in-plugin)
18. [Testing & validation](#18-testing--validation)
19. [Built-in plugin reference](#19-built-in-plugin-reference)

---

## 1. Concept: plugins are declarative

An InSpectre plugin is a **single manifest file** (JSON or YAML). **There is no
plugin code** — you do not write Python, you do not compile anything, and the
plugin cannot execute arbitrary logic inside the backend. Instead, the manifest
*declares* HTTP / file / SNMP operations, and the InSpectre **plugin engine**
performs them on a schedule (or in response to events), then maps the results
into the device inventory and event system.

If you have used other monitoring tools you may expect imperative code hooks
like `on_device_discovered()` or `on_scan_complete()`. InSpectre's equivalent is
the declarative **[event hooks](#12-event-hooks)** map — you bind an InSpectre
event (e.g. `device.new`, `vuln.critical`) to a named **action** the engine then
runs. The mapping from those imagined hooks to the real event keys is:

| Imperative hook you might expect | InSpectre event key |
|---|---|
| `on_device_discovered` | `device.new` |
| `on_device_online` | `device.online` |
| `on_device_offline` | `device.offline` |
| `on_port_opened` / `on_scan_complete` | `port.opened` |
| `on_vulnerability_found` | `vuln.found` (+ `vuln.critical`, `vuln.high`) |
| `on_device_blocked` / `on_device_unblocked` | `device.blocked` / `device.unblocked` |

This design keeps community plugins **safe to share** — a manifest can only make
the network calls it declares, against the credentials a user explicitly enters.

---

## 2. Quick start

1. Copy [`examples/plugins/TEMPLATE.yaml`](examples/plugins/TEMPLATE.yaml) (or
   the JSON [`hello-world.json`](examples/plugins/hello-world.json)).
2. Set a unique lowercase `id`, then edit `config_schema`, `endpoints`, and
   `actions` to match your target API.
3. In InSpectre: **Settings → Plugins → Upload Plugin**, choose your file.
4. Open the plugin, fill in config, click **Test Connection**.
5. Toggle **Enabled**. Polling starts on the next cycle; blocking plugins become
   selectable under **Settings → Security Responses → Blocking Method**.

A minimal discovery plugin is just an endpoint, one action, and a polling block:

```json
{
  "id": "my-router",
  "name": "My Router",
  "version": "1.0.0",
  "capabilities": ["discovery"],
  "config_schema": [
    { "key": "host", "label": "Base URL", "type": "url", "default": "http://192.168.0.1", "required": true },
    { "key": "api_key", "label": "API Key", "type": "password", "default": "", "required": true }
  ],
  "endpoints": { "base_url": "{host}", "auth": "api-key-header", "api_key_header": "X-API-Key" },
  "actions": {
    "get_leases": {
      "method": "GET",
      "path": "/api/dhcp/leases",
      "response_mapping": { "root_path": "leases", "fields": { "mac": "mac_address", "ip": "ip_address", "name": "hostname" } }
    }
  },
  "polling": { "action": "get_leases", "interval_seconds": 120 }
}
```

---

## 3. Manifest reference

| Field | Type | Required | Description |
|---|---|:--:|---|
| `id` | string | ✅ | Unique slug: lowercase letters, digits, hyphens (`^[a-z0-9][a-z0-9-]*[a-z0-9]$`). |
| `name` | string | ✅ | Display name. |
| `version` | string | ✅ | SemVer, e.g. `1.0.0`. |
| `capabilities` | array | ✅ | See [Capabilities](#capabilities). |
| `config_schema` | array | ✅ | User-configurable fields. May be empty (`[]`). |
| `author` | string | | Shown in the Plugins UI. |
| `description` | string | | One-line summary. |
| `homepage` | string | | Link shown in the UI. |
| `min_inspectre_version` | string | | Advisory; the version you developed against. |
| `icon` | string/null | | Reserved. |
| `endpoints` | object | | Base URL, auth, headers. Required for HTTP/SNMP plugins. |
| `actions` | object | | Named operations the engine can run. |
| `event_hooks` | object | | Map InSpectre event → action name. |
| `polling` | object/null | | Scheduled action(s). |
| `data_mapping` | object | | `tag_fields` to promote onto device tags. |

### Capabilities

Declare what your plugin genuinely does. The engine uses these to decide which
UIs and flows it participates in (e.g. only `discovery`/`presence` plugins have
their poll results written to the inventory; only `blocking` plugins appear as
block methods).

| Capability | Meaning |
|---|---|
| `discovery` | Provides MAC/IP/hostname rows for the device inventory. |
| `enrichment` | Adds metadata (vendor, type, tags) to known devices. |
| `presence` | Reports whether a device is online (sets `is_online`). |
| `dns` | Is a DNS server/resolver (AdGuard Home, Pi-hole). |
| `traffic` | Provides DNS query logs / flow data. |
| `blocking` | Can enforce per-device blocks. See [Blocking Contract](#14-the-blocking-contract). |
| `firewall` | Controls a stateful firewall (combine with `blocking`). |
| `export` | Sends InSpectre state to an external system. |
| `notification` | Delivers alerts. |

---

## 4. Config schema

Each entry renders a field in the plugin's config form. Values become `{key}`
placeholders usable in `endpoints` and `actions`.

| Key | Required | Notes |
|---|:--:|---|
| `key` | ✅ | Config key; how you reference the value (`{key}`). |
| `label` | ✅ | Field label in the UI. |
| `type` | | One of the types below. Default `string`. |
| `default` | | Pre-filled value. |
| `required` | | Advisory flag shown in the UI. |
| `help` | | Help text under the field. |
| `options` | | For `select` only — array of strings, or `{value,label}` objects. |

**Field types:** `string`, `password`, `integer`, `boolean`, `select`,
`multiline`, `url`, `filepath`.

- `password` values are **encrypted at rest** (Fernet, derived from the server
  `SECRET_KEY`) and shown as `**redacted**` when reading config back via the API.
- `multiline` renders a textarea (e.g. a newline-separated keyword list).
- `filepath` is a **container-internal** path — mount the file into the backend
  container via `volumes:` in `docker-compose.yml`.
- `boolean` accepts `true`/`false` (or the strings `"true"`/`"false"`).

---

## 5. Endpoints & authentication

```json
"endpoints": {
  "base_url": "{host}",
  "auth": "bearer",
  "headers": { "Content-Type": "application/json" },
  "verify_ssl": true
}
```

| Key | Description |
|---|---|
| `base_url` | Prepended to every action `path`. May contain `{config_key}` placeholders. Scheme must be one of `http`, `https`, `mqtt`, `mqtts`, `snmp`, `snmps`. |
| `auth` | Authentication method (see below). |
| `headers` | Static headers sent on every request; values support templating. |
| `verify_ssl` | Default TLS verification. A `verify_ssl` **config field** overrides this per install. |
| `api_key_header` | Header name for `api-key-header` auth. |
| `api_key_value` | Optional template for the api-key header value (compose from multiple config fields). Falls back to the `api_key` config value. |
| `username_field` / `password_field` | For `basic` auth, map your own config keys onto Basic credentials (defaults `user` / `password`). |
| `session_headers` | Map of `session_extra_key → HTTP header name`, injected on every call after login (e.g. `{ "access_token": "X-FTL-SID" }`). |
| `error_check` | For APIs that always return HTTP 200 — see below. |

### Auth methods

| Value | Mechanism |
|---|---|
| `none` | No auth header. |
| `basic` | HTTP Basic from `username_field`/`password_field` config (default `user`/`password`). |
| `bearer` | `Authorization: Bearer <token>`. Token comes from a `login` action via `session_extract`. The engine **auto-logs-in** when no valid token exists and **auto-retries once** on `401`/`403`. |
| `cookie` | Session cookie. The `login` action's `Set-Cookie` values are captured automatically. Same auto-login / retry behaviour. |
| `api-key-header` | Custom header (`api_key_header`) with value `api_key` or the `api_key_value` template. |

> `api-key-param` is accepted by the validator but **not yet implemented** by the
> request layer — don't rely on it.

### `error_check` (HTTP-200 error envelopes)

Some APIs (e.g. TP-Link Omada) return HTTP 200 with an error code in the body.
Declare how to detect failure so the engine reports it correctly:

```json
"error_check": { "json_path": "errorCode", "success_value": 0, "message_path": "msg" }
```

---

## 6. Actions

Actions are named operations. The default kind is an HTTP request; an action may
instead read a file (`"source": "file"`) or do SNMP (when the resolved URL uses
an `snmp://` scheme).

```json
"get_clients": {
  "description": "Fetch known clients.",
  "method": "GET",
  "path": "/api/clients",
  "depends_on": "login",
  "response_mapping": { "root_path": "clients", "fields": { "ip": "ip_address", "name": "hostname" } }
}
```

| Field | Description |
|---|---|
| `description` | Human-readable; shown in the UI. |
| `method` | HTTP verb (`GET`, `POST`, `PUT`, …). Default `GET`. |
| `path` | Appended to `base_url`. Supports templating. |
| `body` | Request body (object). Templated; supports [list directives](#list-directives). |
| `depends_on` | Run another action first (max chain depth 3). See [§8](#8-dependency-chains-depends_on). |
| `session_extract` | Capture values from the response. See [§9](#9-session-extraction-session_extract). |
| `response_mapping` | Map the response into device rows. See [§10](#10-response-mapping--devices). |
| `source` | `"file"` for a file-reading action. See [§15](#15-file--snmp-plugins). |
| `trigger` | `"webhook"` to mark the action invoked by the webhook endpoint. See [§16](#16-webhook-triggered-actions). |

Conventionally, define a **`test_connection`** action — the UI's **Test
Connection** button calls it.

---

## 7. Template substitution

Any `{placeholder}` in a `base_url`, `path`, `body`, or header value is replaced
from a merged namespace (later sources win):

1. **Config values** — every `config_schema` key.
2. **Context** — for blocking and event-triggered actions:
   - `{mac}` — lowercase colon form, `aa:bb:cc:dd:ee:ff`
   - `{mac_dash}` — uppercase dash form, `AA-BB-CC-DD-EE-FF`
   - `{ip}` — IP string (may be empty)
   - plus any keys the triggering event supplies (`name`, `ports`, `vulns`).
3. **Session extras** — values saved by `session_extract` (e.g. `{omadacId}`).
4. **Dependency outputs** — `{dep_action.field}` (see next section).

An unknown placeholder is left untouched (so literal braces survive).

---

## 8. Dependency chains (`depends_on`)

When an action declares `depends_on`, the engine runs the dependency first
(recursively, up to depth 3) and merges its response into the substitution
context before running the dependent action:

- If the dependency returns an **object**, fields are exposed as
  `{dep_action.field}`.
- If it returns a **list**, items are exposed as `{dep_action.0.field}`,
  `{dep_action.1.field}`, … and the first item's fields also as
  `{dep_action.field}` for convenience.

This is how login/auth flows work: `get_clients` depends on `login`, the engine
authenticates, stores the session, then runs `get_clients` with the token
applied automatically.

---

## 9. Session extraction (`session_extract`)

Capture values from a response for reuse in later actions. May be a single
object or a **list** of objects (multiple extractions from one response).

```json
"login": {
  "method": "POST", "path": "/api/auth",
  "body": { "password": "{api_password}" },
  "session_extract": { "from": "response_body", "json_path": "session.sid", "store_as": "access_token" }
}
```

| Key | Description |
|---|---|
| `from` | `response_body` (default), `response_headers`, or `response_cookies`. |
| `json_path` | Dotted path into the body (e.g. `data.token`). |
| `key` | Header or cookie name (for the header/cookie sources). Omit a cookie `key` to capture **all** cookies. |
| `store_as` | Name to store the value under; referenced later as `{store_as}` and via `session_headers`. |
| `ttl_field` | Body field holding the token lifetime in seconds (sets expiry, minus a 30 s safety margin). |

For `bearer` auth, a value extracted from the body is also used as the bearer
token automatically.

**Selecting from a list (`list_find`)** — pick one item from an array by matching
a config value, then store a field from the matched item (used for "find my site
ID by site name"):

```json
"session_extract": {
  "from": "response_body",
  "list_path": "result.data",
  "list_find": { "field": "name", "config_key": "site_name" },
  "value_key": "id",
  "store_as": "site_id",
  "fallback": "first"
}
```

---

## 10. Response mapping → devices

`response_mapping` converts an action's response into a list of device rows.

```json
"response_mapping": {
  "root_path": "result.clients",
  "fields": { "mac": "mac_address", "ip": "ip_address", "name": "hostname", "online": "is_online" }
}
```

| Key | Description |
|---|---|
| `root_path` | Dotted path to the array of items (omit if the response is already an array). List indices allowed, e.g. `data.0.list`. |
| `root_paths` | Array of paths whose results are merged (deduplicated by MAC). Use instead of `root_path`. |
| `fields` | Map of **source field → InSpectre field**. |

**InSpectre device fields** you can map to: `mac_address`, `ip_address`,
`hostname`, `vendor`, `device_type`, `is_online`, `vlan`. Any other mapped field
is preserved as **enrichment** (see next section).

Mapping rules:
- `mac_address` is **required** per row and is normalised to `aa:bb:cc:dd:ee:ff`;
  rows without a valid MAC are skipped.
- `is_online` is coerced to a boolean (`true`, `1`, `yes`, `online`, `connected`
  count as online).
- Rows are deduplicated by MAC (first occurrence wins).

---

## 11. What happens to mapped devices

When a polling action returns mapped devices **and** the plugin has `discovery`
or `presence` capability, the scheduler upserts them:

- A row **without an `ip_address` is skipped** (it can't be scanned yet; the
  probe will add it when it appears on the network).
- **Hostname priority:** a user `custom_name` is never overwritten; an existing
  probe/DNS hostname is kept; the plugin-provided name is used only as a
  fallback when none exists.
- **Presence:** only plugins with the `presence` capability set `is_online`. An
  offline→online transition writes an `online` device event (unless the device
  has presence-event suppression enabled).
- **Enrichment:** any mapped field that isn't a core device field is stored in
  the `plugin_device_data` table, keyed by `(plugin_id, mac_address)`, and shown
  in the device drawer.
- **Tags:** fields listed in `data_mapping.tag_fields` are merged into the
  device's `tags` (deduplicated). Boolean tag fields can map to label pairs
  (e.g. `wireless: true → "wireless"`, `false → "wired"`).

```json
"data_mapping": { "tag_fields": ["device_type", "wireless"] }
```

---

## 12. Event hooks

Bind an InSpectre event to an action. When the event fires, the engine runs the
action **asynchronously (fire-and-forget)** for every **enabled** plugin that
declares a matching hook.

```json
"event_hooks": {
  "device.new":       "notify_action",
  "vuln.critical":    "notify_action",
  "device.offline":   "notify_action"
}
```

**Valid event keys** and the context each provides:

| Event | Fires when | Context keys |
|---|---|---|
| `device.new` | A device (or new interface) is first seen | `mac`, `name`, `ip` |
| `device.online` | A device comes back online | `mac`, `name`, `ip` |
| `device.offline` | A device goes offline | `mac`, `name`, `ip` |
| `port.opened` | A new open port is detected | `mac`, `name`, `ip`, `ports` |
| `vuln.found` | A vuln scan finds issues | `mac`, `name`, `ip`, `vulns` |
| `vuln.critical` | (reserved severity-specific key) | `mac`, `name`, `ip`, `vulns` |
| `vuln.high` | (reserved severity-specific key) | `mac`, `name`, `ip`, `vulns` |
| `device.blocked` | A device was successfully blocked | `mac`, `ip` |
| `device.unblocked` | A device was unblocked | `mac`, `ip` |

Context keys are available as `{mac}`, `{ip}`, `{name}`, etc. in the hooked
action's `path`/`body`.

> **Don't** hook a blocking plugin's own `device.blocked → block_client` — the
> [blocking coordinator](#14-the-blocking-contract) already calls `block_client`
> directly; hooking it again would double-fire. Event hooks are for *reacting* to
> events (e.g. sending a notification), not for re-doing the action that caused
> them.

---

## 13. Polling

Run action(s) on a schedule. Results are upserted into the inventory when the
plugin has `discovery` or `presence` capability.

```json
"polling": {
  "action": "get_clients",
  "interval_seconds": 120,
  "run_on_startup": true,
  "max_rate_per_minute": 30
}
```

| Key | Description |
|---|---|
| `action` | Single action name to poll. |
| `actions` | Array of action names (results merged, last write wins per MAC). Use instead of `action`. |
| `interval_seconds` | Poll interval. Default 300. |
| `run_on_startup` | Conventional flag. Polling begins shortly after the plugin is enabled (after a ~30 s startup grace), regardless. |
| `max_rate_per_minute` | Optional per-action rate cap enforced by the engine. |

---

## 14. The blocking contract

A plugin that declares `"blocking"` participates in InSpectre's pluggable
blocking system. The blocking coordinator calls the plugin when the user selects
its method under **Settings → Security Responses → Blocking Method**.

### Required actions

A blocking plugin **must** define exactly these two actions:

```json
"block_client":   { "method": "POST", "path": "/your/block",   "body": { "mac": "{mac}", "ip": "{ip}" } },
"unblock_client": { "method": "POST", "path": "/your/unblock", "body": { "mac": "{mac}", "ip": "{ip}" } }
```

Both receive `{mac}`, `{mac_dash}`, and `{ip}` for substitution, and may use
`depends_on` for auth.

### Method category

The block method shown in the UI is derived from capabilities:

| Method | Requires |
|---|---|
| `dns` | `blocking` + `dns` |
| `firewall` | `blocking` + `firewall` |
| `infrastructure` | `blocking` (without `dns`/`firewall`) |

`arp` (probe-native ARP poisoning) is always available. A method is only offered
if at least one enabled, configured plugin qualifies.

### Validation

Saving `block_plugin_id` validates that the plugin exists, is enabled, declares
`blocking`, and defines both `block_client` and `unblock_client`.

### Events emitted

After a successful block/unblock, InSpectre emits `device.blocked` /
`device.unblocked` on the event bus, so **other** plugins can react via
`event_hooks`.

### List directives

Some APIs require read-modify-write of a list (e.g. an allow/deny list).
A `body` value can be a directive that operates on a list fetched by a
`depends_on` action:

```json
"body": {
  "disallowed_clients": { "_list_append": "get_access.disallowed_clients", "_value": "{ip}" }
}
```

| Directive | Effect |
|---|---|
| `_list_append` | Append `_value` if not already present. |
| `_list_remove` | Remove `_value`. |
| `_list_passthrough` | Use the existing list unchanged. |

See the built-in `adguard-home` plugin for a real example.

---

## 15. File & SNMP plugins

**File source** — read and parse a local (container) file instead of HTTP:

```json
"read_leases": {
  "source": "file",
  "file_key": "leases_path",
  "file_format": "dnsmasq",
  "response_mapping": { "fields": { "mac_address": "mac_address", "ip_address": "ip_address" } }
}
```

`file_key` names the config field holding the path; `file_format` is one of
`dnsmasq`, `isc_dhcp`, `csv`, or `json`. Mount the file into the backend
container via `volumes:`.

**SNMP** — when an action's resolved URL uses an `snmp://`/`snmps://` scheme, the
engine performs an SNMP GET/WALK:

```json
"get_arp": { "path": "", "snmp_oid": "1.3.6.1.2.1.4.22.1.2", "snmp_operation": "WALK" }
```

(`community` / `snmp_port` come from config; requires `pysnmp` in the backend.)

---

## 16. Webhook-triggered actions

Mark one action with `"trigger": "webhook"`. An external system can then POST to:

```
POST /api/plugins/{plugin_id}/webhook
```

The posted JSON becomes the action's **context** (usable as `{placeholders}`),
the action runs, and any devices it maps fire `device.online`/`device.offline`
events. If a `webhook_secret` config field is set, the sender must include a
valid `X-Hub-Signature-256` HMAC header.

> This is an advanced trigger: the action still performs its declared HTTP call
> (the payload supplies template values), and webhook results are surfaced via
> the event bus rather than written straight to the inventory. For most
> integrations, prefer [polling](#13-polling).

---

## 17. Overriding a built-in plugin

An uploaded plugin may reuse a built-in `id`. When it does, **the uploaded
manifest wins** for that container session, while the stored config and
enabled/disabled state are preserved. A log line confirms it:

```
[plugins] Uploaded plugin 'tplink-omada' overrides builtin — using uploaded manifest.
```

The on-disk built-in JSON is never modified. To restore it, delete the uploaded
plugin (`DELETE /api/plugins/{id}`) and restart — InSpectre re-registers the
built-in automatically.

> Note: uploading a plugin whose `id` matches a built-in via the UI is rejected
> with a conflict error; overrides are applied to plugins already stored as
> `uploaded` in the database.

---

## 18. Testing & validation

The manifest is validated on upload; common errors: bad `id` format, unknown
capability/field-type/event-key/auth method, a `depends_on` pointing at a missing
action, or an invalid `base_url` scheme.

Sanity-check locally before uploading:

```bash
# JSON
python3 -c "import json,sys; json.load(open(sys.argv[1])); print('JSON OK')" my-plugin.json
# YAML
python3 -c "import yaml,sys; yaml.safe_load(open(sys.argv[1])); print('YAML OK')" my-plugin.yaml
```

Relevant API endpoints (all require auth):

| Method & path | Purpose |
|---|---|
| `GET /api/plugins` | List plugins + status. |
| `POST /api/plugins/upload` | Upload a manifest (`.json`/`.yaml`). |
| `PUT /api/plugins/{id}/config` | Save config. |
| `POST /api/plugins/{id}/enable` · `/disable` | Toggle. |
| `POST /api/plugins/{id}/test` | Run `test_connection`. |
| `POST /api/plugins/{id}/poll` | Poll immediately. |
| `GET /api/plugins/{id}/data` | Per-device enrichment data. |
| `DELETE /api/plugins/{id}` | Remove an uploaded plugin. |

After enabling, watch the logs to confirm polling and mapping:

```bash
./inspectre.sh logs web | grep plugin
```

---

## 19. Built-in plugin reference

The shipped manifests in
[`backend/plugins/builtin/`](backend/plugins/builtin/) are the best real-world
examples — read them alongside this guide.

| Plugin | ID | Capabilities |
|---|---|---|
| AdGuard Home | `adguard-home` | `discovery`, `enrichment`, `dns`, `traffic`, `blocking` |
| Pi-hole | `pihole` | `discovery`, `enrichment`, `dns`, `traffic`, `blocking` |
| TP-Link Omada | `tplink-omada` | `discovery`, `presence`, `blocking`, `enrichment` |
| Home Assistant | `home-assistant` | `export`, `notification` |
| OPNsense | `opnsense` | `discovery`, `enrichment`, `blocking`, `firewall` |
| pfSense | `pfsense` | `discovery`, `enrichment`, `blocking`, `firewall` |

### AdGuard Home blocking notes

`block_client` posts the device IP to `/control/access/set`'s
`disallowed_clients` list using a read-modify-write [list directive](#list-directives).

### Pi-hole blocking notes

`block_client` assigns the device to a Pi-hole group (configured via
`block_group_id`) through `PUT /api/clients/{ip}`. Create a dedicated "Blocked"
group in Pi-hole (Settings → Groups) whose blocklist prevents all resolution,
and set its numeric ID. `unblock_client` returns the device to group 0.
