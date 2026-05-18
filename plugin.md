# InSpectre Plugin Development Guide

This guide explains how to create plugins for InSpectre — from a simple file-based DHCP importer to a full REST API integration with session authentication and scheduled polling.

---

## Overview

Plugins are defined as a single **JSON manifest file**. A manifest describes everything InSpectre needs to know about your plugin: what it does, how to authenticate, what API calls to make, and how to map the response data into InSpectre device records.

Built-in plugins live in `backend/plugins/builtin/` and are loaded automatically on startup. Custom plugins can be uploaded via the InSpectre UI and are stored in the database.

---

## Manifest Structure

A manifest is a JSON object with the following top-level fields:

| Field | Required | Description |
|---|---|---|
| `id` | ✅ | Unique identifier. Lowercase alphanumeric with hyphens only (e.g. `my-plugin`). |
| `name` | ✅ | Human-readable display name. |
| `version` | ✅ | Semver string (e.g. `1.0.0`). |
| `capabilities` | ✅ | Array of capability strings (see [Capabilities](#capabilities)). |
| `config_schema` | ✅ | Array of user-configurable fields (see [Config Schema](#config-schema)). |
| `author` | ❌ | Plugin author name or organisation. |
| `description` | ❌ | Short description shown in the UI. |
| `homepage` | ❌ | URL to documentation or project page. |
| `min_inspectre_version` | ❌ | Minimum InSpectre version required. |
| `icon` | ❌ | Icon URL or `null`. |
| `endpoints` | ❌ | HTTP/SNMP connection settings (see [Endpoints](#endpoints)). |
| `actions` | ❌ | Named API calls this plugin can make (see [Actions](#actions)). |
| `event_hooks` | ❌ | Map InSpectre events to action names (see [Event Hooks](#event-hooks)). |
| `data_mapping` | ❌ | Extra metadata for blocking and tag fields (see [Data Mapping](#data-mapping)). |
| `polling` | ❌ | Schedule a recurring action to run automatically (see [Polling](#polling)). |

---

## Capabilities

The `capabilities` array declares what your plugin can do. At least one is required.

| Value | Description |
|---|---|
| `discovery` | Finds and imports new devices into InSpectre inventory. |
| `presence` | Reports whether existing devices are currently online or offline. |
| `enrichment` | Adds extra metadata to devices (vendor, type, tags, etc.). |
| `blocking` | Can block/unblock a device on the network. |
| `dns` | Provides DNS resolution or hostname enrichment. |
| `traffic` | Reports traffic/bandwidth data. |
| `export` | Exports InSpectre data to an external system. |
| `notification` | Sends notifications (e.g. Slack, webhook, email). |

```json
"capabilities": ["discovery", "presence", "enrichment"]
```

---

## Config Schema

`config_schema` defines the settings the user fills in when enabling the plugin. Each entry is an object:

| Field | Required | Description |
|---|---|---|
| `key` | ✅ | The config key. Referenced as `{key}` in templates. |
| `label` | ✅ | Human-readable label shown in the UI. |
| `type` | ❌ | Field type (default: `string`). See below. |
| `default` | ❌ | Default value pre-populated in the form. |
| `required` | ❌ | Whether the field must be filled (default: `false`). |
| `help` | ❌ | Help text shown beneath the field. |
| `options` | ❌ | Array of `{value, label}` objects for `select` type. |

**Valid types:** `string`, `password`, `integer`, `boolean`, `select`, `multiline`, `url`, `filepath`

> **Note:** Fields with `type: "password"` are stored encrypted in the database using a `SECRET_KEY`-derived Fernet key. The value is automatically decrypted when your action runs.

```json
"config_schema": [
  {
    "key": "host",
    "label": "Controller URL",
    "type": "url",
    "default": "https://192.168.1.1:8043",
    "required": true,
    "help": "Full URL including port number."
  },
  {
    "key": "api_key",
    "label": "API Key",
    "type": "password",
    "required": true
  },
  {
    "key": "verify_ssl",
    "label": "Verify SSL Certificate",
    "type": "boolean",
    "default": false
  }
]
```

---

## Endpoints

The `endpoints` block defines connection-level settings shared across all actions.

| Field | Description |
|---|---|
| `base_url` | Base URL prepended to every action `path`. Supports `{config_key}` substitution. |
| `auth` | Authentication method (see [Authentication](#authentication)). Default: `none`. |
| `headers` | Static headers merged into every request. Supports `{config_key}` and `{session_extras}` substitution. |
| `session_headers` | Map of `session.extras key → HTTP header name`. Auto-injects session values as headers. |
| `verify_ssl` | Boolean SSL verification override. Can also be set per-plugin via `config_schema`. |

**Valid auth methods:** `none`, `basic`, `bearer`, `cookie`, `api-key-header`, `api-key-param`

```json
"endpoints": {
  "base_url": "{host}",
  "auth": "bearer",
  "headers": {
    "Content-Type": "application/json"
  },
  "verify_ssl": false
}
```

---

## Actions

`actions` is an object where each key is an action name and each value defines what InSpectre should do when that action is called.

| Field | Description |
|---|---|
| `description` | Human-readable description of what this action does. |
| `method` | HTTP verb: `GET`, `POST`, `PUT`, `DELETE`, `PATCH`. Default: `GET`. |
| `path` | URL path appended to `base_url`. Supports `{config_key}` and `{context_key}` substitution. |
| `body` | JSON request body. Supports `{key}` substitution. |
| `depends_on` | Name of another action that must run first. Its result is injected into the context. |
| `source` | Set to `"file"` for file-based actions instead of HTTP. |
| `file_key` | Config key containing the file path (for `source: "file"`). |
| `file_format` | `json`, `csv`, `dnsmasq`, or `isc_dhcp` (for `source: "file"`). |
| `session_extract` | Extract values from the response into the session store (see [Session Extraction](#session-extraction)). |
| `response_mapping` | Map response JSON fields to InSpectre device fields (see [Response Mapping](#response-mapping)). |
| `snmp_oid` | OID to query (for SNMP URLs). |
| `snmp_operation` | `GET` or `WALK` (for SNMP URLs). |

### Template Substitution

All `path`, `body`, and `base_url` values support `{key}` placeholder substitution. InSpectre resolves keys in this order:

1. User config values (from `config_schema`)
2. Context values passed at runtime (e.g. `{mac}`, `{ip}` for event hooks)
3. Session extras extracted by prior actions in a `depends_on` chain

```json
"path": "/api/v1/{omadacId}/sites/{site_id}/clients?page=1&pageSize=200"
```

### Action Chaining with `depends_on`

When an action declares `depends_on`, InSpectre runs the dependency first and merges its response data into the context before running the current action. This is how multi-step auth flows work — for example, fetching a controller ID, then exchanging credentials for a token, then calling a data endpoint.

```json
"actions": {
  "get_token": {
    "method": "POST",
    "path": "/auth/token",
    "body": { "username": "{username}", "password": "{password}" },
    "session_extract": { "from": "response_body", "json_path": "data.token", "store_as": "access_token" }
  },
  "get_devices": {
    "depends_on": "get_token",
    "method": "GET",
    "path": "/api/devices"
  }
}
```

Chain depth is limited to **3 levels** to prevent infinite loops.

---

## Authentication

### `none`
No authentication. Useful for open APIs or file-based plugins.

### `basic`
HTTP Basic Auth. Reads `user` and `password` from config.

### `bearer`
Bearer token auth. InSpectre automatically calls the `login` action to obtain a token, stores it in the session, and attaches it as `Authorization: Bearer <token>`. On a `401`/`403` response, the session is cleared and login is retried once.

### `cookie`
Cookie-based session auth. InSpectre calls `login`, captures all `Set-Cookie` headers automatically, and replays them on subsequent requests.

### `api-key-header`
Injects `config.api_key` into the header named by `config.api_key_header` (defaults to `X-API-Key`).

### `api-key-param`
API key as a query parameter (handled by template substitution in `path`).

---

## Session Extraction

`session_extract` tells InSpectre where to find values in a response and store them for use in later requests. It can be a single object or an array of objects for multiple extractions.

| Field | Description |
|---|---|
| `from` | Source: `response_body`, `response_cookies`, or `response_headers`. |
| `key` | Key/header name to look up (for cookies and headers). |
| `json_path` | Dot-notation path into the JSON response body (e.g. `result.accessToken`). Supports list index traversal (e.g. `result.data.0.id`). |
| `store_as` | Name to store the extracted value under in `session.extras`. |
| `ttl_field` | JSON field name whose value (in seconds) sets the token expiry time. |

Stored values become available as `{store_as}` placeholders in subsequent action paths and bodies.

```json
"session_extract": [
  {
    "from": "response_body",
    "json_path": "result.omadacId",
    "store_as": "omadacId"
  },
  {
    "from": "response_body",
    "json_path": "result.accessToken",
    "store_as": "access_token",
    "ttl_field": "result.expiresIn"
  }
]
```

---

## Response Mapping

`response_mapping` maps fields from your API response to InSpectre's canonical device fields. InSpectre uses these to upsert devices into inventory.

| Field | Description |
|---|---|
| `root_path` | Dot-notation path to the list of devices in the response (e.g. `result.data`). Supports list index segments. |
| `fields` | Object mapping `api_field_name → inspectre_field_name`. |

**InSpectre canonical device fields:** `mac_address`, `ip_address`, `hostname`, `vendor`, `device_type`, `is_online`, `vlan`

> Any mapped field not in the canonical list is stored as enrichment data in `plugin_device_data` rather than in the main `devices` table.

MAC addresses are automatically normalised to `AA:BB:CC:DD:EE:FF` format. Only devices with a valid MAC are imported.

```json
"response_mapping": {
  "root_path": "result.data",
  "fields": {
    "mac": "mac_address",
    "ip": "ip_address",
    "name": "hostname",
    "vendor": "vendor",
    "active": "is_online"
  }
}
```

---

## Data Mapping

The optional `data_mapping` block provides additional hints to InSpectre about how to use your plugin's data.

| Field | Description |
|---|---|
| `block_id_field` | Which device field to use as the identifier when blocking/unblocking (usually `mac_address`). |
| `tag_fields` | Array of field names from the response to apply as device tags. Boolean fields use `BOOL_TAG_LABELS` — currently `wireless` maps to `"wireless"` (true) or `"wired"` (false). Other string fields are lowercased and added as-is. |

```json
"data_mapping": {
  "block_id_field": "mac_address",
  "tag_fields": ["wireless", "device_type"]
}
```

---

## Event Hooks

`event_hooks` maps InSpectre system events to action names. When an event fires (e.g. a new device is found), InSpectre calls the specified action asynchronously with device context.

**Valid event keys:**

| Event | Fired when... |
|---|---|
| `device.new` | A new device is discovered for the first time. |
| `device.online` | A known device comes back online. |
| `device.offline` | A device stops responding. |
| `port.opened` | A new open port is detected on a device. |
| `vuln.found` | Any new vulnerability is found. |
| `vuln.critical` | A critical severity vulnerability is found. |
| `vuln.high` | A high severity vulnerability is found. |

Context available in event actions: `{mac}`, `{name}`, `{ip}`, `{ports}`, `{vulns}`

```json
"event_hooks": {
  "device.new": "publish_device_joined",
  "device.online": "publish_device_online",
  "device.offline": "publish_device_offline"
}
```

---

## Polling

The `polling` block schedules an action to run automatically on a timer.

| Field | Description |
|---|---|
| `action` | The action name to run on each poll cycle. |
| `interval_seconds` | How often to run the action (default: `300`). |
| `run_on_startup` | Whether to run immediately on startup as well. |
| `max_rate_per_minute` | Rate limit — if the action is triggered more than this many times per minute, excess calls are rejected. |

The scheduler wakes every 30 seconds and runs any due polls. On success, the plugin status is set to `active`. On failure, the status is set to `error` with the error message stored.

```json
"polling": {
  "action": "get_clients",
  "interval_seconds": 60,
  "run_on_startup": true
}
```

---

## File-Based Plugins

For plugins that read a local file instead of calling an API, set `"source": "file"` on the action.

| Format | Description |
|---|---|
| `json` | JSON file — returned as-is. |
| `csv` | CSV file — parsed into an array of row objects. |
| `dnsmasq` | `dnsmasq.leases` format: `<epoch> <mac> <ip> <hostname> <client-id>` |
| `isc_dhcp` | ISC DHCP `dhcpd.leases` format. |

```json
"actions": {
  "read_leases": {
    "source": "file",
    "file_key": "filepath",
    "file_format": "dnsmasq",
    "response_mapping": {
      "root_path": "",
      "fields": {
        "mac_address": "mac_address",
        "ip_address": "ip_address",
        "hostname": "hostname"
      }
    }
  }
},
"config_schema": [
  {
    "key": "filepath",
    "label": "Path to leases file",
    "type": "filepath",
    "default": "/var/lib/misc/dnsmasq.leases",
    "required": true
  }
]
```

---

## SNMP Plugins

Use an SNMP URL scheme in `base_url` to query devices via SNMP. Requires `pysnmp` to be installed.

```json
"endpoints": {
  "base_url": "snmp://{host}:161"
},
"actions": {
  "get_sysinfo": {
    "snmp_oid": "1.3.6.1.2.1.1",
    "snmp_operation": "WALK"
  }
},
"config_schema": [
  { "key": "host", "label": "Device IP", "type": "string", "required": true },
  { "key": "community", "label": "SNMP Community", "type": "string", "default": "public" }
]
```

---

## Installing a Plugin

### Built-in plugins
Place your `.json` manifest in `backend/plugins/builtin/`. It will be loaded on next container start and registered automatically in the database.

### Uploaded plugins
Use the **Plugins** page in the InSpectre UI to upload your manifest JSON. The plugin is validated immediately on upload and stored in the database. It will not activate until enabled and configured.

---

## Validation Rules

InSpectre validates every manifest on load. Your plugin will be skipped (or upload rejected) if any of these rules are violated:

- `id`, `name`, `version`, `capabilities`, `config_schema` are all required
- `id` must match `^[a-z0-9][a-z0-9\-]*[a-z0-9]$` (or be a single alphanumeric character)
- All capabilities must be from the valid set
- All config field types must be from the valid set
- `endpoints.auth` must be a valid auth method
- `endpoints.base_url` scheme (if present) must be `http`, `https`, `mqtt`, `mqtts`, `snmp`, or `snmps`
- Event hook keys must be from the valid set
- Any action's `depends_on` must reference another action defined in the same manifest
- Any action's `file_format` must be `json`, `csv`, `dnsmasq`, or `isc_dhcp`

---

## Full Example — REST API Plugin with Auth

The following is a complete example of a plugin that authenticates via bearer token, polls for devices, and supports blocking.

```json
{
  "id": "my-router",
  "name": "My Router",
  "version": "1.0.0",
  "author": "You",
  "description": "Discovers devices from a router API with bearer token auth.",
  "capabilities": ["discovery", "presence", "blocking"],
  "config_schema": [
    {
      "key": "host",
      "label": "Router URL",
      "type": "url",
      "default": "http://192.168.1.1",
      "required": true
    },
    {
      "key": "username",
      "label": "Username",
      "type": "string",
      "required": true
    },
    {
      "key": "password",
      "label": "Password",
      "type": "password",
      "required": true
    },
    {
      "key": "verify_ssl",
      "label": "Verify SSL",
      "type": "boolean",
      "default": true
    }
  ],
  "endpoints": {
    "base_url": "{host}",
    "auth": "bearer",
    "headers": {
      "Content-Type": "application/json"
    }
  },
  "actions": {
    "login": {
      "description": "Authenticate and retrieve an access token.",
      "method": "POST",
      "path": "/api/auth/login",
      "body": {
        "username": "{username}",
        "password": "{password}"
      },
      "session_extract": {
        "from": "response_body",
        "json_path": "data.token",
        "store_as": "access_token"
      }
    },
    "get_devices": {
      "description": "Fetch all connected devices.",
      "method": "GET",
      "path": "/api/devices",
      "response_mapping": {
        "root_path": "data.clients",
        "fields": {
          "mac": "mac_address",
          "ip": "ip_address",
          "name": "hostname",
          "manufacturer": "vendor",
          "connected": "is_online"
        }
      }
    },
    "block_device": {
      "description": "Block a device by MAC address.",
      "method": "POST",
      "path": "/api/devices/block",
      "body": { "mac": "{mac}" }
    },
    "unblock_device": {
      "description": "Unblock a device by MAC address.",
      "method": "POST",
      "path": "/api/devices/unblock",
      "body": { "mac": "{mac}" }
    },
    "test_connection": {
      "description": "Test credentials and connectivity.",
      "method": "GET",
      "path": "/api/devices?limit=1"
    }
  },
  "event_hooks": {},
  "data_mapping": {
    "block_id_field": "mac_address",
    "tag_fields": []
  },
  "polling": {
    "action": "get_devices",
    "interval_seconds": 120
  }
}
```

---

## Tips & Common Pitfalls

- **Auto-login is automatic.** For `auth: "bearer"` or `auth: "cookie"` plugins, you do not need to call `login` explicitly. InSpectre calls it for you before any non-login action if no valid session exists, and retries once on `401`/`403`.
- **The `login` action name is special.** It is the action InSpectre calls for auto-login. If your auth endpoint has a different name, `depends_on` it from your data actions instead.
- **SSL verification defaults to `true`.** Add a `verify_ssl` boolean config field (as shown in the examples) to let users disable it for self-signed certificates.
- **MAC addresses are normalised automatically.** You do not need to format them — InSpectre accepts any common separator (`:`, `-`, `.`, none) and will normalise to `AA:BB:CC:DD:EE:FF`.
- **Only devices with a valid MAC are imported.** Entries without a resolvable MAC address are silently skipped during response mapping.
- **Enrichment data is stored separately.** Fields not in the canonical device field list (`mac_address`, `ip_address`, `hostname`, `vendor`, `device_type`, `is_online`, `vlan`) are stored in `plugin_device_data` and available for display but do not overwrite core device fields.
- **Action chain depth is capped at 3.** Keep `depends_on` chains short — `A → B → C` is fine, `A → B → C → D` will fail.
