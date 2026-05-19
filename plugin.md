# InSpectre Plugin Development Guide

This guide covers writing plugin manifests for InSpectre, including the blocking contract that lets a plugin participate in device-level network enforcement.

---

## Manifest structure

Every plugin is a single JSON file. The required top-level fields are:

| Field | Type | Description |
|---|---|---|
| `id` | string | Unique, lowercase slug (e.g. `my-plugin`). Must match the filename. |
| `name` | string | Human-readable display name. |
| `version` | string | SemVer string. |
| `capabilities` | array | See Capabilities below. |
| `config_schema` | array | User-configurable fields shown in the plugin config UI. |
| `endpoints` | object | Base URL, auth method, and default headers. |
| `actions` | object | Named HTTP (or SNMP/file) operations. |
| `event_hooks` | object | Map from InSpectre event name → action name. |
| `polling` | object or null | Which action to run on a schedule (and how often). |
| `data_mapping` | object | Optional — tag fields and block-id field. |

---

## Capabilities

Declare an array of zero or more of these strings. InSpectre uses them to decide which plugins appear in which UI and coordinator flows.

| Capability | Meaning |
|---|---|
| `discovery` | Plugin provides MAC/IP/hostname data to enrich the device inventory. |
| `enrichment` | Plugin adds metadata to known devices (vendor, type, etc.). |
| `presence` | Plugin reports whether a device is currently online. |
| `dns` | Plugin is a DNS server or resolver (AdGuard Home, Pi-hole). |
| `traffic` | Plugin provides DNS query logs or flow data. |
| `blocking` | Plugin can enforce per-device network blocks. **See Blocking Contract below.** |
| `firewall` | Plugin controls a stateful firewall (OPNsense, pfSense — future). |
| `export` | Plugin sends InSpectre state to an external system (Home Assistant). |
| `notification` | Plugin delivers alerts (MQTT, push, etc.). |

---

## Blocking Contract

A plugin that declares `"blocking"` in its `capabilities` array participates in InSpectre's pluggable blocking system. InSpectre's blocking coordinator calls the plugin instead of (or in addition to) the probe's ARP poisoning when the user selects the plugin's method in Settings → Security Responses → Blocking Method.

### Required actions

A blocking-capable plugin **must** define exactly these two actions with these exact IDs:

#### `block_client`

Called when InSpectre wants to block a device.

```json
"block_client": {
  "description": "Block a client by MAC and/or IP address.",
  "method": "POST",
  "path": "/your/api/endpoint",
  "body": {
    "mac": "{mac}",
    "ip":  "{ip}"
  }
}
```

#### `unblock_client`

Called when InSpectre wants to remove a block.

```json
"unblock_client": {
  "description": "Remove a block for a client.",
  "method": "POST",
  "path": "/your/api/endpoint",
  "body": {
    "mac": "{mac}",
    "ip":  "{ip}"
  }
}
```

Both actions receive the following context variables for template substitution:

| Variable | Value |
|---|---|
| `{mac}` | Device MAC address in colon-separated lowercase form (`aa:bb:cc:dd:ee:ff`). |
| `{mac_dash}` | Device MAC address in uppercase dash-separated form (`AA-BB-CC-DD-EE-FF`). Required by some APIs (e.g. TP-Link Omada). |
| `{ip}` | Device IP address as a string. May be empty if unknown. |

Actions may depend on an auth action via `"depends_on"` as usual (e.g. `"depends_on": "get_token"`). The engine resolves the dependency chain before calling the block action.

### Method category

InSpectre derives the block method category from the plugin's capabilities:

| Method shown in UI | Requires capabilities |
|---|---|
| `dns` | `blocking` + `dns` |
| `firewall` | `blocking` + `firewall` |
| `infrastructure` | `blocking` (without `dns` or `firewall`) |

The UI only offers a method if at least one enabled, configured plugin qualifies for it. `arp` (probe-native ARP poisoning) is always available.

### Validation

When a user saves `block_plugin_id` in settings, InSpectre validates that the target plugin:
1. Exists and is enabled.
2. Declares `"blocking"` in its `capabilities`.
3. Defines both `block_client` and `unblock_client` actions.

Saving fails with an error message if any check fails.

### Events emitted

After a successful block/unblock, InSpectre emits `device.blocked` or `device.unblocked` on the plugin event bus. Other plugins can listen to these events via `event_hooks`:

```json
"event_hooks": {
  "device.blocked":   "your_notify_action",
  "device.unblocked": "your_notify_action"
}
```

---

## Auth methods

| Value | Mechanism |
|---|---|
| `none` | No auth header sent. |
| `basic` | HTTP Basic Auth from `user` + `password` config fields. |
| `bearer` | `Authorization: Bearer <token>`. Token sourced from `login` action via `session_extract`. |
| `cookie` | Session cookie. Captured automatically from the `login` action's `Set-Cookie` response. |
| `api-key-header` | Custom header name from `api_key_header` config field, value from `api_key`. |

---

## Session extraction (`session_extract`)

Actions can extract values from the response and store them for use in later actions:

```json
"session_extract": {
  "from": "response_body",
  "json_path": "result.accessToken",
  "store_as": "access_token"
}
```

Extracted values are available as `{store_as}` placeholders in subsequent action paths and bodies.

---

## Event hooks

```json
"event_hooks": {
  "device.new":       "action_name",
  "device.online":    "action_name",
  "device.offline":   "action_name",
  "device.blocked":   "action_name",
  "device.unblocked": "action_name",
  "port.opened":      "action_name",
  "vuln.found":       "action_name",
  "vuln.critical":    "action_name",
  "vuln.high":        "action_name"
}
```

Hooks are fired asynchronously (fire-and-forget) after the triggering event.

---

## Polling

```json
"polling": {
  "action": "get_clients",
  "interval_seconds": 120,
  "run_on_startup": true
}
```

The scheduler calls the named action on this interval. Results are upserted into the device inventory if the plugin has `discovery` or `presence` capability.

---

## Built-in plugin reference

| Plugin | ID | Capabilities |
|---|---|---|
| AdGuard Home | `adguard-home` | `discovery`, `enrichment`, `dns`, `traffic`, `blocking` |
| Pi-hole | `pihole` | `discovery`, `enrichment`, `dns`, `traffic`, `blocking` |
| TP-Link Omada | `tplink-omada` | `discovery`, `presence`, `blocking`, `enrichment` |
| Home Assistant | `home-assistant` | `export`, `notification` |

### AdGuard Home blocking notes

`block_client` posts the device IP to `/control/access/set`'s `disallowed_clients` list. This **replaces the entire list** — pre-existing manual access rules will be cleared. Use AdGuard Home's own client-level filtering if you need fine-grained rules alongside InSpectre.

### Pi-hole blocking notes

`block_client` assigns the device to a Pi-hole group (default ID: 1) via `PUT /api/clients/{ip}`. You must create a dedicated "Blocked" group in Pi-hole (Settings → Groups) with a blocklist that prevents all DNS resolution, and configure its numeric ID in the plugin's `block_group_id` config field. `unblock_client` returns the device to group 0 (default).
