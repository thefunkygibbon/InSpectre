# 🛡️ InSpectre

> A self-hosted, Dockerized network security suite focused on device visibility, historical tracking, intelligent fingerprinting, and active diagnostics.

![Version](https://img.shields.io/badge/version-0.6.0-blue) ![Stack](https://img.shields.io/badge/stack-FastAPI%20%2B%20React%20%2B%20PostgreSQL-informational) ![License](https://img.shields.io/badge/license-MIT-green)

---

## What is InSpectre?

InSpectre continuously monitors your local network using ARP scanning and passive sniffing. Every device that appears on your network is recorded, tracked over time, and presented in a polished React dashboard. You can run live diagnostics, annotate devices with notes and tags, watch for devices going offline, and build up a local fingerprint database to automatically classify device types.

---

## Features

### 🔍 Network Discovery
- **Hybrid ARP presence detection** — active ARP sweep combined with a passive Scapy sniffer thread for near-instant device detection
- **Miss-count offline logic** — a device must miss 5 consecutive sweeps before being marked offline, preventing false positives from transient ARP gaps
- **IP history tracking** — every IP address a device has ever held is recorded with first/last seen timestamps
- **Auto-rescan on IP change** — when a device gets a new stable IP lease, a deep port scan is automatically queued
- **Multi-strategy hostname resolution** — resolves via the LAN DNS server (not Docker's internal resolver), with a configurable `LAN_DNS_SERVER` env var and gateway IP fallback
- **Non-blocking sniffer** — callbacks are dispatched via a worker queue so the sniffer thread never stalls on DB or HTTP calls

### 📊 React Dashboard
- **Live device grid** — cards update every 10 seconds with animated stat counters
- **Three layout modes** — Grid, List, and Category view (devices grouped by inferred type)
- **Clickable stat cards** — clicking Total / Online / Offline / Watched filters the device list instantly, toggling off on a second click
- **Sort controls** — sort by last seen, IP address, name, vendor, status, or watched-first
- **Full-text search** — searches across IP, MAC, hostname, vendor, custom name, tags, and location
- **Smart filter bar** — contextual quick-filters (e.g. "has open ports", "scanned", "has notes") applied on top of the main filter
- **Light / dark mode** — system preference respected, manual toggle in the navbar
- **Live clock** — ticking timestamp in the navbar header
- **Custom SVG logo** — animated crosshair/radar mark

### 🖥️ Device Detail Drawer
Click any device to open a slide-in drawer with three tabs:

**Overview tab**
- Online/offline status badge, scan status, identity-confirmed badge, watched badge
- **Actions panel** — Ping, Traceroute, Re-scan ports, Vulnerability scan (Phase 3), Block internet access (Phase 4)
- Live terminal output box — output streams in real time via SSE with a stop button; auto-scrolls and stays within the box
- Network details — IP, MAC, vendor, hostname (with re-resolve button), custom name, location, miss count
- Collapsible IP history table
- Timeline summary — first seen, last seen, last scanned
- OS detection results with confidence percentages
- Open ports list — web ports are clickable external links
- **Device Identity form** — override vendor (with autocomplete from known vendors) and device type; saves a fingerprint entry to the local DB
- **Rename form** — set a custom display name

**Timeline tab** — chronological event log (joined, online, offline, IP change, scan complete)

**Notes & Tags tab**
- Free-text notes textarea
- Location / room field
- Tag chips — type and press Enter or comma to add; click × to remove
- Saved persistently to the database

### ⭐ Watched Devices
- Star any device from the card, list row, or drawer header
- Watched devices get a dedicated stat card and sort option
- Offline toasts for watched devices are highlighted in red with a star icon
- Optimistic UI update — the star flips instantly, syncs to the backend, reverts on failure

### 🔔 Toast Notifications
- **New device detected** — teal toast with IP, hostname/vendor, and MAC
- **Device went offline** — standard offline toast; red-highlighted if the device is watched
- Both toast types auto-dismiss after 7 seconds
- Clicking anywhere on a toast opens the device drawer directly
- Bell icon in the navbar shows unread alert count with a dropdown list
- Notifications can be toggled off in Settings

### 🧠 Device Fingerprinting & Classification
- **Multi-signal confidence engine** — scores OUI prefix, hostname keywords, and open port evidence independently, then combines them
- **Tiered OUI scoring** — ambiguous mega-vendors (Samsung, Apple, TP-Link, Huawei, etc.) score only 25–35 so they can't auto-classify alone; specific single-purpose vendors (Hikvision, Ubiquiti, Nintendo, Synology, etc.) score 90–95
- Minimum confidence threshold of 60 before a type is auto-assigned
- **Community fingerprint DB** — manual identity corrections are stored as `FingerprintEntry` rows with OUI prefix, hostname pattern, port evidence, hit count, and confidence score
- **Export / import fingerprints** — download your trained DB as JSON and import it on another instance (merges with hit-count increment on duplicates)
- **Category view** — devices grouped and labelled by inferred type (router, smart TV, IoT, NAS, console, laptop, phone, etc.)

### ⚙️ Settings Panel
- Scan interval, IP range, network interface, Nmap arguments — all configurable at runtime
- Toggle notifications on/off
- Export all devices as CSV
- Export / import fingerprint database as JSON
- Settings seeded with defaults on first startup

### 🐳 Docker & Operations
- Full Docker Compose setup — `web` (FastAPI backend), `probe` (scanner), `db` (PostgreSQL), `frontend` (React/Vite/Nginx)
- DB healthcheck ensures `web` and `probe` wait for PostgreSQL to be ready before starting
- `inspectre.sh` management script — start, stop, rebuild, update with clean image/cache handling scoped to InSpectre containers only (no system-wide `docker prune`)
- Probe exposes an HTTP API on `:8001` for ping/traceroute SSE streams and on-demand rescans
- Probe API uses thread-safe synchronous uvicorn startup
- `LAN_DNS_SERVER` env var to point hostname resolution at your router

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Backend API** | Python 3, FastAPI, SQLAlchemy, PostgreSQL |
| **Network Probe** | Python 3, Scapy (ARP sweep + passive sniffer), Nmap |
| **Frontend** | React 18, Vite, Tailwind CSS, Lucide icons |
| **Database** | PostgreSQL 15 |
| **Deployment** | Docker Compose, Nginx (frontend) |

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/thefunkygibbon/InSpectre.git
cd InSpectre

# Configure your network (edit docker-compose.yml)
# Set IP_RANGE, INTERFACE, LAN_DNS_SERVER to match your network

# Start everything
./inspectre.sh start

# Dashboard will be available at http://<your-server-ip>:5173
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `IP_RANGE` | `192.168.1.0/24` | Network range to scan |
| `INTERFACE` | `eno1` | Network interface for ARP sniffing |
| `SCAN_INTERVAL` | `60` | Seconds between ARP sweeps |
| `NMAP_ARGS` | `-sV -O --osscan-limit` | Arguments passed to Nmap deep scans |
| `LAN_DNS_SERVER` | *(gateway IP)* | DNS server for hostname resolution (set to your router IP) |
| `OFFLINE_MISS_THRESHOLD` | `5` | Missed sweeps before marking a device offline |

### `inspectre.sh` Commands

```bash
./inspectre.sh start      # Build and start all containers
./inspectre.sh stop       # Stop and remove containers
./inspectre.sh restart    # Stop then start
./inspectre.sh rebuild    # Stop, remove InSpectre images/cache, rebuild from scratch
./inspectre.sh logs       # Tail logs from all containers
```

---

## Changelog

### v0.6.0 — 12 Apr 2026
- **Device watching** — star any device to mark it as "watched"; new Watched stat card and sort option
- **Device events & timeline** — `DeviceEvent` table records `joined`, `online`, `offline`, `ip_change`, and `scan_complete` events; Timeline tab in drawer shows the full chronological log
- **Device notes, tags & location** — Notes & Tags drawer tab with persistent free-text notes, location field, and tag chip input
- **Smart filter bar** — contextual quick-filters rendered above the device list
- **Identity scoring dashboard** — `/fingerprints/stats` endpoint; CSV device export and fingerprint JSON export/import exposed in the settings panel
- **Probe event emission** — probe upsert now emits all five event types and correctly preserves `is_important=FALSE` on conflict
- Fixed `\u2026` / `\u2014` unicode escape sequences rendering as literal text in the UI

### v0.5.0 — 10–11 Apr 2026
- **Clickable stat cards** — Total, Online, Offline, and Deep Scanned cards now act as filter toggles
- **Offline false-positive fix** — raised `OFFLINE_MISS_THRESHOLD` to 5; sweep now skips miss-count increment if the sniffer saw the device within the current scan interval
- **Deep-scan stability fix** — `deep_scanned` and `scan_results` are now preserved on upsert conflict; IP-change rescan requires the new IP to have been stable for >2 seconds
- **Fingerprint DB + identity editing** — community fingerprint table, `PATCH /devices/{mac}/identity` endpoint, vendor/type overrides in the drawer, autocomplete from known vendors
- **Tiered confidence engine** — ambiguous mega-vendor OUI scores capped at 25–35; minimum confidence threshold raised to 60
- **Settings panel fixed** — missing `/settings` routes added; default settings seeded on startup
- **Export / import** — `GET /export/devices` (CSV), `GET /export/fingerprints` (JSON), `POST /import/fingerprints` (merge with hit-count increment)
- **DNS resolution overhaul** — `LAN_DNS_SERVER` env var; fallback to gateway IP when `/etc/resolv.conf` contains only loopback addresses; resolve-name button routed through the probe API
- **IP history** — `ip_history` table with UNIQUE constraint migration for existing databases
- **Manual fingerprint entries** — saving an identity override now creates/updates a `FingerprintEntry` with `source='manual'`
- Fixed `0.0.0.0` IP being recorded; guard against false IP-change rescans
- Fixed `display_name` not being populated in the `useDevices` hook
- Category view wired into the App with a layout toggle button
- Fixed `deep_scanned` fluctuating on transient IP changes

### v0.4.0 — 10 Apr 2026
- **Category view** — multi-signal device classification engine; grouped view with device-type labels and icons
- **Live ping & traceroute** — real-time output streamed via SSE; probe HTTP server on `:8001`, backend proxy, frontend `EventSource` with `useStreamAction` hook
- **Stop button** for running ping/traceroute streams
- **Toast notifications** — new-device detected and offline-drop toasts with auto-dismiss and click-to-open-drawer
- **Hostname resolution overhaul** — routes through probe API for correct LAN DNS access
- **Actions grid** — Ping, Traceroute, Re-scan ports, Vulnerability scan (stub) in the drawer
- **Clickable open ports** — HTTP/HTTPS ports open in a new tab
- Fixed terminal scroll staying inside the box; probe API uses thread-safe synchronous uvicorn
- Fixed `inspectre.sh` to scope image/cache cleanup to InSpectre containers only
- Fixed settings panel blank page (missing API routes)

### v0.3.0 — 9–10 Apr 2026
- **Visual overhaul** — richer design tokens, animated stat counters (`useCountUp`), device-type icons, header glow, noise texture overlay, skeleton loaders
- **Light / dark mode** — system preference + manual toggle
- **Sort controls** — 8 sort options (last seen, IP, name, vendor, status)
- **List / grid layout toggle**
- **Multi-strategy hostname resolution** improvements
- **IP history table** — `IpHistory` model, `record_ip()` called on every sweep, collapsible section in drawer
- **Settings CRUD API** — `/settings`, `/settings/{key}`, `/settings/reset` endpoints
- **DB healthcheck** — `web` and `probe` services wait for PostgreSQL to pass its healthcheck before starting
- Fixed non-blocking sniffer callback via worker queue
- Fixed atomic upsert to prevent duplicate-key race conditions
- Stricter OS detection confidence filtering

### v0.2.0 — 9 Apr 2026
- **React/Vite frontend** — full dashboard with device grid, detail drawer, and settings panel added as a Docker service
- **FastAPI backend** — device management endpoints, statistics endpoint, rename endpoint
- **Settings model** — full settings CRUD
- **Hybrid ARP presence detection** — passive Scapy sniffer thread + miss-count field + `OFFLINE_MISS_THRESHOLD`
- `inspectre.sh` management script introduced

### v0.1.0 — 8–9 Apr 2026
- Initial project scaffold
- ARP network scanning with Scapy
- PostgreSQL device model with timezone-aware datetimes
- FastAPI root endpoint and device endpoints
- Docker Compose with `web`, `probe`, and `db` services
- Environment variables for IP range, interface, scan interval, and Nmap arguments

---

## Roadmap

| Phase | Feature | Status |
|---|---|---|
| Phase 1 | Device events, notes, tags, timeline, star/watch | ✅ Done |
| Phase 2 | Identity fingerprinting, category view, export/import | ✅ Done |
| Phase 3 | Vulnerability scanning (Nmap NSE scripts) | 🔜 Planned |
| Phase 4 | Block internet access via ARP spoofing kill-switch | 🔜 Planned |
| Phase 5 | Alerting webhooks (Discord, email, Gotify) | 🔜 Planned |

---

## Author

Developed by [thefunkygibbon](mailto:inspectre@thefunkygibbon.net)
