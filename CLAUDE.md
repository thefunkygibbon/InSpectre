# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

---

## Stack at a glance

| Layer | Tech |
|---|---|
| Frontend | React 18 + Vite + Tailwind CSS (no router, single-page) |
| Backend API | FastAPI (Python) served on port 8000 |
| Probe | FastAPI (Python) served on port 8666, runs on host network |
| Database | PostgreSQL 15 |
| Container orchestration | Docker Compose |

---

## Running the stack

All stack management goes through `inspectre.sh`:

```bash
./inspectre.sh up               # start
./inspectre.sh down             # stop
./inspectre.sh rebuild          # full wipe + rebuild (deletes postgres_data/)
./inspectre.sh rebuild keep-data  # rebuild but preserve database
./inspectre.sh logs             # tail all container logs
```

These wrap `docker compose` — there is no separate make/npm workflow for production. The script rebuilds from **local files only** and never runs git commands.

**Frontend dev server** (hot reload, no Docker):
```bash
cd frontend
npm install
npm run dev        # Vite dev server, proxies /api → backend
npm run build      # production build
```

**Backend dev** (outside Docker):
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

There are no automated tests.

---

## Architecture

### Three-container model

```
Browser → [frontend :3000] → nginx → [backend :8000] → PostgreSQL
                                              ↕ httpx
                                      [probe :8666] ← host network, privileged
```

**Probe** (`probe/`) is the only container with raw network access. It:
- Runs ARP sweeps and passive packet sniffing to discover devices
- Writes device records and `device_events` directly to Postgres
- Exposes a small FastAPI on port 8666 for the backend to call (ping, traceroute, vuln scan, config reload, block/unblock)
- Reads config from Postgres `settings` table at the start of each scan cycle (no restart needed for most settings)

**Backend** (`backend/main.py`) is the API gateway. It:
- Serves all frontend API requests (`/api/…` via nginx proxy)
- Never does network scanning itself — proxies scan/diagnostic requests to the probe via `httpx`
- Owns all DB writes that originate from user actions (rename, tag, metadata, identity overrides, fingerprint upserts)
- Runs two background asyncio loops on startup: scheduled vuln scans and the alert dispatch loop

**Frontend** (`frontend/src/`) is a single React page (`App.jsx`). State lives in hooks:
- `useDevices` — polls `/api/devices` every 10 s, detects new/offline devices, fires `onAlert` callback
- `useSmartFilters` — contextual quick-filter logic
- `useTheme` — dark/light toggle persisted to localStorage

### Data flow for new device discovery

1. Probe ARP-sweeps the network and upserts a row into `devices` via SQLAlchemy
2. Probe inserts a `device_events` row (type `joined`)
3. Backend's alert dispatch loop (`_alert_dispatch_loop`) polls `device_events` every 30 s and fires webhook/ntfy/Gotify/Pushbullet if configured
4. Frontend's `useDevices` poll detects the new MAC and fires the `onAlert` callback → browser toast + OS notification + Pushbullet (frontend path)

### Settings flow

Settings live in the `settings` Postgres table. The frontend calls `PUT /api/settings/{key}` to save individual values. Scan-related settings (interval, IP range, nmap args, etc.) only take effect on the next probe scan cycle — the probe reads them from the DB each cycle. To push changes to the running probe immediately, call `POST /api/settings/apply` (backend forwards a subset to `POST /probe/config/reload`).

### Fingerprint database

`FingerprintEntry` rows are matched against devices to auto-classify device type. When a user manually sets `vendor_override` or `device_type_override` on a device, `_upsert_manual_fingerprint` saves the OUI prefix + ports as a `source='manual'` fingerprint. The `_match_fingerprints` helper scores candidates by OUI match (3 pts) + open port overlap (1 pt each).

### Alert dispatch (backend background loop)

`_alert_dispatch_loop` runs every 30 s. It queries `device_events` for rows newer than `_last_alert_event_id` and dispatches to all configured channels (webhook, ntfy, Gotify, Pushbullet) based on the `alert_on_*` settings. Pushbullet is also callable directly via the frontend through `POST /api/notify/pushbullet`.

---

## Key files

| File | Purpose |
|---|---|
| `backend/main.py` | Thin FastAPI orchestrator: app setup, middleware, router includes, startup event |
| `backend/config.py` | Environment variables and constants (DATABASE_URL, PROBE_URL, SECRET_KEY, etc.) |
| `backend/database.py` | SQLAlchemy engine, SessionLocal, get_db, all `_migrate()` SQL migrations, DEFAULT_SETTINGS, legacy migrations |
| `backend/models.py` | SQLAlchemy ORM models (`Device`, `DeviceEvent`, `VulnReport`, `Alert`, `Setting`, `FingerprintEntry`, `TrafficStat`) |
| `backend/auth_utils.py` | JWT helpers, bcrypt password hashing, `get_current_user` dependency |
| `backend/state.py` | Shared mutable singletons: `_ha_mqtt`, plugin registry/runner/bus/scheduler, SSE client set, notification state |
| `backend/schemas.py` | All Pydantic request/response models |
| `backend/probe_client.py` | `_probe_client()` httpx wrapper with shared secret, `_execute_block_bg()` |
| `backend/sse.py` | `_sse_publish()` fan-out, `_sse_event_watcher()` background loop |
| `backend/ha_mqtt.py` | `HAMQTTManager` class and `_ha_startup_connect()` |
| `backend/notifications_core.py` | Apprise notification dispatch, channel/profile logic, `_notification_loop()` background loop |
| `backend/device_utils.py` | `_to_dict()`, `_identity_score()`, `_infer_device_type()`, `_build_name_candidates()`, `_add_event()` |
| `backend/fingerprint_utils.py` | `_match_fingerprints()`, `_upsert_manual_fingerprint()`, `_fingerbank_loop()` |
| `backend/vuln_utils.py` | `_run_single_vuln_scan()`, `_save_vuln_result()`, `_scheduled_vuln_scan_loop()` |
| `backend/background_loops.py` | Traffic flush, speedtest schedule, block schedule loop, Trivy DB update, Docker event watcher, auto-update |
| `backend/routes/` | One file per feature area (see below) |
| `probe/main.py` | Thin orchestrator: startup, scan loop, group backfill, graceful shutdown |
| `probe/probe_config.py` | All config globals, `_load_settings_from_db()`, `apply_runtime_config()`, utility fns |
| `probe/probe_models.py` | ORM models (`Device`, `IPHistory`), engine/Session, all shared in-memory state and locks |
| `probe/probe_db.py` | `wait_for_db()`, `init_db()` with all ALTER TABLE migrations |
| `probe/probe_ip.py` | `record_ip()`, `_primary_ip_is_stale()`, `_write_event()` |
| `probe/probe_hostname.py` | DNS resolver, mDNS hostname strip, MAC vendor DB lookup |
| `probe/probe_grouping.py` | `retroactive_auto_group()`, `_try_auto_group_by_hostname()`, `_choose_group_primary()` |
| `probe/probe_scanner.py` | `arp_scan()`, SYN/TCP port scan, `trigger_deep_scan()` |
| `probe/probe_device.py` | `upsert_seen_device()`, `update_presence_from_sweep()`, DHCP info upsert |
| `probe/probe_sniffer.py` | Passive ARP+DHCP sniffer, worker threads, `start_arp_sniffer()` |
| `probe/probe_mdns.py` | mDNS browse + passive listener, `_apply_mdns_enrichment()` |
| `probe/probe_ssdp.py` | SSDP browse + passive listener, `_apply_ssdp_enrichment()` |
| `probe/probe_blocking.py` | ARP-spoof block/unblock, iptables FORWARD DROP, `_arp_spoof_loop()` |
| `probe/probe_fingerprint.py` | Nerva service fingerprinting, Nuclei template management |
| `probe/probe_routes.py` | FastAPI app (`probe_api`), all probe API routes, `start_probe_api()` |
| `probe/vuln_scanner.py` | NSE-based vuln scan logic called by the probe |
| `frontend/src/App.jsx` | Root component: layout, toasts, notification dispatch |
| `frontend/src/api.js` | All `fetch` calls to the backend — single source of truth for API shape |
| `frontend/src/hooks/useDevices.js` | Device polling, new-device / offline detection, `onAlert` callback |
| `frontend/src/components/DeviceDrawer.jsx` | Per-device detail panel (actions, scan results, timeline, notes) |
| `frontend/src/components/SettingsPanel.jsx` | Tabbed settings UI (Scanner / Notifications / Data) |
| `docker-compose.yml` | Service definitions, env vars, port mappings |

### Backend route modules (`backend/routes/`)

| File | Routes |
|---|---|
| `auth.py` | `GET /`, `GET /health`, `POST /auth/login`, `GET /auth/me`, `POST /auth/change-password` |
| `setup.py` | `GET|POST /setup/*` — setup wizard |
| `system.py` | `GET /system/info`, `POST /system/auto-update*` |
| `devices.py` | `GET|PATCH|POST|DELETE /devices/*`, device groups, ping, block, traceroute |
| `vuln.py` | `GET /devices/{mac}/vuln-scan` (SSE), vuln reports, `/vulns/*` |
| `services.py` | `/devices/{mac}/services`, mDNS/SSDP refresh |
| `zones.py` | `/zones` CRUD |
| `saved_views.py` | `/saved-views` CRUD |
| `suppressions.py` | `/suppressions` CRUD |
| `events.py` | `/events/stream` (SSE), `/events`, `/changes`, `/dashboard/summary`, `/vendors`, `/stats` |
| `settings.py` | `/settings` CRUD, apply, restart |
| `notifications.py` | `/notifications/channels|profiles`, `/ha-mqtt/*` |
| `plugins.py` | `/plugins/*` — upload, config, webhooks |
| `fingerprints.py` | `/fingerprints` CRUD |
| `export.py` | `/export/*`, `/import/*`, `/reports/*` |
| `tools.py` | `/tools/*` network diagnostics, `/speedtest/*` |
| `schedules.py` | `/block-schedules` CRUD |
| `persons.py` | `/persons/*` — presence tracking, block |
| `network.py` | `/network/status|pause|resume` |
| `timeline.py` | `GET /timeline`, `GET /devices/{mac}/timeline` |
| `traffic.py` | `/traffic/*` — start/stop/history/stream |
| `docker.py` | `/docker/*`, `/container-hosts/*`, `/trivy/*`, `/nuclei/*` |

---

## Database schema (key tables)

- **`devices`** — one row per MAC; holds current state + user metadata (custom_name, tags, location, is_important, notes, vendor_override, device_type_override, vuln_severity)
- **`device_events`** — append-only timeline; types: `joined`, `online`, `offline`, `ip_change`, `scan_complete`, `renamed`, `tagged`, `marked_important`, `port_change`, `vuln_scan_complete`
- **`ip_history`** — every IP a device has ever held
- **`vuln_reports`** — NSE scan results per device (severity, findings JSON, raw output)
- **`fingerprints`** — OUI/port pattern → device_type classifier; sources: `manual`, `community`, `auto`
- **`settings`** — key/value store; seeded with defaults on startup, writable via API
- **`alerts`** — model exists in `models.py` but is not yet actively written; `device_events` is used instead

Schema migrations run automatically on startup via `_migrate()` in `backend/database.py` using raw `ALTER TABLE … ADD COLUMN IF NOT EXISTS` statements. **Add new columns there, not via Alembic.**

---

## Adding a new backend setting

1. Add to `DEFAULT_SETTINGS` dict in `backend/database.py`
2. Add to `SETTING_META` in `frontend/src/components/SettingsPanel.jsx` with the correct `tab` and `type`
3. If it affects probe behaviour, handle it in `apply_runtime_config()` in `probe/probe_config.py`

## Adding a new API endpoint

Follow the existing pattern: route decorator → Pydantic model for request body (add to `schemas.py`) → `db: Session = Depends(get_db)` → SQLAlchemy query → return dict. Add to the relevant `routes/` module or create a new one and include it in `main.py`.

## Schema migrations

Run automatically on startup via `_migrate()` in `backend/database.py` using raw `ALTER TABLE … ADD COLUMN IF NOT EXISTS` statements. **Add new columns there, not via Alembic.**

> `backend/main_original.py` is the original 10k-line backend monolith kept for reference during the refactor. It is not used at runtime.

> `probe/main_original.py` is the original 4,447-line probe monolith kept for reference during the refactor. It is not used at runtime.

## Frontend conventions

- No state management library — all state is `useState` + custom hooks
- CSS uses Tailwind utility classes plus CSS custom properties (`--color-brand`, `--color-surface`, etc.) defined in `index.css` for theming
- Icons from `lucide-react` — check v0.378.0 availability before using new icon names
- All API calls go through the `api` object exported from `src/api.js` — add new calls there
- The `onSettingChange(key, value)` prop on `SettingsPanel` propagates live setting changes back to `App.jsx` state (used for toast/browser/Pushbullet enable flags)

---

## Dev branch policy

**All code changes go to `InSpectre-test/` only.** `InSpectre-main/` is the stable branch and must not be modified unless explicitly asked to promote/merge changes.
