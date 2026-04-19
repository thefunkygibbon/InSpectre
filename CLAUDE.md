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

**Probe** (`probe/main.py`) is the only container with raw network access. It:
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
| `backend/main.py` | Entire backend: routes, migrations, background loops, helper functions |
| `backend/models.py` | SQLAlchemy ORM models shared by backend (`Device`, `DeviceEvent`, `VulnReport`, `Alert`, `Setting`, `FingerprintEntry`) |
| `probe/main.py` | Probe: ARP scanner, sniffer, nmap wrapper, ARP-block, probe API |
| `probe/vuln_scanner.py` | NSE-based vuln scan logic called by the probe |
| `frontend/src/App.jsx` | Root component: layout, toasts, notification dispatch |
| `frontend/src/api.js` | All `fetch` calls to the backend — single source of truth for API shape |
| `frontend/src/hooks/useDevices.js` | Device polling, new-device / offline detection, `onAlert` callback |
| `frontend/src/components/DeviceDrawer.jsx` | Per-device detail panel (actions, scan results, timeline, notes) |
| `frontend/src/components/SettingsPanel.jsx` | Tabbed settings UI (Scanner / Notifications / Data) |
| `docker-compose.yml` | Service definitions, env vars, port mappings |

---

## Database schema (key tables)

- **`devices`** — one row per MAC; holds current state + user metadata (custom_name, tags, location, is_important, notes, vendor_override, device_type_override, vuln_severity)
- **`device_events`** — append-only timeline; types: `joined`, `online`, `offline`, `ip_change`, `scan_complete`, `renamed`, `tagged`, `marked_important`, `port_change`, `vuln_scan_complete`
- **`ip_history`** — every IP a device has ever held
- **`vuln_reports`** — NSE scan results per device (severity, findings JSON, raw output)
- **`fingerprints`** — OUI/port pattern → device_type classifier; sources: `manual`, `community`, `auto`
- **`settings`** — key/value store; seeded with defaults on startup, writable via API
- **`alerts`** — model exists in `models.py` but is not yet actively written; `device_events` is used instead

Schema migrations run automatically on startup via `_migrate()` in `backend/main.py` using raw `ALTER TABLE … ADD COLUMN IF NOT EXISTS` statements. **Add new columns there, not via Alembic.**

---

## Adding a new backend setting

1. Add to `DEFAULT_SETTINGS` dict in `backend/main.py`
2. Add to `SETTING_META` in `frontend/src/components/SettingsPanel.jsx` with the correct `tab` and `type`
3. If it affects probe behaviour, handle it in `apply_runtime_config()` in `probe/main.py`

## Adding a new API endpoint

Follow the existing pattern: route decorator → Pydantic model for request body → `db: Session = Depends(get_db)` → SQLAlchemy query → return dict. The backend has no separate router modules — everything is in `main.py`.

## Frontend conventions

- No state management library — all state is `useState` + custom hooks
- CSS uses Tailwind utility classes plus CSS custom properties (`--color-brand`, `--color-surface`, etc.) defined in `index.css` for theming
- Icons from `lucide-react` — check v0.378.0 availability before using new icon names
- All API calls go through the `api` object exported from `src/api.js` — add new calls there
- The `onSettingChange(key, value)` prop on `SettingsPanel` propagates live setting changes back to `App.jsx` state (used for toast/browser/Pushbullet enable flags)

---

## Dev branch policy

**All code changes go to `InSpectre-test/` only.** `InSpectre-main/` is the stable branch and must not be modified unless explicitly asked to promote/merge changes.
