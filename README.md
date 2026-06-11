# InSpectre

**Know every device on your network.**

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Docker](https://img.shields.io/badge/Docker-required-2496ED?logo=docker&logoColor=white)
![Platform](https://img.shields.io/badge/platform-linux%2Famd64-lightgrey)

InSpectre is a self-hosted home network monitor and security scanner that automatically discovers, tracks, fingerprints, and scans every device on your LAN. It runs entirely on your own hardware — no cloud, no subscriptions, no data leaving your network.

Check the [Wiki](https://github.com/thefunkygibbon/InSpectre/wiki) for full admin guide. 
---

<img width="1891" height="832" alt="image" src="https://github.com/user-attachments/assets/1e751db9-1639-4e3f-a912-00999b8d056b" />


---

## Features

### Discovery & Monitoring
- **Automatic device discovery** — active ARP sweeps + passive packet sniffer detect devices within seconds of them joining the network
- **Live updates (SSE)** — the UI subscribes to a Server-Sent Events stream and refreshes affected pages the moment something changes (device online/offline, blocks, schedules, presence) instead of waiting for a fixed poll interval; a slow background poll remains as a fallback
- **Device Presence** — visual online/offline history bars for all devices showing uptime patterns over 7-day, 1-month, or 1-year periods
- **Network Events** — global online/offline event log across all devices with source attribution (ARP sweep, passive sniffer, or plugin)
- **Per-device uptime bar** — 7-day presence history visible at a glance in every device drawer
- **IP history** — every IP address a device has ever held, with timestamps

### Device Management
- **Custom metadata** — set a friendly name, device type, vendor override, location/room, tags, and zone per device
- **Watched flag** — star important devices for elevated offline alerts and priority sorting
- **Ignore flag** — hide known-benign devices from the main view
- **Notes** — free-text notes attached to any device
- **Device grouping** — devices sharing the same hostname (e.g. `laptop` and `laptop.lan`, or a server's real NIC plus a Docker macvlan shim) are automatically grouped as a single physical device with multiple interfaces. Grouping is **self-healing**: a periodic pass merges matching devices discovered at any time, not just at first sight, and picks the most "real" interface (hardware NIC over a virtual/macvlan MAC, online over offline, lowest IP) as the primary. Grouped devices share a unified event timeline and appear as one card on the dashboard. You can override the primary at any time, and by default only the primary interface is port/vuln-scanned (toggle with **Scan grouped members**). Manual grouping and ungrouping is available from the device drawer; **groups you create manually are protected**, and a device you deliberately ungroup is never silently re-merged by the automatic passes.
- **Primary IP & multi-homed hosts** — a device with more than one IP on a single MAC (multi-homed NIC, bridge) no longer flaps between addresses: the probe pins a stable primary IP and tracks the rest as **secondary IPs**. You can pin a specific address as primary from the device drawer's IP History panel, and the probe will keep it permanently.
- **Host-aware presence** — the probe runs in the host's network namespace, so the Docker host's own IPs (its NIC, macvlan shims, bridges) are always treated as present — they can't be marked falsely offline just because a host doesn't ARP for its own addresses.
- **Persistent filters & views** — your active filter, smart filter, sort order, and grid/list view choice are saved and restored automatically the next time you open the dashboard.

### Person Presence
- **People, not just MACs** — group a household member's devices (phone, laptop, watch, etc.) under a named person with an optional photo
- **Home / Away at a glance** — each person card shows a clear **At Home** / **Away** state with colour-coded accent bars and Home/Away icons, derived from whether any of their devices are currently online
- **Primary presence device** — nominate one device (e.g. a phone) as the authoritative presence indicator for that person
- **Presence timeline** — per-person home/away history bars with an at-home percentage over the selected period
- **Per-person blocking** — block or unblock every device belonging to a person in one action
- **Per-person block schedules** — recurring time-based block rules attached to a person (e.g. block a child's devices every school night)
- **Presence notifications** — person arrived home, left home, blocked, and unblocked events feed into the notification profile system (see below)

### Scanning & Security
- **Port scanning** — nmap-based TCP port sweep with OS detection and service fingerprinting. Scans always target a device's pinned **primary IP** — whether triggered on first discovery, on reconnect after a long offline period, or manually from the drawer — so multi-homed and grouped hosts are scanned consistently on the same address.
- **Baseline tracking** — detects port drift and raises alerts when a device's open ports change
- **Vulnerability scanning** — Nuclei-based CVE scanning with per-service template routing; findings shown by severity (critical, high, medium, low)
- **Scheduled scans** — configurable nightly scan window with per-device auto-scan triggers
- **Security dashboard** — network-wide vulnerability overview grouped by severity; includes container image vulnerabilities alongside device findings; scan settings accessible inline via the settings cog

### Container Monitoring
- **Multi-host support** — connect to multiple Docker hosts (local socket or remote TCP) and Proxmox VE nodes simultaneously
- **Container management** — view all running and stopped containers, start/stop/restart with one click
- **Log streaming** — live container log tailing directly from the UI
- **Image vulnerability scanning** — Trivy-based CVE scanner checks container images for known vulnerabilities; findings grouped by severity with expandable CVE cards showing CVSS scores, affected packages, and NVD links
- **Proxmox VE integration** — monitor LXC containers from Proxmox VE nodes via REST API (API token auth)
- **Host filter** — filter the container list by configured host; each container card shows which host it came from
- **Auto-scan results** — last Trivy scan result for each image is stored and shown immediately when you open the drawer

### Device Blocking
- **Per-device blocking** — cut any device off from the internet with one click using ARP MITM
- **Network pause** — block all devices simultaneously
- **Block schedules** — time-based rules to automatically block devices on a recurring schedule
- **Per-person blocking & schedules** — block all of a person's devices at once, or attach a recurring block schedule to a person from the Person Presence page

### Traffic Monitoring
- **Per-device traffic analysis** — bytes, packets, domains contacted, countries, and unusual port activity
- **Live speed test** — run an Ookla-powered speed test from the probe container and report download/upload speeds and ping. Optional server selector and scheduled auto-runs (every 30m / 1h / 6h / daily). Results are stored and shown in the history list.

### Network Tools
- **IP Tools** — Ping, Traceroute, Port Scan, Reverse DNS, ARP Lookup, Wake-on-LAN
- **DNS Tools** — Record Lookup, DNS Propagation, DoH Tester, DNSSEC Validator, Reverse DNS Bulk
- **Web Tools** — HTTP Headers, SSL/TLS Certificate, Redirect Chain, TLS Version Matrix, HTTP Timing
- **Infrastructure** — IP Geolocation, WHOIS, BGP/ASN Lookup, Subnet Calculator
- **Email Tools** — MX/SPF/DMARC/DKIM Checker, SMTP Banner Grab, BIMI Lookup, DNSBL Check

### Extensibility
- **Plugin system** — extend InSpectre with community plugins; built-in plugins ship with the application, community plugins can be uploaded manually via Settings → Plugins

### Alerts & Notifications
- **Toast + browser notifications** — instant in-app and OS-level alerts
- **Pushbullet** — push notifications to your phone
- **ntfy** — self-hosted push notification support
- **Gotify** — self-hosted Gotify server support
- **Webhooks** — generic outbound webhook for any alerting system
- **Channels & Profiles system** — reusable Notification Channels (each with a service type and credentials) are grouped into Profiles that map specific event types to one or more channels; multiple channels can fire for the same event and one channel can serve multiple profiles
- **Event coverage** — device new/online/offline, port drift, vulnerability findings, and **Person Presence events** (person arrived home, left home, blocked, unblocked) are all routable through Profiles
- **Supported channel services** — ntfy, Gotify, Pushbullet, Webhook, Home Assistant (direct REST), Matrix, SMTP (email), Slack, Telegram, Discord, and Apprise generic URL
- **Per-channel testing** — each channel can be tested individually from the Settings panel
- **Home Assistant direct notifications** — a `home_assistant` channel type POSTs alerts directly to the HA REST API (`persistent_notification/create` or any custom `domain/service`); configure host, port, long-lived access token, optional notifier path, and TLS toggle
- **Home Assistant MQTT Auto-Discovery** — dedicated Settings tab publishes InSpectre entities to Home Assistant via MQTT using the standard Auto-Discovery protocol; creates a system device (total devices online, total vulnerabilities, scan state, last scan time) and per-client sensors: presence, new device binary sensor, IP address, open port count, and vulnerability level

### Fingerprinting & Identity
- **OUI lookup** — MAC vendor resolution from the IEEE OUI database
- **DHCP passive capture** — the probe passively captures DHCP packets to collect hostname (Option 12), vendor class ID (Option 60), and parameter request list (Option 55) from every device that broadcasts a lease request
- **Local DHCP classification** — collected DHCP data is matched against known vendor class patterns to infer device type and OS without sending data anywhere
- **Fingerbank cloud lookup** — optionally send DHCP fingerprint data to [Fingerbank](https://fingerbank.org/) (free tier, 600 lookups/hour) for deeper device identification; results include device name, hierarchy, and a confidence score
- **Port pattern matching** — classify device type from open port signature
- **Manual + community + auto fingerprints** — all stored locally, importable/exportable
- **New device acknowledgement** — newly discovered devices float to the top of the device list and are marked as new until acknowledged; clicking the **NEW** badge on the device card or **Acknowledge** in the drawer marks the device as known, removing the badge and the float; the acknowledged state is stored server-side and also drives the MQTT `new` binary sensor

### Authentication & Setup
- **Built-in authentication** — username and password login with JWT session tokens
- **Remember me** — optional extended session duration (30 days) from the login screen
- **First-run setup wizard** — guided 7-step configuration of network settings, vulnerability scanning, notifications, container hosts, and Fingerbank device identification on first launch
- **Backup/restore** — full JSON backup covering all devices, events, vuln reports, speed test history, settings, users, fingerprints, block schedules, and saved views. Optional AES-256-GCM encryption with a user-supplied password. Restorable from the setup wizard or settings panel; encrypted backups are supported in both locations.

---

## Quick Start

### Requirements

- Docker 24+
- Docker Compose v2

### Using `inspectre.sh` (recommended)

```bash
git clone https://github.com/thefunkygibbon/InSpectre.git
cd InSpectre
./inspectre.sh up
```

Open **http://localhost:3000** in your browser and complete the first-run setup wizard. The wizard configures your network settings, scan range, and notifications — no file editing required.

### Available helper commands

```bash
./inspectre.sh up               # start all containers
./inspectre.sh down             # stop all containers
./inspectre.sh rebuild          # full wipe and rebuild (deletes postgres_data/)
./inspectre.sh rebuild keep-data  # rebuild but preserve the database
./inspectre.sh logs             # tail logs from all containers
```

### Using pre-built Docker images (Docker Hub)

If you want to run InSpectre without cloning the repository:

```bash
curl -O https://raw.githubusercontent.com/thefunkygibbon/InSpectre/main/docker-compose.deploy.yml
# Edit docker-compose.deploy.yml — change POSTGRES_PASSWORD and SECRET_KEY
docker compose -f docker-compose.deploy.yml up -d
```

Open **http://localhost:3000** and complete the setup wizard.

Or use the interactive installer, which handles configuration automatically:

```bash
curl -fsSL https://raw.githubusercontent.com/thefunkygibbon/InSpectre/main/inspectre-install.sh | bash
```

### Using Docker Compose directly

```bash
docker compose up -d
```

---

## Configuration

All configuration is done through the **Settings** panel in the UI — no file editing needed after `./inspectre.sh up`. The setup wizard on first run covers scan range, DNS, notifications, and container hosts.

The probe auto-detects the correct network interface and IP range from the host's routing table. If auto-detection picks the wrong interface (e.g. on a machine with multiple NICs), you can override it by uncommenting the relevant lines in `docker-compose.yml`:

```yaml
# IP_RANGE: "192.168.1.0/24"
# INTERFACE: "eth0"
# LAN_DNS_SERVER: "192.168.1.1"
```

Everything else — scan interval, nmap arguments, alert channels, nightly scan window, container hosts, etc. — is managed from the Settings panel at runtime with no restart required.

---

## Architecture

InSpectre runs as three Docker containers coordinated by Docker Compose:

```
                        ┌─────────────────────────────────────┐
Browser                 │           Docker Compose             │
   │                    │                                      │
   │  HTTP :3000        │  ┌─────────────┐                    │
   └───────────────────►│  │  frontend   │  nginx static +    │
                        │  │  :3000      │  reverse proxy     │
                        │  └──────┬──────┘                    │
                        │         │ /api/*                    │
                        │  ┌──────▼──────┐                    │
                        │  │  backend    │  FastAPI REST API  │
                        │  │  :8000      │  alert dispatch    │
                        │  └──────┬──────┘  scheduled scans  │
                        │         │ httpx                     │
                        │  ┌──────▼──────┐                    │
                        │  │   probe     │  ARP sweep         │
                        │  │  :8666      │  packet sniffer    │
                        │  │ host network│  nmap / nuclei     │
                        │  │ privileged  │  ARP block/unblock │
                        │  └──────┬──────┘                    │
                        │         │                           │
                        │  ┌──────▼──────┐                    │
                        │  │ PostgreSQL  │                    │
                        │  │    :5432    │                    │
                        │  └─────────────┘                    │
                        └─────────────────────────────────────┘
```

- **Frontend** — React 18 + Vite + Tailwind CSS single-page app, served by nginx. Receives live updates over a Server-Sent Events (SSE) stream from the backend and refreshes affected views instantly, with a slow background poll as a fallback.
- **Backend** — FastAPI on port 8000. Handles all user-initiated API calls, proxies scan/diagnostic requests to the probe, runs the alert dispatch loop and scheduled vulnerability scans. Connects to Docker hosts and Proxmox VE via SDK/REST API for container monitoring.
- **Probe** — FastAPI on port 8666, runs on the host network with elevated privileges. The only container with raw network access. Performs ARP sweeps, passive sniffing, nmap scans, Nuclei vulnerability scans, and ARP-based device blocking. Writes device data directly to PostgreSQL.

---

## Documentation

Full user documentation is available in [wiki.md](wiki.md), covering:

- Getting started and initial setup
- Device discovery and management
- Network scanning and vulnerability assessment
- Container monitoring (Docker + Proxmox)
- Device blocking and block schedules
- Traffic monitoring
- Network tools reference
- Notifications configuration
- Settings reference
- Backup, restore, and data management
- Troubleshooting and FAQ

---

## Contributing

Contributions are welcome. Please open an issue to discuss a change before submitting a pull request. All development work targets the `InSpectre-test` branch — do not submit pull requests against `InSpectre-main`.

### Versioning

The project version lives in a single file — **`VERSION`** at the repo root — and everything else is derived from it. The backend, probe and frontend each read an auto-generated version module that is stamped from `VERSION`; never edit those generated files by hand:

- `backend/_version.py`, `probe/_version.py`, `frontend/src/version.js`, and the `version` field in `frontend/package.json`

Useful commands:

```bash
scripts/sync-version.sh            # re-stamp all components from VERSION
scripts/bump-version.sh patch      # 1.2.0 -> 1.2.1  (default)
scripts/bump-version.sh minor      # 1.2.0 -> 1.3.0
scripts/bump-version.sh major      # 1.2.0 -> 2.0.0
scripts/bump-version.sh set 2.1.0  # set an explicit version
```

**Automatic bumping:** a git pre-commit hook keeps the version moving forward so it never goes stale again. Enable it once per clone:

```bash
git config core.hooksPath .githooks
```

With the hook active, every commit auto-increments the **patch** number and re-stamps the derived files. To cut a `minor`/`major` release instead, run `scripts/bump-version.sh minor` (or `major`) and stage `VERSION` before committing — the hook detects the manual bump and only syncs. Set `INSPECTRE_NO_VERSION_BUMP=1` to skip bumping for a single commit. `./inspectre.sh rebuild` also re-stamps from `VERSION` before building, so deployed images always carry the correct version.

---

## Licence

InSpectre is dual-licensed:

- **Open Source (AGPL-3.0)** — Free for personal use, home labs, and open-source projects. See [LICENSE](LICENSE).
- **Commercial** — Required for embedding in proprietary products or offering as a hosted service. See [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) or contact [inspectre@thefunkygibbon.net](mailto:inspectre@thefunkygibbon.net).
