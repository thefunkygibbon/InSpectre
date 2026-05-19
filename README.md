# InSpectre

**Know every device on your network.**

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Docker](https://img.shields.io/badge/Docker-required-2496ED?logo=docker&logoColor=white)
![Platform](https://img.shields.io/badge/platform-linux%2Famd64-lightgrey)

InSpectre is a self-hosted home network monitor and security scanner that automatically discovers, tracks, fingerprints, and scans every device on your LAN. It runs entirely on your own hardware — no cloud, no subscriptions, no data leaving your network.

Check the [Wiki](https://github.com/thefunkygibbon/InSpectre/wiki) for full admin guide. 
---

> **Screenshot placeholder** — _add a screenshot of the main dashboard here_

---

## Features

### Discovery & Monitoring
- **Automatic device discovery** — active ARP sweeps + passive packet sniffer detect devices within seconds of them joining the network
- **Network timeline** — visual online/offline history bar for all devices (7-day, 1-month, 1-year views)
- **Per-device uptime bar** — 7-day presence history visible at a glance in every device drawer
- **IP history** — every IP address a device has ever held, with timestamps

### Device Management
- **Custom metadata** — set a friendly name, device type, vendor override, location/room, tags, and zone per device
- **Watched flag** — star important devices for elevated offline alerts and priority sorting
- **Ignore flag** — hide known-benign devices from the main view
- **Notes** — free-text notes attached to any device
- **Device grouping** — devices sharing the same hostname (e.g. `laptop` and `laptop.lan`) are automatically grouped as a single physical device with multiple interfaces. Grouped devices share a unified event timeline and appear as one card on the dashboard. Manual grouping and ungrouping is available from the device drawer.

### Scanning & Security
- **Port scanning** — nmap-based TCP port sweep with OS detection and service fingerprinting
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

### Traffic Monitoring
- **Per-device traffic analysis** — bytes, packets, domains contacted, countries, and unusual port activity
- **Live speed test** — run an Ookla-powered speed test from the probe container and report download/upload speeds and ping. Optional server selector and scheduled auto-runs (every 30m / 1h / 6h / daily). Results are stored and shown in the history list.

### Network Tools
- **IP Tools** — Ping, Traceroute, Port Scan, Reverse DNS, ARP Lookup, Wake-on-LAN
- **DNS Tools** — Record Lookup, DNS Propagation, DoH Tester, DNSSEC Validator, Reverse DNS Bulk
- **Web Tools** — HTTP Headers, SSL/TLS Certificate, Redirect Chain, TLS Version Matrix, HTTP Timing
- **Infrastructure** — IP Geolocation, WHOIS, BGP/ASN Lookup, Subnet Calculator
- **Email Tools** — MX/SPF/DMARC/DKIM Checker, SMTP Banner Grab, BIMI Lookup, DNSBL Check

### Alerts & Notifications
- **Toast + browser notifications** — instant in-app and OS-level alerts
- **Pushbullet** — push notifications to your phone
- **ntfy** — self-hosted push notification support
- **Gotify** — self-hosted Gotify server support
- **Webhooks** — generic outbound webhook for any alerting system
- **Channels & Profiles system** — reusable Notification Channels (each with a service type and credentials) are grouped into Profiles that map specific event types to one or more channels; multiple channels can fire for the same event and one channel can serve multiple profiles
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
- **New device acknowledgement** — newly discovered devices float to the top of the device list and are marked as new until acknowledged; clicking Acknowledge on the device card or in the drawer marks the device as known, removing the badge and the float; the acknowledged state is stored server-side and also drives the MQTT `new` binary sensor

### Authentication & Setup
- **Built-in authentication** — username and password login with JWT session tokens
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

- **Frontend** — React 18 + Vite + Tailwind CSS single-page app, served by nginx. Polls `/api/devices` every 10 seconds.
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

---

## Licence

InSpectre is dual-licensed:

- **Open Source (AGPL-3.0)** — Free for personal use, home labs, and open-source projects. See [LICENSE](LICENSE).
- **Commercial** — Required for embedding in proprietary products or offering as a hosted service. See [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) or contact [your-email].
