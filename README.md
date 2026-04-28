# InSpectre

**Know every device on your network.**

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Docker](https://img.shields.io/badge/Docker-required-2496ED?logo=docker&logoColor=white)
![Platform](https://img.shields.io/badge/platform-linux%2Famd64-lightgrey)

InSpectre is a self-hosted home network monitor and security scanner that automatically discovers, tracks, fingerprints, and scans every device on your LAN. It runs entirely on your own hardware — no cloud, no subscriptions, no data leaving your network.

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

### Scanning & Security
- **Port scanning** — nmap-based TCP port sweep with OS detection and service fingerprinting via Nerva
- **Baseline tracking** — detects port drift and raises alerts when a device's open ports change
- **Vulnerability scanning** — nuclei-based CVE scanning with per-service template routing; findings shown by severity (critical, high, medium, low)
- **Scheduled scans** — configurable nightly scan window with per-device auto-scan triggers
- **Security dashboard** — network-wide vulnerability overview grouped by severity; scan settings accessible via the settings cog on the page

### Device Blocking
- **Per-device blocking** — cut any device off from the internet with one click using ARP MITM
- **Network pause** — block all devices simultaneously
- **Block schedules** — time-based rules to automatically block devices on a recurring schedule

### Traffic Monitoring
- **Per-device traffic analysis** — bytes, packets, domains contacted, countries, and unusual port activity
- **Live speed test** — run a speedtest-cli speed test directly from the UI with optional scheduled auto-runs (every 30m / 1h / 6h / daily)

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

### Fingerprinting & Identity
- **OUI lookup** — MAC vendor resolution from the IEEE OUI database
- **Port pattern matching** — classify device type from open port signature
- **Manual + community + auto fingerprints** — all stored locally, importable/exportable

---

## Quick Start

### Requirements

- Docker 24+
- Docker Compose v2

### Using `inspectre.sh` (recommended)

```bash
git clone https://github.com/thefunkygibbon/InSpectre.git
cd InSpectre

# Edit docker-compose.yml and set:
#   IP_RANGE       e.g. 192.168.1.0/24
#   INTERFACE      e.g. eth0
#   LAN_DNS_SERVER e.g. 192.168.1.1

./inspectre.sh up
```

Open **http://localhost:3000** in your browser.

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

Key environment variables are set in `docker-compose.yml`:

| Variable | Description | Example |
|---|---|---|
| `IP_RANGE` | CIDR range to scan | `192.168.1.0/24` |
| `INTERFACE` | Network interface for the probe | `eth0` |
| `LAN_DNS_SERVER` | DNS server for hostname resolution | `192.168.1.1` |
| `DATABASE_URL` | PostgreSQL connection string (pre-set) | `postgresql://...` |

All other settings (scan interval, nmap arguments, alert channels, nightly scan window, etc.) are managed from the **Settings** panel inside the UI after first run — no restart required for most of them.

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
- **Backend** — FastAPI on port 8000. Handles all user-initiated API calls, proxies scan/diagnostic requests to the probe, runs the alert dispatch loop and scheduled vulnerability scans.
- **Probe** — FastAPI on port 8666, runs on the host network with elevated privileges. The only container with raw network access. Performs ARP sweeps, passive sniffing, nmap scans, nuclei vulnerability scans, and ARP-based device blocking. Writes device data directly to PostgreSQL.

---

## Contributing

Contributions are welcome. Please open an issue to discuss a change before submitting a pull request. All development work targets the `InSpectre-test` branch — do not submit pull requests against `InSpectre-main`.

---

## License

MIT — see [LICENSE](LICENSE) for details.
