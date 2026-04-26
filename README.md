# InSpectre

**Know every device on your network.**

InSpectre is a self-hosted network monitoring and vulnerability assessment suite that automatically discovers, tracks, fingerprints, and scans every device connected to your LAN. It runs entirely on your own hardware — no cloud, no subscriptions, no data leaving your network.

---

## Features

- **Automatic device discovery** — finds devices within seconds of them joining the network using active ARP sweeps and a passive ARP sniffer running in parallel
- **History & timeline** — records first seen, every IP address a device has ever held, and a full chronological event log (joined, online, offline, IP changes, port changes, scans)
- **Device identification** — resolves hostnames via DNS/mDNS/NetBIOS, looks up vendor from MAC OUI, detects OS and open ports via Nmap, and fingerprints services with Nerva
- **Vulnerability scanning** — targeted Nuclei-based scanning with per-service template routing; HTTP endpoints get web templates, SSH/RDP/Redis/etc. get relevant network templates, and identified products get matched CVE templates
- **Network diagnostics** — ping and traceroute streamed live to the dashboard; on-demand port re-scans
- **Device blocking** — cut a device off from the internet with one click using ARP spoofing; unblock just as easily
- **Alerts** — toast and browser notifications when new devices appear or watched devices go offline; optional Pushbullet integration
- **Smart filtering** — filter the device list by vuln status, scan state, open ports, tags, watched status, and more; save filter combinations as named views

---

## Dashboard

### Layout Views

| View | Description |
|---|---|
| Grid | Device cards with status, vendor, hostname, ports, and vuln severity at a glance |
| List | Compact table for dense networks |
| Category | Devices grouped automatically by device type (router, phone, TV, NAS, IoT, etc.) |

### Search & Filtering

- Full-text search across IP, MAC, hostname, vendor, custom name, tags, location, and zone
- Stat cards (Total / Online / Offline / Watched) act as instant one-click filters
- **Smart filter bar** — combinable quick-filters with AND logic:
  - Watched, Unknown type, Open ports, Not scanned, Vulnerable
  - **Vuln scanned** / **Not vuln scanned** — filter by whether a vulnerability scan has ever completed
  - Blocked, Has notes, Tagged, Ignored
  - Save any active combination as a named view for quick recall

### Device Drawer

Click any device to open a full detail panel:

- **Overview** — live status, scan state, vuln severity badge, block status, vendor, hostname, OS, open ports with service names
- **Actions** — Ping, Traceroute, Re-scan ports, Run vulnerability scan, Block / Unblock internet
- **Vulnerability scan** — live streaming output showing each scan phase; findings listed by severity (critical → low); results persisted and shown on next open
- **IP History** — every IP address the device has held with first/last seen timestamps
- **Timeline** — full event log (online/offline events, port changes, scans, blocks)
- **Identity editor** — set custom name, vendor, and device type; corrections feed the local fingerprint database
- **Notes & Tags** — free-text notes, location/room field, tag chips, zone assignment

### Watched Devices

Star any device to mark it as watched. Watched devices get a dedicated stat card, a sort option (Watched first), and elevated offline alert styling.

---

## Security Dashboard

A separate Security Dashboard panel gives a network-wide vulnerability overview — findings grouped by severity, devices sorted by risk, and quick-jump links into individual device drawers.

---

## Vulnerability Scanning

Scans are powered by [Nuclei](https://github.com/projectdiscovery/nuclei) with a targeted routing strategy:

1. **Open ports** — taken from the prior deep scan (no blind TCP sweep needed when port data exists)
2. **Service fingerprinting** — nmap `-sV` runs only on ports without existing service data
3. **Scan plan** — each port is routed to the minimal relevant template set:
   - HTTP/HTTPS ports → `http/misconfiguration`, `http/default-logins`, `http/exposed-panels`, `http/exposures`, `http/vulnerabilities`, `ssl/`
   - Identified products (nginx, Apache, Grafana, etc.) → matched `http/cves` templates filtered by product tag
   - Network services (SSH, FTP, Redis, RDP, MQTT, SMB, etc.) → `network/cves`, `network/default-logins`, `network/exposed-service` filtered by service tag
4. **Results** — findings stored in `vuln_reports` table; device row updated with `vuln_severity` and `vuln_last_scanned`

Nuclei templates are auto-updated on a configurable interval (default: 24h).

---

## Quick Start

Requires Docker and Docker Compose.

```bash
git clone https://github.com/thefunkygibbon/InSpectre.git
cd InSpectre

# Edit docker-compose.yml — set IP_RANGE, INTERFACE, and LAN_DNS_SERVER for your network

docker compose up -d
