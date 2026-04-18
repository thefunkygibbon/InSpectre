# InSpectre

**Know every device on your network.**

InSpectre is a self-hosted network monitoring dashboard that automatically discovers, tracks, and analyses every device connected to your LAN. It runs entirely on your own hardware — no cloud, no subscriptions, no data leaving your network.

---

## What it does

- **Discovers devices automatically** — finds devices within seconds of them joining the network using a combination of active ARP scanning and passive packet sniffing
- **Tracks history** — records when each device first appeared, every IP address it has ever held, and a full timeline of events (joined, online, offline, IP changes, scans)
- **Identifies devices** — resolves hostnames, looks up manufacturer (vendor) from MAC address, detects OS and open ports via Nmap, and builds a local fingerprint database to automatically classify device types
- **Runs diagnostics** — ping and traceroute streamed live to the dashboard; deep port and vulnerability scans on demand
- **Blocks devices** — cut a device off from the internet with one click using ARP spoofing; unblock it just as easily
- **Alerts you** — toast notifications when new devices appear or known devices go offline, with a notification bell in the header

---

## Dashboard

The dashboard gives you a full picture of your network at a glance.

**Three layout views**
- Grid — device cards with status, vendor, hostname, and open ports at a glance
- List — compact table for dense networks
- Category — devices grouped by type (router, phone, smart TV, NAS, IoT, etc.)

**Filter and search**
- Full-text search across IP, hostname, vendor, name, tags, and location
- Clickable stat cards (Total / Online / Offline / Watched) act as instant filters
- Smart filter bar for contextual quick-filters ("has open ports", "not yet scanned", "has notes", etc.)

**Device drawer**
Click any device to open a detail panel with:
- Live status, scan status, and any active block or vulnerability flags
- Actions: Ping, Traceroute, Re-scan ports, Vulnerability scan, Block / Unblock internet access
- Full network details: IP, MAC, vendor, hostname, open ports, OS detection
- IP address history
- Device identity editor — set a custom vendor name and device type; corrections are saved to the local fingerprint database
- Timeline tab — full chronological event log
- Notes & Tags tab — free-text notes, location/room field, tag chips

**Watched devices**
Star any device to mark it as watched. Watched devices get a dedicated stat card, a sort option, and highlighted offline alerts.

---

## Quick Start

InSpectre runs via Docker Compose. You need Docker and Docker Compose installed.

```bash
git clone https://github.com/thefunkygibbon/InSpectre.git
cd InSpectre

# Edit docker-compose.yml and set your network details (see Configuration below)

docker compose up -d
```

Open **http://\<your-server-ip\>:5173** in your browser.

---

## Configuration

Edit the environment variables in `docker-compose.yml` before starting:

| Variable | Default | Description |
|---|---|---|
| `IP_RANGE` | `192.168.0.0/24` | The network range to scan (CIDR notation) |
| `INTERFACE` | `eth0` | Network interface to listen on |
| `LAN_DNS_SERVER` | *(auto-detected)* | Your router's IP — used for hostname resolution. Set this explicitly for best results |
| `SCAN_INTERVAL` | `60` | Seconds between network sweeps |
| `OFFLINE_MISS_THRESHOLD` | `3` | Missed sweeps before a device is marked offline |

All other settings (Nmap arguments, scan workers, OS confidence threshold, notification toggle) can be adjusted live from the **Settings** panel inside the dashboard without restarting.

---

## Requirements

- Docker and Docker Compose
- A Linux host with access to the network interface you want to monitor (the probe container needs `NET_RAW` capability for ARP scanning and device blocking — this is granted automatically by the Compose file)
- The host machine should be on the same LAN segment as the devices you want to monitor

---

## Roadmap

| Feature | Status |
|---|---|
| Device discovery, history & timeline | ✅ |
| Device identity, fingerprinting & classification | ✅ |
| Vulnerability scanning (Nmap NSE) | ✅ |
| Block internet access (ARP spoofing) | ✅ |
| Alerting webhooks (Discord, email, Gotify) | Planned |

---

*InSpectre v1.0.0 — developed by [thefunkygibbon](mailto:inspectre@thefunkygibbon.net)*
