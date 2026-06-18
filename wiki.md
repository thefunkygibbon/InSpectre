# InSpectre — User Documentation

## Table of Contents

1. [Getting Started](#1-getting-started)
   - 1.1 [Requirements](#11-requirements)
   - 1.2 [Installation](#12-installation)
   - 1.3 [First Run & Setup Wizard](#13-first-run--setup-wizard)
   - 1.4 [Accessing the UI](#14-accessing-the-ui)
   - 1.5 [Authentication](#15-authentication)
   - 1.6 [Deploying from Docker Hub](#16-deploying-from-docker-hub)
2. [Device Discovery](#2-device-discovery)
   - 2.1 [How Discovery Works](#21-how-discovery-works)
   - 2.2 [ARP Sweep vs Passive Sniffer](#22-arp-sweep-vs-passive-sniffer)
   - 2.3 [Hostname Resolution](#23-hostname-resolution)
3. [Device Management](#3-device-management)
   - 3.1 [Dashboard Views](#31-dashboard-views)
   - 3.2 [Search and Filtering](#32-search-and-filtering)
   - 3.3 [Device Drawer — Overview Tab](#33-device-drawer--overview-tab)
   - 3.4 [Device Drawer — Actions Tab](#34-device-drawer--actions-tab)
   - 3.5 [Device Drawer — Vulnerabilities Tab](#35-device-drawer--vulnerabilities-tab)
   - 3.6 [Device Drawer — Traffic Tab](#36-device-drawer--traffic-tab)
   - 3.7 [Device Drawer — Timeline Tab](#37-device-drawer--timeline-tab)
   - 3.8 [Device Drawer — Admin Tab](#38-device-drawer--admin-tab)
   - 3.9 [Watched Devices](#39-watched-devices)
   - 3.10 [Ignoring Devices](#310-ignoring-devices)
   - 3.11 [Zones](#311-zones)
   - 3.12 [DHCP Fingerprinting & Fingerbank](#312-dhcp-fingerprinting--fingerbank)
   - 3.13 [Device Grouping](#313-device-grouping)
   - 3.14 [Acknowledging New Devices](#314-acknowledging-new-devices)
   - 3.15 [Device Presence Page](#315-device-presence-page)
   - 3.16 [Network Events Page](#316-network-events-page)
   - 3.17 [Person Presence Page](#317-person-presence-page)
   - 3.18 [Live Updates (SSE)](#318-live-updates-sse)
4. [Network Scanning](#4-network-scanning)
   - 4.1 [Port Scanning](#41-port-scanning)
   - 4.2 [OS Detection](#42-os-detection)
   - 4.3 [Service Fingerprinting](#43-service-fingerprinting)
   - 4.4 [Baseline Tracking and Drift Alerts](#44-baseline-tracking-and-drift-alerts)
5. [Vulnerability Scanning](#5-vulnerability-scanning)
   - 5.1 [How It Works](#51-how-it-works)
   - 5.2 [Running a Scan Manually](#52-running-a-scan-manually)
   - 5.3 [Scheduled Vulnerability Scans](#53-scheduled-vulnerability-scans)
   - 5.4 [Reading Scan Results](#54-reading-scan-results)
   - 5.5 [Vulnerability Settings](#55-vulnerability-settings)
   - 5.6 [Security Dashboard](#56-security-dashboard)
6. [Device Blocking](#6-device-blocking)
   - 6.1 [Blocking a Single Device](#61-blocking-a-single-device)
   - 6.2 [Network Pause (Block All)](#62-network-pause-block-all)
   - 6.3 [Block Schedules](#63-block-schedules)
7. [Traffic Monitor](#7-traffic-monitor)
   - 7.1 [Starting a Traffic Session](#71-starting-a-traffic-session)
   - 7.2 [Understanding the Data](#72-understanding-the-data)
   - 7.3 [Speed Test](#73-speed-test)
8. [Network Tools](#8-network-tools)
   - 8.1 [IP Tools](#81-ip-tools)
   - 8.2 [DNS Tools](#82-dns-tools)
   - 8.3 [Web Tools](#83-web-tools)
   - 8.4 [Infrastructure Tools](#84-infrastructure-tools)
   - 8.5 [Email Tools](#85-email-tools)
9. [Notifications](#9-notifications)
   - 9.1 [Notification Channels](#91-notification-channels)
   - 9.2 [Notification Profiles](#92-notification-profiles)
   - 9.3 [Setting up ntfy](#93-setting-up-ntfy)
   - 9.4 [Setting up Gotify](#94-setting-up-gotify)
   - 9.5 [Setting up Pushbullet](#95-setting-up-pushbullet)
   - 9.6 [Setting up Webhooks](#96-setting-up-webhooks)
   - 9.7 [Setting up Home Assistant (direct notifications)](#97-setting-up-home-assistant-direct-notifications)
   - 9.8 [Home Assistant MQTT Auto-Discovery](#98-home-assistant-mqtt-auto-discovery)
   - 9.9 [MQTT Auto-Discovery (Home Assistant)](#99-mqtt-auto-discovery-home-assistant)
10. [Settings Reference](#10-settings-reference)
    - 10.1 [Scanner Settings](#101-scanner-settings)
    - 10.2 [Notification Settings](#102-notification-settings)
    - 10.3 [Data Settings](#103-data-settings)
    - 10.4 [Home Assistant Settings](#104-home-assistant-settings)
    - 10.5 [Admin Settings](#105-admin-settings)
11. [Data Management](#11-data-management)
    - 11.1 [Backup and Restore](#111-backup-and-restore)
    - 11.2 [CSV Export](#112-csv-export)
    - 11.3 [Fingerprint Database](#113-fingerprint-database)
12. [Container Monitoring](#12-container-monitoring)
    - 12.1 [Overview](#121-overview)
    - 12.2 [Adding Container Hosts](#122-adding-container-hosts)
    - 12.3 [Connecting to Docker (Local)](#123-connecting-to-docker-local)
    - 12.4 [Connecting to Docker (Remote TCP)](#124-connecting-to-docker-remote-tcp)
    - 12.5 [Connecting to Proxmox VE](#125-connecting-to-proxmox-ve)
    - 12.6 [Containers Page](#126-containers-page)
    - 12.7 [Container Drawer](#127-container-drawer)
    - 12.8 [Container Vulnerability Scanning (Trivy)](#128-container-vulnerability-scanning-trivy)
    - 12.9 [Container Vulns in the Security Dashboard](#129-container-vulns-in-the-security-dashboard)
13. [Home Assistant MQTT Integration](#13-home-assistant-mqtt-integration)
    - 13.1 [Overview](#131-overview)
    - 13.2 [Requirements](#132-requirements)
    - 13.3 [Configuration](#133-configuration)
    - 13.4 [Topic Structure](#134-topic-structure)
    - 13.5 [The "New Device" Sensor](#135-the-new-device-sensor)
    - 13.6 [LWT (Last Will and Testament)](#136-lwt-last-will-and-testament)
14. [Troubleshooting](#14-troubleshooting)
15. [FAQ](#15-faq)
16. [Plugins](#16-plugins)

---

## 1. Getting Started

### 1.1 Requirements

- **Docker** 24 or later (with the daemon running)
- **Docker Compose** v2 (included with modern Docker Desktop and Docker Engine installs)
- **curl** and **openssl** (used by the installer to download the compose file and generate secure keys)
- A Linux host — **x86-64** or **ARM64 (Raspberry Pi 3/4/5, 64-bit)** — connected to the LAN you want to monitor (the probe container requires raw network access and runs on the host network stack)

### 1.2 Installation

The recommended way to install InSpectre is the **one-line installer**. It simply downloads and runs `inspectre-install.sh` — **you do not need to clone the repository or build anything**. The installer pulls the pre-built images directly from Docker Hub.

```bash
curl -fsSL https://raw.githubusercontent.com/thefunkygibbon/InSpectre/main/inspectre-install.sh | bash
```

The installer checks all prerequisites, detects your CPU architecture and asks whether to install **x64** or **Raspberry Pi** images, generates secure credentials, and starts the whole stack. See [1.6 Deploying from Docker Hub](#16-deploying-from-docker-hub) for full details and the manual alternative.

**Building from source (developers only):** if you want to modify and rebuild the images yourself, clone the repository and use the helper script:

```bash
git clone https://github.com/thefunkygibbon/InSpectre.git
cd InSpectre
./inspectre.sh up
```

The probe automatically detects the correct network interface and IP range from the host's routing table. All other configuration (scan range, DNS server, notifications, container hosts) is done through the setup wizard and Settings panel in the UI.

**If auto-detection picks the wrong interface** (e.g. on a machine with multiple NICs), you can override it by uncommenting the relevant lines near the bottom of the `probe:` environment block in `docker-compose.yml`:

```yaml
# IP_RANGE: "192.168.1.0/24"
# INTERFACE: "eth0"
# LAN_DNS_SERVER: "192.168.1.1"
```

Rebuild after changing docker-compose.yml: `./inspectre.sh rebuild keep-data`.

### 1.3 First Run & Setup Wizard

This builds all four containers (database, backend/web, probe, and frontend) and starts them in the background. On first run, the database schema is created automatically — you do not need to run any migrations manually.

The first ARP sweep begins within a few seconds. Depending on the size of your network, all currently-online devices typically appear within 30–60 seconds.

**Helper script commands:**

```bash
./inspectre.sh up                    # start the stack
./inspectre.sh down                  # stop the stack
./inspectre.sh rebuild               # full wipe and rebuild (WARNING: deletes postgres_data/)
./inspectre.sh rebuild keep-data     # rebuild containers but preserve the database
./inspectre.sh logs                  # tail live logs from all containers
```

### 1.4 Accessing the UI

Open a browser and navigate to:

```
http://<host-ip>:3000
```

If you are running InSpectre on the same machine as your browser, use `http://localhost:3000`.

The UI is a single-page React application with built-in authentication. On first launch you will be taken through the **Setup Wizard** before reaching the main dashboard.

### 1.5 Authentication

InSpectre has built-in username and password authentication.

**Setup Wizard (first run):**

On first launch, the setup wizard guides you through seven steps:

| Step | What you configure |
|---|---|
| **Create Account** | Admin username (min 3 chars) and password (min 8 chars) |
| **Network Settings** | Scan CIDR range, DNS server, and gateway IP — auto-detected from the host interface |
| **Vuln Scans** | Whether to enable scheduled vulnerability scanning and the scan interval |
| **Notifications** | Toast/browser notifications and any push notification provider (ntfy, Gotify, Pushbullet, webhook) |
| **Container Monitoring** | Optional: add a Docker or Proxmox VE host for container visibility |
| **Device Identification** | Optional: enter a [Fingerbank](https://fingerbank.org/) API key for cloud-based DHCP device identification (free account, 600 lookups/hour) |
| **Done** | Completes setup and goes to the dashboard |

You can also choose **Restore from backup** at the start of the wizard to import a previous InSpectre JSON backup — this restores all devices, settings, and credentials without going through manual configuration.

**Logging in:**

After setup, every visit requires logging in with the credentials you created. Sessions are JWT-based and stored in the browser. If you are inactive for a while, you may be asked to log in again. Use **Remember me** on the login form to extend the session duration (30 days instead of the default 24 hours).

**Changing your password:**

Go to **Settings → Admin → Change Password** to update your credentials at any time.

---

### 1.6 Deploying from Docker Hub

The [one-line installer](#12-installation) is the easiest path and uses these images under the hood. This section documents the images and the manual deployment process.

**Docker Hub images:**

| Image | x86-64 tag | Raspberry Pi / ARM64 tag | Purpose |
|---|---|---|---|
| `thefunkygibbon/inspectre-frontend` | `latest` | `raspi` | nginx + React SPA |
| `thefunkygibbon/inspectre-web` | `latest` | `raspi` | FastAPI backend |
| `thefunkygibbon/inspectre-probe` | `latest` | `raspi` | Network probe |

The PostgreSQL database uses the official multi-arch `postgres:15-alpine` image, which runs natively on both architectures.

**Quick install (interactive, recommended):**

```bash
curl -fsSL https://raw.githubusercontent.com/thefunkygibbon/InSpectre/main/inspectre-install.sh | bash
```

The installer:

- Verifies all prerequisites (Docker, Docker Compose v2, curl, openssl) and that the Docker daemon is running
- Detects your CPU architecture and asks whether to install **x64** (`latest`) or **Raspberry Pi** (`raspi`) images
- Asks for an install directory and downloads `docker-compose.deploy.yml`
- Generates a secure database password and secret key
- Optionally lets you set `IP_RANGE` and `INTERFACE`
- Writes a `.env` file (including `INSPECTRE_TAG`) and starts the stack

**Manual install:**

1. Download the deploy Compose file:

```bash
curl -O https://raw.githubusercontent.com/thefunkygibbon/InSpectre/main/docker-compose.deploy.yml
```

2. Create a `.env` file (in the same directory) and set the required values:

| Variable | What to set |
|---|---|
| `INSPECTRE_TAG` | `latest` for x86-64 (default), or `raspi` for Raspberry Pi / ARM64 |
| `POSTGRES_PASSWORD` | A strong password for the database — used by both `db` and `web`/`probe` |
| `SECRET_KEY` | A random 64-character hex string for JWT signing |

Generate a secure `SECRET_KEY`:

```bash
openssl rand -hex 32
```

Example `.env` for a Raspberry Pi:

```bash
INSPECTRE_TAG=raspi
POSTGRES_PASSWORD=your-strong-password
SECRET_KEY=your-64-char-hex-key
```

3. Optionally override network detection (leave commented out for auto-detection):

```yaml
# IP_RANGE: "192.168.1.0/24"   # Your LAN subnet
# INTERFACE: "eth0"             # Network interface to use
```

4. Start the stack:

```bash
docker compose -f docker-compose.deploy.yml up -d
```

5. Open your browser and navigate to **http://localhost:3000** (or the host's IP). Complete the first-run setup wizard to create your admin account and finalise configuration.

**Updating:**

```bash
docker compose -f docker-compose.deploy.yml pull
docker compose -f docker-compose.deploy.yml up -d
```

---

## 2. Device Discovery

### 2.1 How Discovery Works

Discovery is handled entirely by the **probe** container, which runs on the host's network stack with elevated privileges. Two parallel mechanisms run continuously:

1. **Active ARP sweep** — The probe broadcasts ARP requests to every address in the configured `IP_RANGE`. Hosts that are online reply with their MAC address, which the probe upserts into the `devices` table. The sweep interval is configurable in Settings.
2. **Passive ARP sniffer** — A packet capture listener watches for ARP traffic initiated by other devices (e.g., a phone renewing its lease, a device sending a gratuitous ARP). This catches devices that join the network between sweeps without waiting for the next scan cycle.

When a device is seen for the first time, a `joined` event is written to the event log and an alert is dispatched to all configured notification channels.

### 2.2 ARP Sweep vs Passive Sniffer

| | ARP Sweep | Passive Sniffer |
|---|---|---|
| **How it works** | Probe sends ARP requests, waits for replies | Probe listens for any ARP broadcast on the LAN |
| **Detects new devices** | Yes, on the next sweep cycle | Yes, immediately when they broadcast |
| **Works while device is idle** | Yes | Only if the device sends ARP traffic |
| **Configurable interval** | Yes (Settings → Scanner → Scan Interval) | Runs continuously |
| **CPU/network impact** | Very low | Negligible |

Both mechanisms run in parallel at all times. The sniffer is the primary source of near-instant detection; the sweep catches devices that may not have broadcast ARP traffic since the sniffer started.

### 2.3 Hostname Resolution

For each discovered device, the probe attempts to resolve a hostname using:

1. **Reverse DNS** — PTR lookup against the configured `LAN_DNS_SERVER`
2. **mDNS / Bonjour** — `.local` name resolution for Apple and other mDNS-advertising devices
3. **NetBIOS** — Windows machine names broadcast over the local network
4. **DHCP Option 12** — the hostname a device self-reports in its DHCP lease request; this replaces IP-derived placeholder names (such as `192-168-0-15.lan`) whenever a better name arrives

The best available name is stored in the `hostname` field. If none is found, the field is left blank and only the IP and MAC are shown.

---

## 3. Device Management

### 3.1 Dashboard Views

The main dashboard offers three layout views, selectable from the toolbar:

| View | Description |
|---|---|
| **Grid** | Card-based layout. Each card shows status indicator, IP, custom name or hostname, vendor, device type icon, open port count, and highest vulnerability severity badge. Best for medium-sized networks. |
| **List** | Compact table. More devices visible at once. Columns include status, IP, name, MAC, vendor, ports, vuln severity, and last seen. Best for large networks or dense displays. |
| **Category** | Devices grouped by automatically detected device type (Router, Phone, Laptop, NAS, Smart TV, IoT, Unknown, etc.). Useful for an at-a-glance network composition view. |

Switch views using the grid/list/category icons in the top toolbar. Your preference is remembered across sessions.

The **Device Presence** page (left nav) shows a multi-device uptime timeline with visual presence bars over 7 days, 1 month, or 1 year. Each bar represents a device's online/offline status over time, with green segments for online and red for offline.

The **Network Events** page (left nav) shows a chronological log of all online/offline transitions across all devices, with source attribution (ARP sweep, passive sniffer, or plugin detection).

### 3.2 Search and Filtering

**Search bar** — The search box at the top performs a live full-text match across:
- IP address
- MAC address
- Hostname
- Vendor name
- Custom name
- Tags
- Location / room
- Zone name

**Stat cards** — The four cards at the top of the page (Total, Online, Offline, Watched) act as one-click filters. Clicking "Offline" shows only offline devices, for example. Click again to clear.

**Smart filter bar** — A row of quick-filter chips below the stat cards. Filters use AND logic (multiple active chips narrow the result further). Available filters:

| Filter | Shows devices that... |
|---|---|
| Watched | Are starred/watched |
| Unknown type | Have an unresolved device type |
| Open ports | Have at least one open port recorded |
| Not scanned | Have never had a port scan completed |
| Vulnerable | Have at least one vulnerability finding |
| Vuln scanned | Have had a vulnerability scan completed |
| Blocked | Are currently blocked from the internet |
| Has notes | Have a non-empty notes field |
| Tagged | Have at least one tag assigned |
| Ignored | Are flagged as ignored (hidden by default — enable this filter to see them) |
| New (14d) | Were first seen within the last 14 days |
| DHCP seen | Have broadcast a DHCP packet that the probe captured |

**Saved views** — While one or more filters are active, a **Save View** button appears. Click it to name and save the current filter combination. Saved views appear in the filter bar for instant recall.

### 3.3 Device Drawer — Overview Tab

Click any device card or row to open the device drawer. The **Overview** tab is the default view.

It shows:
- **Status badge** — Online / Offline, with time since last seen
- **Block status** — Blocked badge if the device is currently ARP-blocked
- **Vulnerability severity badge** — highest severity across all current findings (Critical, High, Medium, Low, or Clean)
- **IP address** — current IP, with copy button
- **MAC address** — with copy button
- **Vendor** — resolved from OUI database; falls back to Fingerbank parent hierarchy when no OUI entry exists; shows override if set
- **Hostname** — resolved name, or blank
- **Operating system** — from nmap OS detection, if available
- **Open ports** — list of open TCP ports with service names and version info where known
- **Last seen / First seen** timestamps
- **DHCP Fingerprint** — a collapsible section (shown when DHCP data has been collected) displaying the device's self-reported hostname, vendor class ID, DHCP option list, and any Fingerbank cloud identification result; see [Section 3.12](#312-dhcp-fingerprinting--fingerbank)
- **Grouped interfaces** — if this device has been grouped with other interfaces of the same physical device, a collapsible "Grouped Interfaces" panel shows each member MAC with its display name, current IP, and online status dot

### 3.4 Device Drawer — Actions Tab

The **Actions** tab provides on-demand network operations:

| Action | Description |
|---|---|
| **Ping** | Sends ICMP echo requests to the device and streams results live. Shows round-trip time and packet loss. |
| **Traceroute** | Traces the network path to the device. Output streams in real time. |
| **Re-scan ports** | Triggers an immediate nmap TCP port scan for this device only, using the configured nmap arguments. Results update the open ports list when complete. |
| **Run vulnerability scan** | Triggers an immediate nuclei-based vulnerability scan. Progress streams live in the Vulnerabilities tab. |
| **Block / Unblock** | Enables or disables ARP MITM-based internet blocking for this device. Takes effect within seconds. |

### 3.5 Device Drawer — Vulnerabilities Tab

The **Vulnerabilities** tab displays the results of the most recent nuclei scan for this device.

- **Live streaming output** — when a scan is running, output streams in real time so you can follow progress
- **Findings list** — after scan completion, findings are grouped and shown by severity (Critical first, then High, Medium, Low)
- **Finding detail** — each finding shows the template name, matched URL or target, CVE ID (if applicable), severity badge, and a description
- **Inline scan settings** — scan configuration options (such as template selection and rate limiting) are accessible directly within this tab without navigating to Settings
- **Last scanned timestamp** — shown at the top so you can tell how current the results are

If no scan has ever been run, a prompt is shown to trigger the first scan.

### 3.6 Device Drawer — Traffic Tab

The **Traffic** tab shows per-device traffic analysis collected while a traffic monitoring session was active for this device.

Data shown includes:
- Total bytes in / out
- Total packets in / out
- Domains contacted (resolved from DNS traffic observed during the session)
- Countries contacted (GeoIP resolved)
- Unusual or unexpected ports used
- Protocol breakdown

See [Section 7 — Traffic Monitor](#7-traffic-monitor) for how to start a monitoring session.

### 3.7 Device Drawer — Timeline Tab

The **Timeline** tab provides two views of a device's history:

**7-day uptime bar** — A visual bar showing presence on the network in hour-by-hour segments over the past 7 days. Green segments indicate the device was seen online; grey indicates offline or no data.

**Event log** — A full chronological list of every recorded event for this device, including:

| Event type | Meaning |
|---|---|
| `joined` | First time the device was ever seen |
| `online` | Device came back online after being offline |
| `offline` | Device stopped responding |
| `ip_change` | Device's IP address changed |
| `scan_complete` | Port scan finished |
| `port_change` | Open ports changed since the last baseline |
| `renamed` | Custom name was changed |
| `tagged` | Tags were added or modified |
| `marked_important` | Device was starred/watched |
| `vuln_scan_complete` | Vulnerability scan finished |
| `interface_joined` | A new MAC was discovered sharing the same hostname — automatically grouped with this device as a new interface |

Online/offline events show the **detection method** (ARP sweep, passive sniffer, or plugin source) so you can see how presence was determined.

### 3.8 Device Drawer — Admin Tab

The **Admin** tab provides metadata management for the device:

**Identity overrides:**
- **Custom name** — a friendly label displayed instead of the hostname throughout the UI
- **Vendor override** — override the OUI-resolved vendor name
- **Device type override** — manually set the device type (Router, Phone, Laptop, Smart TV, IoT, etc.). This also feeds the local fingerprint database so future devices with the same OUI + port pattern are auto-classified the same way.

**Organisation:**
- **Location / Room** — free-text field (e.g., "Living Room", "Office")
- **Tags** — comma-separated or chip-based tag input; used for filtering and grouping
- **Zone** — assign the device to a zone/network segment
- **Notes** — multi-line free-text notes visible only in the drawer

**Flags:**
- **Watched** — marks the device as important; enables elevated offline alerts and Watched sort priority
- **Ignored** — hides the device from the default view (it still appears when the Ignored filter is active)

**Device Grouping:**
A **Device Grouping** collapsible at the bottom of the Admin tab allows manual group management. It shows all MACs currently in the group with their display names and online status. From here you can:
- **Remove** a member from the group (it becomes a standalone device again)
- **Set as primary** — the primary member is used as the group representative when multiple interfaces are online simultaneously
- **Add by MAC** — manually add another device (by MAC address) to this group

### 3.9 Watched Devices

Marking a device as **Watched** (by clicking the star icon on a device card or enabling the toggle in the Admin tab) gives it elevated status:

- Appears in the **Watched** stat card count
- Can be sorted to the top of the list using **Sort: Watched first**
- Generates a higher-priority offline alert (distinct from standard offline alerts)
- Watched badge displayed on the device card

Use this for devices you always want to notice — your router, NAS, security cameras, or any device where unexpected downtime matters.

### 3.10 Ignoring Devices

Marking a device as **Ignored** removes it from the default view while keeping all its history intact. This is useful for devices you have confirmed are benign and don't want cluttering the dashboard (e.g., a known smart plug, a printer you don't care about).

To see ignored devices, activate the **Ignored** smart filter.

### 3.11 Zones

Zones are named network segments or logical groupings (e.g., "IoT VLAN", "Guest Network", "Trusted Devices"). Assign devices to a zone from the Admin tab.

Zones currently serve as an organisational label and filter dimension. They appear in search results and can be used in saved views.

### 3.12 DHCP Fingerprinting & Fingerbank

Every time a device renews its IP lease it broadcasts a DHCP packet that the probe captures passively (no extra traffic generated). Three fields are extracted:

| Field | DHCP Option | Example |
|---|---|---|
| **Hostname** | Option 12 | `OnePlus-15` |
| **Vendor class ID** | Option 60 | `dhcpcd-9.4.1:Linux-6.6` |
| **Option 55 list** | Option 55 | `1,3,6,15,26,28,51,58,59,43` |

**How it is used:**

1. **Hostname promotion** — if the device's current hostname is an IP-derived placeholder (e.g., `192-168-0-15.lan`), the DHCP hostname replaces it automatically.
2. **Local classification** — the vendor class ID and option 55 list are matched against known patterns to infer the device type (e.g., `android-dhcp-13` → Phone) before any cloud lookup is made.
3. **Fingerbank lookup** — if a Fingerbank API key is configured, the probe's background loop sends the DHCP data to the [Fingerbank](https://fingerbank.org/) cloud database (free, 600 lookups/hour). Each device is queried **once** automatically; after a successful result or a permanent "no match" response, the device is never re-queried unless you click **Re-fetch** in the drawer.

**DHCP Fingerprint panel (in the device drawer Overview tab):**

- Shown only when at least one DHCP field has been collected.
- Displays hostname, vendor class, and option 55 list.
- If Fingerbank returned a result, shows the **device name**, **parent hierarchy** (e.g., `OnePlus Android › Android › Mobile`), **mapped device type**, and a **confidence score** (colour-coded: green ≥ 70, amber ≥ 40, red < 40).
- A **Re-fetch** button triggers an immediate new lookup against Fingerbank regardless of prior status.

**Status messages when no Fingerbank result is shown:**

| Message | Meaning |
|---|---|
| *Fingerbank lookup pending — will run automatically within a minute.* | The background loop has not yet processed this device. |
| *No match found in Fingerbank database.* | Fingerbank has no entry for this device; the device will not be automatically re-queried. |
| *API key rejected — check Settings → Scanner → Device Identification.* | The configured API key was rejected (401). |
| *Lookup failed: [message]* | A transient error occurred; the loop will retry on the next cycle. |

**No DHCP data yet?**

DHCP packets are only captured when the device actively requests or renews its lease. If a device obtained its lease before InSpectre was started, no DHCP data will be present until the lease expires or you force a renewal. The panel shows a hint with the relevant commands:
- **Windows:** `ipconfig /release` then `ipconfig /renew`
- **Linux:** `sudo dhclient -r && sudo dhclient`

**Configuring Fingerbank:**

Enter your API key in **Settings → Scanner → Device Identification → Fingerbank API Key**. Register for a free account at [fingerbank.org](https://fingerbank.org/).

### 3.13 Device Grouping

Many devices appear on the network with more than one MAC address — typically a laptop or desktop with both a wired Ethernet port and a Wi-Fi adapter, or a server with a real NIC plus a Docker **macvlan shim** interface. Without grouping, these show as two separate devices. InSpectre automatically detects this pattern and merges them.

**How auto-grouping works:**

When two or more devices share the same hostname (after stripping domain suffixes like `.lan` or `.local` and ignoring case), they are placed in the same group. The matching logic:

- Strips domain suffixes: `andrewlaptop.lan` and `andrewLAPTOP` both resolve to base label `andrewlaptop`
- Case-insensitive: `AndrewLaptop` == `andrewlaptop`
- Generic hostnames are excluded (Android-*, iPhone, localhost, etc.) to avoid false merges
- **IP-literal hostnames are excluded** — names that merely echo the address back (e.g. `192-168-0-180.lan`, or a bare numeric label) carry no identity, so unrelated devices that lack a real DNS name are never wrongly merged

**Self-healing (retroactive) grouping:**

Grouping does not only happen the instant a device is first seen. A periodic pass runs on every scan cycle and merges any matching devices — including ones discovered long ago and ones that are currently online. You never need to delete and rediscover devices; existing records are grouped automatically as soon as their hostnames match.

**How the primary interface is chosen:**

When the group is formed automatically, InSpectre picks the most "real" interface as the primary, in this priority order:

1. A globally-unique **hardware** MAC beats a locally-administered/virtual MAC (so a physical Dell NIC wins over a `02:…` macvlan shim)
2. An **online** member beats an offline one
3. The **lowest IP** breaks any remaining tie

The choice is deterministic, so the primary never flaps. You can override it at any time (see below).

**Disabling auto-grouping:**

If you prefer to manage grouping manually, go to **Settings → Scanner → Auto-group by Hostname** and disable the toggle. With auto-grouping off, InSpectre flags devices with matching hostnames (writing a suggestion event) but does not merge them automatically.

**What changes when devices are grouped:**

| Aspect | Behaviour |
|---|---|
| **Dashboard card** | Only one card is shown — the representative interface, which is the user-selected/auto-chosen primary. The card reports **online if *any* member interface is online**, so it won't flap offline when the host switches interfaces. |
| **Card footer — Interfaces row** | Lists all member interfaces with their online status dots and display names |
| **Overview tab** | "Grouped Interfaces" panel shows all members, their IPs, and which is primary |
| **Timeline** | Shows events from all member MACs in a single unified timeline, plus per-member uptime bars. Events from a different MAC than the one whose drawer you have open are labelled with the source interface. |
| **Scanning** | By default only the **primary** interface is port- and vulnerability-scanned, since grouped interfaces are the same physical host. Enable **Settings → Scanner → Scan grouped members** to scan every interface IP separately. |
| **Event type** | New interfaces added to an existing group write an `interface_joined` event instead of a `joined` event |
| **Admin tab** | Device Grouping section allows adding, removing, and setting the primary interface |

**Setting the primary interface:**

Open the group's drawer → **Admin** tab → **Device Grouping**, and click **Set primary** next to the interface you want to represent the group. The primary's name, IP, and MAC are what appear on the dashboard card.

**Manual grouping:**

To manually add a device to an existing group:
1. Open either device's drawer → **Admin** tab → **Device Grouping**.
2. Enter the MAC address of the other device in the "Add by MAC" field.
3. Click **Add**.

To remove a device from a group, click the **Remove** button next to that MAC in the same panel. The removed device becomes a standalone device again and appears separately on the dashboard.

**Manual groups are protected:** any group you create or modify by hand is flagged as manual and is never altered or undone by the automatic passes. In addition, **a device you deliberately ungroup is remembered** — the self-healing pass will not silently re-merge it even if its hostname still matches. (Manually adding it back to a group clears this opt-out.)

### 3.13.1 Primary IP & Multi-Homed Hosts

A single device can answer on more than one IP address from the **same** MAC — for example a server with two addresses on one NIC, or a bridge. Previously this caused the device's displayed IP to "flap" back and forth every scan cycle, spamming `ip_change` events.

InSpectre now pins a **stable primary IP** for each device and treats any other address it answers on as a **secondary IP**:

- The dashboard and drawer show the primary IP; secondary IPs are listed separately (and on the device card).
- A passive secondary sighting no longer writes an `ip_change` event — only a genuine primary change does (and is recorded as `primary_ip_changed`).
- If the primary address genuinely goes away (not seen for several scan cycles) and the device is unlocked, a newly-seen address is promoted to primary automatically.

**Pinning a primary IP manually:**

Open the device drawer → **IP History** panel. Each address shows a role badge (Current, Secondary, Pinned, etc.). Click **Set primary** on the address you want to fix. This pins it permanently — the probe will never auto-change it (a small **pinned ✕** badge appears next to the IP; click it to unpin). This is the most reliable way to control which address represents a multi-homed host.

The auto-update behaviour is governed by **Settings → Scanner → Primary IP Mode** (see Settings Reference):

- **locked** (default) — respects the per-device pin; pinned devices never have their primary auto-changed.
- **dynamic** — always adopts the current IP as primary when a device returns from offline.

### 3.13.2 Host-Aware Presence

The probe runs in the Docker **host's network namespace**, so it shares the host's own IP addresses — its primary NIC, any macvlan shim interfaces, bridges, etc. A host does not answer ARP for its own addresses the way a remote device does, so such interfaces could previously be marked falsely "offline" even though they are trivially reachable.

InSpectre now enumerates the host's own IPv4 addresses each cycle and treats any device holding one of them as **always present**. This fixes the common case where the Docker host itself (or its macvlan shim) showed as offline while still pinging perfectly.

### 3.14 Acknowledging New Devices

When InSpectre sees a device for the first time, it is marked as **new**. By default, new devices float to the top of the device list and are highlighted to draw your attention.

Once you have reviewed a new device and are happy it belongs on your network, click the **NEW** badge (anywhere on the badge) or **Acknowledge** in the device drawer. This:
- Removes the "new" highlight and stops it floating to the top
- Flips the MQTT `new` binary sensor to OFF (if Home Assistant MQTT is configured)
- Persists server-side — acknowledged status survives browser sessions and won't reset if you clear localStorage or open a different browser

To control whether new devices float to the top, see **Settings → Scanner → Float New Devices to Top**.

### 3.15 Device Presence Page

Access the **Device Presence** page from the left navigation menu. This page shows a visual timeline for all devices on your network:

**Features:**
- **Time periods** — switch between 7-day, 1-month, or 1-year views
- **Presence bars** — each device gets a horizontal bar showing online (green), offline (red), and unknown (grey) segments
- **Uptime percentage** — displayed on the right of each bar
- **Device/Container toggle** — switch between network device presence and Docker container uptime
- **Search** — filter the list by device name, IP, or MAC address

Each segment of the presence bar is clickable to see the exact timestamp range.

### 3.16 Network Events Page

Access the **Network Events** page from the left navigation menu. This page shows a chronological log of all online/offline status changes across your entire network:

**Features:**
- **Event log** — lists every device coming online or going offline, newest first
- **Source attribution** — each event shows how it was detected (ARP sweep, passive sniffer, or plugin)
- **Device links** — click any device name to open its drawer
- **Search** — filter events by device name, IP, or MAC address
- **Event limits** — choose to view 50, 120, 300, or 1000 recent events
- **Event stats** — shows total events and counts of online vs offline transitions

This is useful for troubleshooting intermittent connectivity issues or tracking when specific devices were last active.

### 3.17 Person Presence Page

Access the **Person Presence** page from the left navigation menu. Where the dashboard thinks in terms of individual MAC addresses, this page thinks in terms of **people** — group the devices a household member carries (phone, laptop, watch, tablet) under one named person and track whether they are home.

**Creating a person:**

1. Click **Add person**.
2. Enter a name and, optionally, upload a photo.
3. Start typing in the device search box to attach devices — the autocomplete matches by name, IP, or MAC.
4. Click the **star** on any attached device to make it the **primary presence device** (the authoritative indicator for whether the person is home).
5. Save.

**Reading a person card:**

| Element | Meaning |
|---|---|
| **At Home / Away badge** | Shown with a Home or Away icon and a colour-coded accent bar so the state is obvious at a glance. A person is **At Home** when any of their devices (or their primary device, if set) is online. |
| **Avatar** | The uploaded photo, or initials if none is set |
| **Primary tag** | Marks which device drives the presence state |
| **Presence timeline** | A home/away history bar over the selected period, with an at-home percentage |
| **Block button** | Blocks or unblocks every device belonging to the person in one action |

**Per-person block schedules:**

Each person card includes a **Block Schedules** panel. Add a recurring rule (days of the week, start time, end time) that automatically blocks all of that person's devices during the window — for example, blocking a child's devices every school night. Schedules can be enabled/disabled individually and deleted. These use the same scheduling engine as per-device block schedules (see [6.3](#63-block-schedules)).

**Presence notifications:**

Person Presence integrates with the notification profile system. The following events can be routed to any notification channel (see [Notifications](#9-notifications)):

- **Person Arrived Home** (`person.home`) — one of the person's devices came online
- **Person Left Home** (`person.away`) — the person's devices all went offline
- **Person Blocked** (`person.blocked`) — all of a person's devices were blocked
- **Person Unblocked** (`person.unblocked`) — the person's devices were unblocked

### 3.18 Live Updates (SSE)

InSpectre pushes changes to the UI in real time using **Server-Sent Events (SSE)** rather than relying solely on fixed-interval polling. The browser opens a single long-lived connection to `GET /api/events/stream` (authenticated via a query-string token), and the backend broadcasts lightweight hints on channels such as `devices`, `persons`, and `schedules` whenever something changes.

**What this means for you:**

- Pages refresh the instant something happens — a device going offline, a block being applied, a schedule being created or deleted, or a person's presence changing — instead of after a 10–30 second poll.
- You no longer lose in-progress work (e.g. while filling in a schedule form) to a disruptive full-page refresh.
- A slow background poll remains as a safety net if the SSE connection drops, so the UI stays correct even on flaky connections.

No configuration is required. If you run InSpectre behind your own reverse proxy, ensure response buffering is disabled for the `/api/events/stream` path so events are delivered immediately (the bundled nginx config already does this).

---

## 4. Network Scanning

### 4.1 Port Scanning

Port scanning is performed by **nmap** inside the probe container. Each device can be scanned individually (via the Actions tab) or as part of a scheduled sweep across all devices.

**What is scanned:**
- TCP ports, using the nmap arguments configured in Settings → Scanner → Nmap Arguments
- Default arguments perform a SYN scan of the most common ports; you can customise this (e.g., `-p 1-65535` for a full port range, or `-p 80,443,22,3389` for specific ports)

**Scan results stored:**
- Open port numbers and their service names
- Service version strings where nmap can determine them
- OS detection results

**Scheduled port scans** run automatically at the interval configured in Settings → Scanner → Scan Interval. The nightly scan window setting lets you restrict heavy scans to overnight hours to avoid impacting network performance during the day.

**When scans are triggered, and which IP is used:**

A port/service scan can be triggered three ways. All three run the identical scan and always target the device's **primary IP** (see [3.13.1](#3131-primary-ip--multi-homed-hosts)), so multi-homed and grouped hosts are scanned consistently:

| Trigger | When | Notes |
|---|---|---|
| **First seen** | The first time a brand-new device is discovered (if *Auto-scan new devices* is on) | Establishes the initial port set |
| **Reconnect** | A device comes back online after being offline longer than the *Offline rescan hours* threshold | Re-scans to catch changes that happened while it was away |
| **Manual** | The **Rescan** button in the device drawer's Actions tab | On-demand; always runs regardless of schedule |

A device that reconnects after only a *short* offline period is **not** re-scanned.

**Grouped devices:** by default only the group's **primary** interface is scanned, since grouped interfaces belong to the same physical host. Set **Settings → Scanner → Scan grouped members** to scan every interface IP in the group separately. (Manual per-device scans from the drawer always run, regardless of this setting, because they reflect explicit user intent.)

### 4.2 OS Detection

nmap's OS fingerprinting (`-O` flag, enabled by default) probes open ports to make an educated guess at the device's operating system. Results are stored and shown in the Overview tab.

OS detection accuracy varies and is sometimes wrong, especially for IoT devices or devices that limit ICMP/TCP responses. Manual device type overrides in the Admin tab always take precedence in the UI.

### 4.3 Service Fingerprinting

InSpectre combines nmap's `-sV` (service version detection) results with a local fingerprint database to match open ports and detected services against known product signatures.

Fingerprints are stored in the local `fingerprints` table with three source types:

| Source | Created by |
|---|---|
| `auto` | Automatic pattern matching during scan |
| `manual` | User-set device type or vendor override in the Admin tab |
| `community` | Imported from a shared fingerprint database file |

When a user sets a device type or vendor override, the OUI prefix and open port set are saved as a `manual` fingerprint. Future devices with the same OUI + port pattern will be auto-classified to the same device type.

### 4.4 Baseline Tracking and Drift Alerts

After each port scan, InSpectre compares the results against the device's **baseline** — the previously confirmed set of open ports.

If new ports have opened or existing ports have closed since the baseline was set, a `port_change` event is written to the device timeline and an alert is dispatched to configured notification channels.

**Baseline confirmation** is a setting in Settings → Scanner. When enabled, you must explicitly confirm a new port set as the new baseline after reviewing a change. When disabled, the new port set automatically becomes the baseline after each scan.

This is the primary mechanism for detecting unexpected services appearing on devices — for example, a device that suddenly opens port 23 (Telnet) or 4444 (a common backdoor port).

---

## 5. Vulnerability Scanning

### 5.1 How It Works

Vulnerability scanning is powered by [Nuclei](https://github.com/projectdiscovery/nuclei) and runs inside the probe container. InSpectre uses a targeted template-routing strategy rather than running all templates against all ports, which keeps scans fast and reduces false positives.

The scan follows these steps:

1. **Port data** — The prior nmap scan results are used to determine which ports are open. If no port data exists, a service detection pre-scan is run first.
2. **Service fingerprinting** — nmap `-sV` runs against any ports that don't yet have service version data.
3. **Template routing** — Each open port is assigned the most relevant Nuclei template set:
   - HTTP/HTTPS ports receive: `http/misconfiguration`, `http/default-logins`, `http/exposed-panels`, `http/exposures`, `http/vulnerabilities`, `ssl/`
   - Identified HTTP products (nginx, Apache, Grafana, Jellyfin, etc.) receive matched `http/cves` templates filtered by product tag
   - Network services (SSH, FTP, Redis, RDP, MQTT, SMB, Telnet, etc.) receive `network/cves`, `network/default-logins`, and `network/exposed-service` templates filtered by service tag
4. **Results storage** — Findings are stored in the `vuln_reports` table. The device row is updated with the highest severity found and the scan timestamp.

**Template updates** — Nuclei templates are updated automatically on a configurable interval (default: every 24 hours). Updates happen in the background and do not interrupt running scans.

### 5.2 Running a Scan Manually

1. Open a device's drawer by clicking it on the dashboard.
2. Go to the **Actions** tab.
3. Click **Run vulnerability scan**.
4. Switch to the **Vulnerabilities** tab to watch live progress output.

Alternatively, click the vulnerability scan button from any device card context menu.

### 5.3 Scheduled Vulnerability Scans

InSpectre can automatically run vulnerability scans on a schedule. Configure this in **Settings → Scanner**:

- **Auto-scan new devices** — triggers a vulnerability scan automatically when a new device is first discovered
- **Nightly scan window** — define a time window (e.g., 02:00–04:00) during which the backend schedules full vulnerability scans across all devices. This avoids disrupting network usage during the day.
- **Scan interval** — how frequently the scheduled scan cycle runs

### 5.4 Reading Scan Results

Results in the Vulnerabilities tab are grouped by severity:

| Severity | Meaning |
|---|---|
| **Critical** | Severe vulnerabilities that should be addressed immediately. Often remotely exploitable with no authentication. |
| **High** | Serious issues with significant exploitation potential. |
| **Medium** | Exploitable issues with reduced impact or requiring specific conditions. |
| **Low** | Minor issues, informational findings, or hardening recommendations. |

Each finding shows:
- **Template name** — the Nuclei template that matched
- **Target** — the URL or host:port that was matched
- **CVE ID** — if the finding maps to a known CVE
- **Description** — what the finding means and why it matters

A finding does not necessarily mean the device is compromised — it means a condition exists that matches a known vulnerable pattern. Review each finding in context.

### 5.5 Vulnerability Settings

Global vulnerability scan settings are accessible from the **Vulnerability Report** page (the shield icon in the nav bar) via the **settings cog** (⚙) in the top-right of the header. Clicking the cog expands a settings panel inline on the page.

Available settings:

| Setting | Description |
|---|---|
| **Scheduled Scans** | How often to automatically run scans across all eligible devices (disabled / 6h / 12h / daily / weekly). |
| **Scan Targets** | Whether scheduled scans cover all devices or only watched (starred) devices. |
| **Auto-scan New Devices** | Trigger a scan automatically when a previously unseen device is first discovered. |
| **Scan on Port Change** | Trigger a scan when a device's open port list changes (indicates a service change). |
| **Template Updates** | How often to pull the latest nuclei vulnerability templates from the nuclei-templates repository. |
| **Template Tags** | Comma-separated nuclei tag filters (e.g. `cve,exposure,misconfig,default-login,network`). |

Changes take effect on the next scan cycle. Click **Save settings** after making changes.

### 5.6 Security Dashboard

The **Security Dashboard** (Vulnerability Report page) provides a network-wide vulnerability summary. Access it from the main navigation bar (shield icon).

It shows:
- Total finding counts by severity across all devices
- Devices ranked by highest vulnerability severity
- Quick-jump links into each device's Vulnerabilities tab
- A summary of the last time each device was scanned
- **Settings cog** to configure scan schedule and behaviour inline

Use this view to prioritise which devices to address first after a scan cycle completes.

---

## 6. Device Blocking

InSpectre implements device blocking using **ARP spoofing (ARP MITM)**. When a device is blocked, the probe continuously sends spoofed ARP replies to the device and to the gateway, poisoning both ARP caches so traffic between the device and the internet is intercepted and dropped. No traffic needs to traverse the InSpectre host for this to work on most networks — the poisoned ARP cache prevents routing at the source.

> **Note:** ARP-based blocking is effective on flat Layer 2 networks (typical home networks). It may not work on networks with dynamic ARP inspection (DAI) enabled on managed switches, or on VLANs the probe cannot reach.

### 6.1 Blocking a Single Device

**To block:**
1. Open the device drawer.
2. Go to the **Actions** tab.
3. Click **Block internet access**.

Or click the block icon on the device card directly.

The device will show a **Blocked** badge within a few seconds. The block persists across InSpectre restarts.

**To unblock:**
- Return to Actions → click **Unblock internet access**, or click the block icon again on the device card.

### 6.2 Network Pause (Block All)

A **Network Pause** button in the main toolbar blocks all non-InSpectre devices on the network simultaneously. This is useful for:
- Cutting off internet access for all devices at a scheduled time (e.g., at bedtime)
- Quickly isolating the network during a suspected incident

Click **Network Pause** again to unblock all devices.

> Devices that were individually blocked before a network pause remain blocked after the pause is lifted.

### 6.3 Block Schedules

Block schedules let you define time-based rules to automatically block a device on a recurring basis — for example, blocking a games console every night from 22:00 to 07:00.

To create a block schedule:
1. Open the device drawer → **Actions** tab.
2. Click **Add block schedule**.
3. Set the days of the week, start time, and end time.
4. Save.

The probe checks active schedules on each scan cycle and applies or removes blocks accordingly.

Block schedules can also be attached to a **person** from the Person Presence page, in which case the schedule applies to every device belonging to that person. See [3.17 Person Presence Page](#317-person-presence-page).

---

## 7. Traffic Monitor

The Traffic Monitor uses ARP MITM (the same mechanism as device blocking) to intercept and analyse traffic for a specific device. Unlike blocking, the traffic monitor forwards packets to their destination — it only observes them.

### 7.1 Starting a Traffic Session

1. Open the device drawer.
2. Go to the **Traffic** tab.
3. Click **Start monitoring**.

The probe begins intercepting traffic for the device. While a session is active, the Traffic tab updates in real time with bytes, packet counts, domains, and other metrics.

To stop monitoring, click **Stop monitoring**.

> Running a traffic monitor session has a minor CPU impact on the probe host proportional to the amount of traffic the monitored device generates.

### 7.2 Understanding the Data

| Metric | Description |
|---|---|
| **Bytes in / out** | Total data received and sent by the device during the session |
| **Packets in / out** | Total packet counts |
| **Domains** | Hostnames resolved from DNS queries observed in the traffic stream. Shows what services the device is contacting. |
| **Countries** | GeoIP lookup of destination IPs, showing which countries the device is communicating with |
| **Unusual ports** | Destination ports that are not in the list of common expected ports (80, 443, 53, etc.). Unexpected ports can indicate non-standard applications or suspicious activity. |
| **Protocol breakdown** | Proportion of traffic by protocol (TCP, UDP, etc.) |

**Domains** are resolved from DNS traffic, so only hostnames that the device looked up via DNS during the session are captured. Direct IP connections are shown by IP address.

### 7.3 Speed Test

The **Speed Test** panel in the Traffic Monitor view runs the Ookla Speedtest CLI from the probe container and reports:
- Download speed (Mbps)
- Upload speed (Mbps)
- Ping latency (ms)
- Test server name and location

Results reflect the speed available to the InSpectre host, not to any specific client device. This is useful as a baseline to confirm your ISP is delivering the expected bandwidth.

**Running a test:**

1. Navigate to the **Traffic** page (the activity/chart icon in the nav bar).
2. Scroll to the **Speed Test** section.
3. Optionally select a specific test server from the **Choose server** dropdown — click the button to load the server list (closest servers are shown first). Leave on auto-select for the nearest server.
4. Click **Run Speed Test**.

Live download and upload progress is shown in real time as the test runs. When complete, the result is added to the history list below.

**Scheduling:**

Use the gear icon (⚙) in the speed test header to schedule automatic tests. Available intervals: every 30 minutes, hourly, every 6 hours, or daily. Results from scheduled tests appear in the same history list. The schedule persists across restarts.

**History:**

Past speed test results are stored and displayed in the history list with timestamp, server, ping, download, and upload. Individual results can be deleted from the list with the trash icon. Speed test history is included in the full JSON backup.

---

## 8. Network Tools

The **Network Tools** page is accessible from the main navigation bar. It provides a suite of diagnostic utilities that run from the probe container — giving you the perspective of a device on your LAN rather than from an external server.

### 8.1 IP Tools

| Tool | Description |
|---|---|
| **Ping** | Send ICMP echo requests to any IP or hostname. Shows per-packet RTT and summary statistics. |
| **Traceroute** | Trace the network path (hops) to a destination. Output streams live. |
| **Port Scan** | Run a quick TCP port scan against any host on any port range. |
| **Reverse DNS** | Look up the PTR record for an IP address to find its hostname. |
| **ARP Lookup** | Query the ARP cache or send an ARP request to resolve a MAC address for a given IP on the local network. |
| **Wake-on-LAN** | Send a magic packet to wake a device that supports WoL. Requires the target device's MAC address. |

### 8.2 DNS Tools

| Tool | Description |
|---|---|
| **Record Lookup** | Query any DNS record type (A, AAAA, MX, TXT, NS, CNAME, SOA, CAA, SRV) for any domain. |
| **DNS Propagation** | Check how a DNS record has propagated across multiple public resolvers worldwide. |
| **DoH Tester** | Test DNS-over-HTTPS resolution against various DoH providers. |
| **DNSSEC Validator** | Verify DNSSEC chain of trust for a domain, showing each step of the validation process. |
| **Reverse DNS Bulk** | Run PTR lookups for a list of IP addresses in bulk. |

### 8.3 Web Tools

| Tool | Description |
|---|---|
| **HTTP Headers** | Fetch and display all HTTP response headers for a URL. Useful for checking security headers (CSP, HSTS, X-Frame-Options, etc.). |
| **SSL/TLS Certificate** | Show the full details of a site's TLS certificate — issuer, subject, SANs, validity period, and chain. |
| **Redirect Chain** | Follow all HTTP redirects for a URL and show each hop in the chain with status codes. |
| **TLS Versions** | Test which TLS protocol versions (TLS 1.0, 1.1, 1.2, 1.3) a server accepts. |
| **HTTP Timing** | Break down HTTP request timing — DNS resolution, TCP connect, TLS handshake, time to first byte, and total time. |

### 8.4 Infrastructure Tools

| Tool | Description |
|---|---|
| **IP Geolocation** | Look up the geographic location (country, city, ASN) of any public IP address. |
| **WHOIS** | Retrieve WHOIS registration data for a domain or IP address. |
| **BGP/ASN Lookup** | Look up BGP routing information and ASN details for an IP or AS number. |
| **Subnet Calculator** | Calculate network address, broadcast address, usable host range, and subnet mask for any CIDR block. |

### 8.5 Email Tools

| Tool | Description |
|---|---|
| **MX/SPF/DMARC/DKIM** | Check a domain's email authentication records — Mail Exchanger, Sender Policy Framework, DMARC policy, and DKIM public key. |
| **SMTP Banner Grab** | Connect to port 25 on a mail server and capture its SMTP banner. |
| **BIMI Lookup** | Retrieve a domain's Brand Indicators for Message Identification record and display the associated logo URL. |
| **DNSBL Check** | Check whether an IP address appears on common DNS-based blacklists (spam blocklists). |

---

## 9. Notifications

InSpectre uses a **Channels and Profiles** system for notifications. Channels are reusable connection configurations (each has a service type and credentials). Profiles link event types to one or more channels. An event fires all channels attached to matching profiles. One channel can be used by multiple profiles.

Available services: ntfy, Gotify, Pushbullet, Webhook, Home Assistant, Matrix, SMTP, Slack, Telegram, Discord, Apprise generic URL.

### 9.1 Notification Channels

Channels are configured in **Settings → Notifications → Channels**. Each channel has:
- A display name
- A service type (ntfy, Gotify, Pushbullet, Webhook, Home Assistant, Matrix, SMTP, Slack, Telegram, Discord, or Apprise)
- Service-specific credentials (URL, token, host, etc.)
- An enabled/disabled toggle
- A **Test** button that sends a test notification immediately

### 9.2 Notification Profiles

Profiles are configured in **Settings → Notifications → Profiles**. Each profile:
- Has a display name
- Is associated with one or more channels
- Has per-event-type toggles (new device, device online, device offline, watched offline, vulnerability found, port change, device blocked/unblocked, and the Person Presence events: person arrived home, person left home, person blocked, person unblocked)
- Can be enabled/disabled as a whole

When an event fires, InSpectre finds all enabled profiles that have that event type enabled and dispatches to all their channels.

### 9.3 Setting up ntfy

1. Choose a topic name (e.g. `inspectre-alerts`)
2. Subscribe to the topic in the ntfy app on your phone
3. Settings → Notifications → Channels → Add Channel → service: ntfy
4. Fill in Server URL (e.g. `https://ntfy.sh` or your self-hosted URL) and Topic
5. Optionally set Username/Password for authenticated servers
6. Click Test to verify, then Save
7. Create a Profile and attach this channel to it with the events you want

### 9.4 Setting up Gotify

1. Create an application in your Gotify server to get an app token
2. Settings → Notifications → Channels → Add Channel → service: Gotify
3. Fill in Server URL and App Token
4. Click Test to verify, then Save
5. Attach to a Profile with the desired events

### 9.5 Setting up Pushbullet

1. Generate an API key at pushbullet.com (Settings → Account)
2. Settings → Notifications → Channels → Add Channel → service: Pushbullet
3. Enter your API Key
4. Click Test, then Save
5. Attach to a Profile

### 9.6 Setting up Webhooks

1. Settings → Notifications → Channels → Add Channel → service: Webhook
2. Enter the full endpoint URL
3. Optionally set custom headers or a secret for HMAC signing
4. The payload is a JSON object with event type, device details (name, IP, MAC), and timestamp

### 9.7 Setting up Home Assistant (direct notifications)

1. In Home Assistant, create a long-lived access token: Profile → Long-lived access tokens → Create token
2. Settings → Notifications → Channels → Add Channel → service: Home Assistant
3. Fill in: Host (HA hostname or IP), Port (default 8123), Access Token
4. Optionally enable Secure (HTTPS) for remote HA instances
5. Optionally set Notifier — defaults to `persistent_notification/create` (always available). Set to `notify/mobile_app_YOURPHONE` to send to a mobile app, or any other `domain/service` path.
6. Click Test — a test notification appears in HA's persistent notifications
7. Attach to a Profile

### 9.8 Home Assistant MQTT Auto-Discovery

InSpectre can publish device state to Home Assistant via MQTT using the standard Auto-Discovery protocol. This allows HA to automatically create entities for each network device and the InSpectre system. See [Section 13 — Home Assistant MQTT Integration](#13-home-assistant-mqtt-integration) for full configuration details.

### 9.9 MQTT Auto-Discovery (Home Assistant)

Configure the MQTT integration in **Settings → Home Assistant**. Once connected, Home Assistant will automatically discover InSpectre entities including presence sensors, new-device binary sensors, IP address, open ports, and vulnerability level for each device. See [Section 13 — Home Assistant MQTT Integration](#13-home-assistant-mqtt-integration) for full details.

---

## 10. Settings Reference

Access settings via the gear icon in the main navigation bar. Settings are organised into six tabs: Scanner, Notifications, Home Assistant, Docker, Data, and Admin.

### 10.1 Scanner Settings

| Setting | Description |
|---|---|
| **Scan Interval** | How often the probe runs a full ARP sweep, in seconds. Default: 60. Lower values give faster detection but increase network traffic. |
| **IP Range** | The CIDR range to scan. Should match your LAN subnet. Example: `192.168.1.0/24`. |
| **Interface** | The network interface the probe uses for scanning and sniffing. Example: `eth0`. |
| **LAN DNS Server** | The DNS server used for hostname resolution. Typically your router's IP. |
| **Nmap Arguments** | Additional arguments passed to nmap for port scans. Default is a SYN scan of common ports. Example: `-sS -p 1-1024 --open -T4`. |
| **Nightly Scan Window — Start** | Time of day (24h format) when the nightly scheduled scan window begins. Example: `02:00`. |
| **Nightly Scan Window — End** | Time of day when the nightly scan window ends. Example: `04:00`. |
| **Baseline Confirmation** | When enabled, port changes require manual confirmation before the new port set becomes the baseline. When disabled, baselines update automatically after each scan. |
| **Auto-scan new devices** | When enabled, a vulnerability scan is triggered automatically the first time a new device is discovered. |
| **Nuclei Template Update Interval** | How often Nuclei templates are refreshed from the upstream template repository, in hours. Default: 24. |
| **Fingerbank API Key** | Free API key from [fingerbank.org](https://fingerbank.org/). When set, DHCP fingerprint data is sent to Fingerbank for cloud device identification. Leave blank to disable. Results appear in the DHCP Fingerprint section of each device drawer. |
| **Auto-group by Hostname** | When enabled, devices that share the same base hostname (ignoring domain suffixes and case) are automatically grouped as a single physical device with multiple interfaces. A periodic self-healing pass merges matches discovered at any time. Disable to manage grouping manually (a suggestion event is written instead of merging). |
| **Scan grouped members** | When enabled, every interface IP in a device group is port- and vulnerability-scanned. When disabled (default), only the group's primary interface is scanned, since grouped interfaces belong to the same physical host. |
| **Primary IP Mode** | Controls how the probe updates a device's primary IP for multi-homed hosts. `locked` (default) respects the per-device IP pin — pinned devices never have their primary auto-changed. `dynamic` always adopts the current IP as primary when a device returns from offline. |
| **Offline miss threshold** | Number of consecutive missed sweeps before a device is marked offline. Default: 3. Raise it to reduce false-offline flapping on flaky networks. |
| **Offline rescan hours** | How long a device must have been offline before a port/service rescan is triggered when it reconnects. Default: 24. |

### 10.2 Notification Settings

| Setting | Description |
|---|---|
| **Toast Notifications** | Enable/disable in-app toast popups. |
| **Browser Notifications** | Enable/disable OS-level browser push notifications. |
| **Alert on new device** | Fire an alert when a new device joins the network. |
| **Alert on device offline** | Fire an alert when any device goes offline. |
| **Alert on watched offline** | Fire an alert when a watched device goes offline. |
| **Alert on vulnerability** | Fire an alert when a vulnerability scan finds issues. |
| **Alert on port change** | Fire an alert when a device's open ports change. |
| **Pushbullet API Key** | Your Pushbullet access token. |
| **Pushbullet Notifications** | Enable/disable Pushbullet as a notification channel. |
| **ntfy Server URL** | Base URL of your ntfy server. Default: `https://ntfy.sh`. |
| **ntfy Topic** | The ntfy topic name to publish alerts to. |
| **ntfy Notifications** | Enable/disable ntfy as a notification channel. |
| **Gotify URL** | Base URL of your Gotify server (e.g., `http://192.168.1.50:8080`). |
| **Gotify App Token** | The app token generated in the Gotify admin interface. |
| **Gotify Notifications** | Enable/disable Gotify as a notification channel. |
| **Webhook URL** | The HTTP endpoint that receives webhook POST payloads. |
| **Webhook Notifications** | Enable/disable outbound webhooks. |

### 10.3 Data Settings

| Setting | Description |
|---|---|
| **Backup password** | Optional password used to encrypt the backup file (AES-256-GCM). Leave blank for an unencrypted `.json` backup. When set, the backup saves as `.ienc` and cannot be restored without the same password. |
| **Download backup** | Export the full database as a JSON (unencrypted) or `.ienc` (encrypted) backup file covering all devices, events, vuln reports, speed test history, settings, users, fingerprints, block schedules, and saved views. |
| **Restore from backup** | Import a previously exported backup file (`.json` or `.ienc`). If restoring an encrypted backup, enter the password in the backup password field first. |
| **Export devices CSV** | Download a CSV file of all devices and their current metadata. |
| **Import fingerprints** | Import a fingerprint database JSON file to augment the local classification database. |
| **Export fingerprints** | Export the current local fingerprint database as a JSON file. |

### 10.4 Home Assistant Settings

Configure the MQTT-based Home Assistant integration in **Settings → Home Assistant**.

| Setting | Description |
|---|---|
| **Enable HA Integration** | Master toggle to enable or disable the Home Assistant MQTT integration. |
| **Broker Host** | IP or hostname of your MQTT broker (e.g. `192.168.1.10` or `mosquitto`). |
| **Broker Port** | TCP port of the MQTT broker. Default: 1883 (or 8883 for TLS). |
| **Username** | MQTT broker username. Leave blank if the broker allows anonymous connections. |
| **Password** | MQTT broker password. Leave blank if anonymous. |
| **Discovery Prefix** | MQTT topic prefix Home Assistant listens on for auto-discovery messages. Default: `homeassistant`. Must match your HA MQTT integration configuration. |
| **State Prefix** | Topic prefix InSpectre uses for state messages. Default: `inspectre`. |

Click **Save & Connect** to apply changes and connect immediately. The status indicator on the page shows Connected / Disconnected.

### 10.5 Admin Settings

Administrative settings are in **Settings → Admin**.

| Setting | Description |
|---|---|
| **UI Style** | Choose between **Spectre** (modern, rounded, teal accent) and **Phantom** (terminal-style, JetBrains Mono, green-on-black). |
| **Change Password** | Update your admin account password. Enter your current password and a new password (minimum 8 characters). |

---

## 11. Data Management

### 11.1 Backup and Restore

InSpectre's built-in backup covers the complete database state. A backup taken from a running system can be restored to a fresh install and produce an identical result — all data, settings, users, and history included.

**What is included in a backup:**

| Data | Included |
|---|---|
| All device records (names, tags, notes, overrides, baselines, groupings) | Yes |
| Full event timeline (`device_events`) | Yes |
| Vulnerability scan reports | Yes |
| IP history | Yes |
| Speed test history | Yes |
| All settings | Yes |
| User accounts and password hashes | Yes |
| Fingerprint database | Yes |
| Block schedules | Yes |
| Saved filter views | Yes |
| Alert suppressions | Yes |
| Traffic session data | No (ephemeral) |

**Taking a backup:**

1. Go to **Settings → Data → Database Backup & Restore**.
2. Optionally enter a **backup password** to encrypt the file (leave blank for an unencrypted `.json` file).
3. Click **Download backup** — the file saves as `inspectre_backup.json` (unencrypted) or `inspectre_backup.ienc` (encrypted).

**Encryption:**

When a password is provided, the backup is encrypted with AES-256-GCM. The password is not stored anywhere — you must remember it to restore the backup. Any password can be used; it does not have to match your InSpectre login password.

> If you lose the password to an encrypted backup, the backup cannot be decrypted. Keep the password in a secure password manager alongside the backup file.

**Restoring a backup:**

*From within the settings panel (existing install):*
1. Go to **Settings → Data → Database Backup & Restore**.
2. If restoring an encrypted backup, enter the password in the backup password field first.
3. Click **Restore from backup** and select the `.json` or `.ienc` file.
4. A success summary shows the number of records restored by type.

> Restoring merges data into the existing database using upsert logic — it does not wipe first. Existing records are overwritten by the backup values. Run a fresh backup of the current state before restoring if you want to preserve it.

*From the setup wizard (fresh install):*
1. At the start of the setup wizard, choose **Restore from backup** instead of **Fresh setup**.
2. If the backup is encrypted, enter the password in the field shown before selecting the file.
3. Select the backup file — setup is marked complete automatically after restore.

**Directory-level backup (advanced):**

As an alternative to the JSON backup, you can copy the `postgres_data/` directory directly:
```bash
./inspectre.sh down
cp -r postgres_data/ postgres_data.backup/
./inspectre.sh up
```
To restore, replace `postgres_data/` with your copy and start the stack. This preserves everything including tables not covered by the JSON backup (such as in-flight traffic sessions), but the file is not portable across major PostgreSQL version changes.

**Rebuilding without losing data:**
```bash
./inspectre.sh rebuild keep-data
```
This rebuilds all containers from source while preserving the database. Use this after pulling code changes.

### 11.2 CSV Export

**Settings → Data → Export devices CSV** downloads a comma-separated file containing:
- IP address
- MAC address
- Hostname
- Custom name
- Vendor
- Device type
- Tags
- Location
- Zone
- Open ports
- Vulnerability severity
- First seen
- Last seen

This is useful for importing into a spreadsheet, generating reports, or feeding into another tool.

### 11.3 Fingerprint Database

The fingerprint database is a local table of OUI prefix + open port pattern → device type mappings. It is used to automatically classify devices without requiring manual intervention.

**Sources:**
- `manual` — created when you set a device type override in the Admin tab
- `community` — imported from a shared fingerprint file
- `auto` — created by automatic pattern matching during scans

**Exporting fingerprints:**
Go to **Settings → Data → Export fingerprints**. This downloads a JSON file of all fingerprint entries, which you can share with others or use as a backup.

**Importing fingerprints:**
Go to **Settings → Data → Import fingerprints** and upload a fingerprint JSON file. Imported entries are added as `community` source and do not overwrite existing `manual` entries.

**How matching works:**
When a new device is scanned, the probe scores all fingerprint candidates:
- OUI prefix match: **3 points**
- Each matching open port: **1 point per port**

The highest-scoring fingerprint above a minimum threshold determines the automatically assigned device type.

---

## 12. Container Monitoring

### 12.1 Overview

InSpectre can connect to one or more container hosts — local or remote Docker daemons, and Proxmox VE nodes — and display all their containers in a unified **Containers** page. Each container host is configured independently and can be enabled or disabled at any time. You can have any mix of Docker and Proxmox hosts active simultaneously.

Container monitoring features include:
- Viewing all running and stopped containers across all configured hosts
- Starting, stopping, and restarting containers
- Streaming live container logs (Docker only)
- Scanning container images for known CVEs using Trivy (Docker only)
- Monitoring Proxmox LXC containers with VMID, node, and resource data

### 12.2 Adding Container Hosts

Container hosts are managed in **Settings → Docker → Container Hosts**.

Click **Add Host** to open the host form. Fill in the required fields (which vary by host type — see below) and click **Add Host** to save.

Each configured host appears as a row with:
- An **enable/disable toggle** — at least one host must be enabled for the Containers page to work
- A **connection test** button (the wifi icon) — sends a test connection to verify credentials
- **Edit** and **Remove** buttons

You can add as many hosts as needed. During the first-run setup wizard, there is an optional step to add your first container host.

### 12.3 Connecting to Docker (Local)

Use **Docker — Local socket** for a Docker daemon running on the same machine as InSpectre (the most common setup for home servers).

**Requirements:**
- The Docker socket must be mounted into the InSpectre backend container. The default `docker-compose.yml` includes this mount:
  ```yaml
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock
  ```

**Configuration:**

| Field | Value |
|---|---|
| Display Name | Any friendly name, e.g. `Home Server` |
| Host Type | Docker — Local socket |
| Socket Path | `unix:///var/run/docker.sock` (default) |

No authentication is required for local socket connections.

### 12.4 Connecting to Docker (Remote TCP)

Use **Docker — Remote TCP** to connect to a Docker daemon on another machine via the Docker TCP API.

**Requirements on the remote host:**
- The Docker daemon must be configured to listen on a TCP port. This is typically done by adding `-H tcp://0.0.0.0:2375` to the Docker daemon options (`/etc/docker/daemon.json` or the systemd unit file).

> **Security note:** Docker's TCP API with no TLS is only appropriate on a trusted private LAN. For remote access over an untrusted network, enable TLS on the Docker daemon and turn on **Verify TLS** in InSpectre.

**Configuration:**

| Field | Value |
|---|---|
| Display Name | Any friendly name, e.g. `NAS Docker` |
| Host Type | Docker — Remote TCP |
| Docker TCP URL | `tcp://192.168.1.x:2375` |
| Verify TLS | Disable for self-signed certs on trusted LANs; enable for production |

### 12.5 Connecting to Proxmox VE

Use **Proxmox VE** to connect to a Proxmox node and monitor its LXC containers.

**Authentication:** InSpectre uses Proxmox API Tokens (not username/password). API tokens are created in the Proxmox web UI.

**Creating a Proxmox API token:**

1. Log into your Proxmox web UI.
2. Go to **Datacenter → Permissions → API Tokens**.
3. Click **Add**.
4. Select the user (e.g., `root@pam`), give the token an ID (e.g., `inspectre`), and optionally check **Privilege Separation** if you want to restrict what the token can do.
5. Click **Add** — the token secret is shown once. Copy it.

The token format InSpectre expects is `TOKENID=SECRET` — for example: `inspectre=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.

**Minimum required permissions for the token:**
- `VM.Audit` on the relevant nodes/VMs (read-only monitoring)
- `VM.PowerMgmt` if you want to start/stop/restart containers from InSpectre

**Configuration:**

| Field | Value |
|---|---|
| Display Name | Any friendly name, e.g. `Proxmox Node` |
| Host Type | Proxmox VE |
| Proxmox URL | `https://192.168.1.x:8006` |
| API User | The Proxmox user the token belongs to, e.g. `root@pam` |
| API Token | The token in `TOKENID=SECRET` format |
| Default Node | The Proxmox node name to query (e.g. `pve`). Found in the Proxmox web UI left panel. |
| Verify TLS | Disable for self-signed certs (common on home Proxmox installs) |

> **Note:** Proxmox container log streaming and Trivy image scanning are not available for Proxmox LXC containers. These tabs are hidden in the container drawer for Proxmox containers.

### 12.6 Containers Page

The **Containers** page is accessible from the main navigation bar (the box/cube icon). It shows all containers from all enabled hosts.

**Toolbar:**
- **Search** — filter by container name, image, network, or short ID
- **Status filter chips** — All, Running, Stopped, Paused, Restarting
- **Host filter chips** — when more than one host is configured, per-host filter chips appear to narrow the list to containers from a specific host
- **Layout toggle** — grid view (cards) or list view (compact table)
- **Refresh** — manually reload all container data (auto-refreshes every 15 seconds)

**Stat cards** at the top show total, running, stopped, and other container counts. Click a stat card to filter by that status.

**Container cards** (grid view) show:
- Container name and status colour
- Image name
- Short ID
- Port bindings, networks, and restart policy
- Host name (bottom-left of the card footer)
- Time since started or stopped

**Container rows** (list view) show name, status, image, port bindings, networks, host name, and uptime.

### 12.7 Container Drawer

Click any container to open its detail drawer. The drawer has up to four tabs depending on the host type:

**Overview tab** (all containers):
- Status badge and restart policy
- Container ID, image, platform, hostname
- Host name and (for Proxmox) node and VMID
- Port bindings with direct-open links for HTTP/HTTPS ports
- Networks, mounts, labels, and environment variables (secrets masked by default)

**Logs tab** (Docker only):
- Stream live logs from the container
- Select how many lines to tail (50, 100, 200, 500)
- Stop streaming with one click

**Vuln Scan tab** (Docker only):
- Scan the container image for CVEs using Trivy (see [Section 12.8](#128-container-vulnerability-scanning-trivy))

**Admin tab** (all containers):
- Start, stop, restart the container
- View the full command and image ID

### 12.8 Container Vulnerability Scanning (Trivy)

InSpectre uses [Trivy](https://github.com/aquasecurity/trivy) to scan Docker container images for known CVEs. Trivy scans the image (not the running container) against the NVD/OSV vulnerability database.

**Running a scan:**

1. Open a container's drawer.
2. Go to the **Vuln Scan** tab.
3. Click **Scan Image**.

Trivy progress messages stream in real time as the scan runs. When complete, results are displayed grouped by severity.

**Understanding results:**

Each CVE finding shows:
- **Severity badge** — Critical, High, Medium, Low, or Unknown
- **CVSS score** — numeric risk score (0–10) where available
- **CVE ID** — the CVE identifier (e.g., `CVE-2024-1234`), with a link to the NVD entry
- **Package** — the name of the affected package inside the image
- **Installed version** — the version currently in the image
- **Fixed in** — the version that resolves the issue (if a fix exists)
- **Target** — which layer or component of the image the finding is in

Click a finding to expand it for full details.

**Summary badges** show the count per severity at the top of the results when the scan is complete.

**Scan history:**

When InSpectre runs a Trivy auto-scan for a container image (triggered by scheduled scanning), the result is stored. The next time you open the Vuln Scan tab for that container, the last stored result is loaded automatically without needing to re-scan.

**Rescanning:**

Click **Re-scan** to run a fresh Trivy scan at any time. The previous result is replaced.

**Scheduled auto-scanning:**

Configure automatic Trivy scans in **Settings → Docker → Image Vulnerability Scanning**. You can set the scan interval and enable/disable auto-scanning of new containers.

### 12.9 Container Vulns in the Security Dashboard

The **Security Dashboard** (shield icon in the navigation bar) includes container image vulnerability data alongside network device vulnerability data.

The **Container Vulnerabilities** section at the bottom of the dashboard shows:
- Total container images scanned
- Total CVE count across all scanned images
- Count of clean (no findings) images
- CVE findings grouped by severity (Critical, High, Medium, Low) — click a severity group to expand the list of affected containers and their CVE counts
- Click a container name in the expanded list to jump directly to that container's Vuln Scan tab

---

## 13. Home Assistant MQTT Integration

### 13.1 Overview

InSpectre can publish device state to Home Assistant via MQTT using the standard Auto-Discovery protocol. HA automatically creates entities for:
- A **system device** (InSpectre System) with sensors: Devices Online, Total Vulnerabilities, Scan State, Last Scan Time
- A **per-client device** for every non-ignored network device, with sensors: Presence (binary, ON=online), New Device (binary, ON=new/unacknowledged), IP Address, Open Ports, Vulnerability Level

All entities appear under their respective devices in Home Assistant's device registry. You can use them in automations, dashboards, and alerts.

### 13.2 Requirements

- An MQTT broker reachable from both InSpectre and Home Assistant (e.g. Mosquitto add-on)
- Home Assistant with MQTT integration configured (Settings → Devices & Services → Add Integration → MQTT)

### 13.3 Configuration

Go to **Settings → Home Assistant** in InSpectre:

| Field | Description |
|---|---|
| Enable HA Integration | Master toggle |
| Broker Host | IP or hostname of your MQTT broker |
| Broker Port | Default 1883 (or 8883 for TLS) |
| Username / Password | MQTT broker credentials (leave blank if anonymous) |
| Discovery Prefix | MQTT topic prefix HA uses for auto-discovery (default: `homeassistant`) |
| State Prefix | Topic prefix for state messages (default: `inspectre`) |

Click **Save & Connect** to apply changes and connect immediately. The status indicator shows Connected / Disconnected.

### 13.4 Topic Structure

```
inspectre/system/status          LWT — "online" or "offline"
inspectre/system/total_devices   Number of online devices
inspectre/system/total_vulns     Total vulnerability count
inspectre/system/scan_state      "idle" or "scanning"
inspectre/system/last_scan       ISO timestamp of last scan

inspectre/clients/<mac>/presence        "ON" or "OFF"
inspectre/clients/<mac>/new             "ON" (new/unacknowledged) or "OFF"
inspectre/clients/<mac>/ip              Current IP address
inspectre/clients/<mac>/open_ports      Number of open TCP ports
inspectre/clients/<mac>/vulnerabilities Numeric severity (0=clean, 1=low, 2=medium, 3=high/critical)
```

MAC addresses use underscores: `aa_bb_cc_dd_ee_ff`.

### 13.5 The "New Device" Sensor

The `new` binary sensor is ON when a device is newly discovered and not yet acknowledged. Use it in HA automations to alert when a genuinely new device appears. When you acknowledge the device in InSpectre (card button or drawer), the sensor flips to OFF immediately via MQTT.

### 13.6 LWT (Last Will and Testament)

InSpectre publishes `online` to `inspectre/system/status` on connect and configures `offline` as the MQTT LWT. If InSpectre disconnects unexpectedly, HA receives `offline` automatically, allowing you to create an availability-based alert.

---

## 14. Troubleshooting

**The probe container is not connecting / backend shows probe as unreachable**

- Check that the probe container is running: `docker compose ps`
- Check probe logs: `./inspectre.sh logs` and look for errors from the `probe` service
- The probe auto-detects the network interface on startup. If it picked the wrong one, set **Settings → Scanner → Interface** to the correct interface name, or uncomment and set `INTERFACE` in the `probe:` environment block of `docker-compose.yml` and rebuild.
- The probe runs on host network mode and binds to port 8666. Make sure nothing else on the host is using that port.

**Devices are not appearing on the dashboard**

- Check **Settings → Scanner → IP Range** covers the subnet your devices are on. A common mistake is the wrong subnet (e.g., `10.0.0.0/24` when devices are on `192.168.1.0/24`). The probe auto-detects this on first start — if it got it wrong, update the setting and click **Apply**.
- Check that the host machine is on the same Layer 2 network segment as the devices you expect to see. ARP does not cross routers.
- Wait at least 60 seconds (one full scan cycle) after starting for the first results to appear.
- Check probe logs for ARP sweep errors: `./inspectre.sh logs`

**A known device is not being detected**

- Some devices, especially iOS and newer Android devices, use MAC address randomisation. A randomised MAC appears as a new unknown device. Check Settings → Scanner and look for "Use stable MAC" guidance for your device type (varies by OS).
- The device may be on a different VLAN or subnet not covered by `IP_RANGE`.
- Devices in deep sleep may not respond to ARP requests. Wait until the device wakes up.

**The Docker host itself (or its macvlan shim) shows as offline even though it's reachable**

- This is handled automatically: the probe shares the host's network namespace and now treats the host's own IP addresses (NIC, macvlan shims, bridges) as always present. A host does not ARP-reply for its own addresses, which previously caused a false offline.
- If you still see it after upgrading, run `./inspectre.sh rebuild keep-data` so the updated probe is deployed, then wait one scan cycle.

**A device's IP keeps "flapping" between two addresses / repeated `ip_change` events**

- This happens with multi-homed hosts that answer on more than one IP. InSpectre now pins a stable **primary IP** and records the others as secondary IPs without writing `ip_change` events.
- To force a specific address as primary, open the device drawer → **IP History** → **Set primary** on the address you want. This pins it permanently (see [3.13.1](#3131-primary-ip--multi-homed-hosts)).
- If a host has a real NIC plus a Docker **macvlan shim** with a different MAC, group them (auto-grouping does this by hostname) and pick the real NIC as the primary interface.

**Port scans are not running**

- Nmap must be installed in the probe container. It is included in the default Docker image. If you are using a custom image, ensure nmap is present.
- Check nmap arguments for syntax errors: **Settings → Scanner → Nmap Arguments**. An invalid argument will cause all scans to fail silently.
- Confirm the probe has the necessary network capabilities. It runs privileged by default in `docker-compose.yml` — do not remove the `privileged: true` or `NET_ADMIN` / `NET_RAW` capabilities.

**Vulnerability scans are failing or hanging**

- Nuclei must be installed in the probe container. Check the probe logs for Nuclei errors.
- Templates may not have been downloaded yet. Check logs for `nuclei template update` output on first run.
- The scan rate may be too high for slower devices. Reduce the rate limit in **Settings → Scanner → Nuclei rate limit**.
- Large networks with many services can cause scans to run for a long time. This is normal.

**Device blocking is not working**

- ARP MITM requires the probe to be on the same Layer 2 segment as the target device and the gateway. It will not work across VLANs or through managed switches with Dynamic ARP Inspection enabled.
- Check that the probe has `NET_ADMIN` and `NET_RAW` capabilities (set via `privileged: true` in `docker-compose.yml`).
- Verify the interface in **Settings → Scanner → Interface** is the correct LAN-facing interface. ARP spoofing must go out on the same interface as the target device.

**Notifications are not being received**

- Test each channel from the Settings panel after entering credentials.
- For Pushbullet: confirm the API key is correct and the Pushbullet app is installed and logged in on your phone.
- For ntfy: verify the server URL is reachable from the backend container and the topic name matches what you subscribed to in the app.
- For Gotify: confirm the Gotify server URL includes the correct port and is reachable from the backend container.
- For webhooks: check that the endpoint URL is reachable from within Docker (use the host machine's LAN IP, not `localhost`).

**The UI is not loading**

- Confirm the frontend container is running: `docker compose ps`
- Check that port 3000 is not blocked by a firewall on the host.
- Try `./inspectre.sh logs` for nginx or frontend build errors.

**After a `rebuild`, my data is gone**

- `./inspectre.sh rebuild` deletes `postgres_data/` and is intentionally destructive. Use `./inspectre.sh rebuild keep-data` to preserve the database, or take a JSON backup first via **Settings → Data → Backup database**.

**Fingerbank shows "API key rejected"**

- Verify the key in **Settings → Scanner → Device Identification → Fingerbank API Key** matches the key shown at [fingerbank.org](https://fingerbank.org/) under your account settings.
- Keys are case-sensitive. Copy-paste rather than typing by hand.

**DHCP Fingerprint section shows "No DHCP packet seen yet"**

- The probe only captures DHCP packets that are broadcast on the LAN. Unicast renewals mid-lease are not captured. Force a full DHCP cycle to generate a broadcast: Windows — `ipconfig /release` then `ipconfig /renew`; Linux — `sudo dhclient -r && sudo dhclient`.
- Ensure the probe is running on the same Layer 2 segment as the device.

**Fingerbank lookup is stuck as "pending" for a long time**

- The background loop runs every 60 seconds. Check the backend logs for `[fingerbank]` lines: `docker compose logs backend | grep fingerbank`.
- If no API key is configured, lookups never run. Add a key in **Settings → Scanner → Device Identification**.
- If the API key is valid but lookups still don't appear, check whether the backend container can reach the internet: `docker compose exec backend curl -s https://api.fingerbank.org/` should return JSON.

**The Containers page shows "No container hosts configured"**

- Go to **Settings → Docker → Container Hosts** and add at least one host.
- If you added a host but it still shows the disabled state, confirm the host's enabled toggle is on.
- For local Docker, ensure the socket is mounted in `docker-compose.yml` (see [Section 12.3](#123-connecting-to-docker-local)).

**Container host connection test fails**

- For local Docker: confirm `docker-compose.yml` mounts `/var/run/docker.sock` into the backend container. Rebuild the stack if you just added the mount.
- For remote Docker TCP: ensure the remote Docker daemon is listening on TCP (check daemon config) and the port is reachable from the InSpectre host.
- For Proxmox: confirm the URL, username, and API token are correct. Verify the token has at least `VM.Audit` permission. If the Proxmox node uses a self-signed certificate, disable **Verify TLS**.

**Trivy container scan says "no vulnerabilities" but later shows many**

- Trivy downloads its vulnerability database on first use and on each update interval. If the database was not yet downloaded when the scan ran, results will be empty. Wait a few minutes and re-scan.
- Check the backend container logs for Trivy database update messages: `docker compose logs backend`

**Logs tab or Vuln Scan tab is missing for a container**

- These tabs are only available for Docker containers. Proxmox LXC containers show only the Overview and Admin tabs.

**Home Assistant MQTT shows "Disconnected"**

- Verify the broker host and port are reachable from the InSpectre backend container. Use `docker compose exec backend ping <broker-host>` to test connectivity.
- Check broker credentials. Most Mosquitto installs require username/password even on LAN — check your broker's ACL/password file.
- Check that the HA MQTT integration is configured (Settings → Devices & Services → MQTT in Home Assistant).
- After fixing settings, click **Save & Connect** again or use `POST /ha-mqtt/reconnect` from the API.

**Home Assistant entities are not appearing after connecting**

- Wait 30–60 seconds after connecting — discovery messages are retained so HA should pick them up shortly after the MQTT integration sees them.
- Check that the Discovery Prefix matches what your HA MQTT integration is listening on (default: `homeassistant`).
- MQTT discovery messages are published with `retain=true`. Use an MQTT explorer tool to verify the topics are present on your broker.

**Home Assistant notification channel test returns 502**

- Verify the HA host URL is reachable from the backend container: `docker compose exec backend curl -k https://<ha-host>:<port>/api/`
- Confirm the long-lived access token is valid (it should return `{"message":"API running."}` from the above curl).
- The default notifier `persistent_notification/create` is always available. If you set a custom notifier (e.g. `notify/mobile_app_xxx`), ensure that integration is set up in HA.

---

## 15. FAQ

**Q: Does InSpectre send any data to the cloud?**

All scanning, storage, and processing happens within your local network and on your own hardware. The only outbound connections InSpectre makes are:
- Nuclei template updates (downloads from GitHub)
- Trivy vulnerability database updates (downloads from GitHub/ghcr.io, on a configurable interval)
- Notification payloads to external services you explicitly configure (Pushbullet, ntfy.sh, Gotify cloud, webhooks)
- Speed test measurements (to speedtest-cli servers, only when you click the speed test button)
- **Fingerbank lookups** — DHCP fingerprint data (option 55 list, vendor class, hostname, and MAC) is sent to [fingerbank.org](https://fingerbank.org/) only if you configure an API key. Disable by leaving the key blank.

**Q: Will scanning damage or disrupt my devices?**

ARP sweeps and standard nmap port scans are very lightweight and are not harmful to normal devices. They are standard network discovery techniques used by tools like nmap, Angry IP Scanner, and router admin dashboards. However:
- Aggressive nmap scan profiles (e.g., `-T5` or `-A`) generate more traffic and may trigger rate limiting on some routers or IoT devices.
- Vulnerability scanning (Nuclei) sends targeted probes to specific ports. This is safe on well-implemented services but may cause issues on very fragile or poorly-implemented embedded device web servers. Use the rate limit setting to be gentle.

**Q: Can I run InSpectre on a Raspberry Pi?**

Yes, with caveats. The Docker images are currently built for `linux/amd64`. For ARM-based hardware (Raspberry Pi 3, 4, 5), you would need to build the images for `linux/arm64` or `linux/arm/v7`. This is not officially tested but is possible.

**Q: How do I monitor multiple subnets?**

Currently, `IP_RANGE` accepts a single CIDR block. To monitor multiple subnets, you can set a supernet that encompasses all of them (e.g., `192.168.0.0/16` instead of `192.168.1.0/24`), though this increases scan time. Support for multiple IP ranges is a planned enhancement.

**Q: What happens if I change the IP Range after devices are already in the database?**

Existing device records are not deleted. The probe will simply stop seeing devices outside the new range (they will go offline) and will discover any new devices within the new range. Device history is preserved. Change the range in **Settings → Scanner → IP Range** and click **Apply**.

**Q: Can InSpectre block IoT devices from talking to each other (east-west blocking), not just from the internet?**

No. The current ARP MITM implementation blocks traffic between a device and the default gateway only. It does not prevent device-to-device communication on the LAN. For east-west isolation, VLAN segmentation at the router/switch level is required.

**Q: How accurate is the vulnerability scanning?**

Nuclei is a widely used, well-maintained scanner and its templates are generally reliable. However:
- False positives can occur, particularly with templates that match on version strings or banner text.
- False negatives are possible if a service does not respond in the way the template expects.
- Results should be treated as leads for further investigation rather than definitive proof of exploitability.

**Q: How do I update InSpectre?**

```bash
git pull
./inspectre.sh rebuild keep-data
```

This pulls the latest code and rebuilds the containers while preserving your database.

**Q: Is the web UI protected by authentication?**

Yes. InSpectre has built-in username and password authentication using JWT session tokens. You create your admin account during the first-run setup wizard. After that, every visit requires login.

For additional network-level protection (e.g., if you want to expose InSpectre beyond your LAN):
- Place it behind a reverse proxy (nginx, Caddy, Traefik) with HTTPS.
- Use a VPN to restrict access to the host rather than exposing port 3000 directly.

**Q: Where are the logs?**

```bash
./inspectre.sh logs
```

Or for a specific container:

```bash
docker compose logs -f probe
docker compose logs -f backend
docker compose logs -f frontend
```

**Q: How do I write my own plugin / integration?**

Plugins are single declarative manifest files (JSON or YAML) — no coding
required. Copy one of the templates in [`examples/plugins/`](examples/plugins/)
(start with `TEMPLATE.yaml`), adapt the endpoints and field mappings to your
device's API, and upload it via **Settings → Plugins → Upload Plugin**. The full
API reference is in the [Plugin Developer Guide](plugin.md).

---

## 16. Plugins

### Overview

InSpectre supports a plugin system that lets you integrate external services —
DNS servers, firewalls, controllers, DHCP sources — as additional device
discovery, enrichment, presence, and **blocking** sources.

Plugins are **declarative manifests** (a single JSON or YAML file): there is no
plugin code to write or run. You describe the HTTP / file / SNMP calls and how
to map their responses, and the InSpectre plugin engine performs them on a
schedule or in response to events. This keeps shared plugins safe — a manifest
can only make the calls it declares, using the credentials you enter.

The plugin engine is managed from **Settings → Plugins**.

### Built-in Plugins

Built-in plugins ship inside the InSpectre containers and are available
immediately after installation. They are maintained by the InSpectre project and
receive updates alongside the core application. Built-in plugins cannot be
removed, but individual ones can be enabled or disabled from the Plugins tab.

Built-in plugins include **AdGuard Home**, **Pi-hole**, **TP-Link Omada**,
**Home Assistant**, **OPNsense**, and **pfSense**. Their manifests live in
`backend/plugins/builtin/` and double as real-world examples.

### Community Plugins

Community plugins are created and maintained by third parties. They are
distributed as a single manifest file (`.json` or `.yaml`).

> ⚠️ **Security notice:** Community plugins are **not audited or vetted by the
> InSpectre project**. A plugin acts with the credentials you give it and can
> reach the services it declares. Only install plugins from sources you trust,
> and review the manifest (it is human-readable) before uploading.

### Installing a Community Plugin

1. Obtain the plugin manifest file (`.json` or `.yaml`) from the author.
2. Open InSpectre and navigate to **Settings → Plugins**.
3. Click **Upload Plugin**.
4. Select the manifest file and confirm the upload.
5. The plugin appears in the list with its name, version, and author.
6. Open it, fill in the config fields, and click **Test Connection**.
7. Toggle the plugin **Enabled** to activate it. Polling plugins begin on the
   next cycle; blocking plugins become selectable under **Settings → Security
   Responses → Blocking Method**.

### Removing a Plugin

1. Navigate to **Settings → Plugins**.
2. Find the plugin in the list and click the **Remove** (trash) icon.
3. Confirm the deletion. Uploaded plugins are removed immediately; removing one
   that overrode a built-in restores the built-in.

### Writing a Plugin

A plugin is a single manifest describing its capabilities, config fields,
endpoints, actions, event hooks, and (optionally) a polling schedule. Full
details — including authentication, dependency chains, response mapping, the
blocking contract, and event hooks — are in the
**[Plugin Developer Guide](plugin.md)** in the repository root.

To get started quickly, copy one of the ready-made examples in
[`examples/plugins/`](examples/plugins/):

- `TEMPLATE.yaml` — an annotated skeleton with every field explained inline.
- `hello-world.json` — a minimal discovery plugin (polls a JSON API for DHCP leases).
- `example-firewall.json` — a blocking plugin with a login→action auth chain.

---
