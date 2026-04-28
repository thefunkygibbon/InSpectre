# InSpectre — User Documentation

## Table of Contents

1. [Getting Started](#1-getting-started)
   - 1.1 [Requirements](#11-requirements)
   - 1.2 [Installation](#12-installation)
   - 1.3 [First Run](#13-first-run)
   - 1.4 [Accessing the UI](#14-accessing-the-ui)
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
   - 9.1 [Toast Notifications](#91-toast-notifications)
   - 9.2 [Browser Notifications](#92-browser-notifications)
   - 9.3 [Pushbullet](#93-pushbullet)
   - 9.4 [ntfy](#94-ntfy)
   - 9.5 [Gotify](#95-gotify)
   - 9.6 [Webhooks](#96-webhooks)
   - 9.7 [Alert Triggers](#97-alert-triggers)
10. [Settings Reference](#10-settings-reference)
    - 10.1 [Scanner Settings](#101-scanner-settings)
    - 10.2 [Notification Settings](#102-notification-settings)
    - 10.3 [Data Settings](#103-data-settings)
11. [Data Management](#11-data-management)
    - 11.1 [Backup and Restore](#111-backup-and-restore)
    - 11.2 [CSV Export](#112-csv-export)
    - 11.3 [Fingerprint Database](#113-fingerprint-database)
12. [Troubleshooting](#12-troubleshooting)
13. [FAQ](#13-faq)

---

## 1. Getting Started

### 1.1 Requirements

- **Docker** 24 or later
- **Docker Compose** v2 (included with modern Docker Desktop and Docker Engine installs)
- A Linux host (the probe container requires raw network access and runs on the host network stack)
- The host machine must be connected to the LAN you want to monitor

### 1.2 Installation

Clone the repository and configure the required environment variables before starting:

```bash
git clone https://github.com/thefunkygibbon/InSpectre.git
cd InSpectre
```

Open `docker-compose.yml` and set these three variables to match your network:

| Variable | What to put here |
|---|---|
| `IP_RANGE` | The CIDR range of your LAN, e.g. `192.168.1.0/24` |
| `INTERFACE` | The network interface the host uses to reach the LAN, e.g. `eth0` or `enp3s0`. Run `ip link` or `ifconfig` to find it. |
| `LAN_DNS_SERVER` | Your local DNS server or router IP, e.g. `192.168.1.1`. Used for hostname resolution. |

### 1.3 First Run

Use the `inspectre.sh` helper script to start the stack:

```bash
./inspectre.sh up
```

This builds all three containers and starts them in the background. On first run, the database schema is created automatically — you do not need to run any migrations manually.

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

The UI is a single-page React application. There is no login screen by default — access control is managed at the network or reverse-proxy level if required.

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
| Not vuln scanned | Have never had a vulnerability scan |
| Blocked | Are currently blocked from the internet |
| Has notes | Have a non-empty notes field |
| Tagged | Have at least one tag assigned |
| Ignored | Are flagged as ignored (hidden by default — enable this filter to see them) |

**Saved views** — While one or more filters are active, a **Save View** button appears. Click it to name and save the current filter combination. Saved views appear in the filter bar for instant recall.

### 3.3 Device Drawer — Overview Tab

Click any device card or row to open the device drawer. The **Overview** tab is the default view.

It shows:
- **Status badge** — Online / Offline, with time since last seen
- **Block status** — Blocked badge if the device is currently ARP-blocked
- **Vulnerability severity badge** — highest severity across all current findings (Critical, High, Medium, Low, or Clean)
- **IP address** — current IP, with copy button
- **MAC address** — with copy button
- **Vendor** — resolved from OUI database; shows override if set
- **Hostname** — resolved name, or blank
- **Operating system** — from nmap OS detection, if available
- **Open ports** — list of open TCP ports with service names and version info where known
- **Last seen / First seen** timestamps

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

### 4.2 OS Detection

nmap's OS fingerprinting (`-O` flag, enabled by default) probes open ports to make an educated guess at the device's operating system. Results are stored and shown in the Overview tab.

OS detection accuracy varies and is sometimes wrong, especially for IoT devices or devices that limit ICMP/TCP responses. Manual device type overrides in the Admin tab always take precedence in the UI.

### 4.3 Service Fingerprinting

InSpectre uses **Nerva** service fingerprinting on top of nmap's `-sV` (version detection) results to match open ports and detected services against known product signatures.

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

The **Speed Test** panel in the Traffic Monitor view runs `speedtest-cli` from the probe container and reports:
- Download speed (Mbps)
- Upload speed (Mbps)
- Ping latency (ms)
- Test server used

Results reflect the speed available to the InSpectre host, not to any specific client device. This is useful as a baseline to confirm whether your ISP is delivering the expected bandwidth.

**Scheduling:** Use the **Auto-run** dropdown in the speed test panel to schedule automatic tests at a fixed interval (every 30 minutes, hourly, every 6 hours, or daily). Results are stored and displayed in the history list below the panel. The schedule persists across restarts.

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

InSpectre supports multiple notification channels. All channels are configured in **Settings → Notifications**. Channels can be enabled/disabled independently; multiple channels can be active at the same time.

### 9.1 Toast Notifications

In-app popup notifications shown in the bottom-right corner of the UI. Always active — no configuration required.

Toasts are shown for:
- New devices joining the network
- Watched devices going offline
- Completed scan results
- Blocking/unblocking actions

Toasts automatically dismiss after a few seconds.

### 9.2 Browser Notifications

Operating system-level push notifications sent via the Web Notifications API. Requires the browser to grant notification permission when prompted.

Enable in **Settings → Notifications → Browser Notifications**. You will be prompted to grant permission if you haven't already.

Browser notifications appear even if the InSpectre browser tab is in the background or minimised.

### 9.3 Pushbullet

[Pushbullet](https://www.pushbullet.com/) delivers notifications to your phone, tablet, or other browsers.

**Setup:**
1. Create a Pushbullet account and install the app on your phone.
2. Generate an API key at https://www.pushbullet.com/#settings/account.
3. In InSpectre: **Settings → Notifications → Pushbullet API Key** — paste your key.
4. Enable **Pushbullet Notifications**.

### 9.4 ntfy

[ntfy](https://ntfy.sh/) is an open-source push notification service that can be self-hosted.

**Setup:**
1. Choose a topic name (any string, e.g., `inspectre-alerts`).
2. Subscribe to the topic in the ntfy app on your phone.
3. In InSpectre: **Settings → Notifications → ntfy Server URL** (e.g., `https://ntfy.sh` or your self-hosted URL) and **ntfy Topic**.
4. Enable **ntfy Notifications**.

### 9.5 Gotify

[Gotify](https://gotify.net/) is a self-hosted push notification server.

**Setup:**
1. Set up a Gotify server and create an application to get an app token.
2. In InSpectre: **Settings → Notifications → Gotify URL** and **Gotify App Token**.
3. Enable **Gotify Notifications**.

### 9.6 Webhooks

InSpectre can POST a JSON payload to any HTTP endpoint when an alert fires. This allows integration with any system that accepts webhooks (Slack, Discord, Home Assistant, n8n, Zapier, etc.).

**Setup:**
1. In InSpectre: **Settings → Notifications → Webhook URL** — enter the full endpoint URL.
2. Enable **Webhook Notifications**.

The webhook payload is a JSON object containing the alert type, device details (name, IP, MAC), and timestamp.

### 9.7 Alert Triggers

The following events can trigger notifications. Each trigger can be independently enabled or disabled in Settings → Notifications:

| Trigger | Description |
|---|---|
| **New device joined** | A MAC address is seen on the network for the first time |
| **Device offline** | A previously online device stops responding |
| **Watched device offline** | An offline alert specifically for watched/starred devices (can be configured separately for higher priority) |
| **Vulnerability found** | A nuclei scan returns one or more findings |
| **Port change / drift** | A device's open ports differ from its last confirmed baseline |
| **Device blocked** | A device block is applied (manually or by schedule) |
| **Device unblocked** | A device block is removed |

---

## 10. Settings Reference

Access settings via the gear icon in the main navigation bar. Settings are organised into three tabs.

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
| **Backup database** | Export the full database as a JSON file for backup. |
| **Restore database** | Import a previously exported JSON backup. Replaces current data. |
| **Export devices CSV** | Download a CSV file of all devices and their current metadata. |
| **Import fingerprints** | Import a fingerprint database JSON file to augment the local classification database. |
| **Export fingerprints** | Export the current local fingerprint database as a JSON file. |

---

## 11. Data Management

### 11.1 Backup and Restore

InSpectre stores all data in a PostgreSQL database in the `postgres_data/` directory on the host. Two backup approaches are available:

**JSON backup (recommended for portability):**
- Go to **Settings → Data → Backup database**.
- A JSON file is downloaded containing all devices, events, vulnerability reports, fingerprints, and settings.
- To restore: **Settings → Data → Restore database** and upload the JSON file.

> Restoring from a JSON backup replaces all current data. Make sure to take a fresh backup before restoring.

**Directory backup (for self-hosters):**
- Stop InSpectre: `./inspectre.sh down`
- Copy the `postgres_data/` directory to a safe location.
- To restore: replace `postgres_data/` with the backup copy and run `./inspectre.sh up`.

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

## 12. Troubleshooting

**The probe container is not connecting / backend shows probe as unreachable**

- Check that the probe container is running: `docker compose ps`
- Check probe logs: `./inspectre.sh logs` and look for errors from the `probe` service
- Verify the `INTERFACE` variable in `docker-compose.yml` matches an interface that actually exists on the host. Run `ip link` to list available interfaces.
- The probe runs on host network mode and binds to port 8666. Make sure nothing else on the host is using that port.

**Devices are not appearing on the dashboard**

- Confirm `IP_RANGE` in `docker-compose.yml` covers the subnet your devices are on. A common mistake is using the wrong subnet (e.g., `10.0.0.0/24` when devices are on `192.168.1.0/24`).
- Check that the host machine is on the same Layer 2 network segment as the devices you expect to see. ARP does not cross routers.
- Wait at least 60 seconds (one full scan cycle) after starting for the first results to appear.
- Check probe logs for ARP sweep errors: `./inspectre.sh logs`

**A known device is not being detected**

- Some devices, especially iOS and newer Android devices, use MAC address randomisation. A randomised MAC appears as a new unknown device. Check Settings → Scanner and look for "Use stable MAC" guidance for your device type (varies by OS).
- The device may be on a different VLAN or subnet not covered by `IP_RANGE`.
- Devices in deep sleep may not respond to ARP requests. Wait until the device wakes up.

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
- Verify the `INTERFACE` setting is correct. ARP spoofing must go out on the same interface as the target device.

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

---

## 13. FAQ

**Q: Does InSpectre send any data to the cloud?**

No. All scanning, storage, and processing happens entirely within your local network and on your own hardware. The only outbound connections InSpectre makes are:
- Nuclei template updates (downloads from GitHub)
- Notification payloads to external services you explicitly configure (Pushbullet, ntfy.sh, Gotify cloud, webhooks)
- Speed test measurements (to speedtest-cli servers, only when you click the speed test button)

**Q: Will scanning damage or disrupt my devices?**

ARP sweeps and standard nmap port scans are very lightweight and are not harmful to normal devices. They are standard network discovery techniques used by tools like nmap, Angry IP Scanner, and router admin dashboards. However:
- Aggressive nmap scan profiles (e.g., `-T5` or `-A`) generate more traffic and may trigger rate limiting on some routers or IoT devices.
- Vulnerability scanning (Nuclei) sends targeted probes to specific ports. This is safe on well-implemented services but may cause issues on very fragile or poorly-implemented embedded device web servers. Use the rate limit setting to be gentle.

**Q: Can I run InSpectre on a Raspberry Pi?**

Yes, with caveats. The Docker images are currently built for `linux/amd64`. For ARM-based hardware (Raspberry Pi 3, 4, 5), you would need to build the images for `linux/arm64` or `linux/arm/v7`. This is not officially tested but is possible.

**Q: How do I monitor multiple subnets?**

Currently, `IP_RANGE` accepts a single CIDR block. To monitor multiple subnets, you can set a supernet that encompasses all of them (e.g., `192.168.0.0/16` instead of `192.168.1.0/24`), though this increases scan time. Support for multiple IP ranges is a planned enhancement.

**Q: What happens if I change `IP_RANGE` after devices are already in the database?**

Existing device records are not deleted. The probe will simply stop seeing devices outside the new range (they will go offline) and will discover any new devices within the new range. Device history is preserved.

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

**Q: Can I add authentication to the web UI?**

InSpectre does not include built-in authentication. Recommended approaches:
- Run it on a machine that is not accessible from outside your LAN (the typical home setup).
- Place it behind a reverse proxy (nginx, Caddy, Traefik) with HTTP Basic Auth or SSO.
- Use a VPN to restrict access to the host.

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
