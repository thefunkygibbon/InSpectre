Absolutely — here’s a roadmap-style rewrite you can drop into `roadmap.md`.

## Roadmap ideas

InSpectre already has a strong base with device discovery, device metadata, event history, IP history, alert records, vulnerability reports, and a separate probe/backend/frontend architecture. The roadmap should now focus on turning that foundation into a more complete network visibility and lightweight security platform. 

## Alerting

### Notification delivery
Implement outbound alert delivery for key events such as new devices, devices going offline, devices coming back online, IP changes, and vulnerability findings. The existing `Alert` model already defines these alert types, so the next step is to deliver them through channels such as webhooks, ntfy, Gotify, Pushover, email, or similar notification targets. 

### Alert rules
Add configurable alert rules so alerts can be filtered by device tag, importance, location, device type, time window, or severity. This will allow the alerting system to evolve from fixed event generation into a policy-driven monitoring feature. 

## Device intelligence

### mDNS and local name enrichment
Expand discovery with mDNS and DNS-SD enrichment to improve hostname accuracy and identify devices that advertise service identities on the local network. This is especially relevant for Apple devices, smart home gear, printers, streaming devices, and other consumer hardware that often exposes useful broadcast metadata. 

### Service and version detection
Extend scan results to include detected services, banners, and version information in addition to open ports. The current data model already stores scan results and vulnerability findings, so richer service detection would improve identification, triage, and security usefulness. 

### Rogue identity detection
Add checks for suspicious identity mismatches such as vendor/OUI inconsistencies, unexpected hostname patterns, or devices presenting characteristics that conflict with their historical fingerprint. This would make InSpectre more useful as a network trust and anomaly detection tool. 

## Vulnerability management

### Scheduled vulnerability scanning
Introduce scheduled vulnerability scans for all devices, important devices, new devices, or selected tag groups. Vulnerability scanning already exists in the probe and the data model already stores scan history, findings, severity, and timestamps, so scheduled execution is a natural progression. 

### Scan policy profiles
Add reusable scan profiles such as safe, standard, deep, and recurring profiles with configurable Nmap arguments and scan scope. This would allow users to balance speed, network impact, and depth of analysis depending on device class or trust level. 

### Security dashboard
Create a dedicated vulnerability dashboard showing device risk distribution, recent findings, severity totals, and vulnerable device trends over time. The current `VulnReport` structure already provides the data needed to support this view. 

## Device management

### Groups and zones
Add first-class device grouping for zones such as Trusted, IoT, Guest, Lab, or Infrastructure. The current model already contains tags, notes, location, importance, and override fields, so a formal grouping layer would improve filtering, reporting, and policy application. 

### Ignore and suppress controls
Implement ignore lists and per-device suppression options for alerts, scans, and noise-heavy events. This would help reduce clutter from known devices while keeping the event stream useful. 

### Import and export
Add import/export support for device metadata, naming, notes, tags, and other user-maintained data. This would improve backup, restore, migration, and long-term usability of the platform. 

## Network history

### Device activity timeline
Introduce a richer historical timeline view for each device showing discovery, online/offline transitions, IP changes, scan completions, renames, tagging, and vulnerability scan activity. The `DeviceEvent` model already captures this kind of timeline-oriented data. 

### Uptime and availability metrics
Add per-device uptime summaries, offline duration tracking, and network presence statistics derived from device state changes over time. This would give the platform more operational value in addition to security visibility. 

### Historical network snapshots
Support a historical view of the network state at a given point in time, including which devices were online, which IPs they held, and what their known posture looked like then. Existing first-seen, last-seen, and IP history data provides the base for this feature. 

## Security detection

### ARP anomaly detection
Add detection for suspicious ARP behaviour such as rapid IP ownership changes, conflicting MAC/IP relationships, or duplicate claims. Since IP history is already tracked per device and the product already includes ARP-based internet blocking concepts, ARP anomaly monitoring is highly relevant. 

### Port change monitoring
Promote port change tracking into a surfaced security feature that highlights when a device suddenly exposes a new service or loses one unexpectedly. The event model already includes `port_change` as a device event type, making this a strong candidate for expansion. 

### Trust change detection
Track significant identity shifts over time, such as vendor change, hostname change, fingerprint confidence drops, device type shifts, or repeated IP churn. This would strengthen the product’s role as a network anomaly monitor rather than only a discovery scanner. 

## Multi-network support

### Multi-probe architecture
Expand the current separated probe/backend design into first-class multi-probe support so a single backend can monitor multiple VLANs, subnets, or physical locations. The current repository already separates probe and backend concerns, making this a sensible roadmap direction. 

### Probe-aware reporting
Add probe identity, probe assignment, and per-probe health/status views so device discovery can be traced back to the source collector. This will become increasingly important once multi-probe support is introduced. 

## Frontend improvements

### Dashboard refinement
Extend the frontend with dedicated dashboard views for device activity, security posture, alert trends, and network composition. The frontend already has a React application and device categorisation support, so the next stage is better visual surfacing of the data already being collected. 

### Advanced filtering and saved views
Add saved filters for tags, severity, online state, vendor, location, and device type, along with pinned views for common workflows. This would make the UI more usable once the dataset grows beyond a small home network. 

### Network map view
Introduce a network map or topology-inspired view showing devices by subnet, category, trust zone, or physical/logical grouping. The combination of MAC, IP, vendor, fingerprint, device type, and event history makes this a strong fit for the product. 

## Platform and usability

### Live probe configuration
Complete the loop between backend settings and probe behaviour so saved configuration changes can be applied without manual rework. The presence of a `Setting` model suggests the groundwork is already in place for broader runtime configurability. 

### Role and access controls
Add optional authentication and role-based access controls for deployments where multiple users may access the UI. This becomes more relevant as InSpectre grows from a single-user tool into a shared monitoring platform. 

### Backup and restore
Provide a formal backup and restore workflow covering database contents, user settings, and user-maintained device metadata. This would make the platform safer to run long-term and easier to upgrade or move. 

If you want, I can turn that into a cleaner **actual `roadmap.md` markdown file** with sections like **Now / Next / Later** or **Phase 1 / Phase 2 / Phase 3**.
