OFFLINE_RESCAN_HOURS = number to be a setting



# InSpectre Roadmap

InSpectre already has a solid foundation across probe, backend, and frontend components, with support for device discovery, metadata, event history, IP history, alert records, vulnerability reporting, fingerprinting, and user-maintained device context. This roadmap breaks the next stage of work into smaller batches so features can be delivered incrementally without losing product direction.

## Upcoming

### Alert delivery
Add outbound notification delivery for important alert types including new devices, devices going offline, devices returning online, IP changes, and vulnerability findings. The existing `Alert` model already provides the event foundation, so this phase should focus on dispatch integrations such as webhooks, ntfy, Gotify, Pushover, or email targets.

### Scheduled vulnerability scanning
Introduce scheduled vulnerability scans for all devices, important devices, new devices, or selected groups. The probe already includes vulnerability scanning logic and the data model already stores scan timestamps, severity, findings, and raw output, which makes recurring scans a natural next step.

### Port change monitoring
Implement reliable detection and surfacing of port changes so that newly exposed or removed services generate useful history and alert signals. This aligns with the existing event model, which already defines `port_change` as a device event type.

### Advanced filtering and saved views
Expand the frontend with better filtering by online state, vendor, tag, severity, device type, and location, then allow saved views for common workflows. This is a high-value usability improvement because the current data model already supports rich filtering dimensions.

### Live settings application
Complete the path between stored backend settings and actual runtime probe behaviour so configuration changes can be applied more cleanly. The existing `Setting` model provides the base for this work, but the roadmap item is to make those settings operationally meaningful across the stack.

## Next

### Device grouping and zones
Promote device organisation into first-class groups such as Trusted, IoT, Guest, Lab, Infrastructure, and other user-defined zones. Existing fields including tags, notes, location, importance, and override values already provide the raw structure needed for group-based filtering, policy assignment, and reporting.

### mDNS and local identity enrichment
Add mDNS and DNS-SD enrichment so local devices can be identified more accurately through broadcast service announcements. This should improve visibility for Apple devices, printers, smart home hardware, streaming devices, and other consumer gear that often exposes useful local metadata.

### Service and version detection
Extend scans beyond open port presence to include service names, banners, and version information. This will improve both device identification and vulnerability triage by making scan results more meaningful than a simple port list.

### Vulnerability dashboard
Create a dedicated security dashboard showing risk distribution, recent findings, severity trends, and the most exposed devices. The current `VulnReport` model already contains the data needed to support this view.

### Ignore and suppression controls
Add per-device and per-alert suppression controls to reduce noise from known or intentionally ignored devices. This will keep the event and alert stream useful as the number of monitored devices increases.

## Later

### Multi-probe support
Evolve the current split probe/backend design into first-class multi-probe support so a single backend can monitor multiple subnets, VLANs, or physical locations. This is a strong long-term fit for the architecture because probe and backend responsibilities are already separated in the repository.

### Probe-aware reporting
Add probe identity, probe status, and per-probe attribution so discovered devices and events can be tied back to the collector that observed them. This becomes especially important once multi-probe deployments are supported.

### Network map view
Introduce a visual network map or topology-oriented interface that groups devices by subnet, category, trust zone, or other logical structure. The existing combination of MAC, IP, vendor, fingerprint, device type, and event history makes this a strong product fit.

### Historical network snapshots
Add a time-based network state view so users can inspect what the environment looked like at a chosen moment, including device presence, IP allocation, and known posture. Existing `first_seen`, `last_seen`, event history, and IP history already provide a good base for this feature.

### Backup and restore
Provide formal backup and restore support covering device metadata, settings, historical records, and vulnerability data. This will improve long-term operational confidence and make upgrades or migrations safer.

## Security enhancements

### Rogue identity detection
Add detection for vendor and identity inconsistencies such as OUI mismatches, suspicious hostname patterns, or changes that conflict with known device fingerprints. This will strengthen InSpectre’s usefulness as a lightweight trust and anomaly monitoring platform.

### ARP anomaly detection
Add checks for suspicious ARP behaviour such as duplicate ownership, fast IP reassignment, or inconsistent MAC-to-IP relationships. This aligns well with the existing IP history model and the product’s existing ARP-based blocking direction.

### Trust change detection
Track major device identity shifts over time, including vendor changes, hostname changes, repeated IP churn, or device type confidence drops. This would surface network anomalies that are easy to miss in a standard device inventory view.

## UX and product maturity

### Device activity timeline improvements
Expand the device timeline experience so users can clearly inspect joins, online and offline transitions, IP changes, scans, renames, tagging, and vulnerability activity in one place. The `DeviceEvent` model already supports this kind of chronological view.

### Uptime and availability metrics
Add per-device uptime percentages, offline duration summaries, and presence statistics derived from device state history. This would increase the product’s operational value alongside its security features.

### Import and export
Support export and reimport of device names, tags, notes, overrides, and other user-maintained metadata. This will improve backup workflows and make the system easier to migrate or rebuild.

### Authentication and access control
Add optional authentication and role-based access controls for environments where more than one person may access the interface. This becomes more relevant as the platform grows from a personal network tool into a shared monitoring system.
