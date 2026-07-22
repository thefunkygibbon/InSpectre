import re
import socket
import subprocess
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy import text

from models import Device, DeviceEvent, FingerprintEntry


def _strip_fqdn(name: str) -> str:
    return name.rstrip('.') if name else ''


def _resolve_hostname(ip: str) -> str | None:
    try:
        result = socket.gethostbyaddr(ip)
        candidate = _strip_fqdn(result[0])
        if candidate and candidate != ip:
            return candidate
    except Exception:
        pass
    try:
        out = subprocess.run(["avahi-resolve", "-a", ip], capture_output=True, text=True, timeout=3)
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                candidate = _strip_fqdn(parts[1])
                if candidate and candidate != ip:
                    return candidate
    except Exception:
        pass
    try:
        out = subprocess.run(["nmblookup", "-A", ip], capture_output=True, text=True, timeout=4)
        for line in out.stdout.splitlines():
            if '<00>' in line and '<GROUP>' not in line:
                parts = line.strip().split()
                if parts:
                    candidate = parts[0].strip()
                    if candidate and candidate not in ('WORKGROUP', ip, 'Looking'):
                        return candidate
    except Exception:
        pass
    return None


def _identity_score(d: Device) -> dict:
    score   = 0
    reasons = []
    vendor = getattr(d, 'vendor_override', None) or d.vendor
    if vendor and vendor.lower() not in ("unknown", ""):
        score += 20; reasons.append("vendor_known")
    if d.hostname:
        score += 20; reasons.append("hostname_known")
    if d.custom_name:
        score += 10; reasons.append("named_by_user")
    if d.deep_scanned:
        score += 20; reasons.append("deep_scanned")
    scan  = d.scan_results or {}
    ports = scan.get("open_ports") or []
    if ports:
        score += 15; reasons.append("ports_identified")
    if scan.get("os_matches"):
        score += 15; reasons.append("os_identified")
    if getattr(d, 'dhcp_vendor_class', None) or getattr(d, 'dhcp_fingerprint', None):
        score += 10; reasons.append("dhcp_fingerprinted")
    fb = getattr(d, 'fingerbank_result', None)
    if fb and (fb.get('score') or 0) >= 50:
        score += 15; reasons.append("fingerbank_identified")
    return {"score": min(score, 100), "reasons": reasons}


def _infer_device_type(d: Device) -> str | None:
    if getattr(d, 'device_type_override', None):
        return d.device_type_override
    fb = getattr(d, 'fingerbank_result', None)
    if fb and not fb.get('error') and (fb.get('score') or 0) >= 50 and fb.get('mapped_type'):
        return fb['mapped_type']
    scan     = d.scan_results or {}
    dhcp_type = scan.get("device_type")
    if dhcp_type and scan.get("device_type_source") == "dhcp":
        return dhcp_type
    hostname = (d.hostname or d.custom_name or "").lower()
    dhcp_hn  = (getattr(d, 'dhcp_hostname',     None) or "").lower()
    dhcp_vc  = (getattr(d, 'dhcp_vendor_class', None) or "").lower()
    vendor   = (getattr(d, 'vendor_override',   None) or d.vendor or "").lower()
    combined = f"{hostname} {dhcp_hn} {dhcp_vc} {vendor}"
    ports    = {p.get("port") for p in (scan.get("open_ports") or []) if p.get("port")}
    os_guess = (scan.get("os_matches") or [{}])[0].get("name", "").lower() if scan.get("os_matches") else ""
    if any(k in combined for k in ("cam", "camera", "nvr", "reolink", "dahua", "hikvision", "arlo", "ring", "nest-cam")):
        return "camera"
    if any(k in combined for k in ("iphone", "ipad", "android", "pixel", "galaxy", "oneplus", "xiaomi", "redmi")):
        return "phone"
    if "android" in os_guess or "ios" in os_guess:
        return "phone"
    if any(k in combined for k in ("shelly", "tasmota", "sonoff", "gosund", "esphome")):
        return "iot"
    if any(k in combined for k in ("espressif", "tuya", "meross", "bouffalo")):
        return "iot"
    if any(k in combined for k in ("access point", "wireless ap", "unifi", "ubnt", "airos")):
        return "ap"
    if any(k in combined for k in ("router", "gateway", "openwrt", "dd-wrt", "pfsense", "opnsense")):
        return "router"
    if any(k in vendor for k in ("ubiquiti", "tp-link", "netgear", "asus", "linksys")) and {80, 443, 22} & ports:
        return "router"
    if any(k in combined for k in ("nas", "synology", "qnap", "truenas", "openmediavault")):
        return "nas"
    if {445, 139, 2049} & ports:
        return "nas"
    if any(k in combined for k in ("printer", "jetdirect")):
        return "printer"
    if {9100, 515, 631} & ports:
        return "printer"
    if any(k in combined for k in ("roku", "firetv", "fire tv", "chromecast", "appletv", "apple tv")):
        return "streamer"
    if any(k in combined for k in ("smart tv", "androidtv", "android tv", "google tv")):
        return "tv"
    if any(k in combined for k in ("playstation", "xbox", "nintendo")):
        return "console"
    if any(k in vendor for k in ("sony interactive", "microsoft xbox")):
        return "console"
    if "windows" in os_guess or {3389} & ports:
        return "desktop"
    if "linux" in os_guess and {22} & ports and len(ports) > 3:
        return "server"
    return None


_GENERIC_BRAND = re.compile(
    r'^(Generic|Unknown|Internet of Things|Phone|Tablet|Mobile|Android|'
    r'Windows|Linux|IoT|Smart Home|Network|Networking|Wireless)',
    re.I,
)


def _infer_vendor(d: Device) -> str | None:
    if getattr(d, 'vendor_override', None):
        return d.vendor_override
    if d.vendor and d.vendor.lower() not in ('unknown', ''):
        return d.vendor
    fb = getattr(d, 'fingerbank_result', None) or {}
    if fb.get('error'):
        return None
    for p in (fb.get('parents') or []):
        if p and not _GENERIC_BRAND.match(p):
            tok = p.split()[0]
            if tok and len(tok) > 2:
                return tok
    dn = (fb.get('device_name') or '').strip()
    if dn:
        tok = dn.split()[0]
        if tok and len(tok) > 2:
            return tok
    return None


def _apply_fingerbank_enrichment(d: Device, result: dict | None) -> None:
    """Persist conservative identity hints from Fingerbank when local identity is missing."""
    if not result or result.get("error"):
        return
    score = result.get("score") or 0
    if score < 50:
        return
    current_vendor = (getattr(d, "vendor", None) or "").strip()
    if not getattr(d, "vendor_override", None) and (not current_vendor or current_vendor.lower() == "unknown"):
        inferred_vendor = _infer_vendor(d)
        if inferred_vendor:
            d.vendor = inferred_vendor
    if not getattr(d, "device_type_override", None):
        mapped_type = result.get("mapped_type")
        if mapped_type:
            scan = dict(d.scan_results or {})
            current_type = (scan.get("device_type") or "").strip().lower()
            current_source = (scan.get("device_type_source") or "").strip().lower()
            should_set = (
                not current_type
                or current_type == "unknown"
                or current_source in ("", "heuristic", "dhcp")
            )
            if should_set:
                scan["device_type"] = mapped_type
                scan["device_type_source"] = "fingerbank"
                scan["device_type_conf"] = round(min(float(score), 100.0) / 100.0, 2)
                d.scan_results = scan
                from sqlalchemy.orm.attributes import flag_modified
                flag_modified(d, "scan_results")


def _to_dict(d: Device) -> dict:
    id_score = _identity_score(d)
    inferred = _infer_device_type(d)
    return {
        "mac_address":          d.mac_address,
        "ip_address":           d.ip_address,
        "primary_ip":           getattr(d, "primary_ip", None) or d.ip_address,
        "hostname":             d.hostname,
        "vendor":               d.vendor,
        "vendor_override":      getattr(d, 'vendor_override', None),
        "vendor_inferred":      _infer_vendor(d),
        "device_type_override": getattr(d, 'device_type_override', None),
        "custom_name":          d.custom_name,
        "is_online":            d.is_online,
        "deep_scanned":         d.deep_scanned,
        "miss_count":           getattr(d, 'miss_count', 0),
        "is_important":         bool(getattr(d, 'is_important', False)),
        "notes":                getattr(d, 'notes', None),
        "tags":                 getattr(d, 'tags', None),
        "location":             getattr(d, 'location', None),
        "first_seen":           d.first_seen.isoformat()  if d.first_seen  else None,
        "last_seen":            d.last_seen.isoformat()   if d.last_seen   else None,
        "status_changed_at":    d.status_changed_at.isoformat() if getattr(d, 'status_changed_at', None) else None,
        "scan_results":         d.scan_results,
        "services":             (d.scan_results or {}).get("services"),
        "pipeline_stage":       (d.scan_results or {}).get("pipeline_stage"),
        "display_name":         d.custom_name or d.hostname or d.ip_address,
        "name_candidates":      [],
        "identity_score":       id_score["score"],
        "identity_reasons":     id_score["reasons"],
        "device_type":          getattr(d, 'device_type_override', None) or inferred,
        "device_type_inferred": inferred,
        "vuln_last_scanned": d.vuln_last_scanned.isoformat() if d.vuln_last_scanned else None,
        "vuln_severity":     d.vuln_severity,
        "deep_scan_last_run":    d.deep_scan_last_run.isoformat() if getattr(d, 'deep_scan_last_run', None) else None,
        "baseline_ports":        getattr(d, 'baseline_ports', None),
        "baseline_scan_count":   getattr(d, 'baseline_scan_count', 0) or 0,
        "is_blocked":            bool(getattr(d, 'is_blocked', False)),
        "zone":                  getattr(d, 'zone', None),
        "is_ignored":            bool(getattr(d, 'is_ignored', False)),
        "suppress_presence_events": bool(getattr(d, 'suppress_presence_events', False)),
        "primary_ip_locked":     bool(getattr(d, 'primary_ip_locked', False)),
        "dhcp_hostname":         getattr(d, 'dhcp_hostname', None),
        "dhcp_vendor_class":     getattr(d, 'dhcp_vendor_class', None),
        "dhcp_fingerprint":      getattr(d, 'dhcp_fingerprint', None),
        "fingerbank_result":     getattr(d, 'fingerbank_result', None),
        "is_virtual_interface":  False,
        "virtual_of":            None,
        "secondary_ips":         [],
        "group_id":              str(getattr(d, "group_id", None)) if getattr(d, "group_id", None) else None,
        "group_primary":         bool(getattr(d, "group_primary", False)),
        "group_members":         [],
        "group_size":            1,
        "is_group_representative": False,
        "is_acknowledged":       bool(getattr(d, "is_acknowledged", False)),
        "person_id":             str(getattr(d, "person_id", None)) if getattr(d, "person_id", None) else None,
        "person_name":           None,
    }


def _clean_name_candidate(value: str | None) -> str | None:
    value = (value or '').strip()
    return value or None


def _build_name_candidates(db: Session, d: Device) -> list[dict]:
    scan = dict(d.scan_results or {})
    plugin_candidates: list[tuple[str, str]] = []
    try:
        rows = db.execute(text("SELECT plugin_id, data FROM plugin_device_data WHERE mac_address = :mac"), {"mac": d.mac_address}).fetchall()
        for plugin_id, data in rows:
            if isinstance(data, dict):
                cand = _clean_name_candidate(data.get('_inspectre_hostname_candidate'))
                if cand:
                    plugin_candidates.append((plugin_id, cand))
    except Exception:
        plugin_candidates = []

    current_name = _clean_name_candidate(d.custom_name or d.hostname)
    current_source = None
    if d.custom_name and current_name:
        current_source = 'manual'
    elif current_name:
        if _clean_name_candidate(getattr(d, 'dhcp_hostname', None)) == current_name:
            current_source = 'dhcp'
        elif _clean_name_candidate(scan.get('mdns_name')) == current_name:
            current_source = 'mdns'
        else:
            for plugin_id, cand in plugin_candidates:
                if _clean_name_candidate(cand) == current_name:
                    current_source = f'plugin:{plugin_id}'
                    break
            if current_source is None and _clean_name_candidate(scan.get('rdns_hostname')) == current_name:
                current_source = 'rdns'

    out: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(value: str | None, source: str, label: str):
        nonlocal current_source
        clean = _clean_name_candidate(value)
        if not clean:
            return
        key = (source, clean.lower())
        if key in seen:
            return
        seen.add(key)
        out.append({
            'value': clean,
            'source': source,
            'source_label': label,
            'is_pinned': bool(d.custom_name and clean == _clean_name_candidate(d.custom_name)),
            'is_current': current_source == source and clean == current_name,
        })

    add(d.custom_name, 'manual', 'Pinned name')
    add(getattr(d, 'dhcp_hostname', None), 'dhcp', 'DHCP hostname')
    add(scan.get('mdns_name'), 'mdns', 'mDNS / Bonjour')
    for plugin_id, cand in plugin_candidates:
        add(cand, f'plugin:{plugin_id}', f'Plugin ({plugin_id})')
    add(scan.get('rdns_hostname'), 'rdns', 'Reverse DNS')

    if current_name and not any(c['is_current'] for c in out):
        add(current_name, 'stored', 'Stored hostname')
        if out:
            out[-1]['is_current'] = True

    return out


def _add_event(db: Session, mac: str, event_type: str, detail: dict = None):
    try:
        db.add(DeviceEvent(mac_address=mac, type=event_type, detail=detail))
    except Exception:
        pass
