import ipaddress
import os
import re
import subprocess

from _version import __version__ as VERSION  # noqa: F401 (re-exported)

# ---------------------------------------------------------------------------
# Startup network auto-detection
# ---------------------------------------------------------------------------
def _startup_detect_interface() -> str | None:
    try:
        out = subprocess.run(["ip", "route", "show", "default"],
                             capture_output=True, text=True, timeout=3)
        for line in out.stdout.splitlines():
            parts = line.split()
            if parts and parts[0] == "default" and "dev" in parts:
                iface = parts[parts.index("dev") + 1]
                if iface and not iface.startswith("lo"):
                    return iface
    except Exception:
        pass
    return None


def _startup_detect_ip_range(iface: str) -> str | None:
    try:
        out = subprocess.run(["ip", "addr", "show", iface],
                             capture_output=True, text=True, timeout=3)
        for line in out.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet ") and "/" in line:
                return str(ipaddress.ip_interface(line.split()[1]).network)
    except Exception:
        pass
    return None


_autodetected_interface = _startup_detect_interface()
_autodetected_ip_range = (
    _startup_detect_ip_range(_autodetected_interface)
    if _autodetected_interface else None
)

# ---------------------------------------------------------------------------
# Configuration (mutable — updated by _load_settings_from_db each scan cycle)
# ---------------------------------------------------------------------------
DATABASE_URL            = os.environ.get("DATABASE_URL", "postgresql://admin:password123@localhost:5432/inspectre")
SCAN_INTERVAL           = int(os.environ.get("SCAN_INTERVAL",           60))
IP_RANGE                = os.environ.get("IP_RANGE",  "").strip() or _autodetected_ip_range  or "192.168.0.0/24"
INTERFACE               = os.environ.get("INTERFACE", "").strip() or _autodetected_interface or "eth0"
PORT_SCAN_WORKERS       = int(os.environ.get("PORT_SCAN_WORKERS",       200))
GATEWAY_SCAN_WORKERS    = int(os.environ.get("GATEWAY_SCAN_WORKERS",    50))
PORT_SCAN_METHOD        = os.environ.get("PORT_SCAN_METHOD",            "tcp_connect")
OS_CONFIDENCE_THRESHOLD = int(os.environ.get("OS_CONFIDENCE_THRESHOLD", 85))
OFFLINE_MISS_THRESHOLD  = int(os.environ.get("OFFLINE_MISS_THRESHOLD",  8))
PRESENCE_GRACE_SECONDS  = int(os.environ.get("PRESENCE_GRACE_SECONDS",  240))
FLAP_SUPPRESS_SECONDS   = int(os.environ.get("FLAP_SUPPRESS_SECONDS",   120))
SNIFFER_WORKERS         = int(os.environ.get("SNIFFER_WORKERS",         4))
ARP_SCAN_RETRY          = int(os.environ.get("ARP_SCAN_RETRY",          1))
PRIMARY_IP_MODE         = os.environ.get("PRIMARY_IP_MODE",             "locked")
SNIFFER_SUBNET_FILTER   = os.environ.get("SNIFFER_SUBNET_FILTER",  "false").lower() in ("true", "1", "yes")
PROBE_API_PORT          = int(os.environ.get("PROBE_API_PORT",          8001))
LAN_DNS_SERVER_ENV      = os.environ.get("LAN_DNS_SERVER", "").strip()
MDNS_INTERVAL_MINUTES   = int(os.environ.get("MDNS_INTERVAL_MINUTES",   120))

NIGHTLY_SCAN_START            = int(os.environ.get("NIGHTLY_SCAN_START",            2))
NIGHTLY_SCAN_END              = int(os.environ.get("NIGHTLY_SCAN_END",              4))
OFFLINE_RESCAN_HOURS          = int(os.environ.get("OFFLINE_RESCAN_HOURS",          4))
BASELINE_SCAN_COUNT_THRESHOLD = 3
HOSTNAME_COOLDOWN_HOURS       = 24
NUCLEI_TEMPLATE_UPDATE_INTERVAL = os.environ.get("NUCLEI_TEMPLATE_UPDATE_INTERVAL", "24h")

PING_COUNT    = 40
TRACE_MAX_HOP = 30

# Hostname resolution state (also updated by probe_hostname.resolve_hostname)
_DNS_SERVER: str | None = None
_DNS_DETECTED = False

# Feature flags — all default ON
def _env_bool(key: str, default: bool = True) -> bool:
    v = os.environ.get(key, "").strip().lower()
    if not v:
        return default
    return v in ("true", "1", "yes")


ENABLE_ARP_SWEEP              = _env_bool("ENABLE_ARP_SWEEP")
ENABLE_PASSIVE_SNIFFER        = _env_bool("ENABLE_PASSIVE_SNIFFER")
ENABLE_HOSTNAME_RESOLUTION    = _env_bool("ENABLE_HOSTNAME_RESOLUTION")
ENABLE_PORT_SCANNING          = _env_bool("ENABLE_PORT_SCANNING")
ENABLE_SERVICE_FINGERPRINTING = _env_bool("ENABLE_SERVICE_FINGERPRINTING")
ENABLE_MDNS                   = _env_bool("ENABLE_MDNS")
ENABLE_NIGHTLY_SCAN           = _env_bool("ENABLE_NIGHTLY_SCAN")
ENABLE_UNSCANNED_RETRY        = _env_bool("ENABLE_UNSCANNED_RETRY")
AUTO_GROUP_BY_HOSTNAME        = _env_bool("AUTO_GROUP_BY_HOSTNAME")
SCAN_GROUPED_MEMBERS          = _env_bool("SCAN_GROUPED_MEMBERS", default=False)

# Hostname pattern utilities — used across mdns, sniffer, device modules
_IP_DERIVED_RE = re.compile(r'^(\d{1,3}[.\-_]){3}\d{1,3}(\.[a-z]{1,12})?$', re.I)


def _is_ip_derived_hostname(h: str | None) -> bool:
    if not h:
        return True
    return bool(_IP_DERIVED_RE.match(h))


# ---------------------------------------------------------------------------
# Own-MAC detection (probe's interface MAC — filters out own ARP packets)
# ---------------------------------------------------------------------------
def _get_own_mac(iface: str) -> str | None:
    try:
        from scapy.all import get_if_hwaddr
        return get_if_hwaddr(iface).lower()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
_INVALID_IPS = {"0.0.0.0", "", "255.255.255.255"}


def _is_valid_ip(ip: str) -> bool:
    if not ip or ip.strip() in _INVALID_IPS:
        return False
    try:
        addr = ipaddress.ip_address(ip.strip())
        return not (
            addr.packed[0] == 0
            or str(addr) == "255.255.255.255"
            or addr.is_link_local
        )
    except ValueError:
        return False


def _is_valid_dns_server(value: str) -> bool:
    """Validate a user-supplied DNS server address (IP or conservative hostname).
    Rejects anything that could be a CLI flag (leading '-') or contains whitespace."""
    if not value:
        return False
    value = value.strip()
    if not value or value[0] == "-" or any(c.isspace() for c in value):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    return bool(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,253}[A-Za-z0-9])?", value))


def ping_once(ip: str, timeout_s: int = 2) -> bool:
    if not _is_valid_ip(ip):
        return False
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout_s), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_s + 1,
        )
        return result.returncode == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Runtime settings loader (called at startup and top of each scan cycle)
# ---------------------------------------------------------------------------
def _load_settings_from_db() -> None:
    global SCAN_INTERVAL, IP_RANGE, INTERFACE, PORT_SCAN_WORKERS, GATEWAY_SCAN_WORKERS
    global PORT_SCAN_METHOD, OS_CONFIDENCE_THRESHOLD, OFFLINE_MISS_THRESHOLD
    global SNIFFER_WORKERS, ARP_SCAN_RETRY, PRIMARY_IP_MODE, SNIFFER_SUBNET_FILTER
    global NUCLEI_TEMPLATE_UPDATE_INTERVAL, NIGHTLY_SCAN_START, NIGHTLY_SCAN_END
    global OFFLINE_RESCAN_HOURS, BASELINE_SCAN_COUNT_THRESHOLD, HOSTNAME_COOLDOWN_HOURS
    global ENABLE_ARP_SWEEP, ENABLE_PASSIVE_SNIFFER, ENABLE_HOSTNAME_RESOLUTION
    global ENABLE_PORT_SCANNING, ENABLE_SERVICE_FINGERPRINTING, ENABLE_MDNS
    global ENABLE_NIGHTLY_SCAN, ENABLE_UNSCANNED_RETRY, AUTO_GROUP_BY_HOSTNAME
    global SCAN_GROUPED_MEMBERS, PRESENCE_GRACE_SECONDS, _DNS_SERVER
    try:
        from probe_models import Session
        from sqlalchemy import text
        session = Session()
        try:
            rows = session.execute(text("SELECT key, value FROM settings")).fetchall()
        finally:
            session.close()
        db = {r[0]: r[1] for r in rows}
        if "scan_interval"           in db: SCAN_INTERVAL           = int(db["scan_interval"])
        if "ip_range"                in db: IP_RANGE                = db["ip_range"].strip()
        if "port_scan_workers"       in db: PORT_SCAN_WORKERS       = int(db["port_scan_workers"])
        if "gateway_scan_workers"    in db: GATEWAY_SCAN_WORKERS    = int(db["gateway_scan_workers"])
        if "port_scan_method"        in db: PORT_SCAN_METHOD        = db["port_scan_method"].strip()
        if "os_confidence_threshold" in db: OS_CONFIDENCE_THRESHOLD = int(db["os_confidence_threshold"])
        if "presence_grace_seconds"  in db: PRESENCE_GRACE_SECONDS  = int(db["presence_grace_seconds"])
        elif "offline_miss_threshold" in db:
            PRESENCE_GRACE_SECONDS = int(db["offline_miss_threshold"]) * SCAN_INTERVAL
        if "offline_miss_threshold"  in db: OFFLINE_MISS_THRESHOLD  = int(db["offline_miss_threshold"])
        if "sniffer_workers"         in db: SNIFFER_WORKERS         = int(db["sniffer_workers"])
        if "arp_scan_retry"          in db: ARP_SCAN_RETRY          = int(db["arp_scan_retry"])
        if "primary_ip_mode"         in db: PRIMARY_IP_MODE         = db["primary_ip_mode"].strip()
        if "sniffer_subnet_filter"   in db:
            SNIFFER_SUBNET_FILTER = db["sniffer_subnet_filter"].strip().lower() in ("true", "1", "yes")
        if "nuclei_template_update_interval" in db:
            NUCLEI_TEMPLATE_UPDATE_INTERVAL = db["nuclei_template_update_interval"]
        if "nightly_scan_start"            in db: NIGHTLY_SCAN_START            = int(db["nightly_scan_start"])
        if "nightly_scan_end"              in db: NIGHTLY_SCAN_END              = int(db["nightly_scan_end"])
        if "offline_rescan_hours"          in db: OFFLINE_RESCAN_HOURS          = int(db["offline_rescan_hours"])
        if "baseline_scan_count_threshold" in db: BASELINE_SCAN_COUNT_THRESHOLD = int(db["baseline_scan_count_threshold"])
        if "hostname_cooldown_hours"       in db: HOSTNAME_COOLDOWN_HOURS       = int(db["hostname_cooldown_hours"])
        def _pb(k: str, fallback: bool = True) -> bool:
            return db[k].strip().lower() in ("true", "1", "yes") if k in db else fallback
        ENABLE_ARP_SWEEP              = _pb("enable_arp_sweep")
        ENABLE_PASSIVE_SNIFFER        = _pb("enable_passive_sniffer")
        ENABLE_HOSTNAME_RESOLUTION    = _pb("enable_hostname_resolution")
        ENABLE_PORT_SCANNING          = _pb("enable_port_scanning")
        ENABLE_SERVICE_FINGERPRINTING = _pb("enable_service_fingerprinting")
        ENABLE_MDNS                   = _pb("enable_mdns")
        ENABLE_NIGHTLY_SCAN           = _pb("enable_nightly_scan")
        ENABLE_UNSCANNED_RETRY        = _pb("enable_unscanned_retry")
        AUTO_GROUP_BY_HOSTNAME        = _pb("auto_group_by_hostname")
        SCAN_GROUPED_MEMBERS          = _pb("scan_grouped_members", False)
        ds = db.get("dns_server", "").strip()
        if ds and _is_valid_dns_server(ds):
            _DNS_SERVER = ds
        elif ds:
            print(f"[settings] Ignoring invalid dns_server value: {ds!r}", flush=True)
        pi = db.get("probe_interface", "").strip()
        if pi:
            INTERFACE = pi
        elif _autodetected_interface and not db.get("probe_interface", "").strip():
            try:
                s2 = Session()
                try:
                    s2.execute(text(
                        "UPDATE settings SET value=:v WHERE key='probe_interface' AND (value IS NULL OR value='')"
                    ), {"v": _autodetected_interface})
                    s2.commit()
                finally:
                    s2.close()
            except Exception:
                pass
    except Exception as exc:
        print(f"[settings] DB load failed (using current values): {exc}", flush=True)


def apply_runtime_config(payload: dict) -> dict:
    global SCAN_INTERVAL, IP_RANGE, INTERFACE, PORT_SCAN_WORKERS, GATEWAY_SCAN_WORKERS
    global PORT_SCAN_METHOD, OS_CONFIDENCE_THRESHOLD, OFFLINE_MISS_THRESHOLD
    global SNIFFER_WORKERS, ARP_SCAN_RETRY, PRIMARY_IP_MODE, SNIFFER_SUBNET_FILTER
    global NUCLEI_TEMPLATE_UPDATE_INTERVAL, HOSTNAME_COOLDOWN_HOURS
    global ENABLE_ARP_SWEEP, ENABLE_PASSIVE_SNIFFER, ENABLE_HOSTNAME_RESOLUTION
    global ENABLE_PORT_SCANNING, ENABLE_SERVICE_FINGERPRINTING, ENABLE_MDNS
    global ENABLE_NIGHTLY_SCAN, ENABLE_UNSCANNED_RETRY, AUTO_GROUP_BY_HOSTNAME
    global SCAN_GROUPED_MEMBERS, PRESENCE_GRACE_SECONDS, _DNS_SERVER

    changes = {}

    if "scan_interval" in payload:
        SCAN_INTERVAL = int(payload["scan_interval"]); changes["scan_interval"] = SCAN_INTERVAL
    if "ip_range" in payload:
        IP_RANGE = str(payload["ip_range"]).strip(); changes["ip_range"] = IP_RANGE
    if "port_scan_workers" in payload:
        PORT_SCAN_WORKERS = int(payload["port_scan_workers"]); changes["port_scan_workers"] = PORT_SCAN_WORKERS
    if "gateway_scan_workers" in payload:
        GATEWAY_SCAN_WORKERS = int(payload["gateway_scan_workers"]); changes["gateway_scan_workers"] = GATEWAY_SCAN_WORKERS
    if "port_scan_method" in payload:
        PORT_SCAN_METHOD = str(payload["port_scan_method"]).strip(); changes["port_scan_method"] = PORT_SCAN_METHOD
    if "os_confidence_threshold" in payload:
        OS_CONFIDENCE_THRESHOLD = int(payload["os_confidence_threshold"]); changes["os_confidence_threshold"] = OS_CONFIDENCE_THRESHOLD
    if "presence_grace_seconds" in payload:
        PRESENCE_GRACE_SECONDS = int(payload["presence_grace_seconds"]); changes["presence_grace_seconds"] = PRESENCE_GRACE_SECONDS
    if "offline_miss_threshold" in payload:
        OFFLINE_MISS_THRESHOLD = int(payload["offline_miss_threshold"]); changes["offline_miss_threshold"] = OFFLINE_MISS_THRESHOLD
        if "presence_grace_seconds" not in payload:
            PRESENCE_GRACE_SECONDS = OFFLINE_MISS_THRESHOLD * SCAN_INTERVAL
            changes["presence_grace_seconds"] = PRESENCE_GRACE_SECONDS
    if "sniffer_workers" in payload:
        changes["sniffer_workers"] = {
            "requested": int(payload["sniffer_workers"]),
            "applied": SNIFFER_WORKERS,
            "note": "worker count changes require probe restart",
        }
    if "arp_scan_retry" in payload:
        ARP_SCAN_RETRY = int(payload["arp_scan_retry"]); changes["arp_scan_retry"] = ARP_SCAN_RETRY
    if "primary_ip_mode" in payload:
        PRIMARY_IP_MODE = str(payload["primary_ip_mode"]).strip(); changes["primary_ip_mode"] = PRIMARY_IP_MODE
    if "sniffer_subnet_filter" in payload:
        SNIFFER_SUBNET_FILTER = str(payload["sniffer_subnet_filter"]).strip().lower() in ("true", "1", "yes")
        changes["sniffer_subnet_filter"] = SNIFFER_SUBNET_FILTER
    if "probe_interface" in payload:
        v = str(payload["probe_interface"]).strip()
        if v:
            INTERFACE = v; changes["probe_interface"] = INTERFACE
    if "hostname_cooldown_hours" in payload:
        HOSTNAME_COOLDOWN_HOURS = int(payload["hostname_cooldown_hours"]); changes["hostname_cooldown_hours"] = HOSTNAME_COOLDOWN_HOURS
    if "dns_server" in payload:
        ds = str(payload["dns_server"]).strip()
        if ds:
            _DNS_SERVER = ds; changes["dns_server"] = _DNS_SERVER

    def _abool(v) -> bool:
        return str(v).strip().lower() in ("true", "1", "yes")

    if "enable_arp_sweep"              in payload: ENABLE_ARP_SWEEP              = _abool(payload["enable_arp_sweep"]);              changes["enable_arp_sweep"]              = ENABLE_ARP_SWEEP
    if "enable_passive_sniffer"        in payload: ENABLE_PASSIVE_SNIFFER        = _abool(payload["enable_passive_sniffer"]);        changes["enable_passive_sniffer"]        = ENABLE_PASSIVE_SNIFFER
    if "enable_hostname_resolution"    in payload: ENABLE_HOSTNAME_RESOLUTION    = _abool(payload["enable_hostname_resolution"]);    changes["enable_hostname_resolution"]    = ENABLE_HOSTNAME_RESOLUTION
    if "enable_port_scanning"          in payload: ENABLE_PORT_SCANNING          = _abool(payload["enable_port_scanning"]);          changes["enable_port_scanning"]          = ENABLE_PORT_SCANNING
    if "enable_service_fingerprinting" in payload: ENABLE_SERVICE_FINGERPRINTING = _abool(payload["enable_service_fingerprinting"]); changes["enable_service_fingerprinting"] = ENABLE_SERVICE_FINGERPRINTING
    if "enable_mdns"                   in payload: ENABLE_MDNS                   = _abool(payload["enable_mdns"]);                   changes["enable_mdns"]                   = ENABLE_MDNS
    if "enable_nightly_scan"           in payload: ENABLE_NIGHTLY_SCAN           = _abool(payload["enable_nightly_scan"]);           changes["enable_nightly_scan"]           = ENABLE_NIGHTLY_SCAN
    if "enable_unscanned_retry"        in payload: ENABLE_UNSCANNED_RETRY        = _abool(payload["enable_unscanned_retry"]);        changes["enable_unscanned_retry"]        = ENABLE_UNSCANNED_RETRY
    if "auto_group_by_hostname"        in payload: AUTO_GROUP_BY_HOSTNAME        = _abool(payload["auto_group_by_hostname"]);        changes["auto_group_by_hostname"]        = AUTO_GROUP_BY_HOSTNAME
    if "scan_grouped_members"          in payload: SCAN_GROUPED_MEMBERS          = _abool(payload["scan_grouped_members"]);          changes["scan_grouped_members"]          = SCAN_GROUPED_MEMBERS
    if "nuclei_template_update_interval" in payload:
        NUCLEI_TEMPLATE_UPDATE_INTERVAL = str(payload["nuclei_template_update_interval"]).strip()
        changes["nuclei_template_update_interval"] = NUCLEI_TEMPLATE_UPDATE_INTERVAL

    return {
        "applied": True,
        "changes": changes,
        "effective": {
            "scan_interval":           SCAN_INTERVAL,
            "ip_range":                IP_RANGE,
            "port_scan_workers":       PORT_SCAN_WORKERS,
            "gateway_scan_workers":    GATEWAY_SCAN_WORKERS,
            "port_scan_method":        PORT_SCAN_METHOD,
            "os_confidence_threshold": OS_CONFIDENCE_THRESHOLD,
            "offline_miss_threshold":  OFFLINE_MISS_THRESHOLD,
            "sniffer_workers":         SNIFFER_WORKERS,
            "nuclei_template_update_interval": NUCLEI_TEMPLATE_UPDATE_INTERVAL,
        },
    }
