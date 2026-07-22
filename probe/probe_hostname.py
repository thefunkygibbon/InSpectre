import csv
import os
import socket
import subprocess

import probe_config as _cfg


def _strip_fqdn(name: str) -> str:
    return name.rstrip(".") if name else ""


def _get_default_gateway() -> str | None:
    try:
        out = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=3,
        )
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "default" and parts[1] == "via":
                gw = parts[2]
                if not gw.startswith("127.") and not gw.startswith("169.254."):
                    print(f"[hostname] Default gateway detected: {gw}", flush=True)
                    return gw
    except Exception as e:
        print(f"[hostname] Gateway detection failed: {e}", flush=True)
    return None


def _detect_dns_server() -> str | None:
    if _cfg.LAN_DNS_SERVER_ENV:
        print(f"[hostname] DNS server from env (LAN_DNS_SERVER): {_cfg.LAN_DNS_SERVER_ENV}", flush=True)
        return _cfg.LAN_DNS_SERVER_ENV

    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                parts = line.strip().split()
                if parts and parts[0] == "nameserver" and len(parts) >= 2:
                    ip = parts[1]
                    if not ip.startswith("127.") and not ip.startswith("169.254."):
                        print(f"[hostname] DNS server from resolv.conf: {ip}", flush=True)
                        return ip
                    else:
                        print(f"[hostname] Skipping loopback nameserver: {ip}", flush=True)
    except Exception:
        pass

    gw = _get_default_gateway()
    if gw:
        print(f"[hostname] Using default gateway as DNS server: {gw}", flush=True)
        return gw

    print("[hostname] WARNING: no usable DNS server found. "
          "Set LAN_DNS_SERVER=<router_ip> in docker-compose.yml.", flush=True)
    return None


def resolve_hostname(ip: str) -> str | None:
    if not _cfg._is_valid_ip(ip):
        return None

    if not _cfg._DNS_DETECTED:
        _cfg._DNS_SERVER = _detect_dns_server()
        _cfg._DNS_DETECTED = True

    dns = _cfg._DNS_SERVER
    print(f"[hostname] Resolving {ip} (DNS server: {dns})", flush=True)

    if dns:
        try:
            out = subprocess.run(
                ["dig", "+short", "+time=2", "+tries=1", f"@{dns}", "-x", ip],
                capture_output=True, text=True, timeout=5,
            )
            for line in out.stdout.splitlines():
                candidate = _strip_fqdn(line.strip())
                if candidate and candidate != ip and not candidate.startswith(";"):
                    print(f"[hostname] dig resolved {ip} -> {candidate}", flush=True)
                    return candidate
        except Exception as e:
            print(f"[hostname] dig failed: {e}", flush=True)

    try:
        result = socket.gethostbyaddr(ip)
        candidate = _strip_fqdn(result[0])
        if candidate and candidate != ip:
            print(f"[hostname] gethostbyaddr resolved {ip} -> {candidate}", flush=True)
            return candidate
    except Exception as e:
        print(f"[hostname] gethostbyaddr failed for {ip}: {e}", flush=True)

    if dns:
        try:
            out = subprocess.run(
                ["host", ip, dns],
                capture_output=True, text=True, timeout=5,
            )
            for line in out.stdout.splitlines():
                if "domain name pointer" in line:
                    parts = line.strip().split()
                    if parts:
                        candidate = _strip_fqdn(parts[-1])
                        if candidate and candidate != ip:
                            print(f"[hostname] host resolved {ip} -> {candidate}", flush=True)
                            return candidate
        except Exception as e:
            print(f"[hostname] host cmd failed: {e}", flush=True)

    try:
        cmd = ["nslookup", ip]
        if dns:
            cmd.append(dns)
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        for line in out.stdout.splitlines():
            line_l = line.lower()
            if "name =" in line_l or "name=" in line_l:
                parts = line.strip().split("=")
                if len(parts) >= 2:
                    candidate = _strip_fqdn(parts[-1].strip())
                    if candidate and candidate != ip:
                        print(f"[hostname] nslookup resolved {ip} -> {candidate}", flush=True)
                        return candidate
    except Exception as e:
        print(f"[hostname] nslookup failed: {e}", flush=True)

    try:
        out = subprocess.run(
            ["avahi-resolve", "-a", ip],
            capture_output=True, text=True, timeout=4,
        )
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                candidate = _strip_fqdn(parts[1])
                if candidate and candidate != ip:
                    print(f"[hostname] avahi resolved {ip} -> {candidate}", flush=True)
                    return candidate
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    try:
        out = subprocess.run(
            ["nmblookup", "-A", ip],
            capture_output=True, text=True, timeout=4,
        )
        for line in out.stdout.splitlines():
            if "<00>" in line and "<GROUP>" not in line:
                parts = line.strip().split()
                if parts:
                    candidate = parts[0].strip()
                    if candidate and candidate not in ("WORKGROUP", ip, "Looking"):
                        print(f"[hostname] nmblookup resolved {ip} -> {candidate}", flush=True)
                        return candidate
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    print(f"[hostname] All methods failed for {ip}", flush=True)
    return None


# ---------------------------------------------------------------------------
# Vendor lookup
# ---------------------------------------------------------------------------
_MAC_VENDOR_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mac-vendors-export.csv")
_mac_vendor_db: dict[str, str] = {}


def _load_mac_vendor_db() -> None:
    try:
        with open(_MAC_VENDOR_DB_PATH, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                prefix = row["Mac Prefix"].replace(":", "").lower()
                vendor = row["Vendor Name"].strip()
                if prefix and vendor:
                    _mac_vendor_db[prefix] = vendor
        print(f"[vendor] Loaded {len(_mac_vendor_db)} MAC prefixes from {_MAC_VENDOR_DB_PATH}", flush=True)
    except Exception as e:
        print(f"[vendor] Failed to load MAC vendor DB: {e}", flush=True)


def lookup_vendor(mac: str) -> str:
    norm = mac.replace(":", "").replace("-", "").lower()
    for length in (9, 7, 6):
        vendor = _mac_vendor_db.get(norm[:length])
        if vendor:
            return vendor
    return "Unknown"
