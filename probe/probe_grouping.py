import re
import subprocess
import threading
import time

from sqlalchemy import text

import probe_config as _cfg
from probe_models import Session
from probe_ip import _write_event

_GENERIC_HOSTNAME_RE = re.compile(
    r'^(?:android[\-_]|iphone|ipad|localhost|dhcp|unknown|'
    r'desktop(?:[\-_]?\d{0,4})?$|'
    r'workgroup|raspberrypi|my[\-_]pc|workpc|user[\-_]pc|my[\-_]laptop|'
    r'pc$|host$|node$|client$|device$)',
    re.IGNORECASE,
)


def _hostname_base(hostname: str) -> str:
    if not hostname:
        return ""
    return hostname.split(".")[0].lower()


def _is_generic_hostname(hostname: str) -> bool:
    base = _hostname_base(hostname)
    if not base or len(base) < 3:
        return True
    if re.match(r'^\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}$', base) or re.match(r'^\d+$', base):
        return True
    if re.match(r'^[0-9a-f]{12,}$', base, re.I):
        return True
    if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', base, re.I):
        return True
    return bool(_GENERIC_HOSTNAME_RE.match(base))


_host_ips_cache: tuple = (0.0, set())
_host_ips_lock  = threading.Lock()


def _get_host_ipv4s(ttl: int = 120) -> set:
    """IPv4 addresses bound to the probe's active scanning interface (cached ttl seconds).
    Scoped to INTERFACE only — avoids Docker bridge/macvlan addresses overlapping LAN IPs."""
    global _host_ips_cache
    now = time.time()
    with _host_ips_lock:
        ts, cached = _host_ips_cache
        if cached and (now - ts) < ttl:
            return cached
    ips: set = set()
    try:
        from scapy.all import get_if_addr
        a = get_if_addr(_cfg.INTERFACE)
        if a and a != "0.0.0.0" and _cfg._is_valid_ip(a):
            ips.add(a)
    except Exception:
        pass
    if not ips:
        try:
            out = subprocess.run(
                ["ip", "-4", "-o", "addr", "show", "dev", _cfg.INTERFACE],
                capture_output=True, text=True, timeout=5,
            ).stdout
            for line in out.splitlines():
                parts = line.split()
                for i, tok in enumerate(parts):
                    if tok == "inet" and i + 1 < len(parts):
                        cand = parts[i + 1].split("/")[0]
                        if _cfg._is_valid_ip(cand):
                            ips.add(cand)
        except Exception:
            pass
    ips.discard("127.0.0.1")
    with _host_ips_lock:
        _host_ips_cache = (now, ips)
    return ips


def _is_locally_administered(mac: str) -> bool:
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except Exception:
        return False


def _ip_sort_key(ip: str):
    try:
        return tuple(int(o) for o in ip.split("."))
    except Exception:
        return (999, 999, 999, 999)


def _choose_group_primary(members) -> str:
    def keyf(m):
        ip = (getattr(m, "primary_ip", None) or m.ip_address or "")
        return (
            0 if not _is_locally_administered(m.mac_address) else 1,
            0 if m.is_online else 1,
            _ip_sort_key(ip),
        )
    return min(members, key=keyf).mac_address


def retroactive_auto_group() -> None:
    """Periodically merge devices sharing the same base DNS hostname into a group.
    Never disturbs manually-curated groups or opted-out devices."""
    if not _cfg.AUTO_GROUP_BY_HOSTNAME:
        return
    import uuid as _uuid
    from collections import defaultdict
    s = Session()
    try:
        rows = s.execute(text("""
            SELECT mac_address, hostname, group_id, group_primary, group_manual,
                   is_online, ip_address, primary_ip
            FROM devices
            WHERE hostname IS NOT NULL AND hostname != ''
              AND COALESCE(auto_group_optout, false) = false
        """)).fetchall()

        buckets = defaultdict(list)
        for r in rows:
            base = _hostname_base(r.hostname)
            if not base or _is_generic_hostname(r.hostname):
                continue
            buckets[base].append(r)

        for base, members in buckets.items():
            if len(members) < 2:
                continue
            if any(m.group_manual for m in members):
                continue

            existing = {str(m.group_id) for m in members if m.group_id}
            gid = next(iter(existing)) if len(existing) == 1 else str(_uuid.uuid4())
            primary_mac = _choose_group_primary(members)

            already = (
                all(m.group_id and str(m.group_id) == gid for m in members)
                and sum(1 for m in members if m.group_primary) == 1
                and any(m.group_primary and m.mac_address == primary_mac for m in members)
            )
            if already:
                continue

            for m in members:
                s.execute(
                    text("UPDATE devices SET group_id = :g, group_primary = :p WHERE mac_address = :m"),
                    {"g": gid, "p": (m.mac_address == primary_mac), "m": m.mac_address},
                )
            s.commit()
            print(f"[group] Auto-grouped {[m.mac_address for m in members]} "
                  f"(base hostname='{base}', primary={primary_mac})", flush=True)
    except Exception as exc:
        s.rollback()
        print(f"[group] Retroactive auto-group error: {exc}", flush=True)
    finally:
        s.close()


def _try_auto_group_by_hostname(mac: str, hostname: str) -> bool:
    """Look for an offline device with the same base DNS hostname and group them.
    Matches on resolved DNS hostname ONLY (never DHCP hostname) to avoid false merges."""
    base = _hostname_base(hostname)
    if not hostname or not base or _is_generic_hostname(hostname):
        return False
    import uuid as _uuid
    sess = Session()
    try:
        row = sess.execute(
            text("""
                SELECT mac_address, group_id, group_manual FROM devices
                WHERE hostname IS NOT NULL AND hostname != ''
                  AND LOWER(SPLIT_PART(hostname, '.', 1)) = :base
                  AND mac_address != :mac
                  AND is_online = false
                  AND COALESCE(auto_group_optout, false) = false
                LIMIT 1
            """),
            {"base": base, "mac": mac},
        ).fetchone()
        if not row:
            return False
        peer_mac, peer_gid, peer_manual = row[0], row[1], row[2]

        if peer_manual:
            return False
        cur_manual = sess.execute(
            text("SELECT group_manual FROM devices WHERE mac_address = :m"),
            {"m": mac},
        ).scalar()
        if cur_manual:
            return False
        cur_optout = sess.execute(
            text("SELECT COALESCE(auto_group_optout, false) FROM devices WHERE mac_address = :m"),
            {"m": mac},
        ).scalar()
        if cur_optout:
            return False

        if not _cfg.AUTO_GROUP_BY_HOSTNAME:
            _write_event(mac, "group_suggestion", {
                "peer_mac": peer_mac,
                "reason": f"Same base hostname '{base}' as offline device",
            })
            return False

        new_gid = str(peer_gid) if peer_gid else str(_uuid.uuid4())

        if not peer_gid:
            sess.execute(
                text("UPDATE devices SET group_id = :gid, group_primary = true WHERE mac_address = :m"),
                {"gid": new_gid, "m": peer_mac},
            )
        sess.execute(
            text("UPDATE devices SET group_id = :gid, group_primary = false WHERE mac_address = :m"),
            {"gid": new_gid, "m": mac},
        )
        sess.commit()
        print(f"[+] Auto-grouped {mac} with {peer_mac} (base DNS hostname='{base}')", flush=True)
        return True
    except Exception as exc:
        sess.rollback()
        print(f"[grouping] Error auto-grouping {mac}: {exc}", flush=True)
        return False
    finally:
        sess.close()
