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
    """Periodically merge devices sharing the same base DNS or DHCP hostname into a group.
    Never disturbs manually-curated groups or opted-out devices."""
    if not _cfg.AUTO_GROUP_BY_HOSTNAME:
        return
    import uuid as _uuid
    from collections import defaultdict
    s = Session()
    try:
        rows = s.execute(text("""
            SELECT mac_address, hostname, dhcp_hostname, group_id, group_primary, group_manual,
                   is_online, ip_address, primary_ip
            FROM devices
            WHERE COALESCE(auto_group_optout, false) = false
        """)).fetchall()

        # Build buckets by base DNS hostname; fall back to DHCP hostname when DNS is
        # absent or generic (common for MAC-randomized phones whose IP-derived mDNS name
        # would otherwise prevent the match).
        buckets: dict[str, list] = defaultdict(list)
        seen_in_bucket: dict[str, set] = defaultdict(set)  # bucket → mac set (dedup)
        for r in rows:
            placed = False
            dns_base = _hostname_base(r.hostname or "")
            if dns_base and not _is_generic_hostname(r.hostname):
                if r.mac_address not in seen_in_bucket[dns_base]:
                    buckets[dns_base].append(r)
                    seen_in_bucket[dns_base].add(r.mac_address)
                placed = True
            # Also index by DHCP hostname — catches the case where one interface
            # resolved to a generic mDNS name but both share the same DHCP Option 12.
            dhcp_base = _hostname_base(r.dhcp_hostname or "")
            if dhcp_base and not _is_generic_hostname(r.dhcp_hostname) and dhcp_base != dns_base:
                if r.mac_address not in seen_in_bucket[dhcp_base]:
                    buckets[dhcp_base].append(r)
                    seen_in_bucket[dhcp_base].add(r.mac_address)

        for base, members in buckets.items():
            if len(members) < 2:
                continue
            # Never auto-touch a bucket where any member belongs to a manual group
            if any(m.group_manual for m in members):
                continue

            # Collect the full set of group IDs already in this bucket (may be >1
            # if two separate groups both produced members matching this hostname).
            existing = {str(m.group_id) for m in members if m.group_id}

            if len(existing) == 1:
                gid = next(iter(existing))
            else:
                # Two or more existing groups need merging — pick the one whose primary
                # is the most authoritative (non-LAA, online) to avoid ID churn if
                # possible, otherwise mint a fresh UUID.
                non_laa_primaries = [
                    str(m.group_id) for m in members
                    if m.group_id and m.group_primary and not _is_locally_administered(m.mac_address)
                ]
                gid = non_laa_primaries[0] if non_laa_primaries else str(_uuid.uuid4())

            # When merging two groups, also pull in any other members of those groups
            # that weren't matched by hostname (e.g. the IP-derived-hostname interfaces).
            if len(existing) > 1:
                old_gids = tuple(existing - {gid})
                if old_gids:
                    s.execute(
                        text("UPDATE devices SET group_id = :new WHERE group_id = ANY(:old) "
                             "AND COALESCE(group_manual, false) = false"),
                        {"new": gid, "old": list(old_gids)},
                    )

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
                  f"(base='{base}', primary={primary_mac})", flush=True)
    except Exception as exc:
        s.rollback()
        print(f"[group] Retroactive auto-group error: {exc}", flush=True)
    finally:
        s.close()


def _try_auto_group_by_hostname(mac: str, hostname: str) -> bool:
    """Look for another device with the same base DNS hostname and group them.
    Skips the is_online=false guard so LAA/randomized MACs (which may be online
    simultaneously on different SSIDs) are still matched."""
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
                  AND COALESCE(auto_group_optout, false) = false
                ORDER BY is_online DESC
                LIMIT 1
            """),
            {"base": base, "mac": mac},
        ).fetchone()
        if not row:
            return False
        peer_mac, peer_gid, peer_manual = row[0], row[1], row[2]

        if peer_manual:
            return False
        cur_row = sess.execute(
            text("SELECT group_manual, group_id, COALESCE(auto_group_optout, false) FROM devices WHERE mac_address = :m"),
            {"m": mac},
        ).fetchone()
        if not cur_row:
            return False
        cur_manual, cur_gid, cur_optout = cur_row[0], cur_row[1], cur_row[2]
        if cur_manual or cur_optout:
            return False

        if not _cfg.AUTO_GROUP_BY_HOSTNAME:
            _write_event(mac, "group_suggestion", {
                "peer_mac": peer_mac,
                "reason": f"Same base hostname '{base}'",
            })
            return False

        # Determine the winning group ID — prefer the peer's existing gid to
        # reduce churn; if the peer is LAA and the incoming MAC is not, flip it.
        if peer_gid and cur_gid and str(peer_gid) != str(cur_gid):
            # Merge: pick gid from whichever side has a non-LAA primary
            peer_laa = _is_locally_administered(peer_mac)
            cur_laa  = _is_locally_administered(mac)
            if cur_laa and not peer_laa:
                new_gid = str(peer_gid)
                old_gid = str(cur_gid)
            else:
                new_gid = str(peer_gid)
                old_gid = str(cur_gid)
            # Migrate ALL members of the losing group
            sess.execute(
                text("UPDATE devices SET group_id = :new WHERE group_id = :old "
                     "AND COALESCE(group_manual, false) = false"),
                {"new": new_gid, "old": old_gid},
            )
        elif peer_gid:
            new_gid = str(peer_gid)
        elif cur_gid:
            new_gid = str(cur_gid)
            # Assign peer into the incoming device's existing group
            sess.execute(
                text("UPDATE devices SET group_id = :gid WHERE mac_address = :m "
                     "AND COALESCE(group_manual, false) = false"),
                {"gid": new_gid, "m": peer_mac},
            )
        else:
            new_gid = str(_uuid.uuid4())
            sess.execute(
                text("UPDATE devices SET group_id = :gid WHERE mac_address = :m"),
                {"gid": new_gid, "m": peer_mac},
            )

        # Assign incoming MAC (non-primary by default; retroactive_auto_group
        # will re-elect the authoritative primary on its next pass)
        sess.execute(
            text("UPDATE devices SET group_id = :gid, group_primary = false WHERE mac_address = :m"),
            {"gid": new_gid, "m": mac},
        )
        # Ensure peer is marked primary if it wasn't already in a group
        if not peer_gid:
            sess.execute(
                text("UPDATE devices SET group_primary = true WHERE mac_address = :m"),
                {"m": peer_mac},
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
