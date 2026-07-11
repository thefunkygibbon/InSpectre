def is_locked_secondary_sighting(locked: bool, primary_ip: str | None, sighting_ip: str) -> bool:
    if not locked:
        return False
    if not primary_ip:
        return False
    return sighting_ip != primary_ip


def apply_secondary_ip_sighting(scan_results, sighting_ip: str, source: str, now_iso: str):
    scan = dict(scan_results or {})
    sec = dict(scan.get("secondary_ips_seen") or {})
    row = dict(sec.get(sighting_ip) or {})
    row["count"] = int(row.get("count") or 0) + 1
    row["last_seen"] = now_iso
    row["source"] = source
    sec[sighting_ip] = row
    scan["secondary_ips_seen"] = sec
    return scan
