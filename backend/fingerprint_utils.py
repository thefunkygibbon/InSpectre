import asyncio
from datetime import datetime, timezone
from typing import Optional

import httpx
from sqlalchemy import text
from sqlalchemy.orm import Session

from models import Device, FingerprintEntry
from device_utils import _apply_fingerbank_enrichment


_FB_URL = "https://api.fingerbank.org/api/v2/combinations/interrogate"

_FB_TYPE_MAP: list[tuple[list[str], str]] = [
    (["iphone"],                                                    "phone"),
    (["ipad"],                                                      "tablet"),
    (["android tablet", "galaxy tab", "kindle fire"],               "tablet"),
    (["android", "mobile device", "smartphone"],                    "phone"),
    (["chromebook", "chrome os", "chromeos"],                       "laptop"),
    (["macbook", "imac", "mac mini", "mac pro"],                    "laptop"),
    (["laptop", "notebook"],                                        "laptop"),
    (["mac os", "macos", "os x"],                                   "laptop"),
    (["windows", "microsoft windows"],                              "desktop"),
    (["linux"],                                                     "desktop"),
    (["router", "gateway", "openwrt", "dd-wrt", "pfsense",
      "opnsense", "mikrotik", "routeros", "firewall"],              "router"),
    (["access point", "wireless ap", "wireless access point"],      "ap"),
    (["network switch", "managed switch", "unmanaged switch",
      "gigabit switch", "easy smart switch", "smart switch plus",
      "poe switch"],                                                 "switch"),
    (["roku", "fire tv", "firetv", "chromecast", "apple tv",
      "streaming stick", "streaming device"],                       "streamer"),
    (["smart tv", "television", "android tv", "google tv",
      "qled", "oled tv"],                                           "tv"),
    (["playstation", "xbox", "nintendo", "game console",
      "steam deck"],                                                 "console"),
    (["raspberry pi"],                                              "iot"),
    (["iot", "smart home", "internet of things", "thermostat",
      "smart plug", "smart bulb", "smart light"],                   "iot"),
    (["printer", "network printer", "laser printer", "inkjet",
      "all-in-one printer"],                                        "printer"),
    (["ip camera", "security camera", "network camera", "nvr",
      "cctv", "hikvision", "dahua", "reolink"],                    "camera"),
    (["camera"],                                                    "camera"),
    (["voip", "sip phone", "ip phone", "desk phone"],              "voip"),
    (["nas", "network attached", "network storage",
      "synology", "qnap", "truenas", "freenas"],                   "nas"),
    (["server"],                                                    "server"),
]


def _fingerbank_to_type(device_name: str, parents: list[str]) -> str | None:
    all_names = [device_name.lower()] + [p.lower() for p in parents]
    for keywords, dtype in _FB_TYPE_MAP:
        if any(kw in name for name in all_names for kw in keywords):
            return dtype
    return None


def _oui(mac: str) -> str:
    return mac.replace(':', '').replace('-', '').lower()[:6]


def _match_fingerprints(device: Device, fingerprints: list[FingerprintEntry]) -> FingerprintEntry | None:
    device_oui   = _oui(device.mac_address)
    device_ports = set()
    if device.scan_results:
        device_ports = {p.get('port') for p in (device.scan_results.get('open_ports') or []) if p.get('port')}
    best_score = 0
    best_fp    = None
    for fp in fingerprints:
        score = 0
        if fp.oui_prefix and fp.oui_prefix.lower() == device_oui:
            score += 3
        if fp.open_ports:
            score += len(device_ports & set(fp.open_ports))
        if score > best_score or (
            score == best_score and score > 0 and best_fp is not None and
            (fp.confidence_score, fp.hit_count) > (best_fp.confidence_score, best_fp.hit_count)
        ):
            if score > 0:
                best_score = score
                best_fp    = fp
    return best_fp


def _upsert_manual_fingerprint(db: Session, device: Device, vendor_name: Optional[str], device_type: Optional[str]):
    oui = _oui(device.mac_address) if device.mac_address else None
    open_ports = None
    if device.scan_results:
        ports = [p.get('port') for p in (device.scan_results.get('open_ports') or []) if p.get('port')]
        open_ports = ports if ports else None
    effective_type   = (device_type   or "").strip() or None
    effective_vendor = (vendor_name   or "").strip() or None
    existing = None
    if oui:
        q = db.query(FingerprintEntry).filter(
            FingerprintEntry.oui_prefix == oui,
            FingerprintEntry.source == 'manual',
        )
        if effective_type:
            q = q.filter(FingerprintEntry.device_type == effective_type)
        existing = q.first()
    if existing:
        if effective_vendor: existing.vendor_name = effective_vendor
        if effective_type:   existing.device_type = effective_type
        if open_ports:       existing.open_ports  = open_ports
        existing.hit_count        += 1
        existing.confidence_score  = 1.0
    else:
        db.add(FingerprintEntry(
            oui_prefix=oui, hostname_pattern=None, open_ports=open_ports,
            device_type=effective_type or "unknown", vendor_name=effective_vendor,
            confidence_score=1.0, hit_count=1, source='manual',
        ))


async def _fingerbank_query(mac: str, dhcp_fingerprint: str | None, dhcp_vendor: str | None,
                            dhcp_hostname: str | None, api_key: str) -> dict:
    body: dict = {}
    if dhcp_fingerprint:
        body["dhcp_fingerprint"] = dhcp_fingerprint
    if dhcp_vendor:
        body["dhcp_vendor"] = dhcp_vendor
    if dhcp_hostname:
        body["hostname"] = dhcp_hostname
    body["mac"] = mac

    if len(body) == 1:
        return {"error": "No DHCP data available to query", "queried_at": datetime.now(timezone.utc).isoformat(), "dhcp_fp_used": None}

    print(f"[fingerbank] querying {mac}  fp={dhcp_fingerprint!r}  vc={dhcp_vendor!r}", flush=True)

    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            resp = await client.post(
                _FB_URL,
                params={"key": api_key},
                headers={"Authorization": f"Token {api_key}"},
                json=body,
            )
        print(f"[fingerbank] {mac} → HTTP {resp.status_code}", flush=True)

        if resp.status_code == 200:
            data = resp.json()
            dev = data.get("device") or {}

            def _collect_names(node, depth=0) -> list[str]:
                if not node or depth > 8:
                    return []
                names = []
                if isinstance(node, dict):
                    n = (node.get("name") or "").strip()
                    if n:
                        names.append(n)
                    for p in (node.get("parents") or []):
                        names += _collect_names(p, depth + 1)
                elif isinstance(node, list):
                    for item in node:
                        names += _collect_names(item, depth)
                return names

            parent_names = _collect_names(dev.get("parents"))
            device_name  = (dev.get("name") or "").strip() or None
            score        = data.get("score")
            mapped_type  = _fingerbank_to_type(device_name or "", parent_names)

            print(f"[fingerbank] {mac} → {device_name!r} score={score} type={mapped_type} "
                  f"parents={parent_names}", flush=True)
            return {
                "device_name":  device_name,
                "score":        score,
                "parents":      parent_names,
                "mapped_type":  mapped_type,
                "queried_at":   datetime.now(timezone.utc).isoformat(),
                "dhcp_fp_used": dhcp_fingerprint,
            }

        body_text = resp.text[:400]
        ts = datetime.now(timezone.utc).isoformat()
        if resp.status_code == 401:
            msg = f"HTTP 401 Unauthorized — check your API key. Response: {body_text}"
            print(f"[fingerbank] {mac} error: {msg}", flush=True)
            return {"error": msg, "status": "auth_error", "queried_at": ts, "dhcp_fp_used": dhcp_fingerprint}
        elif resp.status_code == 404:
            msg = "No match found in Fingerbank database"
            print(f"[fingerbank] {mac}: {msg}", flush=True)
            return {"error": msg, "status": "no_match", "queried_at": ts, "dhcp_fp_used": dhcp_fingerprint}
        else:
            msg = f"HTTP {resp.status_code}. Response: {body_text}"
            print(f"[fingerbank] {mac} error: {msg}", flush=True)
            return {"error": msg, "status": "error", "queried_at": ts, "dhcp_fp_used": dhcp_fingerprint}

    except Exception as exc:
        msg = f"Request failed: {exc}"
        print(f"[fingerbank] {mac} exception: {msg}", flush=True)
        return {"error": msg, "status": "error", "queried_at": datetime.now(timezone.utc).isoformat(), "dhcp_fp_used": dhcp_fingerprint}


async def _fingerbank_loop():
    await asyncio.sleep(30)  # startup grace — let DHCP data arrive first
    from database import SessionLocal
    from models import Setting
    while True:
        try:
            db = SessionLocal()
            try:
                key_row = db.get(Setting, "fingerbank_api_key")
                api_key = (key_row.value or "").strip() if key_row else ""
                if api_key:
                    rows = db.execute(text("""
                        SELECT mac_address FROM devices
                        WHERE (dhcp_fingerprint IS NOT NULL
                               OR dhcp_vendor_class IS NOT NULL
                               OR dhcp_hostname    IS NOT NULL)
                          AND (
                            fingerbank_result IS NULL
                            OR fingerbank_result->>'status' = 'error'
                            OR (
                              fingerbank_result->>'status' IN ('no_match', 'auth_error')
                              AND COALESCE(fingerbank_result->>'dhcp_fp_used', '') IS DISTINCT FROM COALESCE(dhcp_fingerprint, '')
                            )
                          )
                        ORDER BY last_seen DESC
                    """)).fetchall()
                    if rows:
                        print(f"[fingerbank] loop: {len(rows)} device(s) to query", flush=True)
                    for (mac,) in rows:
                        device = db.get(Device, mac)
                        if not device:
                            continue
                        result = await _fingerbank_query(
                            mac, device.dhcp_fingerprint,
                            device.dhcp_vendor_class, device.dhcp_hostname, api_key
                        )
                        device.fingerbank_result = result
                        from sqlalchemy.orm.attributes import flag_modified
                        flag_modified(device, "fingerbank_result")
                        _apply_fingerbank_enrichment(device, result)
                        db.commit()
                        await asyncio.sleep(0.5)
            finally:
                db.close()
        except Exception as exc:
            print(f"[fingerbank-loop] unhandled error: {exc}", flush=True)
        await asyncio.sleep(60)
