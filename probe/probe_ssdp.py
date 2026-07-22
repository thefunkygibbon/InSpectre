import socket
import struct
import time

from sqlalchemy.orm.attributes import flag_modified

import probe_config as _cfg
from probe_models import Session, Device


def _parse_ssdp_message(text: str) -> dict | None:
    """Parse SSDP NOTIFY or HTTP 200 response headers into a service dict."""
    lines = text.splitlines()
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    st  = headers.get("st",  headers.get("nt",  ""))
    usn = headers.get("usn", "")
    if not (st or usn):
        return None
    return {
        "st":       st,
        "usn":      usn,
        "server":   headers.get("server",   ""),
        "location": headers.get("location", ""),
    }


def _apply_ssdp_enrichment(ssdp_data: dict[str, list[dict]]) -> None:
    """Store SSDP service discoveries in device.scan_results["ssdp_services"]."""
    if not ssdp_data:
        return
    from datetime import datetime, timezone
    session = Session()
    try:
        updated = 0
        now_iso = datetime.now(timezone.utc).isoformat()
        for ip, services in ssdp_data.items():
            dev = session.query(Device).filter(Device.ip_address == ip).first()
            if not dev:
                continue
            scan = dict(dev.scan_results) if dev.scan_results else {}
            existing = {s["usn"]: s for s in scan.get("ssdp_services", []) if s.get("usn")}
            changed = False
            for svc in services:
                usn = svc.get("usn", "")
                if not usn:
                    continue
                svc["last_seen"] = now_iso
                if usn not in existing or existing[usn] != svc:
                    existing[usn] = svc
                    changed = True
            if changed:
                scan["ssdp_services"] = list(existing.values())
                dev.scan_results = scan
                flag_modified(dev, "scan_results")
                updated += 1
        if updated:
            session.commit()
            print(f"[ssdp] Enriched {updated} device(s)", flush=True)
    except Exception as e:
        session.rollback()
        print(f"[ssdp] Enrichment error: {e}", flush=True)
    finally:
        session.close()


def _ssdp_browse(timeout: int = 6) -> dict[str, list[dict]]:
    """Send SSDP M-SEARCH and collect UPnP responses. Returns {ip: [service_dict]}."""
    SSDP_ADDR = "239.255.255.255"
    SSDP_PORT = 1900
    request = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
        'MAN: "ssdp:discover"\r\n'
        f"MX: {max(1, timeout - 2)}\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode()

    result: dict[str, list[dict]] = {}
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
        s.settimeout(0.5)
        s.bind(("", 0))
        s.sendto(request, (SSDP_ADDR, SSDP_PORT))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = s.recvfrom(8192)
                ip = addr[0]
                info = _parse_ssdp_message(data.decode("utf-8", errors="replace"))
                if info and info.get("usn"):
                    existing_usns = {sv["usn"] for sv in result.get(ip, [])}
                    if info["usn"] not in existing_usns:
                        result.setdefault(ip, []).append(info)
            except socket.timeout:
                continue
            except Exception:
                break
    except Exception as e:
        print(f"[ssdp] browse error: {e}", flush=True)
    finally:
        if s:
            try: s.close()
            except Exception: pass

    total = sum(len(v) for v in result.values())
    if result:
        print(f"[ssdp] Discovered {total} service(s) on {len(result)} device(s)", flush=True)
    return result


def _ssdp_passive_listener() -> None:
    """Continuously listen for UPnP NOTIFY announcements on the SSDP multicast group."""
    SSDP_ADDR = "239.255.255.255"
    SSDP_PORT = 1900
    print("[ssdp-passive] Starting passive SSDP listener", flush=True)

    while True:
        pending: dict[str, list[dict]] = {}
        last_flush = time.monotonic()
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try: s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError): pass
            s.bind(("", SSDP_PORT))
            mreq = struct.pack("4sL", socket.inet_aton(SSDP_ADDR), socket.INADDR_ANY)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            s.settimeout(1.0)
            while True:
                try:
                    data, addr = s.recvfrom(8192)
                    text = data.decode("utf-8", errors="replace")
                    if "ssdp:byebye" in text.lower(): continue
                    info = _parse_ssdp_message(text)
                    if info and info.get("usn"):
                        ip = addr[0]
                        existing_usns = {sv["usn"] for sv in pending.get(ip, [])}
                        if info["usn"] not in existing_usns:
                            pending.setdefault(ip, []).append(info)
                except socket.timeout:
                    pass
                except Exception:
                    break
                if pending and time.monotonic() - last_flush > 30:
                    _apply_ssdp_enrichment(pending)
                    pending.clear()
                    last_flush = time.monotonic()
        except PermissionError as e:
            print(f"[ssdp-passive] permission denied: {e}", flush=True)
            time.sleep(60)
        except Exception as e:
            print(f"[ssdp-passive] error, restarting: {e}", flush=True)
            time.sleep(10)
        finally:
            if s:
                try:
                    mreq = struct.pack("4sL", socket.inet_aton(SSDP_ADDR), socket.INADDR_ANY)
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
                except Exception: pass
                try: s.close()
                except Exception: pass
