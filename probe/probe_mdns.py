import socket
import struct
import time

import probe_config as _cfg
from probe_models import Session, Device, _remember_name_source


def _mdns_browse() -> dict[str, dict]:
    """Discover mDNS services by querying the multicast group (RFC 6762).
    Returns {ip: {"mdns_name": str|None, "services": [str, ...]}}"""
    MDNS_ADDR   = "224.0.0.251"
    MDNS_PORT   = 5353
    LISTEN_SECS = 4

    ptr_records: dict[str, list[str]] = {}
    srv_records: dict[str, str]        = {}
    a_records:   dict[str, str]        = {}

    def _decode_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
        if depth > 10:
            return "", offset
        labels: list[str] = []
        jumped = False
        jump_ret = offset
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            elif (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    break
                ptr = ((length & 0x3F) << 8) | data[offset + 1]
                if not jumped:
                    jump_ret = offset + 2
                jumped = True
                suffix, _ = _decode_name(data, ptr, depth + 1)
                if suffix:
                    labels.append(suffix)
                break
            else:
                end = offset + 1 + length
                if end > len(data):
                    break
                labels.append(data[offset + 1:end].decode("utf-8", errors="replace"))
                offset = end
        return ".".join(labels), (jump_ret if jumped else offset)

    def _parse_packet(data: bytes):
        try:
            if len(data) < 12:
                return
            flags = struct.unpack_from(">H", data, 2)[0]
            if not (flags & 0x8000):
                return
            qdcount, ancount, nscount, arcount = struct.unpack_from(">HHHH", data, 4)
            offset = 12
            for _ in range(qdcount):
                _, offset = _decode_name(data, offset)
                offset += 4
            for _ in range(ancount + nscount + arcount):
                if offset + 10 > len(data):
                    break
                name, offset = _decode_name(data, offset)
                if offset + 10 > len(data):
                    break
                rtype, _, _, rdlen = struct.unpack_from(">HHIH", data, offset)
                offset += 10
                rdata_start = offset
                offset += rdlen
                if rdlen == 0 or rdata_start + rdlen > len(data):
                    continue
                name_l = name.lower().rstrip(".")
                if rtype == 12:  # PTR
                    target, _ = _decode_name(data, rdata_start)
                    tgt = target.lower().rstrip(".")
                    if tgt:
                        lst = ptr_records.setdefault(name_l, [])
                        if tgt not in lst:
                            lst.append(tgt)
                elif rtype == 33 and rdlen >= 7:  # SRV
                    tgt, _ = _decode_name(data, rdata_start + 6)
                    srv_records[name_l] = tgt.lower().rstrip(".")
                elif rtype == 1 and rdlen == 4:  # A
                    ip = ".".join(str(b) for b in data[rdata_start:rdata_start + 4])
                    a_records[name_l] = ip
        except Exception:
            pass

    def _build_query(*qnames: str) -> bytes:
        questions = b""
        for qname in qnames:
            for label in qname.rstrip(".").split("."):
                lb = label.encode()
                questions += bytes([len(lb)]) + lb
            questions += b"\x00"
            questions += struct.pack(">HH", 12, 1)  # PTR, IN
        return struct.pack(">HHHHHH", 0, 0, len(qnames), 0, 0, 0) + questions

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        sock.bind(("", MDNS_PORT))
        mreq = struct.pack("4sL", socket.inet_aton(MDNS_ADDR), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(0.5)

        service_types = [
            "_services._dns-sd._udp.local",
            "_googlecast._tcp.local",
            "_airplay._tcp.local",
            "_raop._tcp.local",
            "_printer._tcp.local",
            "_ipp._tcp.local",
            "_http._tcp.local",
            "_https._tcp.local",
            "_smb._tcp.local",
            "_afpovertcp._tcp.local",
            "_ssh._tcp.local",
            "_hap._tcp.local",
            "_companion-link._tcp.local",
            "_amzn-wplay._tcp.local",
        ]
        for i in range(0, len(service_types), 3):
            try:
                sock.sendto(_build_query(*service_types[i:i + 3]), (MDNS_ADDR, MDNS_PORT))
            except Exception:
                pass

        deadline = time.monotonic() + LISTEN_SECS
        while time.monotonic() < deadline:
            try:
                data, _ = sock.recvfrom(8192)
                _parse_packet(data)
            except socket.timeout:
                continue
            except Exception:
                break
    except PermissionError as e:
        print(f"[mdns] permission denied (need privileged/host network): {e}", flush=True)
        return {}
    except Exception as e:
        print(f"[mdns] socket error: {e}", flush=True)
        return {}
    finally:
        if sock:
            try:
                mreq = struct.pack("4sL", socket.inet_aton(MDNS_ADDR), socket.INADDR_ANY)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass

    result: dict[str, dict] = {}
    for hostname, ip in a_records.items():
        if _cfg._is_valid_ip(ip):
            entry = result.setdefault(ip, {"mdns_name": None, "services": []})
            if not entry["mdns_name"]:
                entry["mdns_name"] = hostname.removesuffix(".local")

    for svc_type, instances in ptr_records.items():
        if "._dns-sd." in svc_type:
            continue
        parts = svc_type.removesuffix(".local").split(".")
        svc_label = ".".join(parts[-2:]) if len(parts) >= 2 else svc_type.removesuffix(".local")
        for instance in instances:
            hostname = srv_records.get(instance)
            ip = None
            if hostname:
                ip = a_records.get(hostname) or a_records.get(hostname + ".local")
            if ip and _cfg._is_valid_ip(ip):
                entry = result.setdefault(ip, {"mdns_name": None, "services": []})
                if svc_label not in entry["services"]:
                    entry["services"].append(svc_label)

    if result:
        print(f"[mdns] Discovered {len(result)} device(s) via mDNS", flush=True)
    return result


def _apply_mdns_enrichment(mdns_data: dict[str, dict]) -> None:
    """Update device records with mDNS name and service list."""
    if not mdns_data:
        return
    from probe_grouping import _is_generic_hostname
    session = Session()
    try:
        updated = 0
        for ip, info in mdns_data.items():
            dev = session.query(Device).filter(Device.ip_address == ip).first()
            if not dev:
                continue
            changed = False
            mdns_name = info.get("mdns_name")
            if mdns_name:
                if _remember_name_source(dev, "mdns_name", mdns_name):
                    changed = True
                current_hn = dev.hostname or ""
                dhcp_name = (dev.dhcp_hostname or "").strip()
                if (
                    not dev.custom_name
                    and mdns_name != current_hn
                    and not _is_generic_hostname(mdns_name)
                    and (
                        not current_hn
                        or _cfg._is_ip_derived_hostname(current_hn)
                        or _is_generic_hostname(current_hn)
                        or (dhcp_name and mdns_name == dhcp_name)
                    )
                ):
                    dev.hostname = mdns_name
                    changed = True
            if info.get("services"):
                scan = dict(dev.scan_results) if dev.scan_results else {}
                existing = scan.get("mdns_services", [])
                merged = list(dict.fromkeys(existing + info["services"]))
                if merged != existing:
                    scan["mdns_services"] = merged
                    dev.scan_results = scan
                    changed = True
            if changed:
                updated += 1
        if updated:
            session.commit()
            print(f"[mdns] Enriched {updated} device(s)", flush=True)
    except Exception as e:
        session.rollback()
        print(f"[mdns] Enrichment error: {e}", flush=True)
    finally:
        session.close()


def _mdns_loop() -> None:
    """Scheduled background thread: runs _mdns_browse every MDNS_INTERVAL_MINUTES."""
    interval_s = _cfg.MDNS_INTERVAL_MINUTES * 60
    print(f"[mdns] Scheduled loop started (interval={_cfg.MDNS_INTERVAL_MINUTES}m)", flush=True)
    time.sleep(20)
    while True:
        try:
            print("[mdns] Running browse", flush=True)
            mdns_data = _mdns_browse()
            if mdns_data:
                _apply_mdns_enrichment(mdns_data)
        except Exception as e:
            print(f"[mdns] Loop error: {e}", flush=True)
        time.sleep(interval_s)


def _mdns_passive_listener() -> None:
    """Continuously listen on the mDNS multicast group for spontaneous service announcements."""
    MDNS_ADDR = "224.0.0.251"
    MDNS_PORT = 5353
    print("[mdns-passive] Starting passive listener", flush=True)

    while True:
        ptr_records: dict = {}
        srv_records: dict = {}
        a_records:   dict = {}

        def _dec(data, offset, depth=0):
            if depth > 10: return "", offset
            labels, jumped, jump_ret = [], False, offset
            while offset < len(data):
                length = data[offset]
                if length == 0: offset += 1; break
                elif (length & 0xC0) == 0xC0:
                    if offset + 1 >= len(data): break
                    ptr = ((length & 0x3F) << 8) | data[offset + 1]
                    if not jumped: jump_ret = offset + 2
                    jumped = True
                    s, _ = _dec(data, ptr, depth + 1)
                    if s: labels.append(s)
                    break
                else:
                    end = offset + 1 + length
                    if end > len(data): break
                    labels.append(data[offset + 1:end].decode("utf-8", errors="replace"))
                    offset = end
            return ".".join(labels), (jump_ret if jumped else offset)

        def _parse(data):
            try:
                if len(data) < 12: return
                flags = struct.unpack_from(">H", data, 2)[0]
                if not (flags & 0x8000): return
                qdcount, ancount, nscount, arcount = struct.unpack_from(">HHHH", data, 4)
                offset = 12
                for _ in range(qdcount):
                    _, offset = _dec(data, offset); offset += 4
                for _ in range(ancount + nscount + arcount):
                    if offset + 10 > len(data): break
                    name, offset = _dec(data, offset)
                    if offset + 10 > len(data): break
                    rtype, _, _, rdlen = struct.unpack_from(">HHIH", data, offset)
                    offset += 10
                    rs = offset; offset += rdlen
                    if rdlen == 0 or rs + rdlen > len(data): continue
                    n = name.lower().rstrip(".")
                    if rtype == 12:
                        tgt, _ = _dec(data, rs)
                        t = tgt.lower().rstrip(".")
                        if t:
                            lst = ptr_records.setdefault(n, [])
                            if t not in lst: lst.append(t)
                    elif rtype == 33 and rdlen >= 7:
                        tgt, _ = _dec(data, rs + 6)
                        srv_records[n] = tgt.lower().rstrip(".")
                    elif rtype == 1 and rdlen == 4:
                        a_records[n] = ".".join(str(b) for b in data[rs:rs + 4])
            except Exception:
                pass

        def _flush():
            result = {}
            for hn, ip in a_records.items():
                if _cfg._is_valid_ip(ip):
                    entry = result.setdefault(ip, {"mdns_name": None, "services": []})
                    if not entry["mdns_name"]:
                        entry["mdns_name"] = hn.removesuffix(".local")
            for svc_type, instances in ptr_records.items():
                if "._dns-sd." in svc_type: continue
                parts = svc_type.removesuffix(".local").split(".")
                label = ".".join(parts[-2:]) if len(parts) >= 2 else svc_type.removesuffix(".local")
                for inst in instances:
                    hn = srv_records.get(inst)
                    ip = None
                    if hn: ip = a_records.get(hn) or a_records.get(hn + ".local")
                    if ip and _cfg._is_valid_ip(ip):
                        entry = result.setdefault(ip, {"mdns_name": None, "services": []})
                        if label not in entry["services"]: entry["services"].append(label)
            if result:
                _apply_mdns_enrichment(result)
            ptr_records.clear(); srv_records.clear(); a_records.clear()

        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try: s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError): pass
            s.bind(("", MDNS_PORT))
            mreq = struct.pack("4sL", socket.inet_aton(MDNS_ADDR), socket.INADDR_ANY)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            s.settimeout(30.0)
            pkt_count = 0
            while True:
                try:
                    data, _ = s.recvfrom(8192)
                    _parse(data)
                    pkt_count += 1
                    if pkt_count >= 100: _flush(); pkt_count = 0
                except socket.timeout:
                    if ptr_records or a_records: _flush()
                except Exception: break
        except PermissionError as e:
            print(f"[mdns-passive] permission denied: {e}", flush=True)
            time.sleep(60)
        except Exception as e:
            print(f"[mdns-passive] error, restarting: {e}", flush=True)
            time.sleep(10)
        finally:
            if s:
                try:
                    mreq = struct.pack("4sL", socket.inet_aton(MDNS_ADDR), socket.INADDR_ANY)
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
                except Exception: pass
                try: s.close()
                except Exception: pass
