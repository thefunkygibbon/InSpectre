import threading
import time
from datetime import datetime, timezone

from scapy.all import ARP, Ether, IP, TCP, sr, srp

import probe_config as _cfg
from probe_models import Session, Device, _scan_lock, _scanning
from probe_ip import _write_event

# Per-MAC per-port consecutive-absent counters for baseline drift detection.
# Intentionally in-memory — resets on probe restart (acceptable).
_port_absent_counts: dict = {}

# Cap simultaneous deep scans so many newly-detected devices don't all scan at once
_deep_scan_semaphore = threading.Semaphore(3)


def arp_scan(interface: str, ip_range: str) -> list[dict]:
    pkt    = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    result = srp(pkt, iface=interface, timeout=5, retry=_cfg.ARP_SCAN_RETRY, verbose=0)[0]
    return [{"ip": rcv.psrc, "mac": rcv.hwsrc.lower()} for _, rcv in result]


def _port_severity(device) -> str:
    dtype = (getattr(device, "device_type_override", None) or "").lower()
    is_important = bool(getattr(device, "is_important", False))
    iot_types    = {"iot", "camera", "smart_plug", "smart_home", "console"}
    server_types = {"server", "nas"}
    if not dtype or dtype in iot_types:
        return "critical"
    if is_important or dtype in server_types:
        return "warning"
    return "info"


def _scapy_syn_scan(ip: str, workers: int | None = None) -> list[int]:
    """SYN scan via Scapy raw sockets (requires CAP_NET_RAW)."""
    try:
        from scapy.all import conf as scapy_conf
        scapy_conf.verb = 0
        open_ports: list[int] = []
        batch = 4096
        for start in range(1, 65536, batch):
            end = min(start + batch, 65536)
            pkts = [IP(dst=ip) / TCP(dport=p, flags="S") for p in range(start, end)]
            answered, _ = sr(pkts, timeout=3, verbose=0)
            open_ports.extend(
                snt[TCP].dport
                for snt, rcv in answered
                if rcv.haslayer(TCP) and (rcv[TCP].flags & 0x12) == 0x12
            )
        return sorted(set(open_ports))
    except Exception as exc:
        print(f"[scan] Scapy SYN sweep error for {ip}: {exc}", flush=True)
        return []


def _tcp_connect_sweep(ip: str, workers: int | None = None) -> list[int]:
    """Primary port scanner using TCP connect (200 concurrent workers by default)."""
    import concurrent.futures
    import socket as _socket

    w       = workers if workers is not None else _cfg.PORT_SCAN_WORKERS
    TIMEOUT = 1.0
    MAX_SWEEP_S = max(660, int((65535 / max(w, 1)) * 1.5 + 60))

    def _check(port: int) -> int | None:
        try:
            with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
                s.settimeout(TIMEOUT)
                return port if s.connect_ex((ip, port)) == 0 else None
        except Exception:
            return None

    open_ports: list[int] = []
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=w)
    try:
        futs = {ex.submit(_check, p): p for p in range(1, 65536)}
        try:
            for fut in concurrent.futures.as_completed(futs, timeout=MAX_SWEEP_S):
                try:
                    r = fut.result()
                    if r is not None:
                        open_ports.append(r)
                except Exception:
                    pass
        except concurrent.futures.TimeoutError:
            print(
                f"[scan] TCP sweep exceeded {MAX_SWEEP_S}s for {ip} — "
                f"returning partial results ({len(open_ports)} ports found so far)",
                flush=True,
            )
    except Exception as exc:
        print(f"[scan] TCP sweep error for {ip}: {exc}", flush=True)
    finally:
        ex.shutdown(wait=True, cancel_futures=True)
    return sorted(open_ports)


def _update_port_baseline(mac: str, ip: str, current_ports: list[int]) -> None:
    """Compare current port set against confirmed baseline; write port_opened/port_closed events."""
    current_set = frozenset(current_ports)
    session = Session()
    try:
        device = session.get(Device, mac)
        if not device:
            return

        baseline   = device.baseline_ports
        scan_count = device.baseline_scan_count or 0
        threshold  = _cfg.BASELINE_SCAN_COUNT_THRESHOLD

        if baseline is None:
            device.baseline_ports      = sorted(current_set)
            device.baseline_scan_count = 1
            session.commit()
            print(f"[baseline] {ip} ({mac}): baseline seeded with {len(current_set)} port(s)", flush=True)
            return

        baseline_set = frozenset(baseline)

        if current_set == baseline_set:
            device.baseline_scan_count = scan_count + 1
            session.commit()
            if scan_count + 1 == threshold:
                print(f"[baseline] {ip} ({mac}): baseline confirmed after {threshold} matching scans", flush=True)
            return

        if scan_count < threshold:
            device.baseline_ports      = sorted(current_set)
            device.baseline_scan_count = 1
            session.commit()
            print(f"[baseline] {ip} ({mac}): tentative baseline reset (not yet confirmed)", flush=True)
            return

        severity  = _port_severity(device)
        new_ports  = current_set - baseline_set
        gone_ports = baseline_set - current_set

        for port in sorted(new_ports):
            _write_event(mac, "port_opened", {"port": port, "severity": severity})
            print(f"[baseline] NEW port vs baseline on {ip}: port {port} severity={severity}", flush=True)

        for port in sorted(gone_ports):
            absent_map = _port_absent_counts.setdefault(mac, {})
            absent_map[port] = absent_map.get(port, 0) + 1
            if absent_map[port] >= 2:
                _write_event(mac, "port_closed", {"port": port, "severity": "info"})
                print(f"[baseline] CLOSED port vs baseline on {ip}: port {port}", flush=True)

        if mac in _port_absent_counts:
            for port in list(_port_absent_counts[mac].keys()):
                if port in current_set:
                    del _port_absent_counts[mac][port]

    except Exception as e:
        session.rollback()
        print(f"[baseline] Error for {mac}: {e}", flush=True)
    finally:
        session.close()


def _run_deep_scan_thread(ip: str, mac: str) -> None:
    with _deep_scan_semaphore:
        try:
            from probe_hostname import _get_default_gateway
            from probe_fingerprint import _run_nerva_fingerprint

            t0 = time.monotonic()
            is_gw   = (ip == _get_default_gateway())
            workers = _cfg.GATEWAY_SCAN_WORKERS if is_gw else _cfg.PORT_SCAN_WORKERS
            method  = _cfg.PORT_SCAN_METHOD
            print(f"[scan] {method} scan starting: {ip} ({mac}) workers={workers}", flush=True)
            if method == "scapy_syn":
                fast_ports = _scapy_syn_scan(ip, workers=workers)
            else:
                fast_ports = _tcp_connect_sweep(ip, workers=workers)
            elapsed = round(time.monotonic() - t0, 1)
            print(f"[scan] {len(fast_ports)} open TCP port(s) on {ip} in {elapsed}s", flush=True)

            scan_results = {
                "scanned_at":    datetime.now(timezone.utc).isoformat(),
                "open_ports":    [{"port": p, "proto": "tcp", "service": ""} for p in fast_ports],
                "pipeline_stage": "ports_done",
            }

            session = Session()
            try:
                device = session.get(Device, mac)
                if device:
                    old_scan  = device.scan_results or {}
                    old_ports = {(p.get("port"), p.get("proto")) for p in (old_scan.get("open_ports") or [])}
                    new_ports_set = {(p.get("port"), p.get("proto")) for p in scan_results["open_ports"]}
                    is_rescan = bool(old_scan)

                    device.scan_results      = scan_results
                    device.deep_scanned      = True
                    device.deep_scan_last_run = datetime.now(timezone.utc)
                    session.commit()

                    _write_event(mac, "scan_complete", {"ports": len(fast_ports), "os": None})

                    if is_rescan and old_ports != new_ports_set:
                        added   = [{"port": p[0], "proto": p[1]} for p in (new_ports_set - old_ports)]
                        removed = [{"port": p[0], "proto": p[1]} for p in (old_ports - new_ports_set)]
                        _write_event(mac, "port_change", {"added": added, "removed": removed})
                        print(f"[scan] Port change on {ip} ({mac}): +{len(added)} -{len(removed)}", flush=True)
            except Exception as e:
                session.rollback()
                print(f"[DB] Scan save error {mac}: {e}", flush=True)
            finally:
                session.close()

            if _cfg.ENABLE_SERVICE_FINGERPRINTING:
                threading.Thread(
                    target=_run_nerva_fingerprint,
                    args=(ip, mac, fast_ports),
                    daemon=True,
                    name=f"nerva-{mac}",
                ).start()

            _update_port_baseline(mac, ip, fast_ports)

        finally:
            with _scan_lock:
                _scanning.discard(mac)


def trigger_deep_scan(ip: str, mac: str) -> None:
    if not _cfg.ENABLE_PORT_SCANNING:
        return
    if not _cfg._is_valid_ip(ip):
        return
    try:
        _s = Session()
        try:
            _dev = _s.get(Device, mac)
            if _dev and getattr(_dev, "is_ignored", False):
                return
            if (_dev and getattr(_dev, "group_id", None)
                    and not getattr(_dev, "group_primary", False)
                    and not _cfg.SCAN_GROUPED_MEMBERS):
                return
        finally:
            _s.close()
    except Exception:
        pass
    with _scan_lock:
        if mac in _scanning:
            return
        _scanning.add(mac)
    threading.Thread(target=_run_deep_scan_thread, args=(ip, mac), daemon=True).start()
