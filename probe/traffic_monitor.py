"""
traffic_monitor.py — passive per-device traffic monitoring via ARP MITM.

Packets are forwarded (ip_forward=1), not dropped.  ip_forward is
reference-counted and is only ever restored to its original value — if
the system already had it enabled (Docker always does) we never disable it.
"""

import ipaddress
import os
import struct
import threading
import time
from collections import Counter, deque
from datetime import datetime, timezone
from typing import Optional

from scapy.all import (
    ARP, DNS, Ether, ICMP, IP, Raw, TCP, UDP,
    sendp, sniff,
)

# ---------------------------------------------------------------------------
# Common / well-known ports (anything outside this is flagged "unusual")
# ---------------------------------------------------------------------------
COMMON_PORTS = {
    20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 143, 161,
    443, 445, 465, 587, 993, 995, 3389, 5353, 5900, 8080, 8443,
}

# RFC-1918 + loopback + link-local
_LAN_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def _is_lan(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _LAN_NETS)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# ip_forward reference counter
#
# IMPORTANT: Docker (and the probe container itself) require ip_forward=1
# to route packets between containers.  We read the pre-existing value at
# import time and NEVER write a value lower than what was already there.
# ---------------------------------------------------------------------------
_ip_forward_refcount = 0
_ip_forward_lock = threading.Lock()

# Read original value once at import time so we can restore it correctly.
try:
    with open("/proc/sys/net/ipv4/ip_forward") as _f:
        _ip_forward_original = _f.read().strip()
except Exception:
    _ip_forward_original = "1"  # assume enabled if we can't read it


def _acquire_ip_forward() -> None:
    global _ip_forward_refcount
    with _ip_forward_lock:
        _ip_forward_refcount += 1
        if _ip_forward_refcount == 1 and _ip_forward_original != "1":
            try:
                with open("/proc/sys/net/ipv4/ip_forward", "w") as fh:
                    fh.write("1\n")
                print("[traffic] ip_forward enabled", flush=True)
            except Exception as exc:
                print(f"[traffic] Could not enable ip_forward: {exc}", flush=True)
        else:
            print("[traffic] ip_forward already enabled — leaving as-is", flush=True)


def _release_ip_forward() -> None:
    global _ip_forward_refcount
    with _ip_forward_lock:
        _ip_forward_refcount = max(0, _ip_forward_refcount - 1)
        if _ip_forward_refcount == 0 and _ip_forward_original != "1":
            # Only write 0 if it was 0 before we started.
            # Docker environments always have 1, so this branch is almost never taken.
            try:
                with open("/proc/sys/net/ipv4/ip_forward", "w") as fh:
                    fh.write("0\n")
                print("[traffic] ip_forward restored to 0", flush=True)
            except Exception as exc:
                print(f"[traffic] Could not restore ip_forward: {exc}", flush=True)
        elif _ip_forward_refcount == 0:
            print("[traffic] ip_forward left enabled (was pre-enabled by system)", flush=True)


# ---------------------------------------------------------------------------
# GeoIP — graceful degradation if mmdb is absent
# ---------------------------------------------------------------------------
_geoip_reader = None
_geoip_loaded = False
_geoip_lock   = threading.Lock()

_GEOIP_PATHS = [
    "/opt/geoip/GeoLite2-Country.mmdb",
    "/app/GeoLite2-Country.mmdb",
    "GeoLite2-Country.mmdb",
]


def _load_geoip() -> None:
    global _geoip_reader, _geoip_loaded
    with _geoip_lock:
        if _geoip_loaded:
            return
        _geoip_loaded = True
        for path in _GEOIP_PATHS:
            if os.path.exists(path):
                try:
                    import geoip2.database  # type: ignore
                    _geoip_reader = geoip2.database.Reader(path)
                    print(f"[traffic] GeoIP loaded from {path}", flush=True)
                    return
                except Exception as exc:
                    print(f"[traffic] GeoIP load failed ({path}): {exc}", flush=True)
        print("[traffic] GeoIP database not found — country lookup disabled", flush=True)


def _country_for_ip(ip: str) -> Optional[str]:
    if not _geoip_loaded:
        _load_geoip()
    if _geoip_reader is None:
        return None
    try:
        return _geoip_reader.country(ip).country.iso_code  # type: ignore
    except Exception:
        return None


# ---------------------------------------------------------------------------
# TLS SNI extraction (raw ClientHello, no decryption)
# ---------------------------------------------------------------------------
def _extract_tls_sni(payload: bytes) -> Optional[str]:
    try:
        if len(payload) < 5:
            return None
        if payload[0] != 0x16:  # TLS handshake record
            return None
        record_len = struct.unpack("!H", payload[3:5])[0]
        if len(payload) < 5 + record_len:
            return None
        hs = payload[5: 5 + record_len]
        if not hs or hs[0] != 0x01:  # ClientHello
            return None
        # type(1) + length(3) + version(2) + random(32)
        pos = 38
        if len(hs) < pos + 1:
            return None
        sid_len = hs[pos]; pos += 1 + sid_len
        if len(hs) < pos + 2:
            return None
        cs_len = struct.unpack("!H", hs[pos: pos + 2])[0]; pos += 2 + cs_len
        if len(hs) < pos + 1:
            return None
        comp_len = hs[pos]; pos += 1 + comp_len
        if len(hs) < pos + 2:
            return None
        ext_total = struct.unpack("!H", hs[pos: pos + 2])[0]; pos += 2
        end = pos + ext_total
        while pos + 4 <= end and pos + 4 <= len(hs):
            ext_type = struct.unpack("!H", hs[pos: pos + 2])[0]
            ext_len  = struct.unpack("!H", hs[pos + 2: pos + 4])[0]
            pos += 4
            if ext_type == 0x0000 and pos + ext_len <= len(hs):
                sni_data = hs[pos: pos + ext_len]
                if len(sni_data) >= 5 and sni_data[2] == 0x00:
                    name_len = struct.unpack("!H", sni_data[3:5])[0]
                    if 5 + name_len <= len(sni_data):
                        return sni_data[5: 5 + name_len].decode("ascii", errors="replace")
            pos += ext_len
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Stat buckets
# ---------------------------------------------------------------------------
BUCKET_SECS = 300  # 5-minute rolling window


def _new_bucket(ts: float) -> dict:
    return {
        "ts":            ts,
        "bytes_in":      0,
        "bytes_out":     0,
        "packets_in":    0,
        "packets_out":   0,
        "dns_queries":   Counter(),
        "tls_sni":       Counter(),
        "http_hosts":    Counter(),
        "top_ips":       Counter(),
        "top_ports":     Counter(),
        "top_countries": Counter(),
        "protocols":     Counter(),
        "unusual_ports": Counter(),
        "lan_bytes":     0,
        "wan_bytes":     0,
    }


def _serialise_bucket(b: dict) -> dict:
    def top(c: Counter, n: int = 10) -> list:
        return [{"k": k, "v": v} for k, v in c.most_common(n)]

    return {
        "ts":            datetime.fromtimestamp(b["ts"], tz=timezone.utc).isoformat(),
        "bytes_in":      b["bytes_in"],
        "bytes_out":     b["bytes_out"],
        "packets_in":    b["packets_in"],
        "packets_out":   b["packets_out"],
        "dns_queries":   top(b["dns_queries"]),
        "tls_sni":       top(b["tls_sni"]),
        "http_hosts":    top(b["http_hosts"]),
        "top_ips":       top(b["top_ips"]),
        "top_ports":     top(b["top_ports"]),
        "top_countries": top(b["top_countries"]),
        "protocols":     top(b["protocols"]),
        "unusual_ports": top(b["unusual_ports"]),
        "lan_bytes":     b["lan_bytes"],
        "wan_bytes":     b["wan_bytes"],
    }


# ---------------------------------------------------------------------------
# DNS parsing helper
# ---------------------------------------------------------------------------
def _parse_dns(pkt, bucket: dict, ip_domain_map: dict) -> None:
    try:
        if not pkt.haslayer(DNS):
            return
        dns = pkt[DNS]
        # Outgoing queries
        if dns.qr == 0 and dns.qdcount and dns.qdcount > 0:
            q = dns.qd
            while q and q.name != "NoPayload":
                try:
                    name = q.qname.decode("ascii", errors="replace").rstrip(".")
                    if name:
                        bucket["dns_queries"][name] += 1
                except Exception:
                    pass
                q = q.payload if hasattr(q, "payload") else None
        # Responses — build IP→domain map from A records
        if dns.qr == 1 and dns.ancount and dns.ancount > 0:
            a = dns.an
            while a and a.name != "NoPayload":
                try:
                    if hasattr(a, "rdata") and hasattr(a, "rrname"):
                        rname = a.rrname.decode("ascii", errors="replace").rstrip(".")
                        rdata = str(a.rdata)
                        if rdata and rname:
                            ip_domain_map[rdata] = rname
                except Exception:
                    pass
                a = a.payload if hasattr(a, "payload") else None
    except Exception:
        pass


# ---------------------------------------------------------------------------
# MonitorSession
# ---------------------------------------------------------------------------
class MonitorSession:
    def __init__(
        self,
        target_ip:   str,
        target_mac:  str,
        mac:         str,
        gateway_ip:  str,
        gateway_mac: str,
        iface:       str,
    ) -> None:
        self.target_ip   = target_ip
        self.target_mac  = target_mac
        self.mac         = mac
        self.gateway_ip  = gateway_ip
        self.gateway_mac = gateway_mac
        self.iface       = iface

        self._stop_event   = threading.Event()
        self._lock         = threading.Lock()
        self._ip_domain_map: dict[str, str] = {}
        # 24 h of 5-min buckets = 288 max
        self._buckets: deque = deque(maxlen=288)
        self._current        = _new_bucket(time.time())
        self.started_at      = datetime.now(timezone.utc)

    # ── Lifecycle ──────────────────────────────────────────────────────────────
    def start(self) -> None:
        _acquire_ip_forward()
        # ARP thread is intentionally non-daemon: it must finish sending restore
        # packets before the process can exit, even during SIGTERM shutdown.
        self._arp_thread = threading.Thread(
            target=self._arp_loop,
            daemon=False,
            name=f"traffic-arp-{self.mac}",
        )
        self._arp_thread.start()
        for target, name in [
            (self._sniff_loop,  f"traffic-sniff-{self.mac}"),
            (self._rotate_loop, f"traffic-rotate-{self.mac}"),
        ]:
            threading.Thread(target=target, daemon=True, name=name).start()
        print(f"[traffic] Monitor started: {self.target_ip} ({self.mac})", flush=True)

    def stop(self) -> None:
        # Signal all threads to stop.  The ARP thread will send restore packets
        # and call _release_ip_forward() before it exits.  Call wait_for_stop()
        # if you need to block until cleanup is complete (e.g. in signal handlers).
        self._stop_event.set()
        print(f"[traffic] Monitor stopping: {self.target_ip} ({self.mac})", flush=True)

    def wait_for_stop(self, timeout: float = 5.0) -> None:
        """Block until the ARP restore thread finishes (or timeout expires)."""
        if hasattr(self, "_arp_thread") and self._arp_thread.is_alive():
            self._arp_thread.join(timeout=timeout)

    # ── ARP poison loop (forward mode — ip_forward=1 passes packets through) ──
    def _arp_loop(self) -> None:
        poison_target = Ether(dst=self.target_mac) / ARP(
            op=2,
            pdst=self.target_ip,   hwdst=self.target_mac,
            psrc=self.gateway_ip,
            # hwsrc unset → Scapy fills in the interface MAC (probe poses as gateway)
        )
        poison_gateway = Ether(dst=self.gateway_mac) / ARP(
            op=2,
            pdst=self.gateway_ip,  hwdst=self.gateway_mac,
            psrc=self.target_ip,
            # hwsrc unset → Scapy fills in the interface MAC (probe poses as target)
        )

        try:
            while not self._stop_event.is_set():
                try:
                    sendp(poison_target,  iface=self.iface, verbose=0)
                    sendp(poison_gateway, iface=self.iface, verbose=0)
                except Exception as exc:
                    print(f"[traffic] ARP send error: {exc}", flush=True)
                self._stop_event.wait(timeout=2)
        finally:
            # ── Restore phase ──────────────────────────────────────────────────
            # This block runs whether we exited normally, via stop(), or due to
            # an unhandled exception.  hwsrc must be set to the real MAC —
            # leaving it unset would use the probe's MAC again (same as poison).
            try:
                restore_to_target = Ether(dst=self.target_mac) / ARP(
                    op=2,
                    pdst=self.target_ip,   hwdst=self.target_mac,
                    psrc=self.gateway_ip,  hwsrc=self.gateway_mac,
                )
                restore_to_gateway = Ether(dst=self.gateway_mac) / ARP(
                    op=2,
                    pdst=self.gateway_ip,  hwdst=self.gateway_mac,
                    psrc=self.target_ip,   hwsrc=self.target_mac,
                )
                for _ in range(5):
                    sendp(restore_to_target,  iface=self.iface, verbose=0)
                    sendp(restore_to_gateway, iface=self.iface, verbose=0)
                    time.sleep(0.15)
                print(f"[traffic] ARP tables restored: {self.target_ip} ({self.mac})", flush=True)
            except Exception as exc:
                print(f"[traffic] ARP restore error: {exc}", flush=True)

            # Always release ip_forward AFTER restore packets are on the wire
            _release_ip_forward()
            print(f"[traffic] Monitor stopped: {self.target_ip} ({self.mac})", flush=True)

    # ── Packet capture loop ────────────────────────────────────────────────────
    def _sniff_loop(self) -> None:
        # Use a short timeout so the loop re-checks the stop event even when
        # the monitored device is idle (stop_filter only fires per-packet).
        while not self._stop_event.is_set():
            try:
                sniff(
                    iface=self.iface,
                    filter=f"host {self.target_ip}",
                    prn=self._process_packet,
                    store=0,
                    timeout=2,
                )
            except Exception as exc:
                print(f"[traffic] sniff error ({self.target_ip}): {exc}", flush=True)
                break

    # ── Per-packet accounting ──────────────────────────────────────────────────
    def _process_packet(self, pkt) -> None:
        try:
            if not pkt.haslayer(IP):
                return
            ip_layer = pkt[IP]
            src = ip_layer.src
            dst = ip_layer.dst
            pkt_len = len(pkt)
            outgoing = (src == self.target_ip)

            with self._lock:
                b = self._current

                if outgoing:
                    b["bytes_out"]   += pkt_len
                    b["packets_out"] += 1
                    remote = dst
                    if _is_lan(remote):
                        b["lan_bytes"] += pkt_len
                    else:
                        b["wan_bytes"] += pkt_len
                        country = _country_for_ip(remote)
                        if country:
                            b["top_countries"][country] += 1
                    b["top_ips"][remote] += 1
                else:
                    b["bytes_in"]   += pkt_len
                    b["packets_in"] += 1

                if pkt.haslayer(TCP):
                    b["protocols"]["TCP"] += 1
                    tcp = pkt[TCP]
                    port = tcp.dport if outgoing else tcp.sport
                    b["top_ports"][port] += 1
                    if port not in COMMON_PORTS:
                        b["unusual_ports"][port] += 1
                    if outgoing and port == 443 and pkt.haslayer(Raw):
                        sni = _extract_tls_sni(bytes(pkt[Raw]))
                        if sni:
                            b["tls_sni"][sni] += 1
                    if outgoing and port == 80 and pkt.haslayer(Raw):
                        try:
                            text = bytes(pkt[Raw]).decode("ascii", errors="ignore")
                            for line in text.split("\r\n"):
                                if line.lower().startswith("host:"):
                                    host = line[5:].strip()
                                    if host:
                                        b["http_hosts"][host] += 1
                                    break
                        except Exception:
                            pass
                elif pkt.haslayer(UDP):
                    b["protocols"]["UDP"] += 1
                    udp = pkt[UDP]
                    port = udp.dport if outgoing else udp.sport
                    b["top_ports"][port] += 1
                    if port not in COMMON_PORTS:
                        b["unusual_ports"][port] += 1
                    if udp.sport == 53 or udp.dport == 53:
                        _parse_dns(pkt, b, self._ip_domain_map)
                elif pkt.haslayer(ICMP):
                    b["protocols"]["ICMP"] += 1

        except Exception as exc:
            print(f"[traffic] packet error: {exc}", flush=True)

    # ── Bucket rotation (every 5 min) ─────────────────────────────────────────
    def _rotate_loop(self) -> None:
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=BUCKET_SECS)
            if not self._stop_event.is_set():
                with self._lock:
                    self._buckets.append(self._current)
                    self._current = _new_bucket(time.time())

    # ── Stats export ───────────────────────────────────────────────────────────
    def get_stats(self) -> dict:
        with self._lock:
            history = [_serialise_bucket(b) for b in self._buckets]
            current = _serialise_bucket(self._current)
        return {
            "mac":        self.mac,
            "target_ip":  self.target_ip,
            "started_at": self.started_at.isoformat(),
            "current":    current,
            "history":    history,
        }


# ---------------------------------------------------------------------------
# Session registry (used by probe/main.py)
# ---------------------------------------------------------------------------
_monitor_sessions: dict[str, MonitorSession] = {}
_sessions_lock = threading.Lock()


def get_session(mac: str) -> Optional[MonitorSession]:
    with _sessions_lock:
        return _monitor_sessions.get(mac.lower())


def get_session_by_ip(ip: str) -> Optional[MonitorSession]:
    with _sessions_lock:
        for s in _monitor_sessions.values():
            if s.target_ip == ip:
                return s
    return None


def list_sessions() -> list[dict]:
    with _sessions_lock:
        return [
            {
                "mac":        s.mac,
                "target_ip":  s.target_ip,
                "started_at": s.started_at.isoformat(),
            }
            for s in _monitor_sessions.values()
        ]


def list_sessions_with_stats() -> list[dict]:
    with _sessions_lock:
        sessions = list(_monitor_sessions.values())
    return [s.get_stats() for s in sessions]


def stop_monitor_by_ip(ip: str) -> bool:
    mac = None
    with _sessions_lock:
        for m, s in _monitor_sessions.items():
            if s.target_ip == ip:
                mac = m
                break
    if mac:
        return stop_monitor(mac)
    return False


def start_monitor(
    target_ip:   str,
    target_mac:  str,
    gateway_ip:  str,
    gateway_mac: str,
    iface:       str,
) -> MonitorSession:
    mac = target_mac.lower()
    with _sessions_lock:
        if mac in _monitor_sessions:
            return _monitor_sessions[mac]
        session = MonitorSession(
            target_ip=target_ip,
            target_mac=mac,
            mac=mac,
            gateway_ip=gateway_ip,
            gateway_mac=gateway_mac,
            iface=iface,
        )
        _monitor_sessions[mac] = session
    session.start()
    return session


def stop_monitor(mac: str) -> bool:
    mac = mac.lower()
    with _sessions_lock:
        session = _monitor_sessions.pop(mac, None)
    if session:
        session.stop()
        return True
    return False


def stop_all_and_wait(timeout: float = 5.0) -> None:
    """
    Stop every active monitor session and block until all ARP restore threads
    have finished sending restore packets.  Called from the SIGTERM handler so
    the process does not exit before ARP tables on monitored devices are healed.
    """
    with _sessions_lock:
        sessions = list(_monitor_sessions.values())
        _monitor_sessions.clear()

    for session in sessions:
        session.stop()

    for session in sessions:
        session.wait_for_stop(timeout=timeout)
