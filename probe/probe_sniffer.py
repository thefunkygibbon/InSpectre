import ipaddress
import threading

from scapy.all import ARP, BOOTP, DHCP, Ether, sniff

import probe_config as _cfg
from probe_models import (
    Session,
    _sniffer_queue, _dhcp_queue,
)

# Updated at startup in start_arp_sniffer() once INTERFACE is finalised
_PROBE_OWN_MAC: str | None = _cfg._get_own_mac(_cfg.INTERFACE)


def process_arp_packet(packet) -> None:
    if not _cfg.ENABLE_PASSIVE_SNIFFER:
        return
    if not packet.haslayer(ARP):
        return
    if packet.haslayer(Ether):
        ether_src = (packet[Ether].src or "").lower().strip()
        if _PROBE_OWN_MAC and ether_src == _PROBE_OWN_MAC:
            return
    arp = packet[ARP]
    mac = (arp.hwsrc or "").lower().strip()
    ip  = (arp.psrc  or "").strip()
    if not mac or not ip or mac == "ff:ff:ff:ff:ff:ff" or mac.startswith("01:"):
        return
    if not _cfg._is_valid_ip(ip):
        return
    if _cfg.SNIFFER_SUBNET_FILTER:
        try:
            if ipaddress.ip_address(ip) not in ipaddress.ip_network(_cfg.IP_RANGE, strict=False):
                return
        except ValueError:
            return
    try:
        _sniffer_queue.put_nowait((mac, ip))
    except Exception:
        pass


def _sniffer_worker() -> None:
    from probe_device import upsert_seen_device
    while True:
        try:
            mac, ip = _sniffer_queue.get(timeout=1)
            upsert_seen_device(mac, ip, "sniffer")
            _sniffer_queue.task_done()
        except Exception:
            continue


def process_dhcp_packet(packet) -> None:
    """Extract DHCP Options 12/55/60 from client broadcasts and queue for DB write."""
    if not _cfg.ENABLE_PASSIVE_SNIFFER:
        return
    if not packet.haslayer(BOOTP) or not packet.haslayer(DHCP):
        return
    bootp = packet[BOOTP]
    if bootp.op != 1:
        return

    mac_bytes = bytes(bootp.chaddr)[:6]
    mac = ":".join(f"{b:02x}" for b in mac_bytes)
    if not mac or mac == "00:00:00:00:00:00" or mac == "ff:ff:ff:ff:ff:ff":
        return

    opts: dict = {}
    for opt in packet[DHCP].options:
        if isinstance(opt, tuple) and len(opt) == 2:
            opts[opt[0]] = opt[1]

    raw_msg_type = opts.get("message-type", 0)
    if isinstance(raw_msg_type, bytes):
        msg_type = int(raw_msg_type[0]) if raw_msg_type else 0
    else:
        try:
            msg_type = int(raw_msg_type)
        except Exception:
            msg_type = 0
    if msg_type not in (1, 3, 8):
        return

    def _decode(v) -> str | None:
        if v is None:
            return None
        if isinstance(v, bytes):
            return v.decode("utf-8", errors="replace").strip() or None
        return str(v).strip() or None

    hostname     = _decode(opts.get("hostname"))
    vendor_class = _decode(opts.get("vendor_class_id"))

    raw_pl = opts.get("param_req_list")
    if isinstance(raw_pl, bytes):
        opt55 = list(raw_pl)
    elif isinstance(raw_pl, (list, tuple)):
        opt55 = [int(x) for x in raw_pl]
    else:
        opt55 = []

    _msg_name = {1: "Discover", 3: "Request", 8: "Inform"}.get(msg_type, str(msg_type))
    print(f"[dhcp] {mac}  type={_msg_name}"
          f"  vc={vendor_class!r}  host={hostname!r}  opt55_len={len(opt55)}", flush=True)
    try:
        _dhcp_queue.put_nowait((mac, hostname, vendor_class, opt55 if opt55 else None))
    except Exception:
        pass


def _dhcp_worker() -> None:
    from probe_device import _upsert_dhcp_info
    while True:
        try:
            mac, hostname, vendor_class, opt55 = _dhcp_queue.get(timeout=1)
            _upsert_dhcp_info(mac, hostname, vendor_class, opt55)
            _dhcp_queue.task_done()
        except Exception:
            continue


def _dispatch_packet(packet) -> None:
    if packet.haslayer(ARP):
        process_arp_packet(packet)
    elif packet.haslayer(DHCP):
        process_dhcp_packet(packet)


def start_arp_sniffer() -> None:
    global _PROBE_OWN_MAC
    own = _cfg._get_own_mac(_cfg.INTERFACE)
    if own:
        _PROBE_OWN_MAC = own
        print(f"[*] Probe interface MAC: {_PROBE_OWN_MAC} (own ARP packets ignored)", flush=True)
    for i in range(_cfg.SNIFFER_WORKERS):
        threading.Thread(target=_sniffer_worker, name=f"sniffer-worker-{i}", daemon=True).start()
    threading.Thread(target=_dhcp_worker, name="dhcp-worker", daemon=True).start()
    print(f"[*] Passive ARP+DHCP sniffer on {_cfg.INTERFACE} ({_cfg.SNIFFER_WORKERS} ARP workers)", flush=True)
    sniff(iface=_cfg.INTERFACE, filter="arp or (udp and (port 67 or port 68))",
          store=False, prn=_dispatch_packet)
