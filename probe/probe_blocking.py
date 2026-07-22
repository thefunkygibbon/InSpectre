import ipaddress
import subprocess
import threading
import time

from scapy.all import ARP, Ether, sendp, srp

import probe_config as _cfg
from probe_models import Session, Device

_blocked_devices: dict[str, dict] = {}
_blocked_lock    = threading.Lock()


def _get_mac_for_ip(ip: str) -> str | None:
    try:
        pkt    = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        result = srp(pkt, iface=_cfg.INTERFACE, timeout=3, retry=1, verbose=0)[0]
        if result:
            return result[0][1].hwsrc.lower()
    except Exception as e:
        print(f"[block] MAC lookup failed for {ip}: {e}", flush=True)
    return None


def _block_table_id(target_ip: str) -> int:
    return 10000 + (int(ipaddress.ip_address(target_ip)) % 50000)


def _ip_rule_block(target_ip: str) -> None:
    table = _block_table_id(target_ip)
    steps = [
        ["ip", "route", "replace", "blackhole", "default", "table", str(table)],
        ["ip", "rule",  "add", "from", target_ip, "table", str(table), "priority", "100"],
    ]
    for cmd in steps:
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=5)
            print(f"[block] {' '.join(cmd)}: {'OK' if r.returncode == 0 else r.stderr.decode().strip()}", flush=True)
        except Exception as e:
            print(f"[block] ip rule error: {e}", flush=True)


def _ip_rule_unblock(target_ip: str) -> None:
    table = _block_table_id(target_ip)
    for cmd in [
        ["ip", "rule",  "del", "from", target_ip, "table", str(table), "priority", "100"],
        ["ip", "route", "del", "blackhole", "default", "table", str(table)],
    ]:
        try:
            subprocess.run(cmd, capture_output=True, timeout=5)
        except Exception:
            pass


def _iptables(action: str, target_ip: str) -> None:
    """iptables FORWARD DROP as defence-in-depth alongside the ip-rule blackhole."""
    for direction in ["-s", "-d"]:
        cmd = ["iptables", action, "FORWARD", direction, target_ip, "-j", "DROP"]
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=5)
            if r.returncode == 0:
                print(f"[block] {' '.join(cmd)}: OK", flush=True)
            elif action != "-D":
                print(f"[block] {' '.join(cmd)}: {r.stderr.decode().strip()}", flush=True)
        except FileNotFoundError:
            if action == "-I":
                print("[block] iptables not found — skipping (ip rule is primary)", flush=True)
        except Exception as e:
            if action == "-I":
                print(f"[block] iptables error: {e}", flush=True)


def _arp_spoof_loop(
    target_ip: str, target_mac: str,
    gateway_ip: str, gateway_mac: str,
    iface: str, stop_event: threading.Event,
) -> None:
    """Block internet access via ARP spoofing + iptables FORWARD DROP.
    Both are reversed cleanly when stop_event is set."""
    print(
        f"[block] Starting block: {target_ip} ({target_mac}), "
        f"gateway {gateway_ip} ({gateway_mac})",
        flush=True,
    )

    _ip_rule_block(target_ip)
    _iptables("-I", target_ip)

    poison_target = Ether(dst=target_mac) / ARP(
        op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip,
    )
    poison_gateway = Ether(dst=gateway_mac) / ARP(
        op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip,
    )

    while not stop_event.is_set():
        try:
            sendp(poison_target,  iface=iface, verbose=0)
            sendp(poison_gateway, iface=iface, verbose=0)
        except Exception as e:
            print(f"[block] send error: {e}", flush=True)
        stop_event.wait(timeout=2)

    _ip_rule_unblock(target_ip)
    _iptables("-D", target_ip)

    print(f"[block] Restoring ARP for {target_ip}", flush=True)
    restore_target = Ether(dst=target_mac) / ARP(
        op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac,
    )
    restore_gateway = Ether(dst=gateway_mac) / ARP(
        op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac,
    )
    for _ in range(5):
        try:
            sendp(restore_target,  iface=iface, verbose=0)
            sendp(restore_gateway, iface=iface, verbose=0)
        except Exception:
            pass
        time.sleep(0.5)
    print(f"[block] Block lifted for {target_ip}", flush=True)
