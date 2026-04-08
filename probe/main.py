import time
from scapy.all import ARP, Ether, srp

def scan_network(interface="eth0", ip_range="192.168.1.0/24"):
    print(f"[*] Starting scan on {ip_range}...")
    
    # Craft ARP Request
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

if __name__ == "__main__":
    while True:
        found_devices = scan_network()
        print(f"[+] Found {len(found_devices)} devices online.")
        for d in found_devices:
            print(f"    -> IP: {d['ip']} | MAC: {d['mac']}")
        
        # Wait 5 minutes for the next heartbeat scan
        time.sleep(300)
