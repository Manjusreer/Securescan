from scapy.all import sniff, IP, ICMP, ARP
from collections import defaultdict
import logging
import time

# Setup logging
logging.basicConfig(filename="alerts.log", level=logging.INFO, format='%(asctime)s - %(message)s')

print("[+] SecureScan NIDS is running...")

# ICMP tracking
icmp_counts = defaultdict(list)
icmp_threshold = 45  # Adjust as needed
icmp_window = 10     # seconds

# ARP spoof tracking
arp_table = {}

# Function to handle each packet
def process_packet(packet):
    # ICMP flood & Ping of Death detection
    if packet.haslayer(ICMP):
        src_ip = packet[IP].src
        icmp_counts[src_ip].append(time.time())

        # Remove old timestamps outside the window
        icmp_counts[src_ip] = [t for t in icmp_counts[src_ip] if time.time() - t <= icmp_window]

        count = len(icmp_counts[src_ip])
        print(f"[DEBUG] ICMP from {src_ip}: count = {count}")

        # ICMP flood detection
        if count > icmp_threshold:
            alert = f"[!] ALERT: Possible ICMP flood from {src_ip}"
            print(alert)
            logging.info(alert)
            icmp_counts[src_ip] = []  # reset count after alert

        # Ping of Death detection (check for large packet size)
        if packet.haslayer(IP) and len(packet) > 1000:  # adjust threshold as needed
            alert = f"[!] ALERT: Possible Ping of Death attack from {src_ip} (size: {len(packet)} bytes)"
            print(alert)
            logging.info(alert)

    # ARP spoofing detection
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply (is-at)
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        if ip in arp_table:
            if arp_table[ip] != mac:
                alert = f"[!] ALERT: Possible ARP spoofing detected! {ip} is claiming {mac}, expected {arp_table[ip]}"
                print(alert)
                logging.info(alert)
        else:
            arp_table[ip] = mac

# Start sniffing
sniff(iface="eth0", prn=process_packet, store=0)
