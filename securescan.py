from scapy.all import sniff, IP, ICMP, TCP, ARP, DNS, DNSQR, UDP
from datetime import datetime
from collections import defaultdict
import logging

# Configure logging
logging.basicConfig(filename="alerts.log", level=logging.INFO, format='%(asctime)s - %(message)s')

print("[+] SecureScan NIDS is running...")

# Data structures for tracking
icmp_timestamps = defaultdict(list)
tcp_syn_counter = defaultdict(list)
arp_spoof_detected = set()
dns_request_counter = defaultdict(list)

# Thresholds
ICMP_THRESHOLD = 45
PING_OF_DEATH_SIZE = 1000
TCP_THRESHOLD = 10
DNS_THRESHOLD = 3
DOMAIN_LENGTH_THRESHOLD = 50  # characters

def detect_packet(packet):
    now = datetime.now()

    # ICMP Flood & Ping of Death
    if packet.haslayer(ICMP) and packet.haslayer(IP):
        ip = packet[IP].src
        icmp_timestamps[ip].append(now)
        icmp_timestamps[ip] = [t for t in icmp_timestamps[ip] if (now - t).total_seconds() <= 10]
        if len(icmp_timestamps[ip]) > ICMP_THRESHOLD:
            alert = f"[!] ALERT: Possible ICMP flood from {ip}"
            print(alert)
            logging.info(alert)

        if len(packet) > PING_OF_DEATH_SIZE:
            alert = f"[!] ALERT: Possible Ping of Death from {ip} (size = {len(packet)} bytes)"
            print(alert)
            logging.info(alert)

    # ARP Spoofing Detection
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        sender_ip = packet[ARP].psrc
        sender_mac = packet[ARP].hwsrc
        if sender_ip in arp_spoof_detected:
            return
        arp_spoof_detected.add(sender_ip)
        alert = f"[!] ALERT: ARP spoofing attempt from IP: {sender_ip}, MAC: {sender_mac}"
        print(alert)
        logging.info(alert)

    # TCP Brute-force Login Detection
    if packet.haslayer(TCP) and packet.haslayer(IP):
        if packet[TCP].flags == "S":  # SYN flag
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            key = (src_ip, dst_port)
            tcp_syn_counter[key] = [t for t in tcp_syn_counter[key] if (now - t).total_seconds() <= 10]
            tcp_syn_counter[key].append(now)
            if len(tcp_syn_counter[key]) > TCP_THRESHOLD:
                alert = f"[!] ALERT: Possible TCP brute-force attempt from {src_ip} to port {dst_port}"
                print(alert)
                logging.info(alert)
                tcp_syn_counter[key].clear()

    # DNS Tunneling Detection
    if packet.haslayer(DNS) and packet.haslayer(DNSQR) and packet.haslayer(UDP):
        print(f"[DEBUG] DNS query from {packet[IP].src}: {packet[DNSQR].qname.decode().strip('.')}")
        src_ip = packet[IP].src
        query_name = packet[DNSQR].qname.decode().strip('.')
        dns_request_counter[src_ip].append(now)

        # Filter out timestamps older than 10 seconds
        dns_request_counter[src_ip] = [t for t in dns_request_counter[src_ip] if (now - t).total_seconds() <= 10]

        # Detect high frequency of DNS requests
        if len(dns_request_counter[src_ip]) > DNS_THRESHOLD:
            alert = f"[!] ALERT: High frequency DNS queries from {src_ip} - Possible DNS tunneling"
            print(alert)
            logging.info(alert)
            dns_request_counter[src_ip].clear()

        # Detect unusually long domain names
        if len(query_name) > DOMAIN_LENGTH_THRESHOLD:
            alert = f"[!] ALERT: Suspiciously long DNS query from {src_ip}: {query_name}"
            print(alert)
            logging.info(alert)



# Start packet sniffing
sniff(filter="udp port 53", prn=detect_packet, store=0)
