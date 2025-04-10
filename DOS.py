import socket
import struct
import time
from collections import defaultdict

THRESHOLD = 20
TIME_WINDOW = 10

def create_raw_socket():
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
        return sock
    except PermissionError:
        print("[!] Run this script as root.")
        exit(1)

def parse_packet(packet):
    ip_header = packet[14:34]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    protocol = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    return protocol, src_ip

def monitor_dos():
    sock = create_raw_socket()
    print("[*] Listening for ICMP flood attempts (on all interfaces)...")
    ip_packet_count = defaultdict(list)
    try:
        while True:
            packet, _ = sock.recvfrom(65536)
            protocol, src_ip = parse_packet(packet)
            if protocol == 1:  
                now = time.time()
                ip_packet_count[src_ip].append(now)
                ip_packet_count[src_ip] = [t for t in ip_packet_count[src_ip] if now - t <= TIME_WINDOW]
                if len(ip_packet_count[src_ip]) > THRESHOLD:
                    print(f"[!] DoS Alert: {src_ip} sent {len(ip_packet_count[src_ip])} ICMP packets in {TIME_WINDOW}s")
    except KeyboardInterrupt:
        print("\n[+] Stopping DoS detector.")
        sock.close()