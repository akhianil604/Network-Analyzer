import socket
import struct
import time
from collections import defaultdict

# Constants
THRESHOLD = 20       # Number of ICMP packets allowed per time window before triggering an alert
TIME_WINDOW = 10     # Time window in seconds to track packet frequency

def create_raw_socket():
    """
    Creates a raw socket to capture all network traffic on the interface.
    Requires root privileges.
    """
    try:
        # AF_PACKET is used to receive raw packets including Ethernet headers
        # SOCK_RAW allows reading raw packets
        # ETH_P_IP (0x0800) is used to capture IP packets only
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
        return sock
    except PermissionError:
        print("[!] Run this script as root.")
        exit(1)

def parse_packet(packet):
    """
    Parses the IP header of a raw Ethernet packet to extract the protocol type and source IP address.
    """
    ip_header = packet[14:34]  # Skip Ethernet header (14 bytes) and extract 20-byte IP header
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)  # Unpack IP header
    protocol = iph[6]  # Get protocol (e.g., 1 for ICMP)
    src_ip = socket.inet_ntoa(iph[8])  # Convert source IP address from binary to string
    return protocol, src_ip

def monitor_dos():
    """
    Monitors incoming network traffic for ICMP flood attacks.
    If a single IP sends more than THRESHOLD ICMP packets in TIME_WINDOW seconds, it raises an alert.
    """
    sock = create_raw_socket()
    print("[*] Listening for ICMP flood attempts (on all interfaces)...")
    
    # Dictionary to track ICMP packet timestamps per source IP
    ip_packet_count = defaultdict(list)

    try:
        while True:
            # Receive packet from the network
            packet, _ = sock.recvfrom(65536)

            # Parse the packet for protocol and source IP
            protocol, src_ip = parse_packet(packet)

            # Check if the packet is ICMP (protocol 1)
            if protocol == 1:
                now = time.time()
                ip_packet_count[src_ip].append(now)  # Record current timestamp

                # Remove timestamps outside the TIME_WINDOW
                ip_packet_count[src_ip] = [t for t in ip_packet_count[src_ip] if now - t <= TIME_WINDOW]

                # Raise alert if packet count exceeds threshold
                if len(ip_packet_count[src_ip]) > THRESHOLD:
                    print(f"[!] DoS Alert: {src_ip} sent {len(ip_packet_count[src_ip])} ICMP packets in {TIME_WINDOW}s")

    except KeyboardInterrupt:
        # Graceful shutdown on Ctrl+C
        print("\n[+] Stopping DoS detector.")
        sock.close()