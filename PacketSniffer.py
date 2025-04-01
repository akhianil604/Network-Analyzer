import socket
import struct
import csv
import datetime
import os
import base64
import hashlib

ETH_P_ALL = 0x0003
BUFFER_SIZE = 65536
CSV_FILE = "captured_packets.csv"

with open(CSV_FILE, "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Packet Size"])

def parse_ip_header(data):
    ip_header = struct.unpack("!BBHHHBBH4s4s", data[:20])
    version_ihl = ip_header[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4
    protocol = ip_header[6]
    src_ip = socket.inet_ntoa(ip_header[8])
    dest_ip = socket.inet_ntoa(ip_header[9])
    return version, ihl, protocol, src_ip, dest_ip, data[ihl:]

def parse_tcp_header(data):
    tcp_header = struct.unpack("!HHLLBBHHH", data[:20])
    src_port, dest_port = tcp_header[0], tcp_header[1]
    return src_port, dest_port

def parse_udp_header(data):
    udp_header = struct.unpack("!HHHH", data[:8])
    src_port, dest_port = udp_header[0], udp_header[1]
    return src_port, dest_port

def parse_icmp_header(data):
    icmp_header = struct.unpack("!BBH", data[:4])
    icmp_type, icmp_code = icmp_header[0], icmp_header[1]
    return icmp_type, icmp_code

def sniff_packets():
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
        print("Sniffing packets... Press Ctrl+C to stop.")
        with open(CSV_FILE, "a", newline="") as file:
            writer = csv.writer(file)
            while True:
                raw_data, addr = sock.recvfrom(BUFFER_SIZE)
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                packet_size = len(raw_data)
                eth_header = struct.unpack("!6s6sH", raw_data[:14])
                eth_protocol = socket.ntohs(eth_header[2])
                if eth_protocol == 8: 
                    version, ihl, protocol, src_ip, dest_ip, ip_data = parse_ip_header(raw_data[14:])
                    src_port, dest_port = "", ""
                    if protocol == 6:  
                        src_port, dest_port = parse_tcp_header(ip_data)
                        proto_name = "TCP"
                    elif protocol == 17:  
                        src_port, dest_port = parse_udp_header(ip_data)
                        proto_name = "UDP"
                    elif protocol == 1:  
                        icmp_type, icmp_code = parse_icmp_header(ip_data)
                        proto_name = f"ICMP (Type {icmp_type}, Code {icmp_code})"
                    else:
                        proto_name = f"Other ({protocol})"
                    output_str = f"[{timestamp}] {proto_name} | {src_ip}:{src_port} → {dest_ip}:{dest_port} | Size: {packet_size} bytes"
                    print(output_str)
                    writer.writerow([timestamp, src_ip, dest_ip, proto_name, src_port, dest_port, packet_size])
                    file.flush()
    except KeyboardInterrupt:
        print("\nPacket capture stopped. Data saved to", CSV_FILE)
        sock.close()