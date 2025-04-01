import socket
import struct
import time
from collections import defaultdict

TIME_WINDOW = 60  
ARP_THRESHOLD = 1  

def create_raw_socket():
    try:
        raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0806))  # ARP is 0x0806
        return raw_socket
    except PermissionError:
        print("Permission denied! You need to run this script as root.")
        exit(1)

def parse_arp_packet(packet):
    eth_header = packet[:14]
    eth_unpack = struct.unpack('!6s6sH', eth_header)
    eth_protocol = eth_unpack[2]
    if eth_protocol == 0x0806:  
        arp_header = packet[14:42]  
        arp_unpack = struct.unpack('!HHBBH6s4s6s4s', arp_header)
        sender_ip = socket.inet_ntoa(arp_unpack[8]) 
        sender_mac = ':'.join([f'{x:02x}' for x in arp_unpack[6]])  
        return sender_ip, sender_mac
    return None, None

def detect_arp_spoofing(packet, ip_mac_map, start_time):
    sender_ip, sender_mac = parse_arp_packet(packet)
    if sender_ip: 
        if sender_ip in ip_mac_map:
            if sender_mac != ip_mac_map[sender_ip]:
                print(f"Potential ARP Spoofing detected! IP: {sender_ip} has different MAC addresses: {ip_mac_map[sender_ip]} and {sender_mac}")
        else:
            ip_mac_map[sender_ip] = sender_mac
    current_time = time.time()
    if current_time - start_time > TIME_WINDOW:
        ip_mac_map.clear()
        start_time = current_time
    return start_time