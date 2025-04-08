import socket
import struct
import time
import os
import sys

def checksum(data):
    if len(data) % 2:
        data += b'\x00'

    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word

    # Carry over ones
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return ~total & 0xFFFF

def send_icmp_ping(dest_ip):
    # Create a raw socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("Root privileges are required to run this script (use sudo).")
        sys.exit(1)

    sock.settimeout(2)

    # ICMP Header Fields
    icmp_type = 8  # Echo request
    icmp_code = 0
    checksum_init = 0
    packet_id = os.getpid() & 0xFFFF
    seq_number = 1

    # Payload
    payload = b'Ping from Python!' + bytes(32 - len('Ping from Python!'))
    
    # Header without checksum
    header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum_init, packet_id, seq_number)
    # Compute checksum on the header + payload
    checksum_value = checksum(header + payload)
    # Final header with checksum
    header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum_value, packet_id, seq_number)

    packet = header + payload

    # Send packet
    send_time = time.time()
    sock.sendto(packet, (dest_ip, 1))

    try:
        # Receive response
        data, addr = sock.recvfrom(1024)
        recv_time = time.time()
        rtt = (recv_time - send_time) * 1000  # Round-trip time in ms
        print(f"Reply from {addr[0]}: time={rtt:.2f}ms")
    except socket.timeout:
        print("Request timed out.")
    finally:
        sock.close()

def ping_interface():
    target = input("Enter IP address to ping: ")
    print(f"Pinging {target} with Python ICMP...")
    send_icmp_ping(target)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <target_ip>")
        sys.exit(1)

    target = sys.argv[1]
    print(f"Pinging {target} with Python ICMP...")
    send_icmp_ping(target)
