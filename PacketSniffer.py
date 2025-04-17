import socket
import struct
import csv
import datetime
import os
import base64
import hashlib

# Define constants for Ethernet frame processing
ETH_P_ALL = 0x0003  # Ethernet protocol type for all traffic
BUFFER_SIZE = 65536  # Buffer size for packet capture
CSV_FILE = "captured_packets.csv"  # Output CSV file for captured packets

# Create and open a CSV file for writing captured packet data
with open(CSV_FILE, "w", newline="") as file:
    writer = csv.writer(file)
    # Write the header row to the CSV file
    writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Packet Size"])

def parse_ip_header(data):
    """
    Parse the IP header to extract details such as IP version, protocol type, 
    source IP, destination IP, and return the remaining data after the IP header.
    """
    ip_header = struct.unpack("!BBHHHBBH4s4s", data[:20])  # Unpack first 20 bytes of IP header
    version_ihl = ip_header[0]  # Get the version and IHL (Internet Header Length)
    version = version_ihl >> 4  # Extract the IP version (IPv4 or IPv6)
    ihl = (version_ihl & 0xF) * 4  # Calculate IHL in bytes (length of the IP header)
    protocol = ip_header[6]  # Extract the protocol field (TCP, UDP, ICMP, etc.)
    src_ip = socket.inet_ntoa(ip_header[8])  # Convert source IP from bytes to readable format
    dest_ip = socket.inet_ntoa(ip_header[9])  # Convert destination IP from bytes to readable format
    return version, ihl, protocol, src_ip, dest_ip, data[ihl:]  # Return parsed information and remaining data

def parse_tcp_header(data):
    """
    Parse the TCP header to extract the source and destination ports.
    """
    tcp_header = struct.unpack("!HHLLBBHHH", data[:20])  # Unpack the first 20 bytes of TCP header
    src_port, dest_port = tcp_header[0], tcp_header[1]  # Extract source and destination ports
    return src_port, dest_port  # Return the ports

def parse_udp_header(data):
    """
    Parse the UDP header to extract the source and destination ports.
    """
    udp_header = struct.unpack("!HHHH", data[:8])  # Unpack the first 8 bytes of UDP header
    src_port, dest_port = udp_header[0], udp_header[1]  # Extract source and destination ports
    return src_port, dest_port  # Return the ports

def parse_icmp_header(data):
    """
    Parse the ICMP header to extract the ICMP type and code.
    """
    icmp_header = struct.unpack("!BBH", data[:4])  # Unpack the first 4 bytes of ICMP header
    icmp_type, icmp_code = icmp_header[0], icmp_header[1]  # Extract type and code
    return icmp_type, icmp_code  # Return ICMP type and code

def sniff_packets():
    """
    Sniff packets from the network interface and process them.
    Captured packets are saved to a CSV file with timestamp, IP addresses, protocol, ports, and packet size.
    """
    try:
        # Create a raw socket to capture all Ethernet frames (ETH_P_ALL indicates all protocols)
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
        print("Sniffing packets... Press Ctrl+C to stop.")
        
        # Open the CSV file in append mode to write captured packet data
        with open(CSV_FILE, "a", newline="") as file:
            writer = csv.writer(file)
            
            # Infinite loop to continuously capture packets
            while True:
                # Receive raw packet data
                raw_data, addr = sock.recvfrom(BUFFER_SIZE)
                
                # Get the current timestamp for the packet capture
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                packet_size = len(raw_data)  # Calculate the packet size in bytes

                # Parse the Ethernet header (first 14 bytes)
                eth_header = struct.unpack("!6s6sH", raw_data[:14])  # Unpack the Ethernet header
                eth_protocol = socket.ntohs(eth_header[2])  # Extract protocol type from the Ethernet header
                
                if eth_protocol == 8:  # If the protocol is IP (Ethernet type 0x0800)
                    version, ihl, protocol, src_ip, dest_ip, ip_data = parse_ip_header(raw_data[14:])
                    
                    # Initialize default ports as empty strings
                    src_port, dest_port = "", ""
                    
                    # Determine protocol type and extract port information based on the protocol
                    if protocol == 6:  # TCP protocol
                        src_port, dest_port = parse_tcp_header(ip_data)
                        proto_name = "TCP"
                    elif protocol == 17:  # UDP protocol
                        src_port, dest_port = parse_udp_header(ip_data)
                        proto_name = "UDP"
                    elif protocol == 1:  # ICMP protocol
                        icmp_type, icmp_code = parse_icmp_header(ip_data)
                        proto_name = f"ICMP (Type {icmp_type}, Code {icmp_code})"
                    else:
                        proto_name = f"Other ({protocol})"  # For any other protocol types
                    
                    # Prepare output string with packet details
                    output_str = f"[{timestamp}] {proto_name} | {src_ip}:{src_port} → {dest_ip}:{dest_port} | Size: {packet_size} bytes"
                    print(output_str)  # Print the packet details to the console
                    
                    # Write packet information to the CSV file
                    writer.writerow([timestamp, src_ip, dest_ip, proto_name, src_port, dest_port, packet_size])
                    file.flush()  # Ensure data is written to the file immediately
    except KeyboardInterrupt:
        # Handle interruption (Ctrl+C) and close the socket
        print("\nPacket capture stopped. Data saved to", CSV_FILE)
        sock.close()  # Close the socket to stop packet capture

# Main entry point
if __name__ == "__main__":
    sniff_packets()  # Start sniffing packets and saving data to CSV
