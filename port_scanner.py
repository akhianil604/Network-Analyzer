#!/usr/bin/env python3
import socket
import struct
import random
import time
import sys
import os
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

#command to run:
#sudo python3 port_scanner.py -t 127.0.0.1 -p 22,13 -v --syn

class PortScanner:
    def __init__(self, timeout=1, verbose=False, syn_scan=False):
        self.timeout = timeout
        self.verbose = verbose
        self.syn_scan = syn_scan

    def checksum(self, msg):
        """Calculate the checksum of the message"""
        s = 0
        for i in range(0, len(msg), 2):
            if i + 1 < len(msg):
                w = (msg[i] << 8) + msg[i + 1]
            else:
                w = msg[i] << 8
            s = s + w

        s = (s >> 16) + (s & 0xffff)
        s = s + (s >> 16)

        # Complement and mask to 16 bits
        s = ~s & 0xffff

        return s

    def create_tcp_packet(self, src_ip, dest_ip, src_port, dest_port):
        """Create a raw TCP SYN packet"""
        # IP Header
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 20 + 20  # Total length: IP header + TCP header
        ip_id = random.randint(0, 65535)
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0  # Will be calculated later
        ip_saddr = socket.inet_aton(src_ip)
        ip_daddr = socket.inet_aton(dest_ip)

        ip_ihl_ver = (ip_ver << 4) + ip_ihl

        ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

        # TCP Header
        tcp_sport = src_port
        tcp_dport = dest_port
        tcp_seq = random.randint(0, 2**32 - 1)
        tcp_ack_seq = 0
        tcp_doff = 5  # Data offset: 5 x 4 = 20 bytes
        tcp_fin = 0
        tcp_syn = 1
        tcp_rst = 0
        tcp_psh = 0
        tcp_ack = 0
        tcp_urg = 0
        tcp_window = socket.htons(5840)
        tcp_check = 0
        tcp_urg_ptr = 0

        tcp_doff_res = (tcp_doff << 4) + 0  # Data offset, reserved bits
        tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)

        tcp_header = struct.pack('!HHLLBBHHH', tcp_sport, tcp_dport, tcp_seq, tcp_ack_seq, tcp_doff_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

        # Pseudo Header for Checksum Calculation
        src_addr = socket.inet_aton(src_ip)
        dest_addr = socket.inet_aton(dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)

        psh = struct.pack('!4s4sBBH', src_addr, dest_addr, placeholder, protocol, tcp_length)
        psh_tcp = psh + tcp_header

        tcp_check = self.checksum(psh_tcp)

        # TCP Header with Checksum
        tcp_header = struct.pack('!HHLLBBHHH', tcp_sport, tcp_dport, tcp_seq, tcp_ack_seq, tcp_doff_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

        packet = ip_header + tcp_header

        return packet

    def create_udp_packet(self, src_ip, dest_ip, src_port, dest_port, data=b''):
        """Create a raw UDP packet"""
        length = 8 + len(data)  # UDP header length + data length
        checksum = 0

        # UDP header without checksum
        udp_header = struct.pack('!HHHH', src_port, dest_port, length, checksum)

        # Pseudo header for checksum calculation
        src_addr = socket.inet_aton(src_ip)
        dst_addr = socket.inet_aton(dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_UDP

        # Pseudo header
        psh = struct.pack('!4s4sBBH', src_addr, dst_addr, placeholder, protocol, length)

        # Calculate checksum
        checksum = self.checksum(psh + udp_header + data)

        # Rebuild UDP header with the correct checksum
        udp_header = struct.pack('!HHHH', src_port, dest_port, length, checksum)

        return udp_header + data

    def tcp_scan_port(self, target_ip, port, src_port=None):
        """Scan a TCP port using raw sockets or connect()"""
        if self.syn_scan:
            try:
                # Create a raw socket
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                s.settimeout(self.timeout)

                # Craft TCP SYN packet
                src_port = src_port or random.randint(1024, 65535)
                tcp_packet = self.create_tcp_packet(self.get_source_ip(target_ip), target_ip, src_port, port)
                #dest_addr = (target_ip, port)

                # Send SYN packet
                s.sendto(tcp_packet, (target_ip, port))

                # Receive response
                try:
                    s.settimeout(self.timeout)  # Reset timeout for receiving
                    raw_data, addr = s.recvfrom(65535)
                    ip_header_length = (raw_data[0] & 0x0F) * 4
                    tcp_header = raw_data[ip_header_length:ip_header_length + 20]  # Assuming 20 bytes TCP header
                    tcp_header_data = struct.unpack('!HHLLBBHHH', tcp_header)
                    flags = tcp_header_data[5]
                    if flags & 0x12:  # SYN-ACK
                        s.close()
                        return True, "open"
                    elif flags & 0x14:  # RST-ACK
                        s.close()
                        return False, "closed"
                    else:
                        s.close()
                        return False, "filtered"
                except socket.timeout:
                    s.close()
                    return False, "filtered"  # Assuming filtered due to no response

            except socket.error as e:
                if self.verbose:
                    print(f"Error creating raw socket for TCP SYN scan: {e}")
                return False, f"error: {e}"
        else:
            try:
                # Create a regular TCP socket for simplicity and reliability
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                result = s.connect_ex((target_ip, port))
                s.close()

                if result == 0:
                    return True, "open"
                else:
                    return False, "closed"
            except socket.timeout:
                return False, "filtered"
            except Exception as e:
                if self.verbose:
                    print(f"Error scanning TCP port {port}: {str(e)}")
                return False, f"error: {str(e)}"

    def udp_scan_port(self, target_ip, port, src_port=None):
        """Scan a UDP port using a simple UDP socket with specific data"""
        try:
            # Create a UDP socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.timeout)

            # Add source port and IP
            src_port = src_port or random.randint(1024, 65535)
            src_ip = self.get_source_ip(target_ip)

            # Craft UDP packet with data
            data = b'This is a UDP scan probe.'  # You can customize the data being sent
            udp_packet = self.create_udp_packet(src_ip, target_ip, src_port, port, data)

            # Send UDP packet
            s.sendto(udp_packet, (target_ip, port))

            try:
                # Try to receive data
                data, addr = s.recvfrom(1024)
                s.close()
                return True, "open"
            except socket.timeout:
                # No response could mean open or filtered
                s.close()
                return None, "open|filtered"
            except socket.error as e:
                # Socket error likely means port closed
                s.close()
                return False, f"closed: {e}"
        except Exception as e:
            if self.verbose:
                print(f"Error scanning UDP port {port}: {str(e)}")
            return False, f"error: {str(e)}"

    def get_source_ip(self, dest_ip):
        """Determine the source IP address to use for outgoing packets"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((dest_ip, 80))  # Connect to a known external address
            src_ip = s.getsockname()[0]
            s.close()
            return src_ip
        except socket.error:
            return '127.0.0.1'  # Fallback to localhost

    def scan(self, target, ports, protocol='tcp', concurrency=10):
        """Scan specified ports on target using TCP or UDP"""
        results = {}
        start_time = time.time()

        print(f"Starting {protocol.upper()} scan on {target}")
        print(f"Scanning {len(ports)} ports at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 60)

        try:
            target_ip = socket.gethostbyname(target)
            if self.verbose:
                print(f"Resolved {target} to {target_ip}")
        except socket.gaierror:
            print(f"Hostname {target} could not be resolved")
            return results

        scan_method = self.tcp_scan_port if protocol.lower() == 'tcp' else self.udp_scan_port
        open_ports = 0

        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            future_to_port = {executor.submit(scan_method, target_ip, port): port for port in ports}

            for future in future_to_port:
                port = future_to_port[future]
                try:
                    result, status = future.result()
                    if result is True:
                        service = self.get_service_name(port, protocol)
                        print(f"{port}/{protocol.lower()}\t{status}\t{service}")
                        open_ports += 1
                    elif result is None:
                        service = self.get_service_name(port, protocol)
                        print(f"{port}/{protocol.lower()}\t{status}\t{service}")
                        open_ports += 0.5
                    elif self.verbose:
                        print(f"{port}/{protocol.lower()}\t{status}")
                    results[port] = status
                except Exception as e:
                    print(f"Error scanning port {port}: {str(e)}")
                    results[port] = "error"

        scan_time = time.time() - start_time
        print("-" * 60)
        print(f"Scan completed in {scan_time:.2f} seconds")
        print(f"Found {open_ports} open ports out of {len(ports)} scanned")
        return results

    def get_service_name(self, port, protocol):
        """Get service name for the given port and protocol"""
        try:
            return socket.getservbyport(port, protocol.lower())
        except:
            return "unknown"

def parse_port_range(port_spec):
    """Parse port specification like '80,443,8000-8100'"""
    ports = []
    for item in port_spec.split(','):
        if '-' in item:
            start, end = map(int, item.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(item))
    return ports

def start_port_scanner():
    """Interactive function for the main menu"""
    try:
        print("\nPort Scanner")
        target = input("Enter target IP address or hostname: ")
        port_spec = input("Enter ports to scan (e.g. 80,443,8000-8100) [default: 1-1024]: ") or "1-1024"
        scan_type = input("Enter scan type (tcp/udp/both) [default: tcp]: ").lower() or "tcp"
        timeout = float(input("Enter timeout in seconds [default: 1.0]: ") or "1.0")
        concurrency = int(input("Enter number of concurrent scans [default: 10]: ") or "10")
        verbose = input("Enable verbose output? (y/n) [default: n]: ").lower() == 'y'
        syn_scan = input("Enable TCP SYN scan (requires root)? (y/n) [default: n]: ").lower() == 'y'

        # Parse ports
        try:
            ports = parse_port_range(port_spec)
        except:
            print("Invalid port specification. Using default range 1-1024.")
            ports = list(range(1, 1025))

        # Create scanner
        scanner = PortScanner(timeout=timeout, verbose=verbose, syn_scan=syn_scan)

        # Perform scan
        if scan_type == 'tcp' or scan_type == 'both':
            tcp_results = scanner.scan(target, ports, 'tcp', concurrency)

        if scan_type == 'udp' or scan_type == 'both':
            udp_results = scanner.scan(target, ports, 'udp', concurrency)

    except KeyboardInterrupt:
        print("\nPort scanning canceled.")
    except Exception as e:
        print(f"Error during port scanning: {str(e)}")

if __name__ == '__main__':
    # Original command-line interface
    parser = argparse.ArgumentParser(description='TCP/UDP Port Scanner')
    parser.add_argument('-t', '--target', required=True, help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='1-1024', help='Port(s) to scan (e.g. 80,443,8000-8100)')
    parser.add_argument('-s', '--scan', choices=['tcp', 'udp', 'both'], default='tcp', help='Scan type (tcp, udp, or both)')
    parser.add_argument('--timeout', type=float, default=1.0, help='Timeout in seconds for port scan (default: 1.0)')
    parser.add_argument('-c', '--concurrency', type=int, default=10, help='Number of concurrent scans (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--syn', action='store_true', help='Enable TCP SYN scan (requires root privileges)')

    args = parser.parse_args()

    # Parse ports
    try:
        ports = parse_port_range(args.ports)
    except:
        print("Invalid port specification. Use format like '80,443,8000-8100'")
        sys.exit(1)

    # Create scanner
    scanner = PortScanner(timeout=args.timeout, verbose=args.verbose, syn_scan=args.syn)

    # Perform scan
    if args.scan == 'tcp' or args.scan == 'both':
        tcp_results = scanner.scan(args.target, ports, 'tcp', args.concurrency)

    if args.scan == 'udp' or args.scan == 'both':
        udp_results = scanner.scan(args.target, ports, 'udp', args.concurrency)
