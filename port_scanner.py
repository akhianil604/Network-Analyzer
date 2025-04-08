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

class PortScanner:
    def __init__(self, timeout=1, verbose=False):
        self.timeout = timeout
        self.verbose = verbose
    
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
        # Pseudo header fields
        src_addr = socket.inet_aton(src_ip)
        dst_addr = socket.inet_aton(dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = 20  # TCP header length without options
        
        # TCP header fields
        seq = random.randint(0, 2**32-1)
        ack_seq = 0
        doff = 5  # Data offset: 5x4 = 20 bytes (no options)
        # Flags: SYN
        fin = 0
        syn = 1
        rst = 0
        psh = 0
        ack = 0
        urg = 0
        window = socket.htons(5840)  # Maximum window size
        check = 0
        urg_ptr = 0
        
        offset_res = (doff << 4) + 0
        tcp_flags = (fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5))
        
        # TCP header without checksum
        tcp_header = struct.pack('!HHLLBBHHH', 
            src_port, dest_port, seq, ack_seq, offset_res, 
            tcp_flags, window, check, urg_ptr)
        
        # Pseudo header
        psh = struct.pack('!4s4sBBH', 
            src_addr, dst_addr, placeholder, protocol, tcp_length)
        
        # Calculate checksum
        check = self.checksum(psh + tcp_header)
        
        # Rebuild the TCP header with the correct checksum
        tcp_header = struct.pack('!HHLLBBHHH', 
            src_port, dest_port, seq, ack_seq, offset_res, 
            tcp_flags, window, check, urg_ptr)
        
        return tcp_header
    
    def create_udp_packet(self, src_ip, dest_ip, src_port, dest_port):
        """Create a raw UDP packet"""
        # UDP header fields
        length = 8  # UDP header length
        checksum = 0
        
        # UDP header without checksum
        udp_header = struct.pack('!HHHH', src_port, dest_port, length, checksum)
        
        # Pseudo header for checksum calculation
        src_addr = socket.inet_aton(src_ip)
        dst_addr = socket.inet_aton(dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_UDP
        
        # Pseudo header
        psh = struct.pack('!4s4sBBH', 
            src_addr, dst_addr, placeholder, protocol, length)
        
        # Calculate checksum
        checksum = self.checksum(psh + udp_header)
        
        # Rebuild UDP header with the correct checksum
        udp_header = struct.pack('!HHHH', src_port, dest_port, length, checksum)
        
        return udp_header
    
    def tcp_scan_port(self, target_ip, port, src_port=None):
        """Scan a TCP port using raw sockets"""
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
        """Scan a UDP port using a simple UDP socket"""
        try:
            # Create a UDP socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.timeout)
            
            # Send empty UDP packet
            s.sendto(b'', (target_ip, port))
            
            try:
                # Try to receive data
                data, addr = s.recvfrom(1024)
                s.close()
                return True, "open"
            except socket.timeout:
                # No response could mean open or filtered
                s.close()
                return True, "open|filtered"
            except socket.error:
                # Socket error likely means port closed
                s.close()
                return False, "closed"
        except Exception as e:
            if self.verbose:
                print(f"Error scanning UDP port {port}: {str(e)}")
            return False, f"error: {str(e)}"
    
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
                    is_open, status = future.result()
                    if is_open:
                        service = self.get_service_name(port, protocol)
                        print(f"{port}/{protocol.lower()}\t{status}\t{service}")
                        open_ports += 1
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
        
        # Parse ports
        try:
            ports = parse_port_range(port_spec)
        except:
            print("Invalid port specification. Using default range 1-1024.")
            ports = list(range(1, 1025))
        
        # Create scanner
        scanner = PortScanner(timeout=timeout, verbose=verbose)
        
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
    
    args = parser.parse_args()
    
    # Parse ports
    try:
        ports = parse_port_range(args.ports)
    except:
        print("Invalid port specification. Use format like '80,443,8000-8100'")
        sys.exit(1)
    
    # Create scanner
    scanner = PortScanner(timeout=args.timeout, verbose=args.verbose)
    
    # Perform scan
    if args.scan == 'tcp' or args.scan == 'both':
        tcp_results = scanner.scan(args.target, ports, 'tcp', args.concurrency)
    
    if args.scan == 'udp' or args.scan == 'both':
        udp_results = scanner.scan(args.target, ports, 'udp', args.concurrency)
