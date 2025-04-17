<<<<<<< HEAD
import scapy.all as scapy  # Import Scapy library to capture and analyze network packets
import time  # For time-related functions
from collections import defaultdict  # To easily manage default dictionaries (counting packets/flows)

def monitor_network(duration=60):
    """
    Monitors network traffic for a given duration, calculating performance metrics 
    such as total bandwidth, UDP packet loss, and TCP flow statistics.
    """
    print(f"Starting network performance monitoring for {duration} seconds...\n")
    
    start_time = time.time()  # Record the start time of the monitoring session
    captured_packets = []  # List to store all captured packets
    udp_flows_sent = defaultdict(int)  # Dictionary to count sent UDP packets per flow
    udp_flows_received = defaultdict(int)  # Dictionary to count received UDP packets per flow
    tcp_connections = defaultdict(lambda: {  # Dictionary to store TCP flow statistics
        'start_time': None,  # Connection start time
        'end_time': None,  # Connection end time
        'packets': 0,  # Total packets in this connection
        'bytes': 0,  # Total bytes transferred in this connection
        'retransmissions': 0  # Number of retransmissions in this TCP flow
    })
    
    def packet_callback(packet):
        """
        Callback function to process each captured packet.
        """
        captured_packets.append(packet)  # Add the packet to the list of captured packets
        
        if packet.haslayer(scapy.IP):  # Check if the packet has an IP layer
            ip_layer = packet[scapy.IP]  # Extract the IP layer from the packet
            src_ip = ip_layer.src  # Source IP address
            dst_ip = ip_layer.dst  # Destination IP address

            # Process UDP packets
            if packet.haslayer(scapy.UDP):
                udp_layer = packet[scapy.UDP]  # Extract UDP layer
                flow_key = (src_ip, udp_layer.sport, dst_ip, udp_layer.dport)  # Define the flow key
                # If source IP is from private IP ranges, consider it as a local flow
                if src_ip.startswith("192.") or src_ip.startswith("10.") or src_ip.startswith("172."):
                    udp_flows_sent[flow_key] += 1  # Count the sent UDP packet for this flow
                else:
                    reverse_flow = (dst_ip, udp_layer.dport, src_ip, udp_layer.sport)  # Reverse the flow for receiving side
                    udp_flows_received[reverse_flow] += 1  # Count the received UDP packet for this flow

            # Process TCP packets
            if packet.haslayer(scapy.TCP):
                tcp_layer = packet[scapy.TCP]  # Extract TCP layer
                flow_key = (src_ip, tcp_layer.sport, dst_ip, tcp_layer.dport)  # Define the TCP flow key
                # If this is the first time seeing this flow, set the start time
                if tcp_connections[flow_key]['start_time'] is None:
                    tcp_connections[flow_key]['start_time'] = time.time()

                # Increment packet count and byte count for the flow
                tcp_connections[flow_key]['packets'] += 1
                tcp_connections[flow_key]['bytes'] += len(packet)

                # Check for TCP retransmissions (RST flag)
                if tcp_layer.flags & 0x04:  # Check if the RST flag is set
                    tcp_connections[flow_key]['retransmissions'] += 1
                
                # Update the end time of the TCP flow
                tcp_connections[flow_key]['end_time'] = time.time()
    
    # Start sniffing packets with a timeout duration and process each packet using the callback function
    scapy.sniff(prn=packet_callback, store=False, timeout=duration)
    
    # Calculate the total bytes captured during the monitoring session
    total_bytes = sum(len(pkt) for pkt in captured_packets)
    
    # Print the network performance summary
    print("\n===== Network Performance Summary =====")
    print(f"Total Data Captured: {total_bytes / 1e6:.2f} MB")  # Convert bytes to MB
    print(f"Estimated Overall Bandwidth: {(total_bytes * 8) / (duration * 1e6):.2f} Mbps\n")  # Bandwidth in Mbps
    
    # UDP packet loss estimation
    print("--- UDP Packet Loss Estimation ---")
    if not udp_flows_sent:
        print("No UDP traffic captured.\n")
    for flow, sent in udp_flows_sent.items():
        received = udp_flows_received.get(flow, 0)  # Get the number of received packets for the flow
        loss_percent = (1 - received / sent) * 100 if sent > 0 else 0  # Calculate packet loss percentage
        print(f"UDP Flow: {flow[0]}:{flow[1]} -> {flow[2]}:{flow[3]}")
        print(f"  Sent: {sent}, Received: {received}, Packet Loss: {loss_percent:.2f}%\n")
    
    # TCP flow statistics
    print("--- TCP Flow Summary ---")
    if not tcp_connections:
        print("No TCP flows captured.\n")
    for flow, stats in tcp_connections.items():
        # Calculate the duration of the TCP flow
        duration = (stats['end_time'] - stats['start_time']) if stats['start_time'] and stats['end_time'] else 0
        # Calculate the average bandwidth for the TCP flow
        bandwidth = (stats['bytes'] * 8 / duration / 1e6) if duration > 0 else 0
        print(f"TCP Flow: {flow[0]}:{flow[1]} -> {flow[2]}:{flow[3]}")
        print(f"  Duration: {duration:.2f} seconds")
        print(f"  Packets: {stats['packets']}")
        print(f"  Bytes: {stats['bytes']}")
        print(f"  Average Bandwidth: {bandwidth:.2f} Mbps")
        print(f"  Retransmissions: {stats['retransmissions']}\n")

def start_monitoring_interface():
    """
    Interactive function to prompt the user for the monitoring duration
    and call the monitor_network function.
    """
    try:
        # Ask the user to input the monitoring duration (in seconds)
        duration = int(input("Enter monitoring duration in seconds (default: 60): ") or "60")
        monitor_network(duration)  # Call the monitoring function with the provided duration
    except ValueError:
        # If the user enters an invalid duration, print an error message and use default 60 seconds
        print("Invalid duration. Using default 60 seconds.")
        monitor_network(60)
    except KeyboardInterrupt:
        # Handle manual interruption (Ctrl+C)
        print("\nMonitoring stopped by user.")

if __name__ == "__main__":
    """
    Main function to start the network monitoring interface.
    """
    start_monitoring_interface()
=======
import time
from ping3 import ping
import socket
import threading

# ------------------------- Packet Loss Calculation -------------------------
def calculate_packet_loss(target_ip, num_pings=10):
    print(f"Starting packet loss test to {target_ip} with {num_pings} pings...")
    successful_pings = 0
    for i in range(num_pings):
        try:
            response_time = ping(target_ip, timeout=2)
            print(f"Ping {i+1}: {response_time}")
            if response_time is not None:
                successful_pings += 1
        except Exception as e:
            print(f"Ping error: {e}")
    
    packet_loss = ((num_pings - successful_pings) / num_pings) * 100
    return packet_loss

# ------------------------- Bandwidth Estimation -------------------------
def estimate_bandwidth(server_ip, server_port, payload_size=10_000_000):
    print(f"Starting bandwidth test to {server_ip}:{server_port} with payload size {payload_size} bytes...")
    payload = b'0' * payload_size

    try:
        start_time = time.time()
        with socket.create_connection((server_ip, server_port)) as sock:
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)  # Signal no more data will be sent
            sock.recv(1)  # Wait for acknowledgment
        duration = time.time() - start_time
        bandwidth = (payload_size * 8) / (duration * 1_000_000)  # Mbps
        print(f"Bandwidth test completed in {duration:.2f} seconds.")
        return bandwidth
    except Exception as e:
        print(f"Bandwidth test failed: {e}")
        return None

# ------------------------- Server for Bandwidth Test -------------------------
def run_bandwidth_server(port=5000):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', port))
        s.listen()
        print(f"Bandwidth server listening on port {port}")
        while True:
            conn, _ = s.accept()
            with conn:
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                conn.send(b'1')  # Send acknowledgment

if __name__ == "__main__":
    print("Starting script...")
    server_thread = threading.Thread(target=run_bandwidth_server, daemon=True)
    server_thread.start()

    time.sleep(1)  # Give server time to start

    TARGET_IP = "8.8.8.8"
    NUM_PINGS = 5  # Reduced for faster test
    SERVER_IP = "127.0.0.1"
    SERVER_PORT = 5000

    print(f"Testing network stability to {TARGET_IP}...")

    loss_rate = calculate_packet_loss(TARGET_IP, NUM_PINGS)
    print(f"\nPacket Loss Rate: {loss_rate:.2f}%")

    bandwidth = estimate_bandwidth(SERVER_IP, SERVER_PORT, payload_size=1_000_000)  # 1 MB for faster test
    if bandwidth:
        print(f"Estimated Bandwidth: {bandwidth:.2f} Mbps")
>>>>>>> 436817423341a67144ddb2fdf824c66adbf1e3eb
