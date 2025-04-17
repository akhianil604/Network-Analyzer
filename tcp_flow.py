import socket
import struct
import time
import datetime
import matplotlib.pyplot as plt
from collections import defaultdict

class TCPFlowAnalyzer:
    def __init__(self):
        """
        Initializes the TCPFlowAnalyzer class.
        The flows dictionary holds TCP flow details with default values.
        Each flow is identified by a tuple (src_ip, src_port, dst_ip, dst_port).
        """
        # Dictionary to store flow information (packets, bytes, RTT, etc.)
        self.flows = defaultdict(lambda: {
            'start_time': None,
            'last_update': None,
            'packets': 0,
            'bytes': 0,
            'seq_nums': {},  # seq_num -> timestamp
            'ack_nums': set(),
            'retransmissions': 0,
            'out_of_order': 0,
            'window_sizes': [],
            'rtt_samples': []
        })
        # Create a raw socket to capture all IP packets (TCP specifically)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    def start_capture(self, duration=60):
        """
        Starts the packet capture for a given duration.
        Captures packets, processes them, and generates flow summaries.
        """
        start_time = time.time()  # Start time of the capture
        print(f"Starting TCP flow analysis for {duration} seconds...")

        try:
            # Capture packets until the specified duration has elapsed
            while time.time() - start_time < duration:
                packet = self.sock.recvfrom(65535)[0]  # Receive a raw IP packet
                self.process_packet(packet)  # Process the captured packet
        except KeyboardInterrupt:
            print("Capture stopped by user")  # Stop capture when user interrupts

        # Print the summary of captured flows after the capture is complete
        self.print_flow_summary()

    def process_packet(self, packet):
        """
        Processes a single packet, extracting the relevant details for TCP flow analysis.
        This function parses the IP and TCP headers and updates flow information.
        """
        # Extract the IP header (first 20 bytes)
        ip_header = packet[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        
        # Extract IP header details
        version_ihl = iph[0]
        ihl = version_ihl & 0xF  # Internet Header Length (IHL)
        ip_header_length = ihl * 4
        src_ip = socket.inet_ntoa(iph[8])  # Source IP address
        dst_ip = socket.inet_ntoa(iph[9])  # Destination IP address

        # Extract the TCP header (next 20 bytes)
        tcp_header = packet[ip_header_length:ip_header_length+20]
        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
        
        # Extract TCP header details
        src_port, dst_port = tcph[0], tcph[1]  # Source and destination ports
        sequence, acknowledgement = tcph[2], tcph[3]  # Sequence and Acknowledgement numbers
        doff_reserved = tcph[4]
        tcph_length = doff_reserved >> 4  # Length of the TCP header
        flags, window_size = tcph[5], tcph[6]  # TCP flags and window size

        # Extract flags: SYN and ACK flags in the TCP header
        syn = (flags & 0x02) >> 1
        ack = (flags & 0x10) >> 4

        header_size = ip_header_length + tcph_length * 4  # Calculate the total header size
        data_size = len(packet) - header_size  # Calculate the size of the data portion

        # Define flow identifiers (forward and reverse flows)
        forward_flow = (src_ip, src_port, dst_ip, dst_port)
        reverse_flow = (dst_ip, dst_port, src_ip, src_port)

        # Handling SYN packets (new connection initiation)
        if syn and not ack:
            flow = self.flows[forward_flow]
            flow['start_time'] = time.time()  # Record the start time for the flow
            flow['seq_nums'][sequence + 1] = time.time()  # Store the sequence number

        # Handling ACK packets (acknowledgement and data transmission)
        elif ack:
            # Measure RTT based on acknowledgement and sequence number
            if acknowledgement in self.flows[reverse_flow]['seq_nums']:
                seq_time = self.flows[reverse_flow]['seq_nums'].pop(acknowledgement)
                rtt = time.time() - seq_time  # Calculate round-trip time
                self.flows[reverse_flow]['rtt_samples'].append(rtt)  # Store RTT sample
                print(f"RTT measured for {reverse_flow} → {rtt*1000:.2f} ms")

            flow = self.flows[forward_flow]
            if not flow['start_time']:
                flow['start_time'] = time.time()  # If no start time, set it now
            flow['ack_nums'].add(acknowledgement)  # Record the acknowledged sequence number

            # Handling retransmissions and out-of-order packets
            if sequence in flow['seq_nums'] and data_size > 0:
                flow['retransmissions'] += 1  # Increment retransmission counter

            # Update the sequence number with new data
            if data_size > 0:
                flow['seq_nums'][sequence + data_size] = time.time()
            
            flow['window_sizes'].append(window_size)  # Record window size for flow

        # Update flow statistics (packet count, bytes, last update time)
        flow = self.flows[forward_flow]
        flow['last_update'] = time.time()
        flow['packets'] += 1  # Increment the packet counter
        flow['bytes'] += len(packet)  # Increment the byte counter

    def print_flow_summary(self):
        """
        Prints a summary of all captured TCP flows, including packets, bytes, retransmissions, RTT, and throughput.
        """
        print("\n===== TCP Flow Analysis Summary =====")
        
        for (src_ip, src_port, dst_ip, dst_port), f in self.flows.items():
            if f['packets'] == 0:  # Skip flows with no packets
                continue

            print(f"\nFlow: {src_ip}:{src_port} → {dst_ip}:{dst_port}")
            
            if f['start_time'] and f['last_update']:
                duration = f['last_update'] - f['start_time']  # Calculate duration of the flow
                print(f"Duration: {duration:.2f} seconds")

            print(f"Packets: {f['packets']}")  # Number of packets in the flow
            print(f"Bytes: {f['bytes']}")  # Number of bytes in the flow

            # Display retransmission statistics
            if f['retransmissions']:
                percent = (f['retransmissions'] / f['packets']) * 100
                print(f"Retransmissions: {f['retransmissions']} ({percent:.2f}%)")

            # Display average RTT for the flow
            if f['rtt_samples']:
                avg_rtt = sum(f['rtt_samples']) / len(f['rtt_samples'])
                print(f"Average RTT: {avg_rtt*1000:.2f} ms")

            # Display average window size
            if f['window_sizes']:
                avg_window = sum(f['window_sizes']) / len(f['window_sizes'])
                print(f"Average Window Size: {avg_window}")

            # Calculate and display throughput (in kbps)
            if f['bytes'] and f['start_time'] and f['last_update']:
                duration = f['last_update'] - f['start_time']
                if duration > 0:
                    throughput = (f['bytes'] * 8) / duration / 1000  # Throughput in kbps
                    print(f"Throughput: {throughput:.2f} kbps")

        # Visualize the RTT data for all flows
        self.visualize_rtt()

    def visualize_rtt(self):
        """
        Visualizes the average RTT for each TCP flow using a horizontal bar chart.
        """
        flows = []
        avg_rtts = []
        
        for (src_ip, src_port, dst_ip, dst_port), data in self.flows.items():
            if data['rtt_samples']:
                avg_rtt = sum(data['rtt_samples']) / len(data['rtt_samples'])
                flows.append(f"{src_ip}:{src_port} → {dst_ip}:{dst_port}")  # Flow identifier
                avg_rtts.append(avg_rtt * 1000)  # Convert RTT to milliseconds for plotting

        # If no RTT data is available, skip plotting
        if not flows:
<<<<<<< HEAD
=======
            # print("No RTT data available to plot.")
>>>>>>> 436817423341a67144ddb2fdf824c66adbf1e3eb
            return

        # Create a horizontal bar chart to display RTT for each flow
        plt.figure(figsize=(10, 6))
        plt.barh(flows, avg_rtts, color='skyblue')
        plt.xlabel("Average RTT (ms)")
        plt.title("Average RTT per TCP Flow")
        plt.tight_layout()
        plt.show()

def start_flow_analysis():
    """
    Starts the TCP flow analysis based on user input.
    Prompts the user for capture duration and starts the analysis.
    """
    try:
        print("\nTCP Flow Analysis")
        # User inputs capture duration (default 30 seconds)
        duration = int(input("Enter capture duration in seconds [30]: ") or "30")
        analyzer = TCPFlowAnalyzer()  # Create a new TCPFlowAnalyzer object
        analyzer.start_capture(duration=duration)  # Start the packet capture and analysis
    except PermissionError:
        print("Error: This feature requires root/admin privileges. Please run with sudo.")  # Requires admin privileges
    except Exception as e:
        print(f"Error starting TCP flow analysis: {str(e)}")  # Handle any other exceptions

if __name__ == "__main__":
    """
    Main entry point for the script.
    Starts the flow analysis directly if this script is executed.
    """
    try:
        analyzer = TCPFlowAnalyzer()  # Initialize the analyzer
        analyzer.start_capture(duration=30)  # Start the flow analysis with a 30-second duration
    except PermissionError:
<<<<<<< HEAD
        print("Error: This script requires root/admin privileges. Please run with sudo.")  # Handle permission errors
=======
        print("Error: This script requires root/admin privileges. Please run with sudo.")
>>>>>>> 436817423341a67144ddb2fdf824c66adbf1e3eb
