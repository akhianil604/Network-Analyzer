import socket
import struct
import time
import datetime
import matplotlib.pyplot as plt
from collections import defaultdict

class TCPFlowAnalyzer:
    def __init__(self):
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
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    def start_capture(self, duration=60):
        start_time = time.time()
        print(f"Starting TCP flow analysis for {duration} seconds...")

        try:
            while time.time() - start_time < duration:
                packet = self.sock.recvfrom(65535)[0]
                self.process_packet(packet)
        except KeyboardInterrupt:
            print("Capture stopped by user")

        self.print_flow_summary()

    def process_packet(self, packet):
        ip_header = packet[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        ip_header_length = ihl * 4
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])

        tcp_header = packet[ip_header_length:ip_header_length+20]
        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
        src_port, dst_port = tcph[0], tcph[1]
        sequence, acknowledgement = tcph[2], tcph[3]
        doff_reserved = tcph[4]
        tcph_length = doff_reserved >> 4
        flags, window_size = tcph[5], tcph[6]

        syn = (flags & 0x02) >> 1
        ack = (flags & 0x10) >> 4

        header_size = ip_header_length + tcph_length * 4
        data_size = len(packet) - header_size

        forward_flow = (src_ip, src_port, dst_ip, dst_port)
        reverse_flow = (dst_ip, dst_port, src_ip, src_port)

        if syn and not ack:
            flow = self.flows[forward_flow]
            flow['start_time'] = time.time()
            flow['seq_nums'][sequence + 1] = time.time()
        elif ack:
            if acknowledgement in self.flows[reverse_flow]['seq_nums']:
                seq_time = self.flows[reverse_flow]['seq_nums'].pop(acknowledgement)
                rtt = time.time() - seq_time
                self.flows[reverse_flow]['rtt_samples'].append(rtt)
                print(f"RTT measured for {reverse_flow} → {rtt*1000:.2f} ms")
            flow = self.flows[forward_flow]
            if not flow['start_time']:
                flow['start_time'] = time.time()
            flow['ack_nums'].add(acknowledgement)
            if sequence in flow['seq_nums'] and data_size > 0:
                flow['retransmissions'] += 1
            if data_size > 0:
                flow['seq_nums'][sequence + data_size] = time.time()
            flow['window_sizes'].append(window_size)
        flow = self.flows[forward_flow]
        flow['last_update'] = time.time()
        flow['packets'] += 1
        flow['bytes'] += len(packet)

    def print_flow_summary(self):
        print("\n===== TCP Flow Analysis Summary =====")
        for (src_ip, src_port, dst_ip, dst_port), f in self.flows.items():
            if f['packets'] == 0:
                continue

            print(f"\nFlow: {src_ip}:{src_port} → {dst_ip}:{dst_port}")
            if f['start_time'] and f['last_update']:
                duration = f['last_update'] - f['start_time']
                print(f"Duration: {duration:.2f} seconds")

            print(f"Packets: {f['packets']}")
            print(f"Bytes: {f['bytes']}")
            if f['retransmissions']:
                percent = (f['retransmissions'] / f['packets']) * 100
                print(f"Retransmissions: {f['retransmissions']} ({percent:.2f}%)")

            if f['rtt_samples']:
                avg_rtt = sum(f['rtt_samples']) / len(f['rtt_samples'])
                print(f"Average RTT: {avg_rtt*1000:.2f} ms")

            if f['window_sizes']:
                avg_window = sum(f['window_sizes']) / len(f['window_sizes'])
                print(f"Average Window Size: {avg_window}")

            if f['bytes'] and f['start_time'] and f['last_update']:
                duration = f['last_update'] - f['start_time']
                if duration > 0:
                    throughput = (f['bytes'] * 8) / duration / 1000
                    print(f"Throughput: {throughput:.2f} kbps")

        self.visualize_rtt()

    def visualize_rtt(self):
        flows = []
        avg_rtts = []

        for (src_ip, src_port, dst_ip, dst_port), data in self.flows.items():
            if data['rtt_samples']:
                avg_rtt = sum(data['rtt_samples']) / len(data['rtt_samples'])
                flows.append(f"{src_ip}:{src_port} → {dst_ip}:{dst_port}")
                avg_rtts.append(avg_rtt * 1000)

        if not flows:
            # print("No RTT data available to plot.")
            return

        plt.figure(figsize=(10, 6))
        plt.barh(flows, avg_rtts, color='skyblue')
        plt.xlabel("Average RTT (ms)")
        plt.title("Average RTT per TCP Flow")
        plt.tight_layout()
        plt.show()

def start_flow_analysis():
    try:
        print("\nTCP Flow Analysis")
        duration = int(input("Enter capture duration in seconds [30]: ") or "30")
        analyzer = TCPFlowAnalyzer()
        analyzer.start_capture(duration=duration)
    except PermissionError:
        print("Error: This feature requires root/admin privileges. Please run with sudo.")
    except Exception as e:
        print(f"Error starting TCP flow analysis: {str(e)}")

if __name__ == "__main__":
    try:
        analyzer = TCPFlowAnalyzer()
        analyzer.start_capture(duration=30)
    except PermissionError:
        print("Error: This script requires root/admin privileges. Please run with sudo.")
