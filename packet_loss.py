import scapy.all as scapy
import time
from collections import defaultdict

def monitor_network(duration=60):
    print(f"📡 Starting network performance monitoring for {duration} seconds...\n")
    
    start_time = time.time()
    captured_packets = []
    udp_flows_sent = defaultdict(int)
    udp_flows_received = defaultdict(int)

    tcp_connections = defaultdict(lambda: {
        'start_time': None,
        'end_time': None,
        'packets': 0,
        'bytes': 0,
        'retransmissions': 0
    })

    def packet_callback(packet):
        captured_packets.append(packet)
        
        if packet.haslayer(scapy.IP):
            ip_layer = packet[scapy.IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            if packet.haslayer(scapy.UDP):
                udp_layer = packet[scapy.UDP]
                flow_key = (src_ip, udp_layer.sport, dst_ip, udp_layer.dport)

                # Assume all outgoing UDP packets are "sent", replies are "received"
                if src_ip.startswith("192.") or src_ip.startswith("10.") or src_ip.startswith("172."):
                    udp_flows_sent[flow_key] += 1
                else:
                    reverse_flow = (dst_ip, udp_layer.dport, src_ip, udp_layer.sport)
                    udp_flows_received[reverse_flow] += 1

            if packet.haslayer(scapy.TCP):
                tcp_layer = packet[scapy.TCP]
                flow_key = (src_ip, tcp_layer.sport, dst_ip, tcp_layer.dport)

                if tcp_connections[flow_key]['start_time'] is None:
                    tcp_connections[flow_key]['start_time'] = time.time()

                tcp_connections[flow_key]['packets'] += 1
                tcp_connections[flow_key]['bytes'] += len(packet)

                # Consider RST or duplicate packets as possible retransmissions
                if tcp_layer.flags & 0x04:  # RST
                    tcp_connections[flow_key]['retransmissions'] += 1

                tcp_connections[flow_key]['end_time'] = time.time()

    # Start sniffing
    scapy.sniff(prn=packet_callback, store=False, timeout=duration)

    total_bytes = sum(len(pkt) for pkt in captured_packets)
    print("\n===== 🌐 Network Performance Summary =====")
    print(f"Total Data Captured: {total_bytes / 1e6:.2f} MB")
    print(f"Estimated Overall Bandwidth: {(total_bytes * 8) / (duration * 1e6):.2f} Mbps\n")

    print("📊 --- UDP Packet Loss Estimation ---")
    if not udp_flows_sent:
        print("No UDP traffic captured.\n")
    for flow, sent in udp_flows_sent.items():
        received = udp_flows_received.get(flow, 0)
        loss_percent = (1 - received / sent) * 100 if sent > 0 else 0
        print(f"UDP Flow: {flow[0]}:{flow[1]} -> {flow[2]}:{flow[3]}")
        print(f"  Sent: {sent}, Received: {received}, Packet Loss: {loss_percent:.2f}%\n")

    print("📊 --- TCP Flow Summary ---")
    if not tcp_connections:
        print("No TCP flows captured.\n")
    for flow, stats in tcp_connections.items():
        duration = (stats['end_time'] - stats['start_time']) if stats['start_time'] and stats['end_time'] else 0
        bandwidth = (stats['bytes'] * 8 / duration / 1e6) if duration > 0 else 0
        print(f"TCP Flow: {flow[0]}:{flow[1]} -> {flow[2]}:{flow[3]}")
        print(f"  Duration: {duration:.2f} seconds")
        print(f"  Packets: {stats['packets']}")
        print(f"  Bytes: {stats['bytes']}")
        print(f"  Average Bandwidth: {bandwidth:.2f} Mbps")
        print(f"  Retransmissions: {stats['retransmissions']}\n")

if __name__ == "__main__":
    monitor_network(60)
