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
