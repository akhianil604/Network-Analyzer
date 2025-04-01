import PacketSniffer
import SecureComm
import GeoIP
import socket
import ARP
from collections import defaultdict
import time

def main():
    while True:
        try:
            print("\n==== CLI-Based Network Monitoring & Security Tool ====")
            print("1. Raw Packet Sniffing")
            print("2. Secure End-to-End Encrypted Communication")
            print("3. GeoIP")
            print("4. ARP Spoofing")
            print("5. Exit")
            choice = input("Enter your choice: ")
            if choice == "1":
                PacketSniffer.sniff_packets()
            elif choice == "2":
                print("\n1. Start as Server\n2. Start as Client")
                role = input("Select Role: ")
                if role == "1":
                    SecureComm.start_server()
                elif role == "2":
                    target_ip = input("Enter Server IP: ")
                    SecureComm.start_client(target_ip)
                else:
                    print("Invalid Role Selection.")
            elif choice == "3":
                target_ip = input("Enter your desired IP address to track: ").strip()
                try:
                    socket.inet_aton(target_ip)
                except socket.error:
                    print("Invalid IP address format.")
                GeoIP.capture_packet(target_ip)
            elif choice == "4":
                raw_socket = ARP.create_raw_socket()
                ip_mac_map = defaultdict(str)  
                start_time = time.time()
                print("Starting ARP Spoofing Detection... Press Ctrl+C to stop.")
                while True:
                    try:
                        packet = raw_socket.recv(65565)
                        start_time = ARP.detect_arp_spoofing(packet, ip_mac_map, start_time)
                    except KeyboardInterrupt:
                        print("ARP Spoofing detection stopped.")
                        break
            elif choice == "5":
                print("Exiting...")
                break
            else:
                print("Invalid Choice.")
        except KeyboardInterrupt:
            print("\n[MAIN] Returning to menu... Press Ctrl+C again to exit.")
if __name__ == "__main__":
    main()