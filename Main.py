import PacketSniffer
import GeoIP
import socket
import icmp_ping
import tcp_monitor
import tcp_flow
import port_scanner
import packet_loss
import EDA
import DOS
from collections import defaultdict
import time

def main():
    while True:
        try:
            print("\n==== CLI-Based Network Monitoring & Security Tool ====")
            print("1. Raw Packet Sniffing")
            print("2. GeoIP")
            print("3. ICMP Ping")
            print("4. TCP Connection Monitor")
            print("5. TCP Flow Analysis")
            print("6. Port Scanner")
            print("7. Network Performance Monitor")
            print("8. DOS Attack Detection")
            print("9. EDA on Network Traffic")
            print("10. Exit")
            choice = input("Enter your choice: ")
            if choice == "1":
                PacketSniffer.sniff_packets()
            elif choice == "2":
                target_ip = input("Enter your desired IP address to track: ").strip()
                try:
                    socket.inet_aton(target_ip)
                    GeoIP.capture_packet(target_ip)
                except socket.error:
                    print("Invalid IP address format.")
            elif choice == "3":
                icmp_ping.ping_interface()
                break
            elif choice == "4":
                tcp_monitor.start_monitor()
                break
            elif choice == "5":
                tcp_flow.start_flow_analysis()
                break
            elif choice == "6":
                port_scanner.start_port_scanner()
                break
            elif choice == "7":
                packet_loss.start_monitoring_interface()
                break
            elif choice == "8":
                DOS.monitor_dos()
                break
            elif choice == "9":
                EDA.launch_packet_eda_gui()
            elif choice == "10":
                print("Exiting...")
                break
            else:
                print("Invalid Choice.")
        except KeyboardInterrupt:
            print("\n[MAIN] Returning to menu... Press Ctrl+C again to exit.")

if __name__ == "__main__":
    main()