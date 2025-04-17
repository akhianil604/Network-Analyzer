import socket
import struct
import time
import os
import sys

def checksum(data):
    """
    Computes the checksum for the ICMP packet.
    The checksum is used for error-checking in the IP header.
    """
    # If data length is odd, add a padding byte (0x00) to make it even
    if len(data) % 2:
        data += b'\x00'

    total = 0
    # Iterate through the data in 2-byte chunks and sum them
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word

    # Fold the 32-bit sum into a 16-bit checksum (carry over)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    # Return the one's complement of the sum (checksum)
    return ~total & 0xFFFF

def send_icmp_ping(dest_ip):
    """
    Sends an ICMP Echo Request (ping) to the target IP address and calculates the round-trip time.
    """
    try:
        # Create a raw socket to send and receive ICMP packets
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        # If the script is not run with root privileges, show an error
        print("Root privileges are required to run this script (use sudo).")
        sys.exit(1)

    sock.settimeout(2)  # Set a timeout of 2 seconds for waiting for the response

    # ICMP header fields
    icmp_type = 8  # Echo Request (ping)
    icmp_code = 0  # No code for Echo Request
    checksum_init = 0  # Initial checksum value
    packet_id = os.getpid() & 0xFFFF  # Packet ID set to the process ID (16-bit)
    seq_number = 1  # Sequence number for the ping

    # Payload to send with the ping (a string of 32 bytes)
    payload = b'Ping from Python!' + bytes(32 - len('Ping from Python!'))

    # Pack the ICMP header: type, code, checksum, packet_id, sequence_number
    header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum_init, packet_id, seq_number)

    # Calculate the checksum of the header and payload, then update the header
    checksum_value = checksum(header + payload)
    header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum_value, packet_id, seq_number)

    # Combine the header and the payload to form the full packet
    packet = header + payload

    # Send the packet to the target IP
    send_time = time.time()  # Record the send time for RTT calculation
    sock.sendto(packet, (dest_ip, 1))  # Send packet to the destination IP on ICMP protocol (port 1)

    try:
        # Wait for a response (ICMP Echo Reply)
        data, addr = sock.recvfrom(1024)  # Buffer size 1024 bytes
        recv_time = time.time()  # Record the response time
        rtt = (recv_time - send_time) * 1000  # Calculate round-trip time in milliseconds
        print(f"Reply from {addr[0]}: time={rtt:.2f}ms")  # Print the round-trip time
    except socket.timeout:
        # If the socket times out (no reply within 2 seconds)
        print("Request timed out.")
    finally:
        sock.close()  # Close the socket when done

def ping_interface():
    """
    Interactive function to prompt the user for an IP address to ping and call the ping function.
    """
    try:
        # Ask the user to input an IP address
        target = input("Enter IP address to ping: ")
        print(f"Pinging {target} with Python ICMP...")
        # Call the send_icmp_ping function to send the ping
        send_icmp_ping(target)
    except KeyboardInterrupt:
        # Handle Ctrl+C interruption
        print("\n[ICMP] Ping interrupted. Returning to main menu...")

if __name__ == "__main__":
    """
    Main function to handle script execution. It checks if the correct number of arguments is provided.
    If provided, it pings the target IP directly from the command line.
    """
    if len(sys.argv) != 2:
        # If the script is not run with exactly one argument (the target IP), show usage instructions
        print(f"Usage: sudo python3 {sys.argv[0]} <target_ip>")
        sys.exit(1)

    # Get the target IP from command line arguments
    target = sys.argv[1]
    print(f"Pinging {target} with Python ICMP...")
    # Call the send_icmp_ping function to send the ping
    send_icmp_ping(target)
