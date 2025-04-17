import socket
import struct
import requests

def capture_packet(target_ip):
    """
    Captures incoming TCP packets and filters them by the specified target IP address.
    Once a packet from the target IP is captured, it fetches the GeoIP information for the IP.
    """
    # Create a raw socket to capture all incoming IP packets (with TCP protocol)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    
    # Bind the socket to the local machine (any interface)
    s.bind(('0.0.0.0', 0))
    print("Listening for incoming packets...")

    while True:
        # Receive packet from the network
        packet, addr = s.recvfrom(65565)  # Buffer size of 65565 bytes

        # Extract the first 20 bytes (IP header) from the packet
        ip_header = packet[:20]

        # Unpack the IP header using struct to get the relevant fields
        # Format: '!BBHHHBBH4s4s' corresponds to the fields of the IP header (source and destination IPs, etc.)
        unpacked_header = struct.unpack('!BBHHHBBH4s4s', ip_header)

        # Convert the source IP (in binary form) to a human-readable string format
        source_ip = socket.inet_ntoa(unpacked_header[8])

        # Check if the source IP matches the target IP
        if source_ip == target_ip:
            print(f"Captured packet from {source_ip}")
            
            # Get the GeoIP information for the captured source IP
            geoip_info = get_geoip_info(source_ip)
            print(f"GeoIP Info for {source_ip}: {geoip_info}")
            
            # Stop capturing packets after we get the target IP's information
            break

def get_geoip_info(ip):
    """
    Fetches geographical information about the given IP address using the ip-api service.
    Returns information like country, region, city, and ISP.
    """
    # Construct the URL to get GeoIP data for the given IP
    url = f"http://ip-api.com/json/{ip}?fields=country,region,city,isp"
    
    try:
        # Send an HTTP GET request to the ip-api service
        response = requests.get(url)
        
        # If the response status code is 200 (OK), return the JSON data
        if response.status_code == 200:
            return response.json()
        else:
            # If the request fails, return an error message
            return {"error": "Unable to get GeoIP information"}
    
    # Catch any network or request-related errors
    except requests.RequestException as e:
        return {"error": str(e)}
