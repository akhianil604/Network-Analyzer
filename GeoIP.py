import socket
import struct
import requests

def capture_packet(target_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.bind(('0.0.0.0', 0))
    print("Listening for incoming packets...")
    while True:
        packet, addr = s.recvfrom(65565)
        ip_header = packet[:20]
        unpacked_header = struct.unpack('!BBHHHBBH4s4s', ip_header)
        source_ip = socket.inet_ntoa(unpacked_header[8])
        if source_ip == target_ip:
            print(f"Captured packet from {source_ip}")
            geoip_info = get_geoip_info(source_ip)
            print(f"GeoIP Info for {source_ip}: {geoip_info}")
            break
        
def get_geoip_info(ip):
    url = f"http://ip-api.com/json/{ip}?fields=country,region,city,isp"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": "Unable to get GeoIP information"}
    except requests.RequestException as e:
        return {"error": str(e)}