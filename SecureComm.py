import socket
import os
import base64
import struct
import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

def derive_aes_key(shared_secret):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b'salt_1234', iterations=100000)
    return kdf.derive(shared_secret)

def encrypt_message(aes_key, plaintext):
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ciphertext).decode()

def decrypt_message(aes_key, encrypted_text):
    aesgcm = AESGCM(aes_key)
    decoded = base64.b64decode(encrypted_text)
    nonce, ciphertext = decoded[:12], decoded[12:]
    return aesgcm.decrypt(nonce, ciphertext, None).decode()

def start_server():
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        server.bind(("0.0.0.0", 9000))
        print("[SERVER] Waiting for client... Press Ctrl+C to stop.")
        while True:
            packet, addr = server.recvfrom(65535)
            ip_header = packet[0:20]
            ip_hdr = struct.unpack("!BBHHHBBH4s4s", ip_header)
            src_ip = socket.inet_ntoa(ip_hdr[8])
            data = packet[20:].decode(errors="ignore")
            if "PUBLIC_KEY" in data:
                client_public_key = serialization.load_pem_public_key(data.encode())
                shared_secret = private_key.exchange(ec.ECDH(), client_public_key)
                aes_key = derive_aes_key(shared_secret)
                print(f"[SERVER] Secure connection established with {src_ip}")
                while True:
                    enc_data, _ = server.recvfrom(65535)
                    enc_message = enc_data[20:].decode(errors="ignore")
                    try:
                        decrypted_message = decrypt_message(aes_key, enc_message)
                        print(f"[SERVER] {src_ip} says: {decrypted_message}")
                    except:
                        print("[SERVER] Unable to decrypt message.")
    except KeyboardInterrupt:
        print("\n[SERVER] Stopping Secure Communication... Returning to Main Menu.\n")
        return

def start_client(target_ip):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        pub_key_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        client.sendto(pub_key_pem + b" PUBLIC_KEY", (target_ip, 9000))
        data, _ = client.recvfrom(65535)
        server_public_key = serialization.load_pem_public_key(data)
        shared_secret = private_key.exchange(ec.ECDH(), server_public_key)
        aes_key = derive_aes_key(shared_secret)
        print(f"[CLIENT] Secure connection established with {target_ip}. Press Ctrl+C to stop.")
        while True:
            message = input("[CLIENT] Enter message: ")
            enc_message = encrypt_message(aes_key, message)
            client.sendto(enc_message.encode(), (target_ip, 9000))
    except KeyboardInterrupt:
        print("\n[CLIENT] Stopping Secure Communication... Returning to Main Menu.\n")
        return