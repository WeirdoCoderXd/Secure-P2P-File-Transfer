#!/usr/bin/env python3
"""
Secure P2P File Transfer

This script allows two peers to establish a secure, end-to-end encrypted
connection and transfer files without exposing their contents. It uses
X25519 for key exchange and AES-GCM for data encryption.

Dependencies:
  pip install cryptography

Usage:
  Server mode:
    python secure_p2p_file_transfer.py --mode server --host 0.0.0.0 --port 5000 --output-dir received_files

  Client mode:
    python secure_p2p_file_transfer.py --mode client --host <SERVER_IP> --port 5000 --file path/to/file

"""
import argparse
import socket
import os
import struct
import secrets
import sys
from typing import Optional  # Add this import for Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def derive_key(private_key: X25519PrivateKey, peer_public_bytes: bytes) -> bytes:
    """
    Derive a shared AES key using X25519 key exchange and HKDF.
    """
    peer_public = X25519PublicKey.from_public_bytes(peer_public_bytes)
    shared_secret = private_key.exchange(peer_public)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'p2p-file-transfer',
    )
    return hkdf.derive(shared_secret)


def send_public_key(conn: socket.socket, private_key: X25519PrivateKey) -> None:
    """Send this peer's public key to the other side."""
    public_bytes = private_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    conn.sendall(public_bytes)


def recv_public_key(conn: socket.socket) -> bytes:
    """Receive 32 bytes of the peer's public key."""
    data = conn.recv(32)
    if len(data) != 32:
        raise Exception("Invalid public key length")
    return data


def recvall(conn: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from the socket."""
    buf = b''  
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise Exception("Connection closed unexpectedly")
        buf += chunk
    return buf


def send_encrypted(conn: socket.socket, aesgcm: AESGCM, data: bytes) -> None:
    """Encrypt data with AES-GCM and send it over the connection."""
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    packet = nonce + ciphertext
    conn.sendall(struct.pack('>I', len(packet)))
    conn.sendall(packet)


def recv_encrypted(conn: socket.socket, aesgcm: AESGCM) -> Optional[bytes]:
    """Receive an encrypted packet, decrypt it, and return the plaintext.
    Returns None when a zero-length packet is received (end-of-stream signal)."""
    raw_len = recvall(conn, 4)
    (length,) = struct.unpack('>I', raw_len)
    if length == 0:
        return None
    packet = recvall(conn, length)
    nonce = packet[:12]
    ciphertext = packet[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)


def server_mode(host: str, port: int, output_dir: str) -> None:
    """Run in server mode: listen for a client, exchange public keys, and receive a file."""
    os.makedirs(output_dir, exist_ok=True)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)
        print(f"Server listening on {host}:{port}")
        conn, addr = s.accept()
        with conn:
            print(f"Connection from {addr}")

            # Handshake: exchange X25519 public keys
            private_key = X25519PrivateKey.generate()
            send_public_key(conn, private_key)
            client_pub = recv_public_key(conn)
            key = derive_key(private_key, client_pub)
            aesgcm = AESGCM(key)

            # Receive header: "filename|filesize"
            header = recv_encrypted(conn, aesgcm)
            if header is None:
                print("No header received")
                return
            name, size = header.decode().split('|')
            filesize = int(size)
            filepath = os.path.join(output_dir, os.path.basename(name))
            print(f"Receiving file: {name} ({filesize} bytes)")

            # Receive file data in chunks
            received = 0
            with open(filepath, 'wb') as f:
                while True:
                    chunk = recv_encrypted(conn, aesgcm)
                    if chunk is None:
                        break
                    f.write(chunk)
                    received += len(chunk)
                    print(f"\rReceived {received}/{filesize} bytes", end='')
                print("\nFile received successfully.")


def client_mode(host: str, port: int, file_path: str) -> None:
    """Run in client mode: connect to server, exchange keys, and send the specified file."""
    if not os.path.isfile(file_path):
        print("Error: file does not exist.")
        return
    filesize = os.path.getsize(file_path)
    filename = os.path.basename(file_path)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))

        # Handshake: exchange X25519 public keys
        private_key = X25519PrivateKey.generate()
        server_pub = recv_public_key(s)
        send_public_key(s, private_key)
        key = derive_key(private_key, server_pub)
        aesgcm = AESGCM(key)

        # Send header: "filename|filesize"
        header = f"{filename}|{filesize}".encode()
        send_encrypted(s, aesgcm, header)

        # Send file data in chunks
        sent = 0
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                send_encrypted(s, aesgcm, chunk)
                sent += len(chunk)
                print(f"\rSent {sent}/{filesize} bytes", end='')

        # Signal end of file transfer
        s.sendall(struct.pack('>I', 0))
        print("\nFile sent successfully.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Secure P2P File Transfer")
    parser.add_argument('--mode', choices=['server', 'client'], required=True,
                        help='Mode: server to receive files, client to send a file')
    parser.add_argument('--host', default='127.0.0.1', help='Host or IP to bind/connect')
    parser.add_argument('--port', type=int, default=5000, help='Port number')
    parser.add_argument('--file', help='File path to send (client mode)')
    parser.add_argument('--output-dir', default='received_files',
                        help='Directory to save received files (server mode)')
    args = parser.parse_args()

    if args.mode == 'server':
        server_mode(args.host, args.port, args.output_dir)
    else:
        if not args.file:
            parser.error("Client mode requires --file")
        client_mode(args.host, args.port, args.file)

