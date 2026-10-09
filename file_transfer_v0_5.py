#!/usr/bin/env python3
"""Simple authenticated file transfer for trusted networks.

Examples:
  Receiver:
    python file_transfer.py receive --host 0.0.0.0 --port 5001 --token "change-this-secret" --output received_files

  Sender:
    python file_transfer.py send 192.168.1.25 my_file.pdf --port 5001 --token "change-this-secret"

Security note: authentication is included, but traffic is not encrypted. Use only
on a trusted LAN, or tunnel it through SSH/VPN when transferring over the internet.
"""

import argparse
import hashlib
import hmac
import json
import os
import socket
import struct
from pathlib import Path

CHUNK_SIZE = 64 * 1024
DEFAULT_MAX_SIZE = 1024 * 1024 * 1024  # 1 GiB
MAX_HEADER_SIZE = 16 * 1024


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Connection closed before all data arrived")
        data.extend(chunk)
    return bytes(data)


def send_json(sock, value):
    payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_HEADER_SIZE:
        raise ValueError("Message header is too large")
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_json(sock):
    size = struct.unpack("!I", recv_exact(sock, 4))[0]
    if size > MAX_HEADER_SIZE:
        raise ValueError("Message header is too large")
    return json.loads(recv_exact(sock, size).decode("utf-8"))


def safe_destination(output_dir, incoming_name):
    # Path.name removes directory components such as ../../ or C:\\...
    name = Path(incoming_name).name
    if not name or name in {".", ".."}:
        raise ValueError("Invalid filename")

    output_dir = output_dir.resolve()
    candidate = output_dir / name
    stem, suffix = candidate.stem, candidate.suffix
    number = 1
    while candidate.exists():
        candidate = output_dir / f"{stem}_{number}{suffix}"
        number += 1
    return candidate


def handle_client(conn, address, token, output_dir, max_size):
    temp_path = None
    try:
        conn.settimeout(30)
        request = recv_json(conn)

        supplied_token = str(request.get("token", ""))
        if not hmac.compare_digest(supplied_token, token):
            send_json(conn, {"ok": False, "error": "Authentication failed"})
            return

        filename = str(request.get("filename", ""))
        file_size = int(request.get("size", -1))
        expected_hash = str(request.get("sha256", "")).lower()

        if file_size < 0 or file_size > max_size:
            send_json(conn, {"ok": False, "error": "File size is not allowed"})
            return
        if len(expected_hash) != 64 or any(c not in "0123456789abcdef" for c in expected_hash):
            send_json(conn, {"ok": False, "error": "Invalid SHA-256 value"})
            return

        destination = safe_destination(output_dir, filename)
        temp_path = destination.with_name(destination.name + ".part")
        send_json(conn, {"ok": True, "status": "ready"})

        digest = hashlib.sha256()
        remaining = file_size
        with temp_path.open("wb") as output:
            while remaining:
                chunk = conn.recv(min(CHUNK_SIZE, remaining))
                if not chunk:
                    raise ConnectionError("Connection ended during transfer")
                output.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)

        actual_hash = digest.hexdigest()
        if not hmac.compare_digest(actual_hash, expected_hash):
            temp_path.unlink(missing_ok=True)
            temp_path = None
            send_json(conn, {"ok": False, "error": "Checksum verification failed"})
            return

        temp_path.replace(destination)
        temp_path = None
        send_json(conn, {
            "ok": True,
            "saved_as": destination.name,
            "size": file_size,
            "sha256": actual_hash,
        })
        print(f"Received {destination.name!r} ({file_size} bytes) from {address[0]}")
    except Exception as exc:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
        try:
            send_json(conn, {"ok": False, "error": str(exc)})
        except Exception:
            pass
        print(f"Transfer from {address[0]} failed: {exc}")


def receive(host, port, token, output, max_size):
    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(5)
        print(f"Receiving on {host}:{port}")
        print(f"Saving files to: {output_dir.resolve()}")
        print("Press Ctrl+C to stop.")

        try:
            while True:
                conn, address = server.accept()
                with conn:
                    handle_client(conn, address, token, output_dir, max_size)
        except KeyboardInterrupt:
            print("\nReceiver stopped.")


def calculate_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def send(host, port, token, filename):
    path = Path(filename)
    if not path.is_file():
        raise SystemExit(f"File not found: {path}")

    size = path.stat().st_size
    digest = calculate_sha256(path)
    request = {
        "token": token,
        "filename": path.name,
        "size": size,
        "sha256": digest,
    }

    with socket.create_connection((host, port), timeout=30) as sock:
        send_json(sock, request)
        response = recv_json(sock)
        if not response.get("ok"):
            raise SystemExit(f"Receiver rejected transfer: {response.get('error', 'unknown error')}")

        sent = 0
        with path.open("rb") as source:
            while chunk := source.read(CHUNK_SIZE):
                sock.sendall(chunk)
                sent += len(chunk)
                percent = 100 if size == 0 else sent * 100 / size
                print(f"\rSending: {percent:6.2f}%", end="", flush=True)
        print()

        result = recv_json(sock)
        if not result.get("ok"):
            raise SystemExit(f"Transfer failed: {result.get('error', 'unknown error')}")
        print(f"Success: receiver saved {result['saved_as']!r}")
        print(f"SHA-256: {result['sha256']}")


def build_parser():
    parser = argparse.ArgumentParser(description="Send and receive files over TCP")
    subparsers = parser.add_subparsers(dest="command", required=True)

    receiver = subparsers.add_parser("receive", help="Start the file receiver")
    receiver.add_argument("--host", default="0.0.0.0", help="Address to listen on")
    receiver.add_argument("--port", type=int, default=5001)
    receiver.add_argument("--token", required=True, help="Shared secret")
    receiver.add_argument("--output", default="received_files")
    receiver.add_argument("--max-size", type=int, default=DEFAULT_MAX_SIZE,
                          help="Maximum accepted file size in bytes")

    sender = subparsers.add_parser("send", help="Send one file")
    sender.add_argument("host", help="Receiver IP address or hostname")
    sender.add_argument("filename", help="File to send")
    sender.add_argument("--port", type=int, default=5001)
    sender.add_argument("--token", required=True, help="Shared secret")
    return parser


def main():
    args = build_parser().parse_args()
    if not 1 <= args.port <= 65535:
        raise SystemExit("Port must be between 1 and 65535")

    if args.command == "receive":
        if args.max_size < 0:
            raise SystemExit("Maximum size cannot be negative")
        receive(args.host, args.port, args.token, args.output, args.max_size)
    else:
        send(args.host, args.port, args.token, args.filename)


if __name__ == "__main__":
    main()
