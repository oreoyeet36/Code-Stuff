#!/usr/bin/env python3
"""Encrypted local file transfer with a Tkinter graphical interface.

Dependency:
    python -m pip install cryptography

Security design:
- A shared passphrase is converted into a 256-bit key with Scrypt.
- A fresh random salt is used for every connection.
- Challenge-response HMAC authenticates both peers without sending the passphrase.
- Metadata and file chunks use AES-256-GCM authenticated encryption.
- A unique nonce is generated for every encrypted message.

Both computers must use this encrypted version. It is not protocol-compatible
with the earlier unencrypted version.
"""

import hashlib
import hmac
import json
import os
import queue
import socket
import struct
import threading
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError as exc:
    raise SystemExit(
        "The 'cryptography' package is required. Install it with:\n"
        "python -m pip install cryptography"
    ) from exc

CHUNK_SIZE = 64 * 1024
DEFAULT_PORT = 5001
DEFAULT_MAX_SIZE = 1024 * 1024 * 1024
MAX_FRAME_SIZE = CHUNK_SIZE + 64 * 1024
MAGIC = b"FTENC1"
PROTOCOL_CONTEXT = b"file-transfer-gui-v2"


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Connection closed before all data arrived")
        data.extend(chunk)
    return bytes(data)


def send_frame(sock, payload):
    if len(payload) > MAX_FRAME_SIZE:
        raise ValueError("Frame is too large")
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_frame(sock):
    size = struct.unpack("!I", recv_exact(sock, 4))[0]
    if size > MAX_FRAME_SIZE:
        raise ValueError("Frame is too large")
    return recv_exact(sock, size)


def derive_key(passphrase, salt):
    if not passphrase:
        raise ValueError("The shared passphrase cannot be empty")
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
    return kdf.derive(passphrase.encode("utf-8"))


def proof(key, role, client_challenge, server_challenge):
    message = PROTOCOL_CONTEXT + role + client_challenge + server_challenge
    return hmac.new(key, message, hashlib.sha256).digest()


class SecureChannel:
    def __init__(self, sock, key):
        self.sock = sock
        self.aes = AESGCM(key)
        self.send_counter = 0
        self.recv_counter = 0

    def send(self, plaintext, purpose=b"data"):
        counter = self.send_counter
        self.send_counter += 1
        nonce = os.urandom(12)
        aad = PROTOCOL_CONTEXT + purpose + struct.pack("!Q", counter)
        ciphertext = self.aes.encrypt(nonce, plaintext, aad)
        send_frame(self.sock, nonce + ciphertext)

    def recv(self, purpose=b"data"):
        counter = self.recv_counter
        self.recv_counter += 1
        payload = recv_frame(self.sock)
        if len(payload) < 28:
            raise ValueError("Encrypted frame is too short")
        nonce, ciphertext = payload[:12], payload[12:]
        aad = PROTOCOL_CONTEXT + purpose + struct.pack("!Q", counter)
        try:
            return self.aes.decrypt(nonce, ciphertext, aad)
        except InvalidTag as exc:
            raise PermissionError("Encrypted data failed authentication") from exc

    def send_json(self, value, purpose=b"json"):
        self.send(json.dumps(value, separators=(",", ":")).encode("utf-8"), purpose)

    def recv_json(self, purpose=b"json"):
        return json.loads(self.recv(purpose).decode("utf-8"))


def client_handshake(sock, passphrase):
    client_challenge = os.urandom(32)
    sock.sendall(MAGIC + client_challenge)
    response = recv_exact(sock, 16 + 32 + 32)
    salt = response[:16]
    server_challenge = response[16:48]
    server_proof = response[48:]
    key = derive_key(passphrase, salt)
    expected = proof(key, b"server", client_challenge, server_challenge)
    if not hmac.compare_digest(server_proof, expected):
        raise PermissionError("Authentication failed. Check the shared passphrase.")
    sock.sendall(proof(key, b"client", client_challenge, server_challenge))
    channel = SecureChannel(sock, key)
    result = channel.recv_json(b"auth")
    if not result.get("ok"):
        raise PermissionError("Authentication failed")
    return channel


def server_handshake(sock, passphrase):
    opening = recv_exact(sock, len(MAGIC) + 32)
    if opening[:len(MAGIC)] != MAGIC:
        raise PermissionError("Unsupported or unencrypted client")
    client_challenge = opening[len(MAGIC):]
    salt = os.urandom(16)
    server_challenge = os.urandom(32)
    key = derive_key(passphrase, salt)
    sock.sendall(salt + server_challenge + proof(key, b"server", client_challenge, server_challenge))
    client_proof = recv_exact(sock, 32)
    if not hmac.compare_digest(client_proof, proof(key, b"client", client_challenge, server_challenge)):
        raise PermissionError("Authentication failed")
    channel = SecureChannel(sock, key)
    channel.send_json({"ok": True}, b"auth")
    return channel


def safe_destination(output_dir, incoming_name):
    name = Path(incoming_name).name
    if not name or name in {".", ".."}:
        raise ValueError("Invalid filename")
    output_dir = output_dir.resolve()
    candidate = output_dir / name
    stem, suffix = candidate.stem, candidate.suffix
    number = 1
    while candidate.exists() or candidate.with_name(candidate.name + ".part").exists():
        candidate = output_dir / f"{stem}_{number}{suffix}"
        number += 1
    return candidate


def local_ip_address():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


class ReceiverServer:
    def __init__(self, events):
        self.events = events
        self.stop_event = threading.Event()
        self.server_socket = None
        self.thread = None

    @property
    def running(self):
        return bool(self.thread and self.thread.is_alive())

    def start(self, host, port, passphrase, output_dir):
        if self.running:
            return
        self.stop_event.clear()
        self.thread = threading.Thread(
            target=self._serve,
            args=(host, port, passphrase, Path(output_dir)), daemon=True
        )
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.server_socket:
            try:
                self.server_socket.close()
            except OSError:
                pass
        self.events.put(("receiver_state", False))

    def _serve(self, host, port, passphrase, output_dir):
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                self.server_socket = server
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.settimeout(0.5)
                server.bind((host, port))
                server.listen(5)
                self.events.put(("receiver_state", True))
                self.events.put(("log", f"Encrypted receiver started on {host}:{port}"))
                self.events.put(("log", f"Files will be saved in {output_dir.resolve()}"))
                while not self.stop_event.is_set():
                    try:
                        conn, address = server.accept()
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    threading.Thread(
                        target=self._handle_client,
                        args=(conn, address, passphrase, output_dir), daemon=True
                    ).start()
        except Exception as exc:
            self.events.put(("error", f"Could not start receiver: {exc}"))
        finally:
            self.server_socket = None
            self.events.put(("receiver_state", False))
            self.events.put(("log", "Receiver stopped"))

    def _handle_client(self, conn, address, passphrase, output_dir):
        temp_path = None
        try:
            with conn:
                conn.settimeout(60)
                channel = server_handshake(conn, passphrase)
                metadata = channel.recv_json(b"metadata")
                filename = str(metadata.get("filename", ""))
                file_size = int(metadata.get("size", -1))
                expected_hash = str(metadata.get("sha256", "")).lower()
                if file_size < 0 or file_size > DEFAULT_MAX_SIZE:
                    channel.send_json({"ok": False, "error": "File size is not allowed"}, b"status")
                    return
                if len(expected_hash) != 64 or any(c not in "0123456789abcdef" for c in expected_hash):
                    channel.send_json({"ok": False, "error": "Invalid checksum"}, b"status")
                    return

                destination = safe_destination(output_dir, filename)
                temp_path = destination.with_name(destination.name + ".part")
                channel.send_json({"ok": True}, b"status")
                self.events.put(("log", f"Receiving encrypted file {destination.name} from {address[0]}"))

                digest = hashlib.sha256()
                remaining = file_size
                received = 0
                with temp_path.open("wb") as output:
                    while remaining:
                        chunk = channel.recv(b"file-chunk")
                        if not chunk or len(chunk) > remaining or len(chunk) > CHUNK_SIZE:
                            raise ValueError("Invalid encrypted file chunk")
                        output.write(chunk)
                        digest.update(chunk)
                        received += len(chunk)
                        remaining -= len(chunk)
                        percent = 100 if file_size == 0 else received * 100 / file_size
                        self.events.put(("receive_progress", percent, destination.name))

                actual_hash = digest.hexdigest()
                if not hmac.compare_digest(actual_hash, expected_hash):
                    raise ValueError("Checksum verification failed")
                temp_path.replace(destination)
                temp_path = None
                channel.send_json({"ok": True, "saved_as": destination.name}, b"complete")
                self.events.put(("receive_progress", 100, destination.name))
                self.events.put(("log", f"Received and verified {destination.name}"))
        except Exception as exc:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
            self.events.put(("log", f"Transfer from {address[0]} failed: {exc}"))


class FileTransferApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Encrypted Local File Transfer")
        self.geometry("790x670")
        self.minsize(700, 600)
        self.protocol("WM_DELETE_WINDOW", self.close_app)
        self.events = queue.Queue()
        self.receiver = ReceiverServer(self.events)
        self.sending = False
        self.host_var = tk.StringVar(value="0.0.0.0")
        self.port_var = tk.StringVar(value=str(DEFAULT_PORT))
        self.passphrase_var = tk.StringVar()
        self.show_passphrase_var = tk.BooleanVar(value=False)
        self.output_var = tk.StringVar(value=str(Path.cwd() / "received_files"))
        self.target_var = tk.StringVar(value=local_ip_address())
        self.file_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready. AES-256-GCM encryption enabled.")
        self.ip_var = tk.StringVar(value=f"This computer's likely local IP: {local_ip_address()}")
        self._build_ui()
        self.after(100, self._process_events)

    def _build_ui(self):
        style = ttk.Style(self)
        style.configure("Title.TLabel", font=("TkDefaultFont", 18, "bold"))
        style.configure("Secure.TLabel", foreground="#167a3f")
        outer = ttk.Frame(self, padding=18)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="Encrypted Local File Transfer", style="Title.TLabel").pack(anchor="w")
        ttk.Label(outer, text="End-to-end encrypted with AES-256-GCM", style="Secure.TLabel").pack(anchor="w", pady=(2, 14))
        notebook = ttk.Notebook(outer)
        notebook.pack(fill="both", expand=True)
        receive_tab = ttk.Frame(notebook, padding=16)
        send_tab = ttk.Frame(notebook, padding=16)
        notebook.add(receive_tab, text="Receive")
        notebook.add(send_tab, text="Send")
        self._build_receive_tab(receive_tab)
        self._build_send_tab(send_tab)
        log_frame = ttk.LabelFrame(outer, text="Activity", padding=8)
        log_frame.pack(fill="both", pady=(14, 0))
        self.log_box = tk.Text(log_frame, height=8, state="disabled", wrap="word")
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_box.yview)
        self.log_box.configure(yscrollcommand=scrollbar.set)
        self.log_box.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        ttk.Label(outer, textvariable=self.status_var).pack(anchor="w", pady=(8, 0))

    def _entry(self, parent, label, variable, row, secret=False):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=(0, 10), pady=6)
        entry = ttk.Entry(parent, textvariable=variable, show="*" if secret else "")
        entry.grid(row=row, column=1, sticky="ew", pady=6)
        if secret:
            self.secret_entries.append(entry)
        return entry

    def _build_receive_tab(self, parent):
        self.secret_entries = getattr(self, "secret_entries", [])
        parent.columnconfigure(1, weight=1)
        self._entry(parent, "Listen address", self.host_var, 0)
        self._entry(parent, "Port", self.port_var, 1)
        self._entry(parent, "Shared passphrase", self.passphrase_var, 2, True)
        self._entry(parent, "Save folder", self.output_var, 3)
        ttk.Button(parent, text="Browse...", command=self.choose_output).grid(row=3, column=2, padx=(8, 0))
        ttk.Checkbutton(parent, text="Show passphrase", variable=self.show_passphrase_var,
                        command=self.toggle_passphrase).grid(row=4, column=1, sticky="w")
        ttk.Label(parent, textvariable=self.ip_var).grid(row=5, column=0, columnspan=3, sticky="w", pady=(8, 12))
        buttons = ttk.Frame(parent)
        buttons.grid(row=6, column=0, columnspan=3, sticky="w")
        self.start_button = ttk.Button(buttons, text="Start Encrypted Receiver", command=self.start_receiver)
        self.start_button.pack(side="left")
        self.stop_button = ttk.Button(buttons, text="Stop", command=self.receiver.stop, state="disabled")
        self.stop_button.pack(side="left", padx=(8, 0))
        self.receive_progress = ttk.Progressbar(parent, maximum=100)
        self.receive_progress.grid(row=7, column=0, columnspan=3, sticky="ew", pady=(20, 0))
        self.receive_label = ttk.Label(parent, text="Waiting for an encrypted file")
        self.receive_label.grid(row=8, column=0, columnspan=3, sticky="w", pady=(5, 0))

    def _build_send_tab(self, parent):
        self.secret_entries = getattr(self, "secret_entries", [])
        parent.columnconfigure(1, weight=1)
        self._entry(parent, "Receiver IP", self.target_var, 0)
        self._entry(parent, "Port", self.port_var, 1)
        self._entry(parent, "Shared passphrase", self.passphrase_var, 2, True)
        self._entry(parent, "File", self.file_var, 3)
        ttk.Button(parent, text="Browse...", command=self.choose_file).grid(row=3, column=2, padx=(8, 0))
        ttk.Checkbutton(parent, text="Show passphrase", variable=self.show_passphrase_var,
                        command=self.toggle_passphrase).grid(row=4, column=1, sticky="w")
        self.send_button = ttk.Button(parent, text="Send Encrypted File", command=self.begin_send)
        self.send_button.grid(row=5, column=0, columnspan=3, sticky="w", pady=(12, 16))
        self.send_progress = ttk.Progressbar(parent, maximum=100)
        self.send_progress.grid(row=6, column=0, columnspan=3, sticky="ew")
        self.send_label = ttk.Label(parent, text="No file selected")
        self.send_label.grid(row=7, column=0, columnspan=3, sticky="w", pady=(5, 0))

    def toggle_passphrase(self):
        show = "" if self.show_passphrase_var.get() else "*"
        for entry in self.secret_entries:
            entry.configure(show=show)

    def choose_output(self):
        folder = filedialog.askdirectory(initialdir=self.output_var.get() or str(Path.cwd()))
        if folder:
            self.output_var.set(folder)

    def choose_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_var.set(filename)
            self.send_label.config(text=Path(filename).name)

    def valid_settings(self):
        try:
            port = int(self.port_var.get())
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid port", "Enter a port from 1 to 65535.")
            return None
        passphrase = self.passphrase_var.get()
        if len(passphrase) < 12:
            messagebox.showerror("Weak passphrase", "Use a shared passphrase of at least 12 characters.")
            return None
        return port, passphrase

    def start_receiver(self):
        values = self.valid_settings()
        if not values:
            return
        port, passphrase = values
        self.receiver.start(self.host_var.get().strip() or "0.0.0.0", port, passphrase, self.output_var.get())
        self.status_var.set("Starting encrypted receiver...")

    def begin_send(self):
        if self.sending:
            return
        values = self.valid_settings()
        path = Path(self.file_var.get())
        host = self.target_var.get().strip()
        if not values:
            return
        if not host:
            messagebox.showerror("Missing address", "Enter the receiver's IP address.")
            return
        if not path.is_file():
            messagebox.showerror("Missing file", "Choose a file to send.")
            return
        port, passphrase = values
        self.sending = True
        self.send_button.config(state="disabled")
        self.send_progress["value"] = 0
        threading.Thread(target=self._send_worker, args=(host, port, passphrase, path), daemon=True).start()

    def _send_worker(self, host, port, passphrase, path):
        try:
            size = path.stat().st_size
            digest = hashlib.sha256()
            processed = 0
            with path.open("rb") as source:
                while chunk := source.read(CHUNK_SIZE):
                    digest.update(chunk)
                    processed += len(chunk)
                    percent = 0 if size == 0 else processed * 10 / size
                    self.events.put(("send_status", percent, "Preparing and checking file..."))
            with socket.create_connection((host, port), timeout=30) as sock:
                sock.settimeout(60)
                channel = client_handshake(sock, passphrase)
                channel.send_json({"filename": path.name, "size": size, "sha256": digest.hexdigest()}, b"metadata")
                response = channel.recv_json(b"status")
                if not response.get("ok"):
                    raise RuntimeError(response.get("error", "Receiver rejected transfer"))
                sent = 0
                with path.open("rb") as source:
                    while chunk := source.read(CHUNK_SIZE):
                        channel.send(chunk, b"file-chunk")
                        sent += len(chunk)
                        percent = 100 if size == 0 else 10 + sent * 90 / size
                        self.events.put(("send_status", percent, f"Encrypting and sending {path.name}"))
                result = channel.recv_json(b"complete")
                if not result.get("ok"):
                    raise RuntimeError(result.get("error", "Transfer failed"))
                self.events.put(("send_complete", result["saved_as"]))
        except Exception as exc:
            self.events.put(("send_error", str(exc)))

    def _log(self, text):
        self.log_box.config(state="normal")
        self.log_box.insert("end", text + "\n")
        self.log_box.see("end")
        self.log_box.config(state="disabled")

    def _process_events(self):
        try:
            while True:
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "log":
                    self._log(event[1])
                elif kind == "error":
                    self._log(event[1]); messagebox.showerror("Receiver error", event[1])
                elif kind == "receiver_state":
                    running = event[1]
                    self.start_button.config(state="disabled" if running else "normal")
                    self.stop_button.config(state="normal" if running else "disabled")
                    self.status_var.set("Encrypted receiver is running" if running else "Ready")
                elif kind == "receive_progress":
                    self.receive_progress["value"] = event[1]
                    self.receive_label.config(text=f"{event[2]}: {event[1]:.1f}%")
                elif kind == "send_status":
                    self.send_progress["value"] = event[1]
                    self.send_label.config(text=event[2])
                elif kind == "send_complete":
                    self.sending = False
                    self.send_button.config(state="normal")
                    self.send_progress["value"] = 100
                    self.send_label.config(text=f"Encrypted transfer complete: {event[1]}")
                    self._log(f"Encrypted transfer completed as {event[1]}")
                    messagebox.showinfo("Transfer complete", f"The encrypted transfer completed as {event[1]}.")
                elif kind == "send_error":
                    self.sending = False
                    self.send_button.config(state="normal")
                    self.send_label.config(text="Transfer failed")
                    self._log(f"Send failed: {event[1]}")
                    messagebox.showerror("Transfer failed", event[1])
        except queue.Empty:
            pass
        self.after(100, self._process_events)

    def close_app(self):
        self.receiver.stop()
        self.destroy()


def main():
    FileTransferApp().mainloop()


if __name__ == "__main__":
    main()
