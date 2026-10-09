#!/usr/bin/env python3
"""Graphical file transfer app for trusted local networks.

No third-party packages are required. Uses Tkinter for the interface.
Security note: the shared secret authenticates transfers, but file contents are
not encrypted yet. Use this version only on a trusted LAN.
"""

import hashlib
import hmac
import json
import queue
import socket
import struct
import threading
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

CHUNK_SIZE = 64 * 1024
DEFAULT_PORT = 5001
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


def calculate_sha256(path, progress=None):
    digest = hashlib.sha256()
    total = path.stat().st_size
    processed = 0
    with path.open("rb") as source:
        while chunk := source.read(CHUNK_SIZE):
            digest.update(chunk)
            processed += len(chunk)
            if progress and total:
                progress(processed * 100 / total, "Checking file...")
    return digest.hexdigest()


def local_ip_address():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


class ReceiverServer:
    def __init__(self, event_queue):
        self.event_queue = event_queue
        self.stop_event = threading.Event()
        self.server_socket = None
        self.thread = None

    @property
    def running(self):
        return bool(self.thread and self.thread.is_alive())

    def start(self, host, port, token, output_dir):
        if self.running:
            return
        self.stop_event.clear()
        self.thread = threading.Thread(
            target=self._serve,
            args=(host, port, token, Path(output_dir)),
            daemon=True,
        )
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.server_socket:
            try:
                self.server_socket.close()
            except OSError:
                pass
        self.event_queue.put(("receiver_state", False))

    def _serve(self, host, port, token, output_dir):
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                self.server_socket = server
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.settimeout(0.5)
                server.bind((host, port))
                server.listen(5)
                self.event_queue.put(("receiver_state", True))
                self.event_queue.put(("log", f"Receiver started on {host}:{port}"))
                self.event_queue.put(("log", f"Files will be saved in {output_dir.resolve()}"))

                while not self.stop_event.is_set():
                    try:
                        conn, address = server.accept()
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    threading.Thread(
                        target=self._handle_client,
                        args=(conn, address, token, output_dir),
                        daemon=True,
                    ).start()
        except Exception as exc:
            self.event_queue.put(("error", f"Could not start receiver: {exc}"))
        finally:
            self.server_socket = None
            self.event_queue.put(("receiver_state", False))
            self.event_queue.put(("log", "Receiver stopped"))

    def _handle_client(self, conn, address, token, output_dir):
        temp_path = None
        try:
            with conn:
                conn.settimeout(30)
                request = recv_json(conn)
                supplied_token = str(request.get("token", ""))
                if not hmac.compare_digest(supplied_token, token):
                    send_json(conn, {"ok": False, "error": "Authentication failed"})
                    self.event_queue.put(("log", f"Rejected connection from {address[0]}"))
                    return

                filename = str(request.get("filename", ""))
                file_size = int(request.get("size", -1))
                expected_hash = str(request.get("sha256", "")).lower()

                if file_size < 0 or file_size > DEFAULT_MAX_SIZE:
                    send_json(conn, {"ok": False, "error": "File size is not allowed"})
                    return
                if len(expected_hash) != 64 or any(c not in "0123456789abcdef" for c in expected_hash):
                    send_json(conn, {"ok": False, "error": "Invalid checksum"})
                    return

                destination = safe_destination(output_dir, filename)
                temp_path = destination.with_name(destination.name + ".part")
                send_json(conn, {"ok": True, "status": "ready"})
                self.event_queue.put(("log", f"Receiving {destination.name} from {address[0]}"))

                digest = hashlib.sha256()
                remaining = file_size
                received = 0
                with temp_path.open("wb") as output:
                    while remaining:
                        chunk = conn.recv(min(CHUNK_SIZE, remaining))
                        if not chunk:
                            raise ConnectionError("Connection ended during transfer")
                        output.write(chunk)
                        digest.update(chunk)
                        received += len(chunk)
                        remaining -= len(chunk)
                        percent = 100 if file_size == 0 else received * 100 / file_size
                        self.event_queue.put(("receive_progress", percent, destination.name))

                actual_hash = digest.hexdigest()
                if not hmac.compare_digest(actual_hash, expected_hash):
                    temp_path.unlink(missing_ok=True)
                    temp_path = None
                    send_json(conn, {"ok": False, "error": "Checksum verification failed"})
                    raise ValueError("Checksum verification failed")

                temp_path.replace(destination)
                temp_path = None
                send_json(conn, {
                    "ok": True,
                    "saved_as": destination.name,
                    "size": file_size,
                    "sha256": actual_hash,
                })
                self.event_queue.put(("receive_progress", 100, destination.name))
                self.event_queue.put(("log", f"Received {destination.name} successfully"))
        except Exception as exc:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
            self.event_queue.put(("log", f"Transfer from {address[0]} failed: {exc}"))
            try:
                send_json(conn, {"ok": False, "error": str(exc)})
            except Exception:
                pass


class FileTransferApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Local File Transfer")
        self.geometry("780x650")
        self.minsize(700, 580)
        self.protocol("WM_DELETE_WINDOW", self.close_app)

        self.events = queue.Queue()
        self.receiver = ReceiverServer(self.events)
        self.sending = False

        self.host_var = tk.StringVar(value="0.0.0.0")
        self.port_var = tk.StringVar(value=str(DEFAULT_PORT))
        self.token_var = tk.StringVar()
        self.output_var = tk.StringVar(value=str(Path.cwd() / "received_files"))
        self.target_var = tk.StringVar(value=local_ip_address())
        self.file_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")
        self.ip_var = tk.StringVar(value=f"This computer's likely local IP: {local_ip_address()}")

        self._build_ui()
        self.after(100, self._process_events)

    def _build_ui(self):
        style = ttk.Style(self)
        style.configure("Title.TLabel", font=("TkDefaultFont", 18, "bold"))
        style.configure("Heading.TLabel", font=("TkDefaultFont", 11, "bold"))

        outer = ttk.Frame(self, padding=18)
        outer.pack(fill="both", expand=True)

        ttk.Label(outer, text="Local File Transfer", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            outer,
            text="Send one file between computers on the same trusted network.",
        ).pack(anchor="w", pady=(2, 14))

        notebook = ttk.Notebook(outer)
        notebook.pack(fill="both", expand=True)

        receive_tab = ttk.Frame(notebook, padding=16)
        send_tab = ttk.Frame(notebook, padding=16)
        notebook.add(receive_tab, text="Receive")
        notebook.add(send_tab, text="Send")

        self._build_receive_tab(receive_tab)
        self._build_send_tab(send_tab)

        log_frame = ttk.LabelFrame(outer, text="Activity", padding=8)
        log_frame.pack(fill="both", expand=False, pady=(14, 0))
        self.log_box = tk.Text(log_frame, height=8, state="disabled", wrap="word")
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_box.yview)
        self.log_box.configure(yscrollcommand=scrollbar.set)
        self.log_box.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        ttk.Label(outer, textvariable=self.status_var).pack(anchor="w", pady=(8, 0))

    def _labeled_entry(self, parent, label, variable, row, show=None):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=(0, 10), pady=6)
        entry = ttk.Entry(parent, textvariable=variable, show=show)
        entry.grid(row=row, column=1, sticky="ew", pady=6)
        return entry

    def _build_receive_tab(self, parent):
        parent.columnconfigure(1, weight=1)
        ttk.Label(parent, text="Receiver settings", style="Heading.TLabel").grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 6)
        )
        self._labeled_entry(parent, "Listen address", self.host_var, 1)
        self._labeled_entry(parent, "Port", self.port_var, 2)
        self._labeled_entry(parent, "Shared secret", self.token_var, 3, show="*")
        self._labeled_entry(parent, "Save folder", self.output_var, 4)
        ttk.Button(parent, text="Browse...", command=self.choose_output).grid(row=4, column=2, padx=(8, 0))
        ttk.Label(parent, textvariable=self.ip_var).grid(row=5, column=0, columnspan=3, sticky="w", pady=(8, 12))

        buttons = ttk.Frame(parent)
        buttons.grid(row=6, column=0, columnspan=3, sticky="w")
        self.start_button = ttk.Button(buttons, text="Start Receiver", command=self.start_receiver)
        self.start_button.pack(side="left")
        self.stop_button = ttk.Button(buttons, text="Stop", command=self.stop_receiver, state="disabled")
        self.stop_button.pack(side="left", padx=(8, 0))

        ttk.Label(parent, text="Incoming file").grid(row=7, column=0, sticky="w", pady=(18, 5))
        self.receive_progress = ttk.Progressbar(parent, mode="determinate", maximum=100)
        self.receive_progress.grid(row=8, column=0, columnspan=3, sticky="ew")
        self.receive_label = ttk.Label(parent, text="Waiting for a file")
        self.receive_label.grid(row=9, column=0, columnspan=3, sticky="w", pady=(5, 0))

    def _build_send_tab(self, parent):
        parent.columnconfigure(1, weight=1)
        ttk.Label(parent, text="Send a file", style="Heading.TLabel").grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 6)
        )
        self._labeled_entry(parent, "Receiver IP", self.target_var, 1)
        self._labeled_entry(parent, "Port", self.port_var, 2)
        self._labeled_entry(parent, "Shared secret", self.token_var, 3, show="*")
        self._labeled_entry(parent, "File", self.file_var, 4)
        ttk.Button(parent, text="Browse...", command=self.choose_file).grid(row=4, column=2, padx=(8, 0))

        self.send_button = ttk.Button(parent, text="Send File", command=self.begin_send)
        self.send_button.grid(row=5, column=0, columnspan=3, sticky="w", pady=(12, 16))
        self.send_progress = ttk.Progressbar(parent, mode="determinate", maximum=100)
        self.send_progress.grid(row=6, column=0, columnspan=3, sticky="ew")
        self.send_label = ttk.Label(parent, text="No file selected")
        self.send_label.grid(row=7, column=0, columnspan=3, sticky="w", pady=(5, 0))

    def choose_output(self):
        folder = filedialog.askdirectory(initialdir=self.output_var.get() or str(Path.cwd()))
        if folder:
            self.output_var.set(folder)

    def choose_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_var.set(filename)
            self.send_label.config(text=Path(filename).name)

    def validated_port(self):
        try:
            port = int(self.port_var.get())
            if not 1 <= port <= 65535:
                raise ValueError
            return port
        except ValueError:
            messagebox.showerror("Invalid port", "Enter a port number from 1 to 65535.")
            return None

    def require_token(self):
        token = self.token_var.get()
        if not token:
            messagebox.showerror("Missing secret", "Enter the same shared secret on both computers.")
            return None
        return token

    def start_receiver(self):
        port = self.validated_port()
        token = self.require_token()
        if port is None or token is None:
            return
        self.receiver.start(self.host_var.get().strip() or "0.0.0.0", port, token, self.output_var.get())
        self.status_var.set("Starting receiver...")

    def stop_receiver(self):
        self.receiver.stop()

    def begin_send(self):
        if self.sending:
            return
        port = self.validated_port()
        token = self.require_token()
        path = Path(self.file_var.get())
        host = self.target_var.get().strip()
        if port is None or token is None:
            return
        if not host:
            messagebox.showerror("Missing address", "Enter the receiver's IP address.")
            return
        if not path.is_file():
            messagebox.showerror("Missing file", "Choose a file to send.")
            return

        self.sending = True
        self.send_button.config(state="disabled")
        self.send_progress["value"] = 0
        threading.Thread(target=self._send_worker, args=(host, port, token, path), daemon=True).start()

    def _send_worker(self, host, port, token, path):
        try:
            self.events.put(("send_status", 0, "Calculating checksum..."))
            digest = calculate_sha256(
                path, lambda percent, text: self.events.put(("send_status", percent * 0.1, text))
            )
            size = path.stat().st_size
            request = {"token": token, "filename": path.name, "size": size, "sha256": digest}

            with socket.create_connection((host, port), timeout=30) as sock:
                send_json(sock, request)
                response = recv_json(sock)
                if not response.get("ok"):
                    raise RuntimeError(response.get("error", "Receiver rejected transfer"))

                sent = 0
                with path.open("rb") as source:
                    while chunk := source.read(CHUNK_SIZE):
                        sock.sendall(chunk)
                        sent += len(chunk)
                        percent = 100 if size == 0 else sent * 100 / size
                        self.events.put(("send_status", 10 + percent * 0.9, f"Sending {path.name}"))

                result = recv_json(sock)
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
                    self._log(event[1])
                    messagebox.showerror("Receiver error", event[1])
                elif kind == "receiver_state":
                    running = event[1]
                    self.start_button.config(state="disabled" if running else "normal")
                    self.stop_button.config(state="normal" if running else "disabled")
                    self.status_var.set("Receiver is running" if running else "Ready")
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
                    self.send_label.config(text=f"Sent successfully as {event[1]}")
                    self._log(f"Sent file successfully as {event[1]}")
                    messagebox.showinfo("Transfer complete", f"The file was saved as {event[1]}.")
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
    app = FileTransferApp()
    app.mainloop()


if __name__ == "__main__":
    main()
