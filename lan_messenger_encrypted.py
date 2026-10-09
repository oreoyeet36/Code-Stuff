import base64
import os
import json
import platform
import socket
import sqlite3
import threading
import time
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError:
    Fernet = None
    InvalidToken = Exception

APP_DIR = Path.home() / ".lan_messenger"
SETTINGS_FILE = APP_DIR / "settings.json"
DB_FILE = APP_DIR / "history.db"
DISCOVERY_OFFSET = 1
MAX_MESSAGE = 1_000_000


class LANMessenger:
    LIGHT = {"bg":"#f0f0f0","panel":"#f0f0f0","input":"white","text":"#111111","muted":"#666666","button":"#e8e8e8","active":"#d5d5d5","select":"#0078d7"}
    DARK = {"bg":"#181818","panel":"#242424","input":"#343434","text":"#f2f2f2","muted":"#bbbbbb","button":"#3b3b3b","active":"#505050","select":"#0e639c"}

    def __init__(self, root):
        APP_DIR.mkdir(exist_ok=True)
        self.root = root
        self.root.title("LAN Messenger Encrypted")
        self.root.geometry("980x720")
        self.root.minsize(780, 600)
        self.running = False
        self.server_socket = None
        self.discovery_socket = None
        self.current_port = None
        self.peers = {}
        self.settings = self.load_settings()
        self.dark_mode = bool(self.settings.get("dark_mode", False))
        self.db = sqlite3.connect(DB_FILE, check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, timestamp TEXT, sender TEXT, message TEXT, direction TEXT, status TEXT)")
        self.db.commit()
        self.build_ui()
        self.restore_history()
        self.apply_theme()
        self.root.protocol("WM_DELETE_WINDOW", self.close_app)
        self.root.after(1000, self.refresh_peer_list)
        self.root.after(5000, self.expire_peers)

    def load_settings(self):
        defaults = {"device_name": platform.node() or "Unknown Device", "port": 5000, "recipients": "", "dark_mode": False, "room_key": "", "notifications": True}
        try:
            defaults.update(json.loads(SETTINGS_FILE.read_text(encoding="utf-8")))
        except (OSError, ValueError, TypeError):
            pass
        return defaults

    def save_settings(self):
        data = {"device_name": self.name_entry.get().strip(), "port": self.port_entry.get().strip(), "recipients": self.recipient_entry.get().strip(), "dark_mode": self.dark_mode, "notifications": bool(self.notify_var.get())}
        try:
            SETTINGS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except OSError as error:
            self.log_system(f"Could not save settings: {error}")

    def build_ui(self):
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)
        settings = tk.LabelFrame(self.root, text="Connection", padx=8, pady=8)
        settings.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        settings.columnconfigure(1, weight=1)
        settings.columnconfigure(5, weight=1)

        tk.Label(settings, text="Device name:").grid(row=0, column=0, sticky="w")
        self.name_entry = tk.Entry(settings)
        self.name_entry.grid(row=0, column=1, padx=5, sticky="ew")
        self.name_entry.insert(0, self.settings["device_name"])
        tk.Label(settings, text="Port:").grid(row=0, column=2, padx=(10,0))
        self.port_entry = tk.Entry(settings, width=8)
        self.port_entry.grid(row=0, column=3, padx=5)
        self.port_entry.insert(0, str(self.settings["port"]))
        tk.Label(settings, text="Encryption key:").grid(row=0, column=4, padx=(10,0))
        self.key_entry = tk.Entry(settings, show="*")
        self.key_entry.grid(row=0, column=5, padx=5, sticky="ew")
        self.key_entry.insert(0, "")

        tk.Label(settings, text="Recipients:").grid(row=1, column=0, pady=(7,0), sticky="w")
        self.recipient_entry = tk.Entry(settings)
        self.recipient_entry.grid(row=1, column=1, columnspan=5, padx=5, pady=(7,0), sticky="ew")
        self.recipient_entry.insert(0, self.settings.get("recipients", ""))
        tk.Label(settings, text="Use commas; optional ports are supported, such as 192.168.1.20:5001").grid(row=2, column=1, columnspan=5, sticky="w")

        controls = tk.Frame(settings)
        controls.grid(row=3, column=0, columnspan=6, pady=(8,0), sticky="ew")
        for i in range(6): controls.columnconfigure(i, weight=1)
        self.start_btn = tk.Button(controls, text="Start Listening", command=self.start_server)
        self.start_btn.grid(row=0, column=0, padx=3, sticky="ew")
        self.stop_btn = tk.Button(controls, text="Stop Listening", state="disabled", command=self.stop_server)
        self.stop_btn.grid(row=0, column=1, padx=3, sticky="ew")
        self.scan_btn = tk.Button(controls, text="Look for Devices", state="disabled", command=self.look_for_devices)
        self.scan_btn.grid(row=0, column=2, padx=3, sticky="ew")
        self.theme_btn = tk.Button(controls, text="Dark Mode", command=self.toggle_theme)
        self.theme_btn.grid(row=0, column=3, padx=3, sticky="ew")
        tk.Button(controls, text="Clear Chat", command=self.clear_chat).grid(row=0, column=4, padx=3, sticky="ew")
        tk.Button(controls, text="Export Chat", command=self.export_chat).grid(row=0, column=5, padx=3, sticky="ew")

        main = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, sashwidth=6)
        main.grid(row=1, column=0, padx=10, pady=(0,8), sticky="nsew")
        peers_frame = tk.LabelFrame(main, text="Available Devices", padx=6, pady=6)
        chat_frame = tk.LabelFrame(main, text="Conversation", padx=6, pady=6)
        main.add(peers_frame, minsize=210)
        main.add(chat_frame, minsize=500)
        peers_frame.rowconfigure(0, weight=1); peers_frame.columnconfigure(0, weight=1)
        chat_frame.rowconfigure(0, weight=1); chat_frame.columnconfigure(0, weight=1)

        self.peer_list = tk.Listbox(peers_frame, selectmode=tk.EXTENDED)
        self.peer_list.grid(row=0, column=0, sticky="nsew")
        tk.Button(peers_frame, text="Add Selected to Recipients", command=self.add_selected_peers).grid(row=1, column=0, pady=(6,0), sticky="ew")
        tk.Label(peers_frame, text="Click Look for Devices to scan the local network.", wraplength=190).grid(row=2, column=0, pady=(5,0))

        self.message_box = scrolledtext.ScrolledText(chat_frame, state="disabled", wrap="word", font=("Arial",11))
        self.message_box.grid(row=0, column=0, sticky="nsew")

        compose = tk.LabelFrame(self.root, text="Message", padx=8, pady=8)
        compose.grid(row=2, column=0, padx=10, pady=(0,8), sticky="ew")
        compose.columnconfigure(0, weight=1)
        self.message_entry = tk.Text(compose, height=4, wrap="word", font=("Arial",11))
        self.message_entry.grid(row=0, column=0, padx=(0,8), sticky="ew")
        self.message_entry.bind("<Control-Return>", self.send_shortcut)
        tk.Button(compose, text="Send Message", width=16, command=self.send_message).grid(row=0, column=1, sticky="ns")
        self.notify_var = tk.BooleanVar(value=self.settings.get("notifications", True))
        tk.Checkbutton(compose, text="Sound notification", variable=self.notify_var).grid(row=1, column=0, sticky="w")
        self.status = tk.Label(self.root, text="Not listening", anchor="w")
        self.status.grid(row=3, column=0, padx=10, pady=(0,8), sticky="ew")

    def get_port(self):
        try:
            port = int(self.port_entry.get().strip())
            if not 1 <= port <= 65534: raise ValueError
            return port
        except ValueError:
            messagebox.showerror("Invalid port", "Use a port from 1 through 65534. The next port is used for discovery.")
            return None

    def local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8",80)); ip=s.getsockname()[0]; s.close(); return ip
        except OSError:
            return "127.0.0.1"

    def start_server(self):
        if self.running: return
        if Fernet is None:
            messagebox.showerror("Missing dependency", "Install encryption support with:\n\npython -m pip install cryptography")
            return
        if not self.key_entry.get():
            messagebox.showwarning("Room key required", "Enter the same shared room key on every device.")
            return
        port = self.get_port()
        if port is None: return
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("0.0.0.0", port)); server.listen(); server.settimeout(1)
            discovery = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            discovery.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            discovery.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            discovery.bind(("0.0.0.0", port + DISCOVERY_OFFSET)); discovery.settimeout(1)
            self.server_socket, self.discovery_socket = server, discovery
            self.current_port, self.running = port, True
            self.port_entry.config(state="disabled"); self.start_btn.config(state="disabled"); self.stop_btn.config(state="normal"); self.scan_btn.config(state="normal")
            self.update_status(); self.log_system(f"Listening on {self.local_ip()}:{port}")
            self.save_settings()
            threading.Thread(target=self.accept_loop, daemon=True).start()
            threading.Thread(target=self.discovery_loop, daemon=True).start()
        except OSError as error:
            for s in (locals().get("server"), locals().get("discovery")):
                try: s.close()
                except (OSError, AttributeError): pass
            messagebox.showerror("Could not start", str(error))

    def stop_server(self):
        if not self.running: return
        old = self.current_port; self.running=False; self.current_port=None
        for attr in ("server_socket", "discovery_socket"):
            s=getattr(self,attr); setattr(self,attr,None)
            try: s.close()
            except (OSError, AttributeError): pass
        self.port_entry.config(state="normal"); self.start_btn.config(state="normal"); self.stop_btn.config(state="disabled"); self.scan_btn.config(state="disabled")
        self.update_status(); self.log_system(f"Stopped listening on port {old}")

    def accept_loop(self):
        server=self.server_socket
        while self.running and server is self.server_socket:
            try:
                client,address=server.accept(); threading.Thread(target=self.handle_client,args=(client,address),daemon=True).start()
            except socket.timeout: continue
            except OSError: break

    def derive_cipher(self, salt):
        key_text = self.key_entry.get()
        if not key_text:
            raise ValueError("shared room key is empty")
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        key = base64.urlsafe_b64encode(kdf.derive(key_text.encode("utf-8")))
        return Fernet(key)

    def encrypt_payload(self, payload):
        salt = os.urandom(16)
        plaintext = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        token = self.derive_cipher(salt).encrypt(plaintext).decode("ascii")
        return json.dumps({
            "protocol": "lan-messenger-fernet-v1",
            "salt": base64.b64encode(salt).decode("ascii"),
            "token": token
        }).encode("utf-8") + b"\n"

    def decrypt_payload(self, wrapper):
        if wrapper.get("protocol") != "lan-messenger-fernet-v1":
            raise ValueError("unsupported encrypted-message protocol")
        salt = base64.b64decode(wrapper["salt"], validate=True)
        token = wrapper["token"].encode("ascii")
        plaintext = self.derive_cipher(salt).decrypt(token)
        return json.loads(plaintext.decode("utf-8"))

    def handle_client(self, client, address):
        try:
            client.settimeout(5); received=bytearray()
            while b"\n" not in received:
                chunk=client.recv(4096)
                if not chunk: break
                received.extend(chunk)
                if len(received)>MAX_MESSAGE: raise ValueError("message too large")
            wrapper=json.loads(received.split(b"\n",1)[0].decode("utf-8"))
            payload=self.decrypt_payload(wrapper)
            name=str(payload.get("device_name","Unknown Device")); msg=str(payload.get("message","")); ts=str(payload.get("timestamp",""))
            if msg:
                self.display(f"[{ts}] {name}: {msg}"); self.store(ts,name,msg,"in","received")
                if self.notify_var.get(): self.root.after(0,self.root.bell)
            client.sendall(b'{"status":"delivered"}\n')
        except InvalidToken:
            self.log_system(f"Rejected encrypted message from {address[0]}: wrong room key or altered data")
            try: client.sendall(b'{"status":"rejected"}\n')
            except OSError: pass
        except Exception as error:
            self.log_system(f"Rejected message from {address[0]}: {error}")
            try: client.sendall(b'{"status":"rejected"}\n')
            except OSError: pass
        finally: client.close()

    def parse_recipients(self):
        result=[]
        for item in self.recipient_entry.get().split(","):
            item=item.strip()
            if not item: continue
            host,sep,p=item.rpartition(":")
            if sep and p.isdigit(): result.append((host,int(p)))
            else: result.append((item,self.current_port or self.get_port()))
        return result

    def send_message(self):
        if not self.running:
            messagebox.showwarning("Not listening","Start Listening first."); return
        msg=self.message_entry.get("1.0",tk.END).strip(); recipients=self.parse_recipients()
        if not msg: return
        if not recipients: messagebox.showwarning("No recipients","Enter or select at least one device."); return
        name=self.name_entry.get().strip() or "Unknown Device"; ts=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        payload={"device_name":name,"message":msg,"timestamp":ts}
        try:
            wire=self.encrypt_payload(payload)
        except Exception as error:
            messagebox.showerror("Encryption failed", str(error)); return
        self.display(f"[{ts}] {name} (you): {msg}"); self.store(ts,name,msg,"out","sending")
        self.message_entry.delete("1.0",tk.END); self.save_settings()
        for host,port in recipients:
            threading.Thread(target=self.send_one,args=(host,port,wire,ts,msg),daemon=True).start()

    def send_one(self, host, port, wire, ts, msg):
        try:
            with socket.create_connection((host,port),timeout=3) as s:
                s.sendall(wire); s.settimeout(3); reply=json.loads(s.recv(1024).split(b"\n",1)[0].decode())
            status=reply.get("status","unknown"); self.log_system(f"{host}:{port} - {status}")
        except OSError as error:
            status="failed"; self.log_system(f"{host}:{port} - failed: {error}")
        self.db.execute("UPDATE messages SET status=? WHERE timestamp=? AND message=? AND direction='out'",(status,ts,msg)); self.db.commit()

    def discovery_loop(self):
        sock=self.discovery_socket
        while self.running and sock is self.discovery_socket:
            try:
                data,address=sock.recvfrom(4096); info=json.loads(data.decode("utf-8"))
                message_type=info.get("type")
                if message_type=="lan_messenger_discover":
                    response=json.dumps({
                        "type":"lan_messenger_hello",
                        "name":self.name_entry.get().strip() or "Unknown Device",
                        "port":self.current_port
                    }).encode("utf-8")
                    sock.sendto(response,address)
                elif message_type=="lan_messenger_hello":
                    peer=(address[0],int(info["port"]))
                    if peer!=(self.local_ip(),self.current_port):
                        self.peers[peer]={"name":str(info.get("name","Unknown")),"last":time.time()}
            except socket.timeout: continue
            except (OSError,ValueError,KeyError,TypeError):
                if not self.running: break

    def look_for_devices(self):
        if not self.running or self.discovery_socket is None:
            messagebox.showwarning("Not listening", "Start Listening before looking for devices.")
            return
        self.peers.clear()
        self.scan_btn.config(state="disabled", text="Looking...")
        self.log_system("Looking for devices on the local network...")
        threading.Thread(target=self._send_discovery_queries, daemon=True).start()

    def _send_discovery_queries(self):
        packet=json.dumps({"type":"lan_messenger_discover"}).encode("utf-8")
        for _ in range(3):
            if not self.running: break
            try:
                self.discovery_socket.sendto(packet,("255.255.255.255",self.current_port+DISCOVERY_OFFSET))
            except OSError as error:
                self.log_system(f"Device search failed: {error}"); break
            time.sleep(0.6)
        self.root.after(0,lambda:self.scan_btn.config(state="normal" if self.running else "disabled",text="Look for Devices"))
        self.root.after(0,lambda:self.log_system(f"Device search finished: {len(self.peers)} device(s) found."))

    def refresh_peer_list(self):
        selected={self.peer_list.get(i) for i in self.peer_list.curselection()}
        self.peer_list.delete(0,tk.END)
        for (ip,port),info in sorted(self.peers.items(),key=lambda x:x[1]["name"].lower()):
            label=f'{info["name"]} | {ip}:{port}'; self.peer_list.insert(tk.END,label)
            if label in selected: self.peer_list.selection_set(tk.END)
        self.root.after(1000,self.refresh_peer_list)

    def expire_peers(self):
        cutoff=time.time()-12
        self.peers={k:v for k,v in self.peers.items() if v["last"]>=cutoff}
        self.root.after(5000,self.expire_peers)

    def add_selected_peers(self):
        existing=[x.strip() for x in self.recipient_entry.get().split(",") if x.strip()]
        for i in self.peer_list.curselection():
            address=self.peer_list.get(i).split(" | ",1)[1]
            if address not in existing: existing.append(address)
        self.recipient_entry.delete(0,tk.END); self.recipient_entry.insert(0,", ".join(existing)); self.save_settings()

    def store(self,ts,sender,msg,direction,status):
        self.db.execute("INSERT INTO messages(timestamp,sender,message,direction,status) VALUES(?,?,?,?,?)",(ts,sender,msg,direction,status)); self.db.commit()

    def restore_history(self):
        rows=self.db.execute("SELECT timestamp,sender,message,direction FROM messages ORDER BY id DESC LIMIT 200").fetchall()
        for ts,sender,msg,direction in reversed(rows): self.display(f"[{ts}] {sender}{' (you)' if direction=='out' else ''}: {msg}")

    def clear_chat(self):
        self.db.execute("DELETE FROM messages"); self.db.commit()
        self.message_box.config(state="normal"); self.message_box.delete("1.0",tk.END); self.message_box.config(state="disabled")

    def export_chat(self):
        default=f"lan_chat_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        path=filedialog.asksaveasfilename(defaultextension=".txt",initialfile=default,filetypes=[("Text files","*.txt")])
        if path:
            Path(path).write_text(self.message_box.get("1.0",tk.END).rstrip()+"\n",encoding="utf-8")
            self.log_system(f"Chat exported to {path}")

    def display(self,text): self.root.after(0,self._display,text)
    def _display(self,text):
        self.message_box.config(state="normal"); self.message_box.insert(tk.END,text+"\n"); self.message_box.see(tk.END); self.message_box.config(state="disabled")
    def log_system(self,text): self.display(f"[System] {text}")
    def send_shortcut(self,event): self.send_message(); return "break"

    def update_status(self):
        self.status.config(text=f"Listening on port {self.current_port}" if self.running else "Not listening",fg=("#62d26f" if self.dark_mode else "dark green") if self.running else ("#ff7070" if self.dark_mode else "dark red"))

    def toggle_theme(self): self.dark_mode=not self.dark_mode; self.apply_theme(); self.save_settings()
    def apply_theme(self):
        c=self.DARK if self.dark_mode else self.LIGHT; self.theme_btn.config(text="Light Mode" if self.dark_mode else "Dark Mode"); self._theme(self.root,c); self.update_status()
    def _theme(self,w,c):
        kind=w.winfo_class()
        try:
            if kind in {"Tk","Frame","Labelframe","Panedwindow"}: w.config(bg=c["bg"] if kind=="Tk" else c["panel"]); w.config(fg=c["text"]) if kind=="Labelframe" else None
            elif kind in {"Label","Checkbutton"}: w.config(bg=c["panel"],fg=c["text"],activebackground=c["panel"],activeforeground=c["text"])
            elif kind in {"Entry","Text","Listbox"}: w.config(bg=c["input"],fg=c["text"],insertbackground=c["text"],selectbackground=c["select"])
            elif kind=="Button": w.config(bg=c["button"],fg=c["text"],activebackground=c["active"],activeforeground=c["text"])
        except tk.TclError: pass
        for child in w.winfo_children(): self._theme(child,c)

    def close_app(self):
        self.save_settings()
        if self.running: self.stop_server()
        self.db.close(); self.root.destroy()


def main():
    root=tk.Tk(); LANMessenger(root); root.mainloop()

if __name__=="__main__": main()
