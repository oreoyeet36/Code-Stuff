#!/usr/bin/env python3
"""Encrypted Multi-File Transfer v3.2
Dependency: python -m pip install cryptography
"""
import hashlib, hmac, json, os, queue, shutil, socket, struct, subprocess, sys, tempfile, threading, time, zipfile
from datetime import datetime
from pathlib import Path, PurePosixPath
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError as exc:
    raise SystemExit("Install cryptography first: python -m pip install cryptography") from exc

APP_VERSION="3.3.1"; CHUNK=64*1024; MAGIC=b"FTENC3"; CONTEXT=b"encrypted-file-transfer-v3.2"; MAX_FRAME=CHUNK+65536
CONFIG_PATH=Path.home()/".encrypted_file_transfer_v3_3_1.json"
DEFAULTS={"port":5001,"max_file_mb":4096,"max_extract_mb":8192,"max_zip_entries":5000,"timeout":90,"warning_mb":1024,"keep_zip":False,"require_approval":True,"save_folder":str(Path.home()/"Downloads"/"EncryptedTransfers"),"dark_mode":False}

def exact(s,n,cancel=None):
    out=bytearray()
    while len(out)<n:
        if cancel and cancel.is_set(): raise InterruptedError("Transfer canceled")
        try:b=s.recv(n-len(out))
        except socket.timeout:continue
        if not b:raise ConnectionError("Connection closed early")
        out.extend(b)
    return bytes(out)
def send_frame(s,b):
    if len(b)>MAX_FRAME:raise ValueError("Frame too large")
    s.sendall(struct.pack("!I",len(b))+b)
def recv_frame(s,cancel=None):
    n=struct.unpack("!I",exact(s,4,cancel))[0]
    if n>MAX_FRAME:raise ValueError("Frame too large")
    return exact(s,n,cancel)
def derive(password,salt):return Scrypt(salt=salt,length=32,n=2**15,r=8,p=1).derive(password.encode())
def proof(k,role,c,sv):return hmac.new(k,CONTEXT+role+c+sv,hashlib.sha256).digest()
class Channel:
    def __init__(self,s,k,cancel):self.s=s;self.a=AESGCM(k);self.tx=0;self.rx=0;self.cancel=cancel
    def send(self,b,p):
        if self.cancel.is_set():raise InterruptedError("Transfer canceled")
        i=self.tx;self.tx+=1;n=os.urandom(12);aad=CONTEXT+p+struct.pack("!Q",i);send_frame(self.s,n+self.a.encrypt(n,b,aad))
    def recv(self,p):
        i=self.rx;self.rx+=1;z=recv_frame(self.s,self.cancel);aad=CONTEXT+p+struct.pack("!Q",i)
        try:return self.a.decrypt(z[:12],z[12:],aad)
        except InvalidTag as e:raise PermissionError("Encrypted data authentication failed") from e
    def sendj(self,o,p):self.send(json.dumps(o,separators=(",",":")).encode(),p)
    def recvj(self,p):return json.loads(self.recv(p).decode())
def client_handshake(s,password,cancel):
    c=os.urandom(32);s.sendall(MAGIC+c);z=exact(s,80,cancel);salt,sv,sp=z[:16],z[16:48],z[48:];k=derive(password,salt)
    if not hmac.compare_digest(sp,proof(k,b"server",c,sv)):raise PermissionError("Wrong shared passphrase")
    s.sendall(proof(k,b"client",c,sv));ch=Channel(s,k,cancel)
    if not ch.recvj(b"auth").get("ok"):raise PermissionError("Authentication failed")
    return ch
def server_handshake(s,password,cancel):
    z=exact(s,len(MAGIC)+32,cancel)
    if z[:len(MAGIC)]!=MAGIC:raise PermissionError("Unsupported client version")
    c=z[len(MAGIC):];salt=os.urandom(16);sv=os.urandom(32);k=derive(password,salt);s.sendall(salt+sv+proof(k,b"server",c,sv))
    if not hmac.compare_digest(exact(s,32,cancel),proof(k,b"client",c,sv)):raise PermissionError("Wrong shared passphrase")
    ch=Channel(s,k,cancel);ch.sendj({"ok":True},b"auth");return ch
def unique(folder,name):
    name=Path(name).name
    if not name or name in (".",".."):raise ValueError("Invalid filename")
    p=folder.resolve()/name;i=1
    while p.exists() or p.with_name(p.name+".part").exists():p=folder.resolve()/f"{Path(name).stem}_{i}{Path(name).suffix}";i+=1
    return p
def safe_extract(zp,folder,max_entries,max_bytes,cancel):
    out=unique(folder,zp.stem);out.mkdir();total=0
    try:
        with zipfile.ZipFile(zp) as z:
            infos=z.infolist()
            if len(infos)>max_entries:raise ValueError("ZIP contains too many entries")
            for info in infos:
                if cancel.is_set():raise InterruptedError("Transfer canceled")
                parts=PurePosixPath(info.filename).parts
                if not parts or info.filename.startswith(("/","\\")) or ".." in parts:raise ValueError("Unsafe path in ZIP")
                if (info.external_attr>>16)&0o170000==0o120000:raise ValueError("ZIP symbolic links are not allowed")
                total+=info.file_size
                if total>max_bytes:raise ValueError("Expanded ZIP exceeds configured limit")
                target=out.joinpath(*parts)
                if info.is_dir():target.mkdir(parents=True,exist_ok=True);continue
                target.parent.mkdir(parents=True,exist_ok=True)
                with z.open(info) as src,target.open("xb") as dst:
                    while b:=src.read(CHUNK):
                        if cancel.is_set():raise InterruptedError("Transfer canceled")
                        dst.write(b)
        return out
    except Exception:shutil.rmtree(out,ignore_errors=True);raise
def make_zip(paths,name,cancel,progress):
    fd,tmp=tempfile.mkstemp(prefix="eft_",suffix=".zip");os.close(fd);zp=Path(tmp);total=max(1,sum(p.stat().st_size for p in paths));done=0;used=set()
    try:
        with zipfile.ZipFile(zp,"w",zipfile.ZIP_DEFLATED,allowZip64=True) as z:
            common=None
            try:common=Path(os.path.commonpath([str(p.parent) for p in paths]))
            except ValueError:pass
            for p in paths:
                if cancel.is_set():raise InterruptedError("Transfer canceled")
                try:arc=p.relative_to(common).as_posix() if common else p.name
                except ValueError:arc=p.name
                base=arc;i=1
                while arc in used:arc=f"{Path(base).stem}_{i}{Path(base).suffix}";i+=1
                used.add(arc);z.write(p,arc);done+=p.stat().st_size;progress(done*100/total)
        return zp
    except Exception:zp.unlink(missing_ok=True);raise
def open_folder(path):
    path=str(Path(path).resolve())
    if sys.platform.startswith("win"):os.startfile(path)
    elif sys.platform=="darwin":subprocess.Popen(["open",path])
    else:subprocess.Popen(["xdg-open",path])
def local_ip():
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:s.connect(("8.8.8.8",80));return s.getsockname()[0]
    except OSError:return "127.0.0.1"
def fmt_size(n):
    for unit in ("B","KB","MB","GB","TB"):
        if n<1024:return f"{n:.1f} {unit}"
        n/=1024
    return f"{n:.1f} PB"

class Server:
    def __init__(self,app):self.app=app;self.stop_event=threading.Event();self.sock=None;self.thread=None;self.active=[];self.lock=threading.Lock()
    def start(self,host,port,password,folder,settings):
        if self.thread and self.thread.is_alive():return
        self.stop_event.clear();self.thread=threading.Thread(target=self.serve,args=(host,port,password,Path(folder),settings.copy()),daemon=True);self.thread.start()
    def stop(self):
        self.stop_event.set()
        if self.sock:
            try:self.sock.close()
            except OSError:pass
        self.cancel_all();self.app.q.put(("running",False))
    def cancel_all(self):
        with self.lock:
            for e,s in self.active:e.set();
            for e,s in self.active:
                try:s.shutdown(socket.SHUT_RDWR);s.close()
                except OSError:pass
    def serve(self,host,port,password,folder,settings):
        try:
            folder.mkdir(parents=True,exist_ok=True)
            with socket.socket() as srv:
                self.sock=srv;srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);srv.settimeout(.5);srv.bind((host,port));srv.listen(5);self.app.q.put(("running",True));self.app.q.put(("log",f"Receiver listening on {host}:{port}"))
                while not self.stop_event.is_set():
                    try:s,a=srv.accept()
                    except socket.timeout:continue
                    except OSError:break
                    cancel=threading.Event()
                    with self.lock:self.active.append((cancel,s))
                    threading.Thread(target=self.handle,args=(s,a,password,folder,settings,cancel),daemon=True).start()
        except Exception as e:self.app.q.put(("error",str(e)))
        finally:self.sock=None;self.app.q.put(("running",False))
    def handle(self,s,addr,password,folder,settings,cancel):
        tmp=None;name="unknown";size=0
        try:
            with s:
                s.settimeout(1);ch=server_handshake(s,password,cancel);m=ch.recvj(b"meta");name=Path(str(m["name"])).name;size=int(m["size"]);sha=str(m["sha256"]);count=int(m.get("count",1))
                if size<0 or size>settings["max_file_mb"]*1024**2:ch.sendj({"ok":False,"error":"File exceeds receiver limit"},b"approval");return
                approved=True
                if settings["require_approval"]:approved=self.app.request_approval(addr[0],name,size,count,cancel)
                ch.sendj({"ok":approved,"error":"Receiver rejected transfer" if not approved else ""},b"approval")
                if not approved:self.app.add_history("Received",name,size,addr[0],"Rejected","");return
                dest=unique(folder,name);tmp=dest.with_name(dest.name+".part");h=hashlib.sha256();left=size;got=0
                with tmp.open("wb") as f:
                    while left:
                        b=ch.recv(b"chunk")
                        if not b or len(b)>min(CHUNK,left):raise ValueError("Invalid file chunk")
                        f.write(b);h.update(b);got+=len(b);left-=len(b);self.app.q.put(("receive",100*got/max(1,size),name))
                if not hmac.compare_digest(h.hexdigest(),sha):raise ValueError("Checksum failed")
                tmp.replace(dest);tmp=None;result=dest.name;action="Kept file"
                if dest.suffix.lower()==".zip" and not settings["keep_zip"]:
                    out=safe_extract(dest,folder,settings["max_zip_entries"],settings["max_extract_mb"]*1024**2,cancel);dest.unlink();result=out.name+"/";action="Extracted ZIP"
                ch.sendj({"ok":True,"saved_as":result},b"done");self.app.q.put(("log",f"Received {result}"));self.app.add_history("Received",name,size,addr[0],"Success",action)
        except InterruptedError:self.app.q.put(("log",f"Canceled incoming transfer: {name}"));self.app.add_history("Received",name,size,addr[0],"Canceled","")
        except Exception as e:self.app.q.put(("log",f"Incoming transfer failed: {e}"));self.app.add_history("Received",name,size,addr[0],"Failed",str(e))
        finally:
            if tmp:tmp.unlink(missing_ok=True)
            with self.lock:
                self.active=[x for x in self.active if x[1] is not s]

class App(tk.Tk):
    def __init__(self):
        super().__init__();self.title(f"Encrypted Multi-File Transfer v{APP_VERSION}");self.geometry("900x790");self.minsize(800,700);self.q=queue.Queue();self.server=Server(self);self.files=[];self.send_cancel=threading.Event();self.send_socket=None;self.history=[];self.config_data=self.load_config();self.approvals={};self.approval_id=0
        self.host=tk.StringVar(value="0.0.0.0");self.port=tk.StringVar(value=str(self.config_data["port"]));self.password=tk.StringVar();self.folder=tk.StringVar(value=self.config_data["save_folder"]);self.target=tk.StringVar(value=local_ip());self.keep_zip=tk.BooleanVar(value=self.config_data["keep_zip"]);self.require_approval=tk.BooleanVar(value=self.config_data["require_approval"]);self.bundle=tk.StringVar(value="");self.status=tk.StringVar(value="Ready. AES-256-GCM encryption enabled.");self.show=tk.BooleanVar();self.secret_entries=[];self.sending=False
        self.max_file=tk.StringVar(value=str(self.config_data["max_file_mb"]));self.max_extract=tk.StringVar(value=str(self.config_data["max_extract_mb"]));self.max_entries=tk.StringVar(value=str(self.config_data["max_zip_entries"]));self.timeout=tk.StringVar(value=str(self.config_data["timeout"]));self.warning=tk.StringVar(value=str(self.config_data["warning_mb"]));self.limit_warning=tk.StringVar();self.dark_mode=tk.BooleanVar(value=bool(self.config_data.get("dark_mode",False)))
        self.build();self.apply_theme();self.max_file.trace_add("write",lambda *_:self.update_warning());self.warning.trace_add("write",lambda *_:self.update_warning());self.after(100,self.events);self.protocol("WM_DELETE_WINDOW",self.close)
    def load_config(self):
        d=DEFAULTS.copy()
        try:d.update(json.loads(CONFIG_PATH.read_text()))
        except Exception:pass
        return d
    def save_config(self):
        d=self.get_settings(show_errors=True)
        if not d:return False
        d.update({"port":int(self.port.get()),"save_folder":self.folder.get(),"keep_zip":self.keep_zip.get(),"require_approval":self.require_approval.get(),"dark_mode":self.dark_mode.get()});CONFIG_PATH.write_text(json.dumps(d,indent=2));self.config_data=d;self.update_warning();self.status.set("Settings saved");return True
    def entry(self,p,label,var,row,secret=False):
        ttk.Label(p,text=label).grid(row=row,column=0,sticky="w",padx=(0,10),pady=5);e=ttk.Entry(p,textvariable=var,show="*" if secret else "");e.grid(row=row,column=1,sticky="ew",pady=5)
        if secret:self.secret_entries.append(e)
    def build(self):
        root=ttk.Frame(self,padding=14);root.pack(fill="both",expand=True);ttk.Label(root,text=f"Encrypted Multi-File Transfer v{APP_VERSION}",font=("TkDefaultFont",18,"bold")).pack(anchor="w")
        nb=ttk.Notebook(root);nb.pack(fill="both",expand=True,pady=8);r=ttk.Frame(nb,padding=14);s=ttk.Frame(nb,padding=14);h=ttk.Frame(nb,padding=10);settings=ttk.Frame(nb,padding=14);nb.add(r,text="Receive");nb.add(s,text="Send");nb.add(h,text="History");nb.add(settings,text="Settings");r.columnconfigure(1,weight=1);s.columnconfigure(1,weight=1)
        self.entry(r,"Listen address",self.host,0);self.entry(r,"Port",self.port,1);self.entry(r,"Shared passphrase",self.password,2,True);self.entry(r,"Save folder",self.folder,3);ttk.Button(r,text="Browse...",command=self.pick_folder).grid(row=3,column=2,padx=6)
        ttk.Checkbutton(r,text="KEEP RECEIVED ZIP FILES (do not extract)",variable=self.keep_zip).grid(row=4,column=0,columnspan=3,sticky="w",pady=5);ttk.Checkbutton(r,text="Require approval for every incoming transfer",variable=self.require_approval).grid(row=5,column=0,columnspan=3,sticky="w");ttk.Label(r,text=f"Likely local IP: {local_ip()}").grid(row=6,column=0,columnspan=3,sticky="w",pady=8)
        self.start_btn=ttk.Button(r,text="Start Receiver",command=self.start_server);self.start_btn.grid(row=7,column=0,sticky="w");self.stop_btn=ttk.Button(r,text="Stop",command=self.server.stop,state="disabled");self.stop_btn.grid(row=7,column=1,sticky="w");self.cancel_receive=ttk.Button(r,text="Cancel Incoming Transfer",command=self.server.cancel_all);self.cancel_receive.grid(row=7,column=2,sticky="e")
        self.rprog=ttk.Progressbar(r,maximum=100);self.rprog.grid(row=8,column=0,columnspan=3,sticky="ew",pady=(18,2));self.rlabel=ttk.Label(r,text="Waiting for files");self.rlabel.grid(row=9,column=0,columnspan=3,sticky="w");ttk.Button(r,text="Open Received Folder",command=lambda:self.open_folder_safe(self.folder.get())).grid(row=10,column=0,sticky="w",pady=12)
        self.entry(s,"Receiver IP",self.target,0);self.entry(s,"Port",self.port,1);self.entry(s,"Shared passphrase",self.password,2,True);self.entry(s,"Bundle name (optional)",self.bundle,3);ttk.Label(s,text="Used when two or more files are selected. .zip is added automatically.").grid(row=4,column=1,sticky="w")
        bar=ttk.Frame(s);bar.grid(row=5,column=0,columnspan=3,sticky="w",pady=8);ttk.Button(bar,text="Add Multiple Files...",command=self.add_files).pack(side="left");ttk.Button(bar,text="Add Folder...",command=self.add_folder).pack(side="left",padx=5);ttk.Button(bar,text="Remove Selected",command=self.remove).pack(side="left");ttk.Button(bar,text="Clear",command=self.clear).pack(side="left",padx=5)
        self.file_list=tk.Listbox(s,height=9,selectmode="extended");self.file_list.grid(row=6,column=0,columnspan=3,sticky="nsew");s.rowconfigure(6,weight=1);self.send_btn=ttk.Button(s,text="Review and Send",command=self.review_send);self.send_btn.grid(row=7,column=0,sticky="w",pady=10);self.cancel_send=ttk.Button(s,text="Cancel Transfer",command=self.cancel_outgoing,state="disabled");self.cancel_send.grid(row=7,column=1,sticky="w");self.sprog=ttk.Progressbar(s,maximum=100);self.sprog.grid(row=8,column=0,columnspan=3,sticky="ew");self.slabel=ttk.Label(s,text="No files selected");self.slabel.grid(row=9,column=0,columnspan=3,sticky="w")
        cols=("time","direction","name","size","peer","status","details");self.tree=ttk.Treeview(h,columns=cols,show="headings",height=14)
        for c,w in zip(cols,(135,75,180,80,100,80,180)):self.tree.heading(c,text=c.title());self.tree.column(c,width=w,anchor="w")
        self.tree.pack(fill="both",expand=True);hb=ttk.Frame(h);hb.pack(fill="x",pady=8);ttk.Button(hb,text="Clear History",command=self.clear_history).pack(side="left");ttk.Button(hb,text="Open Received Folder",command=lambda:self.open_folder_safe(self.folder.get())).pack(side="left",padx=6)
        settings.columnconfigure(1,weight=1);self.entry(settings,"Maximum incoming file/bundle (MB)",self.max_file,0);self.entry(settings,"Maximum extracted ZIP size (MB)",self.max_extract,1);self.entry(settings,"Maximum ZIP entries",self.max_entries,2);self.entry(settings,"Connection timeout (seconds)",self.timeout,3);self.entry(settings,"Large-transfer warning threshold (MB)",self.warning,4);ttk.Label(settings,textvariable=self.limit_warning,foreground="#a05a00",wraplength=650).grid(row=5,column=0,columnspan=2,sticky="w",pady=8);ttk.Checkbutton(settings,text="Dark mode",variable=self.dark_mode,command=self.toggle_dark_mode).grid(row=6,column=0,columnspan=2,sticky="w",pady=8);ttk.Button(settings,text="Save Settings",command=self.save_config).grid(row=7,column=0,sticky="w");ttk.Label(settings,text="Changes to receiver limits apply the next time the receiver is started. Theme changes apply immediately.",wraplength=650).grid(row=8,column=0,columnspan=2,sticky="w",pady=8)
        quick=ttk.Frame(root);quick.pack(fill="x");ttk.Checkbutton(quick,text="Show passphrase",variable=self.show,command=self.toggle).pack(side="left");ttk.Checkbutton(quick,text="Dark mode",variable=self.dark_mode,command=self.toggle_dark_mode).pack(side="left",padx=14);box=ttk.LabelFrame(root,text="Activity",padding=5);box.pack(fill="x",pady=6);self.log=tk.Text(box,height=6,state="disabled");self.log.pack(fill="x");ttk.Label(root,textvariable=self.status).pack(anchor="w");self.update_warning()
    def toggle_dark_mode(self):
        self.apply_theme()
        self.config_data["dark_mode"]=self.dark_mode.get()
        try:
            CONFIG_PATH.write_text(json.dumps({**self.config_data,"dark_mode":self.dark_mode.get()},indent=2))
        except Exception:
            pass
    def apply_theme(self):
        dark=self.dark_mode.get()
        colors={
            "bg":"#1e1e1e" if dark else "#f0f0f0",
            "panel":"#252526" if dark else "#ffffff",
            "field":"#333333" if dark else "#ffffff",
            "fg":"#f2f2f2" if dark else "#111111",
            "muted":"#cccccc" if dark else "#333333",
            "select":"#0e639c" if dark else "#0078d7",
            "button":"#3a3a3a" if dark else "#e5e5e5",
            "trough":"#444444" if dark else "#d9d9d9",
        }
        self.configure(bg=colors["bg"])
        style=ttk.Style(self)
        try: style.theme_use("clam")
        except tk.TclError: pass
        style.configure(".",background=colors["bg"],foreground=colors["fg"],fieldbackground=colors["field"],troughcolor=colors["trough"])
        style.configure("TFrame",background=colors["bg"])
        style.configure("TLabel",background=colors["bg"],foreground=colors["fg"])
        style.configure("TLabelframe",background=colors["bg"],foreground=colors["fg"])
        style.configure("TLabelframe.Label",background=colors["bg"],foreground=colors["fg"])
        style.configure("TCheckbutton",background=colors["bg"],foreground=colors["fg"])
        style.map("TCheckbutton",background=[("active",colors["bg"])],foreground=[("disabled",colors["muted"]),("active",colors["fg"])])
        style.configure("TButton",background=colors["button"],foreground=colors["fg"],bordercolor=colors["trough"])
        style.map("TButton",background=[("active",colors["select"]), ("disabled",colors["bg"])],foreground=[("active","#ffffff"),("disabled",colors["muted"])])
        style.configure("TEntry",fieldbackground=colors["field"],foreground=colors["fg"],insertcolor=colors["fg"])
        style.configure("TNotebook",background=colors["bg"],bordercolor=colors["trough"])
        style.configure("TNotebook.Tab",background=colors["button"],foreground=colors["fg"],padding=(10,5))
        style.map("TNotebook.Tab",background=[("selected",colors["select"]), ("active",colors["field"])],foreground=[("selected","#ffffff")])
        style.configure("Treeview",background=colors["field"],fieldbackground=colors["field"],foreground=colors["fg"],rowheight=24)
        style.configure("Treeview.Heading",background=colors["button"],foreground=colors["fg"])
        style.map("Treeview",background=[("selected",colors["select"])],foreground=[("selected","#ffffff")])
        style.configure("Horizontal.TProgressbar",background=colors["select"],troughcolor=colors["trough"])
        file_list=getattr(self,"file_list",None)
        if file_list:
            file_list.configure(
                bg=colors["field"],fg=colors["fg"],
                selectbackground=colors["select"],selectforeground="#ffffff",
                highlightbackground=colors["trough"],highlightcolor=colors["select"]
            )
        activity_log=getattr(self,"log",None)
        if activity_log:
            activity_log.configure(
                bg=colors["field"],fg=colors["fg"],
                insertbackground=colors["fg"],
                selectbackground=colors["select"],selectforeground="#ffffff",
                highlightbackground=colors["trough"],highlightcolor=colors["select"]
            )
        self.status.set(("Dark" if dark else "Light")+" mode enabled")
    def get_settings(self,show_errors=False):
        try:
            d={"max_file_mb":int(self.max_file.get()),"max_extract_mb":int(self.max_extract.get()),"max_zip_entries":int(self.max_entries.get()),"timeout":int(self.timeout.get()),"warning_mb":int(self.warning.get())}
            if any(v<=0 for v in d.values()):raise ValueError
            return d
        except ValueError:
            if show_errors:messagebox.showerror("Invalid settings","All limits must be positive whole numbers.")
            return None
    def update_warning(self):
        try:
            m=int(self.max_file.get());w=int(self.warning.get());self.limit_warning.set(f"Warning: transfers up to {m:,} MB are allowed. Transfers above {w:,} MB may take a while and depend on network speed." if m>w else "")
        except ValueError:self.limit_warning.set("")
    def toggle(self):
        for e in self.secret_entries:e.configure(show="" if self.show.get() else "*")
    def pick_folder(self):
        if x:=filedialog.askdirectory():self.folder.set(x)
    def open_folder_safe(self,p):
        try:Path(p).mkdir(parents=True,exist_ok=True);open_folder(p)
        except Exception as e:messagebox.showerror("Could not open folder",str(e))
    def add_files(self):
        for x in filedialog.askopenfilenames():
            p=Path(x)
            if p not in self.files:self.files.append(p);self.file_list.insert("end",str(p))
        self.slabel.config(text=f"{len(self.files)} file(s) selected")
    def add_folder(self):
        if not (x:=filedialog.askdirectory()):return
        for p in sorted(Path(x).rglob("*")):
            if p.is_file() and p not in self.files:self.files.append(p);self.file_list.insert("end",str(p))
        self.slabel.config(text=f"{len(self.files)} file(s) selected")
    def remove(self):
        for i in reversed(self.file_list.curselection()):self.file_list.delete(i);self.files.pop(i)
        self.slabel.config(text=f"{len(self.files)} file(s) selected")
    def clear(self):self.files.clear();self.file_list.delete(0,"end");self.slabel.config(text="No files selected")
    def basic(self):
        try:p=int(self.port.get());assert 1<=p<=65535
        except Exception:messagebox.showerror("Invalid port","Enter a port from 1 to 65535.");return None
        if len(self.password.get())<12:messagebox.showerror("Weak passphrase","Use at least 12 characters.");return None
        return p,self.password.get()
    def start_server(self):
        b=self.basic();settings=self.get_settings(True)
        if not b or not settings:return
        settings.update({"keep_zip":self.keep_zip.get(),"require_approval":self.require_approval.get()});self.server.start(self.host.get() or "0.0.0.0",b[0],b[1],self.folder.get(),settings)
    def review_send(self):
        if self.sending or not self.files:return
        b=self.basic();settings=self.get_settings(True)
        if not b or not settings:return
        total=sum(p.stat().st_size for p in self.files if p.exists())
        if len(self.files)!=sum(p.exists() for p in self.files):messagebox.showerror("Missing file","A selected file no longer exists.");return
        if total>settings["max_file_mb"]*1024**2:messagebox.showerror("Too large","Selection exceeds your configured maximum transfer size.");return
        name=self.bundle.get().strip() or f"transfer_{datetime.now():%Y%m%d_%H%M%S}"
        if len(self.files)>1 and not name.lower().endswith(".zip"):name+=".zip"
        warning="\n\nThis is a large transfer and may take a while." if total>settings["warning_mb"]*1024**2 else ""
        text=f"Files: {len(self.files)}\nOriginal size: {fmt_size(total)}\nReceiver: {self.target.get()}\nEncryption: AES-256-GCM\nPackage: {name if len(self.files)>1 else self.files[0].name}{warning}"
        if messagebox.askokcancel("Review transfer",text):self.begin_send(b[0],b[1],name)
    def begin_send(self,port,password,name):
        self.sending=True;self.send_cancel.clear();self.send_btn.config(state="disabled");self.cancel_send.config(state="normal");threading.Thread(target=self.worker,args=(self.target.get(),port,password,list(self.files),name),daemon=True).start()
    def cancel_outgoing(self):
        self.send_cancel.set()
        if self.send_socket:
            try:self.send_socket.shutdown(socket.SHUT_RDWR);self.send_socket.close()
            except OSError:pass
        self.status.set("Cancel requested")
    def worker(self,host,port,password,paths,bundle_name):
        temp=None;name=paths[0].name if len(paths)==1 else bundle_name;size=0
        try:
            if len(paths)>1:temp=make_zip(paths,bundle_name,self.send_cancel,lambda x:self.q.put(("sendprog",x*.15,"Creating ZIP package...")));source=temp
            else:source=paths[0]
            size=source.stat().st_size;h=hashlib.sha256();done=0
            with source.open("rb") as f:
                while b:=f.read(CHUNK):
                    if self.send_cancel.is_set():raise InterruptedError("Transfer canceled")
                    h.update(b);done+=len(b);self.q.put(("sendprog",15+5*done/max(1,size),"Preparing transfer..."))
            with socket.create_connection((host,port),timeout=30) as sock:
                self.send_socket=sock;sock.settimeout(1);ch=client_handshake(sock,password,self.send_cancel);ch.sendj({"name":name,"size":size,"sha256":h.hexdigest(),"count":len(paths)},b"meta");reply=ch.recvj(b"approval")
                if not reply.get("ok"):raise PermissionError(reply.get("error","Receiver rejected transfer"))
                done=0
                with source.open("rb") as f:
                    while b:=f.read(CHUNK):ch.send(b,b"chunk");done+=len(b);self.q.put(("sendprog",20+80*done/max(1,size),f"Encrypting and sending {name}"))
                result=ch.recvj(b"done");self.q.put(("complete",result["saved_as"]));self.add_history("Sent",name,size,host,"Success",result["saved_as"])
        except InterruptedError:self.q.put(("senderror","Transfer canceled"));self.add_history("Sent",name,size,host,"Canceled","")
        except Exception as e:self.q.put(("senderror",str(e)));self.add_history("Sent",name,size,host,"Failed",str(e))
        finally:self.send_socket=None;temp and temp.unlink(missing_ok=True)
    def request_approval(self,ip,name,size,count,cancel):
        req=threading.Event();box={"result":False};self.approval_id+=1;i=self.approval_id;self.approvals[i]=(req,box);self.q.put(("approval",i,ip,name,size,count))
        while not req.wait(.2):
            if cancel.is_set() or self.server.stop_event.is_set():return False
        self.approvals.pop(i,None);return box["result"]
    def add_history(self,direction,name,size,peer,status,details):self.q.put(("history",[datetime.now().strftime("%Y-%m-%d %H:%M:%S"),direction,name,fmt_size(size),peer,status,details]))
    def clear_history(self):
        if messagebox.askyesno("Clear history","Clear the displayed transfer history?"):self.history.clear();self.tree.delete(*self.tree.get_children())
    def write_log(self,x):self.log.config(state="normal");self.log.insert("end",x+"\n");self.log.see("end");self.log.config(state="disabled")
    def events(self):
        try:
            while True:
                e=self.q.get_nowait();k=e[0]
                if k=="log":self.write_log(e[1])
                elif k=="error":self.write_log(e[1]);messagebox.showerror("Receiver error",e[1])
                elif k=="running":self.start_btn.config(state="disabled" if e[1] else "normal");self.stop_btn.config(state="normal" if e[1] else "disabled");self.status.set("Receiver running" if e[1] else "Ready")
                elif k=="receive":self.rprog["value"]=e[1];self.rlabel.config(text=f"{e[2]}: {e[1]:.1f}%")
                elif k=="sendprog":self.sprog["value"]=e[1];self.slabel.config(text=e[2])
                elif k=="complete":self.sending=False;self.send_btn.config(state="normal");self.cancel_send.config(state="disabled");self.sprog["value"]=100;self.slabel.config(text=f"Complete: {e[1]}");messagebox.showinfo("Transfer complete",f"Saved as {e[1]}")
                elif k=="senderror":self.sending=False;self.send_btn.config(state="normal");self.cancel_send.config(state="disabled");self.slabel.config(text=e[1]);messagebox.showerror("Transfer ended",e[1])
                elif k=="approval":
                    _,i,ip,name,size,count=e;answer=messagebox.askyesno("Incoming encrypted transfer",f"From: {ip}\nName: {name}\nFiles: {count}\nSize: {fmt_size(size)}\n\nAccept this transfer?");req,box=self.approvals.get(i,(None,None))
                    if req:box["result"]=answer;req.set()
                elif k=="history":self.history.append(e[1]);self.tree.insert("","end",values=e[1])
        except queue.Empty:pass
        self.after(100,self.events)
    def close(self):
        self.cancel_outgoing();self.server.stop()
        try:self.save_config()
        except Exception:pass
        self.destroy()
if __name__=="__main__":App().mainloop()
