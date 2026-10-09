#!/usr/bin/env python3
"""Encrypted multi-file transfer GUI.
Install dependency on both computers: python -m pip install cryptography
"""
import hashlib, hmac, json, os, queue, socket, struct, tempfile, threading, zipfile
from pathlib import Path, PurePosixPath
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError as exc:
    raise SystemExit("Install the required package with: python -m pip install cryptography") from exc

CHUNK=64*1024; PORT=5001; MAX_FILE=4*1024**3; MAX_FRAME=CHUNK+65536
MAGIC=b"FTENC2"; CONTEXT=b"encrypted-file-transfer-v3"

def exact(s,n):
    b=bytearray()
    while len(b)<n:
        x=s.recv(n-len(b))
        if not x: raise ConnectionError("Connection closed early")
        b.extend(x)
    return bytes(b)

def frame_send(s,b):
    if len(b)>MAX_FRAME: raise ValueError("Frame too large")
    s.sendall(struct.pack("!I",len(b))+b)

def frame_recv(s):
    n=struct.unpack("!I",exact(s,4))[0]
    if n>MAX_FRAME: raise ValueError("Frame too large")
    return exact(s,n)

def key_for(password,salt):
    return Scrypt(salt=salt,length=32,n=2**15,r=8,p=1).derive(password.encode())

def proof(key,role,c,s):
    return hmac.new(key,CONTEXT+role+c+s,hashlib.sha256).digest()

class Channel:
    def __init__(self,s,key): self.s=s; self.a=AESGCM(key); self.tx=0; self.rx=0
    def send(self,b,p=b"data"):
        i=self.tx; self.tx+=1; nonce=os.urandom(12); aad=CONTEXT+p+struct.pack("!Q",i)
        frame_send(self.s,nonce+self.a.encrypt(nonce,b,aad))
    def recv(self,p=b"data"):
        i=self.rx; self.rx+=1; z=frame_recv(self.s)
        if len(z)<28: raise ValueError("Invalid encrypted frame")
        try: return self.a.decrypt(z[:12],z[12:],CONTEXT+p+struct.pack("!Q",i))
        except InvalidTag as e: raise PermissionError("Encrypted data was altered or used the wrong key") from e
    def sendj(self,o,p): self.send(json.dumps(o,separators=(",",":")).encode(),p)
    def recvj(self,p): return json.loads(self.recv(p).decode())

def client_handshake(s,password):
    c=os.urandom(32); s.sendall(MAGIC+c); z=exact(s,80); salt,sc,sp=z[:16],z[16:48],z[48:]
    k=key_for(password,salt)
    if not hmac.compare_digest(sp,proof(k,b"server",c,sc)): raise PermissionError("Wrong shared passphrase")
    s.sendall(proof(k,b"client",c,sc)); ch=Channel(s,k)
    if not ch.recvj(b"auth").get("ok"): raise PermissionError("Authentication failed")
    return ch

def server_handshake(s,password):
    z=exact(s,len(MAGIC)+32)
    if z[:len(MAGIC)]!=MAGIC: raise PermissionError("Unsupported client version")
    c=z[len(MAGIC):]; salt=os.urandom(16); sc=os.urandom(32); k=key_for(password,salt)
    s.sendall(salt+sc+proof(k,b"server",c,sc))
    if not hmac.compare_digest(exact(s,32),proof(k,b"client",c,sc)): raise PermissionError("Wrong shared passphrase")
    ch=Channel(s,k); ch.sendj({"ok":True},b"auth"); return ch

def unique_path(folder,name):
    name=Path(name).name
    if not name or name in (".",".."): raise ValueError("Invalid filename")
    p=folder.resolve()/name; base,suf=p.stem,p.suffix; i=1
    while p.exists() or p.with_name(p.name+".part").exists(): p=folder.resolve()/f"{base}_{i}{suf}"; i+=1
    return p

def safe_extract(zpath,out_root,max_files=5000,max_bytes=8*1024**3):
    out=unique_path(out_root,zpath.stem); out.mkdir()
    total=0
    try:
        with zipfile.ZipFile(zpath) as z:
            infos=z.infolist()
            if len(infos)>max_files: raise ValueError("Archive contains too many items")
            for info in infos:
                parts=PurePosixPath(info.filename).parts
                if not parts or info.filename.startswith(("/","\\")) or ".." in parts:
                    raise ValueError("Unsafe path in ZIP archive")
                if (info.external_attr>>16)&0o170000==0o120000: raise ValueError("Symbolic links are not allowed")
                total+=info.file_size
                if total>max_bytes: raise ValueError("Expanded archive is too large")
                target=out.joinpath(*parts)
                if info.is_dir(): target.mkdir(parents=True,exist_ok=True); continue
                target.parent.mkdir(parents=True,exist_ok=True)
                with z.open(info) as src, target.open("xb") as dst:
                    while b:=src.read(CHUNK): dst.write(b)
        return out
    except Exception:
        import shutil; shutil.rmtree(out,ignore_errors=True); raise

def make_zip(paths,progress):
    fd,name=tempfile.mkstemp(prefix="encrypted_transfer_",suffix=".zip"); os.close(fd); zp=Path(name)
    total=max(1,sum(p.stat().st_size for p in paths)); done=0; used=set()
    with zipfile.ZipFile(zp,"w",zipfile.ZIP_DEFLATED,allowZip64=True) as z:
        for p in paths:
            arc=p.name; n=1
            while arc in used: arc=f"{p.stem}_{n}{p.suffix}"; n+=1
            used.add(arc); z.write(p,arc); done+=p.stat().st_size; progress(done*100/total)
    return zp

def local_ip():
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s: s.connect(("8.8.8.8",80)); return s.getsockname()[0]
    except OSError: return "127.0.0.1"

class Server:
    def __init__(self,q): self.q=q; self.stopper=threading.Event(); self.sock=None; self.thread=None
    def start(self,host,port,password,folder,keep_zip):
        if self.thread and self.thread.is_alive(): return
        self.stopper.clear(); self.thread=threading.Thread(target=self.serve,args=(host,port,password,Path(folder),keep_zip),daemon=True); self.thread.start()
    def stop(self):
        self.stopper.set()
        if self.sock:
            try:self.sock.close()
            except OSError:pass
        self.q.put(("running",False))
    def serve(self,host,port,password,folder,keep_zip):
        try:
            folder.mkdir(parents=True,exist_ok=True)
            with socket.socket() as srv:
                self.sock=srv; srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); srv.settimeout(.5); srv.bind((host,port)); srv.listen(5)
                self.q.put(("running",True)); self.q.put(("log",f"Encrypted receiver listening on {host}:{port}"))
                while not self.stopper.is_set():
                    try:c,a=srv.accept()
                    except socket.timeout:continue
                    except OSError:break
                    threading.Thread(target=self.handle,args=(c,a,password,folder,keep_zip),daemon=True).start()
        except Exception as e:self.q.put(("error",str(e)))
        finally:self.sock=None; self.q.put(("running",False))
    def handle(self,s,addr,password,folder,keep_zip):
        tmp=None
        try:
            with s:
                s.settimeout(90); ch=server_handshake(s,password); m=ch.recvj(b"meta")
                size=int(m["size"]); sha=str(m["sha256"]); name=Path(str(m["name"])).name
                if size<0 or size>MAX_FILE or len(sha)!=64: raise ValueError("Invalid transfer metadata")
                dest=unique_path(folder,name); tmp=dest.with_name(dest.name+".part"); ch.sendj({"ok":True},b"ready")
                h=hashlib.sha256(); left=size; got=0
                with tmp.open("wb") as f:
                    while left:
                        b=ch.recv(b"chunk")
                        if not b or len(b)>min(CHUNK,left): raise ValueError("Invalid file chunk")
                        f.write(b); h.update(b); got+=len(b); left-=len(b); self.q.put(("receive",100*got/max(1,size),name))
                if not hmac.compare_digest(h.hexdigest(),sha): raise ValueError("Checksum failed")
                tmp.replace(dest); tmp=None; result=dest.name
                if dest.suffix.lower()==".zip" and not keep_zip:
                    extracted=safe_extract(dest,folder); dest.unlink(); result=extracted.name+"/"
                    self.q.put(("log",f"Safely extracted {name} to {result}"))
                else:self.q.put(("log",f"Saved {dest.name}"))
                ch.sendj({"ok":True,"saved_as":result},b"done")
        except Exception as e:
            if tmp: tmp.unlink(missing_ok=True)
            self.q.put(("log",f"Transfer from {addr[0]} failed: {e}"))

class App(tk.Tk):
    def __init__(self):
        super().__init__(); self.title("Encrypted Multi-File Transfer v3.1"); self.geometry("820x720"); self.minsize(720,640)
        self.q=queue.Queue(); self.server=Server(self.q); self.files=[]; self.sending=False
        self.host=tk.StringVar(value="0.0.0.0"); self.port=tk.StringVar(value=str(PORT)); self.password=tk.StringVar(); self.folder=tk.StringVar(value=str(Path.cwd()/"received_files")); self.target=tk.StringVar(value=local_ip()); self.keep_zip=tk.BooleanVar(value=False); self.show=tk.BooleanVar(value=False); self.status=tk.StringVar(value="Ready. AES-256-GCM encryption enabled.")
        self.secret_entries=[]; self.build(); self.after(100,self.events); self.protocol("WM_DELETE_WINDOW",self.close)
    def entry(self,p,label,var,row,secret=False):
        ttk.Label(p,text=label).grid(row=row,column=0,sticky="w",padx=(0,10),pady=5); e=ttk.Entry(p,textvariable=var,show="*" if secret else ""); e.grid(row=row,column=1,sticky="ew",pady=5)
        if secret:self.secret_entries.append(e)
    def build(self):
        root=ttk.Frame(self,padding=18); root.pack(fill="both",expand=True); ttk.Label(root,text="Encrypted Multi-File Transfer v3.1",font=("TkDefaultFont",18,"bold")).pack(anchor="w"); ttk.Label(root,text="Use Add Multiple Files or Add Folder. Two or more files are bundled into one encrypted ZIP transfer.").pack(anchor="w",pady=(2,12))
        nb=ttk.Notebook(root); nb.pack(fill="both",expand=True); r=ttk.Frame(nb,padding=15); s=ttk.Frame(nb,padding=15); nb.add(r,text="Receive"); nb.add(s,text="Send"); r.columnconfigure(1,weight=1); s.columnconfigure(1,weight=1)
        self.entry(r,"Listen address",self.host,0); self.entry(r,"Port",self.port,1); self.entry(r,"Shared passphrase",self.password,2,True); self.entry(r,"Save folder",self.folder,3); ttk.Button(r,text="Browse...",command=self.pick_folder).grid(row=3,column=2,padx=8)
        ttk.Checkbutton(r,text="KEEP RECEIVED ZIP FILES (do not extract)",variable=self.keep_zip).grid(row=4,column=0,columnspan=3,sticky="w",pady=8)
        ttk.Label(r,text=f"Likely local IP: {local_ip()}").grid(row=5,column=0,columnspan=3,sticky="w"); self.start=ttk.Button(r,text="Start Encrypted Receiver",command=self.start_server); self.start.grid(row=6,column=0,sticky="w",pady=12); self.stop=ttk.Button(r,text="Stop",command=self.server.stop,state="disabled"); self.stop.grid(row=6,column=1,sticky="w")
        self.rprog=ttk.Progressbar(r,maximum=100); self.rprog.grid(row=7,column=0,columnspan=3,sticky="ew"); self.rlabel=ttk.Label(r,text="Waiting for files"); self.rlabel.grid(row=8,column=0,columnspan=3,sticky="w")
        self.entry(s,"Receiver IP",self.target,0); self.entry(s,"Port",self.port,1); self.entry(s,"Shared passphrase",self.password,2,True)
        bar=ttk.Frame(s); bar.grid(row=3,column=0,columnspan=3,sticky="w",pady=8); ttk.Button(bar,text="Add Multiple Files...",command=self.add_files).pack(side="left"); ttk.Button(bar,text="Add Folder...",command=self.add_folder).pack(side="left",padx=6); ttk.Button(bar,text="Remove Selected",command=self.remove_files).pack(side="left"); ttk.Button(bar,text="Clear",command=self.clear_files).pack(side="left",padx=6)
        self.list=tk.Listbox(s,height=8,selectmode="extended"); self.list.grid(row=4,column=0,columnspan=3,sticky="nsew"); s.rowconfigure(4,weight=1)
        self.send=ttk.Button(s,text="Send Selected Files",command=self.begin_send); self.send.grid(row=5,column=0,columnspan=3,sticky="w",pady=12); self.sprog=ttk.Progressbar(s,maximum=100); self.sprog.grid(row=6,column=0,columnspan=3,sticky="ew"); self.slabel=ttk.Label(s,text="No files selected"); self.slabel.grid(row=7,column=0,columnspan=3,sticky="w")
        ttk.Checkbutton(root,text="Show passphrase",variable=self.show,command=self.toggle).pack(anchor="w",pady=(8,0)); box=ttk.LabelFrame(root,text="Activity",padding=6); box.pack(fill="both",pady=8); self.log=tk.Text(box,height=7,state="disabled"); self.log.pack(fill="both"); ttk.Label(root,textvariable=self.status).pack(anchor="w")
    def toggle(self):
        for e in self.secret_entries:e.configure(show="" if self.show.get() else "*")
    def pick_folder(self):
        if x:=filedialog.askdirectory():self.folder.set(x)
    def add_files(self):
        for x in filedialog.askopenfilenames():
            p=Path(x)
            if p not in self.files:self.files.append(p); self.list.insert("end",str(p))
        self.slabel.config(text=f"{len(self.files)} file(s) selected")
    def add_folder(self):
        folder=filedialog.askdirectory()
        if not folder:return
        root=Path(folder)
        added=0
        for p in sorted(root.rglob("*")):
            if p.is_file() and p not in self.files:
                self.files.append(p); self.list.insert("end",str(p)); added+=1
        self.slabel.config(text=f"{len(self.files)} file(s) selected ({added} added from folder)")
    def remove_files(self):
        for i in reversed(self.list.curselection()): self.list.delete(i); self.files.pop(i)
        self.slabel.config(text=f"{len(self.files)} file(s) selected")
    def clear_files(self): self.files.clear(); self.list.delete(0,"end"); self.slabel.config(text="No files selected")
    def settings(self):
        try:p=int(self.port.get()); assert 1<=p<=65535
        except: messagebox.showerror("Invalid port","Enter a port from 1 through 65535."); return None
        if len(self.password.get())<12: messagebox.showerror("Weak passphrase","Use at least 12 characters."); return None
        return p,self.password.get()
    def start_server(self):
        if not (v:=self.settings()):return
        self.server.start(self.host.get() or "0.0.0.0",v[0],v[1],self.folder.get(),self.keep_zip.get())
    def begin_send(self):
        if self.sending or not self.files:return
        if not (v:=self.settings()):return
        if any(not p.is_file() for p in self.files):messagebox.showerror("Missing file","One of the selected files no longer exists.");return
        self.sending=True; self.send.config(state="disabled"); threading.Thread(target=self.worker,args=(self.target.get(),v[0],v[1],list(self.files)),daemon=True).start()
    def worker(self,host,port,password,paths):
        temp=None
        try:
            if len(paths)>1:
                self.q.put(("sendprog",0,"Creating ZIP package...")); temp=make_zip(paths,lambda x:self.q.put(("sendprog",x*.15,"Creating ZIP package..."))); source=temp; send_name="file_bundle.zip"
            else: source=paths[0]; send_name=source.name
            size=source.stat().st_size; h=hashlib.sha256(); done=0
            with source.open("rb") as f:
                while b:=f.read(CHUNK):h.update(b);done+=len(b);self.q.put(("sendprog",15+5*done/max(1,size),"Preparing encrypted transfer..."))
            with socket.create_connection((host,port),timeout=30) as sock:
                sock.settimeout(90); ch=client_handshake(sock,password); ch.sendj({"name":send_name,"size":size,"sha256":h.hexdigest()},b"meta")
                if not ch.recvj(b"ready").get("ok"):raise RuntimeError("Receiver rejected transfer")
                done=0
                with source.open("rb") as f:
                    while b:=f.read(CHUNK):ch.send(b,b"chunk");done+=len(b);self.q.put(("sendprog",20+80*done/max(1,size),f"Encrypting and sending {send_name}"))
                result=ch.recvj(b"done"); self.q.put(("complete",result["saved_as"]))
        except Exception as e:self.q.put(("senderror",str(e)))
        finally:
            if temp:temp.unlink(missing_ok=True)
    def write_log(self,x): self.log.config(state="normal");self.log.insert("end",x+"\n");self.log.see("end");self.log.config(state="disabled")
    def events(self):
        try:
            while True:
                e=self.q.get_nowait(); k=e[0]
                if k=="log":self.write_log(e[1])
                elif k=="error":messagebox.showerror("Receiver error",e[1]);self.write_log(e[1])
                elif k=="running":self.start.config(state="disabled" if e[1] else "normal");self.stop.config(state="normal" if e[1] else "disabled");self.status.set("Encrypted receiver running" if e[1] else "Ready")
                elif k=="receive":self.rprog["value"]=e[1];self.rlabel.config(text=f"{e[2]}: {e[1]:.1f}%")
                elif k=="sendprog":self.sprog["value"]=e[1];self.slabel.config(text=e[2])
                elif k=="complete":self.sending=False;self.send.config(state="normal");self.sprog["value"]=100;self.slabel.config(text=f"Transfer complete: {e[1]}");messagebox.showinfo("Complete",f"Saved as {e[1]}")
                elif k=="senderror":self.sending=False;self.send.config(state="normal");self.slabel.config(text="Transfer failed");messagebox.showerror("Transfer failed",e[1])
        except queue.Empty:pass
        self.after(100,self.events)
    def close(self):self.server.stop();self.destroy()

if __name__=="__main__":App().mainloop()
