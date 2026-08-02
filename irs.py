import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import os
import sys
import subprocess
import time
import json
import threading
import socket
import struct
import hashlib
import math
import re
from datetime import datetime
import psutil

CONFIG_FILE = "/root/irs_godmode_settings.json"

class IncidentResponseSuite:
    def __init__(self, root):
        self.root = root
        self.root.title("[ INCIDENT & RESPONSIVE SUITE ] - SOC COMMAND CENTER")
        self.root.geometry("1800x1080")
        self.root.configure(bg="#090a0f")
        
        self.is_sniffing = False
        self.alarm_active = False
        self.tail_process = None
        self.fim_baselines = {}
        self.pcap_buffer = [] 
        
        self.load_settings()
        self.apply_theme()
        self.setup_ui()
        self.start_baseline_engine()
        self.audit_security_posture()

    def load_settings(self):
        self.settings = {"strict_firewall": False, "auto_snapshot": False}
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    self.settings.update(json.load(f))
            except Exception:
                pass

    def apply_theme(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        bg_dark = "#090a0f"
        bg_panel = "#121520"
        bg_tab_sel = "#1e2436"
        fg_cyan = "#00f3ff"
        
        self.style.configure("TNotebook", background=bg_dark, borderwidth=0)
        self.style.configure("TNotebook.Tab", background=bg_panel, foreground=fg_cyan, 
                             padding=[10, 6], font=('Consolas', 10, 'bold'))
        self.style.map("TNotebook.Tab", background=[("selected", bg_tab_sel)], 
                       foreground=[("selected", "#ffffff")])
        
        self.style.configure("Treeview", background="#0c0e15", foreground=fg_cyan, 
                             fieldbackground="#0c0e15", rowheight=26, font=('Consolas', 9))
        self.style.configure("Treeview.Heading", background="#171b28", foreground="#ffffff", 
                             font=('Consolas', 10, 'bold'))
        self.style.map("Treeview", background=[("selected", "#222c44")])
        
        self.style.configure("Vertical.TScrollbar", background="#121520", bordercolor="#090a0f", arrowcolor="#00f3ff")

    def setup_ui(self):
        self.header = tk.Label(self.root, 
                               text="[ INCIDENT & RESPONSIVE SUITE - ENTERPRISE EDR ]", 
                               font=("Consolas", 16, "bold"), bg="#171b28", fg="#00f3ff", pady=10, bd=1, relief=tk.RAISED)
        self.header.pack(fill=tk.X)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        self.tab_easy = tk.Frame(self.notebook, bg="#090a0f")
        self.tab_truth = tk.Frame(self.notebook, bg="#090a0f")
        self.tab_packet_inspector = tk.Frame(self.notebook, bg="#090a0f") 
        self.tab_malware_analyzer = tk.Frame(self.notebook, bg="#090a0f") 
        self.tab_live_logs = tk.Frame(self.notebook, bg="#090a0f")
        self.tab_contain_ops = tk.Frame(self.notebook, bg="#090a0f") 
        self.tab_forensic = tk.Frame(self.notebook, bg="#090a0f")
        self.tab_network = tk.Frame(self.notebook, bg="#090a0f")
        self.tab_crypto = tk.Frame(self.notebook, bg="#090a0f")
        self.tab_defcon = tk.Frame(self.notebook, bg="#1a0005") 
        self.tab_support = tk.Frame(self.notebook, bg="#090a0f")

        self.notebook.add(self.tab_easy, text="⭐ QUICK ACTIONS")
        self.notebook.add(self.tab_truth, text="1. Process Manager")
        self.notebook.add(self.tab_packet_inspector, text="2. Packet Sniffer")
        self.notebook.add(self.tab_malware_analyzer, text="3. Malware Triage")
        self.notebook.add(self.tab_live_logs, text="4. Live Logs")
        self.notebook.add(self.tab_contain_ops, text="5. Containment & Ops")
        self.notebook.add(self.tab_forensic, text="6. Forensics")
        self.notebook.add(self.tab_network, text="7. Network Matrix")
        self.notebook.add(self.tab_crypto, text="8. Vault & FIM")
        self.notebook.add(self.tab_defcon, text="9. DEFCON")
        self.notebook.add(self.tab_support, text="📖 MANUAL")

        self.build_easy_tab()
        self.build_truth_tab()
        self.build_packet_inspector_tab()
        self.build_malware_analyzer_tab()
        self.build_live_logs_tab()
        self.build_containment_ops_tab()
        self.build_forensic_tab()
        self.build_network_tab()
        self.build_crypto_tab()
        self.build_defcon_tab()
        self.build_support_tab()
        
        console_lbl = tk.Label(self.root, text="GLOBAL AUDIT & REAL-TIME THREAT STREAM", font=("Consolas", 10, "bold"), bg="#090a0f", fg="#00f3ff")
        console_lbl.pack(anchor=tk.W, padx=10)
        self.console = scrolledtext.ScrolledText(self.root, height=7, bg="#050608", fg="#00f3ff", font=("Consolas", 9), insertbackground="#00f3ff")
        self.console.pack(fill=tk.X, padx=10, pady=4)
        
        konsole_frame = tk.Frame(self.root, bg="#121520", padx=5, pady=3)
        konsole_frame.pack(fill=tk.X, padx=10, pady=(0, 6))
        tk.Label(konsole_frame, text="ROOT KONSOLE >", fg="#ff3355", bg="#121520", font=("Consolas", 10, "bold")).pack(side=tk.LEFT)
        self.cmd_entry = tk.Entry(konsole_frame, bg="#090a0f", fg="#00f3ff", font=("Consolas", 10), insertbackground="#00f3ff", bd=1)
        self.cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.cmd_entry.bind("<Return>", self.run_konsole_cmd)

        self.log_alert("[ INCIDENT & RESPONSIVE SUITE ] ONLINE. FLAWLESS EXECUTION ENGINES ACTIVE.", "SUCCESS")

    # ==========================================
    # CORE EXECUTION & ALARMS
    # ==========================================
    def log_alert(self, msg, level="INFO"):
        colors = {"INFO": "#00f3ff", "SUCCESS": "#50fa7b", "WARNING": "#ffb86c", "ERROR": "#ff3355", "CRITICAL": "#ff0055"}
        color = colors.get(level, "#00f3ff")
        timestamp = time.strftime("%H:%M:%S")
        def update_text():
            self.console.insert(tk.END, f"[{timestamp}] [{level}] > {msg}\n")
            self.console.see(tk.END)
        self.root.after(0, update_text)

    def trigger_visual_alarm(self, reason):
        if self.alarm_active: return 
        self.alarm_active = True
        self.log_alert(f"VISUAL HEURISTIC ALARM ENGAGED: {reason}", "CRITICAL")
        
        def flash(count=0):
            if count % 2 == 0:
                self.header.config(bg="#ff0055", fg="#ffffff", text="[ ⚠ CRITICAL ALERT - THREAT VECTOR DETECTED ⚠ ]")
                self.root.configure(bg="#330011")
            else:
                self.header.config(bg="#171b28", fg="#00f3ff", text="[ INCIDENT & RESPONSIVE SUITE - ENTERPRISE EDR ]")
                self.root.configure(bg="#090a0f")
            
            if count < 10: 
                self.root.after(200, flash, count + 1)
            else:
                self.root.configure(bg="#090a0f")
                self.header.config(bg="#171b28", fg="#00f3ff", text="[ INCIDENT & RESPONSIVE SUITE - ENTERPRISE EDR ]")
                self.alarm_active = False
        self.root.after(0, flash)

    def exec_cmd(self, task_name, cmd_list, is_critical=False):
        def run_thread():
            level = "CRITICAL" if is_critical else "INFO"
            self.log_alert(f"Launching pipeline: {task_name}...", level)
            try:
                if isinstance(cmd_list, list):
                    full_str = " ".join(cmd_list)
                    if any(char in full_str for char in ["|", "&&", "||", ">", "<", ";", "if ", "then", "else", "fi"]):
                        final_cmd = ["sh", "-c", full_str]
                    else:
                        final_cmd = cmd_list
                else:
                    final_cmd = ["sh", "-c", str(cmd_list)]

                process = subprocess.Popen(final_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                for line in process.stdout:
                    if line.strip(): self.log_alert(f"[{task_name}] {line.strip()}", "INFO")
                process.wait()
                if process.returncode == 0:
                    self.log_alert(f"SUCCESS: {task_name}", "SUCCESS")
                else:
                    self.log_alert(f"PIPELINE CONFLICT (Code {process.returncode}): {task_name}", "WARNING")
            except Exception as e:
                self.log_alert(f"CORE EXECUTION ERROR: {str(e)}", "ERROR")
        threading.Thread(target=run_thread, daemon=True).start()

    def create_btn_grid(self, parent, buttons, columns=4, width=32):
        row, col = 0, 0
        for text, cmd, critical in buttons:
            color = "#4a0d18" if critical else "#122038"
            hover_color = "#661222" if critical else "#1a3054"
            action = lambda t=text, c=cmd, crit=critical: self.exec_cmd(t, c, crit)
            btn = tk.Button(parent, text=text, bg=color, fg="#00f3ff", activebackground=hover_color, 
                            activeforeground="#ffffff", font=("Consolas", 9, "bold"), command=action, width=width, pady=6, bd=1)
            btn.grid(row=row, column=col, padx=4, pady=4)
            col += 1
            if col >= columns: col = 0; row += 1

    def run_konsole_cmd(self, event):
        cmd = self.cmd_entry.get().strip()
        if not cmd: return
        self.cmd_entry.delete(0, tk.END)
        self.log_alert(f"KONSOLE EXEC: {cmd}", "WARNING")
        def run():
            try:
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if res.stdout:
                    for line in res.stdout.splitlines():
                        if line.strip(): self.root.after(0, lambda l=line: self.log_alert(f"OUT: {l}", "INFO"))
                if res.stderr:
                    for line in res.stderr.splitlines():
                        if line.strip(): self.root.after(0, lambda l=line: self.log_alert(f"ERR: {l}", "ERROR"))
            except Exception as e:
                self.root.after(0, lambda: self.log_alert(f"EXEC ERROR: {str(e)}", "ERROR"))
        threading.Thread(target=run, daemon=True).start()

    # ==========================================
    # TAB 1: QUICK ACTIONS & UTILITIES
    # ==========================================
    def build_easy_tab(self):
        frame = tk.Frame(self.tab_easy, bg="#090a0f", padx=20, pady=20)
        frame.pack(fill=tk.BOTH, expand=True)
        tk.Label(frame, text="🛡️ Universal Deployment & Utility Actions", font=("Consolas", 16, "bold"), bg="#090a0f", fg="#ffffff").pack(pady=(0, 10))
        
        install_cmd = (
            "if command -v apt-get >/dev/null; then apt-get update && apt-get install -y psmisc rkhunter chkrootkit clamav ufw iptables alsa-utils lsof binutils whois dnsutils file docker.io; "
            "elif command -v pacman >/dev/null; then pacman -Sy --noconfirm psmisc rkhunter chkrootkit clamav ufw iptables alsa-utils lsof binutils whois bind file docker; "
            "elif command -v dnf >/dev/null; then dnf install -y psmisc rkhunter chkrootkit clamav ufw iptables alsa-utils lsof binutils whois bind-utils file docker; "
            "elif command -v zypper >/dev/null; then zypper install -y psmisc rkhunter chkrootkit clamav ufw iptables alsa-utils lsof binutils whois bind-utils file docker; "
            "elif command -v apk >/dev/null; then apk add psmisc rkhunter chkrootkit clamav ufw iptables alsa-utils lsof binutils whois bind-tools file docker; "
            "else echo 'Package Manager not automatically recognized.'; fi"
        )
        
        tk.Button(frame, text="⚙️ AUTO-INSTALL DEPENDENCIES (+DOCKER)", bg="#aa5500", fg="white", font=("Consolas", 11, "bold"), 
                  command=lambda: self.exec_cmd("Dependency Auto-Installer", [install_cmd], False), pady=8, bd=1).pack(fill=tk.X, pady=(0, 15))

        btn_grid = tk.Frame(frame, bg="#090a0f")
        btn_grid.pack()
        easy_ops = [
            ("🛡️ Enable UFW", ["ufw", "enable"], False),
            ("🔌 Panic: Drop Network", ["rfkill", "block", "all"], True),
            ("🧹 Flush Caches/Tmp", ["rm", "-rf", "/tmp/*", "/var/tmp/*"], False),
            ("🔒 Lock User Sessions", ["loginctl", "lock-sessions"], False),
            ("📡 Unblock Network", ["rfkill", "unblock", "all"], False),
            ("🔄 Repo Sec-Update", ["sh", "-c", "apt-get update || dnf check-update || pacman -Sy"], False),
            ("👤 List Logged Users", ["who"], False),
            ("💾 Check Disk Usage", ["df", "-h"], False),
            ("🧹 Flush DNS Cache", ["sh", "-c", "systemd-resolve --flush-caches || resolvectl flush-caches"], False),
            ("🕒 Uptime & Load", ["uptime"], False),
            ("☠ Kill Zombie PIDs", ["sh", "-c", "ps -A -ostat,pid | awk '/[zZ]/ {print $2}' | xargs -r kill -9"], True),
            ("🔄 Restart Network", ["sh", "-c", "systemctl restart NetworkManager || systemctl restart network"], False)
        ]
        self.create_btn_grid(btn_grid, easy_ops, columns=4, width=28)

    # ==========================================
    # TAB 2: PROCESS MANAGER
    # ==========================================
    def build_truth_tab(self):
        frame = tk.Frame(self.tab_truth, bg="#090a0f", padx=10, pady=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        self.posture_lbl = tk.Label(frame, text="Security Posture: Auditing Kernels...", font=("Consolas", 10, "bold"), bg="#121520", fg="#ffb86c", pady=4)
        self.posture_lbl.pack(fill=tk.X, pady=(0, 5))
        
        self.baseline_lbl = tk.Label(frame, text="Calibrating Hardware Metrics...", font=("Consolas", 11, "bold"), bg="#171b28", fg="#00f3ff", pady=8)
        self.baseline_lbl.pack(fill=tk.X, pady=(0, 10))

        ctrl_frame = tk.Frame(frame, bg="#090a0f")
        ctrl_frame.pack(fill=tk.X, pady=(0, 5))
        
        tk.Label(ctrl_frame, text="Search PID/Name:", bg="#090a0f", fg="#00f3ff", font=("Consolas", 10)).pack(side=tk.LEFT, padx=5)
        self.proc_search_entry = tk.Entry(ctrl_frame, bg="#121520", fg="#ffffff", font=("Consolas", 10), insertbackground="#00f3ff", width=20)
        self.proc_search_entry.pack(side=tk.LEFT, padx=5)
        self.proc_search_entry.bind("<KeyRelease>", lambda e: self.refresh_process_list())

        tk.Button(ctrl_frame, text="🔄 Refresh", bg="#122038", fg="#00f3ff", font=("Consolas", 9, "bold"), command=self.refresh_process_list).pack(side=tk.LEFT, padx=5)
        
        tk.Button(ctrl_frame, text="☠ KILL PARENT (PPID)", bg="#ff0055", fg="#ffffff", font=("Consolas", 9, "bold"), command=self.kill_parent_proc).pack(side=tk.RIGHT, padx=3)
        tk.Button(ctrl_frame, text="☠ SIGKILL", bg="#660d19", fg="#ffffff", font=("Consolas", 9, "bold"), command=lambda: self.kill_selected_proc(9)).pack(side=tk.RIGHT, padx=3)
        tk.Button(ctrl_frame, text="❄ Freeze", bg="#3b380d", fg="#ffffff", font=("Consolas", 9, "bold"), command=lambda: self.kill_selected_proc(19)).pack(side=tk.RIGHT, padx=3)
        tk.Button(ctrl_frame, text="▶ Resume", bg="#0d3b1e", fg="#ffffff", font=("Consolas", 9, "bold"), command=lambda: self.kill_selected_proc(18)).pack(side=tk.RIGHT, padx=3)
        
        tk.Button(ctrl_frame, text="🧠 Mem Maps", bg="#4a0d18", fg="#ffffff", font=("Consolas", 9, "bold"), command=self.inspect_proc_maps).pack(side=tk.RIGHT, padx=5)
        tk.Button(ctrl_frame, text="🔍 lsof Dump", bg="#122a47", fg="#ffffff", font=("Consolas", 9, "bold"), command=self.inspect_proc_files).pack(side=tk.RIGHT, padx=5)

        self.proc_tree = ttk.Treeview(frame, columns=("PID", "PPID", "Name", "User", "CPU%", "MEM%", "Status", "CmdLine"), show="headings", height=18)
        for col in ("PID", "PPID", "Name", "User", "CPU%", "MEM%", "Status", "CmdLine"):
            self.proc_tree.heading(col, text=col)

        self.proc_tree.column("PID", width=70, anchor=tk.CENTER)
        self.proc_tree.column("PPID", width=70, anchor=tk.CENTER)
        self.proc_tree.column("Name", width=140, anchor=tk.W)
        self.proc_tree.column("User", width=90, anchor=tk.CENTER)
        self.proc_tree.column("CPU%", width=60, anchor=tk.CENTER)
        self.proc_tree.column("MEM%", width=60, anchor=tk.CENTER)
        self.proc_tree.column("Status", width=90, anchor=tk.CENTER)
        self.proc_tree.column("CmdLine", width=600, anchor=tk.W)

        self.proc_tree.pack(fill=tk.BOTH, expand=True)
        self.refresh_process_list()

    def audit_security_posture(self):
        def check():
            try:
                selinux = subprocess.run(["sestatus"], capture_output=True, text=True).stdout.strip()
                se_stat = "ENFORCING" if "enforcing" in selinux.lower() else "DISABLED"
            except Exception: se_stat = "NOT INSTALLED"
                
            try:
                apparmor = subprocess.run(["apparmor_status"], capture_output=True, text=True).stdout.strip()
                aa_stat = "ACTIVE" if "profiles are loaded" in apparmor else "DISABLED"
            except Exception: aa_stat = "NOT INSTALLED"
                
            try:
                fw = subprocess.run(["ufw", "status"], capture_output=True, text=True).stdout.strip()
                fw_stat = "ACTIVE" if "active" in fw.lower() else "INACTIVE"
            except Exception: fw_stat = "NOT INSTALLED"
                
            posture_str = f"🛡️ HOST DEFENSES -> SELinux: [{se_stat}] | AppArmor: [{aa_stat}] | Firewall: [{fw_stat}]"
            self.root.after(0, lambda: self.posture_lbl.config(text=posture_str))
        threading.Thread(target=check, daemon=True).start()

    def refresh_process_list(self):
        filter_text = self.proc_search_entry.get().lower() if hasattr(self, 'proc_search_entry') else ""
        for item in self.proc_tree.get_children(): self.proc_tree.delete(item)
            
        def fetch():
            procs = []
            for proc in psutil.process_iter(['pid', 'ppid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status', 'cmdline']):
                try:
                    pinfo = proc.info
                    cmd = " ".join(pinfo['cmdline']) if pinfo['cmdline'] else pinfo['name']
                    if filter_text and filter_text not in pinfo['name'].lower() and filter_text not in str(pinfo['pid']) and filter_text not in cmd.lower():
                        continue
                    procs.append((
                        pinfo['pid'], pinfo['ppid'], pinfo['name'] or 'N/A', pinfo['username'] or 'N/A',
                        f"{pinfo['cpu_percent']:.1f}", f"{pinfo['memory_percent']:.1f}",
                        pinfo['status'], cmd
                    ))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, KeyError): pass
            
            def update():
                for p in procs[:250]: self.proc_tree.insert("", tk.END, values=p)
            self.root.after(0, update)
        threading.Thread(target=fetch, daemon=True).start()

    def kill_selected_proc(self, sig):
        sel = self.proc_tree.selection()
        if not sel:
            messagebox.showwarning("Warning", "Select a process from the table first.")
            return
        pid = self.proc_tree.item(sel[0])['values'][0]
        proc_name = self.proc_tree.item(sel[0])['values'][2]
        signals = {9: "SIGKILL (-9)", 15: "SIGTERM (-15)", 19: "SIGSTOP (Freeze)", 18: "SIGCONT (Resume)"}
        sig_name = signals.get(sig, str(sig))
        
        if messagebox.askyesno("Confirm Process Action", f"Send {sig_name} to PID {pid} ({proc_name})?"):
            try:
                os.kill(int(pid), sig)
                self.log_alert(f"Signal {sig_name} dispatched to PID {pid} ({proc_name})", "CRITICAL")
                self.root.after(500, self.refresh_process_list)
            except Exception as e:
                self.log_alert(f"Failed to signal PID {pid}: {str(e)}", "ERROR")

    def kill_parent_proc(self):
        sel = self.proc_tree.selection()
        if not sel: return
        ppid = self.proc_tree.item(sel[0])['values'][1]
        proc_name = self.proc_tree.item(sel[0])['values'][2]
        if ppid in [0, 1, 2]:
            messagebox.showwarning("System Protected", "Cannot kill Core System Process (Init/Systemd/Kthreadd).")
            return
            
        if messagebox.askyesno("Kill Parent", f"Sever PARENT PROCESS ID {ppid} to stop {proc_name} from respawning?"):
            try:
                os.kill(int(ppid), 9)
                self.log_alert(f"SIGKILL sent to Parent Process PPID {ppid}", "CRITICAL")
                self.root.after(500, self.refresh_process_list)
            except Exception as e:
                self.log_alert(f"Failed to kill PPID {ppid}: {str(e)}", "ERROR")

    def inspect_proc_files(self):
        sel = self.proc_tree.selection()
        if not sel: return
        pid = self.proc_tree.item(sel[0])['values'][0]
        self.exec_cmd(f"LSOF Dump PID {pid}", ["lsof", "-p", str(pid)], False)

    def inspect_proc_maps(self):
        sel = self.proc_tree.selection()
        if not sel: return
        pid = self.proc_tree.item(sel[0])['values'][0]
        self.exec_cmd(f"Mem Maps PID {pid}", ["sh", "-c", f"cat /proc/{pid}/maps | awk '{{print $6}}' | grep -v '^$' | sort | uniq"], False)

    def start_baseline_engine(self):
        def watchdog():
            while True:
                cpu_usage = psutil.cpu_percent(interval=1)
                mem_usage = psutil.virtual_memory().percent
                status_color = "#00f3ff"
                if cpu_usage > 95:
                    status_color = "#ff3355"
                    self.trigger_visual_alarm(f"CPU Utilization Spike ({cpu_usage}%)")
                status_text = f"SYSTEM TELEMETRY > CPU Load: {cpu_usage}% | RAM Usage: {mem_usage}% | Active PIDs Tracked: {len(psutil.pids())}"
                self.root.after(0, lambda: self.baseline_lbl.config(text=status_text, fg=status_color))
                time.sleep(3)
        threading.Thread(target=watchdog, daemon=True).start()

    # ==========================================
    # TAB 3: PACKET INSPECTOR
    # ==========================================
    def build_packet_inspector_tab(self):
        frame = tk.Frame(self.tab_packet_inspector, bg="#090a0f", padx=10, pady=10)
        frame.pack(fill=tk.BOTH, expand=True)
        ctrl_bar = tk.Frame(frame, bg="#090a0f")
        ctrl_bar.pack(fill=tk.X, pady=(0, 10))
        self.sniff_btn = tk.Button(ctrl_bar, text="▶ START SNIFFING", bg="#0d3b1e", fg="#00f3ff", font=("Consolas", 10, "bold"), command=self.toggle_sniffing, bd=1)
        self.sniff_btn.pack(side=tk.LEFT, padx=5)
        tk.Button(ctrl_bar, text="💾 EXPORT PCAP", bg="#122a47", fg="white", font=("Consolas", 10, "bold"), command=self.export_pcap_buffer, bd=1).pack(side=tk.LEFT, padx=5)
        tk.Button(ctrl_bar, text="🗑 CLEAR BUFFER", bg="#121520", fg="white", font=("Consolas", 10), command=self.clear_pcap_buffer, bd=1).pack(side=tk.LEFT, padx=5)
        
        self.pkt_tree = ttk.Treeview(frame, columns=("Time", "Proto", "Source", "Destination", "Port", "Len"), show="headings", height=22)
        for col in ("Time", "Proto", "Source", "Destination", "Port", "Len"): self.pkt_tree.heading(col, text=col)
        for col in ("Time", "Proto", "Port", "Len"): self.pkt_tree.column(col, width=110, anchor=tk.CENTER)
        self.pkt_tree.column("Source", width=240, anchor=tk.W)
        self.pkt_tree.column("Destination", width=240, anchor=tk.W)
        self.pkt_tree.pack(fill=tk.BOTH, expand=True)

    def clear_pcap_buffer(self):
        self.pcap_buffer.clear()
        self.pkt_tree.delete(*self.pkt_tree.get_children())

    def export_pcap_buffer(self):
        if not self.pcap_buffer:
            messagebox.showwarning("Warning", "Frame buffer is empty.")
            return
        t = time.strftime("%Y%m%d_%H%M%S")
        outpath = f"/root/irs_packet_dump_{t}.txt"
        try:
            with open(outpath, "w") as f:
                f.write("[ INCIDENT & RESPONSIVE SUITE ] - PACKET CAPTURE DUMP\n" + "="*60 + "\n")
                for entry in self.pcap_buffer:
                    f.write(f"[{entry[0]}] {entry[1]} {entry[2]} -> {entry[3]}:{entry[4]} (Len: {entry[5]}b)\n")
            self.log_alert(f"PACKET SNIFFER: Saved {len(self.pcap_buffer)} frames to {outpath}", "SUCCESS")
        except Exception as e:
            self.log_alert(f"Failed to export frames: {str(e)}", "ERROR")

    def toggle_sniffing(self):
        if not self.is_sniffing:
            self.is_sniffing = True
            self.sniff_btn.config(text="■ STOP SNIFFING", bg="#660d19", fg="#ffffff")
            threading.Thread(target=self.packet_sniff_loop, daemon=True).start()
        else:
            self.is_sniffing = False
            self.sniff_btn.config(text="▶ START SNIFFING", bg="#0d3b1e", fg="#00f3ff")

    def packet_sniff_loop(self):
        suspicious_ports = [4444, 4445, 31337, 1337, 6667, 23, 3389] 
        try: sniff_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        except Exception:
            self.is_sniffing = False
            return
        while self.is_sniffing:
            try:
                raw_data, _ = sniff_socket.recvfrom(65565)
                eth_protocol = socket.ntohs(struct.unpack('!6s6sH', raw_data[:14])[2])
                if eth_protocol == 8: 
                    try:
                        ip_header = struct.unpack('!BBHHHBBH4s4s', raw_data[14:34])
                        proto_type = ip_header[6]
                        src_ip = socket.inet_ntoa(ip_header[8])
                        dst_ip = socket.inet_ntoa(ip_header[9])
                        pkt_len = len(raw_data)
                        dst_port, proto_str = "N/A", "IPv4-RAW"
                        if proto_type == 6 and pkt_len > 38: 
                            proto_str = "TCP"
                            _, dst_port = struct.unpack('!HH', raw_data[34:38])
                        elif proto_type == 17 and pkt_len > 38:
                            proto_str = "UDP"
                            _, dst_port = struct.unpack('!HH', raw_data[34:38])
                        
                        if dst_port in suspicious_ports: self.trigger_visual_alarm(f"Suspicious Port Connection: {dst_port} from {src_ip}")
                        
                        entry = (datetime.now().strftime("%H:%M:%S"), proto_str, src_ip, dst_ip, dst_port, pkt_len)
                        self.pcap_buffer.append(entry)
                        if len(self.pcap_buffer) > 1000: self.pcap_buffer.pop(0)

                        def push_to_ui(e=entry):
                            if len(self.pkt_tree.get_children()) > 200: self.pkt_tree.delete(self.pkt_tree.get_children()[0])
                            self.pkt_tree.insert("", tk.END, values=e)
                        self.root.after(0, push_to_ui)
                    except struct.error:
                        pass 
            except Exception: pass
        sniff_socket.close()

    # ==========================================
    # TAB 4: MALWARE TRIAGE
    # ==========================================
    def build_malware_analyzer_tab(self):
        frame = tk.Frame(self.tab_malware_analyzer, bg="#090a0f", padx=15, pady=15)
        frame.pack(fill=tk.BOTH, expand=True)
        input_frame = tk.Frame(frame, bg="#090a0f")
        input_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(input_frame, text="Target Path:", font=("Consolas", 11), bg="#090a0f", fg="#00f3ff").pack(side=tk.LEFT, padx=5)
        self.malware_file_path = tk.Entry(input_frame, font=("Consolas", 11), bg="#121520", fg="white", insertbackground="#00f3ff", width=50, bd=1)
        self.malware_file_path.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        tk.Button(input_frame, text="🔍 DEEP TRIAGE", bg="#4a0d18", fg="white", font=("Consolas", 10, "bold"), command=self.run_malware_triage, bd=1).pack(side=tk.LEFT, padx=5)
        tk.Button(input_frame, text="🕸️ WEBSHELL SWEEP", bg="#3b380d", fg="white", font=("Consolas", 10, "bold"), command=self.run_webshell_regex_sweep, bd=1).pack(side=tk.RIGHT, padx=5)
        
        self.malware_report = scrolledtext.ScrolledText(frame, bg="#050608", fg="#00f3ff", font=("Consolas", 9), insertbackground="#00f3ff")
        self.malware_report.pack(fill=tk.BOTH, expand=True)

    def run_webshell_regex_sweep(self):
        target_dir = self.malware_file_path.get().strip()
        if not target_dir or not os.path.exists(target_dir):
            messagebox.showerror("Error", "Enter a valid directory path (e.g., /var/www/html or /tmp).")
            return
        self.malware_report.delete(1.0, tk.END)
        self.malware_report.insert(tk.END, f"[+] SWEEPING FOR WEBSHELLS & DROPPERS: {target_dir}\n" + "="*85 + "\n")
        
        def sweep_worker():
            patterns = {
                "PHP WebShell": r"eval\s*\(\s*base64_decode",
                "PHP SysExec": r"system\s*\(\s*\$_POST",
                "Python RevShell": r"import socket,subprocess,os",
                "Base64 Pipe": r"echo\s+[A-Za-z0-9+/=]+\s*\|\s*base64\s+-d\s*\|\s*sh",
                "Memfd Exec": r"memfd_create"
            }
            matches = 0
            for root_dir, _, files in os.walk(target_dir):
                for file in files:
                    filepath = os.path.join(root_dir, file)
                    try:
                        with open(filepath, 'r', errors='ignore') as f:
                            content = f.read(500000)
                            for name, pat in patterns.items():
                                if re.search(pat, content, re.IGNORECASE):
                                    matches += 1
                                    def log_hit(fp=filepath, n=name):
                                        self.malware_report.insert(tk.END, f"🚨 HIGH RISK HIT [{n}]: {fp}\n")
                                    self.root.after(0, log_hit)
                    except Exception: pass
            self.root.after(0, lambda: self.malware_report.insert(tk.END, f"\n[+] Sweep complete. Matches: {matches}\n"))
        threading.Thread(target=sweep_worker, daemon=True).start()

    def calculate_entropy(self, data):
        if not data: return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0: entropy += - p_x * math.log(p_x, 2)
        return entropy

    def generate_hex_dump(self, filepath, size=256):
        try:
            with open(filepath, 'rb') as f: chunk = f.read(size)
            hex_dump = ""
            for i in range(0, len(chunk), 16):
                line = chunk[i:i+16]
                hex_str = " ".join(f"{b:02x}" for b in line)
                ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in line)
                hex_dump += f"{i:08x}  {hex_str:<47}  |{ascii_str}|\n"
            return hex_dump
        except Exception as e: return f"Hex dump failed: {str(e)}"

    def run_malware_triage(self):
        target = self.malware_file_path.get().strip()
        if not target or not os.path.exists(target):
            messagebox.showerror("Error", "Target path is invalid.")
            return
        self.malware_report.delete(1.0, tk.END)
        self.malware_report.insert(tk.END, f"[+] Deep Forensic Triage: {target}\n" + "="*85 + "\n")
        
        def triage_worker():
            try:
                md5_hash, sha1_hash, sha256_hash = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
                with open(target, "rb") as f:
                    while chunk := f.read(8192):
                        md5_hash.update(chunk); sha1_hash.update(chunk); sha256_hash.update(chunk)
                
                file_size = os.path.getsize(target)
                file_type_res = subprocess.run(["file", target], capture_output=True, text=True)
                file_type = file_type_res.stdout.split(":", 1)[-1].strip() if file_type_res.returncode == 0 else "Unknown"
                
                elf_info = "Not an ELF binary"
                with open(target, "rb") as f:
                    header = f.read(64)
                    if header.startswith(b"\x7fELF"):
                        arch = "64-bit" if header[4] == 2 else "32-bit"
                        endian = "Little Endian" if header[5] == 1 else "Big Endian"
                        elf_info = f"ELF [{arch}, {endian}]"

                with open(target, "rb") as f:
                    raw_bytes = f.read(1024 * 1024)
                    entropy_score = self.calculate_entropy(raw_bytes)
                entropy_warn = "⚠️ HIGH ENTROPY (>7.2): Packed/Encrypted!" if entropy_score > 7.2 else "Normal density"

                with open(target, "rb") as f:
                    content = f.read(500000)
                    printable_strings = re.findall(b"[\x20-\x7e]{4,}", content)
                    decoded_strings = [s.decode('ascii', errors='ignore') for s in printable_strings]
                
                ips, urls, suspicious_calls = set(), set(), []
                suspicious_keywords = ["/bin/sh", "/bin/bash", "curl", "wget", "nc", "execve", "ptrace", "memfd_create", "socket", "chmod +x", "chattr"]
                for s in decoded_strings:
                    found_ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", s)
                    for ip in found_ips:
                        if not ip.startswith("127.") and not ip.startswith("0."): ips.add(ip)
                    if "http://" in s or "https://" in s: urls.add(s)
                    for kw in suspicious_keywords:
                        if kw in s and len(suspicious_calls) < 20: suspicious_calls.append(s)

                hex_dump_data = self.generate_hex_dump(target, 256)

                def render():
                    r = self.malware_report
                    r.insert(tk.END, f"📌 FILE IDENTIFICATION:\n -> Size: {file_size}b\n -> MD5:    {md5_hash.hexdigest()}\n -> SHA256: {sha256_hash.hexdigest()}\n\n")
                    r.insert(tk.END, f"🔬 BINARY CHARACTERISTICS:\n -> Type: {file_type}\n -> Architecture: {elf_info}\n -> Entropy: {entropy_score:.3f} / 8.000 ({entropy_warn})\n\n")
                    r.insert(tk.END, f"🌐 IOCs:\n -> IPv4: {list(ips) if ips else 'None'}\n -> URLs: {list(urls) if urls else 'None'}\n\n")
                    r.insert(tk.END, f"🚨 SUSPICIOUS STRINGS:\n")
                    if suspicious_calls:
                        for call in suspicious_calls[:15]: r.insert(tk.END, f"   [!] {call}\n")
                    else: r.insert(tk.END, " -> No direct shell calls identified.\n")
                    r.insert(tk.END, f"\n📜 RAW HEX DUMP:\n{hex_dump_data}\n")
                    r.insert(tk.END, f"🔗 VT Link: https://www.virustotal.com/gui/file/{sha256_hash.hexdigest()}\n" + "="*85 + "\n")
                self.root.after(0, render)
            except Exception as e:
                self.root.after(0, lambda: self.malware_report.insert(tk.END, f"Error: {str(e)}"))
        threading.Thread(target=triage_worker, daemon=True).start()

    # ==========================================
    # TAB 5: LIVE LOGS 
    # ==========================================
    def build_live_logs_tab(self):
        frame = tk.Frame(self.tab_live_logs, bg="#090a0f", padx=10, pady=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ctrl_bar = tk.Frame(frame, bg="#090a0f")
        ctrl_bar.pack(fill=tk.X, pady=(0, 10))
        
        tk.Button(ctrl_bar, text="▶ STREAM AUTH", bg="#0d3b1e", fg="#00f3ff", font=("Consolas", 9, "bold"), command=lambda: self.start_tail("auth"), bd=1).pack(side=tk.LEFT, padx=4)
        tk.Button(ctrl_bar, text="▶ STREAM SYSLOG", bg="#0d3b1e", fg="#00f3ff", font=("Consolas", 9, "bold"), command=lambda: self.start_tail("syslog"), bd=1).pack(side=tk.LEFT, padx=4)
        tk.Button(ctrl_bar, text="▶ STREAM KERNEL", bg="#0d3b1e", fg="#00f3ff", font=("Consolas", 9, "bold"), command=lambda: self.start_tail("kernel"), bd=1).pack(side=tk.LEFT, padx=4)
        tk.Button(ctrl_bar, text="▶ STREAM WEB LOGS", bg="#122a47", fg="#00f3ff", font=("Consolas", 9, "bold"), command=lambda: self.start_tail("web"), bd=1).pack(side=tk.LEFT, padx=4)
        
        self.tail_stop_btn = tk.Button(ctrl_bar, text="■ STOP STREAM", bg="#660d19", fg="#ffffff", font=("Consolas", 9, "bold"), command=self.stop_tail, bd=1, state=tk.DISABLED)
        self.tail_stop_btn.pack(side=tk.LEFT, padx=4)
        tk.Button(ctrl_bar, text="🗑 CLEAR LOG", bg="#121520", fg="white", font=("Consolas", 9), command=lambda: self.log_viewer.delete(1.0, tk.END), bd=1).pack(side=tk.LEFT, padx=4)
        
        self.log_viewer = scrolledtext.ScrolledText(frame, bg="#050608", fg="#50fa7b", font=("Consolas", 9), insertbackground="#00f3ff")
        self.log_viewer.pack(fill=tk.BOTH, expand=True)
        
        self.log_viewer.tag_config("alert", foreground="#ff3355", background="#220000")
        self.log_viewer.tag_config("critical_user", foreground="#ffb86c", background="#331a00")
        self.log_viewer.insert(tk.END, "[*] Select a log source above to begin syntax-highlighted live stream...\n")

    def stop_tail(self):
        if self.tail_process:
            self.tail_process.terminate()
            self.tail_process = None
        self.tail_stop_btn.config(state=tk.DISABLED)

    def start_tail(self, log_type):
        self.stop_tail()
        paths = {
            "auth": "/var/log/auth.log" if os.path.exists("/var/log/auth.log") else "/var/log/secure",
            "syslog": "/var/log/syslog" if os.path.exists("/var/log/syslog") else "/var/log/messages",
            "kernel": "/var/log/kern.log" if os.path.exists("/var/log/kern.log") else "/var/log/dmesg",
            "web": "/var/log/nginx/access.log" if os.path.exists("/var/log/nginx/access.log") else ("/var/log/apache2/access.log" if os.path.exists("/var/log/apache2/access.log") else None)
        }
        log_file = paths.get(log_type)
        if not log_file or not os.path.exists(log_file):
            messagebox.showerror("Error", f"Log file for {log_type} not found on this system.")
            return
        
        self.tail_stop_btn.config(state=tk.NORMAL)
        self.log_viewer.insert(tk.END, f"\n--- LIVE SYNTAX-HIGHLIGHTED STREAM: {log_file} ---\n")
        self.tail_process = subprocess.Popen(["tail", "-f", "-n", "30", log_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        def tail_worker():
            for line in iter(self.tail_process.stdout.readline, ''):
                if line:
                    tags = []
                    l_lower = line.lower()
                    if "failed" in l_lower or "invalid" in l_lower or "error" in l_lower or "fatal" in l_lower:
                        tags.append("alert")
                    elif "root" in l_lower or "sudo" in l_lower or "accepted" in l_lower:
                        tags.append("critical_user")
                        
                    def update(l=line, t=tags):
                        self.log_viewer.insert(tk.END, l, tuple(t))
                        self.log_viewer.see(tk.END)
                    self.root.after(0, update)
        threading.Thread(target=tail_worker, daemon=True).start()

    # ==========================================
    # TAB 6: CONTAINMENT & OPS (MEGA DASHBOARD)
    # ==========================================
    def build_containment_ops_tab(self):
        canvas = tk.Canvas(self.tab_contain_ops, bg="#090a0f", highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.tab_contain_ops, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg="#090a0f")

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        def make_subtitle(parent, title):
            ttk.Separator(parent, orient='horizontal').pack(fill='x', pady=8)
            tk.Label(parent, text=title, font=("Consolas", 12, "bold"), bg="#090a0f", fg="#ffb86c").pack(anchor=tk.W, pady=(0, 4))

        # --- SECTION 1: CONTAINMENT & ISOLATION ---
        tk.Label(scrollable_frame, text="🔒 CONTAINMENT & ISOLATION", font=("Consolas", 12, "bold"), bg="#090a0f", fg="#ffb86c").pack(anchor=tk.W, pady=(0, 4))
        grid_contain = tk.Frame(scrollable_frame, bg="#090a0f")
        grid_contain.pack(fill=tk.X)
        ops_contain = [
            ("❄ Freeze Guest", ["pkill", "-STOP", "-u", "guest"], True), 
            ("▶ Resume Guest", ["pkill", "-CONT", "-u", "guest"], False), 
            ("☠ Kill SSH Daemons", ["sh", "-c", "killall sshd || systemctl stop sshd || systemctl stop ssh"], True), 
            ("🔒 Lock /etc (+i)", ["chattr", "-R", "+i", "/etc"], True), 
            ("🔓 Unlock /etc (-i)", ["chattr", "-R", "-i", "/etc"], False), 
            ("🚫 Lock Guest Acct", ["passwd", "-l", "guest"], True), 
            ("✅ Unlock Guest", ["passwd", "-u", "guest"], False),
            ("☠ Disconnect All User", ["sh", "-c", "pkill -KILL -u !root"], True),
            ("🔒 Lock /var/www", ["chattr", "-R", "+i", "/var/www"], True),
            ("🔓 Unlock /var/www", ["chattr", "-R", "-i", "/var/www"], False),
            ("🐳 Pause All Docker", ["sh", "-c", "docker pause $(docker ps -q)"], True),
            ("🐳 Nuke All Docker", ["sh", "-c", "docker kill $(docker ps -q)"], True)
        ]
        self.create_btn_grid(grid_contain, ops_contain, columns=4, width=28)

        # --- SECTION 2: KERNEL WATCHDOG ---
        make_subtitle(scrollable_frame, "🧠 KERNEL WATCHDOG")
        grid_kernel = tk.Frame(scrollable_frame, bg="#090a0f")
        grid_kernel.pack(fill=tk.X)
        ops_kernel = [
            ("📝 List Modules", ["lsmod"], False), 
            ("☢ Check Taints", ["sh", "-c", "dmesg | grep -i taint"], True), 
            ("❌ Kernel Errors", ["sh", "-c", "grep -i 'verification failed' /var/log/kern.log"], True), 
            ("⚙ IOMMU Status", ["sh", "-c", "dmesg | grep -i dma"], False),
            ("🚗 Loaded Drivers", ["lspci", "-k"], False),
            ("💾 CPU Microcode", ["sh", "-c", "dmesg | grep microcode"], False),
            ("🖨 Print Dmesg", ["dmesg"], False)
        ]
        self.create_btn_grid(grid_kernel, ops_kernel, columns=4, width=28)

        # --- SECTION 3: THREAT HUNTING ---
        make_subtitle(scrollable_frame, "🎯 THREAT HUNTING")
        grid_threat = tk.Frame(scrollable_frame, bg="#090a0f")
        grid_threat.pack(fill=tk.X)
        ops_threat = [
            ("🦠 ClamAV Scan (/tmp)", ["clamscan", "-r", "-i", "/tmp"], False), 
            ("🕵️ RKHunter Scan", ["rkhunter", "-c", "--sk"], True), 
            ("🕵️ Chkrootkit", ["chkrootkit"], True), 
            ("🔄 Update RKHunter", ["rkhunter", "--propupd"], False),
            ("🔒 Hunt SUIDs", ["find", "/", "-type", "f", "-perm", "-4000", "-exec", "ls", "-ld", "{}", "\\;"], True),
            ("👻 Hidden Temp Files", ["find", "/tmp", "/var/tmp", "/dev/shm", "-name", ".*", "-ls"], True),
            ("👻 Check ld.so.preload", ["cat", "/etc/ld.so.preload"], True),
            ("🔓 World-Writable", ["find", "/", "-xdev", "-type", "f", "-perm", "-0002", "-ls"], True),
            ("⛏️ Hunt Crypto Miners", ["sh", "-c", "ps aux | grep -iE 'xmrig|minerd|cryptonight|stratum'"], True),
            ("🕵️ Hunt Mem Backdoors", ["sh", "-c", "grep -i 'rwxp' /proc/*/maps 2>/dev/null | awk '{print $1}' | uniq"], True)
        ]
        self.create_btn_grid(grid_threat, ops_threat, columns=4, width=28)

        # --- SECTION 4: SYSTEM HARDENING ---
        make_subtitle(scrollable_frame, "🛡️ SYSTEM HARDENING")
        grid_harden = tk.Frame(scrollable_frame, bg="#090a0f")
        grid_harden.pack(fill=tk.X)
        ops_harden = [
            ("🛡️ UFW Deny Incoming", ["sh", "-c", "ufw default deny incoming && ufw enable"], True), 
            ("🚫 Drop ICMP (Ping)", ["iptables", "-A", "INPUT", "-p", "icmp", "-j", "DROP"], False), 
            ("🚫 Disable Root SSH", ["sed", "-i", "s/PermitRootLogin yes/PermitRootLogin no/g", "/etc/ssh/sshd_config"], True),
            ("✅ Enable RP Filter", ["sysctl", "-w", "net.ipv4.conf.all.rp_filter=1"], True),
            ("✅ Enable SYN Cookies", ["sysctl", "-w", "net.ipv4.tcp_syncookies=1"], True),
            ("🚫 Disable IPv6", ["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"], True),
            ("🔒 Hard BPF JIT", ["sysctl", "-w", "net.core.bpf_jit_harden=2"], True),
            ("🛡️ Audit SSH Config", ["sshd", "-T"], False),
            ("🔒 Lock SSH Config", ["chattr", "+i", "/etc/ssh/sshd_config"], True),
            ("🔓 Unlock SSH Config", ["chattr", "-i", "/etc/ssh/sshd_config"], False),
            ("✅ Randomize TCP MAC", ["sysctl", "-w", "net.ipv4.tcp_rfc1337=1"], True)
        ]
        self.create_btn_grid(grid_harden, ops_harden, columns=4, width=28)

        # --- SECTION 5: HARDWARE WARDEN ---
        make_subtitle(scrollable_frame, "🖥️ HARDWARE WARDEN")
        grid_hardware = tk.Frame(scrollable_frame, bg="#090a0f")
        grid_hardware.pack(fill=tk.X)
        ops_hardware = [
            ("📷 Unload Webcam", ["modprobe", "-r", "uvcvideo"], True), 
            ("📷 Load Webcam", ["modprobe", "uvcvideo"], False), 
            ("📡 Block RF (WiFi/BT)", ["rfkill", "block", "wifi"], True), 
            ("🎤 Mute Microphones", ["amixer", "set", "Capture", "nocap"], True),
            ("🔌 List USB Devices", ["lsusb"], False),
            ("🖥️ List PCI Devices", ["lspci"], False),
            ("🚫 Disable USB Storage", ["modprobe", "-r", "usb-storage"], True),
            ("🚫 Disable Bluetooth", ["sh", "-c", "systemctl stop bluetooth && rfkill block bluetooth"], True)
        ]
        self.create_btn_grid(grid_hardware, ops_hardware, columns=4, width=28)

    # ==========================================
    # TAB 7: FORENSICS
    # ==========================================
    def build_forensic_tab(self):
        frame = tk.Frame(self.tab_forensic, bg="#090a0f", padx=10, pady=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        btn_grid = tk.Frame(frame, bg="#090a0f")
        btn_grid.pack(fill=tk.X, pady=(0, 5))
        
        f_ops = [
            ("USB History", "dmesg | grep -i usb"),
            ("Cron Jobs", "cat /etc/crontab /etc/cron.*/* /var/spool/cron/* 2>/dev/null"),
            ("Systemd Timers", "systemctl list-timers --all"),
            ("SSH Keys", "cat /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null"),
            ("Modified (24h)", "find /etc /usr/bin /tmp /var/tmp -mtime -1 -ls 2>/dev/null"),
            ("Failed Logins", "cat /var/log/auth.log /var/log/secure 2>/dev/null | grep -iE 'failed|invalid' | tail -n 50"),
            ("Sudoers Config", "cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v '^#'"),
            ("Shell History", "cat /root/.bash_history /home/*/.bash_history /home/*/.zsh_history 2>/dev/null | tail -n 150"),
            ("Active Connections", "ss -ntup 2>/dev/null"),
            ("Large Files (>200M)", "find / -type f -size +200M -exec ls -lh {} \\; 2>/dev/null | awk '{ print $9 \": \" $5 }'"),
            ("Enabled Services", "systemctl list-unit-files --state=enabled"),
            ("SUID Root Files", "find / -type f -perm -4000 -exec ls -ld {} \\; 2>/dev/null"),
            ("🐳 List Docker Cnt", "docker ps -a")
        ]
        
        row, col = 0, 0
        for title, cmd in f_ops:
            tk.Button(btn_grid, text=title, bg="#122038", fg="white", font=("Consolas", 9, "bold"),
                      command=lambda c=cmd: self.run_forensic(c), width=24, bd=1).grid(row=row, column=col, padx=4, pady=4)
            col += 1
            if col > 4: col=0; row+=1

        self.forensic_view = scrolledtext.ScrolledText(frame, bg="#050608", fg="#00f3ff", font=("Consolas", 9), insertbackground="#00f3ff")
        self.forensic_view.pack(fill=tk.BOTH, expand=True, pady=5)

    def run_forensic(self, cmd_string):
        self.forensic_view.delete(1.0, tk.END)
        def fetch():
            res = subprocess.run(cmd_string, shell=True, capture_output=True, text=True)
            out = res.stdout if res.stdout else "No records encountered or execution returned empty."
            if res.stderr: out += f"\n[Errors / Standard Error]: {res.stderr}"
            self.root.after(0, lambda: self.forensic_view.insert(tk.END, out))
        threading.Thread(target=fetch, daemon=True).start()

    # ==========================================
    # TAB 8: NETWORK MATRIX
    # ==========================================
    def build_network_tab(self):
        frame = tk.Frame(self.tab_network, bg="#090a0f", padx=10, pady=10)
        frame.pack(fill=tk.BOTH, expand=True)
        ctrl = tk.Frame(frame, bg="#090a0f", pady=5)
        ctrl.pack(fill=tk.X)
        tk.Button(ctrl, text="🔄 Refresh Matrix", bg="#122038", fg="white", font=("Consolas", 10), command=self.scan_network, bd=1).pack(side=tk.LEFT, padx=5)
        tk.Button(ctrl, text="📡 Check Promiscuous", bg="#3b380d", fg="white", font=("Consolas", 10, "bold"), command=lambda: self.exec_cmd("Promisc Check", ["ip", "link", "show"], False), bd=1).pack(side=tk.LEFT, padx=5)
        tk.Button(ctrl, text="🔍 WHOIS / DNS", bg="#122a47", fg="white", font=("Consolas", 10, "bold"), command=self.osint_selected_ip, bd=1).pack(side=tk.LEFT, padx=5)
        
        tk.Button(ctrl, text="☠ KILL PID", bg="#4a0d18", fg="white", font=("Consolas", 10, "bold"), command=self.kill_socket_owner_pid, bd=1).pack(side=tk.RIGHT, padx=5)
        tk.Button(ctrl, text="🚫 Ban IP", bg="#660d19", fg="white", font=("Consolas", 10, "bold"), command=self.ban_selected_ip, bd=1).pack(side=tk.RIGHT, padx=5)
        tk.Button(ctrl, text="☠ Nuke Foreign IPs", bg="#ff0055", fg="white", font=("Consolas", 10, "bold"), command=lambda: self.exec_cmd("Nuke Foreign", ["sh", "-c", "ss -ntp | awk '{print $5}' | grep -v '127.0.0.1' | grep -v '::1' | cut -d: -f1 | sort | uniq | xargs -I {} ufw deny from {}"], True), bd=1).pack(side=tk.RIGHT, padx=5)
        
        self.net_tree = ttk.Treeview(frame, columns=("Protocol", "Local", "Remote", "State", "Process/PID"), show="headings", height=18)
        for col in ("Protocol", "Local", "Remote", "State", "Process/PID"): self.net_tree.heading(col, text=col)
        self.net_tree.pack(fill=tk.BOTH, expand=True)

    def kill_socket_owner_pid(self):
        sel = self.net_tree.selection()
        if not sel:
            messagebox.showwarning("Warning", "Select a network row first.")
            return
        proc_str = str(self.net_tree.item(sel[0])['values'][4])
        match = re.search(r'pid=(\d+)', proc_str)
        if match:
            pid = int(match.group(1))
            if messagebox.askyesno("Confirm", f"Send SIGKILL to Socket Owner PID {pid}?"):
                try:
                    os.kill(pid, 9)
                    self.log_alert(f"SIGKILL sent to Socket Owner PID {pid}", "CRITICAL")
                    self.scan_network()
                except Exception as e:
                    self.log_alert(f"Failed to kill PID {pid}: {str(e)}", "ERROR")

    def scan_network(self):
        self.net_tree.delete(*self.net_tree.get_children())
        def fetch_net():
            try:
                output = subprocess.run(["ss", "-ntup"], capture_output=True, text=True).stdout.split('\n')[1:]
                for line in output:
                    p = line.split()
                    if len(p) >= 5:
                        proc_info = p[6] if len(p) >= 7 else "Unknown/RootReq"
                        self.root.after(0, lambda parts=p, proc=proc_info: self.net_tree.insert("", tk.END, values=(parts[0], parts[4], parts[5], parts[1], proc)))
            except Exception: pass
        threading.Thread(target=fetch_net, daemon=True).start()

    def ban_selected_ip(self):
        sel = self.net_tree.selection()
        if sel:
            ip = self.net_tree.item(sel[0])['values'][2].rsplit(':', 1)[0]
            if messagebox.askyesno("Confirm Isolation", f"Deploy firewall rule blocking all I/O to: {ip}?"): 
                self.exec_cmd(f"FW Block {ip}", ["ufw", "deny", "from", str(ip)], True)

    def osint_selected_ip(self):
        sel = self.net_tree.selection()
        if not sel:
            messagebox.showwarning("Warning", "Select a network connection first.")
            return
        ip = self.net_tree.item(sel[0])['values'][2].rsplit(':', 1)[0]
        if ip in ["0.0.0.0", "*", "127.0.0.1", "::1"]:
            messagebox.showinfo("Recon Info", "Selected IP is a local bind address.")
            return
        top = tk.Toplevel(self.root)
        top.title(f"OSINT Reconnaissance: {ip}")
        top.geometry("800x600")
        top.configure(bg="#090a0f")
        tk.Label(top, text=f"🔍 EXTERNAL INTELLIGENCE FOR TARGET: {ip}", font=("Consolas", 14, "bold"), bg="#121520", fg="#00f3ff", pady=10).pack(fill=tk.X)
        txt = scrolledtext.ScrolledText(top, bg="#050608", fg="#50fa7b", font=("Consolas", 10), insertbackground="#00f3ff")
        txt.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        txt.insert(tk.END, f"[*] Querying databases for {ip}...\n\n")

        def fetch_osint():
            res = subprocess.run(f"host {ip} ; echo '\n--- WHOIS DATA ---' ; whois {ip} | grep -iE 'NetName|OrgName|Country|City|CIDR'", shell=True, capture_output=True, text=True)
            self.root.after(0, lambda: txt.insert(tk.END, res.stdout if res.stdout else "No data returned."))
        threading.Thread(target=fetch_osint, daemon=True).start()

    # ==========================================
    # TAB 9: CONFIG VAULT, FIM & IR REPORT
    # ==========================================
    def build_crypto_tab(self):
        frame = tk.Frame(self.tab_crypto, bg="#090a0f", padx=20, pady=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        fim_frame = tk.Frame(frame, bg="#090a0f", pady=10)
        fim_frame.pack(fill=tk.X)
        tk.Label(fim_frame, text="FILE INTEGRITY MONITORING (FIM) & IR REPORTING", font=("Consolas", 12, "bold"), bg="#090a0f", fg="#ffb86c").pack(pady=5)
        
        tk.Button(fim_frame, text="📸 CAPTURE FIM BASELINE", bg="#122038", fg="white", font=("Consolas", 10, "bold"), command=self.capture_fim_baseline, bd=1).pack(side=tk.LEFT, padx=10)
        tk.Button(fim_frame, text="🔍 VERIFY INTEGRITY", bg="#4a0d18", fg="white", font=("Consolas", 10, "bold"), command=self.verify_fim_baseline, bd=1).pack(side=tk.LEFT, padx=10)
        tk.Button(fim_frame, text="📄 EXPORT IR REPORT (HTML)", bg="#0d3b1e", fg="white", font=("Consolas", 10, "bold"), command=self.generate_ir_report, bd=1).pack(side=tk.RIGHT, padx=10)

        ttk.Separator(frame, orient='horizontal').pack(fill='x', pady=20)
        grid = tk.Frame(frame, bg="#090a0f")
        grid.pack(fill=tk.BOTH)
        t = time.strftime("%Y%m%d_%H%M%S")
        ops = [
            ("BTRFS Snapshot (RO)", ["btrfs", "subvolume", "snapshot", "-r", "/", f"/.snapshots/root_{t}"], False), 
            ("Verify Snapshots", ["btrfs", "subvolume", "list", "/"], False),
            ("Backup /etc (Tarball)", ["tar", "-czpf", f"/root/irs_etc_backup_{t}.tar.gz", "/etc"], False)
        ]
        self.create_btn_grid(grid, ops, columns=4, width=28)

    def generate_ir_report(self):
        t = time.strftime("%Y%m%d_%H%M%S")
        outpath = f"/root/irs_ir_report_{t}.html"
        try:
            procs = [p.info for p in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent'])]
            net_connections = subprocess.run(["ss", "-ntup"], capture_output=True, text=True).stdout
            
            html_content = f"""<html><head><title>INCIDENT & RESPONSIVE SUITE - FORENSIC REPORT</title>
            <style>body {{ background-color: #090a0f; color: #00f3ff; font-family: monospace; padding: 20px; }}
            h1 {{ color: #ff0055; }} table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #121520; padding: 8px; text-align: left; }} th {{ background-color: #171b28; color: #ffffff; }}
            pre {{ background-color: #050608; padding: 10px; border: 1px solid #121520; color: #50fa7b; }}</style></head>
            <body><h1>INCIDENT & RESPONSIVE SUITE FORENSIC REPORT</h1><p><strong>Generated At:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <hr><h2>Active High Resource Processes</h2><table><tr><th>PID</th><th>Name</th><th>User</th><th>CPU %</th><th>MEM %</th></tr>
            {''.join(f"<tr><td>{p['pid']}</td><td>{p['name']}</td><td>{p['username']}</td><td>{p['cpu_percent']}</td><td>{p['memory_percent']}</td></tr>" for p in procs[:25])}
            </table><h2>Active Network Sockets Matrix</h2><pre>{net_connections}</pre></body></html>"""
            
            with open(outpath, "w") as f: f.write(html_content)
            self.log_alert(f"IR REPORT GENERATOR: HTML Report compiled to {outpath}", "SUCCESS")
            messagebox.showinfo("Report Exported", f"Forensic Incident Report exported to:\n{outpath}")
        except Exception as e:
            self.log_alert(f"Failed to generate IR report: {str(e)}", "ERROR")

    def capture_fim_baseline(self):
        core_files = ["/etc/passwd", "/etc/shadow", "/bin/bash", "/usr/sbin/sshd", "/etc/sudoers"]
        self.fim_baselines.clear()
        for filepath in core_files:
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'rb') as f:
                        self.fim_baselines[filepath] = hashlib.sha256(f.read()).hexdigest()
                except Exception: pass
        self.log_alert(f"FIM ENGINE: Captured SHA-256 Baseline hashes for {len(self.fim_baselines)} critical files.", "SUCCESS")

    def verify_fim_baseline(self):
        if not self.fim_baselines:
            messagebox.showwarning("FIM Engine", "No baseline exists! Please Capture System Baseline first.")
            return
        clean_count = 0
        for filepath, expected_hash in self.fim_baselines.items():
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'rb') as f:
                        current_hash = hashlib.sha256(f.read()).hexdigest()
                    if current_hash != expected_hash:
                        self.trigger_visual_alarm(f"FIM ALERT: {filepath} HAS BEEN MODIFIED OR COMPROMISED!")
                    else:
                        clean_count += 1
                except Exception: pass
            else:
                self.trigger_visual_alarm(f"FIM ALERT: {filepath} IS MISSING OR DELETED!")
        if clean_count == len(self.fim_baselines):
            self.log_alert("FIM ENGINE: All tracked system files match cryptographic baseline. No tampering detected.", "SUCCESS")

    # ==========================================
    # TAB 10: DEFCON EMERGENCY
    # ==========================================
    def build_defcon_tab(self):
        frame = tk.Frame(self.tab_defcon, bg="#1a0005", padx=20, pady=20)
        frame.pack(fill=tk.BOTH, expand=True)
        tk.Label(frame, text="⚠ DEFCON 1 CRITICAL AIR-GAP SYSTEM MANAGEMENT ⚠", font=("Consolas", 18, "bold"), bg="#1a0005", fg="#ff0055").pack(pady=20)
        def engage_airgap():
            if messagebox.askyesno("DEFCON 1", "Drop ALL inbound and outbound network traffic instantly?"):
                self.header.config(bg="#ff0055", fg="black", text="[ SYSTEM AIR-GAPPED - ACTIVE ATTACK PROTOCOL ENGAGED ]")
                self.exec_cmd("Airgap Inbound", ["iptables", "-P", "INPUT", "DROP"], True)
                self.exec_cmd("Airgap Outbound", ["iptables", "-P", "OUTPUT", "DROP"], True)
        tk.Button(frame, text="ENGAGE AIR-GAP INFRASTRUCTURE DISCONNECT", bg="#ff0055", fg="white", font=("Consolas", 14, "bold"), command=engage_airgap, pady=15, bd=1).pack(fill=tk.X, pady=15)
        tk.Button(frame, text="FORCE LOW-LEVEL TERMINAL MAINTENANCE RESCUE", bg="#880022", fg="white", font=("Consolas", 12, "bold"), command=lambda: subprocess.run(["systemctl", "isolate", "rescue.target"]), pady=10, bd=1).pack(fill=tk.X, pady=10)

    # ==========================================
    # TAB 11: SUPPORT MANUAL & GUIDE
    # ==========================================
    def build_support_tab(self):
        frame = tk.Frame(self.tab_support, bg="#090a0f", padx=15, pady=15)
        frame.pack(fill=tk.BOTH, expand=True)
        guide_text = scrolledtext.ScrolledText(frame, bg="#050608", fg="#00f3ff", font=("Consolas", 10), insertbackground="#00f3ff")
        guide_text.pack(fill=tk.BOTH, expand=True)
        
        manual_content = """========================================================================================
 [ INCIDENT & RESPONSIVE SUITE ] - OPERATIONAL SUPPORT & COMMAND MANUAL
========================================================================================

1. OVERVIEW & PURPOSE
   The Incident & Responsive Suite is an enterprise-grade Endpoint Detection & Response (EDR), 
   Host-based Intrusion Prevention System (HIPS), and Incident Response (IR) suite designed 
   for Linux environments.

2. MODULE BREAKDOWN & USAGE GUIDELINES

   [⭐ QUICK ACTIONS]
   - High-density grid for immediate environmental actions (Flush DNS, List Users, Enable UFW).
   - Kill Zombie PIDs: Forcefully clears defunct processes cluttering the memory queue.

   [4. LIVE LOGS]
   - Active Syntax Engine: Real-time highlighting maps critical words (Failed, Invalid, Error) 
     to RED, and privileged accesses (Root, Sudo, Accepted) to ORANGE.

   [5. CONTAINMENT & OPS (THE MEGA-TAB)]
   - **FLAWLESS UI:** A fully scrollable Canvas engine prevents clipping and ensures 
     all 45+ forensic and hardening buttons render smoothly across all screen sizes.
   - This dashboard unifies Containment, Kernel Watchdog, Threat Hunting, Hardening, 
     and Hardware Warden into a single layout for immediate access during a crisis.
   - Docker Container Nuke: Instantly pause or kill all active containers.
   - Hunt Mem Backdoors: Scans the /proc filesystem for executable memory regions (rwxp).
   - Randomize TCP MAC: System hardening to drop anti-DDOS vectors.

   [7. NETWORK MATRIX]
   - Kill Socket Owner PID: Select a socket and instantly terminate its owning process directly.

3. EQUIVALENT ROOT TERMINAL COMMAND MATRIX

   +---------------------------------------+-------------------------------------------------------+
   | ACTION                                | UNDERLYING CLI COMMAND                                |
   +---------------------------------------+-------------------------------------------------------+
   | Kill Zombie PIDs                      | ps -A -ostat,pid | awk '/[zZ]/' | xargs -r kill -9    |
   | Hunt Memory Backdoors                 | grep -i 'rwxp' /proc/*/maps                           |
   | Docker Container Nuke                 | docker kill $(docker ps -q)                           |
   | Randomize TCP MAC                     | sysctl -w net.ipv4.tcp_rfc1337=1                      |
   | WebShell Regex Sweep                  | grep -E -r 'eval\(base64_decode' /var/www/            |
   +---------------------------------------+-------------------------------------------------------+

========================================================================================
"""
        guide_text.insert(tk.END, manual_content)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] Access Denied: Incident & Responsive Suite requires root execution parameters.")
        sys.exit(1)
    root = tk.Tk()
    app = IncidentResponseSuite(root)
    root.mainloop()
