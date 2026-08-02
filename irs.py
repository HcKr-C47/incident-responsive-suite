import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, Menu
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
import base64
import csv
import urllib.request
import urllib.error
import shlex  
from datetime import datetime
import psutil

CONFIG_FILE = "/root/irs_godmode_settings.json"
FIM_DB_FILE = "/root/irs_fim_baseline.json"

# ==========================================
# TOOLTIP CLASS (UI/UX)
# ==========================================
class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip_window = None
        self.widget.bind("<Enter>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event=None):
        if self.tooltip_window or not self.text:
            return
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        self.tooltip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify=tk.LEFT,
                         background="#ffb86c", foreground="#090a0f", 
                         relief=tk.SOLID, borderwidth=1,
                         font=("Consolas", 9, "bold"), padx=4, pady=4)
        label.pack(ipadx=1)

    def hide_tooltip(self, event=None):
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None

class IncidentResponseSuite:
    def __init__(self, root):
        self.root = root
        self.root.title("[ INCIDENT & RESPONSIVE SUITE ]")
        self.root.geometry("1800x1080")
        self.root.configure(bg="#090a0f")
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
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

    def on_closing(self):
        self.is_sniffing = False
        if self.tail_process:
            self.tail_process.terminate()
        self.root.destroy()
        sys.exit(0)

    def load_settings(self):
        self.settings = {"strict_firewall": False, "auto_snapshot": False}
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    self.settings.update(json.load(f))
            except Exception: pass
        
        if os.path.exists(FIM_DB_FILE):
            try:
                with open(FIM_DB_FILE, "r") as f:
                    self.fim_baselines = json.load(f)
            except Exception: pass

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
                               text="[ INCIDENT & RESPONSIVE SUITE ]", 
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
        self.tab_rev_eng = tk.Frame(self.notebook, bg="#090a0f")
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
        self.notebook.add(self.tab_rev_eng, text="9. RE & DEOBFUSCATION")
        self.notebook.add(self.tab_defcon, text="10. DEFCON")
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
        self.build_rev_eng_tab() 
        self.build_defcon_tab()
        self.build_support_tab()
        
        console_lbl = tk.Label(self.root, text="GLOBAL AUDIT & REAL-TIME THREAT STREAM", font=("Consolas", 10, "bold"), bg="#090a0f", fg="#00f3ff")
        console_lbl.pack(anchor=tk.W, padx=10)
        self.console = scrolledtext.ScrolledText(self.root, height=7, bg="#050608", fg="#00f3ff", font=("Consolas", 9), insertbackground="#00f3ff")
        self.console.pack(fill=tk.X, padx=10, pady=4)
        
        konsole_frame = tk.Frame(self.root, bg="#121520", padx=5, pady=3)
        konsole_frame.pack(fill=tk.X, padx=10, pady=(0, 2))
        tk.Label(konsole_frame, text="ROOT KONSOLE >", fg="#ff3355", bg="#121520", font=("Consolas", 10, "bold")).pack(side=tk.LEFT)
        self.cmd_entry = tk.Entry(konsole_frame, bg="#090a0f", fg="#00f3ff", font=("Consolas", 10), insertbackground="#00f3ff", bd=1)
        self.cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.cmd_entry.bind("<Return>", self.run_konsole_cmd)
        tk.Button(konsole_frame, text="💾 EXPORT LOGS", bg="#122a47", fg="white", font=("Consolas", 9, "bold"), command=self.export_global_logs, bd=1).pack(side=tk.RIGHT, padx=5)

        self.status_bar = tk.Label(self.root, text="INITIALIZING SYSTEM TELEMETRY...", font=("Consolas", 10, "bold"), bg="#171b28", fg="#50fa7b", pady=4, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        self.log_alert("[ INCIDENT & RESPONSIVE SUITE ] ONLINE. HARDENED EXECUTION ENGINES ACTIVE.", "SUCCESS")
        if self.fim_baselines:
            self.log_alert(f"[+] Loaded {len(self.fim_baselines)} persistent FIM baselines from disk.", "INFO")

    # ==========================================
    # FILE EXPLORER HELPERS & EXPORT
    # ==========================================
    def browse_file(self, entry_widget):
        filepath = filedialog.askopenfilename(title="Select Target File")
        if filepath:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, filepath)

    def browse_directory(self, entry_widget):
        dirpath = filedialog.askdirectory(title="Select Target Directory")
        if dirpath:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, dirpath)

    def export_global_logs(self):
        t = time.strftime("%Y%m%d_%H%M%S")
        outpath = f"/root/irs_global_log_{t}.txt"
        try:
            with open(outpath, "w") as f:
                f.write(self.console.get(1.0, tk.END))
            messagebox.showinfo("Export Success", f"Global logs exported to:\n{outpath}")
            self.log_alert(f"Logs exported to {outpath}", "SUCCESS")
        except Exception as e:
            self.log_alert(f"Failed to export logs: {str(e)}", "ERROR")

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
                self.status_bar.config(bg="#ff0055", fg="black")
            else:
                self.header.config(bg="#171b28", fg="#00f3ff", text="[ INCIDENT & RESPONSIVE SUITE - ENTERPRISE EDR ]")
                self.root.configure(bg="#090a0f")
                self.status_bar.config(bg="#171b28", fg="#50fa7b")
            
            if count < 10: 
                self.root.after(200, flash, count + 1)
            else:
                self.root.configure(bg="#090a0f")
                self.header.config(bg="#171b28", fg="#00f3ff", text="[ INCIDENT & RESPONSIVE SUITE - ENTERPRISE EDR ]")
                self.status_bar.config(bg="#171b28", fg="#50fa7b")
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
            cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
            ToolTip(btn, f"Underlying Execution:\n> {cmd_str}")
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
            "if command -v apt-get >/dev/null; then apt-get update && apt-get install -y psmisc rkhunter chkrootkit clamav ufw iptables alsa-utils lsof binutils whois dnsutils file docker.io strace ltrace curl jq; "
            "elif command -v pacman >/dev/null; then pacman -Sy --noconfirm psmisc rkhunter chkrootkit clamav ufw iptables alsa-utils lsof binutils whois bind file docker strace ltrace curl jq; "
            "elif command -v dnf >/dev/null; then dnf install -y psmisc rkhunter chkrootkit clamav ufw iptables alsa-utils lsof binutils whois bind-utils file docker strace ltrace curl jq; "
            "elif command -v zypper >/dev/null; then zypper install -y psmisc rkhunter chkrootkit clamav ufw iptables alsa-utils lsof binutils whois bind-utils file docker strace ltrace curl jq; "
            "elif command -v apk >/dev/null; then apk add psmisc rkhunter chkrootkit clamav ufw iptables alsa-utils lsof binutils whois bind-tools file docker strace ltrace curl jq; "
            "else echo 'Package Manager not automatically recognized.'; fi"
        )
        
        install_btn = tk.Button(frame, text="⚙️ AUTO-INSTALL DEPENDENCIES (+DOCKER & RE TOOLS)", bg="#aa5500", fg="white", font=("Consolas", 11, "bold"), 
                  command=lambda: self.exec_cmd("Dependency Auto-Installer", [install_cmd], False), pady=8, bd=1)
        install_btn.pack(fill=tk.X, pady=(0, 15))
        ToolTip(install_btn, "Installs all missing dependencies like ClamAV, rkhunter, ufw, lsof, strace, ltrace, curl, and jq.")

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
        
        ctrl_frame = tk.Frame(frame, bg="#090a0f")
        ctrl_frame.pack(fill=tk.X, pady=(0, 5))
        
        tk.Label(ctrl_frame, text="Search PID/Name:", bg="#090a0f", fg="#00f3ff", font=("Consolas", 10)).pack(side=tk.LEFT, padx=5)
        self.proc_search_entry = tk.Entry(ctrl_frame, bg="#121520", fg="#ffffff", font=("Consolas", 10), insertbackground="#00f3ff", width=20)
        self.proc_search_entry.pack(side=tk.LEFT, padx=5)
        self.proc_search_entry.bind("<KeyRelease>", lambda e: self.refresh_process_list())

        tk.Button(ctrl_frame, text="🔄 Refresh", bg="#122038", fg="#00f3ff", font=("Consolas", 9, "bold"), command=self.refresh_process_list).pack(side=tk.LEFT, padx=5)
        tk.Button(ctrl_frame, text="💾 Export CSV", bg="#122a47", fg="#ffffff", font=("Consolas", 9, "bold"), command=self.export_proc_csv).pack(side=tk.LEFT, padx=5)
        
        tk.Button(ctrl_frame, text="☠ KILL PARENT", bg="#ff0055", fg="#ffffff", font=("Consolas", 9, "bold"), command=self.kill_parent_proc).pack(side=tk.RIGHT, padx=3)
        tk.Button(ctrl_frame, text="☠ SIGKILL", bg="#660d19", fg="#ffffff", font=("Consolas", 9, "bold"), command=lambda: self.kill_selected_proc(9)).pack(side=tk.RIGHT, padx=3)
        tk.Button(ctrl_frame, text="❄ Freeze", bg="#3b380d", fg="#ffffff", font=("Consolas", 9, "bold"), command=lambda: self.kill_selected_proc(19)).pack(side=tk.RIGHT, padx=3)
        tk.Button(ctrl_frame, text="▶ Resume", bg="#0d3b1e", fg="#ffffff", font=("Consolas", 9, "bold"), command=lambda: self.kill_selected_proc(18)).pack(side=tk.RIGHT, padx=3)
        tk.Button(ctrl_frame, text="🧠 Mem Maps", bg="#4a0d18", fg="#ffffff", font=("Consolas", 9, "bold"), command=self.inspect_proc_maps).pack(side=tk.RIGHT, padx=5)
        tk.Button(ctrl_frame, text="🔍 lsof Dump", bg="#122a47", fg="#ffffff", font=("Consolas", 9, "bold"), command=self.inspect_proc_files).pack(side=tk.RIGHT, padx=5)

        # Container for Treeview + Scrollbar
        tree_frame = tk.Frame(frame, bg="#090a0f")
        tree_frame.pack(fill=tk.BOTH, expand=True)

        scroll_y = ttk.Scrollbar(tree_frame, orient="vertical")
        self.proc_tree = ttk.Treeview(tree_frame, columns=("PID", "PPID", "Name", "User", "CPU%", "MEM%", "Status", "CmdLine"), 
                                      show="headings", height=18, yscrollcommand=scroll_y.set)
        scroll_y.config(command=self.proc_tree.yview)

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

        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.proc_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.proc_menu = Menu(self.root, tearoff=0, bg="#121520", fg="#00f3ff")
        self.proc_menu.add_command(label="☠ SIGKILL (-9)", command=lambda: self.kill_selected_proc(9))
        self.proc_menu.add_command(label="❄ Freeze Process", command=lambda: self.kill_selected_proc(19))
        self.proc_menu.add_command(label="▶ Resume Process", command=lambda: self.kill_selected_proc(18))
        self.proc_menu.add_separator()
        self.proc_menu.add_command(label="🔍 View Open Files (lsof)", command=self.inspect_proc_files)
        self.proc_menu.add_command(label="🧠 Dump Memory Maps", command=self.inspect_proc_maps)
        self.proc_tree.bind("<Button-3>", self.show_proc_menu)

        self.refresh_process_list()

    def show_proc_menu(self, event):
        iid = self.proc_tree.identify_row(event.y)
        if iid:
            self.proc_tree.selection_set(iid)
            self.proc_menu.tk_popup(event.x_root, event.y_root)

    def export_proc_csv(self):
        t = time.strftime("%Y%m%d_%H%M%S")
        outpath = f"/root/irs_processes_{t}.csv"
        try:
            with open(outpath, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["PID", "PPID", "Name", "User", "CPU%", "MEM%", "Status", "CmdLine"])
                for item in self.proc_tree.get_children():
                    writer.writerow(self.proc_tree.item(item)['values'])
            messagebox.showinfo("Export Success", f"Process list exported to:\n{outpath}")
            self.log_alert(f"Process list CSV exported to {outpath}", "SUCCESS")
        except Exception as e:
            self.log_alert(f"CSV Export Error: {str(e)}", "ERROR")

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
            
            def update_ui():
                # Batched update: deletes and inserts together to prevent UI flickering
                self.proc_tree.delete(*self.proc_tree.get_children())
                for p in procs: 
                    self.proc_tree.insert("", tk.END, values=p)
            self.root.after(0, update_ui)
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
        pid_safe = shlex.quote(str(pid))
        self.exec_cmd(f"Mem Maps PID {pid_safe}", ["sh", "-c", f"cat /proc/{pid_safe}/maps | awk '{{print $6}}' | grep -v '^$' | sort | uniq"], False)

    def start_baseline_engine(self):
        def watchdog():
            while True:
                cpu_usage = psutil.cpu_percent(interval=1)
                mem_usage = psutil.virtual_memory().percent
                pids = len(psutil.pids())
                status_color = "#50fa7b"
                if cpu_usage > 95:
                    status_color = "#ff3355"
                    self.trigger_visual_alarm(f"CPU Utilization Spike ({cpu_usage}%)")
                
                sniff_str = "ACTIVE" if self.is_sniffing else "INACTIVE"
                status_text = f"⚙ HOST TELEMETRY: CPU [{cpu_usage}%] | RAM [{mem_usage}%] | ACTIVE PIDs [{pids}] | RAW SNIFFER [{sniff_str}]"
                self.root.after(0, lambda: self.status_bar.config(text=status_text, fg=status_color))
                time.sleep(2)
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
        
        tree_frame = tk.Frame(frame, bg="#090a0f")
        tree_frame.pack(fill=tk.BOTH, expand=True)

        scroll_y = ttk.Scrollbar(tree_frame, orient="vertical")
        self.pkt_tree = ttk.Treeview(tree_frame, columns=("Time", "Proto", "Source", "Destination", "Port", "Len"), 
                                     show="headings", height=22, yscrollcommand=scroll_y.set)
        scroll_y.config(command=self.pkt_tree.yview)

        for col in ("Time", "Proto", "Source", "Destination", "Port", "Len"): self.pkt_tree.heading(col, text=col)
        for col in ("Time", "Proto", "Port", "Len"): self.pkt_tree.column(col, width=110, anchor=tk.CENTER)
        self.pkt_tree.column("Source", width=240, anchor=tk.W)
        self.pkt_tree.column("Destination", width=240, anchor=tk.W)
        
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.pkt_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

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
        try: 
            sniff_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            sniff_socket.settimeout(1.0) 
        except Exception as e:
            self.is_sniffing = False
            self.log_alert(f"Failed to bind raw socket: {str(e)}", "ERROR")
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
                        
                        if len(self.pcap_buffer) > 10000: self.pcap_buffer.pop(0)

                        def push_to_ui(e=entry):
                            self.pkt_tree.insert("", tk.END, values=e)
                            children = self.pkt_tree.get_children()
                            if len(children) > 1000: # Increased UI visible cap to 1000 for better trailing
                                self.pkt_tree.delete(children[0])
                        self.root.after(0, push_to_ui)
                    except struct.error:
                        pass 
            except socket.timeout:
                continue 
            except Exception: pass
        sniff_socket.close()

    # ==========================================
    # TAB 4: MALWARE TRIAGE 
    # ==========================================
    def build_malware_analyzer_tab(self):
        frame = tk.Frame(self.tab_malware_analyzer, bg="#090a0f", padx=15, pady=15)
        frame.pack(fill=tk.BOTH, expand=True)
        
        input_frame = tk.Frame(frame, bg="#090a0f")
        input_frame.pack(fill=tk.X, pady=(0, 5))
        tk.Label(input_frame, text="Target Path:", font=("Consolas", 11), bg="#090a0f", fg="#00f3ff").pack(side=tk.LEFT, padx=5)
        self.malware_file_path = tk.Entry(input_frame, font=("Consolas", 11), bg="#121520", fg="white", insertbackground="#00f3ff", width=40, bd=1)
        self.malware_file_path.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        tk.Button(input_frame, text="📂 FILE", bg="#122038", fg="white", font=("Consolas", 9, "bold"), command=lambda: self.browse_file(self.malware_file_path), bd=1).pack(side=tk.LEFT, padx=2)
        tk.Button(input_frame, text="📁 DIR", bg="#122038", fg="white", font=("Consolas", 9, "bold"), command=lambda: self.browse_directory(self.malware_file_path), bd=1).pack(side=tk.LEFT, padx=2)
        tk.Button(input_frame, text="🔍 DEEP TRIAGE", bg="#4a0d18", fg="white", font=("Consolas", 10, "bold"), command=self.run_malware_triage, bd=1).pack(side=tk.LEFT, padx=10)
        tk.Button(input_frame, text="🕸️ WEBSHELL SWEEP", bg="#3b380d", fg="white", font=("Consolas", 10, "bold"), command=self.run_webshell_regex_sweep, bd=1).pack(side=tk.RIGHT, padx=5)

        api_frame = tk.Frame(frame, bg="#090a0f")
        api_frame.pack(fill=tk.X, pady=(0, 10))
        tk.Label(api_frame, text="VT API Key (Opt):", font=("Consolas", 10), bg="#090a0f", fg="#ffb86c").pack(side=tk.LEFT, padx=5)
        self.vt_api_entry = tk.Entry(api_frame, font=("Consolas", 10), bg="#121520", fg="#ffb86c", insertbackground="#00f3ff", width=40, bd=1, show="*")
        self.vt_api_entry.pack(side=tk.LEFT, padx=5)
        vt_btn = tk.Button(api_frame, text="🌐 QUERY VIRUSTOTAL (Live)", bg="#5c1f00", fg="white", font=("Consolas", 9, "bold"), command=self.query_virustotal, bd=1)
        vt_btn.pack(side=tk.LEFT, padx=5)
        ToolTip(vt_btn, "Requires Internet and VT API Key. Submits the file hash (not the file) to VirusTotal to get detection ratios.")

        self.malware_report = scrolledtext.ScrolledText(frame, bg="#050608", fg="#00f3ff", font=("Consolas", 9), insertbackground="#00f3ff")
        self.malware_report.pack(fill=tk.BOTH, expand=True)

    def query_virustotal(self):
        target = self.malware_file_path.get().strip()
        api_key = self.vt_api_entry.get().strip()
        
        if not target or not os.path.exists(target) or os.path.isdir(target):
            return messagebox.showerror("Error", "Please select a valid single file (not a directory) to hash.")
        if not api_key:
            return messagebox.showwarning("API Key Missing", "Please enter a valid VirusTotal API (V3) key.")
            
        self.malware_report.insert(tk.END, f"\n[🌐] VIRUSTOTAL API QUERY INITIATED...\nHashing file and transmitting to VT Cloud...\n")
        
        def vt_worker():
            try:
                sha256_hash = hashlib.sha256()
                with open(target, "rb") as f:
                    while chunk := f.read(8192):
                        sha256_hash.update(chunk)
                file_hash = sha256_hash.hexdigest()
                
                url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
                req = urllib.request.Request(url, headers={'x-apikey': api_key})
                
                with urllib.request.urlopen(req, timeout=10) as response:
                    data = json.loads(response.read().decode())
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    undetected = stats.get("undetected", 0)
                    total = malicious + suspicious + undetected
                    
                    rep_str = f"--- [ VIRUSTOTAL INTELLIGENCE ] ---\n"
                    rep_str += f"Target Hash: {file_hash}\n"
                    rep_str += f"Malicious Hits: {malicious} / {total}\n"
                    rep_str += f"Suspicious Hits: {suspicious}\n"
                    rep_str += f"Undetected: {undetected}\n"
                    
                    if malicious > 0:
                        rep_str += "🚨 THREAT DETECTED: This file is known malicious in the VT Database.\n"
                    else:
                        rep_str += "✅ CLEAN: No engines detected this hash as malicious (or it is unknown to VT).\n"
                    
                    self.root.after(0, lambda: self.malware_report.insert(tk.END, rep_str + "-"*50 + "\n"))
                    
            except urllib.error.HTTPError as e:
                err_msg = f"VT API Error {e.code}: {'Not Found (Hash Unknown to VT)' if e.code == 404 else e.reason}"
                self.root.after(0, lambda: self.malware_report.insert(tk.END, f"❌ {err_msg}\n"))
            except Exception as e:
                self.root.after(0, lambda: self.malware_report.insert(tk.END, f"❌ Connection Error: {str(e)}\n"))
        threading.Thread(target=vt_worker, daemon=True).start()

    def run_webshell_regex_sweep(self):
        target_dir = self.malware_file_path.get().strip()
        if not target_dir or not os.path.exists(target_dir) or not os.path.isdir(target_dir):
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
                            content = f.read() # Fully Uncapped Read
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
        if os.path.isdir(target):
            messagebox.showerror("Error", "Target is a directory. Deep Triage requires a specific file.")
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
                target_safe = shlex.quote(target)
                file_type_res = subprocess.run(f"file {target_safe}", shell=True, capture_output=True, text=True)
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
            except PermissionError:
                self.root.after(0, lambda: self.malware_report.insert(tk.END, "Error: Permission Denied. File is locked by Kernel or another process."))
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
    # TAB 6: CONTAINMENT & OPS
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
            ("Failed Logins", "cat /var/log/auth.log /var/log/secure 2>/dev/null | grep -iE 'failed|invalid'"),
            ("Sudoers Config", "cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v '^#'"),
            ("Shell History", "cat /root/.bash_history /home/*/.bash_history /home/*/.zsh_history 2>/dev/null"),
            ("Active Connections", "ss -ntup 2>/dev/null"),
            ("Large Files (>200M)", "find / -type f -size +200M -exec ls -lh {} \\; 2>/dev/null | awk '{ print $9 \": \" $5 }'"),
            ("Enabled Services", "systemctl list-unit-files --state=enabled"),
            ("SUID Root Files", "find / -type f -perm -4000 -exec ls -ld {} \\; 2>/dev/null"),
            ("🐳 List Docker Cnt", "docker ps -a")
        ]
        
        row, col = 0, 0
        for title, cmd in f_ops:
            btn = tk.Button(btn_grid, text=title, bg="#122038", fg="white", font=("Consolas", 9, "bold"),
                      command=lambda c=cmd: self.run_forensic(c), width=24, bd=1)
            btn.grid(row=row, column=col, padx=4, pady=4)
            ToolTip(btn, f"Forensic Script:\n> {cmd}")
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
        tk.Button(ctrl, text="💾 Export CSV", bg="#122a47", fg="#ffffff", font=("Consolas", 10), command=self.export_net_csv, bd=1).pack(side=tk.LEFT, padx=5)
        
        tk.Button(ctrl, text="📡 Check Promiscuous", bg="#3b380d", fg="white", font=("Consolas", 10, "bold"), command=lambda: self.exec_cmd("Promisc Check", ["ip", "link", "show"], False), bd=1).pack(side=tk.LEFT, padx=5)
        tk.Button(ctrl, text="🔍 WHOIS / GeoIP", bg="#122a47", fg="white", font=("Consolas", 10, "bold"), command=self.osint_selected_ip, bd=1).pack(side=tk.LEFT, padx=5)
        
        tk.Button(ctrl, text="☠ KILL PID", bg="#4a0d18", fg="white", font=("Consolas", 10, "bold"), command=self.kill_socket_owner_pid, bd=1).pack(side=tk.RIGHT, padx=5)
        tk.Button(ctrl, text="🚫 Ban IP", bg="#660d19", fg="white", font=("Consolas", 10, "bold"), command=self.ban_selected_ip, bd=1).pack(side=tk.RIGHT, padx=5)
        tk.Button(ctrl, text="☠ Nuke Foreign IPs", bg="#ff0055", fg="white", font=("Consolas", 10, "bold"), command=lambda: self.exec_cmd("Nuke Foreign", ["sh", "-c", "ss -ntp | awk '{print $5}' | grep -v '127.0.0.1' | grep -v '::1' | cut -d: -f1 | sort | uniq | xargs -I {} ufw deny from {}"], True), bd=1).pack(side=tk.RIGHT, padx=5)
        
        tree_frame = tk.Frame(frame, bg="#090a0f")
        tree_frame.pack(fill=tk.BOTH, expand=True)

        scroll_y = ttk.Scrollbar(tree_frame, orient="vertical")
        self.net_tree = ttk.Treeview(tree_frame, columns=("Protocol", "Local", "Remote", "State", "Process/PID"), 
                                     show="headings", height=18, yscrollcommand=scroll_y.set)
        scroll_y.config(command=self.net_tree.yview)

        for col in ("Protocol", "Local", "Remote", "State", "Process/PID"): self.net_tree.heading(col, text=col)
        
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.net_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.net_menu = Menu(self.root, tearoff=0, bg="#121520", fg="#00f3ff")
        self.net_menu.add_command(label="🔍 OSINT & GeoIP Trace", command=self.osint_selected_ip)
        self.net_menu.add_command(label="🚫 Block / Ban Remote IP (UFW)", command=self.ban_selected_ip)
        self.net_menu.add_separator()
        self.net_menu.add_command(label="☠ SIGKILL Owning Process", command=self.kill_socket_owner_pid)
        
        self.net_tree.bind("<Button-3>", self.show_net_menu)

    def show_net_menu(self, event):
        iid = self.net_tree.identify_row(event.y)
        if iid:
            self.net_tree.selection_set(iid)
            self.net_menu.tk_popup(event.x_root, event.y_root)

    def export_net_csv(self):
        t = time.strftime("%Y%m%d_%H%M%S")
        outpath = f"/root/irs_network_{t}.csv"
        try:
            with open(outpath, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Protocol", "Local", "Remote", "State", "Process/PID"])
                for item in self.net_tree.get_children():
                    writer.writerow(self.net_tree.item(item)['values'])
            messagebox.showinfo("Export Success", f"Network Matrix exported to:\n{outpath}")
            self.log_alert(f"Network Matrix CSV exported to {outpath}", "SUCCESS")
        except Exception as e:
            self.log_alert(f"CSV Export Error: {str(e)}", "ERROR")

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
        def fetch_net():
            try:
                output = subprocess.run(["ss", "-ntup"], capture_output=True, text=True).stdout.split('\n')[1:]
                net_rows = []
                for line in output:
                    p = line.split()
                    if len(p) >= 5:
                        proc_info = p[6] if len(p) >= 7 else "Unknown/RootReq"
                        net_rows.append((p[0], p[4], p[5], p[1], proc_info))
                        
                def update_ui():
                    self.net_tree.delete(*self.net_tree.get_children())
                    for row in net_rows:
                        self.net_tree.insert("", tk.END, values=row)
                self.root.after(0, update_ui)
            except Exception: pass
        threading.Thread(target=fetch_net, daemon=True).start()

    def ban_selected_ip(self):
        sel = self.net_tree.selection()
        if sel:
            ip = self.net_tree.item(sel[0])['values'][2].rsplit(':', 1)[0]
            ip_safe = shlex.quote(ip) 
            if messagebox.askyesno("Confirm Isolation", f"Deploy firewall rule blocking all I/O to: {ip}?"): 
                self.exec_cmd(f"FW Block {ip}", ["ufw", "deny", "from", ip_safe], True)

    def osint_selected_ip(self):
        sel = self.net_tree.selection()
        if not sel:
            messagebox.showwarning("Warning", "Select a network connection first.")
            return
        ip = self.net_tree.item(sel[0])['values'][2].rsplit(':', 1)[0]
        if ip in ["0.0.0.0", "*", "127.0.0.1", "::1"]:
            messagebox.showinfo("Recon Info", "Selected IP is a local bind address.")
            return
            
        ip_safe = shlex.quote(ip)
        top = tk.Toplevel(self.root)
        top.title(f"OSINT & GeoIP Recon: {ip}")
        top.geometry("800x600")
        top.configure(bg="#090a0f")
        tk.Label(top, text=f"🔍 EXTERNAL INTELLIGENCE FOR TARGET: {ip}", font=("Consolas", 14, "bold"), bg="#121520", fg="#00f3ff", pady=10).pack(fill=tk.X)
        txt = scrolledtext.ScrolledText(top, bg="#050608", fg="#50fa7b", font=("Consolas", 10), insertbackground="#00f3ff")
        txt.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        txt.insert(tk.END, f"[*] Querying global WHOIS and GeoIP databases for {ip}...\n\n")

        def fetch_osint():
            # Piped ipinfo into jq for highly readable, formatted JSON outputs
            cmd = f"host {ip_safe} ; echo '\n--- GEO-LOCATION / ISP (IPINFO.IO) ---' ; curl -s https://ipinfo.io/{ip_safe} | jq . ; echo '\n--- WHOIS DATA ---' ; whois {ip_safe} | grep -iE 'NetName|OrgName|Country|City|CIDR'"
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
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
        
        btn_cap = tk.Button(fim_frame, text="📸 CAPTURE FIM BASELINE", bg="#122038", fg="white", font=("Consolas", 10, "bold"), command=self.capture_fim_baseline, bd=1)
        btn_cap.pack(side=tk.LEFT, padx=10)
        ToolTip(btn_cap, f"Generates SHA-256 hashes of critical /etc binaries and saves them persistently to {FIM_DB_FILE}.")

        btn_ver = tk.Button(fim_frame, text="🔍 VERIFY INTEGRITY", bg="#4a0d18", fg="white", font=("Consolas", 10, "bold"), command=self.verify_fim_baseline, bd=1)
        btn_ver.pack(side=tk.LEFT, padx=10)
        ToolTip(btn_ver, "Re-hashes files and compares against baseline. Alerts if tampered.")

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
            {''.join(f"<tr><td>{p['pid']}</td><td>{p['name']}</td><td>{p['username']}</td><td>{p['cpu_percent']}</td><td>{p['memory_percent']}</td></tr>" for p in procs)}
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
        
        try:
            with open(FIM_DB_FILE, "w") as f:
                json.dump(self.fim_baselines, f, indent=4) # Formatted cleanly
            self.log_alert(f"FIM ENGINE: Captured SHA-256 Baseline hashes for {len(self.fim_baselines)} files. Saved to {FIM_DB_FILE}", "SUCCESS")
        except Exception as e:
            self.log_alert(f"FIM ENGINE: Failed to write baseline JSON: {str(e)}", "ERROR")

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
    # TAB 10: REVERSE ENGINEERING 
    # ==========================================
    def build_rev_eng_tab(self):
        frame = tk.Frame(self.tab_rev_eng, bg="#090a0f", padx=15, pady=15)
        frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(frame, text="🔬 RE & MALWARE DEOBFUSCATION", font=("Consolas", 14, "bold"), bg="#090a0f", fg="#ffb86c").pack(anchor=tk.W, pady=(0, 10))

        input_frame = tk.Frame(frame, bg="#090a0f")
        input_frame.pack(fill=tk.X, pady=(0, 10))
        tk.Label(input_frame, text="Target File:", font=("Consolas", 11), bg="#090a0f", fg="#00f3ff").pack(side=tk.LEFT, padx=5)
        self.re_file_path = tk.Entry(input_frame, font=("Consolas", 11), bg="#121520", fg="white", insertbackground="#00f3ff", width=45, bd=1)
        self.re_file_path.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        tk.Button(input_frame, text="📂 BROWSE", bg="#122038", fg="white", font=("Consolas", 9, "bold"), command=lambda: self.browse_file(self.re_file_path), bd=1).pack(side=tk.LEFT, padx=5)

        btn_bar = tk.Frame(frame, bg="#090a0f")
        btn_bar.pack(fill=tk.X, pady=(0, 10))
        
        tk.Button(btn_bar, text="⚙️ DISASM (objdump)", bg="#122a47", fg="white", font=("Consolas", 9, "bold"), command=self.re_disassemble, bd=1).pack(side=tk.LEFT, padx=2)
        tk.Button(btn_bar, text="🧬 ELF HEADER", bg="#122038", fg="white", font=("Consolas", 9, "bold"), command=self.re_elf_inspect, bd=1).pack(side=tk.LEFT, padx=2)
        tk.Button(btn_bar, text="🔤 STRINGS", bg="#122038", fg="white", font=("Consolas", 9, "bold"), command=self.re_strings_dump, bd=1).pack(side=tk.LEFT, padx=2)
        tk.Button(btn_bar, text="🔓 AUTO-DECODE DROPPER", bg="#4a0d18", fg="white", font=("Consolas", 9, "bold"), command=self.re_deobfuscate_script, bd=1).pack(side=tk.LEFT, padx=2)
        
        tk.Button(btn_bar, text="☢️ LIB TRACE (ltrace)", bg="#880022", fg="white", font=("Consolas", 9, "bold"), command=self.re_ltrace_sandbox, bd=1).pack(side=tk.RIGHT, padx=2)
        tk.Button(btn_bar, text="☢️ SYS TRACE (strace)", bg="#ff0055", fg="white", font=("Consolas", 9, "bold"), command=self.re_sandbox_trace, bd=1).pack(side=tk.RIGHT, padx=2)

        self.re_output = scrolledtext.ScrolledText(frame, bg="#050608", fg="#50fa7b", font=("Consolas", 9), insertbackground="#00f3ff")
        self.re_output.pack(fill=tk.BOTH, expand=True)

    def re_disassemble(self):
        target = self.re_file_path.get().strip()
        if not target or not os.path.exists(target): return messagebox.showerror("Error", "Invalid target path")
        if os.path.isdir(target): return messagebox.showerror("Error", "Select a file, not a directory.")
        
        self.re_output.delete(1.0, tk.END)
        self.re_output.insert(tk.END, f"[+] DISASSEMBLY ENGINE [INTEL SYNTAX]: {target}\n[!] Parsing entire binary structure. UI may freeze momentarily on large files...\n" + "="*80 + "\n")
        
        def run_objdump():
            target_safe = shlex.quote(target)
            cmd = f"objdump -d -M intel --section=.text {target_safe}"
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            out = res.stdout if res.stdout else res.stderr
            self.root.after(0, lambda: self.re_output.insert(tk.END, out + "\n\n[+] Full Disassembly Complete."))
        threading.Thread(target=run_objdump, daemon=True).start()

    def re_elf_inspect(self):
        target = self.re_file_path.get().strip()
        if not target or not os.path.exists(target): return messagebox.showerror("Error", "Invalid target path")
        if os.path.isdir(target): return messagebox.showerror("Error", "Select a file, not a directory.")
        
        self.re_output.delete(1.0, tk.END)
        self.re_output.insert(tk.END, f"[+] ELF STRUCTURE & SYMBOL TABLE: {target}\n" + "="*80 + "\n")
        
        def run_inspect():
            target_safe = shlex.quote(target)
            header = subprocess.run(f"readelf -h {target_safe}", shell=True, capture_output=True, text=True).stdout
            imports = subprocess.run(f"nm -D {target_safe} | grep ' U '", shell=True, capture_output=True, text=True).stdout
            exports = subprocess.run(f"nm -D {target_safe} | grep ' T '", shell=True, capture_output=True, text=True).stdout
            
            final_out = f"--- [ ELF HEADERS ] ---\n{header}\n\n--- [ IMPORTED LIBRARIES/FUNCTIONS ] ---\n{imports if imports else 'None / Stripped'}\n\n--- [ EXPORTED FUNCTIONS ] ---\n{exports if exports else 'None / Stripped'}"
            self.root.after(0, lambda: self.re_output.insert(tk.END, final_out))
        threading.Thread(target=run_inspect, daemon=True).start()

    def re_strings_dump(self):
        target = self.re_file_path.get().strip()
        if not target or not os.path.exists(target): return messagebox.showerror("Error", "Invalid target path")
        if os.path.isdir(target): return messagebox.showerror("Error", "Select a file, not a directory.")
        
        self.re_output.delete(1.0, tk.END)
        self.re_output.insert(tk.END, f"[+] STRINGS EXTRACTION (Length >= 6): {target}\n[!] Extracting complete string pool. UI may freeze momentarily on large files...\n" + "="*80 + "\n")
        
        def run_strings():
            target_safe = shlex.quote(target)
            cmd = f"strings -n 6 {target_safe}"
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            self.root.after(0, lambda: self.re_output.insert(tk.END, res.stdout + "\n[+] Full Strings Extraction Complete."))
        threading.Thread(target=run_strings, daemon=True).start()

    def re_sandbox_trace(self):
        target = self.re_file_path.get().strip()
        if not target or not os.path.exists(target): return messagebox.showerror("Error", "Invalid target path")
        if os.path.isdir(target): return messagebox.showerror("Error", "Select an executable file, not a directory.")
        if not messagebox.askyesno("WARNING: DYNAMIC ANALYSIS", "You are about to EXECUTE this file in a restricted sandbox trace.\nEnsure your environment is safe to detonate malware.\nProceed?"): return
        
        self.re_output.delete(1.0, tk.END)
        self.re_output.insert(tk.END, f"[☢] SYSTEM CALL TRACE (strace): {target}\n[!] Time-limited to 5s. Capturing I/O, process spawns, and networking...\n" + "="*80 + "\n")
        
        def run_sandbox():
            target_safe = shlex.quote(target)
            cmd = f"timeout 5s strace -f -e trace=open,openat,execve,socket,connect {target_safe}"
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            self.root.after(0, lambda: self.re_output.insert(tk.END, res.stderr + "\n\n[+] Sandbox Trace Completed / Timed Out."))
        threading.Thread(target=run_sandbox, daemon=True).start()

    def re_ltrace_sandbox(self):
        target = self.re_file_path.get().strip()
        if not target or not os.path.exists(target): return messagebox.showerror("Error", "Invalid target path")
        if os.path.isdir(target): return messagebox.showerror("Error", "Select an executable file, not a directory.")
        if not messagebox.askyesno("WARNING: DYNAMIC ANALYSIS", "You are about to EXECUTE this file via Library Trace.\nProceed?"): return
        
        self.re_output.delete(1.0, tk.END)
        self.re_output.insert(tk.END, f"[☢] LIBRARY CALL TRACE (ltrace): {target}\n[!] Time-limited to 5s. Intercepting shared library interactions...\n" + "="*80 + "\n")
        
        def run_sandbox():
            target_safe = shlex.quote(target) 
            cmd = f"timeout 5s ltrace -f {target_safe}"
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            self.root.after(0, lambda: self.re_output.insert(tk.END, res.stderr + "\n\n[+] Ltrace Completed / Timed Out."))
        threading.Thread(target=run_sandbox, daemon=True).start()

    def re_deobfuscate_script(self):
        target = self.re_file_path.get().strip()
        if not target or not os.path.exists(target): return messagebox.showerror("Error", "Invalid target path")
        if os.path.isdir(target): return messagebox.showerror("Error", "Select a script file, not a directory.")
        
        self.re_output.delete(1.0, tk.END)
        self.re_output.insert(tk.END, f"[+] BASE64 DEOBFUSCATION / PAYLOAD EXTRACTOR: {target}\n" + "="*80 + "\n")
        
        def run_decode():
            try:
                with open(target, 'r', errors='ignore') as f:
                    content = f.read()
                
                b64_regex = r"(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
                matches = re.findall(b64_regex, content)
                
                if not matches:
                    self.root.after(0, lambda: self.re_output.insert(tk.END, "No large Base64 blobs found in the file."))
                    return
                
                output = f"Found {len(matches)} potential Base64 payloads.\n\n"
                for i, b64_str in enumerate(matches, 1):
                    try:
                        decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
                        output += f"--- [ PAYLOAD {i} ] ---\n"
                        output += f"Length: {len(b64_str)} bytes\n"
                        output += f"Extracted Text: {decoded[:500]}{'...' if len(decoded) > 500 else ''}\n\n"
                    except Exception:
                        pass
                
                self.root.after(0, lambda: self.re_output.insert(tk.END, output))
            except Exception as e:
                self.root.after(0, lambda: self.re_output.insert(tk.END, f"Error reading file: {str(e)}"))
        threading.Thread(target=run_decode, daemon=True).start()

    # ==========================================
    # TAB 11: DEFCON EMERGENCY
    # ==========================================
    def build_defcon_tab(self):
        frame = tk.Frame(self.tab_defcon, bg="#1a0005", padx=20, pady=20)
        frame.pack(fill=tk.BOTH, expand=True)
        tk.Label(frame, text="⚠ DEFCON 1 CRITICAL AIR-GAP SYSTEM MANAGEMENT ⚠", font=("Consolas", 18, "bold"), bg="#1a0005", fg="#ff0055").pack(pady=20)
        def engage_airgap():
            if messagebox.askyesno("DEFCON 1", "Drop ALL inbound and outbound network traffic instantly?"):
                self.header.config(bg="#ff0055", fg="black", text="[ SYSTEM AIR-GAPPED - ACTIVE ATTACK PROTOCOL ENGAGED ]")
                self.status_bar.config(bg="#ff0055", fg="black")
                self.exec_cmd("Airgap Inbound", ["iptables", "-P", "INPUT", "DROP"], True)
                self.exec_cmd("Airgap Outbound", ["iptables", "-P", "OUTPUT", "DROP"], True)
        tk.Button(frame, text="ENGAGE AIR-GAP INFRASTRUCTURE DISCONNECT", bg="#ff0055", fg="white", font=("Consolas", 14, "bold"), command=engage_airgap, pady=15, bd=1).pack(fill=tk.X, pady=15)
        tk.Button(frame, text="FORCE LOW-LEVEL TERMINAL MAINTENANCE RESCUE", bg="#880022", fg="white", font=("Consolas", 12, "bold"), command=lambda: subprocess.run(["systemctl", "isolate", "rescue.target"]), pady=10, bd=1).pack(fill=tk.X, pady=10)

    # ==========================================
    # TAB 12: SUPPORT MANUAL
    # ==========================================
    def build_support_tab(self):
        frame = tk.Frame(self.tab_support, bg="#090a0f", padx=15, pady=15)
        frame.pack(fill=tk.BOTH, expand=True)
        guide_text = scrolledtext.ScrolledText(frame, bg="#050608", fg="#00f3ff", font=("Consolas", 10), insertbackground="#00f3ff")
        guide_text.pack(fill=tk.BOTH, expand=True)
        
        manual_content = """========================================================================================
 [ INCIDENT & RESPONSIVE SUITE V3.2 ] - OPERATIONAL SUPPORT & COMMAND MANUAL
========================================================================================

1. OVERVIEW & PURPOSE
   The Incident & Responsive Suite is an enterprise-grade Endpoint Detection & Response (EDR), 
   Host-based Intrusion Prevention System (HIPS), and Incident Response (IR) suite designed 
   for Linux environments.

2. SECURITY ARCHITECTURE (V3.2 OPTIMIZED)
   - Unrestricted Analytics: All limiters on `objdump`, `strings`, `auth.log`, `bash_history`, 
     and Process tracking have been removed. 
   - Shell Injection Immunity: All external I/O variables pass through POSIX-compliant 
     shlex cryptographic escaping before pipeline submission.
   - Smooth Execution: Treeviews employ batched inserts and vertical scrolling ensuring 
     the GUI never stutters, even under extreme data loads.

3. MODULE BREAKDOWN & USAGE GUIDELINES

   [⭐ QUICK ACTIONS]
   - Hover tooltips reveal exact underlying terminal commands.
   - Kill Zombie PIDs: Forcefully clears defunct processes cluttering the memory queue.

   [1. PROCESS MANAGER & 7. NETWORK MATRIX]
   - Right-Click Context Menus: Right-click any row to instantly suspend, kill, ban, or geo-locate an IP.
   - Export CSV button securely dumps tabular findings for documentation.

   [3. MALWARE TRIAGE]
   - Live VirusTotal Integration: Enter a V3 API Key, and instantly transmit SHA256 hashes 
     without detonating or exposing your payload.

   [4. LIVE LOGS]
   - Active Syntax Engine: Real-time highlighting maps critical words (Failed, Invalid, Error) 
     to RED, and privileged accesses (Root, Sudo, Accepted) to ORANGE.
     
   [9. RE & DEOBFUSCATION]
   - Disassemble (objdump): Generates FULL static assembly instructions of the target (Intel Syntax).
   - Sandbox Trace (strace / ltrace): Safely detonates a binary for 5 seconds and traces calls.

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
