# [ INCIDENT & RESPONSIVE SUITE ] 🛡️

**A fully open-source, enterprise-grade Endpoint Detection & Response (EDR) and Incident Response (IR) SOC dashboard for Linux.** 

---

## 🚀 Elite Key Features

This suite is built to empower sysadmins, defenders, and everyday users to actively defend their machines, hunt down malware, and stay safe online—with zero telemetry, zero paywalls, and total transparency.
### 🧠 Advanced Process Manager & System Truth
- **Parent Process Killer (PPID):** Advanced malware relies on child-forking. Sever the parent process to stop payloads from respawning.
- **Process Memory Map Dumping:** Hunt for fileless malware and injected rootkits by dumping a process's loaded shared objects (`.so`) and memory regions (`rwxp`).
- **Open File Inspection:** View every file, socket, and pipe a specific process has open via internal `lsof` tracking.
- **Signal Dispatcher:** Send raw kernel signals instantly: `SIGKILL (-9)`, `SIGTERM (-15)`, `SIGSTOP` (Freeze Process), and `SIGCONT` (Resume).
- **Zombie Process Sweeper:** Forcefully clear defunct, memory-clogging zombie processes (`ps -A -ostat,pid | awk '/[zZ]/'`).

### 🌐 Live Socket Matrix & Packet Sniffer
- **Live Network Matrix:** View all active inbound/outbound network connections via `ss -ntup`.
- **Socket Owner Termination:** Select a malicious network connection and instantly **Kill the Socket Owner PID** without leaving the networking tab.
- **Nuke Foreign IPs:** Instantly parse all non-local IPs in your active socket list and drop them via firewall rules.
- **Promiscuous Sniffer Detection:** Detect if an attacker has secretly placed your network card into Promiscuous Mode to sniff local traffic.
- **Raw AF_PACKET Sniffer:** Live-capture network frames in real-time, flag Metasploit/C2 ports (4444, 1337, etc.), and export `.txt` PCAP buffers for offline analysis.
- **Instant OSINT Recon:** Right-click query any IP for complete WHOIS, ASN, and DNS routing data.

### 🦠 Deep Malware Triage & WebShell Sweeper
- **Cryptographic Profiling:** Instantly calculates MD5, SHA-1, and SHA-256 hashes for seamless VirusTotal lookups.
- **Shannon Entropy Analysis:** Detects packed, obfuscated, or encrypted ransomware payloads via mathematical byte distribution scoring (>7.2 warning triggers).
- **Automated IOC Extraction:** Parses binaries for hardcoded IPv4 addresses, URLs, and highly suspicious system calls (`memfd_create`, `ptrace`, `execve`).
- **Hexadecimal Dumping:** Inspect the first 256 bytes of a binary directly in the GUI to verify file magic headers manually.
- **WebShell Regex Engine:** Recursively scans web directories (e.g., `/var/www/`) to hunt down hidden PHP webshells (`eval(base64_decode)`), Python reverse shells, and memory droppers.

### 🔴 Syntax-Highlighted Live Logs
- Real-time `tail -f` visualizer for `auth.log`, `syslog`, `kern.log`, and `nginx/apache` access logs. 
- **Attack Tagging:** Failed logins, errors, and invalid certificates highlight in **Red**. Privileged `sudo`, `root`, or accepted sessions highlight in **Orange**.

### 💼 Containment & Mega-Ops Dashboard
A unified, scrollable tactical dashboard containing over 45+ one-click forensic actions:
- **Docker Containment:** Instantly list, pause, or violently nuke all running Docker containers to stop lateral movement.
- **Account Lockdown:** Lock/Unlock standard users, sever all non-root users from the machine instantly, and kill rogue SSH daemons.
- **Immutable Lockdowns:** Lock critical directories like `/etc` and `/var/www` using `chattr +i` to prevent ransomware encryption.

### 🎯 Threat Hunting & Rootkit Detection
- **Crypto-Miner Sweeper:** Hunts specifically for XMRig, Minerd, Stratum, and other CPU-hogging malware configurations.
- **Memory Backdoor Hunting:** Scans the entire `/proc` filesystem for executable memory regions (`rwxp`) which signify fileless injected rootkits.
- **Hidden File Sweeper:** Uncovers hidden payload droppers (`.*`) lurking in volatile directories like `/tmp`, `/var/tmp`, and `/dev/shm`.
- **Privilege Escalation Scans:** Locate World-Writable files and rogue SUID root binaries natively.
- **Engine Integrations:** Launch integrated sweeps using ClamAV, RKHunter, and Chkrootkit directly from the dashboard.

### 🛡️ System Hardening & Kernel Watchdog
- **Anti-DDoS & Networking:** Enable TCP SYN Cookies, random TCP MAC generation (`rfc1337`), drop ICMP (Pings), and fully disable the IPv6 stack.
- **Kernel Watchdog:** Dump `dmesg`, verify active kernel subsystems, scan the ring buffer for kernel taints, and audit IOMMU hardware status.
- **eBPF Hardening:** Lock down Berkeley Packet Filter JIT compilers (`bpf_jit_harden=2`) to stop modern kernel exploits.
- **SSH Hardening:** Audit current SSH configs and forcefully disable remote root logins.

### 🖥️ Hardware Warden
- **Air-Gap Hardware:** Instantly unload webcam modules (`uvcvideo`), mute all ALSA microphones, and block RF signals (Bluetooth & WiFi via `rfkill`).
- **Physical Port Lockdown:** Disable USB Storage drivers (`usb-storage`) to prevent physical data exfiltration or bad-USB attacks.

### 📄 Config Vault, FIM & IR Reporting
- **File Integrity Monitoring (FIM):** Take a cryptographic SHA-256 baseline of `/etc/passwd`, `shadow`, `bash`, and `sudoers`. Re-verify at any time to instantly detect backdoor tampering.
- **Automated HTML IR Reports:** Instantly export an HTML Incident Response report containing system telemetry, high-CPU processes, and the active network socket matrix.
- **System Snapshots:** Force Read-Only BTRFS root snapshots and compress `/etc` tarball backups.

### ⚠ DEFCON Emergency Control
- **Nuclear Air-Gap:** Drops all inbound and outbound network traffic at the kernel firewall level (`iptables -P INPUT/OUTPUT DROP`).
- **Terminal Rescue Mode:** Drops the system into a low-level terminal maintenance shell (`rescue.target`) for extreme recovery.
## ⚙️ Installation

**1. Clone the repository:**
```bash
git clone https://github.com/HcKr-C47/incident-responsive-suite.git
cd incident-responsive-suite
pip install -r requirements.txt
sudo python3 irs.py
