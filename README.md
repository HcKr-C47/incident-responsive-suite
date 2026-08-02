# [ INCIDENT & RESPONSIVE SUITE ] 🛡️

**A fully open-source, enterprise-grade Endpoint Detection & Response (EDR) and Incident Response (IR) SOC dashboard for Linux.** 

This suite is built to empower sysadmins, defenders, and everyday users to actively defend their machines, hunt down malware, and stay safe online—with zero telemetry, zero paywalls, and total transparency.

## 🚀 Key Features
- **Mega-Ops Dashboard:** An all-in-one scrolling Canvas for containment, kernel watchdog, system hardening, and hardware management.
- **Process Manager & PPID Killer:** Track live processes, dump memory maps (SO files), and kill parent processes to stop malware from respawning.
- **Deep Malware Triage & WebShell Sweep:** Generate SHA-256 hashes, calculate Shannon Entropy (packed malware detection), dump hex, and recursively scan web directories for WebShells (`eval(base64_decode)`).
- **Live Syntax-Highlighted Logs:** Real-time log tailing for Auth, Syslog, Kernel, and Web Server logs with visual alert tagging.
- **FIM & IR Report Generation:** Hash critical files (`/etc/passwd`, `/etc/shadow`) to detect tampering, and export full HTML incident response reports.
- **Network Matrix & OSINT:** View active socket connections, terminate socket owner PIDs, ban foreign IPs via UFW, and run instant WHOIS/DNS recon.

## ⚙️ Installation

**1. Clone the repository:**
```bash
git clone https://github.com/HcKr-C47/incident-responsive-suite.git
cd incident-responsive-suite
pip install -r requirements.txt
sudo python3 irs.py
