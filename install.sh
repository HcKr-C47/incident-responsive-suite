#!/bin/bash
# ==============================================================================
# [ INCIDENT & RESPONSIVE SUITE ] - Universal Environment Installer
# ==============================================================================

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "[-] ERROR: Please run this installer as root (sudo ./install.sh)"
  exit 1
fi

echo "[*] Detecting Linux Distribution and Package Manager..."

# DEBIAN / UBUNTU / KALI / MINT
if command -v apt-get >/dev/null; then
    echo "[+] Debian/Ubuntu (APT) detected."
    apt-get update
    apt-get install -y python3 python3-pip python3-tk python3-psutil psmisc rkhunter chkrootkit clamav ufw iptables alsa-utils lsof binutils whois dnsutils file docker.io

# ARCH LINUX / MANJARO / ENDEAVOUROS
elif command -v pacman >/dev/null; then
    echo "[+] Arch Linux (Pacman) detected."
    pacman -Sy --noconfirm python python-pip tk python-psutil psmisc rkhunter chkrootkit clamav ufw iptables alsa-utils lsof binutils whois bind file docker

# FEDORA / RHEL / CENTOS / ALMA LINUX
elif command -v dnf >/dev/null; then
    echo "[+] Fedora/RHEL (DNF) detected."
    dnf install -y python3 python3-pip python3-tkinter python3-psutil psmisc rkhunter chkrootkit clamav ufw iptables alsa-utils lsof binutils whois bind-utils file docker

# OPENSUSE
elif command -v zypper >/dev/null; then
    echo "[+] openSUSE (Zypper) detected."
    zypper install -y python3 python3-pip python3-tk python3-psutil psmisc rkhunter chkrootkit clamav ufw iptables alsa-utils lsof binutils whois bind-utils file docker

# ALPINE LINUX
elif command -v apk >/dev/null; then
    echo "[+] Alpine Linux (APK) detected."
    apk add python3 py3-pip py3-tkinter py3-psutil psmisc rkhunter chkrootkit clamav ufw iptables alsa-utils lsof binutils whois bind-tools file docker

else
    echo "[-] FATAL: Unsupported package manager. Please install dependencies manually."
    exit 1
fi

echo "[*] Ensuring Python psutil fallback is available..."
# Failsafe fallback to pip if the native psutil package wasn't enough
pip3 install psutil --break-system-packages 2>/dev/null || pip install psutil 2>/dev/null

echo "=============================================================================="
echo "[+] INSTALLATION COMPLETE!"
echo "[+] You can now launch the suite by running: sudo python3 irs.py"
echo "=============================================================================="
