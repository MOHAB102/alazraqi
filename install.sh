#!/bin/bash
echo "[*] Installing AL-AZRAQI dependencies & tools..."
sudo apt update && sudo apt install -y \
    aircrack-ng \
    tshark \
    iw \
    wireless-tools \
    macchanger \
    ethtool \
    python3-pip \
    python3-full \
    git \
    build-essential \
    libpcap-dev \
    crda \
    wpasupplicant

echo "[*] Installing Python requirements..."
sudo pip3 install rich blessed pyfiglet --break-system-packages

echo "[*] Installing AL-AZRAQI as system command..."
sudo cp alazraqi.py /usr/local/bin/alazraqi
sudo chmod +x /usr/local/bin/alazraqi

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                                                               ║"
echo "║   🛡️  AL-AZRAQI installed successfully!                      ║"
echo "║                                                               ║"
echo "║   Run with: sudo alazraqi                                     ║"
echo "║                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"