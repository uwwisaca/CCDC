#!/bin/bash
# DNF Version of 1-linux-triage - UWW CCDC Team
# Created with assistance of Claude.ai
set -e

INSTALL_LOG="/var/log/tools_installs.log"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root."
    exit 1
fi

# Log everything
touch "$INSTALL_LOG"
chmod 600 "$INSTALL_LOG"
exec > >(tee -a "$INSTALL_LOG") 2>&1

echo "========== Tool Installation Script Started: $(date) =========="

if ! dnf repolist | grep -q epel; then
    dnf install -y epel-release || true
fi

dnf update -y

dnf install -y \
    git \
    wget \
    curl \
    jq \
    python3 \
    python3-pip \
    python3-virtualenv \
    kernel-devel-$(uname -r) \
    kernel-headers-$(uname -r) \
    gcc \
    make \
    dkms

# =================
# 1 - LiME
# =================
echo "================ Installing LiME ================"
cd /opt
rm -rf LiME || true
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src
make
mkdir -p /usr/local/lib/lime
cp lime-*.ko /usr/local/lib/lime/ 2>/dev/null || echo "LiME module built but not copied"
echo "================ LiME successfully installed ================"

# =================
# 2 - Volatility 3
# =================
echo "================ Installing Volatility ================"
cd /opt
rm -rf volatility3 || true
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -e .
deactivate

cat > /usr/local/bin/vol3 << 'EOF'
#!/bin/bash
source /opt/volatility3/venv/bin/activate
python3 /opt/volatility3/vol.py "$@"
deactivate
EOF

chmod +x /usr/local/bin/vol3
echo "================ Volatility successfully installed ================"

# =================
# 3 - chkrootkit
# =================
echo "================ Installing chkrootkit ================"
dnf install -y chkrootkit || echo "chkrootkit may not be available on this distro"
echo "================ chkrootkit installation complete ================"

# =================
# 4 - rkhunter
# =================
echo "================ Installing rkhunter ================"
dnf install -y rkhunter || echo "rkhunter may not be available on this distro"

if command -v rkhunter >/dev/null 2>&1; then
    rkhunter --update || true
    rkhunter --propupd || true
fi

echo "================ rkhunter installed and updated ================"

# =================
# 5 - Velociraptor
# =================
echo "================ Installing Velociraptor ================"
cd /opt
VELO_VERSION=$(curl -s https://api.github.com/repos/Velocidex/velociraptor/releases/latest | jq -r '.tag_name')
wget "https://github.com/Velocidex/velociraptor/releases/download/${VELO_VERSION}/velociraptor-${VELO_VERSION}-linux-amd64" -O velociraptor
chmod +x velociraptor
mv velociraptor /usr/local/bin/
echo "================ Velociraptor installed ================"

echo "========== Tool Installation Script Completed: $(date) =========="
