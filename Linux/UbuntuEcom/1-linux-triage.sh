#!/bin/bash
# Claude.ai used to create this script, edited by UWW CCDC Team

set -e

# Establish log file for installs
INSTALL_LOG = "/var/log/tools_installs.log"
if [[ $EUID -ne 0 ]]; then
    echo -e "This script must be run as root."
    exit 1
fi

# 1 - LiME
echo -e "================ Installing LiME ================"
cd /opt
if [ -d "LiME" ]; then
    rm -rf LiME
fi
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src
make
mkdir -p /usr/local/lib/lime
cp lime-*.ko /usr/local/lib/lime/ 2>/dev/null || echo "LiME module built but not copied (normal if module name varies)"
echo -e "================ LiME successfully installed ================"

# ================
# 2. Volatility 3 - Memory Analysis
# ================
echo -e "================ Installing Volatility ================"
cd /opt
if [ -d "volatility3" ]; then
    rm -rf volatility3
fi
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 -m venv venv
source venv/bin/activate
pip install -e .
deactivate

# Create wrapper script
cat > /usr/local/bin/vol3 << 'EOF'
#!/bin/bash
source /opt/volatility3/venv/bin/activate
python /opt/volatility3/vol.py "$@"
deactivate
EOF
chmod +x /usr/local/bin/vol3
echo -e "================ Volatility successfully installed ================"

# ================
# 3. chkrootkit - Rootkit Detector
# ================
echo -e "Installing chkrootkit"
apt install -y chkrootkit
echo -e "================ chkrootkit successfully installed ================"

# ================
# 4. rkhunter - Rootkit Hunter
# ================
echo -e "================ Installing rkhunter ================"
apt install -y rkhunter
# Update rkhunter database
rkhunter --update
rkhunter --propupd
echo -e "================ rkhunter installed and database updated ================"

# Go back to this later
# ================
# 5. osquery - System Query Tool
# ================
#echo -e "================ Installing osquery ================"
# Add osquery repository
#export OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
#apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys $OSQUERY_KEY
#add-apt-repository 'deb [arch=amd64] https://pkg.osquery.io/deb deb main'
#apt update
#apt install -y osquery
#systemctl enable osqueryd
#systemctl start osqueryd
#echo -e "================ osquery installed and service started ================"

# ================
# 6. AVML - Azure Memory Collector
# ================
#echo -e "${YELLOW}[8/8] Installing AVML (Azure VM Memory Collector)...${NC}"
#cd /opt
#AVML_VERSION=$(curl -s https://api.github.com/repos/microsoft/avml/releases/latest | jq -r '.tag_name')
#wget "https://github.com/microsoft/avml/releases/download/${AVML_VERSION}/avml" -O avml
#chmod +x avml
#mv avml /usr/local/bin/
#echo -e "${GREEN}✓ AVML installed${NC}"

# ================
# 7. Velociraptor - EDR/Forensics
# ================
echo -e "================ Installing Velociraptor ================"
cd /opt
VELO_VERSION=$(curl -s https://api.github.com/repos/Velocidex/velociraptor/releases/latest | jq -r '.tag_name')
wget "https://github.com/Velocidex/velociraptor/releases/download/${VELO_VERSION}/velociraptor-${VELO_VERSION}-linux-amd64" -O velociraptor
chmod +x velociraptor
mv velociraptor /usr/local/bin/
echo -e "================ Velociraptor installed ================"