#!/bin/bash
# OpenVAS/GVM (Greenbone Vulnerability Management) Installation
# For Oracle Linux 9.2 / RHEL-based systems
# Splunk Server (172.20.242.20) or Ubuntu Ecom (172.20.242.30)
# Version: 1.0
# Date: January 30, 2026

set -e

LOG_DIR="/var/log/openvas-install"
LOG_FILE="$LOG_DIR/install-$(date +%Y%m%d-%H%M%S).log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

mkdir -p "$LOG_DIR"

log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
    
    case $level in
        ERROR) echo -e "${RED}[$timestamp] [$level] $message${NC}" >&2 ;;
        SUCCESS) echo -e "${GREEN}[$timestamp] [$level] $message${NC}" ;;
        WARN) echo -e "${YELLOW}[$timestamp] [$level] $message${NC}" ;;
        INFO) echo -e "${CYAN}[$timestamp] [$level] $message${NC}" ;;
    esac
}

log INFO "========================================"
log INFO "OpenVAS/GVM Installation for CCDC"
log INFO "========================================"

if [ "$EUID" -ne 0 ]; then
    log ERROR "Please run as root or with sudo"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    log ERROR "Cannot detect OS"
    exit 1
fi

log INFO "Detected OS: $OS $VER"

# Get server IP
SERVER_IP=$(hostname -I | awk '{print $1}')
log INFO "Server IP: $SERVER_IP"

# Install based on OS
if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    log INFO "Installing GVM on Ubuntu/Debian..."
    
    # Update system
    apt-get update
    apt-get install -y software-properties-common
    
    # Install GVM
    log INFO "Adding GVM PPA..."
    add-apt-repository -y ppa:mrazavi/gvm
    apt-get update
    
    log INFO "Installing GVM packages (this may take 10-15 minutes)..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y gvm \
        postgresql postgresql-contrib \
        redis-server redis-tools \
        nmap sqlite3 \
        openvas-scanner \
        gvmd gsad ospd-openvas \
        python3-gvm gvm-tools
    
    GVM_USER="admin"
    
elif [ "$OS" = "ol" ] || [ "$OS" = "rhel" ] || [ "$OS" = "fedora" ]; then
    log INFO "Installing GVM on RHEL/Oracle Linux..."
    
    # Enable EPEL and PowerTools
    dnf install -y epel-release
    crb enable || dnf config-manager --set-enabled powertools || true
    
    # Install dependencies
    log INFO "Installing dependencies..."
    dnf install -y gcc cmake pkg-config \
        glib2-devel libgcrypt-devel gnutls-devel \
        libpcap-devel libssh-devel postgresql-devel \
        hiredis-devel redis python3-devel \
        libxml2-devel libxslt-devel xmltoman \
        git wget curl rsync nmap sqlite \
        bison flex postgresql-server postgresql-contrib \
        python3-pip python3-setuptools python3-packaging \
        python3-wrapt python3-cffi python3-psutil \
        libksba-devel gpgme-devel graphviz \
        nodejs npm
    
    # Install from source (more complex for RHEL)
    log WARN "GVM installation on RHEL/Oracle Linux requires building from source"
    log INFO "This will take 30-60 minutes. Consider using Ubuntu for faster deployment."
    
    # Initialize PostgreSQL
    if [ ! -d /var/lib/pgsql/data/base ]; then
        postgresql-setup --initdb
        systemctl enable postgresql
        systemctl start postgresql
    fi
    
    # Create GVM user
    GVM_USER="gvm"
    if ! id -u $GVM_USER >/dev/null 2>&1; then
        useradd -r -s /bin/bash -c "GVM User" -d /opt/gvm $GVM_USER
    fi
    
    log INFO "Building GVM from source..."
    export GVM_VERSION=22.4
    export GVM_LIBS_VERSION=22.7.3
    export GVMD_VERSION=23.0.1
    export GSA_VERSION=22.6.1
    export OPENVAS_SMB_VERSION=22.5.3
    export OPENVAS_SCANNER_VERSION=22.7.9
    export OSPD_OPENVAS_VERSION=22.6.2
    export GVM_HOME=/opt/gvm
    
    mkdir -p $GVM_HOME/src
    cd $GVM_HOME/src
    
    # Build gvm-libs
    log INFO "Building gvm-libs..."
    git clone --depth 1 --branch v$GVM_LIBS_VERSION https://github.com/greenbone/gvm-libs.git
    cd gvm-libs
    mkdir build && cd build
    cmake .. -DCMAKE_INSTALL_PREFIX=$GVM_HOME
    make -j$(nproc)
    make install
    cd $GVM_HOME/src
    
    # Build openvas-scanner
    log INFO "Building openvas-scanner..."
    git clone --depth 1 --branch v$OPENVAS_SCANNER_VERSION https://github.com/greenbone/openvas-scanner.git
    cd openvas-scanner
    mkdir build && cd build
    cmake .. -DCMAKE_INSTALL_PREFIX=$GVM_HOME
    make -j$(nproc)
    make install
    cd $GVM_HOME/src
    
    # Build gvmd
    log INFO "Building gvmd..."
    git clone --depth 1 --branch v$GVMD_VERSION https://github.com/greenbone/gvmd.git
    cd gvmd
    mkdir build && cd build
    cmake .. -DCMAKE_INSTALL_PREFIX=$GVM_HOME
    make -j$(nproc)
    make install
    cd $GVM_HOME/src
    
    # Build GSA
    log INFO "Building GSA (web interface)..."
    git clone --depth 1 --branch v$GSA_VERSION https://github.com/greenbone/gsa.git
    cd gsa
    cd gsa
    npm install
    npm run build
    mkdir -p $GVM_HOME/share/gvm/gsad/web/
    cp -r build/* $GVM_HOME/share/gvm/gsad/web/
    
    log SUCCESS "GVM built from source"
    
else
    log ERROR "Unsupported OS: $OS"
    exit 1
fi

# Start Redis (required for OpenVAS)
log INFO "Configuring Redis..."
if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    systemctl enable redis-server
    systemctl start redis-server
else
    systemctl enable redis
    systemctl start redis
fi

# Configure Redis for OpenVAS
if ! grep -q "unixsocket /run/redis/redis.sock" /etc/redis/redis.conf 2>/dev/null; then
    cat >> /etc/redis/redis.conf << 'REDIS_CONFIG'
unixsocket /run/redis/redis.sock
unixsocketperm 770
REDIS_CONFIG
    systemctl restart redis-server 2>/dev/null || systemctl restart redis
fi

# Add openvas user to redis group
if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    usermod -aG redis _gvm 2>/dev/null || usermod -aG redis gvm 2>/dev/null || true
fi

# Configure PostgreSQL
log INFO "Configuring PostgreSQL..."
systemctl enable postgresql
systemctl start postgresql

# Create GVM database and user
sudo -u postgres psql -c "CREATE USER gvm WITH PASSWORD 'gvm';" 2>/dev/null || true
sudo -u postgres psql -c "CREATE DATABASE gvmd OWNER gvm;" 2>/dev/null || true
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE gvmd TO gvm;" 2>/dev/null || true

# Configure PostgreSQL authentication
if ! grep -q "host.*gvmd.*gvm.*md5" /var/lib/pgsql/data/pg_hba.conf 2>/dev/null; then
    echo "host    gvmd            gvm             127.0.0.1/32            md5" >> /var/lib/pgsql/data/pg_hba.conf 2>/dev/null || true
    systemctl restart postgresql
fi

# Update NVT (Network Vulnerability Tests) feed
log INFO "Updating NVT feed (this takes 15-30 minutes on first run)..."
if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    runuser -u _gvm -- greenbone-nvt-sync || greenbone-nvt-sync
    log INFO "Updating SCAP, CERT, and GVMD data feeds..."
    runuser -u _gvm -- greenbone-feed-sync --type SCAP || true
    runuser -u _gvm -- greenbone-feed-sync --type CERT || true
    runuser -u _gvm -- greenbone-feed-sync --type GVMD_DATA || true
else
    $GVM_HOME/bin/greenbone-nvt-sync || true
    $GVM_HOME/sbin/greenbone-feed-sync --type SCAP || true
    $GVM_HOME/sbin/greenbone-feed-sync --type CERT || true
    $GVM_HOME/sbin/greenbone-feed-sync --type GVMD_DATA || true
fi

log SUCCESS "Feed synchronization started (runs in background)"

# Create admin user
log INFO "Creating admin user..."
ADMIN_PASSWORD=$(openssl rand -base64 16)

if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    runuser -u _gvm -- gvmd --create-user=admin --password="$ADMIN_PASSWORD" 2>/dev/null || true
    ADMIN_UUID=$(runuser -u _gvm -- gvmd --get-users --verbose | grep admin | awk '{print $2}')
    if [ ! -z "$ADMIN_UUID" ]; then
        runuser -u _gvm -- gvmd --modify-setting 78eceaec-3385-11ea-b237-28d24461215b --value "$ADMIN_UUID"
    fi
else
    sudo -u $GVM_USER $GVM_HOME/sbin/gvmd --create-user=admin --password="$ADMIN_PASSWORD" 2>/dev/null || true
fi

# Save password
echo "$ADMIN_PASSWORD" > /root/gvm-admin-password.txt
chmod 600 /root/gvm-admin-password.txt

log SUCCESS "Admin user created - Password saved to /root/gvm-admin-password.txt"

# Start GVM services
log INFO "Starting GVM services..."

if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    systemctl enable ospd-openvas
    systemctl start ospd-openvas
    systemctl enable gvmd
    systemctl start gvmd
    systemctl enable gsad
    systemctl start gsad
    
    # Wait for services
    sleep 10
    
    if systemctl is-active --quiet gvmd && systemctl is-active --quiet gsad; then
        log SUCCESS "GVM services are running"
    else
        log WARN "Some services may not be running properly"
    fi
else
    # Create systemd services for RHEL
    cat > /etc/systemd/system/gvmd.service << GVMD_SERVICE
[Unit]
Description=Greenbone Vulnerability Manager daemon (gvmd)
After=network.target postgresql.service

[Service]
Type=forking
User=$GVM_USER
Group=$GVM_USER
PIDFile=/run/gvmd/gvmd.pid
RuntimeDirectory=gvmd
RuntimeDirectoryMode=2775
ExecStart=$GVM_HOME/sbin/gvmd --osp-vt-update=/run/ospd/ospd-openvas.sock --listen-group=gvm
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
GVMD_SERVICE

    cat > /etc/systemd/system/gsad.service << GSAD_SERVICE
[Unit]
Description=Greenbone Security Assistant daemon (gsad)
After=network.target gvmd.service

[Service]
Type=forking
User=$GVM_USER
Group=$GVM_USER
RuntimeDirectory=gsad
RuntimeDirectoryMode=2775
PIDFile=/run/gsad/gsad.pid
ExecStart=$GVM_HOME/sbin/gsad --listen=0.0.0.0 --port=9392 --mlisten=127.0.0.1 --mport=9390
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
GSAD_SERVICE

    systemctl daemon-reload
    systemctl enable gvmd gsad
    systemctl start gvmd gsad
fi

# Configure firewall
log INFO "Configuring firewall..."
if command -v ufw &> /dev/null; then
    ufw allow 9392/tcp  # GSA web interface
    ufw allow 9390/tcp  # GVM Manager
elif command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-port=9392/tcp
    firewall-cmd --permanent --add-port=9390/tcp
    firewall-cmd --reload
fi

# Create CCDC scan targets configuration
log INFO "Creating CCDC network scan targets..."

cat > /root/gvm-ccdc-targets.txt << 'TARGETS'
# CCDC 2026 Network Targets for OpenVAS/GVM

# Network Segments
172.20.240.0/24  # Windows network
172.20.242.0/24  # Linux network
172.16.101.0/24  # VyOS router network

# Individual Hosts - Windows
172.20.240.100  # Windows 11 Workstation
172.20.240.101  # Server 2019 Web
172.20.240.102  # Server 2019 AD/DNS
172.20.240.104  # Server 2022 FTP

# Individual Hosts - Linux
172.20.242.20   # Splunk Oracle Linux
172.20.242.30   # Ubuntu Ecom Server
172.20.242.40   # Mailserver Fedora (estimated)
172.20.242.50   # Ubuntu Desktop (estimated)

# Network Devices
172.20.240.200  # Cisco FTD
172.20.242.150  # Palo Alto
172.16.101.1    # VyOS Router
TARGETS

# Create scan automation script
cat > /usr/local/bin/gvm-scan-ccdc.sh << 'SCAN_SCRIPT'
#!/bin/bash
# Automated CCDC Network Scan
# Scans all CCDC targets and generates reports

GVM_USER="admin"
GVM_PASSWORD=$(cat /root/gvm-admin-password.txt)

# Function to create target and scan
create_scan() {
    local target_name=$1
    local target_ip=$2
    
    echo "Creating scan for $target_name ($target_ip)..."
    
    # Create target
    gvm-cli --gmp-username "$GVM_USER" --gmp-password "$GVM_PASSWORD" socket --xml \
        "<create_target><name>$target_name</name><hosts>$target_ip</hosts></create_target>"
    
    # Create and start scan task
    gvm-cli --gmp-username "$GVM_USER" --gmp-password "$GVM_PASSWORD" socket --xml \
        "<create_task><name>CCDC Scan - $target_name</name><target id=\"\">$target_name</target><config id=\"daba56c8-73ec-11df-a475-002264764cea\"/></create_task>"
}

# Scan Windows network
create_scan "Windows Network" "172.20.240.0/24"
create_scan "Linux Network" "172.20.242.0/24"
create_scan "Router Network" "172.16.101.0/24"

echo "Scans created. Access web interface to start scans and view results."
SCAN_SCRIPT

chmod +x /usr/local/bin/gvm-scan-ccdc.sh

# Create feed update cron job
log INFO "Setting up automatic feed updates..."
cat > /etc/cron.daily/gvm-feed-update << 'FEED_UPDATE'
#!/bin/bash
# Daily GVM feed update

if [ -f /usr/sbin/greenbone-feed-sync ]; then
    /usr/sbin/greenbone-feed-sync --type all
else
    /opt/gvm/sbin/greenbone-feed-sync --type all 2>/dev/null || true
fi
FEED_UPDATE

chmod +x /etc/cron.daily/gvm-feed-update

# Create monitoring script
cat > /usr/local/bin/gvm-status.sh << 'STATUS_SCRIPT'
#!/bin/bash
# GVM Status Check

echo "=== GVM Services Status ==="
if systemctl list-units --type=service | grep -q gvmd; then
    systemctl status gvmd --no-pager | head -n 5
    systemctl status gsad --no-pager | head -n 5
    systemctl status ospd-openvas --no-pager | head -n 5 2>/dev/null || true
fi

echo ""
echo "=== Feed Status ==="
if [ -f /usr/sbin/greenbone-nvt-sync ]; then
    greenbone-nvt-sync --describe 2>/dev/null | head -n 5 || echo "Feed sync in progress or not yet run"
fi

echo ""
echo "=== NVT Count ==="
psql -U gvm -d gvmd -c "SELECT count(*) FROM nvts;" 2>/dev/null || echo "Database not accessible"

echo ""
echo "=== Active Scans ==="
gvm-cli socket --gmp-username admin --gmp-password "$(cat /root/gvm-admin-password.txt 2>/dev/null)" --xml "<get_tasks/>" 2>/dev/null | grep -o "<name>[^<]*</name>" | head -n 10 || echo "No active scans or CLI not configured"
STATUS_SCRIPT

chmod +x /usr/local/bin/gvm-status.sh

# Wait for initial setup to complete
log INFO "Waiting for initial setup to complete..."
sleep 5

log INFO ""
log INFO "========================================"
log INFO "OpenVAS/GVM Installation Complete"
log INFO "========================================"
log SUCCESS "Installation log: $LOG_FILE"
log INFO ""
log INFO "Access Information:"
log INFO "  Web Interface: https://$SERVER_IP:9392"
log INFO "  Username: admin"
log INFO "  Password: $ADMIN_PASSWORD"
log INFO "  (Password saved to: /root/gvm-admin-password.txt)"
log INFO ""
log INFO "CCDC Network Targets:"
log INFO "  Configuration: /root/gvm-ccdc-targets.txt"
log INFO "  Scan Script: /usr/local/bin/gvm-scan-ccdc.sh"
log INFO ""
log INFO "Management Commands:"
log INFO "  Status: /usr/local/bin/gvm-status.sh"
log INFO "  Update Feeds: greenbone-feed-sync --type all"
log INFO "  Restart Services: systemctl restart gvmd gsad"
log INFO ""
log WARN "Important Notes:"
log WARN "1. Feed sync takes 30-60 minutes on first run"
log WARN "2. Web interface may be slow until feeds complete"
log WARN "3. Check feed status: greenbone-nvt-sync --describe"
log WARN "4. NVT count should be >90,000 when complete"
log WARN ""
log INFO "First Scan Workflow:"
log INFO "1. Log in to web interface: https://$SERVER_IP:9392"
log INFO "2. Configuration → Targets → New Target"
log INFO "3. Add CCDC networks (172.20.240.0/24, 172.20.242.0/24)"
log INFO "4. Scans → Tasks → New Task"
log INFO "5. Select target and Full and Fast scan config"
log INFO "6. Start scan and monitor results"
log INFO ""
log SUCCESS "OpenVAS/GVM is ready to scan your CCDC environment!"
