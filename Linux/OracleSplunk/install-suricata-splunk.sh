#!/bin/bash
# Suricata IDS Installation for Splunk Oracle Linux Server
# Oracle Linux 9.2 with Splunk 10.0.2 (172.20.242.20)
# Forwards alerts to Splunk for analysis
# Version: 1.0
# Date: January 30, 2026

set -e

LOG_DIR="/var/log/suricata-install"
LOG_FILE="$LOG_DIR/install-$(date +%Y%m%d-%H%M%S).log"
SPLUNK_HOME="/opt/splunk"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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
    esac
}

log INFO "========================================"
log INFO "Suricata IDS Installation for Splunk"
log INFO "Host: Oracle Linux 9.2 Splunk Server (172.20.242.20)"
log INFO "========================================"

if [ "$EUID" -ne 0 ]; then
    log ERROR "Please run as root or with sudo"
    exit 1
fi

# Install EPEL repository
log INFO "Installing EPEL repository..."
dnf install -y epel-release
dnf install -y dnf-plugins-core

# Enable CodeReady Builder
log INFO "Enabling CodeReady Linux Builder..."
crb enable

# Install dependencies
log INFO "Installing dependencies..."
dnf install -y gcc libpcap-devel pcre-devel libyaml-devel file-devel \
    zlib-devel jansson-devel nss-devel libcap-ng-devel libnet-devel \
    tar make libnetfilter_queue-devel lua-devel python3-yaml python3-pip \
    lz4-devel rustc cargo jq

# Install Suricata from source (latest version)
log INFO "Installing Suricata from source..."
cd /tmp
SURICATA_VERSION="7.0.2"
wget https://www.openinfosecfoundation.org/download/suricata-${SURICATA_VERSION}.tar.gz
tar xzf suricata-${SURICATA_VERSION}.tar.gz
cd suricata-${SURICATA_VERSION}

./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
    --enable-nfqueue --enable-lua --enable-geoip

make -j$(nproc)
make install
make install-conf

# Create suricata user
if ! id -u suricata >/dev/null 2>&1; then
    useradd -r -s /sbin/nologin suricata
    log SUCCESS "Created suricata user"
fi

# Install suricata-update
log INFO "Installing suricata-update..."
pip3 install --upgrade suricata-update pyyaml

# Detect network interface
PRIMARY_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
if [ -z "$PRIMARY_IFACE" ]; then
    PRIMARY_IFACE="eth0"
    log WARN "Could not detect interface, using: $PRIMARY_IFACE"
else
    log SUCCESS "Primary interface detected: $PRIMARY_IFACE"
fi

# Backup original configuration
cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.backup

# Create Suricata configuration optimized for Splunk integration
log INFO "Configuring Suricata for Splunk integration..."

cat > /etc/suricata/suricata.yaml << SURICATA_CONFIG
%YAML 1.1
---
# Suricata Configuration for CCDC 2026 - Splunk Integration
# Oracle Linux Server: 172.20.242.20
# Forwards all alerts to Splunk

vars:
  address-groups:
    HOME_NET: "[172.20.242.0/24,172.20.240.0/24,172.16.101.0/24]"
    EXTERNAL_NET: "!\\$HOME_NET"
    HTTP_SERVERS: "[172.20.242.30,172.20.240.101]"
    SMTP_SERVERS: "[172.20.242.30]"
    SQL_SERVERS: "[172.20.242.30]"
    DNS_SERVERS: "[172.20.240.102]"
    SPLUNK_SERVERS: "[172.20.242.20]"
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    SSH_PORTS: 22
    FTP_PORTS: 21

af-packet:
  - interface: $PRIMARY_IFACE
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

# Splunk-optimized logging
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert:
            payload: yes
            payload-buffer-size: 4kb
            payload-printable: yes
            packet: yes
            metadata: yes
            http-body: yes
            http-body-printable: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - files:
            force-magic: yes
        - ssh
        - flow
        - netflow
        - anomaly:
            enabled: yes
  
  - fast:
      enabled: yes
      filename: /var/log/suricata/fast.log
  
  - stats:
      enabled: yes
      filename: /var/log/suricata/stats.log
      totals: yes

# Syslog output for Splunk
  - syslog:
      enabled: yes
      facility: local5
      level: Info

logging:
  default-log-level: info
  outputs:
  - console:
      enabled: yes
  - file:
      enabled: yes
      filename: /var/log/suricata/suricata.log
  - syslog:
      enabled: yes
      facility: local5

app-layer:
  protocols:
    tls:
      enabled: yes
    ftp:
      enabled: yes
    ssh:
      enabled: yes
    smtp:
      enabled: yes
    http:
      enabled: yes
      memcap: 256mb
    dns:
      tcp:
        enabled: yes
      udp:
        enabled: yes

stream:
  memcap: 256mb
  checksum-validation: yes
  inline: auto
  reassembly:
    memcap: 512mb
    depth: 1mb

flow:
  memcap: 256mb
  hash-size: 65536
  prealloc: 10000

defrag:
  memcap: 128mb
  hash-size: 65536

detect:
  profile: medium
  sgh-mpm-context: auto

default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules

threading:
  set-cpu-affinity: no
  detect-thread-ratio: 1.0

unix-command:
  enabled: yes
  filename: /var/run/suricata/suricata-command.socket
SURICATA_CONFIG

log SUCCESS "Suricata configuration created"

# Create systemd service
log INFO "Creating systemd service..."

cat > /etc/systemd/system/suricata.service << 'SYSTEMD_SERVICE'
[Unit]
Description=Suricata IDS/IPS
After=network.target

[Service]
Type=simple
User=suricata
Group=suricata
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml --af-packet
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
SYSTEMD_SERVICE

systemctl daemon-reload

# Set permissions
log INFO "Setting permissions..."
mkdir -p /var/log/suricata /var/run/suricata /var/lib/suricata/rules
chown -R suricata:suricata /var/log/suricata /var/run/suricata /var/lib/suricata /etc/suricata

# Update rules
log INFO "Updating Suricata rules..."
suricata-update update-sources
suricata-update enable-source et/open
suricata-update enable-source oisf/trafficid
suricata-update

# Test configuration
log INFO "Testing configuration..."
if suricata -T -c /etc/suricata/suricata.yaml; then
    log SUCCESS "Configuration test passed"
else
    log ERROR "Configuration test failed"
    exit 1
fi

# Configure rsyslog to forward to Splunk
log INFO "Configuring rsyslog to forward to Splunk..."

cat > /etc/rsyslog.d/30-suricata-splunk.conf << 'RSYSLOG_CONFIG'
# Forward Suricata logs to Splunk
local5.* @@127.0.0.1:5514
RSYSLOG_CONFIG

systemctl restart rsyslog

# Configure Splunk to receive Suricata logs
log INFO "Configuring Splunk inputs..."

if [ -d "$SPLUNK_HOME" ]; then
    cat > $SPLUNK_HOME/etc/system/local/inputs.conf.d/suricata.conf << SPLUNK_INPUT
[monitor:///var/log/suricata/eve.json]
disabled = false
sourcetype = suricata:json
index = main

[monitor:///var/log/suricata/fast.log]
disabled = false
sourcetype = suricata:alert
index = main

[tcp://5514]
disabled = false
sourcetype = suricata:syslog
index = main
connection_host = ip
SPLUNK_INPUT
    
    log SUCCESS "Splunk input configuration created"
    log WARN "Restart Splunk to apply changes: $SPLUNK_HOME/bin/splunk restart"
else
    log WARN "Splunk not found at $SPLUNK_HOME - manual configuration required"
fi

# Enable and start Suricata
log INFO "Starting Suricata service..."
systemctl enable suricata
systemctl start suricata

sleep 3

if systemctl is-active --quiet suricata; then
    log SUCCESS "Suricata service is running"
else
    log ERROR "Suricata service failed to start"
    systemctl status suricata
    exit 1
fi

# Configure firewall
log INFO "Configuring firewall..."
if command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-port=5514/tcp
    firewall-cmd --reload
    log SUCCESS "Firewall configured"
fi

log INFO ""
log INFO "========================================"
log INFO "Suricata Installation Complete"
log INFO "========================================"
log INFO "Monitoring Interface: $PRIMARY_IFACE"
log INFO "Log Files:"
log INFO "  EVE JSON: /var/log/suricata/eve.json"
log INFO "  Fast Log: /var/log/suricata/fast.log"
log INFO ""
log INFO "Splunk Integration:"
log INFO "  Splunk Server: localhost (172.20.242.20)"
log INFO "  Syslog Port: 5514"
log INFO "  Search in Splunk: index=main sourcetype=suricata*"
log INFO ""
log INFO "Commands:"
log INFO "  Status: systemctl status suricata"
log INFO "  Logs: tail -f /var/log/suricata/eve.json | jq"
log INFO "  Update Rules: suricata-update"
log INFO "  Reload Rules: suricatasc -c reload-rules"
log INFO ""
log SUCCESS "Suricata is forwarding alerts to Splunk!"
