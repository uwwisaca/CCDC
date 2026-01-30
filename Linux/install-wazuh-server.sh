#!/bin/bash
# Wazuh Server Installation Script
# Host-Based Intrusion Detection System (HIDS) for CCDC
# Install on Ubuntu Ecom Server (172.20.242.30) or Splunk Server (172.20.242.20)
# Version: 1.0
# Date: January 30, 2026

set -e

LOG_FILE="/var/log/wazuh-install-$(date +%Y%m%d-%H%M%S).log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

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
log INFO "Wazuh Server Installation for CCDC"
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

# Install dependencies based on OS
if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    log INFO "Installing dependencies (Ubuntu/Debian)..."
    apt-get update
    apt-get install -y curl apt-transport-https lsb-release gnupg2
    
    # Add Wazuh repository
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
    apt-get update
    
elif [ "$OS" = "ol" ] || [ "$OS" = "rhel" ] || [ "$OS" = "fedora" ]; then
    log INFO "Installing dependencies (RHEL/Oracle Linux)..."
    
    # Add Wazuh repository
    cat > /etc/yum.repos.d/wazuh.repo << 'WAZUH_REPO'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
WAZUH_REPO
else
    log ERROR "Unsupported OS: $OS"
    exit 1
fi

# Install Wazuh Manager
log INFO "Installing Wazuh Manager..."

if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    apt-get install -y wazuh-manager
else
    dnf install -y wazuh-manager
fi

# Configure Wazuh for CCDC environment
log INFO "Configuring Wazuh Manager for CCDC..."

# Backup original configuration
cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.backup

# Create CCDC-specific configuration
cat > /var/ossec/etc/ossec.conf << 'WAZUH_CONFIG'
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>172.20.242.30</smtp_server>
    <email_from>wazuh@ccdc.local</email_from>
    <email_to>admin@ccdc.local</email_to>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <!-- Logging configuration -->
  <logging>
    <log_format>plain</log_format>
  </logging>

  <!-- Remote connections -->
  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

  <!-- Rootcheck - System audit -->
  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>43200</frequency>
    <rootkit_files>/var/ossec/etc/shared/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/shared/rootkit_trojans.txt</rootkit_trojans>
    <skip_nfs>yes</skip_nfs>
  </rootcheck>

  <!-- File integrity monitoring -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    
    <!-- CCDC critical directories -->
    <directories check_all="yes" realtime="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes" realtime="yes">/bin,/sbin</directories>
    <directories check_all="yes" realtime="yes">/boot</directories>
    <directories check_all="yes" realtime="yes">/var/www</directories>
    <directories check_all="yes" realtime="yes">/opt/splunk/etc</directories>
    
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    
    <no_diff>/etc/ssl/private.key</no_diff>
  </syscheck>

  <!-- Vulnerability detection -->
  <vulnerability-detector>
    <enabled>yes</enabled>
    <interval>5m</interval>
    <min_full_scan_interval>6h</min_full_scan_interval>
    <run_on_start>yes</run_on_start>
    
    <provider name="canonical">
      <enabled>yes</enabled>
      <os>trusty</os>
      <os>xenial</os>
      <os>bionic</os>
      <os>focal</os>
      <os>jammy</os>
      <update_interval>1h</update_interval>
    </provider>

    <provider name="redhat">
      <enabled>yes</enabled>
      <update_from_year>2010</update_from_year>
      <update_interval>1h</update_interval>
    </provider>
  </vulnerability-detector>

  <!-- Active response -->
  <command>
    <name>disable-account</name>
    <executable>disable-account</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>5712,5720</rules_id>
    <timeout>600</timeout>
  </active-response>

  <!-- Log analysis -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\(.*\):\([[:digit:]]*\)\ \+\([0-9\.\:\*]\+\).\+\ \([[:digit:]]*\/[[:alnum:]\-]*\).*/\1 \2 == \3 == \4 \5/' | sort -k 4 -g | sed 's/ == \(.*\) ==/:\1/' | sed 1,2d</command>
    <alias>netstat listening ports</alias>
    <frequency>360</frequency>
  </localfile>

  <!-- Ruleset configuration -->
  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-eventnames</list>
    <list>etc/lists/security-eventchannel</list>
  </ruleset>

  <!-- Cluster configuration (optional for HA) -->
  <cluster>
    <name>ccdc-wazuh</name>
    <node_name>node01</node_name>
    <node_type>master</node_type>
    <key></key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
      <node>NODE_IP</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>yes</disabled>
  </cluster>

</ossec_config>
WAZUH_CONFIG

log SUCCESS "Wazuh Manager configured"

# Enable and start Wazuh Manager
log INFO "Starting Wazuh Manager..."
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager

sleep 3

if systemctl is-active --quiet wazuh-manager; then
    log SUCCESS "Wazuh Manager is running"
else
    log ERROR "Wazuh Manager failed to start"
    systemctl status wazuh-manager
    exit 1
fi

# Configure firewall
log INFO "Configuring firewall..."
if command -v ufw &> /dev/null; then
    ufw allow 1514/tcp  # Wazuh agent connections
    ufw allow 1515/tcp  # Wazuh agent enrollment
    ufw allow 55000/tcp # Wazuh API
elif command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-port=1514/tcp
    firewall-cmd --permanent --add-port=1515/tcp
    firewall-cmd --permanent --add-port=55000/tcp
    firewall-cmd --reload
fi

log SUCCESS "Firewall configured"

# Create agent deployment scripts
log INFO "Creating agent deployment scripts..."

# Extract manager auth key
WAZUH_KEY=$(cat /var/ossec/etc/client.keys 2>/dev/null || echo "")

cat > /root/deploy-wazuh-agent-linux.sh << 'DEPLOY_LINUX'
#!/bin/bash
# Wazuh Agent Deployment Script for Linux

WAZUH_MANAGER="MANAGER_IP"

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
fi

# Install Wazuh agent
if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
    apt-get update
    WAZUH_MANAGER="$WAZUH_MANAGER" apt-get install -y wazuh-agent
else
    cat > /etc/yum.repos.d/wazuh.repo << 'REPO'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
REPO
    WAZUH_MANAGER="$WAZUH_MANAGER" dnf install -y wazuh-agent
fi

# Start agent
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

echo "Wazuh agent installed and connected to $WAZUH_MANAGER"
DEPLOY_LINUX

# Replace MANAGER_IP with actual IP
MANAGER_IP=$(hostname -I | awk '{print $1}')
sed -i "s/MANAGER_IP/$MANAGER_IP/g" /root/deploy-wazuh-agent-linux.sh
chmod +x /root/deploy-wazuh-agent-linux.sh

log SUCCESS "Agent deployment script created: /root/deploy-wazuh-agent-linux.sh"

log INFO ""
log INFO "========================================"
log INFO "Wazuh Server Installation Complete"
log INFO "========================================"
log INFO "Manager IP: $MANAGER_IP"
log INFO "Agent Port: 1514"
log INFO "API Port: 55000"
log INFO ""
log INFO "Deploy agents to all CCDC hosts:"
log INFO "  Linux: /root/deploy-wazuh-agent-linux.sh"
log INFO "  Windows: See install-wazuh-agent-windows.ps1"
log INFO ""
log INFO "Wazuh Logs:"
log INFO "  Alerts: /var/ossec/logs/alerts/alerts.log"
log INFO "  Manager: /var/ossec/logs/ossec.log"
log INFO ""
log INFO "Commands:"
log INFO "  Status: systemctl status wazuh-manager"
log INFO "  List agents: /var/ossec/bin/agent_control -l"
log INFO "  View alerts: tail -f /var/ossec/logs/alerts/alerts.log"
log INFO ""
log SUCCESS "Wazuh HIDS is ready for CCDC!"
