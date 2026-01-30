#!/bin/bash
# Deploy Wazuh Agents to All CCDC Linux Hosts
# Run from Ubuntu Ecom Server (172.20.242.30)
# Version: 1.0
# Date: January 30, 2026

set -e

WAZUH_MANAGER="172.20.242.20"
DRY_RUN=false
LOG_DIR="./Logs"
LOG_FILE="$LOG_DIR/deploy-wazuh-agents-$(date +%Y%m%d-%H%M%S).log"

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

# Parse arguments
while getopts "m:dh" opt; do
    case $opt in
        m) WAZUH_MANAGER="$OPTARG" ;;
        d) DRY_RUN=true ;;
        h)
            echo "Usage: $0 [-m manager_ip] [-d]"
            echo "  -m: Wazuh Manager IP (default: 172.20.242.20)"
            echo "  -d: Dry run mode"
            exit 0
            ;;
    esac
done

log INFO "========================================"
log INFO "Wazuh Agent Bulk Deployment (Linux)"
log INFO "Wazuh Manager: $WAZUH_MANAGER"
log INFO "Dry Run: $DRY_RUN"
log INFO "========================================"

# CCDC Linux hosts
declare -A LINUX_HOSTS
LINUX_HOSTS=(
    ["UbuntuEcom"]="172.20.242.30"
    ["SplunkServer"]="172.20.242.20"
    ["MailserverFedora"]="172.20.242.40"
    ["UbuntuDesktop"]="172.20.242.50"
)

log INFO "Target hosts: ${#LINUX_HOSTS[@]}"
for host in "${!LINUX_HOSTS[@]}"; do
    log INFO "  - $host (${LINUX_HOSTS[$host]})"
done

if [ "$DRY_RUN" = true ]; then
    log WARN "DRY RUN - No agents will be installed"
    log INFO "Commands that would be executed:"
    for host in "${!LINUX_HOSTS[@]}"; do
        log INFO "  ssh ${LINUX_HOSTS[$host]} 'WAZUH_MANAGER=$WAZUH_MANAGER bash /tmp/install-wazuh-agent.sh'"
    done
    exit 0
fi

# Check for sshpass
if ! command -v sshpass &> /dev/null; then
    log WARN "sshpass not found, installing..."
    sudo apt-get update && sudo apt-get install -y sshpass
fi

# Test connectivity to Wazuh Manager
log INFO "Testing connectivity to Wazuh Manager..."
if ping -c 2 "$WAZUH_MANAGER" &> /dev/null; then
    log SUCCESS "Wazuh Manager is reachable"
else
    log ERROR "Cannot reach Wazuh Manager at $WAZUH_MANAGER"
    exit 1
fi

# Create agent installation script
cat > /tmp/install-wazuh-agent.sh << 'AGENT_INSTALL'
#!/bin/bash
set -e

WAZUH_MANAGER="${WAZUH_MANAGER:-172.20.242.20}"

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    echo "Cannot detect OS"
    exit 1
fi

echo "Installing Wazuh agent on $OS $VER..."
echo "Manager: $WAZUH_MANAGER"

# Install based on OS
if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
    # Ubuntu/Debian
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
    apt-get update
    WAZUH_MANAGER="$WAZUH_MANAGER" apt-get install -y wazuh-agent
    
elif [ "$OS" = "ol" ] || [ "$OS" = "rhel" ] || [ "$OS" = "fedora" ]; then
    # RHEL/Oracle Linux/Fedora
    cat > /etc/yum.repos.d/wazuh.repo << 'REPO'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
REPO
    WAZUH_MANAGER="$WAZUH_MANAGER" dnf install -y wazuh-agent || WAZUH_MANAGER="$WAZUH_MANAGER" yum install -y wazuh-agent
else
    echo "Unsupported OS: $OS"
    exit 1
fi

# Configure agent
sed -i "s/<address>.*<\/address>/<address>$WAZUH_MANAGER<\/address>/" /var/ossec/etc/ossec.conf

# Start agent
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl restart wazuh-agent

# Verify
if systemctl is-active --quiet wazuh-agent; then
    echo "Wazuh agent installed and running"
else
    echo "Failed to start Wazuh agent"
    exit 1
fi
AGENT_INSTALL

chmod +x /tmp/install-wazuh-agent.sh

# Deploy to each host
success_count=0
fail_count=0

read -sp "Enter SSH password for root/admin: " SSH_PASSWORD
echo ""

for host in "${!LINUX_HOSTS[@]}"; do
    ip="${LINUX_HOSTS[$host]}"
    
    log INFO ""
    log INFO "Deploying to $host ($ip)..."
    
    # Test connectivity
    if ! ping -c 2 "$ip" &> /dev/null; then
        log ERROR "Cannot reach $host at $ip"
        ((fail_count++))
        continue
    fi
    
    # Copy and execute installation script
    if sshpass -p "$SSH_PASSWORD" scp -o StrictHostKeyChecking=no /tmp/install-wazuh-agent.sh root@$ip:/tmp/; then
        if sshpass -p "$SSH_PASSWORD" ssh -o StrictHostKeyChecking=no root@$ip "WAZUH_MANAGER=$WAZUH_MANAGER bash /tmp/install-wazuh-agent.sh"; then
            log SUCCESS "Wazuh agent deployed to $host"
            ((success_count++))
        else
            log ERROR "Failed to install agent on $host"
            ((fail_count++))
        fi
    else
        log ERROR "Failed to copy script to $host"
        ((fail_count++))
    fi
    
    sleep 2
done

log INFO ""
log INFO "========================================"
log INFO "Deployment Summary"
log INFO "========================================"
log INFO "Total hosts: ${#LINUX_HOSTS[@]}"
log SUCCESS "Successful: $success_count"
if [ $fail_count -gt 0 ]; then
    log ERROR "Failed: $fail_count"
fi
log INFO ""
log INFO "Next steps:"
log INFO "1. Verify agents on Wazuh Manager:"
log INFO "   ssh $WAZUH_MANAGER '/var/ossec/bin/agent_control -l'"
log INFO "2. Check alerts:"
log INFO "   ssh $WAZUH_MANAGER 'tail -f /var/ossec/logs/alerts/alerts.log'"
log INFO ""
log INFO "Log file: $LOG_FILE"
