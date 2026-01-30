#!/bin/bash
# Bash Script to Apply VyOS STIG via SSH from Linux
# Connects to VyOS router and applies STIG hardening commands
# Version: 1.0
# Date: January 30, 2026
#
# Usage: ./deploy-vyos-stig.sh -h <host_ip> -u <username> [-p <password>]

set -e

# Variables
HOST=""
USERNAME=""
PASSWORD=""
DRY_RUN=false
LOG_DIR="./logs"
LOG_FILE="$LOG_DIR/vyos-deploy-$(date +%Y%m%d-%H%M%S).log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to log messages
log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
    
    case $level in
        ERROR)
            echo -e "${RED}[$timestamp] [$level] $message${NC}" >&2
            ;;
        SUCCESS)
            echo -e "${GREEN}[$timestamp] [$level] $message${NC}"
            ;;
        WARN)
            echo -e "${YELLOW}[$timestamp] [$level] $message${NC}"
            ;;
    esac
}

# Function to show usage
usage() {
    cat << EOF
Usage: $0 -h <host_ip> -u <username> [-p <password>] [-d]

Options:
    -h    Host IP address (required)
    -u    Username (required)
    -p    Password (optional, will prompt if not provided)
    -d    Dry run mode (show commands without executing)
    
Example:
    $0 -h 172.16.10.1 -u admin
    $0 -h 172.16.10.1 -u admin -p vyos -d
EOF
    exit 1
}

# Parse command line arguments
while getopts "h:u:p:d" opt; do
    case $opt in
        h) HOST="$OPTARG" ;;
        u) USERNAME="$OPTARG" ;;
        p) PASSWORD="$OPTARG" ;;
        d) DRY_RUN=true ;;
        *) usage ;;
    esac
done

# Validate required arguments
if [ -z "$HOST" ] || [ -z "$USERNAME" ]; then
    usage
fi

# Create log directory
mkdir -p "$LOG_DIR"

log INFO "========================================"
log INFO "VyOS STIG Deployment via SSH"
log INFO "Target: $HOST"
log INFO "========================================"

# Get password if not provided
if [ -z "$PASSWORD" ]; then
    read -sp "Enter password for $USERNAME: " PASSWORD
    echo
fi

# Test connectivity
log INFO "Testing connectivity to $HOST..."
if ! ping -c 2 -W 2 "$HOST" > /dev/null 2>&1; then
    log ERROR "Cannot reach host: $HOST"
    exit 1
fi
log SUCCESS "Host is reachable"

# VyOS STIG Commands
read -r -d '' VYOS_COMMANDS << 'EOF' || true
configure
set system host-name vyos-router
set system domain-name ccdc.local
set system login banner pre-login "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS you consent to monitoring and recording. Unauthorized use may result in criminal and/or civil penalties."
set system login banner post-login "Unauthorized access is prohibited."
set system ntp server 172.16.101.1 prefer
set system time-zone America/New_York
set system syslog global facility all level info
set system syslog global facility protocols level debug
set system syslog host 172.20.242.30 facility all level info
set system syslog host 172.20.242.30 port 514
set service ssh port 22
set service ssh ciphers aes256-ctr
set service ssh ciphers aes192-ctr
set service ssh ciphers aes128-ctr
set service ssh key-exchange curve25519-sha256
set service ssh mac hmac-sha2-512
set service ssh mac hmac-sha2-256
set service ssh disable-password-authentication
delete interfaces ethernet eth0 address dhcp
set interfaces ethernet eth0 address 172.16.10.1/24
set interfaces ethernet eth0 description "LAN Interface"
delete interfaces ethernet eth1 address dhcp
set interfaces ethernet eth1 address 192.168.1.1/24
set interfaces ethernet eth1 description "WAN Interface"
set protocols static route 0.0.0.0/0 next-hop 192.168.1.254
set firewall name WAN-IN default-action drop
set firewall name WAN-IN enable-default-log
set firewall name WAN-IN rule 10 action accept
set firewall name WAN-IN rule 10 state established enable
set firewall name WAN-IN rule 10 state related enable
set firewall name WAN-IN rule 20 action drop
set firewall name WAN-IN rule 20 state invalid enable
set firewall name WAN-IN rule 20 log enable
set firewall name LAN-IN default-action drop
set firewall name LAN-IN enable-default-log
set firewall name LAN-IN rule 10 action accept
set firewall name LAN-IN rule 10 state established enable
set firewall name LAN-IN rule 10 state related enable
set firewall name LAN-IN rule 100 action accept
set firewall name LAN-IN rule 100 source address 172.16.10.0/24
set firewall name LAN-IN rule 100 destination address 0.0.0.0/0
set interfaces ethernet eth1 firewall in name WAN-IN
set interfaces ethernet eth0 firewall in name LAN-IN
set nat source rule 100 outbound-interface eth1
set nat source rule 100 source address 172.16.10.0/24
set nat source rule 100 translation address masquerade
set system ip disable-forwarding
set system ip tcp-flags-check enable
set system ip arp-filter enable
set system conntrack timeout tcp established 7200
set system conntrack timeout tcp close-wait 60
commit
save
EOF

# Dry run mode
if [ "$DRY_RUN" = true ]; then
    log WARN "DRY RUN MODE - Commands that would be executed:"
    echo "$VYOS_COMMANDS"
    log SUCCESS "Dry run complete. No changes made."
    exit 0
fi

# Execute commands via SSH
log INFO "Establishing SSH connection to $HOST..."

# Create temporary expect script
EXPECT_SCRIPT=$(mktemp)
cat > "$EXPECT_SCRIPT" << EXPECTEOF
#!/usr/bin/expect -f

set timeout 30
set host "$HOST"
set username "$USERNAME"
set password "$PASSWORD"

spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \$username@\$host

expect {
    "password:" {
        send "\$password\r"
    }
    "Password:" {
        send "\$password\r"
    }
    timeout {
        puts "Connection timeout"
        exit 1
    }
}

expect {
    "@" {
        # Successfully logged in
    }
    timeout {
        puts "Login failed"
        exit 1
    }
}

# Send commands
$(echo "$VYOS_COMMANDS" | while IFS= read -r cmd; do
    if [ -n "$cmd" ]; then
        echo "send \"$cmd\r\""
        echo "expect -timeout 3 {\"#\" {} \"@\" {} \"\\\$\" {} timeout {}}"
        # Special handling for commit and save commands
        if [[ "$cmd" == "commit" ]] || [[ "$cmd" == "save" ]]; then
            echo "expect -timeout 30 {\"Done\" {} \"Saving\" {} \"#\" {} timeout {}}"
        fi
    fi
done)

send "exit\r"
expect eof
EXPECTEOF

chmod +x "$EXPECT_SCRIPT"

# Check if expect is installed
if ! command -v expect &> /dev/null; then
    log ERROR "expect is not installed. Installing..."
    if [ -f /etc/debian_version ]; then
        sudo apt-get update && sudo apt-get install -y expect
    elif [ -f /etc/redhat-release ]; then
        sudo dnf install -y expect
    else
        log ERROR "Please install expect manually"
        rm -f "$EXPECT_SCRIPT"
        exit 1
    fi
fi

# Execute the expect script
log INFO "Executing commands (this may take 30-60 seconds)..."
if "$EXPECT_SCRIPT" 2>&1 | tee -a "$LOG_FILE"; then
    log SUCCESS "Commands executed successfully"
else
    log ERROR "Failed to execute commands"
    rm -f "$EXPECT_SCRIPT"
    exit 1
fi

# Cleanup
rm -f "$EXPECT_SCRIPT"

log INFO ""
log INFO "========================================"
log INFO "VyOS STIG Deployment Completed"
log INFO "========================================"
log INFO "Log file: $LOG_FILE"
log INFO ""
log WARN "IMPORTANT NEXT STEPS:"
log WARN "1. Verify configuration: show configuration"
log WARN "2. Test network connectivity"
log WARN "3. Verify NTP synchronization: show ntp"
log WARN "4. Check firewall rules: show firewall"
log WARN "5. Test SSH access with key-based authentication"
log WARN "6. Configure additional firewall rules as needed"
log WARN "7. Set up IPsec VPN if required"
log WARN "8. Configure DHCP server if needed"
log WARN "9. Set up DNS forwarding if required"
log WARN "10. Backup configuration: show configuration commands"
log INFO ""
log INFO "To backup configuration to file:"
log INFO "  scp vyos@$HOST:/config/config.boot ./vyos-config.boot"
log INFO ""
log SUCCESS "Script execution complete!"
