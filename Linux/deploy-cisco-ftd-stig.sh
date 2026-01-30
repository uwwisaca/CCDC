#!/bin/bash
# Bash Script to Apply Cisco FTD STIG via SSH from Linux
# Connects to Cisco FTD/ASA and applies STIG hardening commands
# Version: 1.0
# Date: January 30, 2026
#
# Usage: ./deploy-cisco-ftd-stig.sh -h <host_ip> -u <username> [-p <password>] [-e <enable_password>]

set -e

# Variables
HOST=""
USERNAME=""
PASSWORD=""
ENABLE_PASSWORD=""
DRY_RUN=false
LOG_DIR="./logs"
LOG_FILE="$LOG_DIR/cisco-ftd-deploy-$(date +%Y%m%d-%H%M%S).log"

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
Usage: $0 -h <host_ip> -u <username> [-p <password>] [-e <enable_password>] [-d]

Options:
    -h    Host IP address (required)
    -u    Username (required)
    -p    Password (optional, will prompt if not provided)
    -e    Enable password (optional, will prompt if not provided)
    -d    Dry run mode (show commands without executing)
    
Example:
    $0 -h 172.20.240.200 -u admin
    $0 -h 172.20.240.200 -u admin -p Password123 -e EnablePass123 -d
EOF
    exit 1
}

# Parse command line arguments
while getopts "h:u:p:e:d" opt; do
    case $opt in
        h) HOST="$OPTARG" ;;
        u) USERNAME="$OPTARG" ;;
        p) PASSWORD="$OPTARG" ;;
        e) ENABLE_PASSWORD="$OPTARG" ;;
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
log INFO "Cisco FTD STIG Deployment via SSH"
log INFO "Target: $HOST"
log INFO "========================================"

# Check if sshpass is installed
if ! command -v sshpass &> /dev/null; then
    log ERROR "sshpass is not installed. Installing..."
    if [ -f /etc/debian_version ]; then
        sudo apt-get update && sudo apt-get install -y sshpass
    elif [ -f /etc/redhat-release ]; then
        sudo dnf install -y sshpass
    else
        log ERROR "Please install sshpass manually"
        exit 1
    fi
fi

# Get passwords if not provided
if [ -z "$PASSWORD" ]; then
    read -sp "Enter password for $USERNAME: " PASSWORD
    echo
fi

if [ -z "$ENABLE_PASSWORD" ]; then
    read -sp "Enter enable password: " ENABLE_PASSWORD
    echo
fi

# Test connectivity
log INFO "Testing connectivity to $HOST..."
if ! ping -c 2 -W 2 "$HOST" > /dev/null 2>&1; then
    log ERROR "Cannot reach host: $HOST"
    exit 1
fi
log SUCCESS "Host is reachable"

# Cisco FTD STIG Commands
read -r -d '' CISCO_COMMANDS << 'EOF' || true
enable
ENABLE_PASSWORD_PLACEHOLDER
configure terminal
password-policy minimum-length 14
password-policy complexity enable
password-policy lifetime 60
aaa authentication login-attempts max-failures 3
aaa authentication ssh console LOCAL
banner motd You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS you consent to monitoring and recording. Unauthorized use may result in criminal and/or civil penalties.
banner login You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
banner exec Unauthorized access is prohibited.
logging enable
logging timestamp
logging trap informational
logging buffered informational
logging console critical
logging host inside 172.20.242.30 udp/514
ntp server 172.16.101.1 prefer
ntp authenticate
ntp authentication-key 1 md5 ChangeThisNTPKey123
ntp trusted-key 1
crypto key generate rsa modulus 2048
ssh version 2
ssh timeout 15
ssh key-exchange group dh-group14-sha1
no service password-recovery
no http server enable
service password-encryption
timeout uauth 0:15:00 absolute
timeout conn 1:00:00
ssl server-version tlsv1.2
ssl cipher tlsv1.2 custom "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384"
snmp-server group STIG-GROUP v3 priv
snmp-server user snmp-admin STIG-GROUP v3 auth sha AuthPassword123 priv aes 256 PrivPassword123
exit
write memory
EOF

# Replace enable password placeholder
CISCO_COMMANDS="${CISCO_COMMANDS//ENABLE_PASSWORD_PLACEHOLDER/$ENABLE_PASSWORD}"

# Dry run mode
if [ "$DRY_RUN" = true ]; then
    log WARN "DRY RUN MODE - Commands that would be executed:"
    echo "$CISCO_COMMANDS"
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
        exp_continue
    }
    "Password:" {
        send "\$password\r"
        exp_continue
    }
    ">" {
        # Successfully logged in
    }
    "#" {
        # Already in privileged mode
    }
    timeout {
        puts "Connection timeout"
        exit 1
    }
}

# Send commands
$(echo "$CISCO_COMMANDS" | while IFS= read -r cmd; do
    if [ -n "$cmd" ]; then
        echo "send \"$cmd\r\""
        echo "expect -timeout 2 {\"#\" {} \">\" {} \"(config)#\" {} timeout {}}"
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
log INFO "Cisco FTD STIG Deployment Completed"
log INFO "========================================"
log INFO "Log file: $LOG_FILE"
log INFO ""
log WARN "IMPORTANT NEXT STEPS:"
log WARN "1. Verify configuration: show running-config"
log WARN "2. Test SSH access with new settings"
log WARN "3. Verify NTP synchronization: show ntp status"
log WARN "4. Check logging: show logging"
log WARN "5. Configure interface-specific settings (ACLs, inspection)"
log WARN "6. Update NTP key and SNMP passwords with secure values"
log WARN "7. Save configuration to startup-config if not auto-saved"
log WARN "8. Backup configuration to TFTP/SCP server"
log INFO ""
log SUCCESS "Script execution complete!"
