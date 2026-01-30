#!/bin/bash
# Bash Script to Apply Palo Alto STIG via SSH from Linux
# Connects to Palo Alto firewall and applies STIG hardening commands
# Version: 1.0
# Date: January 30, 2026
#
# Usage: ./deploy-paloalto-stig.sh -h <host_ip> -u <username> [-p <password>]

set -e

# Variables
HOST=""
USERNAME=""
PASSWORD=""
DRY_RUN=false
LOG_DIR="./logs"
LOG_FILE="$LOG_DIR/paloalto-deploy-$(date +%Y%m%d-%H%M%S).log"

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
    $0 -h 172.20.242.150 -u admin
    $0 -h 172.20.242.150 -u admin -p Changeme123 -d
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
log INFO "Palo Alto STIG Deployment via SSH"
log INFO "Target: $HOST"
log INFO "========================================"

# Check if sshpass is installed
if ! command -v sshpass &> /dev/null; then
    log WARN "sshpass is not installed. Installing..."
    if [ -f /etc/debian_version ]; then
        sudo apt-get update && sudo apt-get install -y sshpass
    elif [ -f /etc/redhat-release ]; then
        sudo dnf install -y sshpass
    else
        log ERROR "Please install sshpass manually"
        exit 1
    fi
fi

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

# Palo Alto STIG Commands
read -r -d '' PALO_COMMANDS << 'EOF' || true
configure
set mgt-config password-complexity enabled yes
set mgt-config password-complexity minimum-length 15
set mgt-config password-complexity minimum-uppercase-letters 1
set mgt-config password-complexity minimum-lowercase-letters 1
set mgt-config password-complexity minimum-numeric-letters 1
set mgt-config password-complexity minimum-special-characters 1
set mgt-config password-complexity password-change-period-block 5
set mgt-config password-complexity password-change-on-first-login yes
set mgt-config password-complexity expiration-period 60
set mgt-config failed-attempts 3
set mgt-config lockout-time 15
set deviceconfig setting session timeout 15
set deviceconfig system login-banner "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS you consent to monitoring and recording. Unauthorized use may result in criminal and/or civil penalties."
set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 172.16.101.1
set deviceconfig system ntp-servers primary-ntp-server authentication-type symmetric-key
set deviceconfig system ntp-servers primary-ntp-server algorithm sha1
set deviceconfig system ntp-servers primary-ntp-server authentication-key ChangeThisNTPKey123
set deviceconfig system timezone US/Eastern
set shared log-settings syslog STIG-SYSLOG server SIEM-Server server 172.20.242.30
set shared log-settings syslog STIG-SYSLOG server SIEM-Server transport UDP
set shared log-settings syslog STIG-SYSLOG server SIEM-Server port 514
set shared log-settings syslog STIG-SYSLOG server SIEM-Server format BSD
set shared log-settings syslog STIG-SYSLOG server SIEM-Server facility LOG_USER
set deviceconfig system permitted-ip 172.20.240.0/24 description "Management Network"
set deviceconfig system service disable-http yes
set deviceconfig system service disable-telnet yes
set deviceconfig system service disable-snmp yes
set deviceconfig setting ssl-tls-service-profile STIG-TLS protocol-settings min-version tls1-2
set deviceconfig setting ssl-tls-service-profile STIG-TLS protocol-settings max-version tls1-3
set deviceconfig setting management ssl-tls-service-profile STIG-TLS
set zone trust network layer3 ethernet1/1
set zone untrust network layer3 ethernet1/2
set zone dmz network layer3 ethernet1/3
commit description "STIG compliance configuration"
EOF

# Dry run mode
if [ "$DRY_RUN" = true ]; then
    log WARN "DRY RUN MODE - Commands that would be executed:"
    echo "$PALO_COMMANDS"
    log SUCCESS "Dry run complete. No changes made."
    exit 0
fi

# Execute commands via SSH
log INFO "Establishing SSH connection to $HOST..."

# Create temporary expect script
EXPECT_SCRIPT=$(mktemp)
cat > "$EXPECT_SCRIPT" << EXPECTEOF
#!/usr/bin/expect -f

set timeout 60
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
    ">" {
        # Successfully logged in
    }
    timeout {
        puts "Login failed"
        exit 1
    }
}

# Send commands
$(echo "$PALO_COMMANDS" | while IFS= read -r cmd; do
    if [ -n "$cmd" ]; then
        echo "send \"$cmd\r\""
        echo "expect -timeout 3 {\"#\" {} \">\" {} \"(config)\" {} timeout {}}"
        # Special handling for commit command
        if [[ "$cmd" == commit* ]]; then
            echo "expect -timeout 60 {\"Commit job\" {} \"succeeded\" {} \"failed\" {} timeout {}}"
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
log INFO "Executing commands (this may take 1-2 minutes)..."
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
log INFO "Palo Alto STIG Deployment Completed"
log INFO "========================================"
log INFO "Log file: $LOG_FILE"
log INFO ""
log WARN "IMPORTANT NEXT STEPS:"
log WARN "1. Verify configuration via Web UI or CLI"
log WARN "2. Configure security policies (default deny rule)"
log WARN "3. Set up threat prevention profiles"
log WARN "4. Configure SSL decryption policies (if required)"
log WARN "5. Set up TACACS+ or RADIUS authentication"
log WARN "6. Configure GlobalProtect (if VPN needed)"
log WARN "7. Update content (Applications, Threats, WildFire)"
log WARN "8. Test logging to syslog server"
log WARN "9. Configure HA (if second firewall available)"
log WARN "10. Backup configuration to external location"
log INFO ""
log INFO "To view configuration:"
log INFO "  show config running"
log INFO ""
log INFO "To export configuration:"
log INFO "  scp export configuration to admin@172.20.242.30:/backups/paloalto-config.xml"
log INFO ""
log SUCCESS "Script execution complete!"
