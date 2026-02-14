#!/bin/bash
#
# Oracle Linux 9 STIG - Module 9: Enable Firewall
# Based on: U_Oracle_Linux_9_V1R4_Manual_STIG
# Version: 1.0
# Date: February 12, 2026
#
# WARNING: This script enables the firewall
# Ensure all required firewall rules are configured first (module 08)
# Ensure you have an alternate access method (console) in case of lockout
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/oracle-linux-stig-09-firewall-enable-$(date +%Y%m%d-%H%M%S).log"

log() {
    local level=$1
    shift
    local message="$@"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" | tee -a "$LOG_FILE"
    case $level in
        ERROR) echo -e "${RED}[ERROR]${NC} $message" >&2 ;;
        SUCCESS) echo -e "${GREEN}[SUCCESS]${NC} $message" ;;
        WARN) echo -e "${YELLOW}[WARN]${NC} $message" ;;
    esac
}

if [ "$EUID" -ne 0 ]; then
    log "ERROR" "This script must be run as root"
    exit 1
fi

log "INFO" "========================================"
log "INFO" "Module 9: Enable Firewall"
log "INFO" "========================================"

# Check if firewalld is installed
if ! command -v firewall-cmd &> /dev/null; then
    log "ERROR" "firewalld is not installed"
    log "ERROR" "Run module 08 first to install and configure firewall rules"
    exit 1
fi

# Display current firewall rules before enabling
log "INFO" "Current firewall configuration:"
firewall-cmd --permanent --list-all 2>/dev/null || log "WARN" "Could not list firewall rules"

# Verify SSH is allowed
log "INFO" "Verifying SSH access is configured..."
if firewall-cmd --permanent --query-service=ssh &>/dev/null || firewall-cmd --permanent --query-port=22/tcp &>/dev/null; then
    log "SUCCESS" "SSH access is configured"
else
    log "ERROR" "SSH access is NOT configured!"
    log "ERROR" "You may lose access to the system!"
    log "ERROR" "Add SSH rule: firewall-cmd --permanent --add-service=ssh"
    read -p "Continue anyway? (yes/NO): " response
    if [ "$response" != "yes" ]; then
        log "INFO" "Aborted by user"
        exit 1
    fi
fi

log "WARN" ""
log "WARN" "==========================================="
log "WARN" "  WARNING: ENABLING FIREWALL NOW"
log "WARN" "==========================================="
log "WARN" "Ensure you have console access if needed"
log "WARN" ""
log "WARN" "Waiting 5 seconds... (Ctrl+C to abort)"
sleep 5

# Enable and start firewalld
log "INFO" "Enabling firewalld..."
systemctl enable firewalld && log "SUCCESS" "Firewall enabled for boot" || log "ERROR" "Failed to enable firewall"

log "INFO" "Starting firewalld..."
systemctl start firewalld && log "SUCCESS" "Firewall started" || log "ERROR" "Failed to start firewall"

# Verify firewall is running
if systemctl is-active --quiet firewalld; then
    log "SUCCESS" "Firewall is active"
else
    log "ERROR" "Firewall is NOT active"
    exit 1
fi

# Display final firewall status
log "INFO" ""
log "INFO" "Firewall Status:"
firewall-cmd --state | tee -a "$LOG_FILE"

log "INFO" ""
log "INFO" "Active Rules:"
firewall-cmd --list-all | tee -a "$LOG_FILE"

log "INFO" ""
log "SUCCESS" "========================================"
log "SUCCESS" "Module 9 Completed: Firewall Enabled"
log "SUCCESS" "========================================"
log "INFO" "Log file: $LOG_FILE"
log "WARN" ""
log "WARN" "CRITICAL: Verify network connectivity now!"
log "WARN" "Test SSH access from another terminal"
log "WARN" "Test Splunk web interface: https://$(hostname):8000"
log "INFO" ""
log "INFO" "Firewall management commands:"
log "INFO" "  firewall-cmd --list-all                    # Show all rules"
log "INFO" "  firewall-cmd --add-port=<port>/tcp --permanent  # Add port"
log "INFO" "  firewall-cmd --reload                      # Reload rules"
log "INFO" "  systemctl stop firewalld                   # Emergency disable"
log "INFO" ""
log "INFO" "Emergency firewall disable (if locked out via console):"
log "INFO" "  systemctl stop firewalld && systemctl disable firewalld"
