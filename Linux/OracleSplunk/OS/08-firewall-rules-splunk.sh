#!/bin/bash
#
# Oracle Linux 9 STIG - Module 8: Firewall Rules for Splunk
# Based on: U_Oracle_Linux_9_V1R4_Manual_STIG
# Version: 1.0
# Date: February 12, 2026
#
# IMPORTANT: This configures firewall rules but does NOT enable the firewall
# Run 09-firewall-enable.sh after verifying all rules are correct
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/oracle-linux-stig-08-firewall-rules-$(date +%Y%m%d-%H%M%S).log"

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
log "INFO" "Module 8: Firewall Rules (Splunk)"
log "INFO" "========================================"

# Install firewalld
log "INFO" "Installing firewalld..."
dnf install -y firewalld || log "WARN" "firewalld may already be installed"

# Start firewalld temporarily to configure (don't enable yet)
log "INFO" "Starting firewalld for configuration..."
systemctl start firewalld

# Configure firewall rules
log "INFO" "Configuring firewall rules for Splunk..."

# SSH (required for remote administration)
log "INFO" "Adding SSH rule..."
firewall-cmd --permanent --add-service=ssh && log "SUCCESS" "SSH allowed" || log "ERROR" "Failed to add SSH rule"

# Splunk Web Interface (HTTPS)
log "INFO" "Adding Splunk Web Interface (port 8000)..."
firewall-cmd --permanent --add-port=8000/tcp && log "SUCCESS" "Splunk Web (8000/tcp) allowed" || log "ERROR" "Failed to add port 8000"

# Splunk Management Port
log "INFO" "Adding Splunk Management Port (port 8089)..."
firewall-cmd --permanent --add-port=8089/tcp && log "SUCCESS" "Splunk Management (8089/tcp) allowed" || log "ERROR" "Failed to add port 8089"

# Set default policies
log "INFO" "Setting default firewall policies..."
firewall-cmd --permanent --set-default-zone=public && log "SUCCESS" "Default zone set to public" || log "WARN" "Could not set default zone"

# Enable logging for denied packets
log "INFO" "Enabling firewall logging..."
firewall-cmd --permanent --set-log-denied=all && log "SUCCESS" "Firewall logging enabled" || log "WARN" "Could not enable logging"

# Reload firewall to apply rules
log "INFO" "Reloading firewall configuration..."
firewall-cmd --reload && log "SUCCESS" "Firewall rules reloaded" || log "ERROR" "Failed to reload firewall"

# Display configured rules
log "INFO" ""
log "INFO" "Configured Firewall Rules:"
firewall-cmd --list-all | tee -a "$LOG_FILE"

# Stop firewalld (it will be enabled in module 09)
log "INFO" ""
log "INFO" "Stopping firewalld (will be enabled in module 09)..."
systemctl stop firewalld
systemctl disable firewalld 2>/dev/null || true

log "INFO" ""
log "SUCCESS" "========================================"
log "SUCCESS" "Module 8 Completed: Firewall Rules"
log "SUCCESS" "========================================"
log "INFO" "Log file: $LOG_FILE"
log "WARN" ""
log "WARN" "FIREWALL IS NOT YET ENABLED"
log "WARN" "Rules are configured but firewall is stopped"
log "WARN" "Run 09-firewall-enable.sh to enable the firewall"
log "INFO" ""
log "INFO" "Ports configured:"
log "INFO" "  - 22/tcp  (SSH)"
log "INFO" "  - 8000/tcp (Splunk Web Interface)"
log "INFO" "  - 8089/tcp (Splunk Management)"
log "INFO" ""
log "INFO" "Verify rules: firewall-cmd --list-all"
