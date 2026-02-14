#!/bin/bash
#
# RHEL 9 / Fedora STIG - Module 8: Firewall Rules for Mailserver
# Based on: U_RHEL_9_V2R7_Manual_STIG
# Version: 1.0
# Date: February 12, 2026
#
# IMPORTANT: This configures firewall rules but does NOT enable the firewall
# Run 09-firewall-enable.sh after verifying all rules are correct
#
# Note: This script includes common mail server ports. Adjust as needed for your configuration.
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/rhel9-stig-08-firewall-rules-$(date +%Y%m%d-%H%M%S).log"

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
log "INFO" "Module 8: Firewall Rules (Mailserver)"
log "INFO" "========================================"

# Install firewalld
log "INFO" "Installing firewalld..."
dnf install -y firewalld || log "WARN" "firewalld may already be installed"

# Start firewalld temporarily to configure (don't enable yet)
log "INFO" "Starting firewalld for configuration..."
systemctl start firewalld

# Configure firewall rules
log "INFO" "Configuring firewall rules for Mailserver..."

# SSH (required for remote administration)
log "INFO" "Adding SSH rule..."
firewall-cmd --permanent --add-service=ssh && log "SUCCESS" "SSH allowed" || log "ERROR" "Failed to add SSH rule"

# HTTP/HTTPS for web interface (if using webmail)
log "INFO" "Adding HTTP/HTTPS for webmail..."
firewall-cmd --permanent --add-service=http && log "SUCCESS" "HTTP allowed" || log "WARN" "Failed to add HTTP"
firewall-cmd --permanent --add-service=https && log "SUCCESS" "HTTPS allowed" || log "WARN" "Failed to add HTTPS"

# Common mail server ports - UNCOMMENT the ones you need:
log "INFO" "Mail server ports can be added below (edit this script to uncomment)..."

# SMTP (25) - Uncomment if needed
# firewall-cmd --permanent --add-service=smtp && log "SUCCESS" "SMTP (25) allowed" || log "WARN" "Could not add SMTP"

# SMTPS (465) - SMTP over SSL - Uncomment if needed
# firewall-cmd --permanent --add-port=465/tcp && log "SUCCESS" "SMTPS (465) allowed" || log "WARN" "Could not add SMTPS"

# Submission (587) - SMTP submission - Uncomment if needed
# firewall-cmd --permanent --add-service=smtp-submission && log "SUCCESS" "Submission (587) allowed" || log "WARN" "Could not add submission"

# IMAP (143) - Uncomment if needed
# firewall-cmd --permanent --add-service=imap && log "SUCCESS" "IMAP (143) allowed" || log "WARN" "Could not add IMAP"

# IMAPS (993) - IMAP over SSL - Uncomment if needed
# firewall-cmd --permanent --add-service=imaps && log "SUCCESS" "IMAPS (993) allowed" || log "WARN" "Could not add IMAPS"

# POP3 (110) - Uncomment if needed
# firewall-cmd --permanent --add-service=pop3 && log "SUCCESS" "POP3 (110) allowed" || log="WARN" "Could not add POP3"

# POP3S (995) - POP3 over SSL - Uncomment if needed
# firewall-cmd --permanent --add-service=pop3s && log "SUCCESS" "POP3S (995) allowed" || log "WARN" "Could not add POP3S"

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
log "INFO" "Ports currently configured:"
log "INFO" "  - 22/tcp  (SSH)"
log "INFO" "  - 80/tcp  (HTTP)"
log "INFO" "  - 443/tcp (HTTPS)"
log "WARN" ""
log "WARN" "EDIT THIS SCRIPT to uncomment mail server ports you need:"
log "WARN" "  - 25   (SMTP)"
log "WARN" "  - 465  (SMTPS)"
log "WARN" "  - 587  (Submission)"
log "WARN" "  - 143  (IMAP)"
log "WARN" "  - 993  (IMAPS)"
log "WARN" "  - 110  (POP3)"
log "WARN" "  - 995  (POP3S)"
log "INFO" ""
log "INFO" "Verify rules: firewall-cmd --list-all"
