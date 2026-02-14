#!/bin/bash
#
# Oracle Linux 9 STIG - Module 5: SELinux Configuration
# Based on: U_Oracle_Linux_9_V1R4_Manual_STIG
# Version: 1.0
# Date: February 12, 2026
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/oracle-linux-stig-05-selinux-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/oracle-linux-stig-backup-selinux-$(date +%Y%m%d-%H%M%S)"

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
log "INFO" "Module 5: SELinux Configuration"
log "INFO" "========================================"

# Create backup directory
mkdir -p "$BACKUP_DIR"
cp -p /etc/selinux/config "$BACKUP_DIR/" 2>/dev/null || true
log "SUCCESS" "Backup created: $BACKUP_DIR"

# Install SELinux packages
log "INFO" "Installing SELinux packages..."
dnf install -y selinux-policy-targeted policycoreutils-python-utils || log "WARN" "Packages may already be installed"

# Check current SELinux status
CURRENT_MODE=$(getenforce)
log "INFO" "Current SELinux mode: $CURRENT_MODE"

# Configure SELinux
log "INFO" "Configuring SELinux..."
sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
sed -i 's/^SELINUXTYPE=.*/SELINUXTYPE=targeted/' /etc/selinux/config

log "SUCCESS" "SELinux configuration updated"

# Set SELinux to enforcing mode (if possible without reboot)
if [ "$CURRENT_MODE" != "Enforcing" ]; then
    log "INFO" "Attempting to set SELinux to enforcing mode..."
    if setenforce 1 2>/dev/null; then
        log "SUCCESS" "SELinux set to enforcing mode"
    else
        log "WARN" "SELinux cannot be set to enforcing without reboot"
        log "WARN" "SELinux will be enforcing after system reboot"
    fi
else
    log "SUCCESS" "SELinux is already in enforcing mode"
fi

# Verify configuration
log "INFO" "Verifying SELinux configuration..."
if grep -q "^SELINUX=enforcing" /etc/selinux/config; then
    log "SUCCESS" "SELinux enforcing mode configured in /etc/selinux/config"
else
    log "ERROR" "SELinux configuration verification failed"
    exit 1
fi

if grep -q "^SELINUXTYPE=targeted" /etc/selinux/config; then
    log "SUCCESS" "SELinux targeted policy configured"
else
    log "ERROR" "SELinux policy configuration verification failed"
    exit 1
fi

# Fix SELinux contexts for common directories
log "INFO" "Restoring SELinux contexts..."
restorecon -R /etc /var /usr || log "WARN" "Some contexts could not be restored"

log "SUCCESS" "SELinux contexts restored"

# Display SELinux status
log "INFO" "SELinux Status:"
sestatus | tee -a "$LOG_FILE"

log "INFO" ""
log "SUCCESS" "========================================"
log "SUCCESS" "Module 5 Completed: SELinux Configuration"
log "SUCCESS" "========================================"
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"

if [ "$CURRENT_MODE" != "Enforcing" ]; then
    log "WARN" ""
    log "WARN" "SYSTEM REBOOT REQUIRED"
    log "WARN" "SELinux will be in enforcing mode after reboot"
    log "WARN" "Verify with: getenforce"
fi

log "INFO" ""
log "INFO" "Troubleshooting SELinux:"
log "INFO" "  - View denials: ausearch -m avc -ts recent"
log "INFO" "  - SELinux status: sestatus"
log "INFO" "  - Temporarily set permissive: setenforce 0"
log "INFO" "  - View boolean settings: getsebool -a"
