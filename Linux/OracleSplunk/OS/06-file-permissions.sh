#!/bin/bash
#
# Oracle Linux 9 STIG - Module 6: File Permissions
# Based on: U_Oracle_Linux_9_V1R4_Manual_STIG
# Version: 1.0
# Date: February 12, 2026
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/oracle-linux-stig-06-permissions-$(date +%Y%m%d-%H%M%S).log"

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
log "INFO" "Module 6: File Permissions"
log "INFO" "========================================"

# Set permissions on critical system files
log "INFO" "Setting permissions on critical system files..."

# User and group files
log "INFO" "Setting permissions on user/group files..."
chmod 0644 /etc/passwd 2>/dev/null && log "SUCCESS" "Set /etc/passwd to 0644" || log "WARN" "Could not set /etc/passwd"
chmod 0000 /etc/shadow 2>/dev/null && log "SUCCESS" "Set /etc/shadow to 0000" || log "WARN" "Could not set /etc/shadow"
chmod 0000 /etc/gshadow 2>/dev/null && log "SUCCESS" "Set /etc/gshadow to 0000" || log "WARN" "Could not set /etc/gshadow"
chmod 0644 /etc/group 2>/dev/null && log "SUCCESS" "Set /etc/group to 0644" || log "WARN" "Could not set /etc/group"

# Backup files
chmod 0644 /etc/passwd- 2>/dev/null || log "INFO" "/etc/passwd- not found"
chmod 0000 /etc/shadow- 2>/dev/null || log "INFO" "/etc/shadow- not found"
chmod 0000 /etc/gshadow- 2>/dev/null || log "INFO" "/etc/gshadow- not found"
chmod 0644 /etc/group- 2>/dev/null || log "INFO" "/etc/group- not found"

# GRUB configuration
log "INFO" "Setting permissions on boot files..."
if [ -f /boot/grub2/grub.cfg ]; then
    chmod 0600 /boot/grub2/grub.cfg && log "SUCCESS" "Set /boot/grub2/grub.cfg to 0600"
elif [ -f /boot/efi/EFI/redhat/grub.cfg ]; then
    chmod 0600 /boot/efi/EFI/redhat/grub.cfg && log "SUCCESS" "Set EFI grub.cfg to 0600"
elif [ -f /boot/efi/EFI/ol/grub.cfg ]; then
    chmod 0600 /boot/efi/EFI/ol/grub.cfg && log "SUCCESS" "Set EFI grub.cfg to 0600"
else
    log "WARN" "GRUB configuration file not found"
fi

# SSH configuration
log "INFO" "Setting permissions on SSH files..."
chmod 0600 /etc/ssh/sshd_config 2>/dev/null && log "SUCCESS" "Set /etc/ssh/sshd_config to 0600" || log "WARN" "Could not set SSH config"
chmod 0644 /etc/ssh/ssh_config 2>/dev/null || log "INFO" "SSH client config not found"

# Set permissions on SSH host keys
if [ -d /etc/ssh ]; then
    find /etc/ssh -name 'ssh_host_*_key' -exec chmod 0600 {} \; 2>/dev/null && log "SUCCESS" "Set SSH private keys to 0600"
    find /etc/ssh -name 'ssh_host_*_key.pub' -exec chmod 0644 {} \; 2>/dev/null && log "SUCCESS" "Set SSH public keys to 0644"
fi

# Audit configuration
log "INFO" "Setting permissions on audit files..."
chmod 0640 /etc/audit/auditd.conf 2>/dev/null && log "SUCCESS" "Set /etc/audit/auditd.conf to 0640" || log "WARN" "Could not set audit config"
chmod 0640 /etc/audit/audit.rules 2>/dev/null || log "INFO" "audit.rules not found"
chmod 0750 /etc/audit/rules.d 2>/dev/null || log "INFO" "rules.d directory not found"

if [ -d /etc/audit/rules.d ]; then
    chmod 0640 /etc/audit/rules.d/*.rules 2>/dev/null && log "SUCCESS" "Set audit rules to 0640"
fi

# Log files
log "INFO" "Setting permissions on log files..."
chmod 0640 /var/log/messages 2>/dev/null || log "INFO" "/var/log/messages not found"
chmod 0640 /var/log/secure 2>/dev/null || log "INFO" "/var/log/secure not found"
chmod 0600 /var/log/audit/audit.log 2>/dev/null || log "INFO" "audit.log not found"

# Cron files
log "INFO" "Setting permissions on cron files..."
chmod 0600 /etc/crontab 2>/dev/null && log "SUCCESS" "Set /etc/crontab to 0600" || log "WARN" "Could not set crontab"
chmod 0700 /etc/cron.d 2>/dev/null || log "INFO" "/etc/cron.d not found"
chmod 0700 /etc/cron.daily 2>/dev/null || log "INFO" "/etc/cron.daily not found"
chmod 0700 /etc/cron.hourly 2>/dev/null || log "INFO" "/etc/cron.hourly not found"
chmod 0700 /etc/cron.weekly 2>/dev/null || log "INFO" "/etc/cron.weekly not found"
chmod 0700 /etc/cron.monthly 2>/dev/null || log "INFO" "/etc/cron.monthly not found"

# Remove world-writable permissions from system files
log "INFO" "Removing world-writable permissions from system files..."
find / -xdev -type f -perm -002 -exec chmod o-w {} \; 2>/dev/null &
FIND_PID=$!
log "INFO" "Scanning for world-writable files in background (PID: $FIND_PID)"
log "INFO" "This may take several minutes..."

# Wait a bit then continue (don't block on this)
sleep 2

log "INFO" ""
log "SUCCESS" "========================================"
log "SUCCESS" "Module 6 Completed: File Permissions"
log "SUCCESS" "========================================"
log "INFO" "Log file: $LOG_FILE"
log "WARN" "World-writable file scan running in background (PID: $FIND_PID)"
log "INFO" ""
log "INFO" "Verify critical file permissions:"
log "INFO" "  ls -l /etc/passwd /etc/shadow /etc/group /etc/gshadow"
log "INFO" "  ls -l /etc/ssh/sshd_config"
log "INFO" "  ls -l /boot/grub2/grub.cfg"
