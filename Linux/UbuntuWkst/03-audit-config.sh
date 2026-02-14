#!/bin/bash
#
# Ubuntu 24.04 LTS STIG - Module 3: Audit Configuration
# Based on U_CAN_Ubuntu_24-04_LTS_V1R4_Manual_STIG
# Version: 1.0
# Date: February 14, 2026
#
# Usage: sudo ./03-audit-config.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/stig-audit-config-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/stig-backups/audit-$(date +%Y%m%d-%H%M%S)"

log() {
    local level=$1
    shift
    local message="$@"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" | tee -a "$LOG_FILE"
    case $level in
        ERROR) echo -e "${RED}[ERROR]${NC} $message" >&2 ;;
        SUCCESS) echo -e "${GREEN}[SUCCESS]${NC} $message" ;;
        WARN) echo -e "${YELLOW}[WARN]${NC} $message" ;;
        *) echo "[INFO] $message" ;;
    esac
}

if [ "$EUID" -ne 0 ]; then
    log "ERROR" "This script must be run as root"
    exit 1
fi

log "INFO" "========================================="
log "INFO" "Ubuntu 24.04 LTS STIG - Audit Configuration"
log "INFO" "========================================="

# Create backup
mkdir -p "$BACKUP_DIR"
cp /etc/audit/auditd.conf "$BACKUP_DIR/" 2>/dev/null || true
cp -r /etc/audit/rules.d "$BACKUP_DIR/" 2>/dev/null || true
log "SUCCESS" "Backup created: $BACKUP_DIR"

log "INFO" ""
log "INFO" "=== Installing Audit Packages ==="

# Install required packages
PACKAGES=(
    "auditd"
    "audispd-plugins"
)

for pkg in "${PACKAGES[@]}"; do
    if ! dpkg -l | grep -q "^ii  $pkg "; then
        log "INFO" "Installing $pkg..."
        apt-get update >> "$LOG_FILE" 2>&1
        apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1 && \
            log "SUCCESS" "Installed $pkg" || \
            log "ERROR" "Failed to install $pkg"
    else
        log "INFO" "$pkg already installed"
    fi
done

log "INFO" ""
log "INFO" "=== Configuring Audit Rules ==="

# Create comprehensive audit rules
cat > /etc/audit/rules.d/stig.rules << 'EOF'
# STIG Audit Rules for Ubuntu 24.04
# Based on U_CAN_Ubuntu_24-04_LTS_V1R4_Manual_STIG

# Delete all existing rules
-D

# Buffer Size
-b 8192

# Failure Mode (2 = panic on failure)
-f 2

# =======================
# Time change monitoring
# =======================
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# =======================
# User and group changes
# =======================
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# =======================
# Network environment
# =======================
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale
-w /etc/networks -p wa -k system-locale

# =======================
# MAC-policy (AppArmor)
# =======================
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

# =======================
# Login and logout events
# =======================
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# =======================
# Session initiation
# =======================
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# =======================
# Discretionary access control permission modifications
# =======================
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

# =======================
# Unauthorized file access attempts
# =======================
-a always,exit -F arch=b64 -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# =======================
# Privileged commands
# =======================
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# =======================
# File deletion events
# =======================
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# =======================
# Sudoers file changes
# =======================
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# =======================
# Kernel module loading and unloading
# =======================
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# =======================
# System administrator actions
# =======================
-w /var/log/sudo.log -p wa -k actions

# Make configuration immutable - must be last rule
-e 2
EOF

log "SUCCESS" "Created audit rules"

log "INFO" ""
log "INFO" "=== Loading Audit Rules ==="

# Enable and start auditd
systemctl enable auditd
systemctl start auditd

# Reload audit rules
augenrules --load
log "SUCCESS" "Loaded audit rules"

log "INFO" ""
log "INFO" "=== Verifying Audit Configuration ==="

# Show active rules
log "INFO" "Active audit rules count: $(auditctl -l | grep -v "No rules" | wc -l)"

log "INFO" ""
log "INFO" "========================================="
log "SUCCESS" "Audit Configuration Complete"
log "INFO" "========================================="
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "INFO" ""
log "INFO" "=== Verification Commands ==="
log "INFO" "View audit rules: auditctl -l"
log "INFO" "View audit status: auditctl -s"
log "INFO" "Search audit logs: ausearch -k <key>"
log "INFO" "Generate audit report: aureport"
