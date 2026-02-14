#!/bin/bash
#
# Oracle Linux 9 STIG - Module 3: Audit Configuration
# Based on: U_Oracle_Linux_9_V1R4_Manual_STIG
# Version: 1.0
# Date: February 12, 2026
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/oracle-linux-stig-03-audit-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/oracle-linux-stig-backup-audit-$(date +%Y%m%d-%H%M%S)"

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
log "INFO" "Module 3: Audit Configuration"
log "INFO" "========================================"

# Create backup directory
mkdir -p "$BACKUP_DIR"
cp -p /etc/audit/auditd.conf "$BACKUP_DIR/" 2>/dev/null || true
cp -rp /etc/audit/rules.d "$BACKUP_DIR/" 2>/dev/null || true
log "SUCCESS" "Backup created: $BACKUP_DIR"

# Install audit packages
log "INFO" "Installing audit packages..."
dnf install -y audit audispd-plugins || log "WARN" "Packages may already be installed"

# Configure auditd
log "INFO" "Configuring audit daemon..."
cat > /etc/audit/auditd.conf << 'EOF'
# Oracle Linux 9 STIG Audit Configuration

log_file = /var/log/audit/audit.log
log_format = ENRICHED
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 10
num_logs = 5
priority_boost = 4
name_format = HOSTNAME
max_log_file_action = ROTATE

# Space management
space_left = 250
space_left_action = EMAIL
verify_email = yes
action_mail_acct = root
admin_space_left = 100
admin_space_left_action = HALT
disk_full_action = HALT
disk_error_action = HALT

# Performance
disp_qos = lossy
dispatcher = /sbin/audispd
EOF

log "SUCCESS" "Audit daemon configured"

# Configure audit rules
log "INFO" "Configuring audit rules..."
cat > /etc/audit/rules.d/stig.rules << 'EOF'
## Oracle Linux 9 STIG Audit Rules

# Remove any existing rules
-D

# Buffer size
-b 8192

# Failure mode (2 = panic on failure)
-f 2

# Monitor time changes
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# Monitor user/group changes
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Monitor network environment
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

# Monitor SELinux events
-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/share/selinux/ -p wa -k MAC-policy

# Monitor login/logout events
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# Monitor session initiation
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# Monitor permission changes
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod

# Monitor unauthorized access attempts
-a always,exit -F arch=b64 -S open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access

# Monitor privileged commands
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=unset -k privileged

# Monitor file deletion
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete

# Monitor sudoers
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions

# Monitor kernel module operations
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,delete_module -k modules

# Make configuration immutable (must be last)
-e 2
EOF

log "SUCCESS" "Audit rules configured"

# Enable and start auditd
log "INFO" "Enabling audit service..."
systemctl enable auditd
systemctl restart auditd

# Load audit rules
log "INFO" "Loading audit rules..."
augenrules --load

log "SUCCESS" "Audit service enabled and started"

log "INFO" ""
log "SUCCESS" "========================================"
log "SUCCESS" "Module 3 Completed: Audit Configuration"
log "SUCCESS" "========================================"
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "INFO" "Verify audit rules: auditctl -l"
