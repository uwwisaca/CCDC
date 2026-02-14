#!/bin/bash
#
# Ubuntu 24.04 LTS STIG - Module 7: Automatic Updates
# Based on U_CAN_Ubuntu_24-04_LTS_V1R4_Manual_STIG
# Version: 1.0
# Date: February 14, 2026
#
# Usage: sudo ./07-automatic-updates.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/stig-updates-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/stig-backups/updates-$(date +%Y%m%d-%H%M%S)"

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
log "INFO" "Ubuntu 24.04 LTS STIG - Automatic Updates"
log "INFO" "========================================="

# Create backup
mkdir -p "$BACKUP_DIR"
cp -r /etc/apt/apt.conf.d "$BACKUP_DIR/" 2>/dev/null || true
log "SUCCESS" "Backup created: $BACKUP_DIR"

log "INFO" ""
log "INFO" "=== Installing Unattended Upgrades ==="

# Install unattended-upgrades
PACKAGES=(
    "unattended-upgrades"
    "apt-listchanges"
)

for pkg in "${PACKAGES[@]}"; do
    if ! dpkg -l | grep -q "^ii  $pkg "; then
        log "INFO" "Installing $pkg..."
        apt-get update >> "$LOG_FILE" 2>&1
        apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1
        log "SUCCESS" "Installed $pkg"
    else
        log "INFO" "$pkg already installed"
    fi
done

log "INFO" ""
log "INFO" "=== Configuring Automatic Updates ==="

# Configure unattended-upgrades
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
// Automatically upgrade packages from security repositories
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    // "${distro_id}:${distro_codename}-updates";
};

// Package blacklist (packages that should not be automatically upgraded)
Unattended-Upgrade::Package-Blacklist {
    // "vim";
    // "postgresql";
};

// Auto-fix interrupted dpkg on unattended upgrade
Unattended-Upgrade::AutoFixInterruptedDpkg "true";

// Minimal steps
Unattended-Upgrade::MinimalSteps "true";

// Install updates on shutdown instead of background
// Unattended-Upgrade::InstallOnShutdown "false";

// Send email to root on errors
// Unattended-Upgrade::Mail "root";
// Unattended-Upgrade::MailReport "on-change";

// Remove unused automatically installed kernel-related packages
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";

// Remove unused dependencies
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// Automatic reboot (disabled by default for safety)
Unattended-Upgrade::Automatic-Reboot "false";

// If automatic reboot is enabled, set the time
Unattended-Upgrade::Automatic-Reboot-Time "03:00";

// Automatic reboot even if users are logged in
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";

// Enable logging to syslog
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";
EOF

log "SUCCESS" "Configured unattended-upgrades"

# Configure automatic update intervals
cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
// Enable the update/upgrade script (0=disable)
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

log "SUCCESS" "Configured automatic update intervals"

log "INFO" ""
log "INFO" "=== Installing Fail2Ban ==="

if ! dpkg -l | grep -q "^ii  fail2ban "; then
    log "INFO" "Installing fail2ban..."
    apt-get install -y fail2ban >> "$LOG_FILE" 2>&1
    
    # Create local jail configuration
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 3

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
EOF
    
    systemctl enable fail2ban
    systemctl restart fail2ban
    log "SUCCESS" "Installed and configured fail2ban"
else
    log "INFO" "fail2ban already installed"
fi

log "INFO" ""
log "INFO" "=== Testing Configuration ==="

# Test unattended-upgrades
if unattended-upgrades --dry-run >> "$LOG_FILE" 2>&1; then
    log "SUCCESS" "Unattended-upgrades test passed"
else
    log "ERROR" "Unattended-upgrades test failed"
fi

log "INFO" ""
log "INFO" "========================================="
log "SUCCESS" "Automatic Updates Configuration Complete"
log "INFO" "========================================="
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "INFO" ""
log "INFO" "=== Applied Settings Summary ==="
log "INFO" "- Automatic security updates enabled"
log "INFO" "- Package list updates: daily"
log "INFO" "- Auto-cleanup: weekly"
log "INFO" "- Unused packages: auto-remove enabled"
log "INFO" "- Old kernels: auto-remove enabled"
log "INFO" "- Automatic reboot: DISABLED (configure if needed)"
log "INFO" "- Fail2ban installed and configured"
log "INFO" ""
log "INFO" "=== Verification Commands ==="
log "INFO" "Check update status: sudo unattended-upgrades --dry-run"
log "INFO" "View update logs: /var/log/unattended-upgrades/"
log "INFO" "Fail2ban status: sudo fail2ban-client status"
log "INFO" "Fail2ban sshd jail: sudo fail2ban-client status sshd"
