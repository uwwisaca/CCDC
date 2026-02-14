#!/bin/bash
#
# Ubuntu 24.04 LTS STIG - Module 6: File Permissions & AppArmor
# Based on U_CAN_Ubuntu_24-04_LTS_V1R4_Manual_STIG
# Version: 1.0
# Date: February 14, 2026
#
# Usage: sudo ./06-file-permissions-apparmor.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/stig-file-perms-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/stig-backups/file-perms-$(date +%Y%m%d-%H%M%S)"

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
log "INFO" "Ubuntu 24.04 LTS STIG - File Permissions & AppArmor"
log "INFO" "========================================="

# Create backup
mkdir -p "$BACKUP_DIR"
log "SUCCESS" "Backup directory created: $BACKUP_DIR"

log "INFO" ""
log "INFO" "=== Setting Critical File Permissions ==="

# System files permissions
FILES=(
    "/etc/passwd:644"
    "/etc/shadow:600"
    "/etc/group:644"
    "/etc/gshadow:600"
    "/etc/passwd-:644"
    "/etc/shadow-:600"
    "/etc/group-:644"
    "/etc/gshadow-:600"
)

for item in "${FILES[@]}"; do
    file=$(echo "$item" | cut -d: -f1)
    perm=$(echo "$item" | cut -d: -f2)
    
    if [ -f "$file" ]; then
        # Backup original permissions
        stat "$file" > "$BACKUP_DIR/$(basename $file).stat" 2>/dev/null || true
        
        # Set new permissions
        chmod "$perm" "$file"
        log "SUCCESS" "Set $file to $perm"
    else
        log "WARN" "File not found: $file"
    fi
done

log "INFO" ""
log "INFO" "=== Installing AppArmor ==="

PACKAGES=(
    "apparmor"
    "apparmor-utils"
    "apparmor-profiles"
    "apparmor-profiles-extra"
)

for pkg in "${PACKAGES[@]}"; do
    if ! dpkg -l | grep -q "^ii  $pkg "; then
        log "INFO" "Installing $pkg..."
        apt-get update >> "$LOG_FILE" 2>&1
        apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1 && \
            log "SUCCESS" "Installed $pkg" || \
            log "WARN" "Could not install $pkg"
    else
        log "INFO" "$pkg already installed"
    fi
done

log "INFO" ""
log "INFO" "=== Configuring AppArmor ==="

# Enable AppArmor
systemctl enable apparmor
systemctl start apparmor

# Set profiles to enforce mode
log "INFO" "Setting AppArmor profiles to enforce mode..."
aa-enforce /etc/apparmor.d/* 2>&1 | tee -a "$LOG_FILE" | grep -v "Warning" || true

# Check AppArmor status
if aa-status >> "$LOG_FILE" 2>&1; then
    loaded=$(aa-status 2>/dev/null | grep "profiles are loaded" | awk '{print $1}')
    enforce=$(aa-status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}')
    log "SUCCESS" "AppArmor configured: $loaded loaded, $enforce in enforce mode"
else
    log "WARN" "Could not get AppArmor status"
fi

log "INFO" ""
log "INFO" "=== Installing AIDE (File Integrity) ==="

if ! dpkg -l | grep -q "^ii  aide "; then
    log "INFO" "Installing aide and aide-common..."
    apt-get update >> "$LOG_FILE" 2>&1
    apt-get install -y aide aide-common >> "$LOG_FILE" 2>&1
    log "SUCCESS" "Installed AIDE"
    log "WARN" "Initialize AIDE database manually: aideinit"
else
    log "INFO" "AIDE already installed"
fi

log "INFO" ""
log "INFO" "=== Setting Secure Boot Settings ==="

# Ensure grub password protection (requires manual setup)
if [ -f /etc/grub.d/40_custom ]; then
    log "INFO" "GRUB configuration found"
    log "WARN" "Set GRUB password manually: grub-mkpasswd-pbkdf2"
fi

log "INFO" ""
log "INFO" "========================================="
log "SUCCESS" "File Permissions & AppArmor Complete"
log "INFO" "========================================="
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "INFO" ""
log "INFO" "=== Applied Settings Summary ==="
log "INFO" "- Critical file permissions set (/etc/passwd, /etc/shadow, etc.)"
log "INFO" "- AppArmor installed and enabled"
log "INFO" "- AppArmor profiles set to enforce mode"
log "INFO" "- AIDE (file integrity checker) installed"
log "WARN" ""
log "WARN" "=== IMPORTANT NEXT STEPS ==="
log "WARN" "1. Initialize AIDE database:"
log "WARN" "   sudo aideinit"
log "WARN" "   sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
log "WARN" ""
log "WARN" "2. Check file integrity regularly:"
log "WARN" "   sudo aide --check"
log "WARN" ""
log "WARN" "3. View AppArmor status:"
log "WARN" "   sudo aa-status"
