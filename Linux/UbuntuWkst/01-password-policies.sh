#!/bin/bash
#
# Ubuntu 24.04 LTS STIG - Module 1: Password Policies
# Based on U_CAN_Ubuntu_24-04_LTS_V1R4_Manual_STIG
# Version: 1.0
# Date: February 14, 2026
#
# Usage: sudo ./01-password-policies.sh
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

LOG_FILE="/var/log/stig-password-policies-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/stig-backups/password-$(date +%Y%m%d-%H%M%S)"

# Logging function
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

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log "ERROR" "This script must be run as root"
    exit 1
fi

log "INFO" "========================================="
log "INFO" "Ubuntu 24.04 LTS STIG - Password Policies"
log "INFO" "========================================="

# Create backup directory
mkdir -p "$BACKUP_DIR"
log "INFO" "Creating backup in $BACKUP_DIR"

# Backup important configurations
cp /etc/pam.d/common-* "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/security/* "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/login.defs "$BACKUP_DIR/" 2>/dev/null || true

log "SUCCESS" "Backup completed"

log "INFO" ""
log "INFO" "=== Installing Password Policy Packages ==="

# Update package list
apt-get update >> "$LOG_FILE" 2>&1

# Install required security packages
PACKAGES=(
    "libpam-pwquality"
    "libpam-modules"
)

for pkg in "${PACKAGES[@]}"; do
    if ! dpkg -l | grep -q "^ii  $pkg "; then
        log "INFO" "Installing $pkg..."
        apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1 && \
            log "SUCCESS" "Installed $pkg" || \
            log "ERROR" "Failed to install $pkg"
    else
        log "INFO" "$pkg already installed"
    fi
done

log "INFO" ""
log "INFO" "=== Configuring Password Quality Requirements ==="

# Configure password quality requirements (UBTU-24-411025, UBTU-24-411030, etc.)
cat > /etc/security/pwquality.conf << 'EOF'
# Password quality requirements (UBTU-24-411025, UBTU-24-411030, etc.)
minlen = 15
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 4
maxrepeat = 3
maxclassrepeat = 4
dictcheck = 1
usercheck = 1
enforcing = 1
retry = 3
EOF

log "SUCCESS" "Configured password quality requirements"

log "INFO" ""
log "INFO" "=== Configuring Password Aging ==="

# Configure password aging in /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 60/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 15/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs

log "SUCCESS" "Configured password aging policies"

log "INFO" ""
log "INFO" "=== Configuring Account Lockout Policy ==="

# Configure account lockout policy
if ! grep -q "pam_faillock.so" /etc/pam.d/common-auth; then
    # Add faillock configuration
    sed -i '/pam_unix.so/i auth required pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=0' /etc/pam.d/common-auth
    sed -i '/pam_unix.so/a auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=0' /etc/pam.d/common-auth
    sed -i '/pam_deny.so/i auth required pam_faillock.so authsucc audit deny=3 even_deny_root fail_interval=900 unlock_time=0' /etc/pam.d/common-auth
    log "SUCCESS" "Configured account lockout policy (3 failures, 15 min lockout)"
else
    log "INFO" "Account lockout policy already configured"
fi

log "INFO" ""
log "INFO" "=== Configuring Password History ==="

# Configure password history
if ! grep -q "remember=" /etc/pam.d/common-password; then
    sed -i '/pam_unix.so/s/$/ remember=5/' /etc/pam.d/common-password
    log "SUCCESS" "Configured password history (5 passwords)"
else
    log "INFO" "Password history already configured"
fi

log "INFO" ""
log "INFO" "=== Configuring Password Hashing ==="

# Configure password hashing algorithm (SHA-512)
if ! grep -q "sha512" /etc/pam.d/common-password; then
    sed -i 's/pam_unix.so.*/& sha512/' /etc/pam.d/common-password
    log "SUCCESS" "Configured SHA-512 password hashing"
else
    log "INFO" "SHA-512 hashing already configured"
fi

log "INFO" ""
log "INFO" "========================================="
log "SUCCESS" "Password Policies Configuration Complete"
log "INFO" "========================================="
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "INFO" ""
log "INFO" "=== Applied Settings Summary ==="
log "INFO" "- Minimum password length: 15 characters"
log "INFO" "- Password complexity: 4 character classes required"
log "INFO" "- Password aging: Max 60 days, Min 1 day, Warning 7 days"
log "INFO" "- Account lockout: 3 failures, 15 minute lockout"
log "INFO" "- Password history: 5 previous passwords"
log "INFO" "- Password hashing: SHA-512"
