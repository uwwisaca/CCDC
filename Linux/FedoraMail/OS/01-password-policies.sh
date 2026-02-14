#!/bin/bash
#
# RHEL 9 / Fedora STIG - Module 1: Password Policies
# Based on: U_RHEL_9_V2R7_Manual_STIG
# Version: 1.0
# Date: February 12, 2026
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/rhel9-stig-01-password-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/rhel9-stig-backup-password-$(date +%Y%m%d-%H%M%S)"

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
log "INFO" "Module 1: Password Policies"
log "INFO" "========================================"

# Create backup directory
mkdir -p "$BACKUP_DIR"
cp -p /etc/security/pwquality.conf "$BACKUP_DIR/" 2>/dev/null || true
cp -p /etc/login.defs "$BACKUP_DIR/" 2>/dev/null || true
cp -p /etc/pam.d/system-auth "$BACKUP_DIR/" 2>/dev/null || true
cp -p /etc/pam.d/password-auth "$BACKUP_DIR/" 2>/dev/null || true
log "SUCCESS" "Backup created: $BACKUP_DIR"

# Install required packages
log "INFO" "Installing libpwquality..."
dnf install -y libpwquality || log "WARN" "Package may already be installed"

# Configure password quality
log "INFO" "Configuring password quality requirements..."
cat > /etc/security/pwquality.conf << 'EOF'
# RHEL 9 STIG Password Quality Configuration

# RHEL-09-611010: Minimum length
minlen = 15

# RHEL-09-611015: Minimum uppercase characters
ucredit = -1

# RHEL-09-611020: Minimum lowercase characters
lcredit = -1

# RHEL-09-611025: Minimum numeric characters
dcredit = -1

# RHEL-09-611030: Minimum special characters
ocredit = -1

# RHEL-09-611035: Minimum character classes
minclass = 4

# RHEL-09-611040: Maximum repeat characters
maxrepeat = 3

# RHEL-09-611045: Maximum same class repeat
maxclassrepeat = 4

# RHEL-09-611050: Dictionary checking
dictcheck = 1

# RHEL-09-611055: Enforce for root
enforce_for_root

# RHEL-09-611060: Number of retry attempts
retry = 3

# RHEL-09-611065: Minimum different characters from old password
difok = 8
EOF

log "SUCCESS" "Password quality configured"

# Configure password aging in login.defs
log "INFO" "Configuring password aging..."
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   60/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    15/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs

log "SUCCESS" "Password aging configured"

log "INFO" ""
log "SUCCESS" "========================================"
log "SUCCESS" "Module 1 Completed: Password Policies"
log "SUCCESS" "========================================"
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "WARN" "Note: Existing user accounts must be updated manually:"
log "WARN" "  chage -d 0 <username>  # Force password change"
log "WARN" "  chage -M 60 -m 1 -W 7 <username>  # Set password aging"
