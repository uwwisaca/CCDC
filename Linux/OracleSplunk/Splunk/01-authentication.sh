#!/bin/bash
#
# Splunk Enterprise STIG - Module 1: Authentication Configuration
# Based on: U_Splunk_Enterprise_8-x_for_Linux_V2R3_Manual_STIG
# Version: 1.0
# Date: February 12, 2026
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/splunk-stig-01-auth-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/splunk-stig-backup-auth-$(date +%Y%m%d-%H%M%S)"

# Detect Splunk installation
SPLUNK_HOME="/opt/splunk"
if [ ! -d "$SPLUNK_HOME" ]; then
    SPLUNK_HOME="/opt/splunkforwarder"
fi

if [ ! -d "$SPLUNK_HOME" ]; then
    echo "ERROR: Splunk installation not found"
    exit 1
fi

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
log "INFO" "Module 1: Authentication Configuration"
log "INFO" "Splunk Home: $SPLUNK_HOME"
log "INFO" "========================================"

# Create backup
mkdir -p "$BACKUP_DIR"
cp -r "$SPLUNK_HOME/etc/system/local/authentication.conf" "$BACKUP_DIR/" 2>/dev/null || true
log "SUCCESS" "Backup created: $BACKUP_DIR"

# Create system/local directory if it doesn't exist
mkdir -p "$SPLUNK_HOME/etc/system/local"

# Configure authentication
log "INFO" "Configuring authentication settings..."

cat > "$SPLUNK_HOME/etc/system/local/authentication.conf" << 'EOF'
[authentication]
# SPLK-CL-000010 through SPLK-CL-000050: Password policy
minPasswordLength = 15
minPasswordDigit = 1
minPasswordLowercase = 1
minPasswordUppercase = 1
minPasswordSpecial = 1

# SPLK-CL-000060: Password history
passwordHistoryCount = 5

# SPLK-CL-000070: Password expiration (days)
passwordExpiration = 90

# SPLK-CL-000080: Session timeout (minutes)
sessionTimeout = 15

# SPLK-CL-000090: Failed login attempts
lockoutAttempts = 3
lockoutDuration = 15
lockoutResetTimeout = 15

# SPLK-CL-000100: Authentication method
# authType = LDAP
# Note: Configure LDAP settings separately for production

# SPLK-CL-000110: Enable TLS for web interface
enableSplunkdSSL = true

# SPLK-CL-000120: Require strong TLS
sslVersions = tls1.2, tls1.3
EOF

# Set proper ownership
chown -R splunk:splunk "$SPLUNK_HOME/etc/system/local/authentication.conf"
chmod 600 "$SPLUNK_HOME/etc/system/local/authentication.conf"

log "SUCCESS" "Authentication configured"

log "INFO" ""
log "SUCCESS" "========================================"
log "SUCCESS" "Module 1 Completed: Authentication"
log "SUCCESS" "========================================"
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "WARN" ""
log "WARN" "IMPORTANT NEXT STEPS:"
log "WARN" "1. Change admin password to meet policy"
log "WARN" "2. Configure LDAP/AD authentication if required"
log "WARN" "3. Restart Splunk to apply changes"
log "INFO" ""
log "INFO" "Restart command: $SPLUNK_HOME/bin/splunk restart"
