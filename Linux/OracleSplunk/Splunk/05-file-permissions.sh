#!/bin/bash
#
# Splunk Enterprise STIG - Module 5: File Permissions and Ownership
# Based on: U_Splunk_Enterprise_8-x_for_Linux_V2R3_Manual_STIG
# Version: 1.0
# Date: February 12, 2026
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/splunk-stig-05-permissions-$(date +%Y%m%d-%H%M%S).log"

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
log "INFO" "Module 5: File Permissions & Ownership"
log "INFO" "Splunk Home: $SPLUNK_HOME"
log "INFO" "========================================"

# Set overall ownership
log "INFO" "Setting ownership on Splunk directory..."
chown -R splunk:splunk "$SPLUNK_HOME" && log "SUCCESS" "Ownership set to splunk:splunk" || log "ERROR" "Failed to set ownership"

# Secure authentication directory
log "INFO" "Securing authentication directory..."
if [ -d "$SPLUNK_HOME/etc/auth" ]; then
    chmod 700 "$SPLUNK_HOME/etc/auth" && log "SUCCESS" "Set /etc/auth to 700"
    chown splunk:splunk "$SPLUNK_HOME/etc/auth"
    
    # Secure certificate files
    if ls "$SPLUNK_HOME/etc/auth"/*.pem 1> /dev/null 2>&1; then
        chmod 600 "$SPLUNK_HOME/etc/auth"/*.pem && log "SUCCESS" "Set certificate files to 600"
    else
        log "INFO" "No certificate files found"
    fi
else
    log "WARN" "Authentication directory not found"
fi

# Secure configuration files
log "INFO" "Securing configuration files..."
if [ -d "$SPLUNK_HOME/etc/system/local" ]; then
    chmod 600 "$SPLUNK_HOME/etc/system/local"/*.conf 2>/dev/null && log "SUCCESS" "Set config files to 600" || log "INFO" "No config files to secure"
fi

# Secure log directory
log "INFO" "Securing log directory..."
if [ -d "$SPLUNK_HOME/var/log/splunk" ]; then
    chmod 700 "$SPLUNK_HOME/var/log/splunk" && log "SUCCESS" "Set log directory to 700"
    chown splunk:splunk "$SPLUNK_HOME/var/log/splunk"
else
    log "WARN" "Log directory not found"
fi

# Secure private keys
log "INFO" "Securing private key files..."
find "$SPLUNK_HOME" -name "*.key" -type f -exec chmod 600 {} \; 2>/dev/null && log "SUCCESS" "Secured private keys" || log "INFO" "No private keys found"

# Secure password files
log "INFO" "Securing password files..."
if [ -f "$SPLUNK_HOME/etc/passwd" ]; then
    chmod 600 "$SPLUNK_HOME/etc/passwd" && log "SUCCESS" "Secured passwd file"
fi

# Remove world-readable/writable permissions from sensitive areas
log "INFO" "Removing world permissions from sensitive files..."
find "$SPLUNK_HOME/etc" -type f -exec chmod o-rwx {} \; 2>/dev/null &
FIND_PID=$!
log "INFO" "Removing world permissions in background (PID: $FIND_PID)"

log "INFO" ""
log "SUCCESS" "========================================"
log "SUCCESS" "Module 5 Completed: File Permissions"
log "SUCCESS" "========================================"
log "INFO" "Log file: $LOG_FILE"
log "INFO" ""
log "INFO" "Verify critical permissions:"
log "INFO" "  ls -ld $SPLUNK_HOME/etc/auth"
log "INFO" "  ls -l $SPLUNK_HOME/etc/auth/*.pem"
log "INFO" "  ls -l $SPLUNK_HOME/etc/system/local/*.conf"
