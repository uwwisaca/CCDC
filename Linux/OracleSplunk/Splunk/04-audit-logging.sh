#!/bin/bash
#
# Splunk Enterprise STIG - Module 4: Audit and Logging
# Based on: U_Splunk_Enterprise_8-x_for_Linux_V2R3_Manual_STIG
# Version: 1.0
# Date: February 12, 2026
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/splunk-stig-04-audit-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/splunk-stig-backup-audit-$(date +%Y%m%d-%H%M%S)"

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
log "INFO" "Module 4: Audit and Logging"
log "INFO" "Splunk Home: $SPLUNK_HOME"
log "INFO" "========================================"

# Create backup
mkdir -p "$BACKUP_DIR"
cp "$SPLUNK_HOME/etc/system/local/audit.conf" "$BACKUP_DIR/" 2>/dev/null || true
log "SUCCESS" "Backup created: $BACKUP_DIR"

# Create system/local directory if it doesn't exist
mkdir -p "$SPLUNK_HOME/etc/system/local"

# Configure audit logging
log "INFO" "Configuring audit logging..."

cat > "$SPLUNK_HOME/etc/system/local/audit.conf" << 'EOF'
[auditTrail]
# SPLK-CL-000270: Enable audit trail
disabled = false

# SPLK-CL-000280: Audit log location
directory = $SPLUNK_HOME/var/log/splunk

# SPLK-CL-000290: Audit log size (MB)
maxFileSize = 25

# SPLK-CL-000300: Total audit storage (MB)
maxTotalSizeMB = 1000

[searchActivity]
# Enable search activity logging
disabled = false
EOF

# Set proper ownership
chown splunk:splunk "$SPLUNK_HOME/etc/system/local/audit.conf"
chmod 600 "$SPLUNK_HOME/etc/system/local/audit.conf"

# Ensure audit log directory exists
mkdir -p "$SPLUNK_HOME/var/log/splunk"
chown splunk:splunk "$SPLUNK_HOME/var/log/splunk"
chmod 700 "$SPLUNK_HOME/var/log/splunk"

log "SUCCESS" "Audit logging configured"

log "INFO" ""
log "SUCCESS" "========================================"
log "SUCCESS" "Module 4 Completed: Audit and Logging"
log "SUCCESS" "========================================"
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "INFO" ""
log "INFO" "Audit logs location: $SPLUNK_HOME/var/log/splunk/audit.log"
log "INFO" "Search history logs: $SPLUNK_HOME/var/log/splunk/searches.log"
log "WARN" "Restart Splunk to apply changes"
