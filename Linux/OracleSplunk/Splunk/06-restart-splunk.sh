#!/bin/bash
#
# Splunk Enterprise STIG - Module 6: Restart Splunk
# Based on: U_Splunk_Enterprise_8-x_for_Linux_V2R3_Manual_STIG
# Version: 1.0
# Date: February 12, 2026
#
# This module restarts Splunk to apply all configuration changes
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/splunk-stig-06-restart-$(date +%Y%m%d-%H%M%S).log"

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
log "INFO" "Module 6: Restart Splunk"
log "INFO" "Splunk Home: $SPLUNK_HOME"
log "INFO" "========================================"

# Check if Splunk is running
log "INFO" "Checking Splunk status..."
if sudo -u splunk "$SPLUNK_HOME/bin/splunk" status &>/dev/null; then
    log "INFO" "Splunk is running"
    
    # Stop Splunk
    log "INFO" "Stopping Splunk..."
    if sudo -u splunk "$SPLUNK_HOME/bin/splunk" stop; then
        log "SUCCESS" "Splunk stopped successfully"
    else
        log "ERROR" "Failed to stop Splunk"
        exit 1
    fi
else
    log "INFO" "Splunk is not running"
fi

# Start Splunk
log "INFO" "Starting Splunk..."
if sudo -u splunk "$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes; then
    log "SUCCESS" "Splunk started successfully"
else
    log "ERROR" "Failed to start Splunk"
    log "ERROR" "Check Splunk logs: $SPLUNK_HOME/var/log/splunk/splunkd.log"
    exit 1
fi

# Verify Splunk is running
sleep 5
if sudo -u splunk "$SPLUNK_HOME/bin/splunk" status &>/dev/null; then
    log "SUCCESS" "Splunk is running"
else
    log "ERROR" "Splunk failed to start properly"
    exit 1
fi

log "INFO" ""
log "SUCCESS" "========================================"
log "SUCCESS" "Module 6 Completed: Restart Splunk"
log "SUCCESS" "========================================"
log "INFO" "Log file: $LOG_FILE"
log "INFO" ""
log "INFO" "Splunk Web Interface: https://$(hostname):8000"
log "INFO" "Default credentials: admin / changeme"
log "WARN" ""
log "WARN" "CRITICAL NEXT STEPS:"
log "WARN" "1. Change admin password immediately"
log "WARN" "2. Test web interface access"
log "WARN" "3. Verify firewall allows ports 8000 and 8089"
log "WARN" "4. Generate SSL certificates if not already done"
log "WARN" "5. Configure backups for $SPLUNK_HOME/etc"
