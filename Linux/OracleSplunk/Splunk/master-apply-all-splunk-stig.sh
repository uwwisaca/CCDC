#!/bin/bash
#
# Splunk Enterprise STIG - Master Orchestration Script
# Based on: U_Splunk_Enterprise_8-x_for_Linux_V2R3_Manual_STIG
# Version: 1.0
# Date: February 12, 2026
#
# This script runs all Splunk STIG modules in the correct order
# Usage: sudo ./master-apply-all-splunk-stig.sh [options]
#
# Options:
#   --no-restart        Don't restart Splunk at the end
#   --module <N>        Run only a specific module (01-06)
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/splunk-stig-master-$(date +%Y%m%d-%H%M%S).log"
NO_RESTART=false
RUN_MODULE=""

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
        INFO) echo -e "${BLUE}[INFO]${NC} $message" ;;
    esac
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --no-restart)
            NO_RESTART=true
            shift
            ;;
        --module)
            RUN_MODULE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--no-restart] [--module <N>]"
            exit 1
            ;;
    esac
done

if [ "$EUID" -ne 0 ]; then
    log "ERROR" "This script must be run as root"
    exit 1
fi

log "INFO" "================================================================"
log "INFO" "  Splunk Enterprise STIG - Master Application Script"
log "INFO" "================================================================"
log "INFO" "Start time: $(date)"
log "INFO" "Splunk Home: $SPLUNK_HOME"
log "INFO" "Log file: $LOG_FILE"
log "INFO" ""

# Define modules
declare -A MODULES
MODULES=(
    ["01"]="01-authentication.sh|Authentication Configuration"
    ["02"]="02-ssl-tls.sh|SSL/TLS Configuration"
    ["03"]="03-web-interface.sh|Web Interface Security"
    ["04"]="04-audit-logging.sh|Audit and Logging"
    ["05"]="05-file-permissions.sh|File Permissions"
    ["06"]="06-restart-splunk.sh|Restart Splunk"
)

# Run a single module
run_module() {
    local module_num=$1
    local module_info=${MODULES[$module_num]}
    local script_name=$(echo "$module_info" | cut -d'|' -f1)
    local description=$(echo "$module_info" | cut -d'|' -f2)
    
    # Skip restart if requested
    if [ "$NO_RESTART" = true ] && [ "$module_num" = "06" ]; then
        log "WARN" "Skipping Module $module_num: $description (--no-restart specified)"
        return 0
    fi
    
    log "INFO" ""
    log "INFO" "================================================================"
    log "INFO" "  Running Module $module_num: $description"
    log "INFO" "================================================================"
    
    if [ ! -f "$SCRIPT_DIR/$script_name" ]; then
        log "ERROR" "Module script not found: $SCRIPT_DIR/$script_name"
        return 1
    fi
    
    if [ ! -x "$SCRIPT_DIR/$script_name" ]; then
        log "INFO" "Making $script_name executable..."
        chmod +x "$SCRIPT_DIR/$script_name"
    fi
    
    if bash "$SCRIPT_DIR/$script_name" >> "$LOG_FILE" 2>&1; then
        log "SUCCESS" "Module $module_num completed successfully"
        return 0
    else
        log "ERROR" "Module $module_num failed"
        return 1
    fi
}

# Run single module if specified
if [ -n "$RUN_MODULE" ]; then
    log "INFO" "Running single module: $RUN_MODULE"
    run_module "$RUN_MODULE"
    exit $?
fi

# Run all modules
log "INFO" "Running all Splunk STIG modules..."
log "INFO" ""

FAILED_MODULES=()
for module_num in $(echo "${!MODULES[@]}" | tr ' ' '\n' | sort); do
    if ! run_module "$module_num"; then
        FAILED_MODULES+=("$module_num")
        log "ERROR" "Module $module_num failed - continuing with next module"
    fi
    sleep 2
done

# Summary
log "INFO" ""
log "INFO" "================================================================"
log "INFO" "  Splunk STIG Application Complete"
log "INFO" "================================================================"
log "INFO" "End time: $(date)"
log "INFO" "Log file: $LOG_FILE"

if [ ${#FAILED_MODULES[@]} -eq 0 ]; then
    log "SUCCESS" "All modules completed successfully!"
else
    log "ERROR" "The following modules failed: ${FAILED_MODULES[*]}"
    log "ERROR" "Review the log file for details: $LOG_FILE"
fi

log "INFO" ""
log "INFO" "================================================================"
log "INFO" "  NEXT STEPS"
log "INFO" "================================================================"
log "INFO" "1. Access Splunk Web: https://$(hostname):8000"
log "INFO" "2. Login with admin account"
log "INFO" "3. IMMEDIATELY change admin password to meet policy:"
log "INFO" "   - Minimum 15 characters"
log "INFO" "   - At least 1 uppercase, 1 lowercase, 1 digit, 1 special char"
log "INFO" "4. Generate SSL certificates:"
log "INFO" "   cd $SPLUNK_HOME/etc/auth"
log "INFO" "   sudo -u splunk $SPLUNK_HOME/bin/splunk createssl server-cert"
log "INFO" "5. Change pass4SymmKey in server.conf"
log "INFO" "6. Configure LDAP/AD authentication if required"
log "INFO" "7. Set up role-based access control (RBAC)"
log "INFO" "8. Configure data inputs and forwarding"
log "INFO" "9. Set up backup procedures for $SPLUNK_HOME/etc"
log "INFO" "10. Review audit logs regularly"
log "INFO" ""
log "INFO" "Verify configuration with:"
log "INFO" "  $SPLUNK_HOME/bin/splunk btool check"

exit 0
