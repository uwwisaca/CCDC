#!/bin/bash
#
# RHEL 9 / Fedora STIG - Master Orchestration Script
# Based on: U_RHEL_9_V2R7_Manual_STIG
# Version: 1.0
# Date: February 12, 2026
#
# This script runs all STIG modules in the correct order
# Usage: sudo ./master-apply-all-stig.sh [options]
#
# Options:
#   --skip-firewall     Skip firewall configuration and enabling
#   --no-reboot         Don't prompt for reboot at the end
#   --module <N>        Run only a specific module (01-09)
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/rhel9-stig-master-$(date +%Y%m%d-%H%M%S).log"
SKIP_FIREWALL=false
NO_REBOOT=false
RUN_MODULE=""

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
        --skip-firewall)
            SKIP_FIREWALL=true
            shift
            ;;
        --no-reboot)
            NO_REBOOT=true
            shift
            ;;
        --module)
            RUN_MODULE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--skip-firewall] [--no-reboot] [--module <N>]"
            exit 1
            ;;
    esac
done

if [ "$EUID" -ne 0 ]; then
    log "ERROR" "This script must be run as root"
    exit 1
fi

log "INFO" "================================================================"
log "INFO" "  RHEL 9 / Fedora STIG - Master Application Script"
log "INFO" "  For Mailserver"
log "INFO" "================================================================"
log "INFO" "Start time: $(date)"
log "INFO" "Log file: $LOG_FILE"
log "INFO" ""

# Detect distribution
if [ -f /etc/redhat-release ]; then
    DISTRO=$(cat /etc/redhat-release)
    log "INFO" "Detected distribution: $DISTRO"
else
    log "WARN" "Could not detect Red Hat based distribution"
fi

# Define modules
declare -A MODULES
MODULES=(
    ["01"]="01-password-policies.sh|Password Policies"
    ["02"]="02-ssh-hardening.sh|SSH Hardening"
    ["03"]="03-audit-config.sh|Audit Configuration"
    ["04"]="04-kernel-params.sh|Kernel Parameters"
    ["05"]="05-selinux-config.sh|SELinux Configuration"
    ["06"]="06-file-permissions.sh|File Permissions"
    ["07"]="07-services-config.sh|Services Configuration"
    ["08"]="08-firewall-rules-mailserver.sh|Firewall Rules (Mailserver)"
    ["09"]="09-firewall-enable.sh|Enable Firewall"
)

# Run a single module
run_module() {
    local module_num=$1
    local module_info=${MODULES[$module_num]}
    local script_name=$(echo "$module_info" | cut -d'|' -f1)
    local description=$(echo "$module_info" | cut -d'|' -f2)
    
    # Skip firewall modules if requested
    if [ "$SKIP_FIREWALL" = true ] && ( [ "$module_num" = "08" ] || [ "$module_num" = "09" ] ); then
        log "WARN" "Skipping Module $module_num: $description (--skip-firewall specified)"
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
log "INFO" "Running all STIG modules..."
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
log "INFO" "  STIG Application Complete"
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
log "INFO" "1. Review the log file: $LOG_FILE"
log "INFO" "2. Check all module-specific logs in /var/log/"
log "INFO" "3. Test SSH access from another terminal"
log "INFO" "4. Verify firewall rules: firewall-cmd --list-all"
log "INFO" "5. Edit 08-firewall-rules-mailserver.sh to uncomment mail ports"
log "INFO" "6. Rerun firewall modules if you changed mail ports:"
log "INFO" "   ./master-apply-all-stig.sh --module 08"
log "INFO" "   ./master-apply-all-stig.sh --module 09"
log "INFO" "7. Configure mail server application (Postfix, Dovecot, etc.)"
log "INFO" "8. Verify services: systemctl status auditd rsyslog chronyd"
log "INFO" "9. Check SELinux: sestatus"
log "INFO" "10. Run compliance scan:"
log "INFO" "    oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig \\"
log "INFO" "    --results-arf /tmp/results.xml --report /tmp/report.html \\"
log "INFO" "    /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml"
log "WARN" ""
log "WARN" "  SYSTEM REBOOT RECOMMENDED"
log "WARN" "  Some settings require a reboot to take full effect"
log "WARN" ""

if [ "$NO_REBOOT" = false ]; then
    read -p "Reboot now? (yes/NO): " response
    if [ "$response" = "yes" ]; then
        log "INFO" "Rebooting system..."
        reboot
    fi
fi

exit 0
