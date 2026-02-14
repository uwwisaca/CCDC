#!/bin/bash
#
# Ubuntu 24.04 LTS STIG - Module 5: Firewall and Services
# Based on U_CAN_Ubuntu_24-04_LTS_V1R4_Manual_STIG
# Version: 1.0
# Date: February 14, 2026
#
# Usage: sudo ./05-firewall-services.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/stig-firewall-services-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/stig-backups/firewall-$(date +%Y%m%d-%H%M%S)"

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
log "INFO" "Ubuntu 24.04 LTS STIG - Firewall & Services"
log "INFO" "========================================="

# Create backup
mkdir -p "$BACKUP_DIR"
ufw status verbose > "$BACKUP_DIR/ufw-status.txt" 2>/dev/null || true
log "SUCCESS" "Backup created: $BACKUP_DIR"

log "INFO" ""
log "INFO" "=== Installing UFW ==="

if ! dpkg -l | grep -q "^ii  ufw "; then
    log "INFO" "Installing ufw..."
    apt-get update >> "$LOG_FILE" 2>&1
    apt-get install -y ufw >> "$LOG_FILE" 2>&1
    log "SUCCESS" "Installed ufw"
else
    log "INFO" "UFW already installed"
fi

log "INFO" ""
log "INFO" "=== Configuring UFW Firewall ==="

# Reset UFW to default
ufw --force reset >> "$LOG_FILE" 2>&1

# Set default policies
ufw default deny incoming
ufw default allow outgoing
ufw default deny routed

# Enable logging
ufw logging on

# Allow SSH (adjust port if needed)
ufw allow 22/tcp comment 'SSH'

# Add common service rules (uncomment as needed)
# ufw allow 80/tcp comment 'HTTP'
# ufw allow 443/tcp comment 'HTTPS'

# Enable UFW
ufw --force enable

log "SUCCESS" "Configured UFW firewall"

log "INFO" ""
log "INFO" "=== Disabling Unnecessary Services ==="

# List of services to disable
SERVICES_TO_DISABLE=(
    "avahi-daemon"
    "cups"
    "cups-browsed"
    "bluetooth"
    "iscsid"
    "rpcbind"
)

for service in "${SERVICES_TO_DISABLE[@]}"; do
    if systemctl list-unit-files | grep -q "^$service"; then
        if systemctl is-enabled "$service" 2>/dev/null | grep -q "enabled"; then
            systemctl disable "$service" >> "$LOG_FILE" 2>&1
            systemctl stop "$service" >> "$LOG_FILE" 2>&1
            log "SUCCESS" "Disabled and stopped $service"
        else
            log "INFO" "$service already disabled"
        fi
    else
        log "INFO" "$service not found on system"
    fi
done

log "INFO" ""
log "INFO" "=== Verifying Firewall Status ==="

ufw status verbose | tee -a "$LOG_FILE"

log "INFO" ""
log "INFO" "========================================="
log "SUCCESS" "Firewall & Services Configuration Complete"
log "INFO" "========================================="
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "INFO" ""
log "INFO" "=== Applied Settings Summary ==="
log "INFO" "- Default incoming: DENY"
log "INFO" "- Default outgoing: ALLOW"
log "INFO" "- SSH allowed on port 22"
log "INFO" "- Logging enabled"
log "INFO" "- Unnecessary services disabled"
log "WARN" ""
log "WARN" "=== IMPORTANT ==="
log "WARN" "Add firewall rules for your services:"
log "WARN" "  sudo ufw allow <port>/tcp comment 'Service Name'"
log "WARN" "View rules: sudo ufw status numbered"
log "WARN" "Delete rule: sudo ufw delete <number>"
