#!/bin/bash
#
# RHEL 9 / Fedora STIG - Module 7: Services Configuration
# Based on: U_RHEL_9_V2R7_Manual_STIG
# Version: 1.0
# Date: February 12, 2026
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/rhel9-stig-07-services-$(date +%Y%m%d-%H%M%S).log"

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
log "INFO" "Module 7: Services Configuration"
log "INFO" "========================================"

# Install required services
log "INFO" "Installing required services..."
dnf install -y rsyslog chrony aide || log "WARN" "Some packages may already be installed"

# Enable and start essential services
log "INFO" "Enabling essential services..."

log "INFO" "Enabling auditd..."
systemctl enable auditd 2>/dev/null && log "SUCCESS" "auditd enabled" || log "WARN" "Could not enable auditd"

log "INFO" "Enabling rsyslog..."
systemctl enable rsyslog 2>/dev/null && log "SUCCESS" "rsyslog enabled" || log "WARN" "Could not enable rsyslog"
systemctl start rsyslog 2>/dev/null || log "INFO" "rsyslog already running"

log "INFO" "Enabling chronyd..."
systemctl enable chronyd 2>/dev/null && log "SUCCESS" "chronyd enabled" || log "WARN" "Could not enable chronyd"
systemctl start chronyd 2>/dev/null || log "INFO" "chronyd already running"

# Disable unnecessary services
log "INFO" "Disabling unnecessary services..."

SERVICES_TO_DISABLE=(
    "rpcbind"
    "nfs-server"
    "nfs-client.target"
    "ypserv"
    "ypbind"
    "tftp"
    "tftp.socket"
    "certmonger"
    "cgconfig"
    "cgred"
    "cpupower"
    "kdump"
    "mdmonitor"
    "netcf-transaction"
    "nfs-lock"
    "quota_nld"
    "rdisc"
    "rhnsd"
    "rhsmcertd"
    "saslauthd"
    "smartd"
    "sysstat"
    "sysstat-collect.timer"
    "sysstat-summary.timer"
    "bluetooth"
    "cups"
    "avahi-daemon"
)

for service in "${SERVICES_TO_DISABLE[@]}"; do
    if systemctl is-enabled "$service" &>/dev/null; then
        systemctl disable "$service" 2>/dev/null && log "SUCCESS" "Disabled $service" || log "INFO" "$service already disabled"
        systemctl stop "$service" 2>/dev/null || log "INFO" "$service not running"
    else
        log "INFO" "$service not found or already disabled"
    fi
done

# Configure automatic updates
log "INFO" "Configuring automatic security updates..."
dnf install -y dnf-automatic || log "WARN" "dnf-automatic may already be installed"

cat > /etc/dnf/automatic.conf << 'EOF'
[commands]
upgrade_type = security
download_updates = yes
apply_updates = yes

[emitters]
emit_via = stdio

[email]
email_from = root@localhost
email_to = root
email_host = localhost

[base]
debuglevel = 1
EOF

systemctl enable dnf-automatic.timer 2>/dev/null && log "SUCCESS" "Automatic updates enabled" || log "WARN" "Could not enable automatic updates"
systemctl start dnf-automatic.timer 2>/dev/null || log "INFO" "Automatic updates timer started"

# Configure chrony (NTP)
log "INFO" "Configuring time synchronization..."
cat > /etc/chrony.conf << 'EOF'
# Use public NTP servers from the pool.ntp.org project
pool 2.pool.ntp.org iburst

# Record the rate at which the system clock gains/losses time
driftfile /var/lib/chrony/drift

# Allow the system clock to be stepped in the first three updates
makestep 1.0 3

# Enable kernel synchronization of the real-time clock (RTC)
rtcsync

# Specify directory for log files
logdir /var/log/chrony

# Select which information is logged
#log measurements statistics tracking
EOF

systemctl restart chronyd 2>/dev/null || log "WARN" "Could not restart chronyd"

log "SUCCESS" "Services configured"

# Display service status
log "INFO" "Service Status Summary:"
log "INFO" "Auditd: $(systemctl is-active auditd 2>/dev/null || echo 'unknown')"
log "INFO" "Rsyslog: $(systemctl is-active rsyslog 2>/dev/null || echo 'unknown')"
log "INFO" "Chronyd: $(systemctl is-active chronyd 2>/dev/null || echo 'unknown')"
log "INFO" "DNF-Automatic: $(systemctl is-active dnf-automatic.timer 2>/dev/null || echo 'unknown')"

log "INFO" ""
log "SUCCESS" "========================================"
log "SUCCESS" "Module 7 Completed: Services Configuration"
log "SUCCESS" "========================================"
log "INFO" "Log file: $LOG_FILE"
log "INFO" ""
log "INFO" "Verify services:"
log "INFO" "  systemctl status auditd rsyslog chronyd"
log "INFO" "  chronyc sources"
log "INFO" "  systemctl list-unit-files --state=enabled"
