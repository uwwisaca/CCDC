#!/bin/bash
#
# Oracle Linux 9 STIG - Module 4: Kernel Parameters
# Based on: U_Oracle_Linux_9_V1R4_Manual_STIG
# Version: 1.0
# Date: February 12, 2026
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/oracle-linux-stig-04-kernel-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/oracle-linux-stig-backup-kernel-$(date +%Y%m%d-%H%M%S)"

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
log "INFO" "Module 4: Kernel Parameters"
log "INFO" "========================================"

# Create backup directory
mkdir -p "$BACKUP_DIR"
cp -p /etc/sysctl.conf "$BACKUP_DIR/" 2>/dev/null || true
cp -rp /etc/sysctl.d "$BACKUP_DIR/" 2>/dev/null || true
log "SUCCESS" "Backup created: $BACKUP_DIR"

# Configure kernel parameters
log "INFO" "Configuring kernel security parameters..."
cat > /etc/sysctl.d/99-stig.conf << 'EOF'
# Oracle Linux 9 STIG Kernel Parameters

# IPv4 Settings
# Disable IP forwarding
net.ipv4.ip_forward = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Disable send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Enable logging of martian packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Enable reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP echo broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable TCP SYN cookies
net.ipv4.tcp_syncookies = 1

# IPv6 Settings
# Disable IPv6 router advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Disable IPv6 redirects
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable IPv6 source routing
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Disable IPv6 forwarding
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0

# Kernel Hardening
# Enable address space layout randomization
kernel.randomize_va_space = 2

# Restrict access to kernel logs
kernel.dmesg_restrict = 1

# Restrict access to kernel pointers
kernel.kptr_restrict = 1

# Disable core dumps for setuid programs
fs.suid_dumpable = 0

# Restrict ptrace
kernel.yama.ptrace_scope = 1

# Enable kernel panic on oops
kernel.panic_on_oops = 1

# Core dumps behavior
kernel.core_uses_pid = 1
EOF

log "SUCCESS" "Kernel parameters configured"

# Apply sysctl settings
log "INFO" "Applying kernel parameters..."
sysctl -p /etc/sysctl.d/99-stig.conf >> "$LOG_FILE" 2>&1

if [ $? -eq 0 ]; then
    log "SUCCESS" "Kernel parameters applied successfully"
else
    log "ERROR" "Some kernel parameters may not have been applied"
    log "WARN" "Check log file for details: $LOG_FILE"
fi

# Verify critical settings
log "INFO" "Verifying critical kernel parameters..."
CRITICAL_PARAMS=(
    "net.ipv4.ip_forward"
    "kernel.randomize_va_space"
    "fs.suid_dumpable"
)

for param in "${CRITICAL_PARAMS[@]}"; do
    value=$(sysctl -n $param)
    log "INFO" "$param = $value"
done

log "INFO" ""
log "SUCCESS" "========================================"
log "SUCCESS" "Module 4 Completed: Kernel Parameters"
log "SUCCESS" "========================================"
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "INFO" "Current kernel parameters saved to: /etc/sysctl.d/99-stig.conf"
log "INFO" "View all settings: sysctl -a | grep -E '(net\.|kernel\.|fs\.suid)'"
