#!/bin/bash
#
# Ubuntu 24.04 LTS STIG - Module 4: Kernel Parameters
# Based on U_CAN_Ubuntu_24-04_LTS_V1R4_Manual_STIG
# Version: 1.0
# Date: February 14, 2026
#
# Usage: sudo ./04-kernel-params.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/stig-kernel-params-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/stig-backups/kernel-$(date +%Y%m%d-%H%M%S)"

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
log "INFO" "Ubuntu 24.04 LTS STIG - Kernel Parameters"
log "INFO" "========================================="

# Create backup
mkdir -p "$BACKUP_DIR"
cp /etc/sysctl.conf "$BACKUP_DIR/" 2>/dev/null || true
cp -r /etc/sysctl.d "$BACKUP_DIR/" 2>/dev/null || true
log "SUCCESS" "Backup created: $BACKUP_DIR"

log "INFO" ""
log "INFO" "=== Configuring Kernel Security Parameters ==="

# Create STIG kernel parameters configuration
cat > /etc/sysctl.d/99-stig.conf << 'EOF'
# STIG Kernel Parameters for Ubuntu 24.04
# Based on U_CAN_Ubuntu_24-04_LTS_V1R4_Manual_STIG

# =======================
# Network Security - IPv4
# =======================

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# Disable secure ICMP redirects
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Disable sending ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Log martian packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Enable TCP SYN cookies
net.ipv4.tcp_syncookies = 1

# Enable IP forwarding (set to 0 if not a router)
net.ipv4.ip_forward = 0

# =======================
# Network Security - IPv6
# =======================

# Disable IPv6 source packet routing
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Disable IPv6 ICMP redirects
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable IPv6 router advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Disable IPv6 forwarding (set to 0 if not a router)
net.ipv6.conf.all.forwarding = 0

# =======================
# Kernel Hardening
# =======================

# Enable address space layout randomization (ASLR)
kernel.randomize_va_space = 2

# Restrict kernel dmesg access
kernel.dmesg_restrict = 1

# Hide kernel pointers in /proc
kernel.kptr_restrict = 2

# Restrict ptrace scope
kernel.yama.ptrace_scope = 1

# Restrict kernel performance events
kernel.perf_event_paranoid = 2

# Disable kernel module loading after boot (uncomment if needed)
# kernel.modules_disabled = 1

# =======================
# File System Security
# =======================

# Disable core dumps for setuid programs
fs.suid_dumpable = 0

# Increase file handle limits (adjust as needed)
fs.file-max = 65535

# =======================
# Memory Management
# =======================

# Control system request debugging functionality
kernel.sysrq = 0

# Restrict access to kernel logs
kernel.dmesg_restrict = 1

# =======================
# Additional Hardening
# =======================

# Enable ExecShield protection
# kernel.exec-shield = 1

# Control raw socket access
# net.ipv4.ping_group_range = 1 0
EOF

log "SUCCESS" "Created kernel parameters configuration"

log "INFO" ""
log "INFO" "=== Applying Kernel Parameters ==="

# Apply sysctl settings
if sysctl -p /etc/sysctl.d/99-stig.conf >> "$LOG_FILE" 2>&1; then
    log "SUCCESS" "Applied kernel parameters"
else
    log "ERROR" "Failed to apply some kernel parameters (check log)"
fi

log "INFO" ""
log "INFO" "=== Verifying Key Parameters ==="

# Verify critical settings
PARAMS=(
    "net.ipv4.conf.all.accept_source_route"
    "net.ipv4.conf.all.send_redirects"
    "net.ipv4.icmp_echo_ignore_broadcasts"
    "net.ipv4.tcp_syncookies"
    "kernel.randomize_va_space"
    "kernel.dmesg_restrict"
    "fs.suid_dumpable"
)

for param in "${PARAMS[@]}"; do
    value=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
    log "INFO" "$param = $value"
done

log "INFO" ""
log "INFO" "========================================="
log "SUCCESS" "Kernel Parameters Configuration Complete"
log "INFO" "========================================="
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "INFO" ""
log "INFO" "=== Applied Settings Summary ==="
log "INFO" "- Source routing disabled"
log "INFO" "- ICMP redirects disabled"
log "INFO" "- Reverse path filtering enabled"
log "INFO" "- TCP SYN cookies enabled"
log "INFO" "- ASLR enabled (randomize_va_space=2)"
log "INFO" "- Kernel dmesg restricted"
log "INFO" "- Core dumps disabled for setuid programs"
log "INFO" "- Ptrace scope restricted"
log "INFO" ""
log "INFO" "=== Verification Commands ==="
log "INFO" "View all: sysctl -a"
log "INFO" "View specific: sysctl net.ipv4.conf.all.send_redirects"
log "INFO" "Reload all: sysctl --system"
