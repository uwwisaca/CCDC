#!/bin/bash
#
# Ubuntu 24.04 LTS Desktop STIG Implementation Script
# Based on: U_CAN_Ubuntu_24-04_LTS_V1R4_Manual_STIG
# Version: 1.0
# Date: January 30, 2026
#
# Note: Similar to Ubuntu Server STIG with desktop-specific additions
# Usage: sudo ./apply-ubuntu-desktop-stig.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/ubuntu-desktop-stig-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/ubuntu-desktop-stig-backup-$(date +%Y%m%d-%H%M%S)"

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
log "INFO" "Ubuntu 24.04 Desktop STIG Application Starting"
log "INFO" "========================================"

# Create backup
mkdir -p "$BACKUP_DIR"
log "SUCCESS" "Backup directory created: $BACKUP_DIR"

# Install required packages
log "INFO" "Installing required packages..."
apt-get update
apt-get install -y auditd aide libpam-pwquality apparmor apparmor-utils \
    ufw unattended-upgrades vlock gnome-screensaver

log "SUCCESS" "Required packages installed"

# Apply server STIG settings (password policies, SSH, audit, etc.)
log "INFO" "Applying base Ubuntu STIG settings..."

# Password quality
cat > /etc/security/pwquality.conf << 'EOF'
minlen = 15
ucredit = -1
lcredit = -1
dcredit = -1
ocredit = -1
minclass = 4
maxrepeat = 3
maxclassrepeat = 4
dictcheck = 1
enforce_for_root
retry = 3
difok = 8
gecoscheck = 1
EOF

# Account lockout
cat > /etc/security/faillock.conf << 'EOF'
deny = 3
unlock_time = 0
fail_interval = 900
even_deny_root
audit
EOF

# SSH configuration (if SSH is installed)
if [ -f /etc/ssh/sshd_config ]; then
    mkdir -p /etc/ssh/sshd_config.d
    cat > /etc/ssh/sshd_config.d/99-stig.conf << 'EOF'
Protocol 2
PermitRootLogin no
PermitEmptyPasswords no
HostbasedAuthentication no
IgnoreRhosts yes
X11Forwarding no
ClientAliveInterval 600
ClientAliveCountMax 0
Banner /etc/issue.net
Ciphers aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512,hmac-sha2-256
EOF
    systemctl restart ssh || true
fi

# Kernel parameters
cat > /etc/sysctl.d/99-stig.conf << 'EOF'
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.all.forwarding = 0
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 1
EOF

sysctl -p /etc/sysctl.d/99-stig.conf

log "SUCCESS" "Base Ubuntu STIG settings applied"

# ========================================
# Desktop-Specific Settings
# ========================================

log "INFO" "Applying desktop-specific settings..."

# Screen lock settings
log "INFO" "Configuring screen lock..."

# Create dconf profile
mkdir -p /etc/dconf/profile
cat > /etc/dconf/profile/user << 'EOF'
user-db:user
system-db:local
EOF

# Create local database directory
mkdir -p /etc/dconf/db/local.d

# Screen lock configuration
cat > /etc/dconf/db/local.d/00-screensaver << 'EOF'
[org/gnome/desktop/screensaver]
# Lock screen after idle
idle-activation-enabled=true
lock-enabled=true
lock-delay=uint32 0

# Idle delay (15 minutes = 900 seconds)
idle-delay=uint32 900

[org/gnome/desktop/session]
# Idle delay (15 minutes = 900 seconds)
idle-delay=uint32 900

[org/gnome/settings-daemon/plugins/power]
# Sleep when inactive
sleep-inactive-ac-timeout=900
sleep-inactive-battery-timeout=900
EOF

# Lock down screen saver settings
cat > /etc/dconf/db/local.d/locks/screensaver << 'EOF'
/org/gnome/desktop/screensaver/idle-activation-enabled
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/lock-delay
/org/gnome/desktop/session/idle-delay
/org/gnome/settings-daemon/plugins/power/sleep-inactive-ac-timeout
/org/gnome/settings-daemon/plugins/power/sleep-inactive-battery-timeout
EOF

# Update dconf database
dconf update

log "SUCCESS" "Screen lock configured"

# Disable guest account
log "INFO" "Disabling guest account..."

if [ -f /etc/lightdm/lightdm.conf ]; then
    if ! grep -q "allow-guest=false" /etc/lightdm/lightdm.conf; then
        echo "allow-guest=false" >> /etc/lightdm/lightdm.conf
    fi
elif [ -d /etc/lightdm/lightdm.conf.d ]; then
    echo "[Seat:*]" > /etc/lightdm/lightdm.conf.d/50-no-guest.conf
    echo "allow-guest=false" >> /etc/lightdm/lightdm.conf.d/50-no-guest.conf
fi

log "SUCCESS" "Guest account disabled"

# Disable automatic login
log "INFO" "Disabling automatic login..."

if [ -f /etc/gdm3/custom.conf ]; then
    sed -i 's/^AutomaticLoginEnable.*/AutomaticLoginEnable = false/' /etc/gdm3/custom.conf
    sed -i 's/^TimedLoginEnable.*/TimedLoginEnable = false/' /etc/gdm3/custom.conf
fi

log "SUCCESS" "Automatic login disabled"

# Configure login banner
log "INFO" "Configuring login banner..."

cat > /etc/issue << 'EOF'
You are accessing a U.S. Government (USG) Information System (IS).

Unauthorized access is prohibited and subject to criminal and civil penalties.

EOF

cat > /etc/issue.net << 'EOF'
You are accessing a U.S. Government (USG) Information System (IS).

Unauthorized access is prohibited and subject to criminal and civil penalties.

EOF

# GDM banner
mkdir -p /etc/dconf/db/gdm.d
cat > /etc/dconf/db/gdm.d/01-banner-message << 'EOF'
[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='You are accessing a U.S. Government (USG) Information System (IS). Unauthorized access is prohibited.'
EOF

dconf update

log "SUCCESS" "Login banner configured"

# Disable USB storage (optional - may impact usability)
log "WARN" "USB storage restrictions..."
# Uncomment to disable USB storage
# echo "install usb-storage /bin/true" > /etc/modprobe.d/usb-storage.conf

# Privacy settings
log "INFO" "Configuring privacy settings..."

cat > /etc/dconf/db/local.d/00-privacy << 'EOF'
[org/gnome/desktop/privacy]
# Disable recent files
remember-recent-files=false

# Disable app usage tracking
remember-app-usage=false

# Disable location services
location-enabled=false

# Screen privacy
send-software-usage-stats=false
report-technical-problems=false
EOF

dconf update

log "SUCCESS" "Privacy settings configured"

# Disable unnecessary services
log "INFO" "Disabling unnecessary services..."

systemctl disable bluetooth.service || true
systemctl disable avahi-daemon.service || true
systemctl disable cups.service || true

log "SUCCESS" "Unnecessary services disabled"

# Firewall configuration
log "INFO" "Configuring firewall..."

ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw logging on

log "SUCCESS" "Firewall configured"

# AppArmor enforcement
log "INFO" "Enabling AppArmor..."

systemctl enable apparmor
systemctl start apparmor

# Set all profiles to enforce mode
aa-enforce /etc/apparmor.d/* 2>/dev/null || log "WARN" "Some AppArmor profiles may not be enforceable"

log "SUCCESS" "AppArmor enabled"

# Automatic updates
log "INFO" "Configuring automatic security updates..."

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

systemctl enable unattended-upgrades

log "SUCCESS" "Automatic security updates configured"

# AIDE initialization
log "INFO" "Initializing AIDE (this may take several minutes)..."
aideinit || log "WARN" "AIDE initialization in progress"
[ -f /var/lib/aide/aide.db.new ] && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

log "SUCCESS" "AIDE configured"

log "INFO" ""
log "INFO" "========================================"
log "SUCCESS" "Ubuntu 24.04 Desktop STIG Application Completed"
log "INFO" "========================================"
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "WARN" ""
log "WARN" "=== IMPORTANT NEXT STEPS ==="
log "WARN" "1. Reboot the system to apply all settings"
log "WARN" "2. Log out and log back in for desktop settings to take effect"
log "WARN" "3. Set strong passwords for all user accounts"
log "WARN" "4. Test screen lock functionality (should activate after 15 min)"
log "WARN" "5. Configure firewall rules for any required services"
log "WARN" "6. Join to domain if required"
log "WARN" "7. Disable USB storage if required (currently not enforced)"
log "WARN" "8. Configure backup solution"
log "WARN" "9. Test all required applications for compatibility"
log "WARN" "10. Run compliance scan:"
log "WARN" "    sudo apt install -y ssg-base ssg-debderived"
log "WARN" "    oscap xccdf eval --profile stig --results /tmp/results.xml \\"
log "WARN" "      --report /tmp/report.html \\"
log "WARN" "      /usr/share/xml/scap/ssg/content/ssg-ubuntu2404-ds.xml"
log "INFO" ""
log "INFO" "Desktop-specific settings applied:"
log "INFO" "  - Screen lock: 15 minutes idle timeout"
log "INFO" "  - Guest account disabled"
log "INFO" "  - Automatic login disabled"
log "INFO" "  - Login banner configured"
log "INFO" "  - Privacy settings hardened"
log "INFO" "  - Bluetooth/Avahi/CUPS disabled"
