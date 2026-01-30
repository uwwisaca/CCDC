#!/bin/bash
#
# Ubuntu 24.04 LTS Server STIG Implementation Script
# Based on U_CAN_Ubuntu_24-04_LTS_V1R4_Manual_STIG
# Version: 1.0
# Date: January 30, 2026
#
# Usage: sudo ./apply-ubuntu-stig.sh
# Run as root or with sudo privileges
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

LOG_FILE="/var/log/stig-application-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/stig-backups/$(date +%Y%m%d-%H%M%S)"

# Logging function
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

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log "ERROR" "This script must be run as root"
    exit 1
fi

log "INFO" "========================================"
log "INFO" "Ubuntu 24.04 LTS STIG Application Starting"
log "INFO" "========================================"

# Create backup directory
mkdir -p "$BACKUP_DIR"
log "INFO" "Creating backup in $BACKUP_DIR"

# Backup important configurations
cp /etc/pam.d/common-* "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/security/* "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/login.defs "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/ssh/sshd_config "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/sysctl.conf "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/audit/auditd.conf "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/audit/rules.d/*.rules "$BACKUP_DIR/" 2>/dev/null || true

log "SUCCESS" "Backup completed"

log "INFO" ""
log "INFO" "=== Installing Required Packages ==="

# Update package list
apt-get update

# Install required security packages
PACKAGES=(
    "auditd"
    "audispd-plugins"
    "aide"
    "aide-common"
    "libpam-pwquality"
    "libpam-modules"
    "apparmor"
    "apparmor-utils"
    "ufw"
    "fail2ban"
    "chrony"
    "rsyslog"
)

for pkg in "${PACKAGES[@]}"; do
    if ! dpkg -l | grep -q "^ii  $pkg "; then
        log "INFO" "Installing $pkg..."
        apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1 && \
            log "SUCCESS" "Installed $pkg" || \
            log "ERROR" "Failed to install $pkg"
    else
        log "INFO" "$pkg already installed"
    fi
done

log "INFO" ""
log "INFO" "=== Configuring Password Policies ==="

# Configure password quality requirements
cat > /etc/security/pwquality.conf << 'EOF'
# Password quality requirements (UBTU-24-411025, UBTU-24-411030, etc.)
minlen = 15
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 4
maxrepeat = 3
maxclassrepeat = 4
dictcheck = 1
usercheck = 1
enforcing = 1
retry = 3
EOF

log "SUCCESS" "Configured password quality requirements"

# Configure password aging in /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 60/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 15/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs

log "SUCCESS" "Configured password aging policies"

# Configure account lockout policy
if ! grep -q "pam_faillock.so" /etc/pam.d/common-auth; then
    # Add faillock configuration
    sed -i '/pam_unix.so/i auth required pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=0' /etc/pam.d/common-auth
    sed -i '/pam_unix.so/a auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=0' /etc/pam.d/common-auth
    sed -i '/pam_deny.so/i auth required pam_faillock.so authsucc audit deny=3 even_deny_root fail_interval=900 unlock_time=0' /etc/pam.d/common-auth
    log "SUCCESS" "Configured account lockout policy"
else
    log "INFO" "Account lockout policy already configured"
fi

# Configure password history
if ! grep -q "remember=" /etc/pam.d/common-password; then
    sed -i '/pam_unix.so/s/$/ remember=5/' /etc/pam.d/common-password
    log "SUCCESS" "Configured password history (5 passwords)"
fi

# Configure password hashing algorithm (SHA-512)
if ! grep -q "sha512" /etc/pam.d/common-password; then
    sed -i 's/pam_unix.so.*/& sha512/' /etc/pam.d/common-password
    log "SUCCESS" "Configured SHA-512 password hashing"
fi

log "INFO" ""
log "INFO" "=== Configuring SSH Settings ==="

# Backup original sshd_config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Configure SSH according to STIG
cat >> /etc/ssh/sshd_config.d/99-stig.conf << 'EOF'
# STIG SSH Configuration

# UBTU-24-255015: Protocol 2 only (default in modern SSH)
Protocol 2

# UBTU-24-255020: Disable root login
PermitRootLogin no

# UBTU-24-255025: Disable empty passwords
PermitEmptyPasswords no

# UBTU-24-255030: Disable host-based authentication
HostbasedAuthentication no

# UBTU-24-255035: Ignore user known hosts
IgnoreUserKnownHosts yes

# UBTU-24-255040: Disable X11 forwarding
X11Forwarding no

# UBTU-24-255045: Set client alive interval
ClientAliveInterval 600
ClientAliveCountMax 0

# UBTU-24-255050: Set login grace time
LoginGraceTime 60

# UBTU-24-255055: Configure strong ciphers
Ciphers aes256-ctr,aes192-ctr,aes128-ctr

# UBTU-24-255060: Configure strong MACs
MACs hmac-sha2-512,hmac-sha2-256

# UBTU-24-255065: Banner
Banner /etc/issue.net

# UBTU-24-255070: Use privilege separation
UsePrivilegeSeparation sandbox

# UBTU-24-255075: Strict mode
StrictModes yes

# UBTU-24-255080: Disable TCP forwarding
AllowTcpForwarding no

# UBTU-24-255085: Disable agent forwarding
AllowAgentForwarding no

# UBTU-24-255090: Disable stream forwarding
DisableForwarding yes

# UBTU-24-255095: Compression
Compression no

# UBTU-24-255100: Max authentication tries
MaxAuthTries 4

# UBTU-24-255105: Max sessions
MaxSessions 10

# UBTU-24-255110: Public key authentication
PubkeyAuthentication yes

# UBTU-24-255115: Password authentication (disable if using keys only)
PasswordAuthentication yes

# UBTU-24-255120: Challenge response authentication
ChallengeResponseAuthentication no

# UBTU-24-255125: Kerberos authentication
KerberosAuthentication no

# UBTU-24-255130: GSSAPI authentication
GSSAPIAuthentication no

# UBTU-24-255135: Use PAM
UsePAM yes

# UBTU-24-255140: Print last log
PrintLastLog yes

# UBTU-24-255145: Permit user environment
PermitUserEnvironment no
EOF

log "SUCCESS" "Configured SSH settings"

# Create SSH banner
cat > /etc/issue.net << 'EOF'
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
EOF

cp /etc/issue.net /etc/issue
log "SUCCESS" "Created login banners"

# Restart SSH service
systemctl restart sshd
log "SUCCESS" "Restarted SSH service"

log "INFO" ""
log "INFO" "=== Configuring Audit System ==="

# Enable and start auditd
systemctl enable auditd
systemctl start auditd

# Configure audit rules
cat > /etc/audit/rules.d/stig.rules << 'EOF'
# STIG Audit Rules for Ubuntu 24.04

# Delete all existing rules
-D

# Buffer Size
-b 8192

# Failure Mode (2 = panic)
-f 2

# Audit system calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# User and group changes
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Network environment
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale

# Audit configuration modifications
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
-w /etc/selinux/ -p wa -k MAC-policy

# Logins and logouts
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# Session initiation
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# Discretionary access control
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

# Unauthorized file access attempts
-a always,exit -F arch=b64 -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# Privileged commands
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# File deletion events
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# Sudoers file changes
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# Kernel module loading and unloading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Make configuration immutable
-e 2
EOF

# Reload audit rules
augenrules --load
log "SUCCESS" "Configured audit rules"

log "INFO" ""
log "INFO" "=== Configuring Kernel Parameters ==="

# Configure kernel security parameters
cat >> /etc/sysctl.d/99-stig.conf << 'EOF'
# STIG Kernel Parameters

# Network security
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

net.ipv4.tcp_syncookies = 1

net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Kernel hardening
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1

# Core dumps
fs.suid_dumpable = 0
EOF

# Apply sysctl settings
sysctl -p /etc/sysctl.d/99-stig.conf >> "$LOG_FILE" 2>&1
log "SUCCESS" "Configured kernel parameters"

log "INFO" ""
log "INFO" "=== Configuring UFW Firewall ==="

# Enable UFW
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw logging on

# Allow SSH
ufw allow 22/tcp comment 'SSH'

log "SUCCESS" "Configured UFW firewall"

log "INFO" ""
log "INFO" "=== Configuring AppArmor ==="

# Enable AppArmor
systemctl enable apparmor
systemctl start apparmor

# Set all profiles to enforce mode
aa-enforce /etc/apparmor.d/* 2>/dev/null || true

log "SUCCESS" "Configured AppArmor"

log "INFO" ""
log "INFO" "=== Configuring File Permissions ==="

# Set permissions on important files
chmod 644 /etc/passwd
chmod 600 /etc/shadow
chmod 644 /etc/group
chmod 600 /etc/gshadow
chmod 644 /etc/passwd-
chmod 600 /etc/shadow-
chmod 644 /etc/group-
chmod 600 /etc/gshadow-

log "SUCCESS" "Set file permissions"

log "INFO" ""
log "INFO" "=== Configuring Automatic Updates ==="

# Install unattended-upgrades
apt-get install -y unattended-upgrades apt-listchanges

# Configure automatic security updates
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
EOF

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF

log "SUCCESS" "Configured automatic updates"

log "INFO" ""
log "INFO" "=== Disabling Unnecessary Services ==="

# Disable unnecessary services
SERVICES_TO_DISABLE=(
    "avahi-daemon"
    "cups"
    "bluetooth"
)

for service in "${SERVICES_TO_DISABLE[@]}"; do
    if systemctl is-enabled "$service" 2>/dev/null; then
        systemctl disable "$service"
        systemctl stop "$service"
        log "SUCCESS" "Disabled $service"
    fi
done

log "INFO" ""
log "INFO" "========================================"
log "SUCCESS" "Ubuntu 24.04 LTS STIG Application Completed"
log "INFO" "========================================"
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "WARN" "IMPORTANT: Review the log for any errors"
log "WARN" "IMPORTANT: Test SSH access before logging out"
log "WARN" "IMPORTANT: System reboot recommended"
log "INFO" ""
log "INFO" "=== NEXT STEPS ==="
log "INFO" "1. Reboot the system"
log "INFO" "2. Initialize AIDE database: aideinit && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
log "INFO" "3. Verify audit rules: auditctl -l"
log "INFO" "4. Test SSH access"
log "INFO" "5. Run compliance scan with OpenSCAP"
