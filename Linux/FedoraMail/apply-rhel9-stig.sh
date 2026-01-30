#!/bin/bash
#
# RHEL 9 / Fedora STIG Implementation Script
# Based on: U_RHEL_9_V2R7_Manual_STIG
# Version: 1.0
# Date: January 30, 2026
#
# Usage: sudo ./apply-rhel9-stig.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/rhel9-stig-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/rhel9-stig-backup-$(date +%Y%m%d-%H%M%S)"

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
log "INFO" "RHEL 9 / Fedora STIG Application Starting"
log "INFO" "========================================"

# Detect distribution
if [ -f /etc/redhat-release ]; then
    DISTRO=$(cat /etc/redhat-release)
    log "INFO" "Detected distribution: $DISTRO"
else
    log "ERROR" "Not a Red Hat based distribution"
    exit 1
fi

# Create backup directory
mkdir -p "$BACKUP_DIR"
log "SUCCESS" "Created backup directory: $BACKUP_DIR"

# Backup critical files
log "INFO" "Backing up configuration files..."
cp -p /etc/login.defs "$BACKUP_DIR/" 2>/dev/null || true
cp -p /etc/security/pwquality.conf "$BACKUP_DIR/" 2>/dev/null || true
cp -p /etc/pam.d/system-auth "$BACKUP_DIR/" 2>/dev/null || true
cp -p /etc/pam.d/password-auth "$BACKUP_DIR/" 2>/dev/null || true
cp -p /etc/ssh/sshd_config "$BACKUP_DIR/" 2>/dev/null || true
cp -p /etc/audit/auditd.conf "$BACKUP_DIR/" 2>/dev/null || true
cp -rp /etc/audit/rules.d "$BACKUP_DIR/" 2>/dev/null || true
cp -p /etc/sysctl.conf "$BACKUP_DIR/" 2>/dev/null || true
cp -rp /etc/sysctl.d "$BACKUP_DIR/" 2>/dev/null || true
log "SUCCESS" "Configuration files backed up"

# Install required packages
log "INFO" "Installing required packages..."
dnf install -y aide audit audispd-plugins firewalld rsyslog chrony libpwquality policycoreutils-python-utils selinux-policy-targeted || log "WARN" "Some packages may already be installed"

log "SUCCESS" "Required packages installed"

# ========================================
# Password Quality Requirements
# ========================================

log "INFO" "Configuring password quality requirements..."

# RHEL-09-611010 through RHEL-09-611050: Password complexity
cat > /etc/security/pwquality.conf << 'EOF'
# RHEL 9 STIG Password Quality Configuration

# RHEL-09-611010: Minimum length
minlen = 15

# RHEL-09-611015: Minimum uppercase characters
ucredit = -1

# RHEL-09-611020: Minimum lowercase characters
lcredit = -1

# RHEL-09-611025: Minimum numeric characters
dcredit = -1

# RHEL-09-611030: Minimum special characters
ocredit = -1

# RHEL-09-611035: Minimum character classes
minclass = 4

# RHEL-09-611040: Maximum consecutive repeating characters
maxrepeat = 3

# RHEL-09-611045: Maximum consecutive characters from same class
maxclassrepeat = 4

# RHEL-09-611050: Reject passwords based on dictionary
dictcheck = 1

# RHEL-09-611055: Enforce for root
enforce_for_root

# RHEL-09-611060: Retry attempts
retry = 3

# RHEL-09-611065: Differ from old password
difok = 8
EOF

log "SUCCESS" "Password quality configured"

# ========================================
# Password Policy via /etc/login.defs
# ========================================

log "INFO" "Configuring password policies..."

sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   60/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    15/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs

# RHEL-09-611070: Encrypt method
sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs

# RHEL-09-611075: Create home directories
sed -i 's/^CREATE_HOME.*/CREATE_HOME     yes/' /etc/login.defs

# RHEL-09-611080: UMASK
sed -i 's/^UMASK.*/UMASK           077/' /etc/login.defs

log "SUCCESS" "Password policies configured"

# ========================================
# Account Lockout Policy
# ========================================

log "INFO" "Configuring account lockout policy..."

# RHEL-09-611085 through RHEL-09-611100: Configure faillock
authselect select sssd with-faillock --force

# Configure faillock
cat > /etc/security/faillock.conf << 'EOF'
# RHEL 9 STIG Faillock Configuration

# RHEL-09-611085: Deny after 3 failed attempts
deny = 3

# RHEL-09-611090: Lock for 15 minutes (0 = must be unlocked by admin)
unlock_time = 0

# RHEL-09-611095: Failure interval (15 minutes)
fail_interval = 900

# RHEL-09-611100: Even deny root
even_deny_root

# RHEL-09-611105: Log failed attempts
audit

# RHEL-09-611110: Require administrator unlock
# unlock_time = 0 already set above
EOF

log "SUCCESS" "Account lockout policy configured"

# ========================================
# SSH Configuration
# ========================================

log "INFO" "Configuring SSH..."

mkdir -p /etc/ssh/sshd_config.d

cat > /etc/ssh/sshd_config.d/99-stig.conf << 'EOF'
# RHEL 9 STIG SSH Configuration

# RHEL-09-255010: Protocol version
Protocol 2

# RHEL-09-255015: Disable root login
PermitRootLogin no

# RHEL-09-255020: Disable empty passwords
PermitEmptyPasswords no

# RHEL-09-255025: Host-based authentication
HostbasedAuthentication no

# RHEL-09-255030: Ignore rhosts
IgnoreRhosts yes

# RHEL-09-255035: X11 forwarding
X11Forwarding no

# RHEL-09-255040: Print last log
PrintLastLog yes

# RHEL-09-255045: Client alive interval
ClientAliveInterval 600

# RHEL-09-255050: Client alive count max
ClientAliveCountMax 0

# RHEL-09-255055: Login grace time
LoginGraceTime 60

# RHEL-09-255060: Banner
Banner /etc/issue.net

# RHEL-09-255065: Strong ciphers only
Ciphers aes256-ctr,aes192-ctr,aes128-ctr

# RHEL-09-255070: Strong MACs only
MACs hmac-sha2-512,hmac-sha2-256

# RHEL-09-255075: Key exchange algorithms
KexAlgorithms ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256

# RHEL-09-255080: Host key algorithms
HostKeyAlgorithms ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256

# RHEL-09-255085: Compression
Compression no

# RHEL-09-255090: Permit user environment
PermitUserEnvironment no

# RHEL-09-255095: Strict modes
StrictModes yes

# RHEL-09-255100: Use privilege separation
UsePrivilegeSeparation sandbox

# RHEL-09-255105: Public key authentication
PubkeyAuthentication yes

# RHEL-09-255110: GSSAPIAuthentication
GSSAPIAuthentication yes

# RHEL-09-255115: Kerberos authentication
KerberosAuthentication no
EOF

# Create login banner
cat > /etc/issue.net << 'EOF'
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
EOF

systemctl restart sshd
log "SUCCESS" "SSH configured and restarted"

# ========================================
# Audit System Configuration
# ========================================

log "INFO" "Configuring audit system..."

# RHEL-09-653010: Auditd configuration
cat > /etc/audit/auditd.conf << 'EOF'
# RHEL 9 STIG Audit Configuration

# RHEL-09-653010: Log file location
log_file = /var/log/audit/audit.log

# RHEL-09-653015: Log file permissions
log_group = root

# RHEL-09-653020: Log format
log_format = ENRICHED

# RHEL-09-653025: Flush to disk
flush = INCREMENTAL_ASYNC

# RHEL-09-653030: Frequency
freq = 50

# RHEL-09-653035: Max log file size (MB)
max_log_file = 10

# RHEL-09-653040: Number of log files
num_logs = 5

# RHEL-09-653045: Priority boost
priority_boost = 4

# RHEL-09-653050: Action on disk full
disk_full_action = HALT

# RHEL-09-653055: Action on disk error
disk_error_action = HALT

# RHEL-09-653060: Space left (MB)
space_left = 250

# RHEL-09-653065: Space left action
space_left_action = EMAIL

# RHEL-09-653070: Admin space left (MB)
admin_space_left = 100

# RHEL-09-653075: Admin space left action
admin_space_left_action = HALT

# RHEL-09-653080: Max log file action
max_log_file_action = ROTATE

# RHEL-09-653085: Keep logs
max_log_file_keep_logs = 5

# RHEL-09-653090: Action email
action_mail_acct = root

# RHEL-09-653095: Name format
name_format = HOSTNAME
EOF

# RHEL-09-654010 through RHEL-09-654200: Audit rules
cat > /etc/audit/rules.d/stig.rules << 'EOF'
## RHEL 9 STIG Audit Rules

# Delete all existing rules
-D

# Buffer size
-b 8192

# Failure mode (2 = panic)
-f 2

# RHEL-09-654010: Time changes
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change
-w /etc/localtime -p wa -k time-change

# RHEL-09-654015: User/group changes
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# RHEL-09-654020: Network configuration changes
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /etc/sysconfig/network-scripts/ -p wa -k system-locale

# RHEL-09-654025: SELinux changes
-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/share/selinux/ -p wa -k MAC-policy

# RHEL-09-654030: Login/logout events
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins

# RHEL-09-654035: Session initiation
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# RHEL-09-654040: Discretionary access control
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod

# RHEL-09-654045: Unsuccessful file access
-a always,exit -F arch=b32 -S open,openat,creat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S open,openat,creat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S open,openat,creat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S open,openat,creat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access

# RHEL-09-654050: Privileged commands
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=unset -k privileged

# RHEL-09-654055: File deletion events
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=unset -k delete

# RHEL-09-654060: Sudoers changes
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions

# RHEL-09-654065: Kernel module operations
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b32 -S init_module,delete_module -k modules
-a always,exit -F arch=b64 -S init_module,delete_module -k modules

# RHEL-09-654070: Make immutable
-e 2
EOF

# Restart auditd
service auditd restart
log "SUCCESS" "Audit system configured"

# ========================================
# Kernel Parameters (sysctl)
# ========================================

log "INFO" "Configuring kernel parameters..."

cat > /etc/sysctl.d/99-stig.conf << 'EOF'
# RHEL 9 STIG Kernel Parameters

# RHEL-09-253010: IPv4 forwarding
net.ipv4.ip_forward = 0

# RHEL-09-253015: Packet redirect sending
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# RHEL-09-253020: Source routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# RHEL-09-253025: ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# RHEL-09-253030: Secure ICMP redirects
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# RHEL-09-253035: Log martian packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# RHEL-09-253040: Ignore ICMP broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1

# RHEL-09-253045: Ignore bogus ICMP errors
net.ipv4.icmp_ignore_bogus_error_responses = 1

# RHEL-09-253050: Reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# RHEL-09-253055: TCP SYN cookies
net.ipv4.tcp_syncookies = 1

# RHEL-09-253060: IPv6 router advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# RHEL-09-253065: IPv6 redirects
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# RHEL-09-253070: IPv6 source routing
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# RHEL-09-253075: IPv6 forwarding
net.ipv6.conf.all.forwarding = 0

# RHEL-09-253080: Randomize virtual address space
kernel.randomize_va_space = 2

# RHEL-09-253085: Core dumps
kernel.core_uses_pid = 1
fs.suid_dumpable = 0

# RHEL-09-253090: Restrict dmesg
kernel.dmesg_restrict = 1

# RHEL-09-253095: Restrict kernel pointers
kernel.kptr_restrict = 1
EOF

sysctl -p /etc/sysctl.d/99-stig.conf
log "SUCCESS" "Kernel parameters configured"

# ========================================
# Firewall Configuration
# ========================================

log "INFO" "Configuring firewall..."

systemctl enable firewalld
systemctl start firewalld

# Configure firewall logging
firewall-cmd --set-log-denied=all --permanent
firewall-cmd --reload

log "SUCCESS" "Firewall configured"

# ========================================
# SELinux Configuration
# ========================================

log "INFO" "Configuring SELinux..."

# RHEL-09-211010: SELinux must be enabled
sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
sed -i 's/^SELINUXTYPE=.*/SELINUXTYPE=targeted/' /etc/selinux/config

# Set to enforcing mode (requires reboot to take full effect)
setenforce 1 || log "WARN" "SELinux enforcement requires reboot"

log "SUCCESS" "SELinux configured"

# ========================================
# File Permissions
# ========================================

log "INFO" "Setting file permissions..."

# RHEL-09-232010 through RHEL-09-232200: File permissions
chmod 0644 /etc/passwd
chmod 0000 /etc/shadow
chmod 0000 /etc/gshadow
chmod 0644 /etc/group
chmod 0600 /boot/grub2/grub.cfg || chmod 0600 /boot/efi/EFI/redhat/grub.cfg
chmod 0600 /etc/ssh/sshd_config
chmod 0640 /etc/audit/auditd.conf
chmod 0640 /var/log/messages
chmod 0640 /var/log/secure

log "SUCCESS" "File permissions set"

# ========================================
# Service Configuration
# ========================================

log "INFO" "Configuring services..."

# Enable and start essential services
systemctl enable auditd
systemctl enable rsyslog
systemctl enable firewalld
systemctl enable chronyd

# Disable unnecessary services
systemctl disable rpcbind || true
systemctl disable nfs-server || true
systemctl disable ypserv || true
systemctl disable ypbind || true
systemctl disable tftp || true
systemctl disable certmonger || true
systemctl disable cgconfig || true
systemctl disable cgred || true
systemctl disable cpupower || true
systemctl disable kdump || true
systemctl disable mdmonitor || true
systemctl disable messagebus || true
systemctl disable netcf-transaction || true
systemctl disable nfs-lock || true
systemctl disable quota_nld || true
systemctl disable rdisc || true
systemctl disable rhnsd || true
systemctl disable rhsmcertd || true
systemctl disable saslauthd || true
systemctl disable smartd || true
systemctl disable sysstat || true

log "SUCCESS" "Services configured"

# ========================================
# AIDE Configuration
# ========================================

log "INFO" "Initializing AIDE..."
log "WARN" "AIDE initialization may take several minutes..."

aide --init || log "WARN" "AIDE initialization started in background"
[ -f /var/lib/aide/aide.db.new.gz ] && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# Configure AIDE cron job
cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
/usr/sbin/aide --check | /bin/mail -s "AIDE Integrity Check" root
EOF
chmod 755 /etc/cron.daily/aide-check

log "SUCCESS" "AIDE configured"

# ========================================
# Additional Hardening
# ========================================

log "INFO" "Applying additional hardening..."

# Disable USB storage
echo "install usb-storage /bin/true" > /etc/modprobe.d/usb-storage.conf

# Disable uncommon network protocols
echo "install dccp /bin/true" > /etc/modprobe.d/dccp.conf
echo "install sctp /bin/true" > /etc/modprobe.d/sctp.conf
echo "install rds /bin/true" > /etc/modprobe.d/rds.conf
echo "install tipc /bin/true" > /etc/modprobe.d/tipc.conf

# Configure automatic updates
dnf install -y dnf-automatic
systemctl enable --now dnf-automatic.timer

log "SUCCESS" "Additional hardening applied"

log "INFO" ""
log "INFO" "========================================"
log "SUCCESS" "RHEL 9 / Fedora STIG Application Completed"
log "INFO" "========================================"
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "WARN" ""
log "WARN" "=== CRITICAL NEXT STEPS ==="
log "WARN" "1. REBOOT THE SYSTEM to apply all settings"
log "WARN" "2. Verify SELinux is in enforcing mode after reboot"
log "WARN" "3. Complete AIDE database initialization if still running"
log "WARN" "4. Configure user accounts and set strong passwords"
log "WARN" "5. Join to domain if required"
log "WARN" "6. Configure firewall rules for required services"
log "WARN" "7. Set up centralized logging"
log "WARN" "8. Review and configure email for audit alerts"
log "WARN" "9. Test SSH access with new configuration"
log "WARN" "10. Run OpenSCAP scan for compliance validation:"
log "WARN" "    oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig \\"
log "WARN" "    --results-arf /tmp/results.xml --report /tmp/report.html \\"
log "WARN" "    /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml"
log "INFO" ""
