#!/bin/bash
#
# Ubuntu 24.04 LTS STIG - Module 2: SSH Hardening
# Based on U_CAN_Ubuntu_24-04_LTS_V1R4_Manual_STIG
# Version: 1.0
# Date: February 14, 2026
#
# Usage: sudo ./02-ssh-hardening.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/stig-ssh-hardening-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/stig-backups/ssh-$(date +%Y%m%d-%H%M%S)"

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
log "INFO" "Ubuntu 24.04 LTS STIG - SSH Hardening"
log "INFO" "========================================="

# Create backup
mkdir -p "$BACKUP_DIR"
cp /etc/ssh/sshd_config "$BACKUP_DIR/" 2>/dev/null || true
cp -r /etc/ssh/sshd_config.d "$BACKUP_DIR/" 2>/dev/null || true
log "SUCCESS" "Backup created: $BACKUP_DIR"

log "INFO" ""
log "INFO" "=== Creating Login Banners ==="

# Create SSH banner
cat > /etc/issue.net << 'EOF'
*******************************************************************************
                            AUTHORIZED ACCESS ONLY
*******************************************************************************

╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║        HALT! Who would cross the Bridge of SSH must          ║
║           answer me these questions three, ere the           ║
║              other side ye see...                            ║
║                                                              ║
║  QUESTION 1: What is your name?                             ║
║  QUESTION 2: What is your quest?                            ║
║  QUESTION 3: What is the airspeed velocity of an            ║
║              unladen packet?                                 ║
║                                                              ║
║  What? I don't know tha-- AAAAAAHHHHH! [BANNED]             ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Your mother was a hamster and your father smelt of         ║
║  elderberries! I fart in your general direction!            ║
║  Now go away or I shall taunt you a second time!            ║
║                                                              ║
║  AUTHENTICATION ATTEMPTS REMAINING: 3                        ║
║   - First attempt: We shall say "Ni!" to you                ║
║   - Second attempt: Bring us a SHRUBBERY                    ║
║   - Third attempt: [DRAMATIC ORGAN CHORD] THE COMFY CHAIR!  ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  NOTICE: This system is protected by the Spanish            ║
║  Inquisition (bet you weren't expecting that)               ║
║                                                              ║
║  Chief Weapons:                                             ║
║   • Fear                                                     ║
║   • Surprise                                                 ║
║   • Ruthless efficiency                                     ║
║   • An almost fanatical devotion to iptables                ║
║   • Nice red uniforms                                        ║
║                                                              ║
║  "It's just a flesh wound!" - Your SSH connection (Liar)    ║
║                                                              ║
║  "We are the knights who say... SUDO!"                      ║
║                                                              ║
║  'Tis but a server! A scratch! Your bytes cannot pass!      ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

             [COCONUT CLAPPING SOUNDS INTENSIFY]

*******************************************************************************
EOF

cp /etc/issue.net /etc/issue
log "SUCCESS" "Created login banners (/etc/issue.net and /etc/issue)"

log "INFO" ""
log "INFO" "=== Configuring SSH Settings ==="

# Create STIG SSH configuration
cat > /etc/ssh/sshd_config.d/99-stig.conf << 'EOF'
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

# UBTU-24-255045: Set client alive interval (10 minutes)
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

log "SUCCESS" "Created STIG SSH configuration"

log "INFO" ""
log "INFO" "=== Testing SSH Configuration ==="

# Test SSH configuration
if sshd -t; then
    log "SUCCESS" "SSH configuration is valid"
    
    log "INFO" "Restarting SSH service..."
    systemctl restart sshd
    
    if systemctl is-active --quiet sshd; then
        log "SUCCESS" "SSH service restarted successfully"
    else
        log "ERROR" "SSH service failed to start"
        log "WARN" "Restoring backup configuration..."
        cp "$BACKUP_DIR/sshd_config" /etc/ssh/sshd_config
        systemctl restart sshd
        exit 1
    fi
else
    log "ERROR" "SSH configuration test failed"
    log "WARN" "Configuration not applied. Check syntax."
    exit 1
fi

log "INFO" ""
log "INFO" "========================================="
log "SUCCESS" "SSH Hardening Complete"
log "INFO" "========================================="
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "WARN" ""
log "WARN" "=== IMPORTANT WARNINGS ==="
log "WARN" "1. Root login is now DISABLED"
log "WARN" "2. Test SSH access with a non-root user BEFORE logging out"
log "WARN" "3. Ensure you have sudo access with your user account"
log "WARN" "4. If SSH access fails, use console/KVM to restore"
log "WARN" "   Restore command: cp $BACKUP_DIR/sshd_config /etc/ssh/sshd_config"
log "INFO" ""
log "INFO" "=== Applied Settings Summary ==="
log "INFO" "- Root login disabled"
log "INFO" "- Strong ciphers: aes256-ctr, aes192-ctr, aes128-ctr"
log "INFO" "- Strong MACs: hmac-sha2-512, hmac-sha2-256"
log "INFO" "- Client timeout: 10 minutes"
log "INFO" "- Max auth tries: 4"
log "INFO" "- Login banner configured"
