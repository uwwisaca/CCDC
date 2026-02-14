#!/bin/bash
#
# Oracle Linux 9 STIG - Module 2: SSH Hardening
# Based on: U_Oracle_Linux_9_V1R4_Manual_STIG
# Version: 1.0
# Date: February 12, 2026
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/oracle-linux-stig-02-ssh-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/oracle-linux-stig-backup-ssh-$(date +%Y%m%d-%H%M%S)"

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
log "INFO" "Module 2: SSH Hardening"
log "INFO" "========================================"

# Create backup directory
mkdir -p "$BACKUP_DIR"
cp -p /etc/ssh/sshd_config "$BACKUP_DIR/" 2>/dev/null || true
cp -p /etc/issue.net "$BACKUP_DIR/" 2>/dev/null || true
log "SUCCESS" "Backup created: $BACKUP_DIR"

# Configure SSH
log "INFO" "Configuring SSH hardening..."
mkdir -p /etc/ssh/sshd_config.d

cat > /etc/ssh/sshd_config.d/99-stig.conf << 'EOF'
# Oracle Linux 9 STIG SSH Configuration

# Protocol version
Protocol 2

# Root login
PermitRootLogin no

# Empty passwords
PermitEmptyPasswords no

# Host-based authentication
HostbasedAuthentication no

# Ignore rhosts
IgnoreRhosts yes

# X11 forwarding
X11Forwarding no

# Client alive settings (timeout after 10 minutes)
ClientAliveInterval 600
ClientAliveCountMax 0

# Login grace time
LoginGraceTime 60

# Banner
Banner /etc/issue.net

# Cipher suites
Ciphers aes256-ctr,aes192-ctr,aes128-ctr

# MACs
MACs hmac-sha2-512,hmac-sha2-256

# Key exchange algorithms
KexAlgorithms ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256

# Compression
Compression no

# Permit user environment
PermitUserEnvironment no

# Strict modes
StrictModes yes

# Public key authentication
PubkeyAuthentication yes

# GSSAPI authentication
GSSAPIAuthentication yes
EOF

log "SUCCESS" "SSH configuration created"

# Create login banner
log "INFO" "Creating login banner..."
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

log "SUCCESS" "Login banner created"

# Test SSH configuration
log "INFO" "Testing SSH configuration..."
sshd -t
if [ $? -eq 0 ]; then
    log "SUCCESS" "SSH configuration is valid"
    
    # Restart SSH
    log "INFO" "Restarting SSH service..."
    systemctl restart sshd
    log "SUCCESS" "SSH service restarted"
else
    log "ERROR" "SSH configuration test failed"
    log "ERROR" "Restoring backup..."
    cp "$BACKUP_DIR/sshd_config" /etc/ssh/sshd_config
    exit 1
fi

log "INFO" ""
log "SUCCESS" "========================================"
log "SUCCESS" "Module 2 Completed: SSH Hardening"
log "SUCCESS" "========================================"
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "WARN" "CRITICAL: Test SSH access from another session before logging out!"
log "WARN" "If locked out, use console access to restore: $BACKUP_DIR/sshd_config"
