#!/bin/bash

# Mail server backup
# Created with assistance from AI

set -e

if [[ $EUID -ne 0 ]]; then
    echo -e "This script must be run as root."
    exit 1
fi

# Create backup dir'
sudo mkdir -p /root/backup
sudo chmod 700 /root/backup

# Configuration
BACKUP_BASE_DIR="${1:-/root/backup}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="${BACKUP_BASE_DIR}/mail-backup-${TIMESTAMP}"
LOG_FILE="${BACKUP_BASE_DIR}/backup-${TIMESTAMP}.log"

# Logging function
log() {
    echo -e "[$(date +%Y-%m-%d\ %H:%M:%S)]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "[$(date +%Y-%m-%d\ %H:%M:%S)] ERROR:${NC} $1" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "[$(date +%Y-%m-%d\ %H:%M:%S)] WARNING:${NC} $1" | tee -a "$LOG_FILE"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root"
   exit 1
fi

# Create backup directory
log "Creating backup directory: $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

# Backup Postfix configuration and data
log "Backing up Postfix..."
if systemctl is-active --quiet postfix; then
    POSTFIX_RUNNING=true
    log "Postfix is running"
else
    POSTFIX_RUNNING=false
    warn "Postfix is not running"
fi

# Postfix configuration
if [ -d /etc/postfix ]; then
    log "  - Backing up /etc/postfix configuration"
    tar -czf "$BACKUP_DIR/postfix-config.tar.gz" -C /etc postfix
else
    warn "  - /etc/postfix not found"
fi

# Postfix queue
if [ -d /var/spool/postfix ]; then
    log "  - Backing up Postfix mail queue"
    tar -czf "$BACKUP_DIR/postfix-spool.tar.gz" -C /var/spool postfix
else
    warn "  - /var/spool/postfix not found"
fi

# Virtual mailbox mappings and databases (if using virtual domains)
if [ -f /etc/postfix/virtual ]; then
    log "  - Backing up virtual domain mappings"
    cp /etc/postfix/virtual "$BACKUP_DIR/"
fi

# Backup Dovecot configuration and data
log "Backing up Dovecot..."
if systemctl is-active --quiet dovecot; then
    DOVECOT_RUNNING=true
    log "Dovecot is running"
else
    DOVECOT_RUNNING=false
    warn "Dovecot is not running"
fi

# Dovecot configuration
if [ -d /etc/dovecot ]; then
    log "  - Backing up /etc/dovecot configuration"
    tar -czf "$BACKUP_DIR/dovecot-config.tar.gz" -C /etc dovecot
else
    warn "  - /etc/dovecot not found"
fi

# Dovecot mail storage (common locations)
MAIL_LOCATIONS=(
    "/var/mail"
    "/var/spool/mail"
    "/home/vmail"
)

for MAIL_DIR in "${MAIL_LOCATIONS[@]}"; do
    if [ -d "$MAIL_DIR" ]; then
        SAFE_NAME=$(echo "$MAIL_DIR" | tr '/' '_' | sed 's/^_//')
        log "  - Backing up mail from $MAIL_DIR"
        tar -czf "$BACKUP_DIR/mail-${SAFE_NAME}.tar.gz" "$MAIL_DIR"
    fi
done

# Backup SSL/TLS certificates
#log "Backing up SSL/TLS certificates..."
#if [ -d /etc/pki/tls ]; then
#    log "  - Backing up /etc/pki/tls"
#    tar -czf "$BACKUP_DIR/tls-certs.tar.gz" -C /etc/pki tls
#fi

#if [ -d /etc/letsencrypt ]; then
#    log "  - Backing up Let's Encrypt certificates"
#    tar -czf "$BACKUP_DIR/letsencrypt.tar.gz" -C /etc letsencrypt
#fi

# Backup aliases and related files
log "Backing up mail aliases and related files..."
if [ -f /etc/aliases ]; then
    log "  - Backing up /etc/aliases"
    cp /etc/aliases "$BACKUP_DIR/"
fi

if [ -f /etc/aliases.db ]; then
    log "  - Backing up /etc/aliases.db"
    cp /etc/aliases.db "$BACKUP_DIR/"
fi

# Save systemd service states
log "Saving service states..."
{
    echo "=== Service States ==="
    for service in postfix dovecot; do
        if systemctl list-unit-files | grep -q "^${service}.service"; then
            echo "[$service]"
            systemctl is-enabled "$service" 2>/dev/null || echo "not enabled"
            systemctl is-active "$service" 2>/dev/null || echo "not active"
            echo ""
        fi
    done
} > "$BACKUP_DIR/service-states.txt"

# Create a backup manifest
log "Creating backup manifest..."
{
    echo "=== Mail Server Backup Manifest ==="
    echo "Backup Date: $(date)"
    echo "Hostname: $(hostname)"
    echo "Backup Directory: $BACKUP_DIR"
    echo ""
    echo "=== Files Included ==="
    find "$BACKUP_DIR" -type f -exec ls -lh {} \;
    echo ""
    echo "=== Total Backup Size ==="
    du -sh "$BACKUP_DIR"
} > "$BACKUP_DIR/MANIFEST.txt"

# Set appropriate permissions
log "Setting backup permissions..."
chmod 700 "$BACKUP_DIR"
chmod 600 "$BACKUP_DIR"/*

# Calculate and display backup size
BACKUP_SIZE=$(du -sh "$BACKUP_DIR" | cut -f1)
log "Backup completed successfully!"
log "Backup location: $BACKUP_DIR"
log "Backup size: $BACKUP_SIZE"

exit 0
