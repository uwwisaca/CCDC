#!/bin/bash

# Mail server restore
# Created with assistance from AI

set -e

if [[ $EUID -ne 0 ]]; then
    echo -e "This script must be run as root."
    exit 1
fi

# Configuration
BACKUP_DIR="${1:-}"
LOG_FILE="/var/log/mail-restore-$(date +%Y%m%d_%H%M%S).log"

# Logging function
log() {
    echo -e "[$(date +%Y-%m-%d\ %H:%M:%S)] $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "[$(date +%Y-%m-%d\ %H:%M:%S)] ERROR: $1" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "[$(date +%Y-%m-%d\ %H:%M:%S)] WARNING: $1" | tee -a "$LOG_FILE"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root"
   exit 1
fi

# Check if backup directory was provided
if [ -z "$BACKUP_DIR" ]; then
    error "No backup directory specified"
    echo ""
    echo "Usage: sudo $0 /path/to/backup-directory"
    echo ""
    echo "Available backups in /root/backup:"
    ls -ld /root/backup/mail-backup-* 2>/dev/null || echo "  No backups found"
    exit 1
fi

# Verify backup directory exists
if [ ! -d "$BACKUP_DIR" ]; then
    error "Backup directory does not exist: $BACKUP_DIR"
    exit 1
fi

log "Starting mail server restore from: $BACKUP_DIR"
log "Log file: $LOG_FILE"

# Check what's in the backup
log "Checking backup contents..."
if [ -f "$BACKUP_DIR/MANIFEST.txt" ]; then
    log "Backup manifest found"
    cat "$BACKUP_DIR/MANIFEST.txt" >> "$LOG_FILE"
else
    warn "No manifest found in backup"
fi

# Stop services
log "Stopping mail services..."
if systemctl is-active --quiet postfix; then
    systemctl stop postfix
    log "  - Stopped Postfix"
fi

if systemctl is-active --quiet dovecot; then
    systemctl stop dovecot
    log "  - Stopped Dovecot"
fi

# Restore Postfix configuration
log "Restoring Postfix configuration..."
if [ -f "$BACKUP_DIR/postfix-config.tar.gz" ]; then
    log "  - Restoring /etc/postfix"
    tar -xzf "$BACKUP_DIR/postfix-config.tar.gz" -C /etc/
    log "  - Postfix configuration restored"
else
    warn "  - postfix-config.tar.gz not found in backup"
fi

# Restore Postfix queue
log "Restoring Postfix queue..."
if [ -f "$BACKUP_DIR/postfix-spool.tar.gz" ]; then
    log "  - Restoring /var/spool/postfix"
    tar -xzf "$BACKUP_DIR/postfix-spool.tar.gz" -C /var/spool/
    log "  - Postfix queue restored"
else
    warn "  - postfix-spool.tar.gz not found in backup"
fi

# Restore virtual mappings
if [ -f "$BACKUP_DIR/virtual" ]; then
    log "  - Restoring virtual domain mappings"
    cp "$BACKUP_DIR/virtual" /etc/postfix/
fi

# Restore Dovecot configuration
log "Restoring Dovecot configuration..."
if [ -f "$BACKUP_DIR/dovecot-config.tar.gz" ]; then
    log "  - Restoring /etc/dovecot"
    tar -xzf "$BACKUP_DIR/dovecot-config.tar.gz" -C /etc/
    log "  - Dovecot configuration restored"
else
    warn "  - dovecot-config.tar.gz not found in backup"
fi

# Restore mail directories
log "Restoring mail directories..."
for mail_backup in "$BACKUP_DIR"/mail-*.tar.gz; do
    if [ -f "$mail_backup" ]; then
        # Extract the original directory name from the backup filename
        backup_name=$(basename "$mail_backup" .tar.gz)
        dir_name=$(echo "$backup_name" | sed 's/^mail-//' | tr '_' '/')
        
        log "  - Restoring /$dir_name"
        tar -xzf "$mail_backup" -C /
    fi
done

# Restore aliases
log "Restoring mail aliases..."
if [ -f "$BACKUP_DIR/aliases" ]; then
    log "  - Restoring /etc/aliases"
    cp "$BACKUP_DIR/aliases" /etc/
    
    # Rebuild aliases database
    log "  - Rebuilding aliases database"
    newaliases
fi

if [ -f "$BACKUP_DIR/aliases.db" ]; then
    log "  - Restoring /etc/aliases.db"
    cp "$BACKUP_DIR/aliases.db" /etc/
fi

# Restore SSL/TLS certificates (if backed up)
#log "Restoring SSL/TLS certificates..."
#if [ -f "$BACKUP_DIR/tls-certs.tar.gz" ]; then
#    log "  - Restoring /etc/pki/tls"
#    tar -xzf "$BACKUP_DIR/tls-certs.tar.gz" -C /etc/pki/
#fi

#if [ -f "$BACKUP_DIR/letsencrypt.tar.gz" ]; then
#    log "  - Restoring Let's Encrypt certificates"
#    tar -xzf "$BACKUP_DIR/letsencrypt.tar.gz" -C /etc/
#fi

# Set proper permissions
log "Setting proper permissions..."
if [ -d /etc/postfix ]; then
    chown -R root:root /etc/postfix
    chmod 755 /etc/postfix
    chmod 644 /etc/postfix/*
    log "  - Postfix permissions set"
fi

if [ -d /etc/dovecot ]; then
    chown -R root:root /etc/dovecot
    chmod 755 /etc/dovecot
    log "  - Dovecot permissions set"
fi

# fix failures for postfix startup (perms)
if [ -d /var/spool/postfix ]; then
    chown root:root /var/spool/postfix
    chmod 755 /var/spool/postfix
    
    # pid directory must be owned by root
    if [ -d /var/spool/postfix/pid ]; then
        chown root:root /var/spool/postfix/pid
        chmod 755 /var/spool/postfix/pid
    fi
    
    # public and maildrop must be owned by postfix:postdrop
    if [ -d /var/spool/postfix/public ]; then
        chown postfix:postdrop /var/spool/postfix/public
        chmod 710 /var/spool/postfix/public
    fi
    
    if [ -d /var/spool/postfix/maildrop ]; then
        chown postfix:postdrop /var/spool/postfix/maildrop
        chmod 730 /var/spool/postfix/maildrop
    fi
    
    # Most other directories should be owned by postfix
    for dir in active bounce corrupt defer deferred flush hold incoming private saved trace; do
        if [ -d "/var/spool/postfix/$dir" ]; then
            chown postfix:postfix "/var/spool/postfix/$dir"
            chmod 700 "/var/spool/postfix/$dir"
        fi
    done
    
    # Remove any stale pid file
    if [ -f /var/spool/postfix/pid/master.pid ]; then
        log "  - Removing stale PID file"
        rm -f /var/spool/postfix/pid/master.pid
    fi
    log "  - Postfix spool permissions set"
fi

# Set mail directory permissions
for mail_dir in /var/mail /var/spool/mail /home/vmail; do
    if [ -d "$mail_dir" ]; then
        chmod 1777 /var/mail 2>/dev/null || true
        chmod 1777 /var/spool/mail 2>/dev/null || true
        chown -R vmail:vmail /home/vmail 2>/dev/null || true
    fi
done

# Start services
log "Starting mail services..."
if systemctl list-unit-files | grep -q "^postfix.service"; then
    systemctl start postfix
    if systemctl is-active --quiet postfix; then
        log "  - Postfix started successfully"
    else
        error "  - Failed to start Postfix"
    fi
fi

if systemctl list-unit-files | grep -q "^dovecot.service"; then
    systemctl start dovecot
    if systemctl is-active --quiet dovecot; then
        log "  - Dovecot started successfully"
    else
        error "  - Failed to start Dovecot"
    fi
fi

# Verify services
log "Verifying services..."
if systemctl is-active --quiet postfix; then
    log "Postfix is running"
else
    warn "Postfix is not running"
fi

if systemctl is-active --quiet dovecot; then
    log "Dovecot is running"
else
    warn "Dovecot is not running"
fi

log "Restore completed!"
log "Log file: $LOG_FILE"
log ""
log "Please verify:"
log "  - Check Postfix: systemctl status postfix"
log "  - Check Dovecot: systemctl status dovecot"
log "  - Check mail logs: tail -f /var/log/maillog"
log "  - Test sending email"
log "  - Test receiving email"

exit 0