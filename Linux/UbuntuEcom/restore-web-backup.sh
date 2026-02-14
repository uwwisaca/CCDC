#!/bin/bash

# Apache/OpenCart server restore
# Created with assistance from AI

set -e

if [[ $EUID -ne 0 ]]; then
    echo -e "This script must be run as root."
    exit 1
fi

# Configuration
BACKUP_DIR="${1:-}"
LOG_FILE="/var/log/apache-restore-$(date +%Y%m%d_%H%M%S).log"

# Restore target (can be overridden)
OPENCART_ROOT="${OPENCART_ROOT:-/var/www/html}"

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
    ls -ld /root/backup/apache-backup-* 2>/dev/null || echo "  No backups found"
    exit 1
fi

# Verify backup directory exists
if [ ! -d "$BACKUP_DIR" ]; then
    error "Backup directory does not exist: $BACKUP_DIR"
    exit 1
fi

log "Starting Apache/OpenCart restore from: $BACKUP_DIR"
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
log "Stopping services..."
if systemctl is-active --quiet apache2; then
    systemctl stop apache2
    log "  - Stopped Apache2"
fi

if systemctl is-active --quiet mysql; then
    log "  - MySQL is running (will remain running for restore)"
elif systemctl is-active --quiet mariadb; then
    log "  - MariaDB is running (will remain running for restore)"
else
    warn "  - No MySQL/MariaDB service found running"
fi

# Restore Apache2 configuration
log "Restoring Apache2 configuration..."
if [ -f "$BACKUP_DIR/apache2-config.tar.gz" ]; then
    log "  - Restoring /etc/apache2"
    tar -xzf "$BACKUP_DIR/apache2-config.tar.gz" -C /etc/
    log "  - Apache2 configuration restored"
else
    warn "  - apache2-config.tar.gz not found in backup"
fi

# Restore OpenCart files
log "Restoring OpenCart files..."
if [ -f "$BACKUP_DIR/opencart-files.tar.gz" ]; then
    log "  - Restoring OpenCart to $OPENCART_ROOT"
    
    # Extract to parent directory
    tar -xzf "$BACKUP_DIR/opencart-files.tar.gz" -C "$(dirname "$OPENCART_ROOT")"
    log "  - OpenCart files restored"
else
    warn "  - opencart-files.tar.gz not found in backup"
fi

# Restore database
log "Restoring database..."
if [ -f "$BACKUP_DIR/opencart-database.sql.gz" ]; then
    # Try to get database credentials from restored config
    OPENCART_CONFIG="$OPENCART_ROOT/config.php"
    
    if [ -f "$OPENCART_CONFIG" ]; then
        DB_HOST=$(grep "define('DB_HOSTNAME'" "$OPENCART_CONFIG" | sed "s/.*'\(.*\)'.*/\1/" || echo "localhost")
        DB_USER=$(grep "define('DB_USERNAME'" "$OPENCART_CONFIG" | sed "s/.*'\(.*\)'.*/\1/" || echo "")
        DB_PASS=$(grep "define('DB_PASSWORD'" "$OPENCART_CONFIG" | sed "s/.*'\(.*\)'.*/\1/" || echo "")
        DB_NAME=$(grep "define('DB_DATABASE'" "$OPENCART_CONFIG" | sed "s/.*'\(.*\)'.*/\1/" || echo "")
        
        if [ -n "$DB_NAME" ] && [ -n "$DB_USER" ]; then
            log "  - Database: $DB_NAME"
            log "  - User: $DB_USER"
            
            # Create MySQL config file for credentials
            MYSQL_CNF="/tmp/.my.cnf.$$"
            cat > "$MYSQL_CNF" <<EOF
[client]
host=$DB_HOST
user=$DB_USER
password=$DB_PASS
EOF
            chmod 600 "$MYSQL_CNF"
            
            # Check if database exists, create if not
            if ! mysql --defaults-file="$MYSQL_CNF" -e "USE $DB_NAME" 2>/dev/null; then
                log "  - Creating database: $DB_NAME"
                mysql --defaults-file="$MYSQL_CNF" -e "CREATE DATABASE $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci" 2>/dev/null || true
            fi
            
            # Restore database
            log "  - Restoring database content (this may take a while)..."
            gunzip < "$BACKUP_DIR/opencart-database.sql.gz" | mysql --defaults-file="$MYSQL_CNF" "$DB_NAME"
            
            rm "$MYSQL_CNF"
            log "  - Database restored successfully"
        else
            error "  - Could not extract database credentials from config.php"
            error "  - Please restore database manually"
        fi
    else
        warn "  - OpenCart config.php not found"
        warn "  - Please restore database manually"
    fi
else
    warn "  - opencart-database.sql.gz not found in backup"
fi

# Restore PHP configuration
log "Restoring PHP configuration..."
if [ -f "$BACKUP_DIR/php-apache-config.tar.gz" ]; then
    PHP_VERSION=$(php -v 2>/dev/null | head -n1 | grep -oP '\d+\.\d+' | head -n1 || echo "")
    
    if [ -n "$PHP_VERSION" ]; then
        log "  - Restoring PHP $PHP_VERSION configuration"
        tar -xzf "$BACKUP_DIR/php-apache-config.tar.gz" -C /etc/php/$PHP_VERSION/
        log "  - PHP configuration restored"
    else
        warn "  - PHP version could not be detected"
    fi
else
    warn "  - php-apache-config.tar.gz not found in backup"
fi

# Restore SSL/TLS certificates (if backed up)
#log "Restoring SSL/TLS certificates..."
#if [ -f "$BACKUP_DIR/letsencrypt.tar.gz" ]; then
#    log "  - Restoring Let's Encrypt certificates"
#    tar -xzf "$BACKUP_DIR/letsencrypt.tar.gz" -C /etc/
#fi

#if [ -f "$BACKUP_DIR/ssl-certs.tar.gz" ]; then
#    log "  - Restoring SSL certificates"
#    tar -xzf "$BACKUP_DIR/ssl-certs.tar.gz" -C /etc/ssl/
#fi

# Set proper permissions
log "Setting proper permissions..."
if [ -d "$OPENCART_ROOT" ]; then
    chown -R www-data:www-data "$OPENCART_ROOT"
    find "$OPENCART_ROOT" -type f -exec chmod 644 {} \;
    find "$OPENCART_ROOT" -type d -exec chmod 755 {} \;
    
    # Make specific directories writable
    if [ -d "$OPENCART_ROOT/image" ]; then
        chmod -R 777 "$OPENCART_ROOT/image"
    fi
    
    if [ -d "$OPENCART_ROOT/system/storage" ]; then
        chmod -R 777 "$OPENCART_ROOT/system/storage"
    fi
    
    if [ -d "$OPENCART_ROOT/system/cache" ]; then
        chmod -R 777 "$OPENCART_ROOT/system/cache"
    fi
    
    if [ -d "$OPENCART_ROOT/download" ]; then
        chmod -R 777 "$OPENCART_ROOT/download"
    fi
    
    log "  - OpenCart permissions set"
fi

if [ -d /etc/apache2 ]; then
    chown -R root:root /etc/apache2
    log "  - Apache2 permissions set"
fi

# Test Apache configuration
log "Testing Apache configuration..."
if apache2ctl configtest 2>&1 | grep -q "Syntax OK"; then
    log "Apache configuration is valid"
else
    error "Apache configuration has errors"
    apache2ctl configtest 2>&1 | tee -a "$LOG_FILE"
fi

# Start services
log "Starting services..."
if systemctl list-unit-files | grep -q "^apache2.service"; then
    systemctl start apache2
    if systemctl is-active --quiet apache2; then
        log "  - Apache2 started successfully"
    else
        error "  - Failed to start Apache2"
        error "  - Check logs: journalctl -xeu apache2"
    fi
fi

# Verify services
log "Verifying services..."
if systemctl is-active --quiet apache2; then
    log " Apache2 is running"
else
    warn "Apache2 is not running"
fi

if systemctl is-active --quiet mysql; then
    log "MySQL is running"
elif systemctl is-active --quiet mariadb; then
    log "MariaDB is running"
else
    warn "Database service is not running"
fi

log "Restore completed!"
log "Log file: $LOG_FILE"
log ""
log "Please verify:"
log "  - Check Apache: systemctl status apache2"
log "  - Check MySQL: systemctl status mysql"
log "  - Check Apache logs: tail -f /var/log/apache2/error.log"
log "  - Visit your website in a browser"
log "  - Test OpenCart admin panel"
log "  - Test checkout process"

exit 0
