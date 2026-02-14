#!/bin/bash

# Apache2 web server backup
# Created with assistance from AI

set -e

if [[ $EUID -ne 0 ]]; then
    echo -e "This script must be run as root."
    exit 1
fi

# Create backup dir
sudo mkdir -p /root/backup
sudo chmod 700 /root/backup

# Configuration
BACKUP_BASE_DIR="${1:-/root/backup}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="${BACKUP_BASE_DIR}/apache-backup-${TIMESTAMP}"
LOG_FILE="${BACKUP_BASE_DIR}/backup-${TIMESTAMP}.log"

# OpenCart configuration (auto-detect or set manually)
OPENCART_ROOT="${OPENCART_ROOT:-/var/www/html}"
OPENCART_CONFIG="${OPENCART_ROOT}/config.php"

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

# Create backup directory
log "Creating backup directory: $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

# Backup Apache2 configuration and data
log "Backing up Apache2..."
if systemctl is-active --quiet apache2; then
    APACHE_RUNNING=true
    log "Apache2 is running"
else
    APACHE_RUNNING=false
    warn "Apache2 is not running"
fi

# Apache configuration
if [ -d /etc/apache2 ]; then
    log "  - Backing up /etc/apache2 configuration"
    tar -czf "$BACKUP_DIR/apache2-config.tar.gz" -C /etc apache2
else
    warn "  - /etc/apache2 not found"
fi

# Enabled sites
if [ -d /etc/apache2/sites-enabled ]; then
    log "  - Backing up enabled sites list"
    ls -la /etc/apache2/sites-enabled > "$BACKUP_DIR/apache2-sites-enabled.txt"
fi

# Enabled modules
if [ -d /etc/apache2/mods-enabled ]; then
    log "  - Backing up enabled modules list"
    ls -la /etc/apache2/mods-enabled > "$BACKUP_DIR/apache2-mods-enabled.txt"
fi

# Backup OpenCart files
log "Backing up OpenCart..."

# Try to find OpenCart installation
if [ ! -f "$OPENCART_CONFIG" ]; then
    warn "OpenCart config not found at $OPENCART_CONFIG"
    
    # Common OpenCart locations
    for loc in "/var/www/html/opencart" "/var/www/opencart" "/var/www/html"; do
        if [ -f "$loc/config.php" ]; then
            OPENCART_ROOT="$loc"
            OPENCART_CONFIG="$loc/config.php"
            log "Found OpenCart installation at: $OPENCART_ROOT"
            break
        fi
    done
fi

if [ -f "$OPENCART_CONFIG" ]; then
    log "  - OpenCart root: $OPENCART_ROOT"
    
    # Backup OpenCart files
    log "  - Backing up OpenCart files"
    tar -czf "$BACKUP_DIR/opencart-files.tar.gz" \
        --exclude='*.log' \
        --exclude='*.tmp' \
        --exclude='cache/*' \
        --exclude='system/storage/cache/*' \
        --exclude='system/storage/logs/*' \
        -C "$(dirname "$OPENCART_ROOT")" \
        "$(basename "$OPENCART_ROOT")"
    
    # Extract database credentials from config
    DB_HOST=$(grep "define('DB_HOSTNAME'" "$OPENCART_CONFIG" | sed "s/.*'\(.*\)'.*/\1/" || echo "localhost")
    DB_USER=$(grep "define('DB_USERNAME'" "$OPENCART_CONFIG" | sed "s/.*'\(.*\)'.*/\1/" || echo "")
    DB_PASS=$(grep "define('DB_PASSWORD'" "$OPENCART_CONFIG" | sed "s/.*'\(.*\)'.*/\1/" || echo "")
    DB_NAME=$(grep "define('DB_DATABASE'" "$OPENCART_CONFIG" | sed "s/.*'\(.*\)'.*/\1/" || echo "")
    
    if [ -n "$DB_NAME" ] && [ -n "$DB_USER" ]; then
        log "  - Backing up database: $DB_NAME"
        
        # Create MySQL config file for credentials
        MYSQL_CNF="/tmp/.my.cnf.$$"
        cat > "$MYSQL_CNF" <<EOF
[client]
host=$DB_HOST
user=$DB_USER
password=$DB_PASS
EOF
        chmod 600 "$MYSQL_CNF"
        
        # Backup database
        if command -v mysqldump &> /dev/null; then
            mysqldump --defaults-file="$MYSQL_CNF" \
                --single-transaction \
                --quick \
                --lock-tables=false \
                "$DB_NAME" | gzip > "$BACKUP_DIR/opencart-database.sql.gz"
            rm "$MYSQL_CNF"
        else
            warn "  - mysqldump not found, skipping database backup"
            rm "$MYSQL_CNF"
        fi
    else
        warn "  - Could not extract database credentials"
    fi
else
    warn "  - OpenCart installation not found"
fi

# Backup PHP configuration
log "Backing up PHP..."
PHP_VERSION=$(php -v 2>/dev/null | head -n1 | grep -oP '\d+\.\d+' | head -n1 || echo "")

if [ -n "$PHP_VERSION" ]; then
    log "  - PHP version: $PHP_VERSION"
    
    if [ -d "/etc/php/$PHP_VERSION/apache2" ]; then
        log "  - Backing up PHP Apache configuration"
        tar -czf "$BACKUP_DIR/php-apache-config.tar.gz" -C /etc/php/$PHP_VERSION apache2
    else
        warn "  - /etc/php/$PHP_VERSION/apache2 not found"
    fi
else
    warn "  - PHP not found"
fi

# Backup SSL/TLS certificates
#log "Backing up SSL/TLS certificates..."
#if [ -d /etc/letsencrypt ]; then
#    log "  - Backing up Let's Encrypt certificates"
#    tar -czf "$BACKUP_DIR/letsencrypt.tar.gz" -C /etc letsencrypt
#fi

#if [ -d /etc/ssl/certs ]; then
#    log "  - Backing up SSL certificates"
#    tar -czf "$BACKUP_DIR/ssl-certs.tar.gz" -C /etc/ssl certs
#fi

# Save systemd service states
log "Saving service states..."
{
    echo "=== Service States ==="
    for service in apache2 mysql; do
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
    echo "=== Apache/OpenCart Server Backup Manifest ==="
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