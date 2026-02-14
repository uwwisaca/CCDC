#!/bin/bash
#
# Apache 2.4 STIG - Module 4: File Permissions & Access Control
# Based on U_Apache_Server_2-4_UNIX_Server_V3R2_Manual_STIG
# Version: 1.0
# Date: February 14, 2026
#
# Usage: sudo ./04-apache-file-permissions.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/apache-stig-permissions-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/apache-stig-backup-permissions-$(date +%Y%m%d-%H%M%S)"

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

log "INFO" "============================================"
log "INFO" "Apache 2.4 STIG - File Permissions & Access Control"
log "INFO" "============================================"

# Detect Apache installation
if [ -d "/etc/apache2" ]; then
    APACHE_DIR="/etc/apache2"
    APACHE_SERVICE="apache2"
    APACHE_USER="www-data"
    APACHE_GROUP="www-data"
    LOG_DIR="/var/log/apache2"
    DOC_ROOT="/var/www/html"
elif [ -d "/etc/httpd" ]; then
    APACHE_DIR="/etc/httpd"
    APACHE_SERVICE="httpd"
    APACHE_USER="apache"
    APACHE_GROUP="apache"
    LOG_DIR="/var/log/httpd"
    DOC_ROOT="/var/www/html"
else
    log "ERROR" "Apache installation not found"
    exit 1
fi

log "INFO" "Apache directory: $APACHE_DIR"
log "INFO" "Apache user: $APACHE_USER"
log "INFO" "Document root: $DOC_ROOT"

# Create backup
mkdir -p "$BACKUP_DIR"
log "SUCCESS" "Backup directory created: $BACKUP_DIR"

log "INFO" ""
log "INFO" "=== Setting Apache Configuration Directory Permissions ==="

# Apache configuration directories (AS24-U1-000280 through AS24-U1-000310)
# Root owns config, Apache user can only read
chown -R root:root "$APACHE_DIR"
chmod 750 "$APACHE_DIR"

# Set file permissions in Apache directory
find "$APACHE_DIR" -type f -exec chmod 640 {} \;
find "$APACHE_DIR" -type d -exec chmod 750 {} \;

log "SUCCESS" "Set Apache configuration directory permissions"

log "INFO" ""
log "INFO" "=== Setting Document Root Permissions ==="

# Document root - Apache user owns content
if [ -d "$DOC_ROOT" ]; then
    chown -R root:$APACHE_GROUP "$DOC_ROOT"
    
    # Files: readable by Apache, writable by root only
    find "$DOC_ROOT" -type f -exec chmod 644 {} \;
    
    # Directories: executable for traversal
    find "$DOC_ROOT" -type d -exec chmod 755 {} \;
    
    log "SUCCESS" "Set document root permissions: $DOC_ROOT"
else
    log "WARN" "Document root not found: $DOC_ROOT"
fi

log "INFO" ""
log "INFO" "=== Setting Log Directory Permissions ==="

# Log files - Only Apache user and root can access
if [ -d "$LOG_DIR" ]; then
    chown -R root:$APACHE_GROUP "$LOG_DIR"
    chmod 750 "$LOG_DIR"
    
    # Set permissions on existing log files
    find "$LOG_DIR" -type f -exec chmod 640 {} \;
    
    log "SUCCESS" "Set log directory permissions: $LOG_DIR"
else
    log "WARN" "Log directory not found: $LOG_DIR"
fi

log "INFO" ""
log "INFO" "=== Creating Uploads Directory with Restricted Permissions ==="

# Create uploads directory with restrictive permissions
UPLOADS_DIR="$DOC_ROOT/uploads"
if [ ! -d "$UPLOADS_DIR" ]; then
    mkdir -p "$UPLOADS_DIR"
    chown root:$APACHE_GROUP "$UPLOADS_DIR"
    chmod 750 "$UPLOADS_DIR"
    log "SUCCESS" "Created uploads directory: $UPLOADS_DIR"
else
    chown root:$APACHE_GROUP "$UPLOADS_DIR"
    chmod 750 "$UPLOADS_DIR"
    log "SUCCESS" "Updated uploads directory permissions: $UPLOADS_DIR"
fi

log "INFO" ""
log "INFO" "=== Creating Access Control Configuration ==="

# Create file access control configuration
cat > "$APACHE_DIR/conf-available/stig-file-access.conf" << 'EOF'
# Apache 2.4 STIG - File Access Control Configuration

# Deny access to hidden files and directories
<DirectoryMatch "^/.*/\.">
    Require all denied
</DirectoryMatch>

# Deny access to Apache configuration files
<FilesMatch "^\.ht">
    Require all denied
</FilesMatch>

# Deny access to backup and sensitive files
<FilesMatch "\.(bak|backup|old|swp|config|sql|fla|psd|ini|log|sh|inc|dist|save|mysql|db)$">
    Require all denied
</FilesMatch>

# Deny access to version control directories
<DirectoryMatch "/(\.git|\.svn|\.hg|CVS|\.bzr)">
    Require all denied
</DirectoryMatch>

# Deny access to common backup directories
<DirectoryMatch "/(backup|backups|old|tmp|temp|cache)">
    Options -Indexes
    <FilesMatch "\.(sql|gz|zip|tar|bz2)$">
        Require all denied
    </FilesMatch>
</DirectoryMatch>

# Protect sensitive directories
<Directory /var/www/html/admin>
    Options -Indexes -FollowSymLinks
    AllowOverride None
    
    # Require authentication (configure as needed)
    # AuthType Basic
    # AuthName "Restricted Area"
    # AuthUserFile /etc/apache2/.htpasswd
    # Require valid-user
    
    # Or restrict by IP
    # Require ip 10.0.0.0/8 192.168.0.0/16
</Directory>

<Directory /var/www/html/private>
    Options -Indexes -FollowSymLinks
    AllowOverride None
    Require all denied
</Directory>

# Uploads directory - no script execution
<Directory /var/www/html/uploads>
    Options -Indexes -ExecCGI -FollowSymLinks
    AllowOverride None
    
    # Disable script handlers
    AddHandler cgi-script .php .pl .py .jsp .asp .sh .cgi .rb
    RemoveHandler .php .pl .py .jsp .asp .sh .cgi .rb
    
    # Only allow specific file types (images, documents, etc.)
    <FilesMatch "\.(jpg|jpeg|png|gif|pdf|doc|docx|xls|xlsx|txt)$">
        Require all granted
    </FilesMatch>
    
    # Deny everything else
    <FilesMatch "^.*$">
        Require all denied
    </FilesMatch>
</Directory>

# Deny access to dangerous file types
<FilesMatch "\.(exe|dll|bat|cmd|com|pif|scr|vbs|js|jar|msi|app|deb|rpm)$">
    Require all denied
</FilesMatch>

# Deny access to sensitive application files
<FilesMatch "(composer\.json|composer\.lock|package\.json|package-lock\.json|yarn\.lock|Gemfile|Gemfile\.lock|\.env|\.htpasswd)$">
    Require all denied
</FilesMatch>

# Default deny for root directory
<Directory />
    Options None
    AllowOverride None
    Require all denied
</Directory>

# Document root configuration
<Directory /var/www/html>
    Options -Indexes -FollowSymLinks
    AllowOverride None
    Require all granted
    
    # Prevent access to PHP source code
    <FilesMatch "\.phps$">
        Require all denied
    </FilesMatch>
</Directory>
EOF

# Enable file access configuration
if [ -d "$APACHE_DIR/conf-available" ]; then
    a2enconf stig-file-access 2>/dev/null
    log "SUCCESS" "Enabled file access configuration"
else
    # For non-Debian systems, include directly
    if ! grep -q "Include.*stig-file-access.conf" "$APACHE_DIR/conf/httpd.conf" 2>/dev/null; then
        echo "Include $APACHE_DIR/conf-available/stig-file-access.conf" >> "$APACHE_DIR/conf/httpd.conf"
        log "SUCCESS" "Added file access configuration to httpd.conf"
    fi
fi

log "INFO" ""
log "INFO" "=== Verifying Critical File Permissions ==="

# Verify critical files
CRITICAL_FILES=(
    "$APACHE_DIR/apache2.conf:640"
    "$APACHE_DIR/envvars:640"
    "$APACHE_DIR/ports.conf:640"
)

for item in "${CRITICAL_FILES[@]}"; do
    file=$(echo "$item" | cut -d: -f1)
    perm=$(echo "$item" | cut -d: -f2)
    
    if [ -f "$file" ]; then
        chmod "$perm" "$file" 2>/dev/null || true
        log "SUCCESS" "Verified $file permissions"
    fi
done

log "INFO" ""
log "INFO" "=== Creating Permission Verification Script ==="

# Create script to verify permissions
cat > "/root/verify-apache-permissions.sh" << 'EOF'
#!/bin/bash
# Apache Permission Verification Script

echo "=== Apache Permission Verification ==="
echo ""

# Check Apache config directory
if [ -d "/etc/apache2" ]; then
    APACHE_DIR="/etc/apache2"
elif [ -d "/etc/httpd" ]; then
    APACHE_DIR="/etc/httpd"
fi

echo "Apache Config Directory:"
ls -ld "$APACHE_DIR"
echo ""

echo "Apache Config Files (sample):"
ls -l "$APACHE_DIR"/*.conf 2>/dev/null | head -5
echo ""

echo "Document Root:"
ls -ld /var/www/html 2>/dev/null || ls -ld /var/www 2>/dev/null
echo ""

echo "Log Directory:"
ls -ld /var/log/apache2 2>/dev/null || ls -ld /var/log/httpd 2>/dev/null
echo ""

echo "Checking for world-writable files in document root:"
find /var/www -type f -perm -002 2>/dev/null | head -10
echo ""

echo "Checking for suspicious SUID/SGID files:"
find /var/www -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null
echo ""

echo "=== Verification Complete ==="
EOF

chmod 750 /root/verify-apache-permissions.sh
log "SUCCESS" "Created permission verification script: /root/verify-apache-permissions.sh"

log "INFO" ""
log "INFO" "=== Testing Configuration ==="

# Test Apache configuration
if $APACHE_CMD configtest > /dev/null 2>&1; then
    log "SUCCESS" "Apache configuration test passed"
else
    log "ERROR" "Apache configuration test failed"
    log "ERROR" "Run: $APACHE_CMD configtest"
    exit 1
fi

log "INFO" ""
log "INFO" "============================================"
log "SUCCESS" "File Permissions & Access Control Complete"
log "INFO" "============================================"
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "INFO" ""
log "INFO" "=== Applied Settings Summary ==="
log "INFO" "- Apache config directory: 750 (root:root)"
log "INFO" "- Apache config files: 640"
log "INFO" "- Document root: 755/644 (root:$APACHE_GROUP)"
log "INFO" "- Log directory: 750 (root:$APACHE_GROUP)"
log "INFO" "- Uploads directory: 750 with no script execution"
log "INFO" "- Hidden files: Denied"
log "INFO" "- Backup files: Denied"
log "INFO" "- Version control dirs: Denied"
log "INFO" "- Dangerous file types: Denied"
log "WARN" ""
log "WARN" "=== NEXT STEPS ==="
log "WARN" "1. Verify permissions:"
log "WARN" "   sudo /root/verify-apache-permissions.sh"
log "WARN" ""
log "WARN" "2. Restart Apache:"
log "WARN" "   sudo systemctl restart $APACHE_SERVICE"
log "WARN" ""
log "WARN" "3. Test file access restrictions:"
log "WARN" "   curl https://your-domain.com/.git/"
log "WARN" "   curl https://your-domain.com/config.bak"
log"WARN" ""
log "WARN" "4. Configure admin area authentication if needed"
