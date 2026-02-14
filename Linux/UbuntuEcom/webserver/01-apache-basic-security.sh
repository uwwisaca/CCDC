#!/bin/bash
#
# Apache 2.4 STIG - Module 1: Basic Security Configuration
# Based on U_Apache_Server_2-4_UNIX_Server_V3R2_Manual_STIG
# Version: 1.0
# Date: February 14, 2026
#
# Usage: sudo ./01-apache-basic-security.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/apache-stig-basic-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/apache-stig-backup-basic-$(date +%Y%m%d-%H%M%S)"

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
log "INFO" "Apache 2.4 STIG - Basic Security Configuration"
log "INFO" "============================================"

# Detect Apache installation
if [ -d "/etc/apache2" ]; then
    APACHE_DIR="/etc/apache2"
    APACHE_SERVICE="apache2"
    APACHE_CMD="apache2ctl"
elif [ -d "/etc/httpd" ]; then
    APACHE_DIR="/etc/httpd"
    APACHE_SERVICE="httpd"
    APACHE_CMD="apachectl"
else
    log "ERROR" "Apache installation not found"
    exit 1
fi

log "INFO" "Apache directory: $APACHE_DIR"

# Create backup
mkdir -p "$BACKUP_DIR"
cp -r "$APACHE_DIR" "$BACKUP_DIR/"
log "SUCCESS" "Backup created: $BACKUP_DIR"

log "INFO" ""
log "INFO" "=== Configuring Apache Modules ==="

# Enable required modules
log "INFO" "Enabling required Apache modules..."
a2enmod ssl 2>/dev/null || log "WARN" "ssl module already enabled or not available"
a2enmod headers 2>/dev/null || log "WARN" "headers module already enabled or not available"
a2enmod rewrite 2>/dev/null || log "WARN" "rewrite module already enabled or not available"
a2enmod env 2>/dev/null || log "WARN" "env module already enabled or not available"
a2enmod setenvif 2>/dev/null || log "WARN" "setenvif module already enabled or not available"

log "SUCCESS" "Required modules enabled"

# Disable unnecessary modules
log "INFO" "Disabling unnecessary modules..."
a2dismod status 2>/dev/null || log "INFO" "status module already disabled or not available"
a2dismod info 2>/dev/null || log "INFO" "info module already disabled or not available"
a2dismod autoindex 2>/dev/null || log "INFO" "autoindex module already disabled or not available"
a2dismod userdir 2>/dev/null || log "INFO" "userdir module already disabled or not available"
a2dismod cgi 2>/dev/null || log "INFO" "cgi module already disabled or not available"

log "SUCCESS" "Unnecessary modules disabled"

log "INFO" ""
log "INFO" "=== Creating Basic Security Configuration ==="

# Create main STIG configuration file
cat > "$APACHE_DIR/conf-available/stig-basic-security.conf" << 'EOF'
# Apache 2.4 STIG - Basic Security Configuration

# AS24-U1-000010: Server tokens - Minimize information disclosure
ServerTokens Prod
ServerSignature Off

# AS24-U1-000020: Disable TRACE method (prevents XST attacks)
TraceEnable Off

# AS24-U1-000030: Set timeout (prevents slowloris attacks)
Timeout 10

# AS24-U1-000040: Max keep-alive requests
MaxKeepAliveRequests 100

# AS24-U1-000050: Keep-alive timeout
KeepAliveTimeout 15

# AS24-U1-000060: Request line limit
LimitRequestLine 8190

# AS24-U1-000070: Request field size
LimitRequestFieldSize 8190

# AS24-U1-000080: Number of request fields
LimitRequestFields 100

# AS24-U1-000090: Request body limit (1MB default, adjust as needed)
LimitRequestBody 1048576

# Disable directory listings (AS24-U1-000160)
<Directory />
    Options None
    AllowOverride None
    Require all denied
</Directory>

# Disable default redirects to icons and manual
RedirectMatch 404 /\..*$
RedirectMatch 404 /icons
RedirectMatch 404 /manual

# File and directory protection
<DirectoryMatch "^/.*/\.">
    Require all denied
</DirectoryMatch>

<FilesMatch "^\.ht">
    Require all denied
</FilesMatch>

<FilesMatch "\.(bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist)$">
    Require all denied
</FilesMatch>

# Disable dangerous file types
<IfModule mod_mime.c>
    <FilesMatch "\.(exe|dll|bat|cmd|com|pif|scr|vbs|js|msi)$">
        Require all denied
    </FilesMatch>
</IfModule>

# Disable CGI execution in uploads directory (AS24-U1-000180)
<Directory /var/www/html/uploads>
    Options -ExecCGI
    AddHandler cgi-script .php .pl .py .jsp .asp .sh .cgi
    RemoveHandler .php .pl .py .jsp .asp .sh .cgi
</Directory>
EOF

# Enable configuration
if [ -d "$APACHE_DIR/conf-available" ]; then
    a2enconf stig-basic-security 2>/dev/null
    log "SUCCESS" "Enabled basic security configuration"
else
    # For non-Debian systems, include directly
    if ! grep -q "Include.*stig-basic-security.conf" "$APACHE_DIR/conf/httpd.conf" 2>/dev/null; then
        echo "Include $APACHE_DIR/conf-available/stig-basic-security.conf" >> "$APACHE_DIR/conf/httpd.conf"
        log "SUCCESS" "Added basic security configuration to httpd.conf"
    fi
fi

log "SUCCESS" "Created basic security configuration"

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
log "SUCCESS" "Basic Security Configuration Complete"
log "INFO" "============================================"
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "INFO" ""
log "INFO" "=== Applied Settings Summary ==="
log "INFO" "- ServerTokens: Prod (minimal information)"
log "INFO" "- ServerSignature: Off"
log "INFO" "- TRACE method: Disabled"
log "INFO" "- Timeout: 10 seconds"
log "INFO" "- KeepAliveTimeout: 15 seconds"
log "INFO" "- Request body limit: 1MB"
log "INFO" "- Directory listings: Disabled"
log "INFO" "- Dangerous file types: Blocked"
log "INFO" "- Unnecessary modules: Disabled"
log "WARN" ""
log "WARN" "=== NEXT STEPS ==="
log "WARN" "1. Restart Apache for changes to take effect:"
log "WARN" "   sudo systemctl restart $APACHE_SERVICE"
log "WARN" "2. Continue with Module 2 (SSL/TLS Configuration)"
log "WARN" "3. Adjust LimitRequestBody if your application needs larger uploads"
