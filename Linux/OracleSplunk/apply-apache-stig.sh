#!/bin/bash
#
# Apache Web Server STIG Implementation Script
# Supports: Ubuntu/Debian Apache 2.4
# Based on: U_Apache_Server_2-4_UNIX_Server_V3R2_Manual_STIG
# Version: 1.0
# Date: January 30, 2026
#
# Usage: sudo ./apply-apache-stig.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/apache-stig-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/apache-stig-backup-$(date +%Y%m%d-%H%M%S)"

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
log "INFO" "Apache 2.4 STIG Application Starting"
log "INFO" "========================================"

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

# Install required modules
log "INFO" "Enabling required Apache modules..."
a2enmod ssl
a2enmod headers
a2enmod rewrite
a2enmod log_config
a2enmod env
a2enmod setenvif

# Disable unnecessary modules
log "INFO" "Disabling unnecessary modules..."
a2dismod status || true
a2dismod info || true
a2dismod autoindex || true
a2dismod userdir || true
a2dismod cgi || true

log "INFO" "Creating STIG configuration..."

# Create main STIG configuration file
cat > "$APACHE_DIR/conf-available/stig-security.conf" << 'EOF'
# Apache 2.4 STIG Security Configuration

# AS24-U1-000010: Server tokens
ServerTokens Prod
ServerSignature Off

# AS24-U1-000020: Disable TRACE
TraceEnable Off

# AS24-U1-000030: Set timeout
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

# AS24-U1-000090: Request body limit
LimitRequestBody 1048576

# Security Headers (AS24-U1-000100 through AS24-U1-000150)
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always unset X-Powered-By
Header always unset Server

# Disable directory listings (AS24-U1-000160)
<Directory />
    Options None
    AllowOverride None
    Require all denied
</Directory>

# Session cookie security (AS24-U1-000170)
Header edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure

# File and directory permissions
<DirectoryMatch "^/.*/\.">
    Require all denied
</DirectoryMatch>

<FilesMatch "^\.ht">
    Require all denied
</FilesMatch>

<FilesMatch "\.(bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist)$">
    Require all denied
</FilesMatch>

# Disable CGI execution in uploads directory (AS24-U1-000180)
<Directory /var/www/html/uploads>
    Options -ExecCGI
    AddHandler cgi-script .php .pl .py .jsp .asp .sh .cgi
    RemoveHandler .php .pl .py .jsp .asp .sh .cgi
</Directory>

# Log format (AS24-U1-000190)
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %D" combined_with_response_time
CustomLog /var/log/apache2/access.log combined_with_response_time
ErrorLog /var/log/apache2/error.log

# Error log level (AS24-U1-000200)
LogLevel warn

# File upload restrictions
<IfModule mod_mime.c>
    # Restrict dangerous file types
    <FilesMatch "\.(exe|dll|bat|cmd|com|pif|scr|vbs|js|msi)$">
        Require all denied
    </FilesMatch>
</IfModule>

# Clickjacking protection
<IfModule mod_headers.c>
    Header always append X-Frame-Options SAMEORIGIN
</IfModule>

# Require SSL/TLS (AS24-U1-000210)
<IfModule mod_ssl.c>
    SSLEngine on
    
    # SSL Protocol (AS24-U1-000220)
    SSLProtocol -all +TLSv1.2 +TLSv1.3
    
    # SSL Cipher Suite (AS24-U1-000230)
    SSLCipherSuite HIGH:!aNULL:!MD5:!3DES:!CAMELLIA:!AES128
    SSLHonorCipherOrder on
    
    # SSL Compression (AS24-U1-000240)
    SSLCompression off
    
    # OCSP Stapling (AS24-U1-000250)
    SSLUseStapling on
    SSLStaplingCache "shmcb:logs/ssl_stapling(32768)"
    
    # SSL Session Cache (AS24-U1-000260)
    SSLSessionCache "shmcb:logs/ssl_scache(512000)"
    SSLSessionCacheTimeout 300
</IfModule>

# Restrict HTTP methods (AS24-U1-000270)
<LimitExcept GET POST HEAD>
    Require all denied
</LimitExcept>

# Disable default sites and examples
RedirectMatch 404 /\..*$
RedirectMatch 404 /icons
RedirectMatch 404 /manual
EOF

# Enable STIG configuration
if [ -d "$APACHE_DIR/conf-available" ]; then
    a2enconf stig-security
fi

log "SUCCESS" "Created STIG security configuration"

# Configure SSL if mod_ssl is enabled
if [ -f "$APACHE_DIR/mods-enabled/ssl.conf" ] || [ -f "$APACHE_DIR/mods-enabled/ssl.load" ]; then
    log "INFO" "Configuring SSL settings..."
    
    # Create SSL configuration
    cat > "$APACHE_DIR/conf-available/stig-ssl.conf" << 'EOF'
# STIG SSL Configuration

<IfModule mod_ssl.c>
    # Disable SSLv2 and SSLv3 (AS24-U2-000010)
    SSLProtocol -all +TLSv1.2 +TLSv1.3
    
    # Strong ciphers only (AS24-U2-000020)
    SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    
    # Honor server cipher order (AS24-U2-000030)
    SSLHonorCipherOrder on
    
    # Disable SSL compression (AS24-U2-000040)
    SSLCompression off
    
    # Enable OCSP stapling (AS24-U2-000050)
    SSLUseStapling on
    SSLStaplingResponderTimeout 5
    SSLStaplingReturnResponderErrors off
    SSLStaplingCache "shmcb:/var/run/ocsp(128000)"
    
    # SSL session tickets (AS24-U2-000060)
    SSLSessionTickets off
    
    # Client certificate verification (AS24-U2-000070)
    # SSLVerifyClient require
    # SSLVerifyDepth 10
    
    # HSTS (AS24-U2-000080)
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
</IfModule>
EOF
    
    if [ -d "$APACHE_DIR/conf-available" ]; then
        a2enconf stig-ssl
    fi
    
    log "SUCCESS" "Configured SSL settings"
fi

# Set proper file permissions (AS24-U1-000280 through AS24-U1-000310)
log "INFO" "Setting file permissions..."

# Apache configuration directories
chmod 750 "$APACHE_DIR"
find "$APACHE_DIR" -type f -exec chmod 640 {} \;
find "$APACHE_DIR" -type d -exec chmod 750 {} \;

# Document root
if [ -d "/var/www/html" ]; then
    chown -R root:www-data /var/www/html
    find /var/www/html -type f -exec chmod 644 {} \;
    find /var/www/html -type d -exec chmod 755 {} \;
fi

# Log files
if [ -d "/var/log/apache2" ]; then
    chmod 750 /var/log/apache2
    find /var/log/apache2 -type f -exec chmod 640 {} \;
elif [ -d "/var/log/httpd" ]; then
    chmod 750 /var/log/httpd
    find /var/log/httpd -type f -exec chmod 640 {} \;
fi

log "SUCCESS" "Set file permissions"

# Configure log rotation
log "INFO" "Configuring log rotation..."

cat > /etc/logrotate.d/apache2-stig << 'EOF'
/var/log/apache2/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 640 root adm
    sharedscripts
    postrotate
        if [ -f /var/run/apache2/apache2.pid ]; then
            /etc/init.d/apache2 reload > /dev/null
        fi
    endscript
}
EOF

log "SUCCESS" "Configured log rotation"

# Create default secure virtual host template
log "INFO" "Creating secure virtual host template..."

cat > "$APACHE_DIR/sites-available/000-default-ssl.conf" << 'EOF'
<IfModule mod_ssl.c>
<VirtualHost _default_:443>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html
    
    # Logging
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined_with_response_time
    
    # SSL Configuration
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem
    SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key
    
    # Security Headers
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Strict-Transport-Security "max-age=31536000"
    
    <Directory /var/www/html>
        Options -Indexes -FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>
    
    # Disable TRACE
    TraceEnable Off
    
    # Restrict HTTP methods
    <LimitExcept GET POST HEAD>
        Require all denied
    </LimitExcept>
</VirtualHost>
</IfModule>
EOF

log "SUCCESS" "Created secure virtual host template"

# Disable default sites that are not secure
if [ -L "$APACHE_DIR/sites-enabled/000-default.conf" ]; then
    a2dissite 000-default
    log "SUCCESS" "Disabled default HTTP site"
fi

# Test Apache configuration
log "INFO" "Testing Apache configuration..."
if $APACHE_CMD configtest > /dev/null 2>&1; then
    log "SUCCESS" "Apache configuration test passed"
    
    # Restart Apache
    systemctl restart $APACHE_SERVICE
    log "SUCCESS" "Apache restarted successfully"
else
    log "ERROR" "Apache configuration test failed"
    log "ERROR" "Review configuration and restore from backup if needed"
    log "ERROR" "Backup location: $BACKUP_DIR"
    exit 1
fi

log "INFO" ""
log "INFO" "========================================"
log "SUCCESS" "Apache STIG Application Completed"
log "INFO" "========================================"
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "WARN" ""
log "WARN" "=== IMPORTANT NEXT STEPS ==="
log "WARN" "1. Replace self-signed SSL certificate with valid certificate"
log "WARN" "2. Configure virtual hosts with proper ServerName directives"
log "WARN" "3. Review and customize security headers for your application"
log "WARN" "4. Test all application functionality"
log "WARN" "5. Configure WAF/ModSecurity if required"
log "WARN" "6. Set up centralized logging"
log "WARN" "7. Run vulnerability scan"
log "INFO" ""
log "INFO" "SSL Certificate locations:"
log "INFO" "  Certificate: /etc/ssl/certs/"
log "INFO" "  Private Key: /etc/ssl/private/"
log "INFO" ""
log "INFO" "To enable SSL site:"
log "INFO" "  sudo a2ensite 000-default-ssl"
log "INFO" "  sudo systemctl restart $APACHE_SERVICE"
