#!/bin/bash
#
# Apache 2.4 STIG - Module 2: SSL/TLS Configuration
# Based on U_Apache_Server_2-4_UNIX_Server_V3R2_Manual_STIG
# Version: 1.0
# Date: February 14, 2026
#
# Usage: sudo ./02-apache-ssl-tls.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/apache-stig-ssl-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/apache-stig-backup-ssl-$(date +%Y%m%d-%H%M%S)"

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
log "INFO" "Apache 2.4 STIG - SSL/TLS Configuration"
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
cp -r "$APACHE_DIR" "$BACKUP_DIR/" 2>/dev/null || true
log "SUCCESS" "Backup created: $BACKUP_DIR"

log "INFO" ""
log "INFO" "=== Enabling SSL Module ==="

# Enable SSL module
a2enmod ssl 2>/dev/null || log "INFO" "SSL module already enabled or not available"
a2enmod socache_shmcb 2>/dev/null || log "INFO" "socache_shmcb module already enabled or not available"

log "SUCCESS" "SSL modules enabled"

log "INFO" ""
log "INFO" "=== Creating SSL/TLS Configuration ==="

# Create STIG SSL configuration
cat > "$APACHE_DIR/conf-available/stig-ssl.conf" << 'EOF'
# Apache 2.4 STIG - SSL/TLS Configuration

<IfModule mod_ssl.c>
    # AS24-U2-000010: Disable SSLv2 and SSLv3, enable only TLS 1.2 and 1.3
    SSLProtocol -all +TLSv1.2 +TLSv1.3
    
    # AS24-U2-000020: Strong ciphers only
    # Modern cipher suite - removes weak ciphers
    SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    
    # AS24-U2-000030: Honor server cipher order
    SSLHonorCipherOrder on
    
    # AS24-U2-000040: Disable SSL compression (prevents CRIME attack)
    SSLCompression off
    
    # AS24-U2-000050: Enable OCSP stapling
    SSLUseStapling on
    SSLStaplingResponderTimeout 5
    SSLStaplingReturnResponderErrors off
    SSLStaplingCache "shmcb:/var/run/apache2/ocsp(128000)"
    
    # AS24-U2-000060: Disable SSL session tickets
    SSLSessionTickets off
    
    # SSL Session Cache (AS24-U1-000260)
    SSLSessionCache "shmcb:/var/run/apache2/ssl_scache(512000)"
    SSLSessionCacheTimeout 300
    
    # Client certificate verification (optional - uncomment if needed)
    # AS24-U2-000070: Client certificate authentication
    # SSLVerifyClient require
    # SSLVerifyDepth 10
    # SSLCACertificateFile /etc/ssl/certs/ca-bundle.crt
    
    # HSTS (AS24-U2-000080)
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    
    # Require SSL for all connections (optional - enforce HTTPS)
    # Redirect HTTP to HTTPS
    # <VirtualHost *:80>
    #     RewriteEngine On
    #     RewriteCond %{HTTPS} off
    #     RewriteRule ^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]
    # </VirtualHost>
</IfModule>
EOF

# Enable SSL configuration
if [ -d "$APACHE_DIR/conf-available" ]; then
    a2enconf stig-ssl 2>/dev/null
    log "SUCCESS" "Enabled SSL configuration"
else
    # For non-Debian systems, include directly
    if ! grep -q "Include.*stig-ssl.conf" "$APACHE_DIR/conf/httpd.conf" 2>/dev/null; then
        echo "Include $APACHE_DIR/conf-available/stig-ssl.conf" >> "$APACHE_DIR/conf/httpd.conf"
        log "SUCCESS" "Added SSL configuration to httpd.conf"
    fi
fi

log "INFO" ""
log "INFO" "=== Creating Secure Virtual Host Template ==="

# Create default secure virtual host template
cat > "$APACHE_DIR/sites-available/000-default-ssl.conf" << 'EOF'
<IfModule mod_ssl.c>
<VirtualHost _default_:443>
    ServerAdmin webmaster@localhost
    ServerName example.com
    DocumentRoot /var/www/html
    
    # Logging
    ErrorLog ${APACHE_LOG_DIR}/ssl_error.log
    CustomLog ${APACHE_LOG_DIR}/ssl_access.log combined
    
    # SSL Configuration
    SSLEngine on
    
    # SSL Certificate paths (replace with your certificates)
    SSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem
    SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key
    # SSLCertificateChainFile /etc/ssl/certs/ca-bundle.crt
    
    # Apply STIG SSL settings
    SSLProtocol -all +TLSv1.2 +TLSv1.3
    SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    SSLHonorCipherOrder on
    
    # Security Headers
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    
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

# Disable insecure default site
if [ -L "$APACHE_DIR/sites-enabled/000-default.conf" ]; then
    a2dissite 000-default 2>/dev/null
    log "SUCCESS" "Disabled default HTTP site (recommend HTTPS only)"
else
    log "INFO" "Default HTTP site not enabled"
fi

log "INFO" ""
log "INFO" "=== Creating OCSP Stapling Directory ==="

# Create directory for OCSP stapling cache
mkdir -p /var/run/apache2
chown www-data:www-data /var/run/apache2 2>/dev/null || chown apache:apache /var/run/apache2 2>/dev/null
chmod 755 /var/run/apache2

log "SUCCESS" "Created OCSP stapling directory"

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
log "SUCCESS" "SSL/TLS Configuration Complete"
log "INFO" "============================================"
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "INFO" ""
log "INFO" "=== Applied Settings Summary ==="
log "INFO" "- SSL/TLS Protocols: TLS 1.2 and 1.3 only"
log "INFO" "- Strong ciphers configured"
log "INFO" "- OCSP stapling enabled"
log "INFO" "- SSL session tickets disabled"
log "INFO" "- HSTS header enabled (1 year max-age)"
log "INFO" "- Secure virtual host template created"
log "WARN" ""
log "WARN" "=== CRITICAL NEXT STEPS ==="
log "WARN" "1. Replace self-signed certificate with valid CA-signed certificate:"
log "WARN" "   - Edit: $APACHE_DIR/sites-available/000-default-ssl.conf"
log "WARN" "   - Update SSLCertificateFile and SSLCertificateKeyFile paths"
log "WARN" ""
log "WARN" "2. Enable SSL site:"
log "WARN" "   sudo a2ensite 000-default-ssl"
log "WARN" ""
log "WARN" "3. Restart Apache:"
log "WARN" "   sudo systemctl restart $APACHE_SERVICE"
log "WARN" ""
log "WARN" "4. Test SSL configuration:"
log "WARN" "   openssl s_client -connect localhost:443 -tls1_2"
log "WARN" "   curl -vI https://localhost"
log "WARN" ""
log "WARN" "5. Test SSL rating (after deploying with valid cert):"
log "WARN" "   https://www.ssllabs.com/ssltest/"
