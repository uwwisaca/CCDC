#!/bin/bash
#
# Apache 2.4 STIG - Module 3: Security Headers & HTTP Methods
# Based on U_Apache_Server_2-4_UNIX_Server_V3R2_Manual_STIG
# Version: 1.0
# Date: February 14, 2026
#
# Usage: sudo ./03-apache-headers-methods.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/apache-stig-headers-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/apache-stig-backup-headers-$(date +%Y%m%d-%H%M%S)"

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
log "INFO" "Apache 2.4 STIG - Security Headers & HTTP Methods"
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
log "INFO" "=== Enabling Headers Module ==="

# Enable headers module
a2enmod headers 2>/dev/null || log "INFO" "Headers module already enabled or not available"

log "SUCCESS" "Headers module enabled"

log "INFO" ""
log "INFO" "=== Creating Security Headers Configuration ==="

# Create security headers configuration
cat > "$APACHE_DIR/conf-available/stig-security-headers.conf" << 'EOF'
# Apache 2.4 STIG - Security Headers Configuration

<IfModule mod_headers.c>
    # Security Headers (AS24-U1-000100 through AS24-U1-000150)
    
    # X-Frame-Options: Prevents clickjacking attacks
    Header always set X-Frame-Options "SAMEORIGIN"
    
    # X-Content-Type-Options: Prevents MIME type sniffing
    Header always set X-Content-Type-Options "nosniff"
    
    # X-XSS-Protection: Enables browser XSS protection
    Header always set X-XSS-Protection "1; mode=block"
    
    # Strict-Transport-Security: Enforces HTTPS (HSTS)
    # Note: Only set this header over HTTPS connections
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" env=HTTPS
    
    # Content-Security-Policy: Prevents XSS, clickjacking, and other code injection attacks
    # Adjust policy based on your application requirements
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'self'"
    
    # Referrer-Policy: Controls referrer information
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    
    # Permissions-Policy: Controls browser features
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()"
    
    # Remove server identification headers
    Header always unset X-Powered-By
    Header always unset Server
    Header unset Server
    
    # Session cookie security (AS24-U1-000170)
    # Add HttpOnly and Secure flags to all cookies
    Header edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure;SameSite=Strict
    
    # Remove ETag headers (can leak inodes)
    Header unset ETag
    FileETag None
</IfModule>

# Restrict HTTP methods (AS24-U1-000270)
# Only allow GET, POST, and HEAD methods
<LimitExcept GET POST HEAD>
    Require all denied
</LimitExcept>

# Apply restrictions to all directories
<Directory "/var/www">
    <LimitExcept GET POST HEAD>
        Require all denied
    </LimitExcept>
</Directory>

# Additional method restrictions for specific paths
<Location "/">
    <LimitExcept GET POST HEAD>
        Require all denied
    </LimitExcept>
</Location>

# Disable HTTP OPTIONS method globally
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{REQUEST_METHOD} ^(TRACE|TRACK|OPTIONS)
    RewriteRule .* - [F,L]
</IfModule>
EOF

# Enable security headers configuration
if [ -d "$APACHE_DIR/conf-available" ]; then
    a2enconf stig-security-headers 2>/dev/null
    log "SUCCESS" "Enabled security headers configuration"
else
    # For non-Debian systems, include directly
    if ! grep -q "Include.*stig-security-headers.conf" "$APACHE_DIR/conf/httpd.conf" 2>/dev/null; then
        echo "Include $APACHE_DIR/conf-available/stig-security-headers.conf" >> "$APACHE_DIR/conf/httpd.conf"
        log "SUCCESS" "Added security headers configuration to httpd.conf"
    fi
fi

log "SUCCESS" "Created security headers configuration"

log "INFO" ""
log "INFO" "=== Creating CORS Policy Configuration (Optional) ==="

# Create optional CORS configuration template
cat > "$APACHE_DIR/conf-available/stig-cors-policy.conf.disabled" << 'EOF'
# Apache 2.4 STIG - CORS Policy Configuration
# Rename this file to .conf and enable if CORS is needed
# WARNING: Only enable CORS if your application requires it

<IfModule mod_headers.c>
    # CORS Configuration - Restrictive by default
    # Adjust Access-Control-Allow-Origin to your specific domain
    
    # Option 1: Single origin (recommended)
    # Header always set Access-Control-Allow-Origin "https://trusted-domain.com"
    
    # Option 2: Multiple origins (use SetEnvIf)
    # SetEnvIf Origin "^https://(trusted1\.com|trusted2\.com)$" ORIGIN_ALLOWED=$0
    # Header always set Access-Control-Allow-Origin "%{ORIGIN_ALLOWED}e" env=ORIGIN_ALLOWED
    
    # Option 3: All origins (NOT RECOMMENDED - security risk)
    # Header always set Access-Control-Allow-Origin "*"
    
    # CORS headers
    Header always set Access-Control-Allow-Methods "GET, POST, HEAD"
    Header always set Access-Control-Allow-Headers "Content-Type, Authorization"
    Header always set Access-Control-Max-Age "3600"
    Header always set Access-Control-Allow-Credentials "true"
    
    # Handle preflight OPTIONS requests
    <If "%{REQUEST_METHOD} == 'OPTIONS'">
        Header always set Access-Control-Allow-Origin "https://trusted-domain.com"
        Header always set Access-Control-Allow-Methods "GET, POST, HEAD"
        Header always set Access-Control-Allow-Headers "Content-Type, Authorization"
        Header always set Access-Control-Max-Age "3600"
        Header always set Content-Length "0"
        Header always set Content-Type "text/plain"
    </If>
</IfModule>
EOF

log "SUCCESS" "Created CORS policy template (disabled by default)"

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
log "SUCCESS" "Security Headers & HTTP Methods Configuration Complete"
log "INFO" "============================================"
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "INFO" ""
log "INFO" "=== Applied Settings Summary ==="
log "INFO" "- X-Frame-Options: SAMEORIGIN (clickjacking protection)"
log "INFO" "- X-Content-Type-Options: nosniff (MIME sniffing protection)"
log "INFO" "- X-XSS-Protection: Enabled with blocking"
log "INFO" "- Content-Security-Policy: Configured (default restrictive)"
log "INFO" "- HSTS: Enabled (1 year max-age)"
log "INFO" "- HTTP Methods: Limited to GET, POST, HEAD"
log "INFO" "- Cookie Security: HttpOnly, Secure, SameSite=Strict"
log "INFO" "- Server headers: Removed"
log "INFO" "- ETag: Disabled"
log "WARN" ""
log "WARN" "=== IMPORTANT NOTES ==="
log "WARN" "1. Content-Security-Policy may need adjustment for your application"
log "WARN" "   - Review and update based on your JavaScript/CSS resources"
log "WARN" "   - Test thoroughly to ensure functionality"
log "WARN" ""
log "WARN" "2. CORS is disabled by default"
log "WARN" "   - Enable only if cross-origin requests are required"
log "WARN" "   - Template available: stig-cors-policy.conf.disabled"
log "WARN" ""
log "WARN" "3. Restart Apache for changes to take effect:"
log "WARN" "   sudo systemctl restart $APACHE_SERVICE"
log "WARN" ""
log "WARN" "4. Test headers with:"
log "WARN" "   curl -I https://your-domain.com"
log "WARN" "   Or use: https://securityheaders.com"
