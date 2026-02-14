#!/bin/bash
#
# Apache 2.4 STIG - Module 5: Logging Configuration
# Based on U_Apache_Server_2-4_UNIX_Server_V3R2_Manual_STIG
# Version: 1.0
# Date: February 14, 2026
#
# Usage: sudo ./05-apache-logging.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/apache-stig-logging-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/apache-stig-backup-logging-$(date +%Y%m%d-%H%M%S)"

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
log "INFO" "Apache 2.4 STIG - Logging Configuration"
log "INFO" "============================================"

# Detect Apache installation
if [ -d "/etc/apache2" ]; then
    APACHE_DIR="/etc/apache2"
    APACHE_SERVICE="apache2"
    APACHE_CMD="apache2ctl"
    LOG_DIR="/var/log/apache2"
    APACHE_USER="www-data"
    APACHE_GROUP="www-data"
elif [ -d "/etc/httpd" ]; then
    APACHE_DIR="/etc/httpd"
    APACHE_SERVICE="httpd"
    APACHE_CMD="apachectl"
    LOG_DIR="/var/log/httpd"
    APACHE_USER="apache"
    APACHE_GROUP="apache"
else
    log "ERROR" "Apache installation not found"
    exit 1
fi

log "INFO" "Apache directory: $APACHE_DIR"
log "INFO" "Log directory: $LOG_DIR"

# Create backup
mkdir -p "$BACKUP_DIR"
cp -r "$APACHE_DIR" "$BACKUP_DIR/" 2>/dev/null || true
log "SUCCESS" "Backup created: $BACKUP_DIR"

log "INFO" ""
log "INFO" "=== Creating Log Directory ==="

# Ensure log directory exists with proper permissions
mkdir -p "$LOG_DIR"
chown root:$APACHE_GROUP "$LOG_DIR"
chmod 750 "$LOG_DIR"

log "SUCCESS" "Log directory configured: $LOG_DIR"

log "INFO" ""
log "INFO" "=== Creating Logging Configuration ==="

# Create comprehensive logging configuration
cat > "$APACHE_DIR/conf-available/stig-logging.conf" << 'EOF'
# Apache 2.4 STIG - Logging Configuration

# Error log level (AS24-U1-000200)
# Levels: debug, info, notice, warn, error, crit, alert, emerg
LogLevel warn

# Main error log
ErrorLog ${APACHE_LOG_DIR}/error.log

# Custom log format with detailed information (AS24-U1-000190)
# Includes: host, user, timestamp, request, status, bytes, referrer, user-agent, response time
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %D" combined_with_time
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%h %l %u %t \"%r\" %>s %b" common
LogFormat "%{Referer}i -> %U" referer
LogFormat "%{User-agent}i" agent

# Forensic logging format - tracks request and response
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %I %O %{ratio}n%% %D" forensic

# Security-focused log format
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %{SSL_PROTOCOL}x %{SSL_CIPHER}x %D %I %O" security

# Main access log
CustomLog ${APACHE_LOG_DIR}/access.log combined_with_time

# Security events log (SSL, authentication, errors)
CustomLog ${APACHE_LOG_DIR}/security.log security env=HTTPS

# Separate log for POST requests (often contains sensitive operations)
CustomLog ${APACHE_LOG_DIR}/post.log combined_with_time env=post_request
SetEnvIf Request_Method "POST" post_request

# Log SSL/TLS handshake information
<IfModule mod_ssl.c>
    CustomLog ${APACHE_LOG_DIR}/ssl_request.log \
        "%t %h %{SSL_PROTOCOL}x %{SSL_CIPHER}x \"%r\" %b"
</IfModule>

# Log denied requests
<IfModule mod_log_config.c>
    # Log requests that result in 403 or 404
    CustomLog ${APACHE_LOG_DIR}/denied.log combined_with_time env=denied
    SetEnvIf Request_Status ^(403|404) denied
</IfModule>

# Additional logging modules
<IfModule mod_logio.c>
    # Log input/output bytes
    LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %I %O" combinedio
    CustomLog ${APACHE_LOG_DIR}/access_io.log combinedio
</IfModule>

# Error log per virtual host (recommended)
# Add to each virtual host configuration:
# ErrorLog ${APACHE_LOG_DIR}/vhost_error.log
# CustomLog ${APACHE_LOG_DIR}/vhost_access.log combined_with_time

# Ensure logs are not accessible via web
<FilesMatch "\.(log|LOG)$">
    Require all denied
</FilesMatch>

<Directory "${APACHE_LOG_DIR}">
    Require all denied
</Directory>
EOF

# Enable logging configuration
if [ -d "$APACHE_DIR/conf-available" ]; then
    a2enconf stig-logging 2>/dev/null
    log "SUCCESS" "Enabled logging configuration"
else
    # For non-Debian systems, include directly
    if ! grep -q "Include.*stig-logging.conf" "$APACHE_DIR/conf/httpd.conf" 2>/dev/null; then
        echo "Include $APACHE_DIR/conf-available/stig-logging.conf" >> "$APACHE_DIR/conf/httpd.conf"
        log "SUCCESS" "Added logging configuration to httpd.conf"
    fi
fi

log "INFO" ""
log "INFO" "=== Configuring Log Rotation ==="

# Create comprehensive log rotation configuration
cat > /etc/logrotate.d/apache2-stig << 'EOF'
/var/log/apache2/*.log /var/log/httpd/*.log {
    # Rotate daily
    daily
    
    # Keep 52 weeks of logs (1 year)
    rotate 365
    
    # Don't error if log file is missing
    missingok
    
    # Don't rotate if log is empty
    notifempty
    
    # Compress old logs
    compress
    
    # Delay compression until next rotation
    delaycompress
    
    # Create new log files with these permissions
    create 640 root adm
    
    # Use date as suffix instead of number
    dateext
    dateformat -%Y%m%d
    
    # Run scripts only once for all logs
    sharedscripts
    
    # After rotation, reload Apache
    postrotate
        if systemctl is-active apache2 > /dev/null 2>&1; then
            systemctl reload apache2 > /dev/null 2>&1
        elif systemctl is-active httpd > /dev/null 2>&1; then
            systemctl reload httpd > /dev/null 2>&1
        fi
    endscript
    
    # If log size exceeds 100MB, rotate immediately
    size 100M
    
    # Max age of log files (in days)
    maxage 365
}

# Critical error log - keep longer
/var/log/apache2/error.log /var/log/httpd/error.log {
    daily
    rotate 730
    missingok
    notifempty
    compress
    delaycompress
    create 640 root adm
    dateext
    sharedscripts
    postrotate
        if systemctl is-active apache2 > /dev/null 2>&1; then
            systemctl reload apache2 > /dev/null 2>&1
        elif systemctl is-active httpd > /dev/null 2>&1; then
            systemctl reload httpd > /dev/null 2>&1
        fi
    endscript
}
EOF

log "SUCCESS" "Configured log rotation"

log "INFO" ""
log "INFO" "=== Creating Log Monitoring Script ==="

# Create log monitoring script
cat > "/root/monitor-apache-logs.sh" << 'EOF'
#!/bin/bash
# Apache Log Monitoring Script

LOG_DIR="/var/log/apache2"
[ -d "/var/log/httpd" ] && LOG_DIR="/var/log/httpd"

echo "=== Apache Log Monitoring Report ==="
echo "Generated: $(date)"
echo ""

# Check log directory size
echo "=== Log Directory Usage ==="
du -sh "$LOG_DIR"
echo ""

# Recent errors
echo "=== Recent Errors (Last 10) ==="
tail -10 "$LOG_DIR/error.log" 2>/dev/null || echo "No error log found"
echo ""

# Access log summary
echo "=== Access Log Summary (Last 1000 entries) ==="
if [ -f "$LOG_DIR/access.log" ]; then
    echo "Total requests: $(wc -l < "$LOG_DIR/access.log")"
    echo "Unique IPs: $(awk '{print $1}' "$LOG_DIR/access.log" | sort -u | wc -l)"
    echo ""
    echo "Top 10 IPs:"
    awk '{print $1}' "$LOG_DIR/access.log" | sort | uniq -c | sort -rn | head -10
    echo ""
    echo "Top 10 Requested URLs:"
    awk '{print $7}' "$LOG_DIR/access.log" | sort | uniq -c | sort -rn | head -10
    echo ""
    echo "Response Status Codes:"
    awk '{print $9}' "$LOG_DIR/access.log" | sort | uniq -c | sort -rn
fi
echo ""

# Security events
echo "=== Security Events ==="
echo "403 Forbidden:"
grep -c "\" 403 " "$LOG_DIR/access.log" 2>/dev/null || echo "0"
echo "404 Not Found:"
grep -c "\" 404 " "$LOG_DIR/access.log" 2>/dev/null || echo "0"
echo "500 Server Error:"
grep -c "\" 500 " "$LOG_DIR/access.log" 2>/dev/null || echo "0"
echo ""

# Suspicious patterns
echo "=== Suspicious Activity (Sample) ==="
echo "SQL Injection attempts:"
grep -i "union.*select\|concat.*char" "$LOG_DIR/access.log" 2>/dev/null | tail -5 || echo "None detected"
echo ""
echo "XSS attempts:"
grep -i "<script\|javascript:" "$LOG_DIR/access.log" 2>/dev/null | tail -5 || echo "None detected"
echo ""
echo "Path traversal attempts:"
grep -i "\.\./\|\.\.%2f" "$LOG_DIR/access.log" 2>/dev/null | tail -5 || echo "None detected"
echo ""

echo "=== Monitoring Complete ==="
EOF

chmod 750 /root/monitor-apache-logs.sh
log "SUCCESS" "Created log monitoring script: /root/monitor-apache-logs.sh"

log "INFO" ""
log "INFO" "=== Setting Log File Permissions ==="

# Set permissions on existing log files
if [ -d "$LOG_DIR" ]; then
    # Set directory permissions
    chmod 750 "$LOG_DIR"
    chown root:$APACHE_GROUP "$LOG_DIR"
    
    # Set log file permissions
    find "$LOG_DIR" -type f -name "*.log" -exec chmod 640 {} \;
    find "$LOG_DIR" -type f -name "*.log" -exec chown root:$APACHE_GROUP {} \;
    
    log "SUCCESS" "Set log file permissions"
fi

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

# Test log rotation
logrotate -d /etc/logrotate.d/apache2-stig > /dev/null 2>&1
if [ $? -eq 0 ]; then
    log "SUCCESS" "Log rotation configuration test passed"
else
    log "WARN" "Log rotation test had warnings (may be normal)"
fi

log "INFO" ""
log "INFO" "============================================"
log "SUCCESS" "Logging Configuration Complete"
log "INFO" "============================================"
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "INFO" ""
log "INFO" "=== Applied Settings Summary ==="
log "INFO" "- Log directory: $LOG_DIR (750 permissions)"
log "INFO" "- Error log level: warn"
log "INFO" "- Access log format: combined with response time"
log "INFO" "- Security log: Separate SSL/TLS log"
log "INFO" "- POST requests log: Separate tracking"
log "INFO" "- Denied requests log: 403/404 tracking"
log "INFO" "- Log rotation: Daily, 365 days retention"
log "INFO" "- Log compression: Enabled"
log "INFO" "- Monitoring script: /root/monitor-apache-logs.sh"
log "WARN" ""
log "WARN" "=== NEXT STEPS ==="
log "WARN" "1. Restart Apache for logging changes:"
log "WARN" "   sudo systemctl restart $APACHE_SERVICE"
log "WARN" ""
log "WARN" "2. Test log rotation manually:"
log "WARN" "   sudo logrotate -f /etc/logrotate.d/apache2-stig"
log "WARN" ""
log "WARN" "3. Monitor logs:"
log "WARN" "   sudo /root/monitor-apache-logs.sh"
log "WARN" ""
log "WARN" "4. Set up centralized logging (recommended):"
log "WARN" "   - Configure rsyslog to forward logs"
log "WARN" "   - Or use ELK stack (Elasticsearch, Logstash, Kibana)"
log "WARN" "   - Or use Splunk/SIEM solution"
log "WARN" ""
log "WARN" "5. Configure log monitoring alerts:"
log "WARN" "   - Set up alerts for error spikes"
log "WARN" "   - Monitor for security events"
log "WARN" "   - Track application errors"
log "INFO" ""
log "INFO" "=== Log File Locations ==="
log "INFO" "- Access log: $LOG_DIR/access.log"
log "INFO" "- Error log: $LOG_DIR/error.log"
log "INFO" "- Security log: $LOG_DIR/security.log"
log "INFO" "- SSL log: $LOG_DIR/ssl_request.log"
log "INFO" "- POST log: $LOG_DIR/post.log"
log "INFO" "- Denied log: $LOG_DIR/denied.log"
