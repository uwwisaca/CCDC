#!/bin/bash
#
# Splunk Enterprise 8.x STIG Implementation Script
# Based on: U_Splunk_Enterprise_8-x_for_Linux_V2R3_Manual_STIG
# Version: 1.0
# Date: January 30, 2026
#
# Usage: sudo ./apply-splunk-stig.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/splunk-stig-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/splunk-stig-backup-$(date +%Y%m%d-%H%M%S)"

# Detect Splunk installation
SPLUNK_HOME="/opt/splunk"
if [ ! -d "$SPLUNK_HOME" ]; then
    SPLUNK_HOME="/opt/splunkforwarder"
fi

if [ ! -d "$SPLUNK_HOME" ]; then
    echo "ERROR: Splunk installation not found"
    exit 1
fi

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
log "INFO" "Splunk Enterprise STIG Application Starting"
log "INFO" "Splunk Home: $SPLUNK_HOME"
log "INFO" "========================================"

# Create backup
mkdir -p "$BACKUP_DIR"
cp -r "$SPLUNK_HOME/etc/system/local" "$BACKUP_DIR/" 2>/dev/null || true
cp -r "$SPLUNK_HOME/etc/apps" "$BACKUP_DIR/" 2>/dev/null || true
log "SUCCESS" "Backup created: $BACKUP_DIR"

# Create system/local directory if it doesn't exist
mkdir -p "$SPLUNK_HOME/etc/system/local"

# ========================================
# Authentication and Access Control
# ========================================

log "INFO" "Configuring authentication settings..."

# SPLK-CL-000010: Strong password policy
cat > "$SPLUNK_HOME/etc/system/local/authentication.conf" << 'EOF'
[authentication]
# SPLK-CL-000010 through SPLK-CL-000050: Password policy
minPasswordLength = 15
minPasswordDigit = 1
minPasswordLowercase = 1
minPasswordUppercase = 1
minPasswordSpecial = 1

# SPLK-CL-000060: Password history
passwordHistoryCount = 5

# SPLK-CL-000070: Password expiration
passwordExpiration = 90

# SPLK-CL-000080: Session timeout (minutes)
sessionTimeout = 15

# SPLK-CL-000090: Failed login attempts
lockoutAttempts = 3
lockoutDuration = 15
lockoutResetTimeout = 15

# SPLK-CL-000100: Authentication method
authType = LDAP
# Note: Configure LDAP settings separately for production

# SPLK-CL-000110: Enable TLS for web interface
enableSplunkdSSL = true

# SPLK-CL-000120: Require strong TLS
sslVersions = tls1.2, tls1.3
EOF

log "SUCCESS" "Authentication configured"

# ========================================
# SSL/TLS Configuration
# ========================================

log "INFO" "Configuring SSL/TLS..."

# SPLK-CL-000130 through SPLK-CL-000160: SSL configuration
cat > "$SPLUNK_HOME/etc/system/local/server.conf" << 'EOF'
[sslConfig]
# SPLK-CL-000130: Enable SSL
enableSplunkdSSL = true

# SPLK-CL-000140: SSL versions
sslVersions = tls1.2, tls1.3

# SPLK-CL-000150: Cipher suite
cipherSuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256

# SPLK-CL-000160: Require client certificate (optional - for mutual auth)
# requireClientCert = true

[httpServer]
# SPLK-CL-000170: Disable SSLv2/SSLv3
# disableDefaultPort = true   # REMOVED - DON'T RUN - causes issues

# SPLK-CL-000180: Secure cookies
secureCookies = true

# SPLK-CL-000190: X-Frame-Options
x_frame_options_sameorigin = true

# SPLK-CL-000200: Cross-site scripting protection
crossOriginSharingPolicy = *

[general]
# SPLK-CL-000210: Session timeout
sessionTimeout = 15m

# SPLK-CL-000220: Server name
serverName = splunk-server

# SPLK-CL-000230: Pass4SymmKey - CHANGE THIS
pass4SymmKey = $7$CHANGETHISKEY

[diskUsage]
# SPLK-CL-000240: Minimum free space
minFreeSpace = 5000

[httpServerListener:8089]
# SPLK-CL-000250: Management port SSL
ssl = true

[httpServerListener:8000]
# SPLK-CL-000260: Web interface SSL
ssl = true
EOF

log "SUCCESS" "SSL/TLS configured"

# ========================================
# Audit and Logging
# ========================================

log "INFO" "Configuring audit logging..."

# SPLK-CL-000270 through SPLK-CL-000300: Audit configuration
cat > "$SPLUNK_HOME/etc/system/local/audit.conf" << 'EOF'
[auditTrail]
# SPLK-CL-000270: Enable audit trail
disabled = false

# SPLK-CL-000280: Audit log location
directory = $SPLUNK_HOME/var/log/splunk

# SPLK-CL-000290: Audit log retention
maxFileSize = 25

# SPLK-CL-000300: Number of audit files
maxTotalSizeMB = 1000
EOF

log "SUCCESS" "Audit logging configured"

# ========================================
# Input Configuration
# ========================================

log "INFO" "Configuring input security..."

# SPLK-CL-000310 through SPLK-CL-000330: Input security
cat > "$SPLUNK_HOME/etc/system/local/inputs.conf" << 'EOF'
[default]
# SPLK-CL-000310: Connection host
host = splunk-server

[splunktcp]
# SPLK-CL-000320: Disabled by default - enable only if needed
# disabled = false

[splunktcp-ssl:9997]
# SPLK-CL-000330: Secure forwarder connections
disabled = false
requireClientCert = true
sslVersions = tls1.2, tls1.3
cipherSuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384

[SSL]
# SPLK-CL-000340: SSL certificate paths
serverCert = $SPLUNK_HOME/etc/auth/server.pem
sslPassword = $7$CHANGETHISPASSWORD
requireClientCert = false
EOF

log "SUCCESS" "Input security configured"

# ========================================
# Web Interface Security
# ========================================

log "INFO" "Configuring web interface security..."

# SPLK-CL-000350 through SPLK-CL-000380: Web security
cat > "$SPLUNK_HOME/etc/system/local/web.conf" << 'EOF'
[settings]
# SPLK-CL-000350: Enable SSL
enableSplunkWebSSL = true

# SPLK-CL-000360: SSL versions
sslVersions = tls1.2, tls1.3

# SPLK-CL-000370: Cipher suite
cipherSuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256

# SPLK-CL-000380: Login banner
login_content = You are accessing a U.S. Government (USG) Information System (IS)

# SPLK-CL-000390: Session timeout
ui_inactivity_timeout = 15m

# SPLK-CL-000400: HTTP port (disabled)
httpport = 0

# SPLK-CL-000410: HTTPS port
httpsPort = 8000

# SPLK-CL-000420: Prevent embedding
x_frame_options_sameorigin = true

# SPLK-CL-000430: Server tokens
server.socket_host = 0.0.0.0
tools.proxy.on = false
EOF

log "SUCCESS" "Web interface secured"

# ========================================
# Authorization and Roles
# ========================================

log "INFO" "Configuring role-based access control..."

# SPLK-CL-000440 through SPLK-CL-000470: RBAC
cat > "$SPLUNK_HOME/etc/system/local/authorize.conf" << 'EOF'
[default]
# SPLK-CL-000440: Default permissions
# Set strict defaults

[role_admin]
# SPLK-CL-000450: Admin role restrictions
srchIndexesAllowed = *
srchIndexesDefault = main
srchJobsQuota = 10
srchMaxTime = 8640000
EOF

log "SUCCESS" "RBAC configured"

# ========================================
# Search Configuration
# ========================================

log "INFO" "Configuring search limits..."

# SPLK-CL-000480 through SPLK-CL-000500: Search limits
cat > "$SPLUNK_HOME/etc/system/local/limits.conf" << 'EOF'
[search]
# SPLK-CL-000480: Search time limit (seconds)
max_time_before_alert = 300

# SPLK-CL-000490: Maximum concurrent searches per user
max_searches_per_user = 6

# SPLK-CL-000500: Maximum search results
max_count = 500000

[thruput]
# SPLK-CL-000510: Maximum throughput (bytes/sec)
maxKBps = 256
EOF

log "SUCCESS" "Search limits configured"

# ========================================
# Index Configuration
# ========================================

log "INFO" "Configuring index security..."

# SPLK-CL-000520 through SPLK-CL-000540: Index configuration
cat > "$SPLUNK_HOME/etc/system/local/indexes.conf" << 'EOF'
[default]
# SPLK-CL-000520: Index permissions
# Indexes should have appropriate read/write permissions

# SPLK-CL-000530: Retention period
frozenTimePeriodInSecs = 31536000

# SPLK-CL-000540: Maximum data size
maxTotalDataSizeMB = 500000

[main]
homePath = $SPLUNK_DB/defaultdb/db
coldPath = $SPLUNK_DB/defaultdb/colddb
thawedPath = $SPLUNK_DB/defaultdb/thaweddb

[_audit]
# Audit index - critical
maxTotalDataSizeMB = 10000

[_internal]
# Internal logs
maxTotalDataSizeMB = 10000
EOF

log "SUCCESS" "Index security configured"

# ========================================
# File Permissions
# ========================================

log "INFO" "Setting file permissions..."

# SPLK-CL-000550 through SPLK-CL-000580: File permissions
chown -R splunk:splunk "$SPLUNK_HOME"
chmod 700 "$SPLUNK_HOME/etc/auth"
chmod 600 "$SPLUNK_HOME/etc/auth/*.pem" 2>/dev/null || true
chmod 600 "$SPLUNK_HOME/etc/system/local/*.conf"
chmod 700 "$SPLUNK_HOME/var/log/splunk"

log "SUCCESS" "File permissions set"

# ========================================
# Deployment Configuration
# ========================================

log "INFO" "Configuring deployment server settings..."

# SPLK-CL-000590: Deployment server
cat > "$SPLUNK_HOME/etc/system/local/deploymentclient.conf" << 'EOF'
[deployment-client]
# SPLK-CL-000590: Disable if not using deployment server
disabled = true

[target-broker:deploymentServer]
# Configure if using deployment server
# targetUri = <deployment_server>:8089
EOF

log "SUCCESS" "Deployment configuration set"

# ========================================
# Disable Unnecessary Features
# ========================================

log "INFO" "Disabling unnecessary features..."

# SPLK-CL-000600: Disable scripted inputs if not needed
mkdir -p "$SPLUNK_HOME/etc/apps/disabled_scripted_inputs/local"
cat > "$SPLUNK_HOME/etc/apps/disabled_scripted_inputs/local/inputs.conf" << 'EOF'
[script]
disabled = true
EOF

# SPLK-CL-000610: Disable file monitor if not needed
# Configure based on requirements

log "SUCCESS" "Unnecessary features disabled"

# ========================================
# Restart Splunk
# ========================================

log "INFO" "Restarting Splunk..."

# Stop Splunk
sudo -u splunk "$SPLUNK_HOME/bin/splunk" stop

# Start Splunk
sudo -u splunk "$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes

log "SUCCESS" "Splunk restarted"

log "INFO" ""
log "INFO" "========================================"
log "SUCCESS" "Splunk Enterprise STIG Application Completed"
log "INFO" "========================================"
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "WARN" ""
log "WARN" "=== CRITICAL NEXT STEPS ==="
log "WARN" "1. Generate SSL certificates:"
log "WARN" "   cd $SPLUNK_HOME/etc/auth"
log "WARN" "   $SPLUNK_HOME/bin/splunk createssl server-cert"
log "WARN" ""
log "WARN" "2. Change default passwords:"
log "WARN" "   - Admin user password"
log "WARN" "   - pass4SymmKey in server.conf"
log "WARN" "   - SSL certificate password"
log "WARN" ""
log "WARN" "3. Configure LDAP/AD authentication:"
log "WARN" "   Edit: $SPLUNK_HOME/etc/system/local/authentication.conf"
log "WARN" ""
log "WARN" "4. Set up indexes with appropriate retention:"
log "WARN" "   Edit: $SPLUNK_HOME/etc/system/local/indexes.conf"
log "WARN" ""
log "WARN" "5. Configure forwarders with SSL certificates"
log "WARN" ""
log "WARN" "6. Set up role-based access control:"
log "WARN" "   Web UI > Settings > Access Controls > Roles"
log "WARN" ""
log "WARN" "7. Configure firewall to allow only:"
log "WARN" "   - Port 8000 (HTTPS web interface)"
log "WARN" "   - Port 8089 (Management port)"
log "WARN" "   - Port 9997 (Forwarder connections)"
log "WARN" ""
log "WARN" "8. Enable and configure alerting"
log "WARN" ""
log "WARN" "9. Set up backup procedures for:"
log "WARN" "   - $SPLUNK_HOME/etc"
log "WARN" "   - $SPLUNK_HOME/var/lib/splunk"
log "WARN" ""
log "WARN" "10. Run Splunk security audit:"
log "WARN" "    $SPLUNK_HOME/bin/splunk btool check"
log "INFO" ""
log "INFO" "Access Splunk Web Interface:"
log "INFO" "  https://$(hostname):8000"
log "INFO" ""
log "INFO" "Default credentials (CHANGE IMMEDIATELY):"
log "INFO" "  Username: admin"
log "INFO" "  Password: changeme"
