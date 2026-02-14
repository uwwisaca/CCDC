#!/bin/bash
#
# Splunk Enterprise STIG - Module 2: SSL/TLS Configuration
# Based on: U_Splunk_Enterprise_8-x_for_Linux_V2R3_Manual_STIG
# Version: 1.0
# Date: February 12, 2026
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/splunk-stig-02-ssl-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/splunk-stig-backup-ssl-$(date +%Y%m%d-%H%M%S)"

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
log "INFO" "Module 2: SSL/TLS Configuration"
log "INFO" "Splunk Home: $SPLUNK_HOME"
log "INFO" "========================================"

# Create backup
mkdir -p "$BACKUP_DIR"
cp "$SPLUNK_HOME/etc/system/local/server.conf" "$BACKUP_DIR/" 2>/dev/null || true
log "SUCCESS" "Backup created: $BACKUP_DIR"

# Create system/local directory if it doesn't exist
mkdir -p "$SPLUNK_HOME/etc/system/local"

# Configure SSL/TLS
log "INFO" "Configuring SSL/TLS..."

cat > "$SPLUNK_HOME/etc/system/local/server.conf" << 'EOF'
[sslConfig]
# SPLK-CL-000130: Enable SSL
enableSplunkdSSL = true

# SPLK-CL-000140: SSL versions (TLS 1.2 and 1.3 only)
sslVersions = tls1.2, tls1.3

# SPLK-CL-000150: Strong cipher suite
cipherSuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256

# SPLK-CL-000160: Require client certificate (optional - for mutual auth)
# requireClientCert = true

[httpServer]
# SPLK-CL-000170: Disable default port
disableDefaultPort = true

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

# SPLK-CL-000230: Pass4SymmKey - CHANGE THIS IN PRODUCTION
pass4SymmKey = $7$CHANGETHISKEY

[diskUsage]
# SPLK-CL-000240: Minimum free space (MB)
minFreeSpace = 5000

[httpServerListener:8089]
# SPLK-CL-000250: Management port SSL
ssl = true

[httpServerListener:8000]
# SPLK-CL-000260: Web interface SSL
ssl = true
EOF

# Set proper ownership
chown splunk:splunk "$SPLUNK_HOME/etc/system/local/server.conf"
chmod 600 "$SPLUNK_HOME/etc/system/local/server.conf"

log "SUCCESS" "SSL/TLS configured"

log "INFO" ""
log "SUCCESS" "========================================"
log "SUCCESS" "Module 2 Completed: SSL/TLS"
log "SUCCESS" "========================================"
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "WARN" ""
log "WARN" "CRITICAL: Generate SSL certificates:"
log "WARN" "  cd $SPLUNK_HOME/etc/auth"
log "WARN" "  sudo -u splunk $SPLUNK_HOME/bin/splunk createssl server-cert"
log "WARN" ""
log "WARN" "CRITICAL: Change pass4SymmKey in server.conf"
log "WARN" "  Edit: $SPLUNK_HOME/etc/system/local/server.conf"
log "WARN" ""
log "WARN" "Restart Splunk to apply changes"
