#!/bin/bash
#
# Splunk Enterprise STIG - Module 3: Web Interface Security
# Based on: U_Splunk_Enterprise_8-x_for_Linux_V2R3_Manual_STIG
# Version: 1.0
# Date: February 12, 2026
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/splunk-stig-03-web-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/splunk-stig-backup-web-$(date +%Y%m%d-%H%M%S)"

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
log "INFO" "Module 3: Web Interface Security"
log "INFO" "Splunk Home: $SPLUNK_HOME"
log "INFO" "========================================"

# Create backup
mkdir -p "$BACKUP_DIR"
cp "$SPLUNK_HOME/etc/system/local/web.conf" "$BACKUP_DIR/" 2>/dev/null || true
log "SUCCESS" "Backup created: $BACKUP_DIR"

# Create system/local directory if it doesn't exist
mkdir -p "$SPLUNK_HOME/etc/system/local"

# Configure web interface security
log "INFO" "Configuring web interface security..."

cat > "$SPLUNK_HOME/etc/system/local/web.conf" << 'EOF'
[settings]
# SPLK-CL-000350: Enable SSL
enableSplunkWebSSL = true

# SPLK-CL-000360: SSL versions (TLS 1.2 and 1.3 only)
sslVersions = tls1.2, tls1.3

# SPLK-CL-000370: Strong cipher suite
cipherSuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256

# SPLK-CL-000380: Login banner
login_content = You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. Unauthorized use is prohibited and subject to criminal and civil penalties.

# SPLK-CL-000390: Session timeout (minutes)
ui_inactivity_timeout = 15m

# SPLK-CL-000400: HTTP port (disabled - use HTTPS only)
httpport = 0

# SPLK-CL-000410: HTTPS port
httpsPort = 8000

# SPLK-CL-000420: Prevent embedding (X-Frame-Options)
x_frame_options_sameorigin = true

# SPLK-CL-000430: Server security settings
server.socket_host = 0.0.0.0
tools.proxy.on = false
EOF

# Set proper ownership
chown splunk:splunk "$SPLUNK_HOME/etc/system/local/web.conf"
chmod 600 "$SPLUNK_HOME/etc/system/local/web.conf"

log "SUCCESS" "Web interface security configured"

log "INFO" ""
log "SUCCESS" "========================================"
log "SUCCESS" "Module 3 Completed: Web Interface"
log "SUCCESS" "========================================"
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "INFO" ""
log "INFO" "Web interface will be accessible at: https://$(hostname):8000"
log "WARN" "Restart Splunk to apply changes"
