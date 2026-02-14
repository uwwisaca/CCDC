#!/bin/bash
#
# MySQL 8.0 STIG - Module 3: Audit Logging
# Based on U_Oracle_MySQL_8-0_V2R2_Manual_STIG
# Version: 1.0
# Date: February 14, 2026
#
# Usage: sudo ./03-mysql-audit-logging.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/mysql-stig-audit-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/mysql-stig-backup-audit-$(date +%Y%m%d-%H%M%S)"

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

log "INFO" "==========================================="
log "INFO" "MySQL 8.0 STIG - Audit Logging"
log "INFO" "==========================================="

# Detect MySQL installation
if [ -f "/etc/mysql/my.cnf" ]; then
    MYSQL_CONF_DIR="/etc/mysql/mysql.conf.d"
elif [ -f "/etc/my.cnf" ]; then
    MYSQL_CONF_DIR="/etc/my.cnf.d"
else
    log "ERROR" "MySQL configuration not found"
    exit 1
fi

# Create backup
mkdir -p "$BACKUP_DIR"
cp -r /etc/mysql "$BACKUP_DIR/" 2>/dev/null || cp -r /etc/my.cnf* "$BACKUP_DIR/" 2>/dev/null || true
log "SUCCESS" "Backup created: $BACKUP_DIR"

log "INFO" ""
log "INFO" "=== Creating Audit Configuration ==="

# Create audit logging configuration
STIG_AUDIT_CONF="$MYSQL_CONF_DIR/mysqld-audit.cnf"

cat > "$STIG_AUDIT_CONF" << 'EOF'
# MySQL 8.0 STIG - Audit Logging Configuration
# MYS8-00-000100: Audit logging must be enabled

[mysqld]

# Audit log plugin (MYS8-00-000100)
plugin-load-add=audit_log.so
audit_log_format=JSON
audit_log_policy=ALL
audit_log_buffer_size=1048576
audit_log_rotate_on_size=52428800
audit_log_rotations=10

# Error log configuration (MYS8-00-000900)
log_error=/var/log/mysql/error.log
log_error_verbosity=3

# General query log (optional - may impact performance)
# Enable for detailed activity monitoring
# general_log=ON
# general_log_file=/var/log/mysql/general.log

# Slow query log (MYS8-00-000900)
slow_query_log=ON
slow_query_log_file=/var/log/mysql/slow.log
long_query_time=2
log_slow_admin_statements=ON
log_slow_slave_statements=ON

# Binary logging for point-in-time recovery (MYS8-00-001000)
log_bin=/var/log/mysql/mysql-bin
binlog_format=ROW
binlog_row_image=FULL
sync_binlog=1
expire_logs_days=7
max_binlog_size=100M

# Enable logging to syslog
# log_syslog=ON
# log_syslog_facility=daemon
# log_syslog_tag=mysql
EOF

log "SUCCESS" "Created audit configuration: $STIG_AUDIT_CONF"

log "INFO" ""
log "INFO" "=== Creating Log Directory ==="

# Create log directory
mkdir -p /var/log/mysql
chown mysql:mysql /var/log/mysql
chmod 750 /var/log/mysql

log "SUCCESS" "Created log directory: /var/log/mysql"

log "INFO" ""
log "INFO" "=== Creating SQL Script for Audit Plugin ==="

# Create SQL script for audit plugin installation
SQL_SCRIPT="$BACKUP_DIR/install-audit-plugin.sql"

cat > "$SQL_SCRIPT" << 'EOF'
-- Install audit log plugin
INSTALL PLUGIN audit_log SONAME 'audit_log.so';

-- Verify plugin installation
SELECT PLUGIN_NAME, PLUGIN_STATUS, PLUGIN_TYPE 
FROM INFORMATION_SCHEMA.PLUGINS 
WHERE PLUGIN_NAME = 'audit_log';

-- Show audit log variables
SHOW VARIABLES LIKE 'audit_log%';

-- Show binary log status
SHOW VARIABLES LIKE 'log_bin%';

-- Show error log settings
SHOW VARIABLES LIKE 'log_error%';

-- Show slow query log settings
SHOW VARIABLES LIKE 'slow_query_log%';
EOF

log "SUCCESS" "Created SQL script: $SQL_SCRIPT"

log "INFO" ""
log "INFO" "==========================================="
log "SUCCESS" "Audit Logging Configuration Complete"
log "INFO" "==========================================="
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "WARN" ""
log "WARN" "=== IMPORTANT NEXT STEPS ==="
log "WARN" "1. Restart MySQL service:"
log "WARN" "   sudo systemctl restart mysql"
log "WARN" ""
log "WARN" "2. Install audit plugin (run SQL script):"
log "WARN" "   mysql -u root -p < $SQL_SCRIPT"
log "WARN" ""
log "WARN" "3. Verify audit log is working:"
log "WARN" "   sudo ls -lh /var/lib/mysql/audit.log*"
log "WARN" ""
log "WARN" "4. Monitor audit logs regularly:"
log "WARN" "   sudo tail -f /var/lib/mysql/audit.log"
log "WARN" ""
log "WARN" "5. Set up log rotation for audit logs"
log "INFO" ""
log "INFO" "=== Log File Locations ==="
log "INFO" "Audit log: /var/lib/mysql/audit.log*"
log "INFO" "Error log: /var/log/mysql/error.log"
log "INFO" "Slow query log: /var/log/mysql/slow.log"
log "INFO" "Binary logs: /var/log/mysql/mysql-bin.*"
log "INFO" ""
log "INFO" "=== Audit Settings ==="
log "INFO" "- Audit format: JSON"
log "INFO" "- Audit policy: ALL (logs all events)"
log "INFO" "- Log rotation: 50 MB per file, keep 10 files"
log "INFO" "- Error log verbosity: 3 (detailed)"
log "INFO" "- Slow query threshold: 2 seconds"
log "INFO" "- Binary log retention: 7 days"
