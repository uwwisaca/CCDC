#!/bin/bash
#
# MySQL 8.0 STIG - Module 1: Authentication & User Security
# Based on U_Oracle_MySQL_8-0_V2R2_Manual_STIG
# Version: 1.0
# Date: February 14, 2026
#
# Usage: sudo ./01-mysql-authentication.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/mysql-stig-auth-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/mysql-stig-backup-auth-$(date +%Y%m%d-%H%M%S)"

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
log "INFO" "MySQL 8.0 STIG - Authentication & Users"
log "INFO" "==========================================="

# Create backup
mkdir -p "$BACKUP_DIR"

# Check if MySQL is running
if ! systemctl is-active --quiet mysql && ! systemctl is-active --quiet mysqld; then
    log "ERROR" "MySQL is not running"
    exit 1
fi

# Create SQL script for authentication hardening
SQL_SCRIPT="$BACKUP_DIR/auth-hardening.sql"

cat > "$SQL_SCRIPT" << 'EOF'
-- MySQL 8.0 STIG Authentication Hardening
-- MYS8-00-000300: Authentication

-- Install password validation component
INSTALL COMPONENT 'file://component_validate_password';

-- Install connection control plugins
INSTALL PLUGIN CONNECTION_CONTROL SONAME 'connection_control.so';
INSTALL PLUGIN CONNECTION_CONTROL_FAILED_LOGIN_ATTEMPTS SONAME 'connection_control.so';

-- Configure password validation (MYS8-00-000400)
SET GLOBAL validate_password.policy = 'STRONG';
SET GLOBAL validate_password.length = 15;
SET GLOBAL validate_password.mixed_case_count = 1;
SET GLOBAL validate_password.number_count = 1;
SET GLOBAL validate_password.special_char_count = 1;
SET GLOBAL validate_password.check_user_name = ON;

-- Configure password reuse (MYS8-00-002000)
SET GLOBAL password_history = 5;
SET GLOBAL password_reuse_interval = 365;

-- Configure password lifetime (MYS8-00-002100)
SET GLOBAL default_password_lifetime = 90;

-- Configure connection control (MYS8-00-002200)
SET GLOBAL connection_control_failed_connections_threshold = 3;
SET GLOBAL connection_control_min_connection_delay = 1000;
SET GLOBAL connection_control_max_connection_delay = 2147483647;

-- Remove anonymous users
DELETE FROM mysql.user WHERE User='';

-- Remove test database
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';

-- Ensure root can only login from localhost
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');

-- Flush privileges
FLUSH PRIVILEGES;

-- Show password settings
SELECT 'Password Policy Settings:' AS Info;
SELECT 
    @@validate_password.policy AS 'Policy',
    @@validate_password.length AS 'Min Length',
    @@default_password_lifetime AS 'Lifetime (days)',
    @@password_history AS 'History Count',
    @@password_reuse_interval AS 'Reuse Interval (days)';

-- Show connection control settings
SELECT 'Connection Control Settings:' AS Info;
SELECT 
    @@connection_control_failed_connections_threshold AS 'Failed Login Threshold',
    @@connection_control_min_connection_delay AS 'Min Delay (ms)',
    @@connection_control_max_connection_delay AS 'Max Delay (ms)';

-- Show plugin status
SELECT 'Installed Security Plugins:' AS Info;
SELECT PLUGIN_NAME, PLUGIN_STATUS 
FROM INFORMATION_SCHEMA.PLUGINS 
WHERE PLUGIN_NAME IN ('validate_password', 'CONNECTION_CONTROL', 'CONNECTION_CONTROL_FAILED_LOGIN_ATTEMPTS');
EOF

log "SUCCESS" "Created SQL hardening script: $SQL_SCRIPT"
log "INFO" ""
log "WARN" "==========================================="
log "WARN" "MANUAL STEP REQUIRED"
log "WARN" "==========================================="
log "WARN" "Execute the SQL script manually:"
log "WARN" "  mysql -u root -p < $SQL_SCRIPT"
log "WARN" ""
log "WARN" "After running the script:"
log "WARN" "1. Update root password with strong password:"
log "WARN" "   mysql> ALTER USER 'root'@'localhost' IDENTIFIED BY 'NewStrongPassword123!';"
log "WARN" ""
log "WARN" "2. Create application users (example):"
log "WARN" "   mysql> CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'StrongPassword123!';"
log "WARN" "   mysql> GRANT SELECT, INSERT, UPDATE, DELETE ON app_db.* TO 'app_user'@'localhost';"
log "WARN" "   mysql> FLUSH PRIVILEGES;"
log "INFO" ""
log "INFO" "==========================================="
log "SUCCESS" "Authentication Configuration Script Ready"
log "INFO" "==========================================="
log "INFO" "Log file: $LOG_FILE"
log "INFO" "SQL script: $SQL_SCRIPT"
log "INFO" ""
log "INFO" "=== Settings to be Applied ==="
log "INFO" "- Password policy: STRONG"
log "INFO" "- Minimum password length: 15 characters"
log "INFO" "- Password lifetime: 90 days"
log "INFO" "- Password history: 5 passwords"
log "INFO" "- Failed login threshold: 3 attempts"
log "INFO" "- Account lockout delay: progressive (1s to max)"
