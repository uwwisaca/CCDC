#!/bin/bash
#
# MySQL 8.0 STIG - Module 4: Security Settings
# Based on U_Oracle_MySQL_8-0_V2R2_Manual_STIG
# Version: 1.0
# Date: February 14, 2026
#
# Usage: sudo ./04-mysql-security-settings.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/mysql-stig-security-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/mysql-stig-backup-security-$(date +%Y%m%d-%H%M%S)"

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
log "INFO" "MySQL 8.0 STIG - Security Settings"
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
log "INFO" "=== Creating Security Configuration ==="

# Create security settings configuration
STIG_SECURITY_CONF="$MYSQL_CONF_DIR/mysqld-security.cnf"

cat > "$STIG_SECURITY_CONF" << 'EOF'
# MySQL 8.0 STIG - Security Settings

[mysqld]

# Connection security (MYS8-00-000500)
max_connect_errors=3
max_connections=151
max_user_connections=50

# Disable symbolic links (MYS8-00-000600)
symbolic_links=OFF
skip_symbolic_links

# Secure file operations (MYS8-00-000700, MYS8-00-000800)
secure_file_priv=/var/lib/mysql-files
local_infile=OFF

# Network configuration (MYS8-00-001400)
# Bind to localhost only (change if remote access needed)
bind_address=127.0.0.1
port=3306

# Disable DNS lookups
skip_name_resolve

# Disable SHOW DATABASES for non-privileged users
skip_show_database

# Transaction safety (MYS8-00-001100)
innodb_flush_log_at_trx_commit=1
innodb_support_xa=ON

# Character set (MYS8-00-001200)
character_set_server=utf8mb4
collation_server=utf8mb4_unicode_ci

# SQL Mode - Enable strict mode (MYS8-00-001600)
sql_mode=STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION,NO_AUTO_CREATE_USER

# Connection timeout (MYS8-00-001800)
wait_timeout=300
interactive_timeout=300
connect_timeout=10

# Thread stack (MYS8-00-001900)
thread_stack=256K

# Buffer pool and memory (MYS8-00-001700)
innodb_buffer_pool_size=1G
max_allowed_packet=64M
table_open_cache=4000
tmp_table_size=64M
max_heap_table_size=64M

# Performance schema (for monitoring)
performance_schema=ON

# Disable old authentication plugins
default_authentication_plugin=caching_sha2_password

# Disable unsafe functions
# log_bin_trust_function_creators=OFF
EOF

log "SUCCESS" "Created security configuration: $STIG_SECURITY_CONF"

log "INFO" ""
log "INFO" "=== Creating Secure File Directory ==="

# Create secure file directory
mkdir -p /var/lib/mysql-files
chown mysql:mysql /var/lib/mysql-files
chmod 750 /var/lib/mysql-files

log "SUCCESS" "Created secure file directory: /var/lib/mysql-files"

log "INFO" ""
log "INFO" "=== Setting File Permissions ==="

# Set proper file permissions
if [ -d "/etc/mysql" ]; then
    chown -R mysql:mysql /etc/mysql
    find /etc/mysql -type f -exec chmod 640 {} \;
    find /etc/mysql -type d -exec chmod 750 {} \;
    log "SUCCESS" "Set /etc/mysql permissions"
fi

# Set log directory permissions
if [ -d "/var/log/mysql" ]; then
    chown mysql:mysql /var/log/mysql
    chmod 750 /var/log/mysql
    log "SUCCESS" "Set /var/log/mysql permissions"
fi

log "INFO" ""
log "INFO" "==========================================="
log "SUCCESS" "Security Settings Configuration Complete"
log "INFO" "==========================================="
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "INFO" ""
log "INFO" "=== Applied Settings Summary ==="
log "INFO" "- Max connect errors: 3"
log "INFO" "- Symbolic links: DISABLED"
log "INFO" "- Local infile: DISABLED"
log "INFO" "- Secure file directory: /var/lib/mysql-files"
log "INFO" "- Bind address: 127.0.0.1 (localhost only)"
log "INFO" "- Strict SQL mode: ENABLED"
log "INFO" "- Connection timeout: 5 minutes"
log "INFO" "- Character set: utf8mb4"
log "INFO" "- Authentication: caching_sha2_password"
log "WARN" ""
log "WARN" "=== CONFIGURATION NOTES ==="
log "WARN" "1. MySQL is configured to listen on localhost only"
log "WARN" "   To allow remote access, change bind_address in:"
log "WARN" "   $STIG_SECURITY_CONF"
log "WARN" ""
log "WARN" "2. Adjust innodb_buffer_pool_size based on available RAM"
log "WARN" "   Current: 1GB (recommended: 70-80% of available RAM)"
log "WARN" ""
log "WARN" "3. Restart MySQL for changes to take effect:"
log "WARN" "   sudo systemctl restart mysql"
