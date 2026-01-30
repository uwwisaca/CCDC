#!/bin/bash
#
# MySQL 8.0 STIG Implementation Script
# Based on: U_Oracle_MySQL_8-0_V2R2_Manual_STIG
# Version: 1.0
# Date: January 30, 2026
#
# Usage: sudo ./apply-mysql-stig.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/mysql-stig-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/mysql-stig-backup-$(date +%Y%m%d-%H%M%S)"

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
log "INFO" "MySQL 8.0 STIG Application Starting"
log "INFO" "========================================"

# Detect MySQL installation
if [ -f "/etc/mysql/my.cnf" ]; then
    MYSQL_CNF="/etc/mysql/my.cnf"
    MYSQL_CONF_DIR="/etc/mysql/mysql.conf.d"
elif [ -f "/etc/my.cnf" ]; then
    MYSQL_CNF="/etc/my.cnf"
    MYSQL_CONF_DIR="/etc/my.cnf.d"
else
    log "ERROR" "MySQL configuration not found"
    exit 1
fi

# Create backup
mkdir -p "$BACKUP_DIR"
if [ -d "/etc/mysql" ]; then
    cp -r /etc/mysql "$BACKUP_DIR/"
elif [ -d "/etc" ]; then
    cp /etc/my.cnf "$BACKUP_DIR/" 2>/dev/null || true
    cp -r /etc/my.cnf.d "$BACKUP_DIR/" 2>/dev/null || true
fi

# Backup databases
mysqldump --all-databases --single-transaction --quick --lock-tables=false > "$BACKUP_DIR/all-databases.sql" 2>/dev/null || log "WARN" "Could not backup databases"

log "SUCCESS" "Backup created: $BACKUP_DIR"

# Check if MySQL is running
if ! systemctl is-active --quiet mysql && ! systemctl is-active --quiet mysqld; then
    log "ERROR" "MySQL is not running"
    exit 1
fi

log "INFO" "Creating STIG configuration..."

# Create STIG configuration file
STIG_CONF="$MYSQL_CONF_DIR/mysqld-stig.cnf"

cat > "$STIG_CONF" << 'EOF'
# MySQL 8.0 STIG Configuration
# Based on U_Oracle_MySQL_8-0_V2R2_Manual_STIG

[mysqld]

# MYS8-00-000100: Audit logging must be enabled
plugin-load-add=audit_log.so
audit_log_format=JSON
audit_log_policy=ALL
audit_log_buffer_size=1048576
audit_log_rotate_on_size=52428800
audit_log_rotations=10

# MYS8-00-000200: SSL/TLS encryption
require_secure_transport=ON
ssl_ca=/etc/mysql/ssl/ca-cert.pem
ssl_cert=/etc/mysql/ssl/server-cert.pem
ssl_key=/etc/mysql/ssl/server-key.pem
tls_version=TLSv1.2,TLSv1.3

# MYS8-00-000300: Authentication
default_authentication_plugin=caching_sha2_password
# mysql_native_password is deprecated - use caching_sha2_password

# MYS8-00-000400: Password validation
validate_password.policy=STRONG
validate_password.length=15
validate_password.mixed_case_count=1
validate_password.number_count=1
validate_password.special_char_count=1
validate_password.check_user_name=ON

# MYS8-00-000500: Connection security
max_connect_errors=3
max_connections=151

# MYS8-00-000600: Disable symbolic links
symbolic_links=OFF

# MYS8-00-000700: Secure file operations
secure_file_priv=/var/lib/mysql-files
local_infile=OFF

# MYS8-00-000800: Disable LOAD DATA LOCAL INFILE
local_infile=OFF

# MYS8-00-000900: Log configuration
log_error=/var/log/mysql/error.log
log_error_verbosity=3

# General query log for auditing (disable in production if performance is critical)
# general_log=ON
# general_log_file=/var/log/mysql/general.log

# Slow query log
slow_query_log=ON
slow_query_log_file=/var/log/mysql/slow.log
long_query_time=2
log_slow_admin_statements=ON

# MYS8-00-001000: Binary logging for point-in-time recovery
log_bin=/var/log/mysql/mysql-bin
binlog_format=ROW
binlog_row_image=FULL
sync_binlog=1
expire_logs_days=7

# MYS8-00-001100: Transaction safety
innodb_flush_log_at_trx_commit=1
innodb_support_xa=ON

# MYS8-00-001200: Character set
character_set_server=utf8mb4
collation_server=utf8mb4_unicode_ci

# MYS8-00-001300: Disable old authentication plugins
skip_name_resolve
skip_show_database

# MYS8-00-001400: Networking
bind_address=127.0.0.1
port=3306

# MYS8-00-001500: Disable dangerous features
skip_symbolic_links

# MYS8-00-001600: Enable strict mode
sql_mode=STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION

# MYS8-00-001700: Buffer pool and memory
innodb_buffer_pool_size=1G
max_allowed_packet=64M

# MYS8-00-001800: Connection timeout
wait_timeout=300
interactive_timeout=300

# MYS8-00-001900: Thread stack
thread_stack=256K

# MYS8-00-002000: History length for password reuse
password_history=5
password_reuse_interval=365

# MYS8-00-002100: Password lifetime
default_password_lifetime=90

# MYS8-00-002200: Failed login tracking
connection_control_failed_connections_threshold=3
connection_control_min_connection_delay=1000
connection_control_max_connection_delay=2147483647

# Performance schema for monitoring
performance_schema=ON
EOF

log "SUCCESS" "Created STIG configuration: $STIG_CONF"

# Create SSL directory if it doesn't exist
mkdir -p /etc/mysql/ssl
chmod 750 /etc/mysql/ssl

# Check if SSL certificates exist, if not create self-signed ones
if [ ! -f /etc/mysql/ssl/server-cert.pem ]; then
    log "WARN" "SSL certificates not found, creating self-signed certificates..."
    
    # Generate CA key and certificate
    openssl genrsa 2048 > /etc/mysql/ssl/ca-key.pem
    openssl req -new -x509 -nodes -days 3650 -key /etc/mysql/ssl/ca-key.pem -out /etc/mysql/ssl/ca-cert.pem -subj "/C=US/ST=State/L=City/O=Organization/CN=MySQL-CA"
    
    # Generate server key and certificate signing request
    openssl req -newkey rsa:2048 -days 3650 -nodes -keyout /etc/mysql/ssl/server-key.pem -out /etc/mysql/ssl/server-req.pem -subj "/C=US/ST=State/L=City/O=Organization/CN=MySQL-Server"
    
    # Generate server certificate
    openssl x509 -req -in /etc/mysql/ssl/server-req.pem -days 3650 -CA /etc/mysql/ssl/ca-cert.pem -CAkey /etc/mysql/ssl/ca-key.pem -set_serial 01 -out /etc/mysql/ssl/server-cert.pem
    
    # Generate client key and certificate
    openssl req -newkey rsa:2048 -days 3650 -nodes -keyout /etc/mysql/ssl/client-key.pem -out /etc/mysql/ssl/client-req.pem -subj "/C=US/ST=State/L=City/O=Organization/CN=MySQL-Client"
    openssl x509 -req -in /etc/mysql/ssl/client-req.pem -days 3650 -CA /etc/mysql/ssl/ca-cert.pem -CAkey /etc/mysql/ssl/ca-key.pem -set_serial 02 -out /etc/mysql/ssl/client-cert.pem
    
    # Set permissions
    chown -R mysql:mysql /etc/mysql/ssl
    chmod 600 /etc/mysql/ssl/*-key.pem
    chmod 644 /etc/mysql/ssl/*-cert.pem
    
    log "SUCCESS" "Created self-signed SSL certificates"
    log "WARN" "Replace self-signed certificates with valid CA-signed certificates in production"
fi

# Create secure file directory
mkdir -p /var/lib/mysql-files
chown mysql:mysql /var/lib/mysql-files
chmod 750 /var/lib/mysql-files

log "SUCCESS" "Created secure file directory"

# Set proper file permissions
log "INFO" "Setting file permissions..."

chown -R mysql:mysql /etc/mysql
find /etc/mysql -type f -exec chmod 640 {} \;
find /etc/mysql -type d -exec chmod 750 {} \;

# Log directory
mkdir -p /var/log/mysql
chown mysql:mysql /var/log/mysql
chmod 750 /var/log/mysql

log "SUCCESS" "Set file permissions"

# Create SQL script for additional hardening
SQL_SCRIPT="$BACKUP_DIR/mysql-hardening.sql"

cat > "$SQL_SCRIPT" << 'EOF'
-- MySQL 8.0 STIG SQL Hardening Script

-- Install audit log plugin if not already installed
INSTALL PLUGIN audit_log SONAME 'audit_log.so';

-- Install password validation component
INSTALL COMPONENT 'file://component_validate_password';

-- Install connection control plugins
INSTALL PLUGIN CONNECTION_CONTROL SONAME 'connection_control.so';
INSTALL PLUGIN CONNECTION_CONTROL_FAILED_LOGIN_ATTEMPTS SONAME 'connection_control.so';

-- Configure password validation
SET GLOBAL validate_password.policy = 'STRONG';
SET GLOBAL validate_password.length = 15;
SET GLOBAL validate_password.mixed_case_count = 1;
SET GLOBAL validate_password.number_count = 1;
SET GLOBAL validate_password.special_char_count = 1;
SET GLOBAL validate_password.check_user_name = ON;

-- Configure password reuse
SET GLOBAL password_history = 5;
SET GLOBAL password_reuse_interval = 365;

-- Configure password lifetime
SET GLOBAL default_password_lifetime = 90;

-- Remove anonymous users
DELETE FROM mysql.user WHERE User='';

-- Remove test database
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';

-- Ensure root can only login from localhost
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');

-- Create audit admin user (replace 'YourStrongPassword' with actual strong password)
-- CREATE USER 'audit_admin'@'localhost' IDENTIFIED BY 'YourStrongPassword';
-- GRANT AUDIT_ADMIN, SELECT ON *.* TO 'audit_admin'@'localhost';

-- Flush privileges
FLUSH PRIVILEGES;

-- Show security-related settings
SELECT @@require_secure_transport AS 'Require SSL',
       @@validate_password.policy AS 'Password Policy',
       @@default_password_lifetime AS 'Password Lifetime Days',
       @@password_history AS 'Password History',
       @@local_infile AS 'Local Infile Disabled';

-- Show plugin status
SELECT PLUGIN_NAME, PLUGIN_STATUS 
FROM INFORMATION_SCHEMA.PLUGINS 
WHERE PLUGIN_NAME IN ('audit_log', 'validate_password', 'CONNECTION_CONTROL');
EOF

log "SUCCESS" "Created SQL hardening script: $SQL_SCRIPT"

# Restart MySQL to apply configuration
log "INFO" "Restarting MySQL..."

if systemctl is-active --quiet mysql; then
    systemctl restart mysql
    SERVICE_NAME="mysql"
elif systemctl is-active --quiet mysqld; then
    systemctl restart mysqld
    SERVICE_NAME="mysqld"
else
    log "ERROR" "MySQL service name not recognized"
    exit 1
fi

# Wait for MySQL to start
sleep 5

if systemctl is-active --quiet $SERVICE_NAME; then
    log "SUCCESS" "MySQL restarted successfully"
else
    log "ERROR" "MySQL failed to start"
    log "ERROR" "Check error log: /var/log/mysql/error.log"
    log "ERROR" "Restore from backup if needed: $BACKUP_DIR"
    exit 1
fi

log "INFO" ""
log "INFO" "========================================"
log "SUCCESS" "MySQL STIG Application Completed"
log "INFO" "========================================"
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "WARN" ""
log "WARN" "=== CRITICAL NEXT STEPS ==="
log "WARN" "1. Run the SQL hardening script manually:"
log "WARN" "   mysql -u root -p < $SQL_SCRIPT"
log "WARN" ""
log "WARN" "2. Update root password with strong password:"
log "WARN" "   ALTER USER 'root'@'localhost' IDENTIFIED BY 'NewStrongPassword';"
log "WARN" ""
log "WARN" "3. Create application users with minimal privileges:"
log "WARN" "   CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'StrongPassword';"
log "WARN" "   GRANT SELECT, INSERT, UPDATE, DELETE ON app_db.* TO 'app_user'@'localhost';"
log "WARN" ""
log "WARN" "4. Replace self-signed SSL certificates with valid CA certificates"
log "WARN" "   Certificates location: /etc/mysql/ssl/"
log "WARN" ""
log "WARN" "5. Review and adjust bind_address in STIG config if remote access needed"
log "WARN" "   Current setting: bind_address=127.0.0.1 (localhost only)"
log "WARN" ""
log "WARN" "6. Configure firewall rules:"
log "WARN" "   sudo ufw allow from <trusted_ip> to any port 3306"
log "WARN" ""
log "WARN" "7. Set up regular backups using mysqldump or MySQL Enterprise Backup"
log "WARN" ""
log "WARN" "8. Monitor audit logs regularly:"
log "WARN" "   Audit log location: /var/lib/mysql/audit.log"
log "WARN" ""
log "WARN" "9. Test database connectivity and application functionality"
log "WARN" ""
log "WARN" "10. Review slow query log for performance issues:"
log "WARN" "    /var/log/mysql/slow.log"
log "INFO" ""
log "INFO" "To verify STIG settings are applied:"
log "INFO" "  mysql -u root -p -e \"SHOW VARIABLES LIKE '%ssl%';\""
log "INFO" "  mysql -u root -p -e \"SHOW VARIABLES LIKE '%password%';\""
log "INFO" "  mysql -u root -p -e \"SHOW VARIABLES LIKE 'audit_log%';\""
