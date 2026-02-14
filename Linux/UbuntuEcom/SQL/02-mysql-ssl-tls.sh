#!/bin/bash
#
# MySQL 8.0 STIG - Module 2: SSL/TLS Configuration
# Based on U_Oracle_MySQL_8-0_V2R2_Manual_STIG
# Version: 1.0
# Date: February 14, 2026
#
# Usage: sudo ./02-mysql-ssl-tls.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/mysql-stig-ssl-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/root/mysql-stig-backup-ssl-$(date +%Y%m%d-%H%M%S)"

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
log "INFO" "MySQL 8.0 STIG - SSL/TLS Configuration"
log "INFO" "==========================================="

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
cp -r /etc/mysql "$BACKUP_DIR/" 2>/dev/null || true
log "SUCCESS" "Backup created: $BACKUP_DIR"

log "INFO" ""
log "INFO" "=== Creating SSL Directory ==="

# Create SSL directory
mkdir -p /etc/mysql/ssl
chmod 750 /etc/mysql/ssl

log "SUCCESS" "Created /etc/mysql/ssl"

log "INFO" ""
log "INFO" "=== Generating SSL Certificates ==="

# Check if SSL certificates exist
if [ ! -f /etc/mysql/ssl/server-cert.pem ]; then
    log "INFO" "Generating self-signed SSL certificates..."
    
    # Generate CA key and certificate
    openssl genrsa 2048 > /etc/mysql/ssl/ca-key.pem 2>> "$LOG_FILE"
    openssl req -new -x509 -nodes -days 3650 \
        -key /etc/mysql/ssl/ca-key.pem \
        -out /etc/mysql/ssl/ca-cert.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=MySQL-CA" \
        2>> "$LOG_FILE"
    
    # Generate server key and certificate signing request
    openssl req -newkey rsa:2048 -days 3650 -nodes \
        -keyout /etc/mysql/ssl/server-key.pem \
        -out /etc/mysql/ssl/server-req.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=MySQL-Server" \
        2>> "$LOG_FILE"
    
    # Generate server certificate
    openssl x509 -req -in /etc/mysql/ssl/server-req.pem -days 3650 \
        -CA /etc/mysql/ssl/ca-cert.pem \
        -CAkey /etc/mysql/ssl/ca-key.pem \
        -set_serial 01 \
        -out /etc/mysql/ssl/server-cert.pem \
        2>> "$LOG_FILE"
    
    # Generate client key and certificate
    openssl req -newkey rsa:2048 -days 3650 -nodes \
        -keyout /etc/mysql/ssl/client-key.pem \
        -out /etc/mysql/ssl/client-req.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=MySQL-Client" \
        2>> "$LOG_FILE"
    
    openssl x509 -req -in /etc/mysql/ssl/client-req.pem -days 3650 \
        -CA /etc/mysql/ssl/ca-cert.pem \
        -CAkey /etc/mysql/ssl/ca-key.pem \
        -set_serial 02 \
        -out /etc/mysql/ssl/client-cert.pem \
        2>> "$LOG_FILE"
    
    # Set permissions
    chown -R mysql:mysql /etc/mysql/ssl
    chmod 600 /etc/mysql/ssl/*-key.pem
    chmod 644 /etc/mysql/ssl/*-cert.pem
    
    log "SUCCESS" "Created self-signed SSL certificates"
    log "WARN" "Replace self-signed certificates with valid CA-signed certificates in production"
else
    log "INFO" "SSL certificates already exist"
fi

log "INFO" ""
log "INFO" "=== Creating SSL Configuration ==="

# Create SSL configuration file
STIG_SSL_CONF="$MYSQL_CONF_DIR/mysqld-ssl.cnf"

cat > "$STIG_SSL_CONF" << 'EOF'
# MySQL 8.0 STIG - SSL/TLS Configuration
# MYS8-00-000200: SSL/TLS encryption

[mysqld]

# Require secure transport (MYS8-00-000200)
require_secure_transport=ON

# SSL Certificate paths
ssl_ca=/etc/mysql/ssl/ca-cert.pem
ssl_cert=/etc/mysql/ssl/server-cert.pem
ssl_key=/etc/mysql/ssl/server-key.pem

# TLS versions (disable TLS 1.0 and 1.1)
tls_version=TLSv1.2,TLSv1.3

# Strong ciphers only
# ssl_cipher=DHE-RSA-AES256-SHA:AES128-SHA

[client]
# Client SSL configuration
ssl_ca=/etc/mysql/ssl/ca-cert.pem
ssl_cert=/etc/mysql/ssl/client-cert.pem
ssl_key=/etc/mysql/ssl/client-key.pem
EOF

log "SUCCESS" "Created SSL configuration: $STIG_SSL_CONF"

log "INFO" ""
log "INFO" "==========================================="
log "SUCCESS" "SSL/TLS Configuration Complete"
log "INFO" "==========================================="
log "INFO" "Log file: $LOG_FILE"
log "INFO" "Backup: $BACKUP_DIR"
log "WARN" ""
log "WARN" "=== IMPORTANT NEXT STEPS ==="
log "WARN" "1. Restart MySQL service:"
log "WARN" "   sudo systemctl restart mysql"
log "WARN" ""
log "WARN" "2. Verify SSL is enabled:"
log "WARN" "   mysql -u root -p -e \"SHOW VARIABLES LIKE '%ssl%';\""
log "WARN" ""
log "WARN" "3. Test SSL connection:"
log "WARN" "   mysql -u root -p --ssl-mode=REQUIRED"
log "WARN" ""
log "WARN" "4. Replace self-signed certificates with CA-signed certificates"
log "WARN" "   Certificate location: /etc/mysql/ssl/"
log "INFO" ""
log "INFO" "=== SSL Files Created ==="
log "INFO" "CA Certificate: /etc/mysql/ssl/ca-cert.pem"
log "INFO" "Server Certificate: /etc/mysql/ssl/server-cert.pem"
log "INFO" "Server Key: /etc/mysql/ssl/server-key.pem"
log "INFO" "Client Certificate: /etc/mysql/ssl/client-cert.pem"
log "INFO" "Client Key: /etc/mysql/ssl/client-key.pem"
