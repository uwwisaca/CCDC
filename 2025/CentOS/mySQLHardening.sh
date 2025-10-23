#!/bin/bash

# MySQL Security Hardening Script

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Prompt for MySQL root password securely
read -s -p "Enter MySQL root password: " MYSQL_ROOT_PASSWORD
echo ""

# Disable anonymous logins
mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "DELETE FROM mysql.user WHERE User = '';"

# Disable remote MySQL root login
mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"

# Remove test databases
mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "DROP DATABASE IF EXISTS test;"
mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"

# Prompt to change MySQL root password
read -s -p "Enter new MySQL root password: " NEW_MYSQL_ROOT_PASSWORD
echo ""
read -s -p "Confirm new MySQL root password: " CONFIRM_NEW_MYSQL_ROOT_PASSWORD
echo ""

if [ "$NEW_MYSQL_ROOT_PASSWORD" != "$CONFIRM_NEW_MYSQL_ROOT_PASSWORD" ]; then
    echo "Passwords do not match. Exiting."
    exit 1
fi

# Change MySQL root password
mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$NEW_MYSQL_ROOT_PASSWORD';"

# Reload privilege tables
mysql -u root -p"$NEW_MYSQL_ROOT_PASSWORD" -e "FLUSH PRIVILEGES;"

echo "MySQL security hardening and password change completed."
