#!/bin/bash

# Dovecot Hardening Script for Fedora 21
# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "Run this script as root."
    exit 1
fi

echo "Starting Dovecot Hardening Process..."

# Step 1: Update system packages
echo "Updating system packages..."
yum update -y

# Step 2: Enforce secure SSL/TLS settings
echo "Configuring SSL/TLS..."
SSL_CONF="/etc/dovecot/conf.d/10-ssl.conf"
if [ -f "$SSL_CONF" ]; then
    sed -i 's/^ssl =.*/ssl = yes/' "$SSL_CONF"
    sed -i 's/^#ssl_protocols =.*/ssl_protocols = !SSLv3 !TLSv1/' "$SSL_CONF"
    sed -i 's/^#ssl_cipher_list =.*/ssl_cipher_list = HIGH:!aNULL:!MD5/' "$SSL_CONF"
else
    echo "SSL configuration file not found: $SSL_CONF"
fi

# Step 3: Restrict authentication mechanisms
echo "Configuring secure authentication..."
AUTH_CONF="/etc/dovecot/conf.d/10-auth.conf"
if [ -f "$AUTH_CONF" ]; then
    sed -i 's/^auth_mechanisms =.*/auth_mechanisms = plain login/' "$AUTH_CONF"
else
    echo "Authentication configuration file not found: $AUTH_CONF"
fi

# Step 4: Set file permissions
echo "Setting secure file permissions..."
chmod 600 /etc/dovecot/dovecot.conf
chmod 600 /etc/dovecot/conf.d/*

# Step 5: Restrict service exposure
echo "Configuring firewall rules..."
firewall-cmd --add-service=imap --permanent
firewall-cmd --add-service=pop3 --permanent
firewall-cmd --reload

# Step 6: Enable SELinux enforcement
echo "Enabling SELinux enforcement..."
setenforce 1

# Step 7: Restart Dovecot service
echo "Restarting Dovecot service..."
systemctl restart dovecot
systemctl enable dovecot

echo "Dovecot Hardening Complete!"
