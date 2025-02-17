#!/bin/bash

echo "Updating system packages..."
dnf update -y && dnf upgrade -y
echo "System packages have been successfully updated."

echo "Establishing firewall rules..."
# Flush existing rules
systemctl stop firewalld
rm -rf /etc/firewalld/zones/*
rm -rf /etc/firewalld/services/*
systemctl start firewalld

# Set default policy to DROP all incoming traffic
firewall-cmd --permanent --set-default-zone=public
firewall-cmd --permanent --zone=public --set-target=DROP

# Allow essential incoming connections
firewall-cmd --permanent --zone=public --add-port=8000/tcp # Splunk Web
firewall-cmd --permanent --zone=public --add-port=8089/tcp # Splunk Management
firewall-cmd --permanent --zone=public --add-port=9997/tcp # Splunk Forward

# Allow established and related connections
firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" source address=0.0.0.0/0 accept'

# Apply the changes
firewall-cmd --reload
echo "Firewall rules have been successfully established."

echo "Removing the SSH service..."
# Stopping SSH service, then uninstalling
systemctl stop sshd
systemctl disable sshd
systemctl mask sshd
dnf remove openssh-server -y

# Deleting all SSH-related files
rm -rf /etc/ssh ~/.ssh /root/.ssh
find /home -name ".ssh" -type d -exec rm -rf {} +

echo "Configuring Splunk..."
# Adjusting Splunk permissions
chattr -Ri /opt/splunk
chown -R splunk:splunk /opt/splunk
chmod -R 770 /opt/splunk
usermod -aG splunk sysadmin
usermod -aG splunk root

# Set up web.conf (enabling SSL, defining HTTP port)
echo "enableSplunkSSL = 1" > /opt/splunk/etc/system/local/web.conf
echo "httpport = 8000" >> /opt/splunk/etc/system/local/web.conf

# Restart Splunk
/opt/splunk/bin/splunk restart
echo "Splunk has been successfully configured."

echo "Installing ClamAV"
dnf install -y epel-release
dnf install -y clamav clamav-update
freshclam
echo "ClamAV is now running."
