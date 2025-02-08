#!/bin/bash

# CentOS Hardening Script
# Run as root

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

echo "Starting CentOS hardening process..."

# Set critical file permissions
echo "Setting critical file permissions..."
chmod 644 /etc/passwd
chmod 000 /etc/shadow
chmod 644 /etc/group
chmod 000 /etc/gshadow
chmod 600 /etc/ssh/sshd_config
chmod 600 /etc/sudoers
chmod 700 /root
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys

# Secure /home directories
for user in $(ls /home); do
    chmod 700 /home/$user
    if [ -d "/home/$user/.ssh" ]; then
        chmod 700 /home/$user/.ssh
        chmod 600 /home/$user/.ssh/authorized_keys 2>/dev/null
    fi
done

# Print users that can log in
echo -e "\nUsers that can log in to the system:"
echo "====================================="
getent passwd | awk -F: '$7 != "/sbin/nologin" && $7 != "/bin/false" {print "Username:", $1, "\nShell:", $7, "\n"}'

# Disable SSHD
echo "Disabling SSH service..."
systemctl stop sshd
systemctl disable sshd
echo "SSH service has been disabled"

# Install and configure fail2ban
echo "Installing and configuring fail2ban..."
dnf install -y epel-release
dnf install -y fail2ban firewalld

# Enable and start firewalld
systemctl enable firewalld
systemctl start firewalld

# Create fail2ban configuration
cat > /etc/fail2ban/jail.local << 'EOL'
[DEFAULT]
# Ban hosts for 1 hour
bantime  = 3600
findtime  = 600
maxretry = 5

# Ignore localhost
ignoreip = 127.0.0.1/8 ::1

# Use firewalld instead of iptables
banaction = firewallcmd-rich-rules
banaction_allports = firewallcmd-rich-rules

# Only send one email per banned IP
destemail = root@localhost
sender = root@localhost
mta = sendmail
action = %(action_mw)s

# SSH jail
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/secure
maxretry = 3

# FTP jail
[vsftpd]
enabled = true
port = ftp,ftp-data,ftps,ftps-data
filter = vsftpd
logpath = /var/log/secure
maxretry = 3

# Don't block HTTP/HTTPS
[http-get-dos]
enabled = false

[apache-badbots]
enabled = false

[apache-auth]
enabled = false
EOL

# Configure firewalld
echo "Configuring firewalld..."
# Add HTTP and HTTPS to public zone
firewall-cmd --permanent --zone=public --add-service=http
firewall-cmd --permanent --zone=public --add-service=https
# Reload firewall to apply changes
firewall-cmd --reload

# Start and enable fail2ban
systemctl enable fail2ban
systemctl start fail2ban

# Verify fail2ban status
echo -e "\nFail2ban status:"
fail2ban-client status

# Print summary of actions
echo -e "\nHardening Summary:"
echo "==================="
echo "1. Set secure permissions on critical files"
echo "2. Listed all users with login capability"
echo "3. Disabled SSH service"
echo "4. Installed and configured fail2ban with firewalld"
echo "   - Using firewalld for ban actions"
echo "   - Blocking failed login attempts for SSH and FTP"
echo "   - Not blocking web server traffic"
echo "   - Ban time: 1 hour"
echo "   - Max retry: 5 attempts within 10 minutes"
echo "5. Configured firewalld to allow HTTP/HTTPS traffic"

echo -e "\nScript completed successfully!"