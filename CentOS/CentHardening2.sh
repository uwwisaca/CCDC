#!/bin/bash
# CentOS Hardening Script
# Run as root
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
bantime  = 3600
findtime  = 600
maxretry = 5
ignoreip = 127.0.0.1/8 ::1
banaction = firewallcmd-rich-rules
banaction_allports = firewallcmd-rich-rules
destemail = root@localhost
sender = root@localhost
mta = sendmail
action = %(action_mw)s

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/secure
maxretry = 3

[vsftpd]
enabled = true
port = ftp,ftp-data,ftps,ftps-data
filter = vsftpd
logpath = /var/log/secure
maxretry = 3

[http-get-dos]
enabled = false
[apache-badbots]
enabled = false
[apache-auth]
enabled = false
EOL

# Configure firewall-cmd
systemctl enable firewalld
systemctl start firewalld
echo "Configuring firewalld..."
firewall-cmd --permanent --zone=public --add-service=http
firewall-cmd --permanent --zone=public --add-service=https
firewall-cmd --permanent --zone=public --add-port=8089/tcp
firewall-cmd --reload

# Start and enable fail2ban
systemctl enable fail2ban
systemctl start fail2ban

# Verify fail2ban status
echo -e "\nFail2ban status:"
fail2ban-client status

# Prevent directory traversal for web servers
echo "Configuring web server directory traversal protection..."
cat >> /etc/httpd/conf/httpd.conf << 'EOL'
<Directory />
    Options -Indexes
    AllowOverride None
    Order deny,allow
    Deny from all
</Directory>

<Directory /var/www/html>
    Options -Indexes
    AllowOverride None
    Require all granted
</Directory>
EOL

# Secure /var/www/ directory permissions
echo "Securing /var/www/ directory permissions..."
chown -R root:apache /var/www/
find /var/www/ -type d -exec chmod 755 {} \;
find /var/www/ -type f -exec chmod 644 {} \;
chmod 755 /var/www/

# Restart web server to apply changes
systemctl restart httpd

# Print summary of actions
echo -e "\nHardening Summary:"
echo "==================="
echo "1. Set secure permissions on critical files"
echo "2. Listed all users with login capability"
echo "3. Disabled SSH service"
echo "4. Installed and configured fail2ban with firewalld"
echo "5. Configured firewalld to allow HTTP/HTTPS and Splunk port"
echo "6. Added directory traversal protection for web server"
echo "7. Secured /var/www/ directory permissions"

echo -e "\nScript completed successfully!"
