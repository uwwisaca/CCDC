#!/bin/bash

# Exit on error
set -e

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Install required packages
yum -y install audit fail2ban iptables-services

# Disable unnecessary services
services_to_disable=(
    "avahi-daemon"
    "cups"
    "dhcpd"
    "nfs"
    "rpcbind"
    "vsftpd"
)

for service in "${services_to_disable[@]}"; do
    systemctl disable $service
    systemctl stop $service
done

# Configure and enable firewall
cat > /etc/sysconfig/iptables << 'EOF'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

# Allow established connections
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow localhost
-A INPUT -i lo -j ACCEPT

# Allow HTTP/HTTPS
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT

# Log dropped packets
-A INPUT -j LOG --log-prefix "IPTables-Dropped: "

COMMIT
EOF

systemctl enable iptables
systemctl restart iptables

# Secure SSH
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
cat > /etc/ssh/sshd_config << 'EOF'
Protocol 2
PermitRootLogin no
MaxAuthTries 3
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 0
AllowUsers apache
EOF

systemctl restart sshd

# Configure fail2ban
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true

[apache-auth]
enabled = true

[apache-badbots]
enabled = true
EOF

systemctl enable fail2ban
systemctl start fail2ban

# Secure Apache
yum -y install mod_security mod_evasive
cat > /etc/httpd/conf.d/security.conf << 'EOF'
ServerTokens Prod
ServerSignature Off
TraceEnable Off
EOF

# Configure SELinux
setenforce 1
sed -i 's/SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config

# Set secure file permissions
chmod 644 /etc/passwd
chmod 000 /etc/shadow
chmod 644 /etc/group

# Configure system logging
cat > /etc/sysctl.d/99-security.conf << 'EOF'
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.randomize_va_space = 2
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.rp_filter = 1
EOF

sysctl -p /etc/sysctl.d/99-security.conf

# Remove unnecessary users/groups
userdel games
userdel operator

# Set password policies
sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
sed -i 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
sed -i 's/PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs

echo "System hardening complete. Please review changes and reboot."