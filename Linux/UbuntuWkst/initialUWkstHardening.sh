#!/bin/bash
set -e

ALLOWED_SUBNET="172.20.242.0/24"
SSH_PORT=22
HTTPS_PORT=443

#checks if running as root
if [ "$EUID" -ne 0 ]; then
     echo "ERROR: Must be run as root"
     exit 1
fi

echo "!!Restricting SSH to $ALLOWED_SUBNET!!"

# Enables ufw
if ! systemctl is-active --quiet ufw; then
     echo "Starting ufw firewall..."
     sudo systemctl enable --now ufw
fi

# Reset UFW Rules
sudo ufw --force reset

echo "Setting up default ufw rules"
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw logging on

sudo ufw reload
sudo ufw enable

#installs fail2ban
echo
echo "Installing Fail2Ban"
sudo apt install -y fail2ban

#configures fail2ban
echo "Configuring Fail2Ban for SSH..."

sudo cat > /etc/fail2ban/jail.local <<EOF
[ufw]
enabled=true
filter=ufw.aggressive
action=iptables-allports
logpath=/var/log/ufw.log
maxretry=1
bantime=-1

[sshd]
backend=systemd
enabled=true
filter=sshd
mode=normal
port=22
protocol=tcp
maxretry=3
bantime=-1
EOF

sudo systemctl enable --now fail2ban

#verifies fail2ban status
echo
echo "Fail2Ban status:"
sudo fail2ban-client status sshd

echo
echo "SSH restricted to $ALLOWED_SUBNET"
echo "Fail2Ban enabled for SSH"
echo
echo "TEST FROM ALLOWED NETWORK:"
echo "  ssh ccdcuser1@<server_ip>"
echo
echo "TEST BLOCK (outside subnet):"
echo "  connection should be refused"