#!/bin/bash
set -e

#Root Check
if [ "$EUID" -ne 0 ]; then
  echo "ERROR: Must be run as root"
  exit 1
fi

echo "Fail2Ban Install Script"
echo

echo "Installing Fail2Ban and dependencies..."
dnf install -y epel-release
dnf install -y fail2ban fail2ban-firewalld

echo "Configuring Fail2Ban..."
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd

[sshd]
enabled = true
EOF

systemctl enable --now fail2ban

echo "Fail2Ban installed and running"
echo
echo "Fail2Ban setup finished!"
