#!/bin/bash
set -e

ALLOWED_SUBNET="172.20.242.0/24"
SSH_PORT=22

#checks if running as root
if [ "$EUID" -ne 0 ]; then
  echo "ERROR: Must be run as root"
  exit 1
fi

#checks if ccdcuser1 exists
if ! id ccdcuser1 &>/dev/null; then
  echo "ERROR: ccdcuser1 does not exist. Aborting."
  exit 1
fi

echo "!!Restricting SSH to $ALLOWED_SUBNET!!"

#enables firewalld
if ! systemctl is-active --quiet firewalld; then
  echo "Starting firewalld..."
  systemctl enable --now firewalld
fi

echo "Removing generic SSH access"
firewall-cmd --permanent --remove-service=ssh || true

echo "Allowing SSH only from $ALLOWED_SUBNET"
firewall-cmd --permanent \
  --add-rich-rule="rule family='ipv4' source address='$ALLOWED_SUBNET' service name='ssh' accept"

firewall-cmd --reload

#verifies firewall rules
echo
echo "Firewall SSH rules:"
firewall-cmd --list-rich-rules

#installs fail2ban
echo
echo "Installing Fail2Ban"
dnf install -y epel-release
dnf install -y fail2ban fail2ban-firewalld

#configures fail2ban
echo "Configuring Fail2Ban for SSH..."

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

#verifies fail2ban status
echo
echo "Fail2Ban status:"
fail2ban-client status sshd

echo
echo "SSH restricted to $ALLOWED_SUBNET"
echo "Fail2Ban enabled for SSH"
echo
echo "TEST FROM ALLOWED NETWORK:"
echo "  ssh ccdcuser1@<server_ip>"
echo
echo "TEST BLOCK (outside subnet):"
echo "  connection should be refused"