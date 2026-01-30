#!/usr/bin/env bash
# CCDC CyberHawks

set -euo pipefail

SSHD_CONFIG_SRC="$(dirname "$0")/sshd_config"
SSHD_CONFIG_DST="/etc/ssh/sshd_config"
BACKUP_DIR="/etc/ssh/backup"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"

echo "[*] SSHD hardening setup starting..."

# Check if sshd exists
if ! command -v sshd >/dev/null 2>&1; then
    echo "[!] sshd not installed, skipping SSH hardening"
    exit 0
fi

# Ensure source config exists
if [ ! -f "$SSHD_CONFIG_SRC" ]; then
    echo "[!] Source sshd_config not found at $SSHD_CONFIG_SRC"
    exit 1
fi

# Backup existing config if it exists
if [ -f "$SSHD_CONFIG_DST" ]; then
    echo "[*] Backing up existing sshd_config"
    mkdir -p "$BACKUP_DIR"
    cp "$SSHD_CONFIG_DST" "$BACKUP_DIR/sshd_config.$TIMESTAMP"
fi

# Install new config and harden the directory.
echo "[*] Installing hardened sshd_config"
cp "$SSHD_CONFIG_SRC" "$SSHD_CONFIG_DST"
chmod 600 "$SSHD_CONFIG_DST"
chown root:root "$SSHD_CONFIG_DST"

# Validate config before restart
echo "[*] Validating sshd configuration"
sshd -t

# Restart sshd safely
echo "[*] Restarting sshd"
if systemctl is-enabled sshd >/dev/null 2>&1 || systemctl is-active sshd >/dev/null 2>&1; then
    systemctl restart sshd
elif systemctl is-enabled ssh >/dev/null 2>&1 || systemctl is-active ssh >/dev/null 2>&1; then
    systemctl restart ssh
else
    echo "[!] sshd service not managed by systemctl, skipping restart"
fi

echo "[+] SSHD hardening complete"