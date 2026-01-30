#!/bin/bash

# CCDC Triage Script: Find Suspicious Users & Privileges
# Copyright (C) Google Gemini 
# This script is READ-ONLY. It will not change your system.

# Checks if script is running as root
if [ "$EUID" -ne 0 ]; then
  echo "ERROR: Please run script as root."
  exit 1
fi

echo "================================================="
echo "  Cyber Hawk User & Privilege Audit Tool"
echo "================================================="

echo -e "\n### 1. Users with Root Privileges (UID 0) ###"
echo "---"
awk -F: '($3 == "0") { print $1 }' /etc/passwd
echo -e "\n> Note: This list should ONLY contain 'root'. Anything else is a critical finding."

# ---

echo -e "\n\n### 2. Users with Sudo Access (wheel or sudo group) ###"
echo "---"
grep '^wheel:' /etc/group
grep '^sudo:' /etc/group
echo -e "\n> Note: Review all users in this list. "
echo -e "> Use 'gpasswd -d <username> wheel' or 'gpasswd -d <username> sudo' to remove them."

# ---

echo -e "\n\n### 3. All Regular Users (for review) ###"
echo "---"
awk -F: '($3 >= 1000 && $1 != "nfsnobody") { print $1 }' /etc/passwd
echo -e "\n> Note: Do you recognize all these users? If not, investigate them."

# ---

echo -e "\n\n### 4. Accounts with Empty Passwords ###"
echo "---"
awk -F: '($2 == "") { print $1 }' /etc/shadow
echo -e "\n> Note: These accounts are CRITICAL. Lock them immediately with 'passwd -l <username>'."

# ---

echo -e "\n\n### 5. Suspicious Login Shells ###"
echo "---"
# Find users who have a login shell but aren't standard users (e.g., service accounts with /bin/bash)
grep -E "(/bin/bash|/bin/sh)" /etc/passwd | grep -vE "(^root|^#)" | awk -F: '($3 < 1000)'
echo -e "\n> Note: Service accounts (UID < 1000) should NOT have a login shell. This is a common backdoor."

# ---

echo -e "\n\n### 6. SSH Authorized Public Keys (authorized_keys) ###"
echo "---"
echo "> Scanning for SSH public keys in user and system authorized_keys locations..."

print_keyfile() {
  local owner="$1"
  local file="$2"

  [ -f "$file" ] || return 0

  echo ""
  echo "File: $file (Owner: $owner)"

  # Print ssh key-like lines with line numbers; skip blanks/comments
  # Shows: Line N: keytype comment...
  nl -ba "$file" \
    | sed -e 's/^[[:space:]]*//' \
    | grep -Ev '^[0-9]+[[:space:]]*(#|$)' \
    | grep -E 'ssh-(ed25519|rsa)[[:space:]]|ecdsa-sha2-nistp(256|384|521)[[:space:]]|sk-ssh-ed25519@openssh.com[[:space:]]|sk-ecdsa-sha2-nistp256@openssh.com[[:space:]]' \
    | sed -E 's/^([0-9]+)[[:space:]]+([a-z0-9@._-]+)[[:space:]]+[^[:space:]]+[[:space:]]*(.*)$/  Line \1: \2  comment=[\3]/'
}

# Per-user locations from /etc/passwd
while IFS=: read -r user _ uid _ _ home _; do
  [ -n "$home" ] || continue
  [ -d "$home" ] || continue

  print_keyfile "$user" "$home/.ssh/authorized_keys"
  print_keyfile "$user" "$home/.ssh/authorized_keys2"

  # Extra: show loose public keys too (informational)
  if [ -d "$home/.ssh" ]; then
    for f in "$home/.ssh"/*.pub; do
      [ -f "$f" ] && print_keyfile "$user" "$f"
    done
  fi
done < /etc/passwd

# System-wide locations
print_keyfile "SYSTEM" "/etc/ssh/authorized_keys"
if [ -d /etc/ssh/authorized_keys ]; then
  for f in /etc/ssh/authorized_keys/*; do
    [ -f "$f" ] && print_keyfile "SYSTEM" "$f"
  done
fi

echo -e "\n> Note: Any unknown key = treat as persistence. Remove from authorized_keys after validating."

# ---

echo -e "\n\n================================================="
echo "               Audit Complete."
echo "   Manually investigate all findings."
echo "   - To delete a user: userdel -r <username>"
echo "   - To lock a user:   passwd -l <username>"
echo "================================================="

exit 0