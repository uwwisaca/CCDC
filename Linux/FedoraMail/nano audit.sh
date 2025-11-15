#!/bin/bash

# CCDC Triage Script: Find Suspicious Users & Privileges
# This script is READ-ONLY. It will not change your system.

echo "================================================="
echo "   CCDC User & Privilege Audit Tool"
echo "================================================="

echo -e "\n### 1. Users with Root Privileges (UID 0) ###"
echo "---"
awk -F: '($3 == "0") { print $1 }' /etc/passwd
echo -e "\n> Note: This list should ONLY contain 'root'. Anything else is a critical finding."

# ---

echo -e "\n\n### 2. Users with Sudo Access (wheel group) ###"
echo "---"
grep '^wheel:' /etc/group
echo -e "\n> Note: Review all users in this list. Use 'gpasswd -d <username> wheel' to remove them."

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

echo -e "\n\n================================================="
echo "               Audit Complete."
echo "   Manually investigate all findings."
echo "   - To delete a user: userdel -r <username>"
echo "   - To lock a user:   passwd -l <username>"
echo "================================================="

exit 0