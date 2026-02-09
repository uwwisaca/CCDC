#!/bin/bash
# UWW ISACA CCDC - Phase 1: Universal Red Team Purge

echo "--- [1] REVOKING UNAUTHORIZED PRIVILEGES ---"
# 1.1: Fix the NOPASSWD entry you found; it's a Red Team favorite
sed -i 's/NOPASSWD: ALL/ALL/g' /etc/sudoers
# 1.2: Check for hidden "UID 0" users (attackers love making a user named 'service' with root IDs)
awk -F: '($3 == "0" && $1 != "root") {print "ALERT: Unauthorized Root User: " $1}' /etc/passwd

echo -e "\n--- [2] SEVERING PERSISTENCE CHANNELS ---"
# 2.1: Wipe crontabs where Red Teams hide reverse shells and re-infection scripts
rm -rf /var/spool/cron/* /etc/cron.d/* /etc/cron.daily/*
# 2.2: Check for 'SSH Authorized Keys'—this is how they log in without a password
find /home /root -name "authorized_keys" -exec rm -f {} \;
# 2.3: Look for hidden 'Dot Files' in home directories that execute code at login
find /home /root -maxdepth 2 -name ".*" -not -name ".bash*" -not -name "." -ls

echo -e "\n--- [3] NETWORK & SERVICE LOCKDOWN ---"
# 3.1: Identify 'Beacons' or 'Reverse Shells' connecting back to the Red Team
ss -tulpn
# 3.2: Kill non-essential services used for exfiltration (FTP, Telnet, Rsh)
for svc in ftp telnet rsh rlogin; do systemctl disable --now $svc 2>/dev/null; done

echo -e "\n--- [4] SYSTEM INTEGRITY (THE TRUTH SEEKER) ---"
# 4.1: Verify if core tools (ls, ps, netstat) have been hijacked to hide processes
# If the Red Team replaced 'ps', they can hide their scripts from your view
rpm -Va | grep '^..5'
