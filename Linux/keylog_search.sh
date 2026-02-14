#!/bin/bash
echo "--- DEEP LINUX KEYLOGGER & PERSISTENCE SWEEP ---"

# 1. Check for processes accessing input devices (Keyloggers)
echo "[!] Processes accessing input event files:"
sudo lsof /dev/input/event*

# 2. Check for shell history hijacking in environment variables
echo -e "\n[!] Checking for PROMPT_COMMAND history logging:"
grep -r "PROMPT_COMMAND" /etc/profile /etc/bashrc /home/*/.bashrc

# 3. Check for recently modified binaries (Binary Hijacking)
echo -e "\n[!] Binaries modified in the last 24 hours:"
find /usr/bin /usr/sbin -type f -mmin -1440

# 4. Search for common 'hidden' log locations
echo -e "\n[!] Searching for hidden log files in /tmp and /dev/shm:"
find /tmp /dev/shm -type f -name ".*" -ls
