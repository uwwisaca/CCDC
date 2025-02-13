#!/bin/bash

echo "=== System-wide crontabs ==="
ls -la /etc/cron*

echo -e "\n=== Content of system-wide cron directories ==="
find /etc/cron* -type f -exec ls -la {} \; -exec cat {} \; -exec echo -e "\n" \;

echo "=== User crontabs ==="
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -l -u $user 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "Found crontab for user: $user"
        crontab -l -u $user
        echo -e "\n"
    fi
done

echo "=== Checking for hidden cron files ==="
find / -name ".cron*" -ls 2>/dev/null

echo "=== Checking cron.deny and cron.allow ==="
ls -la /etc/cron.deny /etc/cron.allow 2>/dev/null
cat /etc/cron.deny /etc/cron.allow 2>/dev/null