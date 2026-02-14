#!/bin/bash

# Boot check cron installer

set -e

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

echo "Boot Integrity Check - Cron Setup"
echo "=================================="
echo ""

# Copy script to system location
echo "Installing boot-check.sh to /usr/local/bin..."
cp boot-check.sh /usr/local/bin/
chmod +x /usr/local/bin/boot-check.sh

# Create baseline
echo "Creating initial baseline..."
/usr/local/bin/boot-check.sh

CRON_SCHEDULE="*/5 * * * *"

# Install cron job
CRON_JOB="$CRON_SCHEDULE /usr/local/bin/boot-check.sh >> /var/log/boot-check.log 2>&1"
(crontab -l 2>/dev/null | grep -v "boot-check.sh"; echo "$CRON_JOB") | crontab -
echo "Successfully made cron job."