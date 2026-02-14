#!/bin/bash

# Checks to see if boot folder changed using hash

set -e

STATE_FILE="/var/lib/boot-check.sha256"
BOOT_DIR="/boot"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Calculate current hash
CURRENT_HASH=$(find "$BOOT_DIR" -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')

# First run - create baseline
if [ ! -f "$STATE_FILE" ]; then
    echo "$CURRENT_HASH" > "$STATE_FILE"
    echo "Hash created: $CURRENT_HASH"
    exit 0
fi

# Read previous hash
PREVIOUS_HASH=$(cat "$STATE_FILE")

# Compare
if [ "$CURRENT_HASH" == "$PREVIOUS_HASH" ]; then
    echo "No changes detected in $BOOT_DIR"
    exit 0
else
    echo "CHANGES DETECTED IN $BOOT_DIR"
    echo "Previous: $PREVIOUS_HASH"
    echo "Current:  $CURRENT_HASH"
    exit 1
fi