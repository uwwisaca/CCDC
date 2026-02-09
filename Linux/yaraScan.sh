#!/bin/bash

RULES_DIR="/root/GCTI/YARA/CobaltStrike"
LOG_FILE="/root/yara_hits_$(date +%F_%H-%M-%S).log"

echo "[*] Starting YARA scan..."
echo "[*] Rules: $RULES_DIR"
echo "[*] Output: $LOG_FILE"
echo

sudo find / \
  -path /proc -prune -o \
  -path /sys -prune -o \
  -path /dev -prune -o \
  -path /run -prune -o \
  -type f -size -50M -print 2>/dev/null \
| xargs -r yara -w "$RULES_DIR"/*.yara \
| tee "$LOG_FILE"

echo
echo "[*] Scan complete."
echo "[*] Results saved to: $LOG_FILE"

