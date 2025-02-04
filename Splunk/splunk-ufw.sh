#!/bin/bash

# Reset UFW
ufw --force reset

# Set default policies
ufw default deny incoming
ufw default deny outgoing

# Allow essential incoming connections
ufw allow in 8000    # Splunk Web
ufw allow in 8089    # Splunk Management
ufw allow in 9997    # Splunk Forward

# Allow essential outgoing connections
ufw allow out 53     # DNS
ufw allow out 80     # HTTP
ufw allow out 123    # NTP
ufw allow out 443    # HTTPS
ufw allow out 67/udp # DHCP

# Enable UFW
echo "y" | ufw enable

# Show final status
ufw status verbose
