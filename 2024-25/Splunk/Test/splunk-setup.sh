#!/bin/bash

# UPDATE SYSTEM PACKAGES
apt update && apt upgrade -y
echo "System packages have been updated."

# CONFIGURE UFW SETTINGS
# Reset UFW
ufw --force reset

# Set default UFW policies
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
ufw allow out 8089   # Splunk Management (other hosts)
ufw allow out 8090   # Splunk Management (splunk host)
ufw allow out 67/udp # DHCP

# Enable UFW
echo "y" | ufw enable

# Show final status
ufw status verbose

# APPEND LINES TO WEB.CONF (enabling SSL, defining HTTP port)
echo "enableSplunkSSL = 1" >> /opt/splunk/etc/system/local/web.conf
echo "httpport = 8000" >> /opt/splunk/etc/system/local/web.conf

# RESTART SPLUNK
/opt/splunk/bin/splunk restart
echo "Splunk has been restarted."
