#!/bin/bash

# UFW SETTINGS
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


# APPENDING LINES TO WEB.CONF (enabling SSL, defining HTTP port)
# Defining the web.conf file path
FILE_PATH = "/opt/splunk/etc/system/local/web.conf"

# Append these lines to the web file if they do not already exist
if ! grep -q "^enableSplunkSSL = 1$" "$FILE_PATH"; then
	echo "enableSplunkSSL = 1" >> "$FILE_PATH"
fi
if ! grep -q "^httpport = 8000$" "$FILE_PATH"; then
	echo "httpport = 8000" >> "$FILE_PATH"
fi
echo "Lines added to $FILE_PATH successfully."


# RESTART SPLUNK
/opt/splunk/bin/splunk restart
echo "Splunk has been restarted."
