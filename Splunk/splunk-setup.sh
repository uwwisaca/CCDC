#!/bin/bash

# UPDATE SYSTEM PACKAGES
dnf update -y && dnf upgrade -y
echo "System packages have been updated."

# CONFIGURE CMD-FIREWALL SETTINGS
# Flush existing rules
echo "Establishing firewall rules"
cmd-firewall --flush

# Allow essential incoming connections
cmd-firewall --allow-in 8000 # Splunk Web
cmd-firewall --allow-in 8089 # Splunk Management
cmd-firewall --allow-in 9997 # Splunk Forward

# Block all other incoming connections
cmd-firewall --deny-in ALL

# Save the rules
cmd-firewall --save
echo "Firewall rules successfully established and saved."

# APPEND LINES TO WEB.CONF (enabling SSL, defining HTTP port)
echo "enableSplunkSSL = 1" >> /opt/splunk/etc/system/local/web.conf
echo "httpport = 8000" >> /opt/splunk/etc/system/local/web.conf

# RESTART SPLUNK
/opt/splunk/bin/splunk restart
echo "Splunk has been restarted."
