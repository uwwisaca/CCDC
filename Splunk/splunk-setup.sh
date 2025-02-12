#!/bin/bash

# UPDATE SYSTEM PACKAGES
dnf update -y && dnf upgrade -y
echo "System packages have been updated."

# CONFIGURE IPTABLES SETTINGS
# Flush existing rules
iptables -F
iptables -X

# Set default IPTables policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback interface traffic
iptables -A INPUT -i lo -j ACCEPT

# Allow established and related connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow essential incoming connections
iptables -A INPUT -p tcp --dport 8000 -j ACCEPT    # Splunk Web
iptables -A INPUT -p tcp --dport 8089 -j ACCEPT    # Splunk Management
iptables -A INPUT -p tcp --dport 9997 -j ACCEPT    # Splunk Forward

# Log dropped packets
iptables -A INPUT -j LOG --log-prefix "IPTables-Dropped: " --log-level 4 

# Save the rules
iptables-save > /etc/iptables.rules
echo "Firewall rules applied successfully."

# APPEND LINES TO WEB.CONF (enabling SSL, defining HTTP port)
echo "enableSplunkSSL = 1" >> /opt/splunk/etc/system/local/web.conf
echo "httpport = 8000" >> /opt/splunk/etc/system/local/web.conf

# RESTART SPLUNK
/opt/splunk/bin/splunk restart
echo "Splunk has been restarted."
