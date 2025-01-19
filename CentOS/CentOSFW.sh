#!/bin/bash

#If you're wondering, yes this is chatgpt generated... I edited it a little bit though! 
#I don't have the skills to do this from scratch lol...

# Function to check the status of the last command and exit on failure
check_status() {
    if [ $? -ne 0 ]; then
        echo "Error: $1"
        exit 1
    fi
}

# Start firewalld if not already running
echo "Starting firewalld..."
systemctl start firewalld
check_status "Failed to start firewalld."

# Enable firewalld to start on boot
echo "Enabling firewalld to start on boot..."
systemctl enable firewalld
check_status "Failed to enable firewalld."

# Set the default zone to drop
echo "Setting default zone to drop..."
firewall-cmd --set-default-zone=drop
check_status "Failed to set default zone to drop."

# Allow traffic on port 80 (HTTP)
echo "Allowing traffic on port 80 (HTTP)..."
firewall-cmd --zone=drop --add-port=80/tcp --permanent
check_status "Failed to allow port 80."

# Allow traffic on port 443 (HTTPS)
echo "Allowing traffic on port 443 (HTTPS)..."
firewall-cmd --zone=drop --add-port=443/tcp --permanent
check_status "Failed to allow port 443."

# Reload firewalld to apply changes
echo "Reloading firewalld to apply changes..."
firewall-cmd --reload
check_status "Failed to reload firewalld."

echo "Firewalld configuration completed successfully!"
