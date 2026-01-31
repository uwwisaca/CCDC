#!/bin/bash

#Script to install Splunk Forwarder on Ubuntu

set -e

# Variables
SPLUNK_USER="splunk"
SPLUNK_GROUP="splunk"
SPLUNK_HOME="/opt/splunkforwarder"
DEB_DOWNLOAD_URL="https://download.splunk.com/products/universalforwarder/releases/10.0.2/linux/splunkforwarder-10.0.2-e2d18b4767e9-linux-amd64.deb"
DEB_PKG_NAME="splunkforwarder-10.0.2-e2d18b4767e9-linux-amd64.deb"
SPLUNK_ADMIN_USER="admin"
DEFAULT_PASS="changeme" #USER WILL BE PROMPTED TO CHANGE PASSWORD AT THE END OF THIS SCRIPT

#Root Check
if [ "$EUID" -ne 0 ]; then
  echo "ERROR: This script must be run as root."
  exit 1
fi

#Install prerequisites
echo "Updating package cache..."
apt-get update -qq

#Download forwarder
if [ ! -f "/tmp/$DEB_PKG_NAME" ]; then
  echo "Downloading Splunk Universal Forwarder .deb..."
  curl -fsSL -o "/tmp/$DEB_PKG_NAME" "$DEB_DOWNLOAD_URL"
fi

#Install forwarder
echo "Installing Splunk Universal Forwarder..."
dpkg -i "/tmp/$DEB_PKG_NAME" || apt-get install -f -y

#Create splunk user
if ! id "$SPLUNK_USER" >/dev/null 2>&1; then
  echo "Creating user/group: $SPLUNK_USER..."
  groupadd $SPLUNK_GROUP || true
  useradd -m -g $SPLUNK_GROUP $SPLUNK_USER
fi

#Set ownership of $SPLUNK_HOME to splunk user
echo "Setting ownership for $SPLUNK_HOME..."
chown -R $SPLUNK_USER:$SPLUNK_GROUP "$SPLUNK_HOME"

#Start the forwarder
echo "Starting Splunk Universal Forwarder..."
$SPLUNK_HOME/bin/splunk start --accept-license --answer-yes --no-prompt

#Point forwarder to indexer
/opt/splunkforwarder/bin/splunk add forward-server 172.20.242.20:9997 -auth admin:changeme
/opt/splunkforwarder/bin/splunk restart

#Set default admin password (USER WILL BE PROMPTED AT END TO MANUALLY CHANGE)
echo "Setting default admin password..."
$SPLUNK_HOME/bin/splunk edit user $SPLUNK_ADMIN_USER \
    -password $DEFAULT_PASS -role admin -auth admin:changeme || true

#Prompt user to change password
echo
echo "IMPORTANT: Please change the default admin password now."
echo "You will be prompted to enter a new password."
$SPLUNK_HOME/bin/splunk edit user $SPLUNK_ADMIN_USER -password -role admin -auth $SPLUNK_ADMIN_USER:$DEFAULT_PASS

echo
echo "Splunk Universal Forwarder 10.0.2 installation complete."
echo "Use $SPLUNK_HOME/bin/splunk {start|stop|restart} to manage the forwarder."
echo "Please move the inputs.conf file from your machine's Github folder to /opt/splunkforwarder/etc/system/local/inputs.conf !"