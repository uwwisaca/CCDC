#!/bin/bash

set -euo pipefail #error handling

trap 'unset splunkNewPassword splunkPasswordConfirm' EXIT #ensures clearing of variables on exit


if [[ "$(stat -c %U /opt/splunk)" != "splunk" ]]; then #just in case of accidental sudo of splunk commands without changing user
        sudo chown -R splunk:splunk /opt/splunk #if ever used sudo /opt/splunk anything, some files in /opt/splunk/* may belong to root causing ownership conflict
fi

splunkBin="/opt/splunk/bin/splunk"
splunkUser="admin"

sudo -u splunk "$splunkBin" login #alternative to hardcoding password using -auth method

read -s -p "Enter the old Splunk admin password: " splunkCurrentPassword
echo
read -s -p "Please enter the new password for the Splunk Web Admin account: " splunkNewPassword
echo
read -s -p "Please confirm password: " splunkPasswordConfirm

if [[ "$splunkNewPassword" != "$splunkPasswordConfirm" ]]; then
        echo "Error: Passwords don't match."
        exit 1
fi

sudo -u splunk "$splunkBin" edit user "$splunkUser" -password "$splunkNewPassword" -auth "$splunkUser:$splunkCurrentPassword"

echo "Splunk admin password updated successfully."
