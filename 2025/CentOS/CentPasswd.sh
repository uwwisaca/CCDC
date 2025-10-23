#!/bin/bash

# List all user accounts
echo "=== User Accounts ==="
awk -F: '{print $1}' /etc/passwd

# List all groups
echo -e "\n=== Groups ==="
awk -F: '{print $1}' /etc/group

# Prompt to change root password
echo -e "\nWould you like to change the root password? (y/N): "
read -r response

if [[ $response =~ ^[yY]$ ]]; then
    passwd root
else
    echo "Operation cancelled."
fi

# Get list of local user accounts
users=$(getent passwd | awk -F: '$3 >= 1000 && $3 < 60000 {print $1}')

echo "Found the following user accounts:"
echo "$users"

# Iterate through users
for username in $users; do
    read -p "Change password for $username? (y/n): " choice
    if [[ $choice == "y" || $choice == "Y" ]]; then
        passwd $username
    fi
done

echo "Password change process complete."
