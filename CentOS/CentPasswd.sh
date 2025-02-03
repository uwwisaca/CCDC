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