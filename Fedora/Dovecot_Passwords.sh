#!/bin/bash

# Get the list of all Dovecot users
users=$(doveadm user '*')

# Loop through each user and change their password
for user in $users; do
    # Generate a random password
    new_password=$(openssl rand -base64 12)
    
    # Change the user's password
    echo -e "$new_password\n$new_password" | doveadm pw -s SHA512-CRYPT | doveadm user -u $user password set
    
    echo "Changed password for user: $user"
    echo "New password: $new_password"
    echo "------------------------"
done
