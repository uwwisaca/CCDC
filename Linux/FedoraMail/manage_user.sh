#!/bin/bash

# ===================================================================
#   CyberHawks User Management Script
#   A safe wrapper for changing names, passwords, and locking.
# ===================================================================

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (or with sudo)"
  exit 1
fi

ACTION=$1
USERNAME=$2
NEW_NAME=$3

# --- Main Logic ---
case $ACTION in
    rename)
        if [ -z "$USERNAME" ] || [ -z "$NEW_NAME" ]; then
            echo "Usage: $0 rename <old_username> <new_username>"
            exit 1
        fi
        echo "--- Renaming user: $USERNAME -> $NEW_NAME ---"
        usermod -l "$NEW_NAME" "$USERNAME"
        echo "✅ User renamed."
        ;;

    setpass)
        if [ -z "$USERNAME" ]; then
            echo "Usage: $0 setpass <username>"
            exit 1
        fi
        echo "--- Setting new password for: $USERNAME ---"
        # This will securely prompt you to type the new password
        passwd "$USERNAME"
        echo "✅ Password changed."
        ;;

    lock)
        if [ -z "$USERNAME" ]; then
            echo "Usage: $0 lock <username>"
            exit 1
        fi
        echo "--- Locking account: $USERNAME ---"
        passwd -l "$USERNAME"
        echo "✅ Account locked."
        ;;

    unlock)
        if [ -z "$USERNAME" ]; then
            echo "Usage: $0 unlock <username>"
            exit 1
        fi
        echo "--- Unlocking account: $USERNAME ---"
        passwd -u "$USERNAME"
        echo "✅ Account unlocked."
        ;;

    *)
        echo "Usage: $0 {rename|setpass|lock|unlock} [username] [new_name]"
        echo "Commands:"
        echo "  rename <old_user> <new_user> - Renames a user"
        echo "  setpass <user>             - Interactively sets a new password for a user"
        echo "  lock <user>                - Locks a user's account"
        echo "  unlock <user>              - Unlocks a user's account"
        exit 1
        ;;
esac

exit 0