#!/bin/bash
set -e

#Root Check
if [ "$EUID" -ne 0 ]; then
  echo "ERROR: Must be run as root"
  exit 1
fi

#Specify user for later when username is changed
USER="sysadmin"

#Checks if user exists
if ! id "$USER" &>/dev/null; then
  echo "ERROR: User '$USER' does not exist. Aborting."
  exit 1
fi

echo "Account Management"
echo

#Calls for resetting password
reset_password() {
  read -p "Which user's password would you like to reset? " TARGET_USER

  if ! id "$TARGET_USER" &>/dev/null; then
    echo "ERROR: User '$TARGET_USER' does not exist."
    return 1
  fi

  passwd "$TARGET_USER"
  echo "Password updated for $TARGET_USER"
  echo
}

#Loops through password resets based on user input
while true; do
  reset_password

  read -p "Would you like to change another user's password? (yes/no): " ANOTHER
  if [[ ! "$ANOTHER" =~ ^[Yy][Ee][Ss]$ ]]; then
    break
  fi
done

#Change sysadmin username
read -p "Enter NEW username for '$USER': " NEW_USERNAME

if id "$NEW_USERNAME" &>/dev/null; then
  echo "ERROR: User '$NEW_USERNAME' already exists. Aborting."
  exit 1
fi

echo "Renaming user '$USER' to '$newUsername'..."

usermod -l "$NEW_USERNAME" "$USER"
usermod -d "/home/$NEW_USERNAME" -m "$NEW_USERNAME"
groupmod -n "$NEW_USERNAME" "$USER"

echo "User renamed to $newUsername"
echo

#Kill all user sessions in case of compromise (conjoined with password changes for ease)
read -p "Kill ALL user sessions (including root)? (yes/no): " KILL_SESSIONS

if [[ "$KILL_SESSIONS" =~ ^[Yy][Ee][Ss]$ ]]; then
  echo "Terminating all user sessions except current..."

  CURRENT_SESSION="$XDG_SESSION_ID"

  loginctl list-sessions --no-legend | awk '{print $1}' | while read sid; do
    if [[ "$sid" != "$CURRENT_SESSION" ]]; then
      loginctl terminate-session "$sid"
    fi
  done

  echo "All other user sessions terminated"
else
  echo "Skipping session termination"
fi

echo
echo "Password refresh complete. Remember to log out of current session for changes to take effect!"