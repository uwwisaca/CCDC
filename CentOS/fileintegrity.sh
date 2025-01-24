#!/bin/bash

#I feel a little bad generating these with chat... I gotta improve my scripting lol.

# Configuration
WEB_PAGES_DIR="/path/to/web/pages"         # Directory containing web pages
HASH_STORE_FILE="/path/to/hash_store.txt"  # File to store hashes

# Function to calculate MD5 hashes of all files in the directory
calculate_hashes() {
    find "$WEB_PAGES_DIR" -type f -exec md5sum {} \; | sort > /tmp/current_hashes.txt
}

# Function to load previously stored hashes
load_previous_hashes() {
    if [[ -f "$HASH_STORE_FILE" ]]; then
        sort "$HASH_STORE_FILE" > /tmp/previous_hashes.txt
    else
        touch /tmp/previous_hashes.txt
    fi
}

# Compare the current hashes with the previous hashes and detect changes
check_integrity() {
    local changes_detected=0

    # Compare for modified or new files
    while IFS= read -r line; do
        if ! grep -Fq "$line" /tmp/previous_hashes.txt; then
            echo "Warning: New or modified file detected - $(echo "$line" | awk '{print $2}')"
            changes_detected=1
        fi
    done < /tmp/current_hashes.txt

    # Check for deleted files
    while IFS= read -r line; do
        if ! grep -Fq "$line" /tmp/current_hashes.txt; then
            echo "Warning: Deleted file detected - $(echo "$line" | awk '{print $2}')"
            changes_detected=1
        fi
    done < /tmp/previous_hashes.txt

    # If no changes are detected
    if [[ $changes_detected -eq 0 ]]; then
        echo "No changes detected."
    fi
}

# Save the current hashes for future comparisons
save_hashes() {
    mv /tmp/current_hashes.txt "$HASH_STORE_FILE"
}

# Main script execution
calculate_hashes
load_previous_hashes
check_integrity
save_hashes