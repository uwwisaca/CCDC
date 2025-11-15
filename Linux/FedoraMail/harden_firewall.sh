#!/bin/bash

# ===================================================================
#   Cyber Hawk Firewall Hardening Script (firewalld)
#   Strategy: Default Deny, Allow by Exception
# ===================================================================

# --- EDIT THIS LIST ---
# Add all the services you are REQUIRED to run.
# Examples: "http", "httpsS", "dns", "smtp"
#
# I am only including 'ssh' so you don't lock yourself out.
#
SERVICES_TO_KEEP=("ssh" "smtp" "imap" "pop3")
#
# --- END EDIT ---


# --- Script Logic (No need to edit below) ---

# Get the default zone (usually 'public')
ZONE=$(firewall-cmd --get-default-zone)

if [ -z "$ZONE" ]; then
    echo "Error: Could not determine default firewall zone."
    exit 1
fi

echo "--- Hardening firewall for zone: $ZONE ---"

# Get the list of currently allowed services
CURRENT_SERVICES=$(firewall-cmd --zone=$ZONE --list-services)

echo "Current services: $CURRENT_SERVICES"
echo "Services to keep: ${SERVICES_TO_KEEP[@]}"
echo ""

# --- 1. REMOVE services that are NOT in the keep list ---
for service in $CURRENT_SERVICES; do
    keep=0
    # Check if the service is in our keep list
    for keep_service in "${SERVICES_TO_KEEP[@]}"; do
        if [ "$service" == "$keep_service" ]; then
            keep=1
            break
        fi
    done

    # If 'keep' is still 0, the service is not in our list, so remove it.
    if [ $keep -eq 0 ]; then
        echo "REMOVING service: $service"
        firewall-cmd --zone=$ZONE --remove-service=$service --permanent
    fi
done

# --- 2. ADD services that ARE in the keep list ---
# (This ensures they are added, even if the list was empty before)
for service in "${SERVICES_TO_KEEP[@]}"; do
    echo "ENSURING service is allowed: $service"
    firewall-cmd --zone=$ZONE --add-service=$service --permanent
done

# --- 3. Apply changes and show the result ---
echo ""
echo "--- Reloading firewall to apply all changes... ---"
firewall-cmd --reload

echo ""
echo "--- ✅ Firewall Hardening Complete. ---"
echo "--- Final Configuration: ---"
firewall-cmd --list-all