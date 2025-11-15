# CCDC

UW-Whitewater's official CCDC team repository.

# Fedora 42 Mail Server

Change root user name and passoword
    -->To rename the defualt admin user 
        sudo ./manage_user.sh rename <fedora_admin> <my_secret_admin>
    -->To change a user's password 
        sudo ./manage_user.sh setpass <fedora_admin>
    -->To lock a suspicious account
        sudo ./manage_user.sh lock <badguy>
Check ports open with 
        harden_firewall.sh

Check for root users with 
        nano audit.sh

