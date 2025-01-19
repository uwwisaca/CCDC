# CCDC CentOS Instructions
This folder was created by Tyler Deal with the intention of passing on to future UWW Cyber/ISACA students, to help with preperation and competition.
## Update!
sudo yum update -y
## User Accounts
It's important to figure out which user accounts are on your system.
we can run ~ cat /etc/passwd | grep /bin/bash
This will output the user accounts. 
sudo passwd (userAccountName)
Randomly generated password work best for this. User a password generator and storage system. (keepass, bitwarden, etc...)
## Ports!
If the formal remains the same for years to come, CentOS just needs to have 2 ports open: 80, and 443.

Enable the firewall:
sudo systemctl start firewalld
sudo systemctl enable firewalld

Set the device to drop all incoming packets by default. 
sudo firewall-cmd --set-default-zone=drop

Allow ports 80 and 443 through:
sudo firewall-cmd --permanent --zone=drop --add-port=80/tcp
sudo firewall-cmd --permanent --zone=drop --add-port=443/tcp

Reload the firewall:
sudo firewall-cmd --reload

Verify the config:
sudo firewall-cmd --zone=drop --list-all

