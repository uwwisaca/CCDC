# CCDC CentOS Instructions
This folder was created by Tyler Deal with the intention of passing on to future UWW Cyber/ISACA students, to help with preperation and competition.
# Update!
sudo yum update -y
# User Accounts
It's important to figure out which user accounts are on your system.
we can run ~ cat /etc/passwd | grep /bin/bash
This will output the user accounts. 
sudo passwd (userAccountName)
Randomly generated password work best for this. User a password generator and storage system. (keepass, bitwarden, etc...)
# Ports!
If the formal remains the same for years to come, CentOS just needs to have 2 ports open. 