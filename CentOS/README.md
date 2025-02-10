# CentOS Hardening Instructions
This folder was created by Tyler Deal with the intention of passing on to future UWW Cyber/ISACA students, to help with preperation and competition.
If install is needed: https://ultahost.com/knowledge-base/install-prestashop-on-ubuntu/
Assume everything is compromised. Secure passwords, firewalls, and account/permission audits will be crucial. 

## What to do on competetion day?
Login

Git clone the repo.

run CentPasswd.sh, Run CentOSHardening.sh

Ensure configuration works as expected.

Check for Cronjobs. (CronJobCheck.sh)

Check var/www/html for any strange file folder permissions

Run the "who" command to see any current sessions. 

Ensure that the CVE does not affect our Prestashop store. 

Check for strange prestashop accounts (using mysql):
    SELECT * FROM ps_customer;
    SELECT * FROM ps_employee;
    Or check from employee panel. 

## Update! (Optional, might be a waste of time)
sudo yum update -y
sudo yum upgrade -y

## User Accounts
It's important to figure out which user accounts are on your system.
we can run ~ cat /etc/passwd | grep /bin/bash
This will output the user accounts. 
sudo passwd (userAccountName)
Randomly generated password work best for this. User a password generator and storage system. (keepass, bitwarden, etc...)

## Ports!
For the competition: 

80,443,8089

Try your best never to use port 80 for connecting to the web server.
# How do we harden Prestashop?
There's a few important things to remember here. [CVE 2024-34716](https://nvd.nist.gov/vuln/detail/CVE-2024-34716)  
