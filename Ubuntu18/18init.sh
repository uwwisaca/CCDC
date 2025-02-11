#!/bin/sh

systemctl stop sshd
systemctl disable sshd
systemctl mask sshd

chown -R www-data:www-data /var/www/html
chmod -R 750 /var/www/html
chmod 640 /etc/apache2/apache2.conf
chmod 640 /etc/apache2/sites-available/*
chmod 640 /var/log/apache2/*

a2dismod -f autoindex status


#Scripts
mkdir -p Scripts
cd Scripts
wget https://raw.githubusercontent.com/uwwisaca/CCDC/refs/heads/main/Ubuntu18/Scripts/iptables.sh
wget https://raw.githubusercontent.com/uwwisaca/CCDC/refs/heads/main/Ubuntu18/Scripts/newconfig.sh
