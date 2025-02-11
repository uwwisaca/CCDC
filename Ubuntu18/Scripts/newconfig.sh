#!/bin/sh
cd ~
mkdir configs
cd configs

wget https://raw.githubusercontent.com/uwwisaca/CCDC/refs/heads/main/Ubuntu18/configs/000-default.conf
wget https://raw.githubusercontent.com/uwwisaca/CCDC/refs/heads/main/Ubuntu18/configs/apache2.conf
wget https://raw.githubusercontent.com/uwwisaca/CCDC/refs/heads/main/Ubuntu18/configs/security.conf
wget https://raw.githubusercontent.com/uwwisaca/CCDC/refs/heads/main/Ubuntu18/configs/sshd_config

cd ~

cp -r /root/configs/000-default.conf /etc/apache2/sites-available/000-default.conf
cp -r /root/configs/apache2.conf /etc/apache2/apache2.conf
cp -r /root/configs/security.conf /etc/apache2/conf-available/security.conf
cp -r /root/configs/sshd_config /etc/ssh/sshd_config

systemctl restart apache2
systemctl restart httpd
