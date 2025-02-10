#!/bin/sh
mkdir configs
cd configs

wget https://raw.githubusercontent.com/b-lamer/temprepo/refs/heads/main/configs/000-default.conf
wget https://raw.githubusercontent.com/b-lamer/temprepo/refs/heads/main/configs/apache2.conf
wget https://raw.githubusercontent.com/b-lamer/temprepo/refs/heads/main/configs/security.conf
wget https://raw.githubusercontent.com/b-lamer/temprepo/refs/heads/main/configs/sshd_config

cp -r /root/configs/000-default.conf /etc/apache2/sites-available/000-default.conf
cp -r /root/configs/apache2.conf /etc/apache2/apache2.conf
cp -r /root/configs/security.conf /etc/apache2/conf-available/security.conf
cp -r /root/configs/sshd_config /etc/ssh/sshd_config

systemctl restart apache2
systemctl restart httpd