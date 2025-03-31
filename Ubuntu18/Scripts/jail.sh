#!/bin/sh
apt install fail2ban
systemctl enable fail2ban
systemctl start fail2ban
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
fail2ban-client status

fail2ban-client add apache-auth
fail2ban-client set apache-auth maxretry 3
fail2ban-client set apache-auth bantime 3600
fail2ban-client start apache-auth

fail2ban-client add apache-badbots
fail2ban-client set apache-badbots maxretry 2
fail2ban-client set apache-badbots bantime 86400
fail2ban-client start apache-badbots

fail2ban-client add apache-noscript
fail2ban-client set apache-noscript maxretry 3
fail2ban-client set apache-noscript bantime 3600
fail2ban-client start apache-noscript

fail2ban-client add apache-overflows
fail2ban-client set apache-overflows maxretry 3
fail2ban-client set apache-overflows bantime 3600
fail2ban-client start apache-overflows

fail2ban-client add apache-fakegooglebot
fail2ban-client set apache-fakegooglebot maxretry 2
fail2ban-client set apache-fakegooglebot bantime 86400
fail2ban-client start apache-fakegooglebot

fail2ban-client add apache-modsecurity
fail2ban-client set apache-modsecurity maxretry 3
fail2ban-client set apache-modsecurity bantime 3600
fail2ban-client start apache-modsecurity

#fail2ban-client add ssh
#fail2ban-client set ssh maxretry 3
#fail2ban-client set ssh bantime 3600
#fail2ban-client start ssh

fail2ban-client add recidive
fail2ban-client set recidive maxretry 3
fail2ban-client set recidive bantime 604800  # 1 week
fail2ban-client start recidive

fail2ban-client add apache-shellshock
fail2ban-client set apache-shellshock maxretry 3
fail2ban-client set apache-shellshock bantime 3600
fail2ban-client start apache-shellshock

fail2ban-client add apache-xss
fail2ban-client set apache-xss maxretry 3
fail2ban-client set apache-xss bantime 3600
fail2ban-client start apache-xss

fail2ban-client add apache-sqli
fail2ban-client set apache-sqli maxretry 3
fail2ban-client set apache-sqli bantime 3600
fail2ban-client start apache-sqli

fail2ban-client add apache-botsearch
fail2ban-client set apache-botsearch maxretry 3
fail2ban-client set apache-botsearch bantime 3600
fail2ban-client start apache-botsearch
