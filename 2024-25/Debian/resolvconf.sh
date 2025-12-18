echo "Installing resolvconf"
apt install resolvconf

echo "Starting resolvconf"
systemctl status resolvconf.service
system start resolvconf.service
systemctl enable resolvconf.service
systemctl status resolvconf.service

echo "Configuring resolvconf"
cat > /etc/resolvconf/resolv.conf.d/head << 'EOL'
#cloudflare DNS
nameserver 1.1.1.1
#google DNS
nameserver 8.8.8.8
EOL

echo "Restarting resolvconf"
systemctl restart resolvconf.service
systemctl status resolvconf.service

