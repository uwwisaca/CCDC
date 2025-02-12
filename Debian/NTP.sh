echo "Installing NTP"
apt install ntp

echo "Creating backup of original NTP config"
cp /etc/ntp.conf /etc/ntp.conf.backup

echo "Configuring NTP server"
cat > /etc/ntp.conf << 'EOL'
# /etc/ntp.conf

# Preferred primary NTP server
server time.aws.com prefer iburst

# Backup NTP servers
server amazon.pool.ntp.org iburst
server 0.amazon.pool.ntp.org iburst
server 2.amazon.pool.ntp.org iburst

# By default, exchange time with everybody, but don't allow configuration.
restrict -4 default kod notrap nomodify nopeer noquery limited
restrict -6 default kod notrap nomodify nopeer noquery limited

# Needed for adding pool entries
restrict source notrap nomodify noquery
EOL

echo "Configuring IPTABLES (Open port 123)"
iptables -A INPUT -p udp --dport 123 -j ACCEPT
iptables -A OUTPUT -p udp --sport 123 -j ACCEPT

echo "Restarting NTP"
systemctl enable ntp
systemctl status ntp
systemctl restart ntp
systemctl status ntp

echo "Checking time sync"
ntpq -q
