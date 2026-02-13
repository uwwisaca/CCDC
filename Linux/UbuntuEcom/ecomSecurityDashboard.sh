#!/bin/bash

SESSION="UbuntuEcom"
alertLog="/var/log/ccdc_security_alerts.log"
HOSTNAME=$(hostname)

# Safety check
if [[ $EUID -ne 0 ]]; then
    echo "Run as root."
    exit 1
fi

# Alert log setup
touch "$alertLog"
chmod 600 "$alertLog"

# Alert helper
alert() {
    local level="$1"
    local message="$2"
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$ts][$level][$HOSTNAME] $message" >> "$alertLog"
}

# Background log monitor (start once)
if ! pgrep -f "ubuntuEcomMonitor" >/dev/null; then
(
    export CCDC_UBUNTU_ECOM_MONITOR=1

    journalctl -f -o short-iso | while read -r line; do

        # SSH authentication abuse
        echo "$line" | grep -qiE "Failed password|Invalid user|authentication failure" && \
            alert "SSH_AUTH_FAIL" "$line"

        echo "$line" | grep -qiE "sshd.*Accepted" && \
            alert "SSH_LOGIN" "$line"

        # Web attack indicators (SQLi, RFI, LFI, scanners)
        echo "$line" | grep -qiE "union select|/wp-admin|/phpmyadmin|cmd=|/etc/passwd|\.\./|\<script\>|base64_decode|curl|wget" && \
            alert "WEB_ATTACK" "$line"

        # Nginx/Apache errors
        echo "$line" | grep -qiE "nginx.*(error|crit|alert)|apache2.*(error|AH)" && \
            alert "WEB_ERROR" "$line"

        # MySQL/MariaDB auth failures
        echo "$line" | grep -qiE "Access denied for user|mysql.*error|mariadb.*error" && \
            alert "DB_AUTH_FAIL" "$line"

        # Sudo abuse
        echo "$line" | grep -qiE "sudo.*(FAILED|incorrect password|not in sudoers)" && \
            alert "SUDO_FAIL" "$line"

        # Root sessions / privilege escalation
        echo "$line" | grep -qiE "session opened for user root|su:|pam_unix\(su:" && \
            alert "PRIV_ESC" "$line"

        # Account changes
        echo "$line" | grep -qiE "useradd|usermod|userdel|groupadd|groupdel|new user" && \
            alert "ACCOUNT_CHANGE" "$line"

        # UFW firewall changes
        echo "$line" | grep -qiE "ufw.*(allow|deny|added|deleted)" && \
            alert "FIREWALL_CHANGE" "$line"

        # AppArmor denials (Ubuntu default MAC)
        echo "$line" | grep -qiE "apparmor=\"DENIED\"" && \
            alert "APPARMOR" "$line"

        # Service restarts (web/db critical)
        echo "$line" | grep -qiE "Started|Stopped|Restarted|Reloaded|Failed to start" && \
            alert "SERVICE_EVENT" "$line"

    done
) &
fi

# TMUX handling
tmux has-session -t $SESSION 2>/dev/null
if [ $? -eq 0 ]; then
    tmux attach -t $SESSION
    exit 0
fi

tmux new-session -d -s $SESSION -n MAIN

# TOP LEFT PANE = SSH + AUTH
tmux send-keys -t $SESSION:0.0 \
"journalctl -f | grep --line-buffered -Ei 'sshd|Failed password|Invalid user|authentication failure'" C-m

# TOP RIGHT PANE = WEB TRAFFIC MONITOR
tmux split-window -h -t $SESSION
tmux send-keys -t $SESSION:0.1 \
"tail -F /var/log/nginx/access.log /var/log/apache2/access.log 2>/dev/null | grep --line-buffered -Ei 'POST|GET|union|select|wp-admin|phpmyadmin|\\.\\./|/etc/passwd|curl|wget'" C-m

# BOTTOM LEFT = SERVICES + DB + SUDO
tmux split-window -v -t $SESSION:0.0
tmux send-keys -t $SESSION:0.2 \
"journalctl -f | grep --line-buffered -Ei 'sudo|session opened for user root|mysql|mariadb|Started|Stopped|Restarted|Failed to start'" C-m

# LAYOUT
tmux select-layout -t $SESSION even-vertical
tmux resize-pane -t $SESSION:0.0 -y 15
tmux set-option -t $SESSION history-limit 50000
tmux set-option -t $SESSION mouse on
tmux set-option -t $SESSION status-bg magenta
tmux set-option -t $SESSION status-fg white
tmux set-option -t $SESSION status-left '#[fg=black,bg=yellow] UBUNTU 24.04 #[fg=white,bg=magenta] E-COM LIVE MONITOR '

tmux attach -t $SESSION
