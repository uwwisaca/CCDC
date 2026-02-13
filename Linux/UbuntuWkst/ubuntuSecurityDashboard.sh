#!/bin/bash

SESSION="UbuntuWorkstation"
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

# Background journal monitor (start once)
if ! pgrep -f "ubuntuWorkstationMonitor" >/dev/null; then
(
    export CCDC_UBUNTU_WS_MONITOR=1

    journalctl -f -o short-iso | while read -r line; do

        # SSH + local authentication failures
        echo "$line" | grep -qiE "Failed password|Invalid user|authentication failure" && \
            alert "AUTH_FAIL" "$line"

        echo "$line" | grep -qiE "sshd.*Accepted|session opened for user" && \
            alert "LOGIN" "$line"

        # Sudo misuse
        echo "$line" | grep -qiE "sudo.*(FAILED|incorrect password|not in sudoers)" && \
            alert "SUDO_FAIL" "$line"

        # Privilege escalation attempts
        echo "$line" | grep -qiE "su:|pam_unix\(su:" && \
            alert "PRIV_ESC" "$line"

        # Package installs / removals
        echo "$line" | grep -qiE "apt.*(install|remove|purge)|dpkg.*(install|remove)" && \
            alert "PACKAGE_CHANGE" "$line"

        # Service manipulation
        echo "$line" | grep -qiE "Started|Stopped|Restarted|Failed to start" && \
            alert "SERVICE_EVENT" "$line"

        # Account changes
        echo "$line" | grep -qiE "useradd|usermod|userdel|groupadd|groupdel|new user" && \
            alert "ACCOUNT_CHANGE" "$line"

        # UFW firewall changes
        echo "$line" | grep -qiE "ufw.*(allow|deny|added|deleted)" && \
            alert "FIREWALL_CHANGE" "$line"

        # AppArmor denials
        echo "$line" | grep -qiE "apparmor=\"DENIED\"" && \
            alert "APPARMOR" "$line"

        # Removable media mount (USB)
        echo "$line" | grep -qiE "Mounted /media|udisksd.*mounted" && \
            alert "USB_MOUNT" "$line"

        # Suspicious execution indicators
        echo "$line" | grep -qiE "EXECVE|setuid|setgid|chmod|chown" && \
            alert "EXECUTION_EVENT" "$line"

    done
) &
fi

# ---- TMUX SETUP ----

tmux has-session -t $SESSION 2>/dev/null
if [ $? -eq 0 ]; then
    tmux attach -t $SESSION
    exit 0
fi

tmux new-session -d -s $SESSION -n MAIN

# TOP LEFT = AUTH + SUDO
tmux send-keys -t $SESSION:0.0 \
"journalctl -f | grep --line-buffered -Ei 'Failed password|Invalid user|authentication failure|sudo|su:'" C-m

# TOP RIGHT = SYSTEM CHANGES
tmux split-window -h -t $SESSION
tmux send-keys -t $SESSION:0.1 \
"journalctl -f | grep --line-buffered -Ei 'apt|dpkg|Started|Stopped|Restarted|ufw|apparmor'" C-m

# BOTTOM = GENERAL SYSTEM + MOUNTS
tmux split-window -v -t $SESSION:0.0
tmux send-keys -t $SESSION:0.2 \
"journalctl -f | grep --line-buffered -Ei 'session opened|Mounted|udisksd|EXECVE|setuid|setgid'" C-m

# Layout tuning
tmux select-layout -t $SESSION even-vertical
tmux resize-pane -t $SESSION:0.0 -y 15
tmux set-option -t $SESSION history-limit 50000
tmux set-option -t $SESSION mouse on
tmux set-option -t $SESSION status-bg cyan
tmux set-option -t $SESSION status-fg black
tmux set-option -t $SESSION status-left '#[fg=white,bg=blue] UBUNTU 24.04 #[fg=black,bg=cyan] WORKSTATION MONITOR '

tmux attach -t $SESSION
