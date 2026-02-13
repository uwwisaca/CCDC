#!/bin/bash

SESSION="Oracle"
alertLog="/var/log/ccdc_security_alerts.log"
HOSTNAME=$(hostname)

#Safety checks
if [[ $EUID -ne 0 ]]; then
    echo "Run as root."
    exit 1
fi

#Alert log setup
touch "$alertLog"
chmod 600 "$alertLog"

#Alert helper
alert() {
    local level="$1"
    local message="$2"
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$ts][$level][$HOSTNAME] $message" >> "$alertLog"
}


#Background log monitor (only start once)
if ! pgrep -f "oracleLogMonitor" >/dev/null; then
(
    export CCDC_ORACLE_LOG_MONITOR=1

    journalctl -f -o short-iso | while read -r line; do

        echo "$line" | grep -qiE "Failed password|invalid user|authentication failure" && \
            alert "AUTH" "$line"

        echo "$line" | grep -qiE "sshd.*(Failed|error|disconnect)" && \
            alert "SSH" "$line"

        echo "$line" | grep -qiE "sudo.*(FAILED|incorrect password|not in sudoers)" && \
            alert "SUDO" "$line"

        echo "$line" | grep -qiE "session opened for user root|su: pam" && \
            alert "PRIV_ESC" "$line"

        echo "$line" | grep -qiE "useradd|usermod|userdel|groupadd|groupdel" && \
            alert "ACCOUNT_CHANGE" "$line"

        echo "$line" | grep -qiE "avc:.*denied" && \
            alert "SELINUX" "$line"

        echo "$line" | grep -qiE "EXECVE|setuid|setgid|chmod|chown" && \
            alert "AUDIT" "$line"

    done
) &
fi

#tmux session handling
tmux has-session -t $SESSION 2>/dev/null
if [ $? -eq 0 ]; then
    tmux attach -t $SESSION
    exit 0
fi

tmux new-session -d -s $SESSION -n MAIN

#TOP LEFT PANE = AUTH / SSH 
tmux send-keys -t $SESSION:0.0 \
"journalctl -f | grep --line-buffered -Ei 'Failed password|invalid user|authentication failure|sshd'" C-m


#TOP RIGHT PANE = ADMIN CONSOLE (USER)
tmux split-window -h -t $SESSION
tmux send-keys -t $SESSION:0.1 \
"clear; echo '*** ADMIN CONSOLE ***'; echo 'Alerts: $alertLog'" C-m


#BOTTOM PANE = SERVICES + SELinux + AUDIT
tmux split-window -v -t $SESSION:0.0
tmux send-keys -t $SESSION:0.2 \
"journalctl -f | grep --line-buffered -Ei 'sudo|session opened for user root|Started|Stopped|Reloaded|avc:.*denied|audit|EXECVE|setuid|setgid'" C-m

#LAYOUT TUNING
tmux select-layout -t $SESSION even-vertical
tmux resize-pane -t $SESSION:0.0 -y 15
tmux set-option -t $SESSION history-limit 50000
tmux set-option -t $SESSION mouse on
tmux set-option -t $SESSION status-bg red
tmux set-option -t $SESSION status-fg white
tmux set-option -t $SESSION status-left '#[fg=black,bg=yellow] CCDC #[fg=white,bg=red] LIVE MONITOR '

tmux attach -t $SESSION
