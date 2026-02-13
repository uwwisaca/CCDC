#!/bin/bash

SESSION="FedoraMonitor"
alertLog="/var/log/ccdc_security_alerts.log"
HOSTNAME=$(hostname)

# Safety checks
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

# Background log monitor (only start once)
if ! pgrep -f "fedoraLogMonitor" >/dev/null; then
(
    export CCDC_FEDORA_LOG_MONITOR=1

    # Follow journal with ISO timestamps
    journalctl -f -o short-iso | while read -r line; do

        # Authentication failures
        echo "$line" | grep -qiE "Failed password|authentication failure|Invalid user|FAILED LOGIN" && \
            alert "AUTH" "$line"

        # SSH activity
        echo "$line" | grep -qiE "sshd.*(Failed|Accepted|error|disconnect)" && \
            alert "SSH" "$line"

        # Sudo abuse
        echo "$line" | grep -qiE "sudo.*(FAILED|incorrect password|not in sudoers|TTY=)" && \
            alert "SUDO" "$line"

        # Privilege escalation
        echo "$line" | grep -qiE "session opened for user root|su:|pam_unix\(su:" && \
            alert "PRIV_ESC" "$line"

        # Account changes
        echo "$line" | grep -qiE "useradd|usermod|userdel|groupadd|groupdel|new user" && \
            alert "ACCOUNT_CHANGE" "$line"

        # SELinux denials (Fedora = enforcing by default)
        echo "$line" | grep -qiE "avc:.*denied|SELinux is preventing" && \
            alert "SELINUX" "$line"

        # Audit subsystem
        echo "$line" | grep -qiE "audit.*(EXECVE|SYSCALL|USER_CMD|CRED_ACQ|CRED_DISP)" && \
            alert "AUDIT" "$line"

        # Service manipulation (systemd specific)
        echo "$line" | grep -qiE "Started|Stopped|Restarted|Reloaded|Failed to start" && \
            alert "SERVICE" "$line"

    done
) &
fi

# tmux session handling
tmux has-session -t $SESSION 2>/dev/null
if [ $? -eq 0 ]; then
    tmux attach -t $SESSION
    exit 0
fi

tmux new-session -d -s $SESSION -n MAIN

# TOP LEFT PANE = AUTH / SSH
tmux send-keys -t $SESSION:0.0 \
"journalctl -f | grep --line-buffered -Ei 'Failed password|Invalid user|authentication failure|sshd'" C-m

# TOP RIGHT PANE = ADMIN CONSOLE
tmux split-window -h -t $SESSION
tmux send-keys -t $SESSION:0.1 \
"clear; echo '*** FEDORA ADMIN CONSOLE ***'; echo 'Alerts: $alertLog'" C-m

# BOTTOM PANE = SERVICES + SELINUX + AUDIT
tmux split-window -v -t $SESSION:0.0
tmux send-keys -t $SESSION:0.2 \
"journalctl -f | grep --line-buffered -Ei 'sudo|session opened for user root|Started|Stopped|Restarted|Reloaded|avc:.*denied|audit|EXECVE|SYSCALL'" C-m

# Layout tuning
tmux select-layout -t $SESSION even-vertical
tmux resize-pane -t $SESSION:0.0 -y 15
tmux set-option -t $SESSION history-limit 50000
tmux set-option -t $SESSION mouse on
tmux set-option -t $SESSION status-bg blue
tmux set-option -t $SESSION status-fg white
tmux set-option -t $SESSION status-left '#[fg=black,bg=green] FEDORA #[fg=white,bg=blue] LIVE MONITOR '

tmux attach -t $SESSION
