#!/usr/bin/env bash
echo '{"pass_hash":"x"}' > /etc/quantum-panel/panel.json
chown root:root /etc/quantum-panel/panel.json
sed -n '/^start_service()/,/^}/p' /work/install-panel.sh > /tmp/startfn.sh
printf 'PANEL_DIR=/etc/quantum-panel\nPANEL_USER=quantum-panel\nBIN=/usr/local/bin/quantum-panel\nREPLACED_BINARY=0\nNO_START=0\nhave() { command -v "$1" >/dev/null; }\ntrun() { local t="$1"; shift; timeout "$t" "$@"; }\ninfo() { echo "INFO: $1"; }\nwarn() { echo "WARN: $1"; }\ndie() { echo "DIE: $1"; exit 1; }\n' > /tmp/env.sh
# systemctl must be a real executable: trun spawns `timeout`, and shell
# functions do not survive into child processes.
mkdir -p /tmp/stubbin
printf '#!/bin/sh\nexit 0\n' > /tmp/stubbin/systemctl
chmod +x /tmp/stubbin/systemctl
source /tmp/env.sh
source /tmp/startfn.sh
PATH="/tmp/stubbin:$PATH" start_service
stat -c %U /etc/quantum-panel/panel.json
