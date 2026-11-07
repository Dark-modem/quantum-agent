#!/usr/bin/env bash
useradd --system quantum-panel 2>/dev/null || true
mkdir -p /etc/quantum-panel/tls
sed -n '/^tls_selfsigned_step()/,/^}/p' /work/install-panel.sh > /tmp/tlsfn.sh
printf 'PANEL_DIR=/etc/quantum-panel\nPANEL_USER=quantum-panel\nSERVER_NAME=""\nTLS_PORT=7443\nhave() { command -v "$1" >/dev/null; }\ninfo() { echo "INFO: $1"; }\n' > /tmp/env.sh
source /tmp/env.sh
source /tmp/tlsfn.sh
tls_selfsigned_step
