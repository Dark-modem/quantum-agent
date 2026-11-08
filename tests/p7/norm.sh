#!/usr/bin/env bash
# Extract the needed functions from the installers, then run the check.
sed -n '/^normalize_server_url()/,/^}/p' /work/install-agent.sh > /tmp/normfn.sh
printf 'die() { echo "DIE: %s"; exit 1; }\ninfo() { echo "INFO: %s"; }\ntrun() { local t="$1"; shift; timeout "$t" "$@"; }\nSERVER="http://127.0.0.1:18901/mybase"\n' > /tmp/env.sh
source /tmp/env.sh
source /tmp/normfn.sh
normalize_server_url
echo "NORMALIZED:$SERVER"
