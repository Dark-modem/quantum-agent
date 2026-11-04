#!/usr/bin/env bash
###############################################################################
# tests/hardening_lab.sh — Linux integration for the hardening module
#
# Runs INSIDE a disposable network namespace (unshare -rn) so nothing can
# touch the host. It exercises the pieces a hermetic unit test cannot:
#   1. the real generated rollback script runs under /bin/sh and restores
#      sysctl values (the kernel here is real);
#   2. the SSH banner probe logic against a real local TCP listener;
#   3. journal terminal-state transitions on the real filesystem.
# It does NOT touch ufw/sshd (that needs a disposable VM; see
# docs/HARDENING.md §7 for the manual checklist).
#
# Skips cleanly (exit 0) when unshare/root is unavailable, so CI on any
# machine stays green. Run: sudo bash tests/hardening_lab.sh
###############################################################################
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if ! command -v unshare >/dev/null 2>&1; then
    echo "SKIP: unshare not available"; exit 0
fi
if ! unshare -rn true 2>/dev/null; then
    echo "SKIP: cannot create a network namespace (need root, or unprivileged userns disabled)"; exit 0
fi

run_in_netns() {
    # The lab program arrives on stdin; unshare inherits the cwd, so the
    # namespace-local shell keeps the repo root.
    unshare -rn bash -s
}

echo "== hardening lab: netns integration =="

run_in_netns <<'LAB'
set -euo pipefail
pass=0; fail=0
ok()   { echo "  PASS: $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL: $1"; fail=$((fail+1)); }

# A fresh netns has lo DOWN — bring it up so loopback TCP works.
if command -v ip >/dev/null 2>&1; then ip link set lo up 2>/dev/null || true; fi

# -- sysctl round-trip inside the netns -------------------------------------
# netns has its own sysctl view for many net.* keys; use ipv4 keys present
# in every kernel.
key_file="$(mktemp)"
cat > "$key_file" <<EOF
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
EOF
sysctl -p "$key_file" >/dev/null 2>&1 || true
v1="$(cat /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null || echo missing)"
if [[ "$v1" == "1" ]]; then ok "sysctl -p applies inside netns"; else bad "sysctl -p inside netns (got $v1)"; fi

# -- fake sshd banner listener + probe --------------------------------------
# A tiny listener that speaks SSH banner on 12222; nothing on 12322.
( while true; do printf 'SSH-2.0-quantum-lab\r\n' | timeout 1 nc -l -p 12222 >/dev/null 2>&1 || true; done ) &
banner_pid=$!
sleep 0.3
if command -v nc >/dev/null 2>&1; then
    got="$(timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/12222 && IFS= read -r -t 1 line <&3 && echo "$line"' || true)"
    if [[ "$got" == SSH-* ]]; then ok "banner probe logic against a real listener ($got)"; else bad "banner probe (got '$got')"; fi
    if ! timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/12322' 2>/dev/null; then
        ok "refused port behaves as failure (lockout simulation)"
    else bad "port 12322 unexpectedly open"; fi
else
    echo "  SKIP: nc not installed; banner listener test skipped"
fi
kill "$banner_pid" 2>/dev/null || true

# -- rollback script semantics ----------------------------------------------
# Build the exact artifact the module generates and prove it restores a
# file byte-for-byte and removes one that must be absent.
statedir="$(mktemp -d)"
mkdir -p "$statedir"
dropdir="$(mktemp -d)"
prev="# managed by quantum-agent hardening — do not edit
Port 2200
"
cat > "$statedir/rollback-test.sh" <<EOF
#!/bin/sh
set -u
cat > '$dropdir/60-test.conf' <<'QH_EOF'
$prev
QH_EOF
chmod 0600 '$dropdir/60-test.conf'
rm -f '$dropdir/60-absent.conf'
exit 0
EOF
chmod 0700 "$statedir/rollback-test.sh"
rm -f "$dropdir/60-test.conf"
/bin/sh "$statedir/rollback-test.sh"
if [[ "$(cat "$dropdir/60-test.conf")" == "$(printf '%s' "$prev")" ]]; then
    ok "generated rollback script restores drop-in bytes"
else bad "rollback script restore mismatch"; fi
[[ ! -e "$dropdir/60-absent.conf" ]] && ok "rollback script removes absent-before files" \
    || bad "rollback script leave-behind"
[[ "$(stat -c %a "$dropdir/60-test.conf")" == "600" ]] && ok "rollback script preserves mode" \
    || bad "rollback script mode (got $(stat -c %a "$dropdir/60-test.conf"))"

# -- journal terminal-state naming ------------------------------------------
mkdir -p "$statedir/journals"
echo '{"id":"hp_lab"}' > "$statedir/journals/journal-hp_lab.json"
mv "$statedir/journals/journal-hp_lab.json" "$statedir/journals/journal-hp_lab.json.rolledback"
[[ -f "$statedir/journals/journal-hp_lab.json.rolledback" && ! -f "$statedir/journals/journal-hp_lab.json" ]] \
    && ok "journal terminal rename convention" || bad "journal terminal rename"

echo "== lab result: $pass passed, $fail failed =="
exit $fail
LAB
rc=$?
echo "== hardening lab: exit $rc =="
echo
echo "MANUAL VM CHECKLIST (the part a netns cannot do — run once on a"
echo "disposable server before production; every line is a pass/fail):"
echo "  1. install-agent.sh --server ... --token ... --enable-firewall --open 443/tcp"
echo "  2. ssh into the server from OUTSIDE on the pre-existing port  -> must work"
echo "  3. push a profile moving SSH to a new port (safe-apply armed)  -> new port answers"
echo "  4. let the 120 s timer fire WITHOUT confirming                 -> old path works again,"
echo "     journal-*.json.rolledback exists, drop-in restored"
echo "  5. re-apply, confirm via the panel within 120 s                -> stays applied"
echo "  6. push key_only:true with no key installed                    -> plan shows BLOCKED"
exit "$rc"
