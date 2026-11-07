#!/usr/bin/env bash
###############################################################################
# tests/installers_container_test.sh — RELEASE-REQUESTS verification in a
# clean ubuntu:24.04 container named quantum-test-* (removed afterwards,
# with docker ps -a proof):
#
#   1. shellcheck clean on install-agent.sh + install-panel.sh
#   2. --verify-only --binary --checksum  → OK, works non-root, no systemd
#   3. --verify-only with a WRONG checksum → exit 1 printing expected: + got:
#   4. full install, wrong checksum → fails at the CHECKSUM, before systemd
#   5. full install, valid checksum → passes verification, dies at systemd
#   6. --verify-only without --checksum → clear error
#
# Requires: docker CLI (docker or docker.exe) + go (to build the agent
# binary; or pass AGENT_BIN=<prebuilt linux binary>).
# Run: bash tests/installers_container_test.sh
###############################################################################
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

PREFIX="quantum-test-installers"
CT="$PREFIX"
WORK="$(pwd)/tests/.installer-work"
rm -rf "$WORK"; mkdir -p "$WORK"

cleanup() {
    docker rm -f "$CT" >/dev/null 2>&1 || true
    rm -rf tests/.installer-work 2>/dev/null || true
    echo "== proof: no $PREFIX resources remain =="
    # Scoped to THIS test's prefix: other sessions may legitimately run
    # their own quantum-test-* containers (e.g. quantum-test-eng45).
    docker ps -a --format '{{.Names}}' | grep "^$PREFIX" && echo "LEFTOVER CONTAINERS!" || echo "containers: none ✓"
}
trap cleanup EXIT

DOCKER="docker"
command -v docker >/dev/null 2>&1 || { DOCKER="docker.exe"; docker() { "$DOCKER" "$@"; }; }

$DOCKER info >/dev/null 2>&1 || { echo "SKIP: docker daemon not reachable"; trap - EXIT; exit 0; }
WINMOUNT="$(cygpath -m "$(pwd)" 2>/dev/null || pwd)"

echo "== building a real quantum-agent binary (linux/amd64) =="
if [ -n "${AGENT_BIN:-}" ]; then
    cp "$AGENT_BIN" "$WORK/quantum-agent-linux-amd64"
elif command -v go >/dev/null 2>&1; then
    GOFLAGS=-mod=mod GOPROXY=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
        go build -trimpath -o "$WORK/quantum-agent-linux-amd64" ./cmd/quantum-agent
else
    wsl.exe -d Ubuntu-24.04 -- bash -lc \
        "export GOFLAGS=-mod=mod GOPROXY=file:///tmp/goproxy,https://proxy.golang.org GOSUMDB=off GOPRIVATE=github.com/Dark-modem/* GOPATH=\$HOME/go; cd /mnt/c/Users/-Mahdi/Downloads/Quantum/01-REPOSITORIES/wt-phase4-installers && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o '$(cygpath -m "$WORK" | sed 's|^C:|/mnt/c|')/quantum-agent-linux-amd64' ./cmd/quantum-agent"
fi
[ -f "$WORK/quantum-agent-linux-amd64" ] || { echo "FAIL: no test binary"; exit 1; }
REAL_SUM="$(sha256sum "$WORK/quantum-agent-linux-amd64" | cut -d' ' -f1)"
echo "binary sha256: $REAL_SUM"

echo "== container up =="
docker rm -f "$CT" >/dev/null 2>&1 || true
docker run -d --name "$CT" -v "${WINMOUNT}:/work" ubuntu:24.04 sleep 1200 >/dev/null
docker exec "$CT" bash -c "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq shellcheck openssl curl python3 >/dev/null 2>&1" \
    || { echo "SKIP: container apt failed (no network?)"; exit 0; }
BIN_IN="/work/tests/.installer-work/quantum-agent-linux-amd64"

pass=0; fail=0
ok()  { echo "  PASS: $1"; pass=$((pass+1)); }
bad() { echo "  FAIL: $1"; fail=$((fail+1)); }

echo "== 1. shellcheck =="
if docker exec "$CT" bash -c "cd /work && shellcheck -S warning install-agent.sh install-panel.sh"; then
    ok "shellcheck clean (both installers)"
else
    bad "shellcheck reported problems"
fi

echo "== 2. --verify-only OK case (non-root, no systemd) =="
out="$(docker exec -u 1000:1000 "$CT" bash -c "cd /work && bash install-agent.sh --verify-only --binary $BIN_IN --checksum $REAL_SUM" 2>&1)" && rc=0 || rc=$?
if [ "$rc" -eq 0 ] && echo "$out" | grep -q "checksum verified"; then
    ok "--verify-only OK (non-root, no systemd): checksum verified"
else
    bad "--verify-only OK case (rc=$rc): $out"
fi

echo "== 3. --verify-only WRONG checksum =="
out="$(docker exec "$CT" bash -c "cd /work && bash install-agent.sh --verify-only --binary $BIN_IN --checksum 0000000000000000000000000000000000000000000000000000000000000000" 2>&1)" && rc=0 || rc=$?
if [ "$rc" -ne 0 ] && echo "$out" | grep -q "checksum mismatch" \
   && echo "$out" | grep -q "expected: 0000000000000000000000000000000000000000000000000000000000000000" \
   && echo "$out" | grep -q "got:      $REAL_SUM"; then
    ok "mismatch exits 1 printing expected: 0000… and got: $REAL_SUM"
else
    bad "mismatch output (rc=$rc): $out"
fi

echo "== 4. full install, WRONG checksum → fails BEFORE systemd =="
out="$(docker exec "$CT" bash -c "cd /work && bash install-agent.sh --binary $BIN_IN --checksum 0000000000000000000000000000000000000000000000000000000000000000 --server https://panel.example:7443 --token-file /dev/null" 2>&1)" && rc=0 || rc=$?
if echo "$out" | grep -q "checksum mismatch" && ! echo "$out" | grep -q "systemd is required"; then
    ok "wrong checksum fails at the CHECKSUM (before the systemd gate)"
else
    bad "ordering broken (rc=$rc): $out"
fi

echo "== 5. full install, VALID checksum → passes, dies at systemd =="
out="$(docker exec "$CT" bash -c "cd /work && bash install-agent.sh --binary $BIN_IN --checksum $REAL_SUM --server https://panel.example:7443 --token-file /dev/null" 2>&1)" && rc=0 || rc=$?
if echo "$out" | grep -q "systemd is required" && ! echo "$out" | grep -q "checksum mismatch"; then
    ok "valid checksum passes verification; systemd gate is the next stop"
else
    bad "valid-checksum full install (rc=$rc): $out"
fi

echo "== 6. --verify-only without --checksum =="
out="$(docker exec "$CT" bash -c "cd /work && bash install-agent.sh --verify-only --binary $BIN_IN" 2>&1)" && rc=0 || rc=$?
if echo "$out" | grep -q "requires --checksum"; then
    ok "missing --checksum reported clearly"
else
    bad "missing --checksum case (rc=$rc): $out"
fi


# ---- Phase-7 fixes (RUNBOOK-FIXES items 7, 8, 9 + panel-side 2/3) ----
# The inner scripts ride /work as files (no nested quoting in the test).

echo "== 7. enroll URL keeps the base path (item 7) =="
# NB: no pkill here — `pkill -f xstub` would match this bash -c's own
# command line and kill the shell before the stub starts (fresh container
# each run, so nothing to clean).
docker exec "$CT" bash -c 'nohup python3 -c "
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        code = 400 if self.path == \"/mybase/api/agent/enroll\" else 404
        self.send_response(code); self.send_header(\"Content-Length\", \"0\"); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer((\"127.0.0.1\", 18901), H).serve_forever()
" > /tmp/stub.log 2>&1 & sleep 1' || true
# MSYS_NO_PATHCONV=1 (per-call, NOT exported): Git Bash would otherwise
# translate the "/work/..." file argument into a Windows path before
# docker.exe sees it.
if MSYS_NO_PATHCONV=1 docker exec "$CT" bash /work/tests/p7/norm.sh | grep -q "NORMALIZED:http://127.0.0.1:18901/mybase"; then
    ok "normalize_server_url keeps the base path (item 7)"
else
    bad "base-path normalization (item 7)"
fi

echo "== 9. panel TLS cert has IP SANs + key owned by the service user (items 2/8) =="
MSYS_NO_PATHCONV=1 docker exec "$CT" bash /work/tests/p7/tls.sh >/dev/null 2>&1 || true
if docker exec "$CT" bash -c 'openssl x509 -in /etc/quantum-panel/tls/server.crt -noout -text | grep -q "IP Address"'; then
    ok "panel TLS cert carries IP SANs (item 8)"
else
    bad "panel TLS cert missing IP SANs"
fi
if docker exec "$CT" bash -c '[ "$(stat -c %U /etc/quantum-panel/tls/server.key)" = "quantum-panel" ]'; then
    ok "TLS key owned by the service user (item 2)"
else
    bad "TLS key ownership wrong"
fi

echo "== 10. panel.json chowned to the service user (item 3) =="
out="$( { MSYS_NO_PATHCONV=1 docker exec "$CT" bash /work/tests/p7/owner.sh 2>&1 || true; } | tail -1)"
if echo "$out" | grep -q "quantum-panel"; then
    ok "panel.json chowned to the service user (item 3)"
else
    bad "panel.json ownership (out=$out)"
fi
