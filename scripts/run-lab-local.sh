#!/usr/bin/env bash
###############################################################################
# scripts/run-lab-local.sh — isolated laptop lab, end to end (AGENT-16).
#
# One entry point for the full quantum-agent lab on THIS laptop:
#   [1/5] hermetic gates           — gofmt + go vet + go test ./... -count=1
#                                    (WSL Ubuntu-24.04, GOTOOLCHAIN=go1.26.9)
#   [2/5] hardening netns lab      — tests/hardening_lab.sh (unshare -rn, WSL)
#   [3/5] ctunnel netns lab        — REAL ctunnel-engine v1.1.1 release binary
#                                    through the real driver paths: R5-style
#                                    artifact verify → TUN → reverse carrier →
#                                    TCP/UDP echo → restart (go test -tags
#                                    integration -run TestCtunnelIntegration)
#   [4/5] e2e netns lab            — REAL panel + 6 REAL agents over netns:
#                                    v2 negotiation, DesiredV2, weighted
#                                    forwards, failover, counters (e2e_real.sh)
#   [5/5] installer container test — shellcheck + verify/install lifecycle in
#                                    clean ubuntu:24.04 containers named
#                                    quantum-test-*
#
# Isolation: Linux labs run in network namespaces; the container test uses
# docker containers named quantum-test-* only; nothing touches real servers.
# The script ENDS with cleanup proof: full `docker ps -a` (no quantum-test-*
# may remain) + `ip netns list` / bridge / nft / process checks (no lab
# leftovers may remain). Any leftover makes the script exit non-zero.
#
# Run from Git Bash on the laptop (needs wsl.exe + docker.exe + a Windows go
# for step 5; steps 1-4 run inside WSL as the default user — the lab scripts
# use passwordless sudo for the netns operations only).
#
# Optional explicit skips (reported as SKIPPED, never silent):
#   QUANTUM_LAB_SKIP="ctunnel e2e installers"   — space-separated step names;
#                                                 step 1 (gates) always runs.
###############################################################################
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WREPO="$(cygpath -m "$REPO_ROOT" 2>/dev/null || echo "$REPO_ROOT")"
WSL_REPO="/mnt/c/${WREPO#*:/}"
WSL_DISTRO="${WSL_DISTRO:-Ubuntu-24.04}"
CT_CACHE="\$HOME/.cache/quantum-lab/ct-int"
SCRATCH="$REPO_ROOT/tests/.lab-scratch"
WSL_SCRATCH="/mnt/c/${WREPO#*:/}/tests/.lab-scratch"
mkdir -p "$SCRATCH"

DOCKER="docker"
command -v docker >/dev/null 2>&1 || DOCKER="docker.exe"

PASS=0; FAIL=0; SKIPPED=0
want() { case " ${QUANTUM_LAB_SKIP:-} " in *" $1 "*) return 1 ;; *) return 0 ;; esac; }
ok()   { PASS=$((PASS+1)); echo "[lab] PASS: $*"; }
bad()  { FAIL=$((FAIL+1)); echo "[lab] FAIL: $*"; }
skip() { SKIPPED=$((SKIPPED+1)); echo "[lab] SKIPPED: $*"; }
say()  { echo; echo "[lab] ===== $* ====="; }

# Run a step inside WSL. Payloads live under tests/.lab-scratch on /mnt/c
# (persistent); the /tmp copy only needs to survive this one WSL invocation.
# WSL_STEP_SUDO=1 runs the payload via `sudo -n` (for the root-only netns/nft
# inspection in the cleanup proof).
wsl_step() { # $1=payload FILENAME under tests/.lab-scratch
    local RUNNER="bash"
    [ "${WSL_STEP_SUDO:-0}" = "1" ] && RUNNER="sudo -n bash"
    MSYS_NO_PATHCONV=1 wsl.exe -d "$WSL_DISTRO" -- bash -c \
        "tr -d '\r' < '$WSL_SCRATCH/$1' > /tmp/lab-payload.sh && $RUNNER /tmp/lab-payload.sh"
}

run_step() { # $1=name $2=payload filename — prints output, verdicts on exit code
    local out rc
    out="$(wsl_step "$2" 2>&1 | tr -d '\0')"; rc=$?
    echo "$out" | sed 's/^/      /'
    if [ "$rc" -eq 0 ]; then ok "$1"; else bad "$1 (exit $rc — see output above)"; fi
}

cleanup_scratch() { rm -rf "$SCRATCH" 2>/dev/null || true; }
trap cleanup_scratch EXIT

echo "[lab] repo:    $REPO_ROOT"
echo "[lab] wsl:     $WSL_DISTRO ($WSL_REPO)"
echo "[lab] docker:  $DOCKER"
echo "[lab] skips:   ${QUANTUM_LAB_SKIP:-none}"

# [1/5] hermetic gates (always run) --------------------------------------------
say "step 1/5 hermetic gates (gofmt + vet + test)"
cat > "$SCRATCH/gates.sh" <<EOF
set -o pipefail
export GOTOOLCHAIN=go1.26.9
cd "$WSL_REPO" || exit 1
echo "\$(go version)"
UNFMT="\$("\$(go env GOROOT)/bin/gofmt" -l . 2>&1)"
if [ -n "\$UNFMT" ]; then echo "\$UNFMT"; echo GOFMT-DIRTY; exit 2; fi
echo GOFMT-CLEAN
go vet ./... && echo VET-OK || { echo VET-FAIL; exit 3; }
go test ./... -count=1 && echo TEST-OK || { echo TEST-FAIL; exit 4; }
EOF
run_step "hermetic gates" "gates.sh"

# [2/5] hardening netns lab -----------------------------------------------------
say "step 2/5 hardening netns lab"
if want hardening; then
cat > "$SCRATCH/hardening.sh" <<EOF
cd "$WSL_REPO" || exit 1
bash tests/hardening_lab.sh
EOF
    run_step "hardening netns lab" "hardening.sh"
else
    skip "hardening netns lab"
fi

# [3/5] ctunnel real-binary netns integration -----------------------------------
say "step 3/5 ctunnel netns lab (real v1.1.1 binary)"
if want ctunnel; then
cat > "$SCRATCH/ctunnel.sh" <<EOF
set -o pipefail
export GOTOOLCHAIN=go1.26.9
cd "$WSL_REPO" || exit 1
mkdir -p "$CT_CACHE"
CT_INTEGRATION=1 CT_INTEG_DIR="$CT_CACHE" go test -tags integration \
    -run TestCtunnelIntegration ./internal/agent/ -count=1 -v
EOF
    run_step "ctunnel netns lab" "ctunnel.sh"
else
    skip "ctunnel netns lab"
fi

# [4/5] e2e netns lab ------------------------------------------------------------
say "step 4/5 e2e netns lab (real panel + 6 agents)"
if want e2e; then
cat > "$SCRATCH/e2e.sh" <<EOF
set -o pipefail
export GOTOOLCHAIN=go1.26.9
cd "$WSL_REPO" || exit 1
bash tests/e2e_real.sh
EOF
    run_step "e2e netns lab" "e2e.sh"
else
    skip "e2e netns lab"
fi

# [5/5] installer container test --------------------------------------------------
say "step 5/5 installer container test (quantum-test-*)"
if want installers; then
    if "$DOCKER" info >/dev/null 2>&1; then
        (cd "$REPO_ROOT" && bash tests/installers_container_test.sh) \
            && ok "installer container test" || bad "installer container test"
    else
        bad "docker daemon unreachable — installer container test cannot run"
    fi
else
    skip "installer container test"
fi

# CLEANUP PROOF (the last thing this script prints) --------------------------------
say "cleanup proof"
echo "== docker ps -a (full) =="
"$DOCKER" ps -a 2>&1
echo "== docker verdict =="
if "$DOCKER" ps -a --format '{{.Names}}' 2>/dev/null | grep '^quantum-test'; then
    bad "LEFTOVER quantum-test-* containers (listed above)"
else
    ok "containers: no quantum-test-* left"
fi
cat > "$SCRATCH/netns-proof.sh" <<EOF
echo "== ip netns list =="
ip netns list
echo "== bridge/nft leftovers =="
ip link show br-qe2e 2>&1 | head -1
nft list table ip quantum-fwd 2>&1 | head -2
echo "== lab processes =="
pgrep -a quantum-panel || echo "no quantum-panel process"
pgrep -af "quantum-agent run" || echo "no quantum-agent run process"
echo "== netns verdict =="
LEFT=0
ip netns list | grep -E '^(q-|ct-)' && { echo "leftover netns (listed above)"; LEFT=1; }
ip link show br-qe2e >/dev/null 2>&1 && { echo "br-qe2e still present"; LEFT=1; }
nft list table ip quantum-fwd >/dev/null 2>&1 && { echo "nft table quantum-fwd still present"; LEFT=1; }
pgrep -x quantum-panel >/dev/null && { echo "quantum-panel still running"; LEFT=1; }
pgrep -f "quantum-agent run" >/dev/null && { echo "quantum-agent still running"; LEFT=1; }
[ "\$LEFT" = "0" ] && echo NETNS-CLEAN || echo NETNS-LEFTOVERS
exit "\$LEFT"
EOF
out="$(WSL_STEP_SUDO=1 wsl_step "netns-proof.sh" 2>&1 | tr -d '\0')"; rc=$?
echo "$out" | sed 's/^/      /'
if [ "$rc" -eq 0 ]; then ok "netns: clean (proof above)"; else bad "netns: leftovers (exit $rc, proof above)"; fi

say "verdict: $PASS passed, $FAIL failed, $SKIPPED skipped"
[ "$FAIL" -eq 0 ] || exit 1
echo "LAB-GREEN"
