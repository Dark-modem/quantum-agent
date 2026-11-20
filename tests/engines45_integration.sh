#!/usr/bin/env bash
###############################################################################
# tests/engines45_integration.sh — REAL wstunnel v10.1.9 + chisel v1.10.1 +
# frp 0.61.1 through the REAL drivers, ONE privileged container
# (quantum-test-eng45) with TWO network namespaces inside (nsa =
# foreign/server, nsb = iran/client), artifacts over real HTTP (R5 manifest
# + files), iperf3 THROUGH the tunnels, kill → Health fails → supervisor
# restart → traffic again, and the mixed-engine Manager phase (frp +
# wstunnel + chisel + matrix). Phases run BACK-TO-BACK in the same netns;
# the client legs are phase-scoped (see engines45_integration_test.go).
# The container is REMOVED afterwards with proof.
#
# AGENT-25 harness repairs (all pre-existing drift):
#   - the artifacts step ran the script through `tr -d "\n"`, which makes
#     it a ONE-LINE COMMENT (no-op) — the lab silently ran on stale pins +
#     a stale /var/tmp/eng45-art for generations; now run BY PATH.
#   - the runner was built from a hardcoded phase-7-era worktree path
#     (wt-p7-engines); now from THIS repo.
#   - the preflight checked the upstream frp name (underscores) while the
#     repacked artifact is dash-named — preflight could never pass.
#   - the WSL build env used GOSUMDB=off (blocks the pinned toolchain's
#     verification) and a /tmp/goproxy that does not survive a WSL
#     restart; now the backend19-gates.sh env pattern.
#   - the runner-start docker exec lines carry POSIX paths in -e values
#     without MSYS_NO_PATHCONV=1 — Git Bash rewrote ENG45_STATUS to a
#     Windows path, status writes went nowhere, and every phase "ended"
#     via the 8-minute TIMEOUT branch (the predecessors' eng45 evidence
#     shows exactly that; the mixed-B FAIL was only ever visible in the
#     runner-B log tail).
###############################################################################
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

CT=quantum-test-eng45
STATUS_DIR="$(pwd)/tests/.eng45-status.d"; rm -rf "$STATUS_DIR"; mkdir -p "$STATUS_DIR"
STATUS="$STATUS_DIR/status.txt"
WSVER=10.1.9; CHVER=1.10.1; FRVER=0.61.1

cleanup() {
    docker rm -f "$CT" >/dev/null 2>&1 || true
    echo "== proof: no quantum-test-eng45 resources remain =="
    docker ps -a --format '{{.Names}}' | grep '^quantum-test-eng45' && echo "LEFTOVER!" || echo "containers: none ✓"
}
trap cleanup EXIT

DOCKER="docker"; command -v docker >/dev/null 2>&1 || DOCKER=docker.exe

echo "== 1-4. fetch + repack + sign + manifest (WSL-native /tmp) =="
REPO_WIN="$(cygpath -m "$(pwd)" 2>/dev/null || echo "$(pwd)")"
WSL_REPO="/mnt/c/${REPO_WIN#*:}"
# Run the artifacts script BY PATH and let it write the pins into THIS
# repo's tests/ (gitignored). The old `tr -d "\n"` "copy" made the script
# a one-line comment (silent no-op — the lab ran on stale pins for
# generations); see the header.
MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -- bash -c "bash '$WSL_REPO/tests/engines45_artifacts.sh' '$WSL_REPO/tests/.eng45-env.sh'" || exit 1
eval "$(cat tests/.eng45-env.sh)"
[ -n "${PUB_B64:-}" ] && [ -n "${WS_SHA_AMD:-}" ] && [ -n "${FR_SHA_AMD:-}" ] || { echo "FATAL: pins incomplete"; exit 1; }
echo "  pins loaded (pub ${PUB_B64:0:20}…)"

echo "== 5. build the runner test binary (linux/amd64, key pinned) =="
# ALWAYS build in WSL with the linux toolchain; output to the /mnt/c path
# (a Windows-form -o path silently produced a PE binary once — never again).
# Gate env = the backend19-gates.sh pattern (GOTOOLCHAIN pinned, GOPROXY=off
# over the synced module cache): GOSUMDB=off BLOCKS the pinned toolchain's
# verification, and /tmp/goproxy does not survive a WSL restart.
MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -- bash -c "source '$WSL_REPO/tests/.eng45-env.sh'; export GOTOOLCHAIN=go1.26.9 GOFLAGS=-mod=mod GOPROXY=off GOPATH=\$HOME/go; export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:\$HOME/go/bin; cd '$WSL_REPO' && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -tags integration -ldflags \"-X github.com/Dark-modem/quantum-agent/internal/agent.engineArtifactPubKeyB64=\$PUB_B64\" -o '$WSL_REPO/tests/.eng45.test' ./internal/agent/" || exit 1
head -c 4 tests/.eng45.test | od -A n -t x1 | grep -q "7f 45 4c 46" || { echo "FATAL: runner binary is not a linux ELF"; exit 1; }
echo "  runner binary: linux ELF ok"
# NOTE: the ldflags pin is best-effort (the /mnt/c source flakes under
# AV locks); the container runners re-pin from ENG45_PUBKEY at runtime,
# which the orchestrator passes per container — that is the authoritative
# mechanism (verified by the artifact signature checks in the scenario).

echo "== 6. ONE privileged container, TWO network namespaces inside =="
docker rm -f "$CT" >/dev/null 2>&1 || true
STATUS_WIN="$(cygpath -m "$STATUS_DIR" 2>/dev/null || echo "$STATUS_DIR")"
docker run -d --name "$CT" --privileged -v "${STATUS_WIN}:/status" ubuntu:24.04 sleep 7200 >/dev/null
docker cp tests/.eng45.test "$CT":/eng45.test && docker exec "$CT" bash -c 'chmod 755 /eng45.test'
docker exec "$CT" bash -c "apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq iperf3 python3 iproute2 curl >/dev/null 2>&1"
MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -- bash -c 'cd /var/tmp/eng45-art/pub && tar -cf - .' | docker exec -i "$CT" bash -c 'mkdir -p /pub && tar -xf - -C /pub && echo "artifacts in container: $(ls /pub/pk/api/agent/artifact | wc -l)"'
docker exec "$CT" bash -c 'ip netns add nsa && ip netns add nsb && ip link add veth-a type veth peer name veth-b && ip link set veth-a netns nsa && ip link set veth-b netns nsb && ip netns exec nsa ip addr add 10.200.0.1/24 dev veth-a && ip netns exec nsa ip link set veth-a up && ip netns exec nsa ip link set lo up && ip netns exec nsb ip addr add 10.200.0.2/24 dev veth-b && ip netns exec nsb ip link set veth-b up && ip netns exec nsb ip link set lo up && echo netns-ok'
docker exec "$CT" bash -c 'test -x /eng45.test || exit 1; test -f /pub/pk/api/agent/artifact/frp-0.61.1-linux-amd64.tar.gz || exit 1; echo preflight-ok' || exit 1

run_phase() { # phase testname
    local phase="$1" testname="$2"
    echo "== phase: $phase =="
    : > "$STATUS"
    # Artifact HTTP server in nsa (the server end fetches via loopback of
    # its own ns; the client end via the veth IP).
    docker exec -d "$CT" bash -c 'ip netns exec nsa python3 -m http.server 8111 --directory /pub'
    sleep 1
    # SERVER end (nsa): self=germany. CLIENT end (nsb): self=iran-1.
    # NOTE: each -e gets ONE VAR=value (docker drops combined strings).
    local -a envsrv=(ENG45_ROLE=server ENG45_SELF=germany ENG45_PEER=10.200.0.1
        ENG45_ART_URL=http://127.0.0.1:8111/pk ENG45_STATUS=/status/status.txt
        ENG45_PUBKEY="$PUB_B64")
    local -a envcli=(ENG45_ROLE=client ENG45_SELF=iran-1 ENG45_PEER=10.200.0.1
        ENG45_ART_URL=http://10.200.0.1:8111/pk ENG45_STATUS=/status/status.txt
        ENG45_PUBKEY="$PUB_B64")
    envsrv+=(ENG45_ART_NAME_WST=wstunnel-$WSVER-linux-{arch}.tar.gz ENG45_ART_SHA_WST=$WS_SHA_AMD "ENG45_ART_SIG_WST=$WS_SIG_AMD")
    envcli+=(ENG45_ART_NAME_WST=wstunnel-$WSVER-linux-{arch}.tar.gz ENG45_ART_SHA_WST=$WS_SHA_AMD "ENG45_ART_SIG_WST=$WS_SIG_AMD")
    envsrv+=(ENG45_ART_NAME_CHISEL=chisel-$CHVER-linux-{arch}.tar.gz ENG45_ART_SHA_CHISEL=$CH_SHA_AMD "ENG45_ART_SIG_CHISEL=$CH_SIG_AMD")
    envcli+=(ENG45_ART_NAME_CHISEL=chisel-$CHVER-linux-{arch}.tar.gz ENG45_ART_SHA_CHISEL=$CH_SHA_AMD "ENG45_ART_SIG_CHISEL=$CH_SIG_AMD")
    envsrv+=(ENG45_ART_NAME_FRP=frp-$FRVER-linux-{arch}.tar.gz ENG45_ART_SHA_FRP=$FR_SHA_AMD "ENG45_ART_SIG_FRP=$FR_SIG_AMD")
    envcli+=(ENG45_ART_NAME_FRP=frp-$FRVER-linux-{arch}.tar.gz ENG45_ART_SHA_FRP=$FR_SHA_AMD "ENG45_ART_SIG_FRP=$FR_SIG_AMD")
    # MSYS_NO_PATHCONV=1 — the -e values carry POSIX paths (/status/...);
    # from Git Bash without it, MSYS rewrites them to Windows paths (the
    # live repro caught ENG45_STATUS=C:/Program Files/Git/status/status.txt
    # — every status write silently went nowhere, so NO phase ever saw its
    # done marker and every phase "ended" via the 8-minute TIMEOUT branch).
    MSYS_NO_PATHCONV=1 docker exec -d "${envsrv[@]/#/-e}" "$CT" bash -c "ip netns exec nsa /eng45.test -test.run $testname -test.timeout 30m > /status/runner-A-$phase.log 2>&1"
    sleep 2
    MSYS_NO_PATHCONV=1 docker exec -d "${envcli[@]/#/-e}" "$CT" bash -c "ip netns exec nsb /eng45.test -test.run $testname -test.timeout 30m > /status/runner-B-$phase.log 2>&1"
    local done_marker="$phase SCENARIO-DONE"
    for i in $(seq 1 240); do
        if grep -q "$done_marker" "$STATUS" 2>/dev/null; then echo "  $phase DONE"; return 0; fi
        # The kill is SELF-INFLICTED by the client runner (t+15s,
        # deterministic) — the supervisor restarts it; no host coordination.
        if [ -f "$STATUS.killed$phase" ]; then :; fi
        if grep -qE "ERROR|NEVER-UP|NEVER-DOWN|NEVER-RECOVERED" "$STATUS" 2>/dev/null; then
            echo "  $phase FAILED:"; grep -E "ERROR|NEVER" "$STATUS" | head -3
            echo "  --- A:"; tail -6 "$STATUS_DIR/runner-A-$phase.log" 2>/dev/null
            echo "  --- B:"; tail -6 "$STATUS_DIR/runner-B-$phase.log" 2>/dev/null
            return 1
        fi
        sleep 2
    done
    echo "  $phase TIMEOUT"
    echo "  --- A:"; tail -8 "$STATUS_DIR/runner-A-$phase.log" 2>/dev/null
    echo "  --- B:"; tail -8 "$STATUS_DIR/runner-B-$phase.log" 2>/dev/null
    return 1
}

echo "== 7. install runner + preflight (done above) =="
echo "== 8. phases =="
RC=0
# Phase name "wst": the test's status line is "wst SCENARIO-DONE" — the
# old "wstunnel" phase name's done marker never matched, so the wst phase
# always burned the full 8-minute timeout before moving on.
run_phase wst "TestEngines45WstunnelEnd" || RC=1
run_phase chisel "TestEngines45ChiselEnd" || RC=1
run_phase mixed "TestEngines45MixedManager" || RC=1

echo "== 9. results =="
cat "$STATUS"
echo
echo "== overhead (lab-loopback, iperf3 Mbits/s) =="
grep -E "iperf" "$STATUS" || echo "  (iperf3 fell back to the byte pump — see FALLBACK lines)"
rm -f "$STATUS".killed* /tmp/eng45-signing.key
docker rm -f "$CT" >/dev/null 2>&1 || true
exit $RC
