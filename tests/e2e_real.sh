#!/usr/bin/env bash
# e2e_real.sh — REAL panel + REAL agents over network namespaces (Phase 3).
#
# Topology (ARCHITECTURE-BRIEF-V2.md): 2 Iran DCs x 2 servers, 1 foreign
# DC x 2 servers; two topologies (drak-hz, chekavak-hz); each (iran,
# foreign) pair carries 2 tunnels with DIFFERENT engines — matrix (the
# real tinc engine; see the UNVERIFIED note in the report about
# systemd-coupled engines in per-netns labs) and the lab fake engine
# (real TCP sinks + real byte counters).
#
# Verifies: v2 negotiated on all agents, DesiredV2 delivered, forward
# rule traffic with a measured weighted split, tunnel-death failover
# time, whole-foreign-server failover, panel death (traffic + failover
# keep working), panel restart without a revision storm, wire/payload
# counters in the usage API, weight change enforced on the agent.
#
# Cleanup: trap-driven (namespaces + processes) on exit and on failure.
# Nothing outside the namespaces is reconfigured (the panel runs on the
# host namespace; the balancer's nft table lives in each agent's netns).

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAB=/tmp/quantum-e2e
PANEL_IP=10.200.0.10
PANEL_PORT=18443
BR=br-qe2e
PANEL_PASS="e2e-admin-pass-1"
SINK_PORT=8443
FWD_LISTEN=8443

NS_IRAN=(q-ir-drak-1 q-ir-drak-2 q-ir-chk-1 q-ir-chk-2)
NS_FOREIGN=(q-hz-fra-1 q-hz-fra-2)
IP_IRAN=(10.200.0.11 10.200.0.12 10.200.0.13 10.200.0.14)
IP_FOREIGN=(10.200.0.21 10.200.0.22)
NS_ALL=("${NS_IRAN[@]}" "${NS_FOREIGN[@]}")
IP_ALL=("${IP_IRAN[@]}" "${IP_FOREIGN[@]}")

PASS=0; FAIL=0
# Real script exit status, restored by the EXIT trap (a completed trap
# otherwise masks `exit 1` with its own last rc — observed phase16).
E2E_RC=1
FAILED_CHECKS=()
PANEL_PID=""; AGENT_PIDS=""

say()  { echo "[e2e] $*"; }
ok()   { PASS=$((PASS+1)); echo "[e2e] PASS: $*"; }
bad()  { FAIL=$((FAIL+1)); FAILED_CHECKS+=("$*"); echo "[e2e] FAIL: $*"; }
check(){ if [ "$1" = "0" ]; then ok "$2"; else bad "$2"; fi; }

cleanup() {
  say "cleanup..."
  # /tmp dies with the WSL VM between invocations — keep the evidence
  # somewhere persistent (the repo tree) for the next debugging session.
  if [ -d "$LAB" ]; then
    LOGDIR="${E2E_LOGS:-$REPO_ROOT/tests/e2e-logs}"
    mkdir -p "$LOGDIR"
    cp -f "$LAB"/run-*.log "$LAB"/panel.log "$LAB"/api.log "$LAB"/dist-diag.log "$LOGDIR"/ 2>/dev/null
  fi
  [ -n "${PANEL_PID:-}" ] && kill "$PANEL_PID" 2>/dev/null
  # The panel's SIGTERM graceful shutdown can hang while agent sessions
  # are open — a leak means the NEXT run's panel shares this config dir
  # and store, and the two fight over panel.json (observed as RSTs).
  sleep 1
  [ -n "${PANEL_PID:-}" ] && kill -KILL "$PANEL_PID" 2>/dev/null
  sudo pkill -x quantum-panel 2>/dev/null
  for p in $AGENT_PIDS; do sudo ip netns pids "${p}" >/dev/null 2>&1; done
  sudo pkill -f "quantum-agent run" 2>/dev/null
  # Bridge FIRST, netns second. Deleting a bridge whose ports are the
  # freshly-orphaned ends of veths from netns deleted moments earlier has
  # been observed to hang the netlink call and abort this trap mid-way
  # (phase16: bridge left behind twice) — the settled bridge deletes fine.
  # timeout() keeps a hang from killing the whole cleanup either way.
  del_bridge() {
    timeout 10 sudo ip link del $BR 2>/dev/null
    if ip link show $BR >/dev/null 2>&1; then
      sleep 2
      timeout 10 sudo ip link del $BR 2>/dev/null
    fi
    ip link show $BR >/dev/null 2>&1 \
      && echo "[e2e] WARNING: bridge $BR STILL PRESENT after cleanup" \
      || echo "[e2e] cleanup: bridge $BR removed"
  }
  del_bridge
  for ns in "${NS_ALL[@]}"; do
    sudo ip netns pids "$ns" 2>/dev/null | while read -r p; do kill "$p" 2>/dev/null; done
    sudo ip netns del "$ns" 2>/dev/null
  done
  # (re-check netns too: a leftover ns would poison the NEXT run)
  LEFT_NS=0
  for ns in "${NS_ALL[@]}"; do
    ip netns list | grep -q "^$ns " && { echo "[e2e] WARNING: netns $ns STILL PRESENT"; LEFT_NS=1; }
  done
  [ "$LEFT_NS" = "0" ] && echo "[e2e] cleanup: all lab netns removed"
  del_bridge
  sudo nft delete table ip quantum-fwd 2>/dev/null
  # -D removes ONE occurrence per call; earlier aborted runs can leave
  # duplicates — loop until none remain.
  while sudo iptables -D INPUT -s 10.200.0.0/24 -j ACCEPT 2>/dev/null; do :; done
  while sudo iptables -D INPUT -i $BR -j ACCEPT 2>/dev/null; do :; done
  while sudo iptables -D FORWARD -i $BR -o $BR -j ACCEPT 2>/dev/null; do :; done
  while sudo iptables -D FORWARD -s 10.200.0.0/24 -d 10.200.0.0/24 -j ACCEPT 2>/dev/null; do :; done
  say "cleanup done"
  # bash uses the EXIT trap's last command status as the script's exit
  # status — restore the script's real rc so the lab harness sees failures
  # (a completed trap otherwise masks `exit 1` as 0; observed phase16).
  [ "$E2E_RC" -eq 0 ]
}
trap cleanup EXIT

# 0. build the real binaries ----------------------------------------------
say "building real binaries..."
# The panel pins the PRIVATE quantum-protocol module: root's git needs
# the invoking user's gh credential (passed via E2E_GH_TOKEN).
if [ -n "${E2E_GH_TOKEN:-}" ]; then
  git config --global url."https://x-access-token:${E2E_GH_TOKEN}@github.com/".insteadOf "https://github.com/"
fi
rm -rf $LAB; mkdir -p $LAB
# Pre-start sweep: a panel leaked by an aborted earlier run would share
# this fresh config dir and fight the new panel (observed as RSTs).
sudo pkill -x quantum-panel 2>/dev/null
sleep 1
# B-AG3 (AGENT-22, test-only): the panel is normally built from the SIBLING
# checkout's CURRENT state (it sits on ui/live and churns), so a lab verdict
# says nothing about WHICH panel source produced it. E2E_PANEL_SRC=<dir>
# pins the panel source: when set, the panel builds from that directory
# (an exported snapshot / throwaway clone at a known SHA) instead, making
# lab verdicts reproducible. UNSET = the default behavior, unchanged.
# Invocation note: when the lab runs from Git Bash, wsl.exe only carries
# Windows env vars listed in WSLENV — export WSLENV="E2E_PANEL_SRC"
# alongside the variable (a direct WSL shell needs no WSLENV).
PANEL_SRC="$REPO_ROOT/../quantum-panel"
if [ -n "${E2E_PANEL_SRC:-}" ]; then
  PANEL_SRC="$E2E_PANEL_SRC"
  echo "panel source PINNED via E2E_PANEL_SRC: $PANEL_SRC"
fi
if [ ! -f "$PANEL_SRC/cmd/quantum-panel/main.go" ]; then
  echo "panel source has no cmd/quantum-panel/main.go: $PANEL_SRC"
  exit 1
fi
cd "$PANEL_SRC" || exit 1
GOFLAGS="-trimpath -buildvcs=false" go build -o $LAB/quantum-panel ./cmd/quantum-panel || { echo "panel build failed"; exit 1; }
cd "$REPO_ROOT" || exit 1
GOFLAGS="-trimpath -buildvcs=false" go build -o $LAB/quantum-agent ./cmd/quantum-agent || { echo "agent build failed"; exit 1; }
cd - >/dev/null || true

# 1. namespaces + bridge ---------------------------------------------------
say "creating namespaces..."
sudo ip link add $BR type bridge 2>/dev/null
sudo ip addr add $PANEL_IP/24 dev $BR 2>/dev/null
sudo ip link set $BR up
i=0
for ns in "${NS_ALL[@]}"; do
  sudo ip netns add "$ns"
  ipaddr=${IP_ALL[$i]}
  sudo ip link add "v-$ns" type veth peer name "p-$ns"
  sudo ip link set "v-$ns" master $BR
  sudo ip link set "v-$ns" up
  sudo ip link set "p-$ns" netns "$ns"
  sudo ip netns exec "$ns" ip addr add "$ipaddr/24" dev "p-$ns"
  sudo ip netns exec "$ns" ip link set "p-$ns" up
  sudo ip netns exec "$ns" ip link set lo up
  # The balancer's DNAT forwards connections ACROSS this namespace
  # (arrive on p-$ns, leave toward the foreign sink) — without IP
  # forwarding every DNATed connection is silently dropped.
  sudo ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
  # MASQUERADE the forwarded traffic: the lab's "tunnel" is an L2 bridge,
  # so the sink's reply would otherwise be bridged STRAIGHT to the client
  # (the host answers ARP for 10.200.0.10), bypassing the balancer's
  # conntrack — the client then sees an un-translated SYN-ACK and RSTs.
  # A real deployment has no hairpin (the tunnel is an L3 interface and
  # egress traffic carries the mesh IP) — MASQUERADE replicates that
  # source semantics here.
  sudo ip netns exec "$ns" iptables -t nat -A POSTROUTING -d 10.200.0.0/24 -j MASQUERADE 2>/dev/null
  i=$((i+1))
done
REACH=0
for ipaddr in "${IP_ALL[@]}"; do ping -c1 -W1 "$ipaddr" >/dev/null 2>&1 && REACH=$((REACH+1)); done
[ "$REACH" = "${#IP_ALL[@]}" ] && ok "all 6 namespaces reachable (${REACH}/6)" || bad "namespaces reachable ($REACH/6)"

# The host firewall (ufw, INPUT policy DROP) would block netns→panel TCP;
# with br_netfilter active (bridge-nf-call-iptables=1, FORWARD DROP) the
# SAME host chains also filter BRIDGED netns→netns traffic — the probes
# and the DNATed forward connections both die there. Scope: this bridge
# only, for the duration of the run.
sudo iptables -I INPUT 1 -s 10.200.0.0/24 -j ACCEPT 2>/dev/null
sudo iptables -I INPUT 1 -i $BR -j ACCEPT 2>/dev/null
sudo iptables -I FORWARD 1 -i $BR -o $BR -j ACCEPT 2>/dev/null
sudo iptables -I FORWARD 1 -s 10.200.0.0/24 -d 10.200.0.0/24 -j ACCEPT 2>/dev/null

# 2. panel ------------------------------------------------------------------
say "starting the real panel..."
# GRE_PANEL_HTTP_BIND: the panel's plain-HTTP listener defaults to
# 127.0.0.1 (cleartext-login hardening) — the netns agents reach the panel
# over the bridge, so this lab needs the documented container/unit escape
# hatch. Scope: this lab run only; the lab subnet is firewalled in above.
export GRE_PANEL_DIR=$LAB/panel GRE_PANEL_PASSWORD=$PANEL_PASS GRE_PANEL_HTTP_BIND=0.0.0.0
mkdir -p $LAB/panel
# Pin the port BEFORE first start: the panel's preferred port (7777) is
# held by a boot-time process on this machine and the panel's auto-switch
# watcher rebinds the listener mid-run (observed as connection-refused on
# the scripted calls and the enroll POSTs). A pre-set port keeps the
# listener stable for the whole run.
PANEL_PORT=7779
printf '{"port": %d}\n' "$PANEL_PORT" > $LAB/panel/panel.json
$LAB/quantum-panel > $LAB/panel.log 2>&1 &
PANEL_PID=$!
# First start generates the config: random base path + first free port,
# with GRE_PANEL_PASSWORD applied as the initial admin password. Read the
# ACTUAL port+base back from panel.json for every scripted call.
sleep 3
eval "$(python3 -c "
import json
cfg = json.load(open('$LAB/panel/panel.json'))
print('PANEL_PORT=' + str(cfg.get('port', 7777)))
base = str(cfg.get('base_path', ''))
if base and not base.startswith('/'):
    base = '/' + base
print('PANEL_BASE=' + base)
" 2>/dev/null)"
# The panel OWNS its port: when its preferred port is busy it rebinds and
# saves panel.json — observed mid-run while a boot-time process holds the
# default port. The harness follows, never assumes.
refresh_panel_addr() {
  local P B
  eval "$(python3 -c "
import json
cfg = json.load(open('$LAB/panel/panel.json'))
print('P=' + str(cfg.get('port', 7777)))
base = str(cfg.get('base_path', ''))
if base and not base.startswith('/'):
    base = '/' + base
print('B=' + base)
" 2>/dev/null)"
  if [ -n "$P" ] && [ "$P" != "$PANEL_PORT" ]; then
    say "panel moved to port $P (was $PANEL_PORT) — following"
    PANEL_PORT=$P
  fi
  [ -n "$B" ] && PANEL_BASE=$B
  PANEL_URL="http://127.0.0.1:$PANEL_PORT$PANEL_BASE"
}
PANEL_URL="http://127.0.0.1:$PANEL_PORT$PANEL_BASE"
say "panel at $PANEL_URL"
refresh_panel_addr   # the panel may have moved after startup
LIVE=""
for i in $(seq 1 30); do
  curl -s -o /dev/null "$PANEL_URL/api/login" && LIVE=1 && break
  sleep 0.5
done
[ "$LIVE" = "1" ] && ok "panel listening at $PANEL_URL" || { bad "panel never listened"; echo "--- panel.log ---"; tail -30 "$LAB/panel.log" 2>/dev/null; exit 1; }
# Re-assert the ACCEPT rules AFTER the panel starts: the panel's own
# startup may add firewall rules that shadow our earlier ACCEPT
# (absorbed from the FRP session's harness fix).
sudo iptables -I INPUT 1 -s 10.200.0.0/24 -j ACCEPT 2>/dev/null
sudo iptables -I INPUT 1 -i $BR -j ACCEPT 2>/dev/null
curl -s -c $LAB/admin.cookies -X POST "$PANEL_URL/api/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$PANEL_PASS\"}" > $LAB/login.json
CSRF=$(python3 -c "import json;print(json.load(open('$LAB/login.json')).get('csrf_token',''))")
[ -n "$CSRF" ] && ok "panel login (admin)" || bad "panel login"

api() { # api METHOD PATH [body] — prints the response body, logs the code
  local m=$1 p=$2 b=${3:-}
  local out code
  # The CSRF header is required on EVERY mutating call — bodyless POSTs
  # (e.g. agents/{id}/push) were silently rejected without it.
  if [ -n "$b" ]; then
    out=$(curl -s -b $LAB/admin.cookies -X "$m" "$PANEL_URL$p" \
      -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' -d "$b" \
      -w $'\n%{http_code}')
  else
    out=$(curl -s -b $LAB/admin.cookies -X "$m" "$PANEL_URL$p" \
      -H "X-CSRF-Token: $CSRF" \
      -w $'\n%{http_code}')
  fi
  code=${out##*$'\n'}
  echo "$m $p http=$code" >> $LAB/api.log
  echo "${out%$'\n'*}"
}
# jq_get FILE EXPR parses FILE; jq_get EXPR (one arg) parses stdin — both
# call conventions exist in this script, and under `set -u` a missing $2
# used to abort the whole expression (every pipe-form call returned "").
jq_get() {
  if [ "$#" -ge 2 ]; then
    python3 -c "import json,sys;d=json.load(open(sys.argv[1]));print(eval(sys.argv[2]))" "$1" "$2" 2>/dev/null || echo ""
  else
    JS="$(cat)"
    python3 -c "import json,sys;d=json.loads(sys.argv[1]);print(eval(sys.argv[2]))" "$JS" "$1" 2>/dev/null || echo ""
  fi
}

# 3. mesh configuration ------------------------------------------------------
say "configuring the mesh (2 iran DCs, 1 foreign DC, 6 servers)..."
api POST /api/mesh/datacenters '{"name":"Drak","kind":"iran","price_coefficient":1.0}' >/dev/null
api POST /api/mesh/datacenters '{"name":"Chekavak","kind":"iran","price_coefficient":1.5}' >/dev/null
api POST /api/mesh/datacenters '{"name":"Hetzner Germany","kind":"foreign","price_coefficient":1.0}' >/dev/null
DC_RAW=$(api GET /api/mesh/datacenters)
echo "[e2e] DC_RAW=${DC_RAW:0:200}"
DC_DRAK=$(echo "$DC_RAW" | jq_get "[d['id'] for d in d['datacenters'] if d['name']=='Drak'][0]")
DC_HZ=$(echo "$DC_RAW" | jq_get "[d['id'] for d in d['datacenters'] if d['name']=='Hetzner Germany'][0]")
[ -n "$DC_DRAK" ] && [ -n "$DC_HZ" ] && ok "datacenters created ($DC_DRAK/$DC_HZ)" || bad "datacenters ($DC_DRAK/$DC_HZ)"

declare -A SRV_ID
declare -A SRV_IP
mkserver() { # name role dcid ip
  api POST /api/mesh/servers "{\"name\":\"$1\",\"role\":\"$2\",\"datacenter_id\":$3,\"address\":\"$4\"}" > $LAB/srv-tmp.json
  SRV_ID[$1]=$(jq_get $LAB/srv-tmp.json "d['id']")
  SRV_IP[$1]=$4
  if [ -z "${SRV_ID[$1]}" ]; then bad "server $1 creation returned no id"; fi
}
mkserver ir-drak-1 iran "$DC_DRAK" ${IP_IRAN[0]}
mkserver ir-drak-2 iran "$DC_DRAK" ${IP_IRAN[1]}
mkserver ir-chk-1 iran "$DC_DRAK" ${IP_IRAN[2]}
mkserver ir-chk-2 iran "$DC_DRAK" ${IP_IRAN[3]}
mkserver hz-fra-1 foreign "$DC_HZ" ${IP_FOREIGN[0]}
mkserver hz-fra-2 foreign "$DC_HZ" ${IP_FOREIGN[1]}
ok "6 servers registered"

# lab engine_params per SLOT: the fake slot points at the remote
# server's lab IP (filled per pair below via two generate calls, one per
# iran server so the remote IP is known at generate time).
GEN1=$(api POST /api/mesh/topologies/generate "{
  \"name\":\"drak-hz\",
  \"iran_servers\":[${SRV_ID[ir-drak-1]},${SRV_ID[ir-drak-2]}],
  \"foreign_servers\":[${SRV_ID[hz-fra-1]},${SRV_ID[hz-fra-2]}],
  \"tunnels_per_pair\":2,\"engines\":[\"matrix\",\"fake\"],\"enabled\":true}")
GEN2=$(api POST /api/mesh/topologies/generate "{
  \"name\":\"chekavak-hz\",
  \"iran_servers\":[${SRV_ID[ir-chk-1]},${SRV_ID[ir-chk-2]}],
  \"foreign_servers\":[${SRV_ID[hz-fra-1]},${SRV_ID[hz-fra-2]}],
  \"tunnels_per_pair\":2,\"engines\":[\"matrix\",\"fake\"],\"enabled\":true}")
echo "$GEN1" > $LAB/gen1.json
TOPO1=$(jq_get $LAB/gen1.json "d['topology_id']")
N1=$(jq_get $LAB/gen1.json "len(d['tunnels'])")
[ "$N1" = "8" ] && ok "drak-hz generated (2x2x2=8 tunnels)" || bad "drak-hz generated ($N1 tunnels) raw=$GEN1 && tail -12 $LAB/api.log 2>/dev/null"

# The panel's default failover policy is SwitchBackS=300 (a 300-second
# sticky-away before a recovered target is re-admitted). The balancer
# honors it correctly — but these sections test the MECHANICS (failure
# detection, exclusion, re-admission), so the lab topologies opt out of
# the sticky window; the sticky-away semantics are covered hermetically
# by TestBalancerSwitchBackStickyAway.
TOPO1_ID=$(jq_get $LAB/gen1.json "d['topology_id']")
api PATCH "/api/mesh/topologies/$TOPO1_ID" '{"failover":{"switch_back_s":0}}' > /dev/null
refresh_panel_addr   # follow the panel port before every HTTP phase
# Patch every fake tunnel's engine_params with its remote server's lab IP.
# A short settle after the config burst: the panel rejects a connection
# outright (RST) for a moment right after the generate storm.
sleep 2
# The panel serves everything under its randomized base path — without it
# every call here 404s (the whole forward-traffic chain hangs off this).
python3 - "$PANEL_PORT" "$PANEL_BASE" "$LAB/admin.cookies" "$CSRF" "$SINK_PORT" <<'PYEOF'
import json, sys, time, traceback, urllib.request, urllib.error

port, base, jar, csrf, sink = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])

# admin.cookies is a curl Netscape jar (curl -c): raw contents are NOT a
# Cookie header. Parse the jar the way curl -b does. HttpOnly cookies are
# stored as "#HttpOnly_..." lines — they are data, not comments.
cookie = ""
for line in open(jar):
    if line.startswith("#HttpOnly_"):
        line = line[len("#HttpOnly_"):]
    elif line.startswith("#") or not line.strip():
        continue
    parts = line.rstrip("\n").split("\t")
    if len(parts) >= 7:
        cookie += f"{parts[5]}={parts[6]}; "

def call(method, path, body=None, retries=6):
    req_body = None
    if body is not None:
        req_body = json.dumps(body).encode()
    last = None
    for attempt in range(retries):
        req = urllib.request.Request(f"http://127.0.0.1:{port}{base}{path}", method=method)
        req.add_header("Cookie", cookie.rstrip("; "))
        req.add_header("X-CSRF-Token", csrf)
        if req_body is not None:
            req.add_header("Content-Type", "application/json")
        try:
            return json.load(urllib.request.urlopen(req, req_body))
        except urllib.error.HTTPError as e:
            print(f"api {method} {path} -> HTTP {e.code}: {e.read()[:300]!r}", file=sys.stderr)
            raise
        except Exception as e:
            # Transient infra noise (one-off connection reset during the
            # panel's startup churn): retry, never mask a real failure.
            last = e
            import subprocess
            probe = subprocess.run(["sh", "-c",
                "(timeout 2 tcpdump -i lo -nn -c 6 'tcp port " + str(port) + "' 2>/dev/null &"
                " sleep 0.3; curl -s -o /dev/null -w 'curl-code=%{http_code}\\n' -X PATCH"
                f" --max-time 1 http://127.0.0.1:{port}{base}{path} 2>&1 | tail -1) ;"
                " wait"],
                capture_output=True, text=True)
            print(f"[refused-diag] attempt {attempt}: {e!r}\n wire: {probe.stdout!r}", file=sys.stderr)
            time.sleep(1.0 * (attempt + 1))
    print(f"api {method} {path} failed after {retries} attempts: {last!r}", file=sys.stderr)
    traceback.print_exc()
    raise last

servers_raw = call("GET", "/api/mesh/servers")["servers"]
servers = {s["name"]: s["address"] for s in servers_raw}
servers_by_id = {s["id"]: s for s in servers_raw}
# Phase 5: each fake tunnel gets its OWN sink port — N tunnels converge
# on one foreign host and the lab engine binds 0.0.0.0:<lab_port> on the
# far end; a shared port let only the first bind (the Phase-4 100/0
# artifact). The balancer's per-target-port nft map needs exactly this.
patched = 0
sink_ports = {}
for tname in ("drak-hz", "chekavak-hz"):
    topos = call("GET", "/api/mesh/topologies")["topologies"]
    topo = [t for t in topos if t["name"] == tname][0]
    full = call("GET", f"/api/mesh/topologies/{topo['id']}")
    for t in full.get("tunnels", []):
        if t["engine"] != "fake":
            continue
        rs = servers_by_id.get(t["remote_server_id"])  # tunnels carry ids, not names
        rip = servers.get(rs["name"], "") if rs else ""
        if not rip:
            continue
        # A DISTINCT local name — `port` here would shadow the PANEL port
        # variable the call() closure uses (the Phase-5 "connection
        # refused" hunt: every PATCH after the first GET was hitting the
        # sink port on the host netns, where nothing listens).
        sport = sink + patched
        sink_ports[t["tunnel_key"]] = sport
        call("PATCH", f"/api/mesh/tunnels/{t['id']}",
             {"engine_params": {"lab_addr": rip, "lab_port": sport}})
        patched += 1
with open("/tmp/quantum-e2e/sink_ports.json", "w") as fh:
    json.dump(sink_ports, fh)
print(f"patched {patched} fake tunnels (distinct sink ports)")
PYEOF
check $? "fake tunnel engine_params patched (distinct per-tunnel sink ports)"

# 4. enroll + link 6 real agents --------------------------------------------
say "enrolling 6 real agents..."
for i in "${!NS_ALL[@]}"; do
  ns=${NS_ALL[$i]}; name=${ns#q-}; ipaddr=${IP_ALL[$i]}
  role=iran; case "$ns" in *fra*) role=foreign;; esac
  sid=${SRV_ID[$name]}
  api POST /api/agents/tokens "{\"role\":\"$role\",\"label\":\"$name\",\"expires_days\":1}" > $LAB/tok-tmp.json
  tok=$(jq_get $LAB/tok-tmp.json "d['token']")
  # The enroll URL MUST carry the panel's base path (the real panel
  # randomizes it) — and the panel IP is reachable from every netns via
  # the bridge gateway.
  sudo ip netns exec "$ns" env GRE_PANEL_DIR=$LAB/agents/$name \
    $LAB/quantum-agent enroll --server "http://$PANEL_IP:$PANEL_PORT$PANEL_BASE" --token "$tok" --name "$name" \
    > "$LAB/enroll-$name.log" 2>&1
  aid=$(sudo ip netns exec "$ns" env GRE_PANEL_DIR=$LAB/agents/$name \
    $LAB/quantum-agent status 2>/dev/null | jq_get "d['id']" 2>/dev/null)
  if [ -z "$aid" ]; then
    bad "agent $name enroll failed"
    echo "[e2e] enroll-$name log: $(tail -3 "$LAB/enroll-$name.log" 2>/dev/null)"
    continue
  fi
  api POST /api/mesh/agents/$aid/link "{\"server_id\":$sid}" >/dev/null
done
api GET /api/mesh/agents > $LAB/agents.json
AGENTS=$(jq_get $LAB/agents.json "json.dumps(d['agents'])")
N_AGENTS=$(echo "$AGENTS" | jq_get "len(d)")
[ "$N_AGENTS" = "6" ] && ok "6 agents enrolled + linked" || bad "agents enrolled ($N_AGENTS/6)"

# 5. run the real agents ------------------------------------------------------
say "starting 6 real agents..."
for i in "${!NS_ALL[@]}"; do
  ns=${NS_ALL[$i]}; name=${ns#q-}
  sudo ip netns exec "$ns" env GRE_PANEL_DIR=$LAB/agents/$name QUANTUM_ENGINES_LAB=fake \
    $LAB/quantum-agent run > "$LAB/run-$name.log" 2>&1 &
  AGENT_PIDS="$AGENT_PIDS $!"
done
sleep 4
agentTestWait() { # desc seconds command...
  local desc=$1 secs=$2; shift 2
  local deadline=$(( $(date +%s) + secs ))
  while [ $(date +%s) -lt $deadline ]; do
    if "$@"; then return 0; fi
    sleep 0.5
  done
  return 1
}
# Re-fetch: the agents just connected and negotiated — the stale list
# from enrollment time still shows proto_version 0.
wait_v2() {
  api GET /api/mesh/agents > $LAB/agents.json
  AGENTS=$(jq_get $LAB/agents.json "json.dumps(d['agents'])")
  [ "$(echo "$AGENTS" | jq_get "sum(1 for a in d if a.get('proto_version',0)>=2)")" = "6" ]
}
if agentTestWait "v2 negotiation" 20 wait_v2; then
  ok "v2 negotiated on all 6 agents"
else
  api GET /api/mesh/agents > $LAB/agents.json
  AGENTS=$(jq_get $LAB/agents.json "json.dumps(d['agents'])")
  bad "v2 negotiated ($(echo "$AGENTS" | jq_get "sum(1 for a in d if a.get('proto_version',0)>=2)")/6)"
  for ns in "${NS_ALL[@]}"; do
    nm=${ns#q-}
    echo "[e2e] run-$nm: $(tail -3 "$LAB/run-$nm.log" 2>/dev/null)"
  done
fi

# 6. push DesiredV2 to every agent -------------------------------------------
say "pushing DesiredV2 to every agent..."
for aid in $(echo "$AGENTS" | jq_get "'\n'.join(a['id'] for a in d)"); do
  api POST /api/mesh/agents/$aid/push > "$LAB/push-$aid.json" 2>/dev/null
done
sleep 3
# fake sinks listening on the foreign agents: each fake tunnel owns a
# DISTINCT sink port (SINK_PORT + tunnel index), and each foreign ns
# hosts one sink per iran server (2 topologies × 2 iran servers = 4).
SINKS=0
for ns in "${NS_FOREIGN[@]}"; do
  cnt=$(sudo ip netns exec "$ns" ss -tln 2>/dev/null | awk '{print $4}' \
        | grep -oE '[0-9]+$' | awk -v lo="$SINK_PORT" '$1>=lo && $1<lo+20' | wc -l)
  [ "$cnt" -ge 2 ] && SINKS=$((SINKS+1))
done
[ "$SINKS" = "2" ] && ok "fake sinks listening on both foreign agents (per-tunnel ports)" || bad "fake sinks ($SINKS/2)"

AG_DRAK1=$(echo "$AGENTS" | jq_get "[a['id'] for a in d if a['name']=='ir-drak-1'][0]")
refresh_panel_addr

# 7. forward rule + measured weighted split ----------------------------------
say "forward rule + measured weighted split..."
# Cross-netns reachability precheck (the agent's probe path, no DNAT):
# bisects "firewall/routing broken" from "DNAT-specific".
P1_PORT=$(jq_get $LAB/sink_ports.json "d['tun-drak-hz-ir-drak-1-hz-fra-1-b']")
P1_PORT=${P1_PORT:-$SINK_PORT}
P2_PORT=$(jq_get $LAB/sink_ports.json "d['tun-drak-hz-ir-drak-1-hz-fra-2-b']")
P2_PORT=${P2_PORT:-$SINK_PORT}
if sudo ip netns exec q-ir-drak-1 bash -c "printf 'precheck\n' | timeout 3 nc -q1 ${IP_FOREIGN[0]} $P1_PORT" 2>/dev/null; then
  ok "cross-netns TCP to the hz-fra-1 sink works (direct, no DNAT)"
else
  bad "cross-netns TCP to the hz-fra-1 sink BLOCKED (direct, no DNAT) — probes and forwards cannot work"
fi
api POST /api/mesh/forwards "{\"topology_id\":$TOPO1,\"local_server_id\":${SRV_ID[ir-drak-1]},\"listen_port\":$FWD_LISTEN,\"proto\":\"tcp\",\"enabled\":true}" >/dev/null
# Phase 5: actually SET the weights (the old harness only claimed 70/30).
api POST /api/mesh/topologies/$TOPO1/weights "{\"local_server_id\":${SRV_ID[ir-drak-1]},\"remote_server_id\":${SRV_ID[hz-fra-1]},\"weight\":70}" >/dev/null
api POST /api/mesh/topologies/$TOPO1/weights "{\"local_server_id\":${SRV_ID[ir-drak-1]},\"remote_server_id\":${SRV_ID[hz-fra-2]},\"weight\":30}" >/dev/null
api POST /api/mesh/agents/$AG_DRAK1/push >/dev/null
sleep 3
# The agent's rendered nft map must carry both targets with 70/30 ranges
# (verified directly against the KERNEL ruleset, not the panel API).
IP_HZ1=${IP_FOREIGN[0]}; IP_HZ2=${IP_FOREIGN[1]}
sleep 2
nft_map() { sudo ip netns exec q-ir-drak-1 nft list table ip quantum-fwd 2>/dev/null; }
NFT_MAP=$(nft_map)
if echo "$NFT_MAP" | grep -q "$IP_HZ1" && echo "$NFT_MAP" | grep -q "$IP_HZ2"; then
  ok "nft map carries both foreign targets (kernel ruleset)"
else
  bad "nft map missing a target: $(echo "$NFT_MAP" | grep dnat | head -2)"
fi
N_CONN=10000
# Fixed-size payloads (65 bytes each): the byte-based per-tunnel split
# equals the connection split exactly.
# ONE threaded python process on the host — an xargs+nc fork storm cost
# 30+ minutes on WSL (20k forks) and the usage reads landed mid-storm.
send_conns() { # send_conns COUNT — parallel NEW connections to the forward listen port
  python3 - "$1" "$FWD_LISTEN" <<'PYEOF'
import socket, sys, concurrent.futures
count, port = int(sys.argv[1]), int(sys.argv[2])
def one(i):
    try:
        s = socket.create_connection(("10.200.0.11", port), timeout=3)
        s.sendall(b"%064d\n" % i)
        s.close()
        return 1
    except Exception:
        return 0
ok = 0
with concurrent.futures.ThreadPoolExecutor(64) as ex:
    ok = sum(ex.map(one, range(count)))
print(f"connect_ok={ok}/{count}", file=sys.stderr)
PYEOF
}
# Delivered traffic + weighted split: the lab engines count received bytes
# themselves (the payload counters behind the usage API), per tunnel —
# each ir-drak-1 fake tunnel targets one foreign server, so the byte
# delta between the two = the measured split.
# The counters reach the store only on the NEXT heartbeat (30 s cadence,
# 5 s sample throttle) — the harness polls, never assumes.
wait_usage() { # wait_usage BEFORE_SNAPSHOT — poll until the totals grow past
  # the snapshot AND then hold STILL across one full heartbeat cadence.
  # The counters reach the store on the NEXT heartbeat (30 s cadence, 5 s
  # sample throttle); the first growth-carrying heartbeat can hold a
  # mid-send partial window, and one agent's heartbeat can lag another's by
  # a full cadence (phase16: 12/88 and 0/100 splits measured on lagging
  # store counters while the kernel map was verifiably correct). Polling
  # to stability measures the TRUE final split; a genuinely broken split
  # stays broken across samples, so this cannot mask a real failure.
  local before="$1" deadline=$(( $(date +%s) + 150 )) sum prev="" grew=0
  while [ $(date +%s) -lt $deadline ]; do
    sum=$(fake_tunnel_usage | tr ' ' '\n' | cut -d: -f2 | tr -cd 0-9)
    if [ -n "$sum" ] && [ "$sum" -gt "$before" ]; then
      grew=1
      if [ -n "$prev" ] && [ "$sum" = "$prev" ]; then
        return 0 # unchanged across a 31 s gap: the window is complete
      fi
      prev=$sum
      sleep 31
      continue
    fi
    sleep 3
  done
  [ "$grew" = "1" ] && return 0
  return 1
}
# AGENT-23 diagnostics (test-only, never verdict-affecting): ground-truth
# probes for the distribution-leg "0 of 0" flake. The store view
# (fake_tunnel_usage) is the MEASUREMENT; these probes read the OTHER two
# observation points of the same counter chain so a 0-delta run can say
# WHERE it died:
#   diag_agents_runtime — the panel's LIVE per-agent heartbeat view
#     (/api/mesh/agents → runtime[]: the last report's counters). Grows
#     while the store does not → the sample-write path; stale/missing →
#     the agent stopped heartbeating or the session died.
#   diag_store_windows — the store's payload_rx for the same tunnels over
#     (0,now] AND (from_ts,now]: distinguishes "no new samples at all"
#     from "samples exist but the summed deltas are zero".
diag_log() { diag_log_ts=$(date +%s); echo "[diag $diag_log_ts] $*" >> "$LAB/dist-diag.log"; }
diag_agents_runtime() { # diag_agents_runtime KEY_SUBSTR
python3 - "$PANEL_PORT" "$PANEL_BASE" "$LAB/admin.cookies" "$CSRF" "$1" <<'PYEOF'
import json, sys, urllib.request
port, base, jar, csrf, key = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
cookie = ""
for line in open(jar):
    if line.startswith("#HttpOnly_"):
        line = line[len("#HttpOnly_"):]
    elif line.startswith("#") or not line.strip():
        continue
    parts = line.rstrip("\n").split("\t")
    if len(parts) >= 7:
        cookie += f"{parts[5]}={parts[6]}; "
req = urllib.request.Request(f"http://127.0.0.1:{port}{base}/api/mesh/agents")
req.add_header("Cookie", cookie.rstrip("; "))
req.add_header("X-CSRF-Token", csrf)
for a in json.load(urllib.request.urlopen(req))["agents"]:
    rt = a.get("runtime") or []
    if not rt:
        print(f"agent={a['id']} status={a.get('status')} last_seen={a.get('last_seen')} runtime=NONE")
        continue
    for r in rt:
        if key in r.get("tunnel_id", ""):
            print(f"agent={a['id']} status={a.get('status')} last_seen={a.get('last_seen')} "
                  f"tunnel={r.get('tunnel_id')} up={r.get('up')} prx={r.get('payload_rx', 0)} "
                  f"pknown={r.get('payload_known')} wknown={r.get('wire_known')} err={r.get('last_error', '')}")
PYEOF
}
diag_store_windows() { # diag_store_windows FROM_TS KEY_SUBSTR
python3 - "$PANEL_PORT" "$PANEL_BASE" "$LAB/admin.cookies" "$CSRF" "$1" "$2" <<'PYEOF'
import json, sys, urllib.request
port, base, jar, csrf = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
from_ts, key = sys.argv[5], sys.argv[6]
cookie = ""
for line in open(jar):
    if line.startswith("#HttpOnly_"):
        line = line[len("#HttpOnly_"):]
    elif line.startswith("#") or not line.strip():
        continue
    parts = line.rstrip("\n").split("\t")
    if len(parts) >= 7:
        cookie += f"{parts[5]}={parts[6]}; "
def call(path):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{base}{path}")
    req.add_header("Cookie", cookie.rstrip("; "))
    req.add_header("X-CSRF-Token", csrf)
    return json.load(urllib.request.urlopen(req))
topo = [t for t in call("/api/mesh/topologies")["topologies"] if t["name"] == "drak-hz"][0]
full = call(f"/api/mesh/topologies/{topo['id']}")
for t in full.get("tunnels", []):
    if t["engine"] == "fake" and key in t["tunnel_key"]:
        all_u = call(f"/api/mesh/usage?tunnel_id={t['id']}")["usage"]
        try:
            win_u = call(f"/api/mesh/usage?tunnel_id={t['id']}&from={from_ts}")["usage"]
            win = win_u.get("payload_rx", 0)
        except Exception as e:
            win = f"ERR({e})"
        print(f"tunnel={t['tunnel_key']} all_prx={all_u.get('payload_rx', 0)} "
              f"window_prx={win} window_from={from_ts}")
PYEOF
}
dist_sink_probe() { # dist_sink_probe — the decisive chain test, run ONLY
  # on a failed distribution verdict: push 1000 bytes straight into each
  # sink (bypassing the balancer map entirely), wait across two full
  # heartbeats, then read the store windows again. A store view that grew
  # by the probe bytes proves the sink-counting → agent-heartbeat →
  # panel-sample-write chain WORKS (so the failure was delivery: the
  # balancer path); a still store view proves the CHAIN itself broke
  # panel-side (or agent-side reporting) — evidence for the architect.
  local p1 p2 ts
  p1=$(jq_get $LAB/sink_ports.json "d.get('tun-drak-hz-ir-drak-1-hz-fra-1-b', 0)")
  p2=$(jq_get $LAB/sink_ports.json "d.get('tun-drak-hz-ir-drak-1-hz-fra-2-b', 0)")
  ts=$(date +%s)
  diag_log "sink probe: direct 1000B → 10.200.0.21:$p1 (hz-fra-1-b) and 10.200.0.22:$p2 (hz-fra-2-b) at $ts"
  python3 - "$p1" "$p2" <<'PYEOF'
import socket, sys
for name, ip, port in (("hz-fra-1-b", "10.200.0.21", int(sys.argv[1])),
                       ("hz-fra-2-b", "10.200.0.22", int(sys.argv[2]))):
    try:
        s = socket.create_connection((ip, port), timeout=3)
        s.sendall(b"P" * 1000)
        s.close()
        print(f"probe {name} {ip}:{port}: sent 1000B")
    except Exception as e:
        print(f"probe {name} {ip}:{port}: FAILED: {e}")
PYEOF
  sleep 95 # > two 30 s heartbeats + margin — the probe bytes MUST surface
  diag_log "sink probe store windows after 95s (expect +1000 per tunnel when the chain works):"
  diag_store_windows "$ts" ir-drak-1
  diag_log "sink probe live agent view after 95s:"
  diag_agents_runtime ir-drak-1
}
wait_usage_diag() { # wait_usage_diag BEFORE FROM_TS — wait_usage's poll
  # semantics verbatim, plus a probe trail: every ~15 s it appends the
  # store view AND the live agent view to $LAB/dist-diag.log, so a 0-delta
  # run records whether the agents kept heartbeating and what their last
  # reported counters were while the store stayed still.
  local before="$1" from_ts="$2" deadline=$(( $(date +%s) + 150 )) sum prev="" grew=0 polls=0
  while [ $(date +%s) -lt $deadline ]; do
    sum=$(fake_tunnel_usage | tr ' ' '\n' | cut -d: -f2 | tr -cd 0-9)
    polls=$((polls+1))
    if [ -n "$sum" ] && [ "$sum" -gt "$before" ]; then
      grew=1
      if [ -n "$prev" ] && [ "$sum" = "$prev" ]; then
        diag_log "poll=$polls sum=$sum STABLE (window complete)"
        return 0 # unchanged across a 31 s gap: the window is complete
      fi
      diag_log "poll=$polls sum=$sum GREW (prev=${prev:-none})"
      prev=$sum
      sleep 31
      continue
    fi
    if [ $((polls % 5)) = "0" ]; then
      diag_log "poll=$polls sum=${sum:-EMPTY} still<=before=$before; live agent view:"
      diag_agents_runtime ir-drak-1 >> "$LAB/dist-diag.log" 2>&1
      diag_store_windows "$from_ts" ir-drak-1 >> "$LAB/dist-diag.log" 2>&1
    fi
    sleep 3
  done
  diag_log "TIMEOUT after 150s grew=$grew — final live agent view:"
  diag_agents_runtime ir-drak-1 >> "$LAB/dist-diag.log" 2>&1
  diag_store_windows "$from_ts" ir-drak-1 >> "$LAB/dist-diag.log" 2>&1
  [ "$grew" = "1" ] && return 0
  return 1
}
fake_tunnel_usage() { # → "tunnel_key:payload_rx ..." for ir-drak-1's fake tunnels
python3 - "$PANEL_PORT" "$PANEL_BASE" "$LAB/admin.cookies" "$CSRF" <<'PYEOF'
import json, sys, urllib.request
port, base, jar, csrf = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
cookie = ""
for line in open(jar):
    if line.startswith("#HttpOnly_"):
        line = line[len("#HttpOnly_"):]
    elif line.startswith("#") or not line.strip():
        continue
    parts = line.rstrip("\n").split("\t")
    if len(parts) >= 7:
        cookie += f"{parts[5]}={parts[6]}; "
def call(path):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{base}{path}")
    req.add_header("Cookie", cookie.rstrip("; "))
    req.add_header("X-CSRF-Token", csrf)
    return json.load(urllib.request.urlopen(req))
topo = [t for t in call("/api/mesh/topologies")["topologies"] if t["name"] == "drak-hz"][0]
full = call(f"/api/mesh/topologies/{topo['id']}")
out = []
for t in full.get("tunnels", []):
    if t["engine"] == "fake" and "ir-drak-1" in t["tunnel_key"]:
        u = call(f"/api/mesh/usage?tunnel_id={t['id']}")["usage"]
        out.append(f"{t['tunnel_key']}:{u['payload_rx']}")
print(" ".join(out))
PYEOF
}
comm_delta() { # comm_delta AFTER BEFORE KEY — one tunnel's payload byte delta
  local a b
  a=$(echo "$1" | tr ' ' '\n' | grep "$3" | cut -d: -f2 | tr -cd 0-9)
  b=$(echo "$2" | tr ' ' '\n' | grep "$3" | cut -d: -f2 | tr -cd 0-9)
  echo $(( ${a:-0} - ${b:-0} ))
}
SPLIT_BEFORE=$(fake_tunnel_usage)
send_conns $N_CONN
wait_usage "$(echo "$SPLIT_BEFORE" | tr ' ' '\n' | cut -d: -f2 | tr -cd 0-9)" || true
SPLIT_AFTER=$(fake_tunnel_usage)
# Per-tunnel delta (hz-fra-1's tunnel vs hz-fra-2's tunnel).
B1=$(echo "$SPLIT_BEFORE" | tr ' ' '\n' | grep 'hz-fra-1' | cut -d: -f2 | tr -cd 0-9); B1=${B1:-0}
A1=$(echo "$SPLIT_AFTER"  | tr ' ' '\n' | grep 'hz-fra-1' | cut -d: -f2 | tr -cd 0-9); A1=${A1:-0}
B2=$(echo "$SPLIT_BEFORE" | tr ' ' '\n' | grep 'hz-fra-2' | cut -d: -f2 | tr -cd 0-9); B2=${B2:-0}
A2=$(echo "$SPLIT_AFTER"  | tr ' ' '\n' | grep 'hz-fra-2' | cut -d: -f2 | tr -cd 0-9); A2=${A2:-0}
C1=$((A1-B1)); C2=$((A2-B2)); TOTAL=$((C1+C2))
[ "$TOTAL" -ge $((N_CONN*60/100)) ] && ok "forwarded traffic flows ($TOTAL/$((N_CONN*65)) payload bytes delivered)" || bad "forwarded traffic ($TOTAL bytes)"
# ±2 percentage points against the configured 70/30 (the documented
# acceptance tolerance for 10k NEW connections).
P1=$((C1*100/(TOTAL>0?TOTAL:1))); P2=$((C2*100/(TOTAL>0?TOTAL:1)))
say "measured split: hz-fra-1=$C1 bytes (${P1}%) hz-fra-2=$C2 bytes (${P2}%) — desired 70/30"
if [ "$TOTAL" -gt 0 ] && [ "$P1" -ge 68 ] && [ "$P1" -le 72 ]; then
  ok "weighted split within ±2pp of 70/30 (${P1}%/${P2}%)"
else
  bad "weighted split outside ±2pp of 70/30 (${P1}%/${P2}%)"
fi

# 8. tunnel failover — REAL failure injection --------------------------------
# The lab engine's sink IS the tunnel's far end, and the agent's near-end
# health probe dials it. Dropping the path between the iran agent and
# that sink port (scoped iptables rules INSIDE the iran test namespace)
# kills both the probe and the forwarded traffic — a faithful tunnel
# death, unlike the old kill-nc no-op.
say "tunnel failover (path to hz-fra-1's sink blocked)..."
P1_PORT=$(jq_get $LAB/sink_ports.json "d['tun-drak-hz-ir-drak-1-hz-fra-1-b']")
P1_PORT=${P1_PORT:-$SINK_PORT}
block_target() { # block_target NETNS IP [PORT] — scoped: that ns, that dst only
  local ns=$1 ip=$2 port=${3:-}
  if [ -n "$port" ]; then
    sudo ip netns exec "$ns" iptables -I OUTPUT 1 -d "$ip" -p tcp --dport "$port" -j DROP 2>/dev/null
    sudo ip netns exec "$ns" iptables -I FORWARD 1 -d "$ip" -p tcp --dport "$port" -j DROP 2>/dev/null
  else
    sudo ip netns exec "$ns" iptables -I OUTPUT 1 -d "$ip" -j DROP 2>/dev/null
    sudo ip netns exec "$ns" iptables -I FORWARD 1 -d "$ip" -j DROP 2>/dev/null
  fi
}
unblock_target() {
  local ns=$1 ip=$2 port=${3:-}
  if [ -n "$port" ]; then
    sudo ip netns exec "$ns" iptables -D OUTPUT -d "$ip" -p tcp --dport "$port" -j DROP 2>/dev/null
    sudo ip netns exec "$ns" iptables -D FORWARD -d "$ip" -p tcp --dport "$port" -j DROP 2>/dev/null
  else
    sudo ip netns exec "$ns" iptables -D OUTPUT -d "$ip" -j DROP 2>/dev/null
    sudo ip netns exec "$ns" iptables -D FORWARD -d "$ip" -j DROP 2>/dev/null
  fi
}
# Cleanup guard: every injected rule is removed on exit whatever happens.
cleanup_injection() {
  unblock_target q-ir-drak-1 "$IP_HZ1"
  unblock_target q-ir-drak-1 "$IP_HZ2"
}
trap cleanup_injection EXIT

T0=$(date +%s.%N)
# Precondition: the dnat map must be live BEFORE the injection — "the
# target vanished" means nothing if it was never rendered.
if ! nft_map | grep -q "dnat"; then bad "precondition: no dnat rendered before the failover injection"; fi
# The injection MUST provably install: a silently-failing block would
# make "the target did not vanish" meaningless (Phase-5 report UNVERIFIED
# item: the port-scoped rules were swallowed by 2>/dev/null).
block_target q-ir-drak-1 "$IP_HZ1" "$P1_PORT"
if sudo ip netns exec q-ir-drak-1 iptables -C OUTPUT -d "$IP_HZ1" -p tcp --dport "$P1_PORT" -j DROP 2>/dev/null \
   && sudo ip netns exec q-ir-drak-1 iptables -C FORWARD -d "$IP_HZ1" -p tcp --dport "$P1_PORT" -j DROP 2>/dev/null; then
  ok "port-scoped injection rules verified present (OUTPUT+FORWARD, $IP_HZ1:$P1_PORT)"
else
  bad "port-scoped injection rules NOT installed"
fi
# Detection = the target disappearing from the KERNEL ruleset (the agent
# re-renders on the health flip) while the chain itself still exists.
DETECTED=0
DEADLINE=$(( $(date +%s) + 45 ))
while [ $(date +%s) -lt $DEADLINE ]; do
  if nft_map | grep -q "dnat" && ! nft_map | grep -q "$IP_HZ1"; then DETECTED=1; break; fi
  sleep 0.3
done
T1=$(date +%s.%N)
DT=$(python3 -c "print(f'{$T1-$T0:.1f}')")
if [ "$DETECTED" = "1" ]; then ok "tunnel failover: hz-fra-1 excluded from the nft map in ${DT}s (detection)"; else bad "tunnel failover: hz-fra-1 not excluded within 45s"; fi
FAILOVER_TIME=$DT
# New traffic must now flow to the survivor only. SHORT-BURST STATISTICAL
# NOTE (closes the Phase-5 report's short-burst UNVERIFIED item): with
# n=200 connections the binomial standard error at p=0.7 is
# sqrt(0.7*0.3/200) ≈ 3.2pp — a ±2pp band is statistically meaningless at
# this burst size, so this check asserts DELIVERY only (bytes reached the
# survivor, none the blocked target). Proportional assertions with the
# ±2pp band are made exclusively on the 10,000-connection bursts, where
# σ ≈ 0.45pp.
SB1=$(fake_tunnel_usage)
send_conns 200
wait_usage "$(echo "$SB1" | tr ' ' '\n' | cut -d: -f2 | tr -cd 0-9)" || true
SA1=$(fake_tunnel_usage)
D2=$(comm_delta "$SA1" "$SB1" 'hz-fra-2')
D1=$(comm_delta "$SA1" "$SB1" 'hz-fra-1')
[ "${D2:-0}" -gt 0 ] && [ "${D1:-0}" -eq 0 ] && ok "post-failover traffic 100% to hz-fra-2 (${D2} bytes; hz-fra-1 got ${D1})" || bad "post-failover split: hz-fra-1=${D1:-0} hz-fra-2=${D2:-0}"

# 9. whole foreign server down + failback ------------------------------------
say "whole-server failover + failback..."
# Recover the single-tunnel block first, then take the WHOLE server path
# down (every sink port on hz-fra-1).
unblock_target q-ir-drak-1 "$IP_HZ1" "$P1_PORT"
DEADLINE=$(( $(date +%s) + 45 ))
BACK1=0
while [ $(date +%s) -lt $DEADLINE ]; do
  if nft_map | grep -q "$IP_HZ1"; then BACK1=1; break; fi
  sleep 0.3
done
T0=$(date +%s.%N)
if [ "$BACK1" = "1" ]; then ok "recovered tunnel re-admitted to the nft map (failback)"; else bad "recovered tunnel not re-admitted within 20s"; fi
block_target q-ir-drak-1 "$IP_HZ1"   # the whole server: every port
DETECTED2=0
DEADLINE=$(( $(date +%s) + 45 ))
while [ $(date +%s) -lt $DEADLINE ]; do
  if nft_map | grep -q "dnat" && ! nft_map | grep -q "$IP_HZ1"; then DETECTED2=1; break; fi
  sleep 0.3
done
T1=$(date +%s.%N)
DT2=$(python3 -c "print(f'{$T1-$T0:.1f}')")
if [ "$DETECTED2" = "1" ]; then ok "whole foreign server excluded from the nft map in ${DT2}s"; else bad "whole server not excluded within 45s"; fi
WHOLE_SERVER_TIME=$DT2
# Recovery of the server: traffic returns to the 70/30 split.
T0=$(date +%s.%N)
unblock_target q-ir-drak-1 "$IP_HZ1"
DEADLINE=$(( $(date +%s) + 45 ))
BACK2=0
while [ $(date +%s) -lt $DEADLINE ]; do
  if nft_map | grep -q "$IP_HZ1"; then BACK2=1; break; fi
  sleep 0.3
done
T1=$(date +%s.%N)
DT3=$(python3 -c "print(f'{$T1-$T0:.1f}')")
if [ "$BACK2" = "1" ]; then ok "whole-server recovery re-admitted to the nft map in ${DT3}s"; else bad "whole-server recovery not re-admitted within 20s"; fi
RECOVERY_TIME=$DT3
SB2=$(fake_tunnel_usage)
send_conns 10000
wait_usage "$(echo "$SB2" | tr ' ' '\n' | cut -d: -f2 | tr -cd 0-9)" || true
SA2=$(fake_tunnel_usage)
R1=$(comm_delta "$SA2" "$SB2" 'hz-fra-1'); R2=$(comm_delta "$SA2" "$SB2" 'hz-fra-2')
RT=$(( ${R1:-0} + ${R2:-0} ))
RP1=$(( ${R1:-0} * 100 / (RT>0 ? RT : 1) ))
if [ "$RT" -gt 0 ] && [ "$RP1" -ge 68 ] && [ "$RP1" -le 72 ]; then
  ok "failback split back within ±2pp of 70/30 (${RP1}%/$((100-RP1))% of $RT bytes)"
else
  bad "failback split outside tolerance (hz-fra-1=${R1:-0} hz-fra-2=${R2:-0} of $RT)"
fi

# 9b. all destinations down: the fail-fast pass-through chain ----------------
say "all destinations down..."
block_target q-ir-drak-1 "$IP_HZ1"
block_target q-ir-drak-1 "$IP_HZ2"
DEADLINE=$(( $(date +%s) + 45 ))
ALLDOWN=0
while [ $(date +%s) -lt $DEADLINE ]; do
  if ! nft_map | grep -q "dnat"; then ALLDOWN=1; break; fi
  sleep 0.3
done
if [ "$ALLDOWN" = "1" ]; then ok "all targets down: no dnat rendered (fail-fast pass-through)"; else bad "all-down still renders dnat"; fi
FAILS=0
for i in 1 2 3 4 5; do
  printf "%064d\n" "$i" | timeout 2 nc -q1 -w1 ${IP_IRAN[0]} $FWD_LISTEN >/dev/null 2>&1 || FAILS=$((FAILS+1))
done
[ "$FAILS" -ge 3 ] && ok "all-down: new connections fail fast ($FAILS/5 refused/timeout)" || bad "all-down behavior ($FAILS/5 failed)"
unblock_target q-ir-drak-1 "$IP_HZ1"
unblock_target q-ir-drak-1 "$IP_HZ2"
DEADLINE=$(( $(date +%s) + 45 ))
RECOVERED=0
while [ $(date +%s) -lt $DEADLINE ]; do
  if nft_map | grep -q "dnat"; then RECOVERED=1; break; fi
  sleep 0.3
done
if [ "$RECOVERED" = "1" ]; then ok "all targets recovered: dnat re-rendered"; else bad "all-down recovery missing dnat"; fi

# 10. panel death: traffic + failover keep working ---------------------------
say "panel death..."
# Snapshot per-agent revisions while the panel is still alive — the storm
# criterion compares these against the post-restart state.
refresh_panel_addr
api GET /api/mesh/agents > $LAB/agents-before.json
kill "$PANEL_PID" 2>/dev/null; PANEL_PID=""
wait "$PANEL_PID" 2>/dev/null
sleep 1
# failover WITHOUT the panel: block hz-fra-1's path -> new connections move
T0=$(date +%s.%N)
block_target q-ir-drak-1 "$IP_HZ1"
DEADLINE=$(( $(date +%s) + 45 ))
MOVED2=0
while [ $(date +%s) -lt $DEADLINE ]; do
  if nft_map | grep -q "dnat" && ! nft_map | grep -q "$IP_HZ1"; then MOVED2=1; break; fi
  sleep 0.3
done
T1=$(date +%s.%N)
DT4=$(python3 -c "print(f'{$T1-$T0:.1f}')")
unblock_target q-ir-drak-1 "$IP_HZ1"
if [ "$MOVED2" = "1" ]; then ok "traffic + failover keep working with the panel dead (${DT4}s to re-render)"; else bad "panel-dead failover did not re-render"; fi
DEAD_PANEL_FAILOVER=$MOVED2
PANEL_DEATH_FAILOVER_TIME=$DT4

# 11. panel restart: re-sync without a revision storm -------------------------
say "panel restart..."
# GRE_PANEL_HTTP_BIND: the panel's plain-HTTP listener defaults to
# 127.0.0.1 (cleartext-login hardening) — the netns agents reach the panel
# over the bridge, so this lab needs the documented container/unit escape
# hatch. Scope: this lab run only; the lab subnet is firewalled in above.
export GRE_PANEL_DIR=$LAB/panel GRE_PANEL_PASSWORD=$PANEL_PASS GRE_PANEL_HTTP_BIND=0.0.0.0
$LAB/quantum-panel >> $LAB/panel.log 2>&1 &
PANEL_PID=$!
LIVE=""
for i in $(seq 1 30); do curl -s -o /dev/null "http://127.0.0.1:$PANEL_PORT$PANEL_BASE/api/login" && LIVE=1 && break || sleep 0.5; done
[ "$LIVE" = "1" ] && ok "panel restarted" || bad "panel restart"
curl -s -c $LAB/admin.cookies -X POST "http://127.0.0.1:$PANEL_PORT$PANEL_BASE/api/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$PANEL_PASS\"}" > $LAB/login2.json
CSRF=$(python3 -c "import json;print(json.load(open('$LAB/login2.json')).get('csrf_token',''))")
# agents reconnect; give them time, then compare revision stability
sleep 8
api GET /api/mesh/agents > $LAB/agents-revs.json
REVS=$(python3 -c "
import json
before = {a['id']: a.get('applied_revision','') for a in json.load(open('$LAB/agents-before.json'))['agents']}
after  = {a['id']: a.get('applied_revision','') for a in json.load(open('$LAB/agents-revs.json'))['agents']}
changed = sum(1 for k in after if before.get(k) != after[k] and after[k])
print(changed)" 2>/dev/null)
REVS=${REVS:-ERR}
[ "$REVS" = "0" ] && ok "panel restart: no revision storm (0 revisions changed on reconnect)" || bad "revision storm ($REVS revisions changed)"

# 12. wire/payload counters in the usage API ----------------------------------
refresh_panel_addr
say "usage counters..."
# The usage API needs a scope param and answers {scope, usage:{wire_rx,…}}.
# Query per topology: the store's traffic_samples carry the agent's
# reported wire+payload counters (fake tunnels: wire == payload).
TOPO1_USAGE=$(api GET "/api/mesh/usage?topology_id=$TOPO1")
echo "$TOPO1_USAGE" > /tmp/quantum-e2e/usage.json
USAGE_OK=$(python3 -c "
import json
d = json.load(open('/tmp/quantum-e2e/usage.json'))
u = d.get('usage', {})
print('YES' if (u.get('wire_rx', 0) > 0 or u.get('payload_rx', 0) > 0) else 'NO')" 2>/dev/null)
[ "$USAGE_OK" = "YES" ] && ok "usage API carries real byte counters (wire==payload for fake tunnels)" || bad "usage API counters ($TOPO1_USAGE)"

# 13. weight change enforced on the agent -------------------------------------
say "weight change 70/30 -> 30/70..."
refresh_panel_addr
api POST /api/mesh/topologies/$TOPO1/weights "{\"local_server_id\":${SRV_ID[ir-drak-1]},\"remote_server_id\":${SRV_ID[hz-fra-1]},\"weight\":30}" >/dev/null
api POST /api/mesh/topologies/$TOPO1/weights "{\"local_server_id\":${SRV_ID[ir-drak-1]},\"remote_server_id\":${SRV_ID[hz-fra-2]},\"weight\":70}" >/dev/null
api POST /api/mesh/agents/$AG_DRAK1/push >/dev/null
# The new revision must re-render the KERNEL ruleset (30/70 ranges).
DEADLINE=$(( $(date +%s) + 45 ))
FLIPPED=0
while [ $(date +%s) -lt $DEADLINE ]; do
  # hz-fra-1's range must now be the MINOR share (0-29 for 30%).
  if nft_map | grep -q "0-29 : $IP_HZ1" && nft_map | grep -q "30-99 : $IP_HZ2"; then FLIPPED=1; break; fi
  sleep 0.3
done
if [ "$FLIPPED" = "1" ]; then ok "weight change re-rendered the nft map (30/70 ranges)"; else bad "weight change did not re-render the nft map"; fi
WB=$(fake_tunnel_usage)
WB_TS=$(date +%s)
send_conns 10000
wait_usage_diag "$(echo "$WB" | tr ' ' '\n' | cut -d: -f2 | tr -cd 0-9)" "$WB_TS" || true
WA=$(fake_tunnel_usage)
W1=$(comm_delta "$WA" "$WB" 'hz-fra-1'); W2=$(comm_delta "$WA" "$WB" 'hz-fra-2')
WT=$(( ${W1:-0} + ${W2:-0} ))
WP1=$(( ${W1:-0} * 100 / (WT>0 ? WT : 1) ))
if [ "$WT" -gt 0 ] && [ "$WP1" -ge 28 ] && [ "$WP1" -le 32 ]; then
  ok "distribution followed the weight change (${WP1}%/$((100-WP1))% of $WT bytes — want 30/70)"
else
  bad "distribution did not follow the weight change (hz-fra-1=${W1:-0} hz-fra-2=${W2:-0} of $WT — want ~30/70)"
  # AGENT-23: evidence dump for the "0 of 0" flake. Three observation
  # points of the same counter chain, in order:
  #   1. the store windows + the LIVE agent heartbeat view (what the
  #      agents last REPORTED vs what the store kept),
  #   2. a DIRECT sink probe — 1000 bytes straight into each sink,
  #      bypassing the balancer map entirely, then ~2 heartbeats of store
  #      polling: store grows by the probe bytes → the counter chain
  #      works and the balancer path never delivered; store stays still →
  #      the chain (sink counting → agent heartbeat → panel sample write)
  #      itself broke,
  #   3. the panel/agent logs' tails.
  echo "[e2e] distribution-leg evidence (also in $LAB/dist-diag.log):"
  {
    diag_log "=== failure evidence: measured W1=${W1:-0} W2=${W2:-0} WT=${WT:-0} (WB=$WB / WA=$WA) ==="
    diag_log "--- live agent heartbeat view + store windows (ir-drak-1 tunnels):"
    diag_agents_runtime ir-drak-1
    diag_store_windows "$WB_TS" ir-drak-1
    diag_log "--- direct sink probe (bypasses the balancer map):"
    dist_sink_probe
    diag_log "--- panel.log tail:"
    tail -25 "$LAB/panel.log" 2>/dev/null
    diag_log "--- api.log tail:"
    tail -10 "$LAB/api.log" 2>/dev/null
  } | sed 's/^/[e2e]   /' | tee -a "$LAB/dist-diag.log"
  # Diagnose (never mask): a portless map element (`0-29 : IP . 0`) passes
  # the re-render grep but the kernel no-ops it — conns fall through to
  # the local listener, connect_ok stays 10000, sinks count 0. Dump the
  # live ruleset + the agent's own runtime view for post-mortem.
  echo "[e2e] nft table at failure:"
  nft_map | grep -E 'map|dnat|elements' | head -8 | sed 's/^/[e2e]   /'
  echo "[e2e] agent runtime view:"
  sudo ip netns exec q-ir-drak-1 env GRE_PANEL_DIR=$LAB/agents/ir-drak-1 \
    $LAB/quantum-agent balancer status 2>/dev/null | head -30 | sed 's/^/[e2e]   /'
fi

# verdict ----------------------------------------------------------------------
echo
echo "[e2e] ===== verdict: $PASS passed, $FAIL failed ====="
E2E_RC=$FAIL
# Copy the evidence NOW, not only in the EXIT trap: WSL terminates the
# distro instance when the last client disconnects and the trap has lost
# that race on every phase16 run (e2e-logs stayed 10 days old).
if [ -d "$LAB" ]; then
  LOGDIR="${E2E_LOGS:-$REPO_ROOT/tests/e2e-logs}"
  mkdir -p "$LOGDIR"
  cp -f "$LAB"/run-*.log "$LAB"/panel.log "$LAB"/api.log "$LAB"/enroll-*.log "$LAB"/dist-diag.log "$LOGDIR"/ 2>/dev/null
fi
for f in "${FAILED_CHECKS[@]}"; do echo "[e2e]   FAILED: $f"; done
[ $FAIL -eq 0 ] || exit 1
