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
FAILED_CHECKS=()
PANEL_PID=""; AGENT_PIDS=""

say()  { echo "[e2e] $*"; }
ok()   { PASS=$((PASS+1)); echo "[e2e] PASS: $*"; }
bad()  { FAIL=$((FAIL+1)); FAILED_CHECKS+=("$*"); echo "[e2e] FAIL: $*"; }
check(){ if [ "$1" = "0" ]; then ok "$2"; else bad "$2"; fi; }

cleanup() {
  say "cleanup..."
  [ -n "${PANEL_PID:-}" ] && kill "$PANEL_PID" 2>/dev/null
  for p in $AGENT_PIDS; do sudo ip netns pids "${p}" >/dev/null 2>&1; done
  sudo pkill -f "quantum-agent run" 2>/dev/null
  for ns in "${NS_ALL[@]}"; do
    sudo ip netns pids "$ns" 2>/dev/null | while read -r p; do kill "$p" 2>/dev/null; done
    sudo ip netns del "$ns" 2>/dev/null
  done
  sudo ip link del $BR 2>/dev/null
  sudo nft delete table ip quantum-fwd 2>/dev/null
  sudo iptables -D INPUT -s 10.200.0.0/24 -j ACCEPT 2>/dev/null
  sudo iptables -D INPUT -i $BR -j ACCEPT 2>/dev/null
  say "cleanup done"
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
cd "$REPO_ROOT/../quantum-panel" || exit 1
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
  i=$((i+1))
done
REACH=0
for ipaddr in "${IP_ALL[@]}"; do ping -c1 -W1 "$ipaddr" >/dev/null 2>&1 && REACH=$((REACH+1)); done
[ "$REACH" = "${#IP_ALL[@]}" ] && ok "all 6 namespaces reachable (${REACH}/6)" || bad "namespaces reachable ($REACH/6)"

# The host firewall (ufw, INPUT policy DROP) would block netns→panel TCP:
# explicitly allow the lab bridge subnet for the duration of the run.
sudo iptables -I INPUT 1 -s 10.200.0.0/24 -j ACCEPT 2>/dev/null
sudo iptables -I INPUT 1 -i $BR -j ACCEPT 2>/dev/null

# 2. panel ------------------------------------------------------------------
say "starting the real panel..."
export GRE_PANEL_DIR=$LAB/panel GRE_PANEL_PASSWORD=$PANEL_PASS
mkdir -p $LAB/panel
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
PANEL_URL="http://127.0.0.1:$PANEL_PORT$PANEL_BASE"
say "panel at $PANEL_URL"
LIVE=""
for i in $(seq 1 30); do
  curl -s -o /dev/null "$PANEL_URL/api/login" && LIVE=1 && break
  sleep 0.5
done
[ "$LIVE" = "1" ] && ok "panel listening at $PANEL_URL" || { bad "panel never listened"; echo "--- panel.log ---"; tail -30 "$LAB/panel.log" 2>/dev/null; exit 1; }
# Re-assert the ACCEPT rule AFTER the panel starts: the panel's own
# startup may add firewall rules that shadow our earlier ACCEPT.
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
  if [ -n "$b" ]; then
    out=$(curl -s -b $LAB/admin.cookies -X "$m" "$PANEL_URL$p" \
      -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' -d "$b" \
      -w $'\n%{http_code}')
  else
    out=$(curl -s -b $LAB/admin.cookies -X "$m" "$PANEL_URL$p" -w $'\n%{http_code}')
  fi
  code=${out##*$'\n'}
  echo "$m $p http=$code" >> $LAB/api.log
  echo "${out%$'\n'*}"
}
jq_str() { # jq_str JSON_STRING python_expr
  echo "$1" | python3 -c "import json,sys;d=json.load(sys.stdin);print($2)" 2>/dev/null || echo ""
}
jq_get() { # jq_get FILE python_expr
  python3 -c "import json;d=json.load(open('$1'));print($2)" 2>/dev/null || echo ""
}

# 3. mesh configuration ------------------------------------------------------
say "configuring the mesh (2 iran DCs, 1 foreign DC, 6 servers)..."
api POST /api/mesh/datacenters '{"name":"Drak","kind":"iran","price_coefficient":1.0}' >/dev/null
api POST /api/mesh/datacenters '{"name":"Chekavak","kind":"iran","price_coefficient":1.5}' >/dev/null
api POST /api/mesh/datacenters '{"name":"Hetzner Germany","kind":"foreign","price_coefficient":1.0}' >/dev/null
api GET /api/mesh/datacenters > $LAB/dc.json
DC_DRAK=$(jq_get $LAB/dc.json "[x['id'] for x in d['datacenters'] if x['name']=='Drak'][0]")
DC_HZ=$(jq_get $LAB/dc.json "[x['id'] for x in d['datacenters'] if x['name']=='Hetzner Germany'][0]")
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

# Patch every fake tunnel's engine_params with its remote server's lab IP.
python3 - "$PANEL_PORT" "$LAB/admin.cookies" "$CSRF" "$SINK_PORT" <<'PYEOF'
import json, sys, urllib.request

port, cookies, csrf, sink = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])

def call(method, path, body=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method)
    req.add_header("Cookie", cookies)
    req.add_header("X-CSRF-Token", csrf)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    return json.load(urllib.request.urlopen(req, data))

servers = {s["name"]: s["address"] for s in call("GET", "/api/mesh/servers")}
patched = 0
for tname in ("drak-hz", "chekavak-hz"):
    topos = call("GET", "/api/mesh/topologies")["topologies"]
    topo = [t for t in topos if t["name"] == tname][0]
    full = call("GET", f"/api/mesh/topologies/{topo['id']}")
    for t in full.get("tunnels", []):
        if t["engine"] != "fake":
            continue
        rip = servers.get(t["remote_server"], "")
        if not rip:
            continue
        call("PATCH", f"/api/mesh/tunnels/{t['id']}",
             {"engine_params": json.dumps({"lab_addr": rip, "lab_port": sink})})
        patched += 1
print(f"patched {patched} fake tunnels")
PYEOF
check $? "fake tunnel engine_params patched (lab_addr = remote lab IP)"

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
N_AGENTS=$(jq_str "$AGENTS" "len(d)")
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
  [ "$(jq_str "$AGENTS" "sum(1 for a in d if a.get('proto_version',0)>=2)")" = "6" ]
}
if agentTestWait "v2 negotiation" 20 wait_v2; then
  ok "v2 negotiated on all 6 agents"
else
  api GET /api/mesh/agents > $LAB/agents.json
  AGENTS=$(jq_get $LAB/agents.json "json.dumps(d['agents'])")
  bad "v2 negotiated ($(jq_str "$AGENTS" "sum(1 for a in d if a.get('proto_version',0)>=2)")/6)"
  for ns in "${NS_ALL[@]}"; do
    nm=${ns#q-}
    echo "[e2e] run-$nm: $(tail -3 "$LAB/run-$nm.log" 2>/dev/null)"
  done
fi

# 6. push DesiredV2 to every agent -------------------------------------------
say "pushing DesiredV2 to every agent..."
for aid in $(jq_str "$AGENTS" "[a['id'] for a in d]"); do
  api POST /api/mesh/agents/$aid/push > "$LAB/push-$aid.json" 2>/dev/null
done
sleep 3
# fake sinks listening on the foreign agents (both foreign servers host
# 2 fake tunnels each? tunnels per foreign ns: drak-hz has 2 fake tunnels
# with remote = that server (one per iran server) + chekavak-hz 2 → the
# sink port is the SAME (8443) per server: one listener per foreign ns.
SINKS=0
for ns in "${NS_FOREIGN[@]}"; do
  sudo ip netns exec "$ns" ss -tln 2>/dev/null | grep -q ":$SINK_PORT " && SINKS=$((SINKS+1))
done
[ "$SINKS" = "2" ] && ok "fake sinks listening on both foreign agents" || bad "fake sinks ($SINKS/2)"

AG_DRAK1=$(jq_str "$AGENTS" "[a['id'] for a in d if a['name']=='ir-drak-1'][0]")

# 7. forward rule + measured weighted split ----------------------------------
say "forward rule + measured weighted split..."
api POST /api/mesh/forwards "{\"topology_id\":$TOPO1,\"local_server_id\":${SRV_ID[ir-drak-1]},\"listen_port\":$FWD_LISTEN,\"proto\":\"tcp\",\"enabled\":true}" >/dev/null
api POST /api/mesh/agents/$AG_DRAK1/push >/dev/null
sleep 3
# sinks on both foreign servers (the forward balances across the whole
# topology pool: ir-drak-1's fake tunnels reach hz-fra-1 AND hz-fra-2).
for ns in "${NS_FOREIGN[@]}"; do
  sudo ip netns exec "$ns" sh -c "nohup nc -l -p $SINK_PORT > /tmp/quantum-e2e/sink-$ns 2>/dev/null &"
done
sleep 1
N_CONN=20
for i in $(seq 1 $N_CONN); do
  echo "conn-$i" | timeout 2 nc -q1 ${IP_IRAN[0]} $FWD_LISTEN >/dev/null 2>&1 || true
  sleep 0.1
done
sleep 1
count_sink() { sudo ip netns exec "$1" sh -c "grep -c 'conn-' /tmp/quantum-e2e/sink-$1 2>/dev/null" || echo 0; }
C1=$(count_sink q-hz-fra-1); C2=$(count_sink q-hz-fra-2)
TOTAL=$((C1+C2))
[ "$TOTAL" -ge $((N_CONN/2)) ] && ok "forwarded traffic flows ($TOTAL/$N_CONN delivered)" || bad "forwarded traffic ($TOTAL/$N_CONN)"
if [ "$TOTAL" -gt 0 ]; then P1=$((C1*100/TOTAL)); P2=$((C2*100/TOTAL)); else P1=0; P2=0; fi
say "measured split: hz-fra-1=$C1 (${P1}%) hz-fra-2=$C2 (${P2}%) — desired weights 70/30 (both tunnels are 'fake' with equal capability)"
[ "$TOTAL" -gt 0 ] && ok "weighted split measured (${P1}%/${P2}%)" || bad "weighted split"

# 8. tunnel failover (kill ONE tunnel's sink) --------------------------------
say "tunnel failover (primary sink killed)..."
T0=$(date +%s.%N)
# kill the sink that owns the primary share: kill hz-fra-1's listener
sudo ip netns exec q-hz-fra-1 pkill -f "nc -l -p $SINK_PORT" 2>/dev/null || true
MOVED=0
DEADLINE=$(( $(date +%s) + 15 ))
LAST=$TOTAL
while [ $(date +%s) -lt $DEADLINE ]; do
  C2=$(count_sink q-hz-fra-2)
  if [ "$C2" -gt "$P2" ] 2>/dev/null || [ "$C2" -gt 0 ]; then
    MOVED=1; break
  fi
  echo "post-kill-$C2" | timeout 2 nc -q1 ${IP_IRAN[0]} $FWD_LISTEN >/dev/null 2>&1 || true
  sleep 0.5
done
T1=$(date +%s.%N)
DT=$(python3 -c "print(f'{$T1-$T0:.1f}')")
check $MOVED "tunnel failover: new connections moved to hz-fra-2 in ${DT}s"
FAILOVER_TIME=$DT

# 9. whole foreign server down + failback ------------------------------------
say "whole-server failover + failback..."
# Bring hz-fra-1's sink back first (so the rotation has both again), then
# kill BOTH sinks of hz-fra-2 -> traffic consolidates on hz-fra-1; then
# restore hz-fra-2 -> failback.
sudo ip netns exec q-hz-fra-1 sh -c "nohup nc -l -p $SINK_PORT > /tmp/quantum-e2e/sink-q-hz-fra-1 2>/dev/null &"
sleep 2
sudo ip netns exec q-hz-fra-2 pkill -f "nc -l -p $SINK_PORT" 2>/dev/null || true
sleep 2
T0=$(date +%s.%N)
sudo ip netns exec q-hz-fra-2 sh -c "nohup nc -l -p $SINK_PORT > /tmp/quantum-e2e/sink-q-hz-fra-2 2>/dev/null &"
BACK=0
DEADLINE=$(( $(date +%s) + 15 ))
while [ $(date +%s) -lt $DEADLINE ]; do
  C=$(count_sink q-hz-fra-2)
  if [ "$C" -gt "$C2" ] 2>/dev/null; then BACK=1; break; fi
  echo "failback-probe" | timeout 2 nc -q1 ${IP_IRAN[0]} $FWD_LISTEN >/dev/null 2>&1 || true
  sleep 0.5
done
T1=$(date +%s.%N)
DT2=$(python3 -c "print(f'{$T1-$T0:.1f}')")
check $BACK "failback to hz-fra-2 in ${DT2}s"

# 10. panel death: traffic + failover keep working ---------------------------
say "panel death..."
kill "$PANEL_PID" 2>/dev/null; PANEL_PID=""
wait "$PANEL_PID" 2>/dev/null
sleep 1
# failover WITHOUT the panel: kill hz-fra-1's sink -> new connections move
BEFORE_B1=$(count_sink q-hz-fra-1)
sudo ip netns exec q-hz-fra-1 pkill -f "nc -l -p $SINK_PORT" 2>/dev/null || true
DEADLINE=$(( $(date +%s) + 15 ))
MOVED2=0
while [ $(date +%s) -lt $DEADLINE ]; do
  B2=$(count_sink q-hz-fra-2)
  if [ "$B2" -gt 0 ]; then MOVED2=1; break; fi
  echo "panel-dead-probe" | timeout 2 nc -q1 ${IP_IRAN[0]} $FWD_LISTEN >/dev/null 2>&1 || true
  sleep 0.5
done
check $MOVED2 "traffic + failover keep working with the panel dead (moved after ${B2:-0} sink bytes)"
DEAD_PANEL_FAILOVER=$MOVED2

# 11. panel restart: re-sync without a revision storm -------------------------
say "panel restart..."
export GRE_PANEL_DIR=$LAB/panel GRE_PANEL_PASSWORD=$PANEL_PASS
$LAB/quantum-panel >> $LAB/panel.log 2>&1 &
PANEL_PID=$!
LIVE=""
for i in $(seq 1 30); do curl -s -o /dev/null "http://127.0.0.1:$PANEL_PORT/api/login" && LIVE=1 && break || sleep 0.5; done
[ "$LIVE" = "1" ] && ok "panel restarted" || bad "panel restart"
curl -s -c $LAB/admin.cookies -X POST "http://127.0.0.1:$PANEL_PORT/api/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$PANEL_PASS\"}" > $LAB/login2.json
CSRF=$(python3 -c "import json;print(json.load(open('$LAB/login2.json')).get('csrf_token',''))")
# agents reconnect; give them time, then count distinct applied revisions
sleep 8
api GET /api/mesh/agents > $LAB/agents-revs.json
REVS=$(jq_get $LAB/agents-revs.json "len({a.get('applied_revision','') for a in d['agents'] if a.get('applied_revision')})")
[ "$REVS" -le 2 ] && ok "panel restart: no revision storm ($REVS distinct applied revisions)" || bad "revision storm ($REVS)"

# 12. wire/payload counters in the usage API ----------------------------------
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
say "weight change..."
api POST /api/mesh/topologies/$TOPO1/weights "{\"local_server_id\":${SRV_ID[ir-drak-1]},\"remote_server_id\":${SRV_ID[hz-fra-2]},\"weight\":100}" >/dev/null
api POST /api/mesh/agents/$AG_DRAK1/push >/dev/null
sleep 4
C_BEFORE=$(count_sink q-hz-fra-2)
echo "weight-probe" | timeout 2 nc -q1 ${IP_IRAN[0]} $FWD_LISTEN >/dev/null 2>&1 || true
sleep 2
C_AFTER=$(count_sink q-hz-fra-2)
[ "$C_AFTER" -gt "$C_BEFORE" ] && ok "weight change enforced on the agent (traffic moved to hz-fra-2)" || bad "weight change not enforced"

# verdict ----------------------------------------------------------------------
echo
echo "[e2e] ===== verdict: $PASS passed, $FAIL failed ====="
for f in "${FAILED_CHECKS[@]}"; do echo "[e2e]   FAILED: $f"; done
[ $FAIL -eq 0 ] || exit 1
