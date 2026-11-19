package agent

// Reverse Path Doctor, Phase 1: READ-ONLY. Collects hub-side facts, classifies
// them with a pure function, and reports. Nothing here writes sysctl, routes,
// iptables or restarts a unit; fixes are text only.
//
// REFACTOR-PLAN-AGENT §6.A3: the probe/classify/handler layer (29 of this
// file's 30 funcs — diagnosePeer, revPathRefresh, the probe primitives, the
// parsers and the legacy HTTP handlers) is prod-unreachable (deadcode RTA
// from main, reproduced) and is deleted; nothing populated revPathCache in
// the reachable graph, so the doctor's reader below always saw an empty
// list. What survives is the doctor-facing SHAPE: the entry/diagnosis types
// (doctor.go renders them) and the cache the reader reads — so the doctor
// JSON field names stay byte-identical if a future stage re-arms the
// collector.

import (
	"sort"
	"sync"
	"time"
)

type ProbeResult struct {
	Layer     string  `json:"layer"`
	Direction string  `json:"direction"`
	OK        bool    `json:"ok"`
	RTTms     float64 `json:"rtt_ms"`
	Err       string  `json:"err,omitempty"`
	Size      int     `json:"size,omitempty"`
	DF        bool    `json:"df,omitempty"`
}

// ProbeMatrix holds both directions. GRE packet-counter deltas are nil when
// not measured. Deltas include concurrent tunnel traffic, so they are only
// meaningful as "zero vs non-zero".
type ProbeMatrix struct {
	Results []ProbeResult `json:"results"`

	HubRxDelta   *uint64 `json:"hub_gre_rx_delta,omitempty"`
	HubTxDelta   *uint64 `json:"hub_gre_tx_delta,omitempty"`
	SpokeRxDelta *uint64 `json:"spoke_gre_rx_delta,omitempty"`
	SpokeTxDelta *uint64 `json:"spoke_gre_tx_delta,omitempty"`
}

type LocalSnapshot struct {
	GreIf           string `json:"gre_if"`
	InnerLocal      string `json:"inner_local,omitempty"`
	RPFilterAll     int    `json:"rp_filter_all"`
	RPFilterDefault int    `json:"rp_filter_default"`
	RPFilterIface   int    `json:"rp_filter_iface"`
	IPForward       bool   `json:"ip_forward"`
	GreMTU          int    `json:"gre_mtu"`

	FwChecked         bool `json:"fw_checked"`
	InputDropsProto47 bool `json:"input_drops_proto47"`
	FwDropsICMP       bool `json:"fw_drops_icmp"`

	ConntrackKnown         bool `json:"conntrack_known"`
	ConntrackInvalidRising bool `json:"conntrack_invalid_rising"`

	RouteKnown      bool   `json:"route_known"`
	RouteBackViaGre bool   `json:"route_back_via_gre"`
	SrcAddrOnReply  string `json:"src_addr_on_reply,omitempty"`
}

type Verdict string

const (
	VerdictRPFilter         Verdict = "RP_FILTER"
	VerdictSrcSelect        Verdict = "SRC_SELECT"
	VerdictNoReturnRoute    Verdict = "NO_RETURN_ROUTE"
	VerdictFwInput          Verdict = "FW_INPUT"
	VerdictMTUBlackhole     Verdict = "MTU_BLACKHOLE"
	VerdictConntrackInvalid Verdict = "CONNTRACK_INVALID"
	VerdictISPICMPOneWay    Verdict = "ISP_ICMP_ONE_WAY"
	VerdictISPGreBlock      Verdict = "ISP_GRE_BLOCK"
	VerdictCloudSG          Verdict = "CLOUD_SG"
	VerdictHealthy          Verdict = "HEALTHY"
	VerdictUnknown          Verdict = "UNKNOWN"
)

type RevPathDiagnosis struct {
	Verdict      Verdict  `json:"verdict"`
	Confidence   string   `json:"confidence"` // "high" | "medium" | "low"
	Evidence     []string `json:"evidence"`
	SuggestedFix string   `json:"suggested_fix,omitempty"` // text only in Phase 1
	AutoFixable  bool     `json:"auto_fixable"`
}

var revPathFixText = map[Verdict]string{
	VerdictRPFilter:         "Set net.ipv4.conf.{all,default,<gre-if>}.rp_filter=2 (loose) and persist it in /etc/sysctl.d.",
	VerdictSrcSelect:        "Pin the GRE route source: ip route replace <peer-inner> dev <gre-if> src <local-inner>.",
	VerdictNoReturnRoute:    "Add a route to the peer inner address via the GRE interface and persist it in the gre unit.",
	VerdictFwInput:          "Allow proto 47, ICMP and the GRE interface in INPUT/FORWARD (use a dedicated chain, never edit user rules).",
	VerdictMTUBlackhole:     "Lower the GRE MTU stepwise (1380 -> 1360 -> 1340 -> 1300) and re-check the MSS clamp.",
	VerdictConntrackInvalid: "Exempt proto 47 / the GRE interface from conntrack (raw table NOTRACK).",
	VerdictISPICMPOneWay:    "No local fix: ICMP is filtered upstream. Rely on the TCP/session signal; do not restart the tunnel.",
	VerdictISPGreBlock:      "Proto 47 is not delivered one way while TCP over the public path works: switch the carrier to WSS.",
	VerdictCloudSG:          "Cloud security group / provider firewall: allow IP protocol 47 and ICMP from the hub IP on the spoke.",
}

var revPathAutoFixable = map[Verdict]bool{
	VerdictRPFilter: true, VerdictSrcSelect: true, VerdictNoReturnRoute: true,
	VerdictFwInput: true, VerdictMTUBlackhole: true, VerdictConntrackInvalid: true,
}

type revPathEntry struct {
	PeerID    int              `json:"peer_id"`
	Name      string           `json:"name"`
	Checked   string           `json:"checked"`
	Diagnosis RevPathDiagnosis `json:"diagnosis"`
	Matrix    ProbeMatrix      `json:"matrix"`
	Snapshot  LocalSnapshot    `json:"snapshot"`
	checkedAt time.Time
}

const revPathTTL = 60 * time.Second

// procRoot is the /proc root (test seam). §6.A3 note: snapshot_compat.go's
// dead parsers — that file being outside this stage's named scope — still
// compile against it.
var procRoot = "/proc"

var (
	revPathMu    sync.Mutex // guards revPathCache
	revPathCache = map[int]*revPathEntry{}
)

// revPathCached returns the reverse-path entries the doctor's status view
// renders. Nothing populates the cache since the §6.A3 purge of the
// (unreachable) probe collector, so this is an empty, shape-stable list —
// exactly what the reachable graph produced before the purge.
func revPathCached() []revPathEntry {
	revPathMu.Lock()
	defer revPathMu.Unlock()
	res := make([]revPathEntry, 0, len(revPathCache))
	for _, c := range revPathCache {
		res = append(res, *c)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].PeerID < res[j].PeerID })
	return res
}
