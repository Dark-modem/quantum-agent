package agent

// wg_companion.go — carrier companions for the WireGuard engine, per
// 00-ADMIN/ENGINE-COMPANION-DESIGN.md: a tunnel description stays ONE
// engine instance; the engine id gains a carrier-suffix form
// ("wireguard@udp2raw") and the params gain a companion object. The
// companion wraps the WG UDP carrier in fake-TCP (udp2raw, MIT — license
// verified from the upstream LICENSE.md, Yu Wang 2017) so Iran routes
// that drop raw UDP can still carry the tunnel.
//
// Kernel knobs, strictly scoped to the instance and removed on stop:
//   - one iptables INPUT DROP rule for the udp2raw listen port's
//     unsolicited SYNs (the kernel would otherwise answer RST first);
//     tagged with the tunnel id in a comment so Del removes exactly
//     what Add created.
//   - the udp2raw binary needs CAP_NET_RAW: root agents have it; non-root
//     agents get a setcap attempt at Start — fail closed with a clear
//     error when neither is possible.
//
// Health/counters/lifecycle are UNCHANGED from the base engine: the WG
// handshake now flows through fake-TCP, so a healthy handshake PROVES the
// companion works.

import (
	"context"
	"fmt"
	"github.com/Dark-modem/quantum-agent/internal/engine"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const companionUDP2Raw = "udp2raw"

// wgCompanion is the carrier-wrap description (params.companion).
type wgCompanion struct {
	Kind         string `json:"kind"`          // only "udp2raw"
	ServerAddr   string `json:"server_addr"`   // client end: dial the server's fake-TCP "host:port"
	ListenAddr   string `json:"listen_addr"`   // both ends: the local fake-TCP port (server binds it; client dials 127.0.0.1:it)
	Password     string `json:"password"`      // udp2raw -a (8-256, CLI-safe)
	AutoIptables bool   `json:"auto_iptables"` // manage the kernel RST rule
	// Binary delivery (R5 manifest engine "udp2raw" + pinned fallback —
	// same trust model as every other engine artifact).
	Version   string `json:"version"`
	Artifact  string `json:"artifact"`
	SHA256Amd string `json:"sha256_amd64"`
	SHA256Arm string `json:"sha256_arm64"`
	SigAmd    string `json:"signature_amd64"`
	SigArm    string `json:"signature_arm64"`
}

func (c *wgCompanion) validate() error {
	if c == nil {
		return nil
	}
	if c.Kind != companionUDP2Raw {
		return fmt.Errorf("wg: companion.kind must be %q (got %q)", companionUDP2Raw, c.Kind)
	}
	for _, a := range []struct{ label, v string }{{"server_addr", c.ServerAddr}, {"listen_addr", c.ListenAddr}} {
		if strings.TrimSpace(a.v) == "" || len(a.v) > 128 || strings.ContainsAny(a.v, "\"'\n\r\\") {
			return fmt.Errorf("wg: companion.%s must be 1-128 CLI-safe chars (host:port)", a.label)
		}
		if _, _, err := net.SplitHostPort(a.v); err != nil {
			return fmt.Errorf("wg: companion.%s must be host:port", a.label)
		}
	}
	if len(c.Password) < 8 || len(c.Password) > 256 || strings.ContainsAny(c.Password, "\"'\\\n\r ") {
		return fmt.Errorf("wg: companion.password must be 8-256 chars without quotes/backslash/space")
	}
	if err := backhaulValidateArtifactPins2(c.Version, c.Artifact, c.SHA256Amd, c.SigAmd, c.SHA256Arm, c.SigArm, "wg companion"); err != nil {
		return err
	}
	return nil
}

// wgCompanionUDP2RawArgs renders the udp2raw CLI for one end.
// server: udp2raw -s -l <listen> -r 127.0.0.1:<wg_port> -a <password> --raw-mode faketcp
// client: udp2raw -c -l 127.0.0.1:<local> -r <server_addr> -a <password> --raw-mode faketcp
func wgCompanionUDP2RawArgs(role engineSide, p wgParams, c *wgCompanion, localUDPPort int) []string {
	if role == engineSideServer {
		return []string{"-s", "-l", c.ListenAddr,
			"-r", net.JoinHostPort("127.0.0.1", fmt.Sprint(p.CarrierPort)),
			"-a", c.Password, "--raw-mode", "faketcp"}
	}
	return []string{"-c", "-l", net.JoinHostPort("127.0.0.1", fmt.Sprint(localUDPPort)),
		"-r", c.ServerAddr, "-a", c.Password, "--raw-mode", "faketcp"}
}

// wgCompanionIptablesRule is the kernel-RST guard for the server end's
// fake-TCP listen port (comment-tagged with the tunnel id).
func wgCompanionIptablesRule(c *wgCompanion) int {
	if c == nil || c.Kind != companionUDP2Raw {
		return 0
	}
	return ratholePortOf(c.ListenAddr)
}

// osGeteuid seams the effective-uid check (hermetic tests stub it).
var osGeteuid = os.Geteuid

// wgCompanionEnsureRawCap: udp2raw needs CAP_NET_RAW. Root has it; a
// non-root agent gets a best-effort setcap on the binary (fails closed
// with a clear error when neither is possible).
func wgCompanionEnsureRawCap(binPath string) error {
	if osGeteuid() == 0 {
		return nil
	}
	if out, err := exec.Command("setcap", "cap_net_raw+ep", binPath).CombinedOutput(); err != nil {
		return fmt.Errorf("udp2raw needs CAP_NET_RAW (not root; setcap failed: %v: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// wgCompanionEnsureBinary delivers the udp2raw binary through the R5
// manifest (engine "udp2raw") with the pinned fallback — fail closed
// without a pinned key, like every engine artifact.
func wgCompanionEnsureBinary(ctx context.Context, tunnelID string, c *wgCompanion) (string, error) {
	key := strings.TrimSpace(engineArtifactPubKeyB64)
	if key == "" {
		return "", fmt.Errorf("wg companion: no engine artifact signing key pinned in this build (fail closed)")
	}
	pin := func() (string, string, string, error) {
		return enginePinForArch(EnginePin{Version: c.Version, Artifact: c.Artifact,
			SHA256Amd: c.SHA256Amd, SHA256Arm: c.SHA256Arm, SigAmd: c.SigAmd, SigArm: c.SigArm})
	}
	name, sha256Hex, sigB64, err := pin()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(configDir, "engines", companionUDP2Raw, "bin", c.Version)
	if engineCacheHit(dir, sha256Hex, []string{"udp2raw"}) {
		return dir, nil
	}
	ident, ok := frpLoadIdentity()
	if !ok || strings.TrimSpace(ident.Server) == "" {
		return "", fmt.Errorf("wg companion: no controller identity — cannot fetch the udp2raw artifact (fail closed)")
	}
	name, sha256Hex, sigB64, _, err = engineArtifactPin(ctx, ident, companionUDP2Raw, pin)
	if err != nil {
		return "", err
	}
	downloadURL := engineManifestFileURL(ident, name)
	body, err := frpFetchArtifact(ctx, downloadURL)
	if err != nil {
		return "", err
	}
	if err := engine.VerifyArtifact(body, sha256Hex, sigB64, key); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := engineExtractTarball(body, dir, map[string]bool{"udp2raw": true}); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "artifact.sha256"), []byte(sha256Hex), 0o600); err != nil {
		return "", err
	}
	return dir, nil
}

// wgCompanionSpawn seams the udp2raw process spawn (args-only CLI).
var wgCompanionSpawn = func(binPath string, args []string) (frpProcess, error) {
	cmd := exec.Command(binPath, args...)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("udp2raw: start: %w", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	return &frpExecProcess{cmd: cmd, done: done}, nil
}

// wgCompanionStart delivers the binary, spawns the udp2raw process for
// this end, and (server end) adds the kernel RST rule. Called from Start
// AFTER the WG interface is up; failures unwind the whole instance.
func wgCompanionStart(st *wgInstState, tunnelID string) error {
	c := st.comp
	dir, err := wgCompanionEnsureBinary(context.Background(), tunnelID, c)
	if err != nil {
		return err
	}
	binPath := filepath.Join(dir, "udp2raw")
	if err := wgCompanionEnsureRawCap(binPath); err != nil {
		return err
	}
	st.compBin = binPath
	args := wgCompanionUDP2RawArgs(st.role, st.params, c, listenPortOf(c.ListenAddr))
	proc, err := wgCompanionSpawn(binPath, args)
	if err != nil {
		return err
	}
	st.compProc = proc
	if st.role == engineSideServer {
		if port := wgCompanionIptablesRule(c); port > 0 {
			comment := "quantum-wg-" + tunnelID
			out, err := frpIptables("-I", "INPUT", "-p", "tcp", "--dport", fmt.Sprint(port),
				"--tcp-flags", "SYN,RST", "SYN", "-j", "DROP", "-m", "comment", "--comment", comment)
			if err != nil {
				frpProcStop(proc)
				return fmt.Errorf("wg companion: kernel RST rule: %v: %s", err, strings.TrimSpace(string(out)))
			}
		}
	}
	return nil
}

// listenPortOf extracts the port from a host:port listen address.
func listenPortOf(addr string) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n := 0
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return 0
		}
		n = n*10 + int(port[i]-'0')
		if n > 65535 {
			return 0
		}
	}
	return n
}

// superviseCompanion keeps the udp2raw process alive with the same capped
// backoff as the base engine (2s→15s); Stop closes st.stop first.
func (d *WgDriver) superviseCompanion(st *wgInstState) {
	backoff := 2 * time.Second
	for {
		select {
		case <-st.stop:
			return
		case <-st.compProc.Done():
			select {
			case <-st.stop:
				return
			case <-time.After(backoff):
			}
			if backoff < 15*time.Second {
				backoff *= 2
			}
			args := wgCompanionUDP2RawArgs(st.role, st.params, st.comp, listenPortOf(st.comp.ListenAddr))
			if proc, err := wgCompanionSpawn(st.compBin, args); err == nil {
				st.compProc = proc
			}
		}
	}
}

// wgCompanionStop kills the udp2raw process and removes the kernel RST
// rule (exactly the rule this tunnel added — comment-tagged).
func wgCompanionStop(st *wgInstState, tunnelID string) {
	if st.comp == nil {
		return
	}
	frpProcStop(st.compProc)
	if st.role == engineSideServer {
		if port := wgCompanionIptablesRule(st.comp); port > 0 {
			comment := "quantum-wg-" + tunnelID
			_, _ = frpIptables("-D", "INPUT", "-p", "tcp", "--dport", fmt.Sprint(port),
				"--tcp-flags", "SYN,RST", "SYN", "-j", "DROP", "-m", "comment", "--comment", comment)
		}
	}
}
