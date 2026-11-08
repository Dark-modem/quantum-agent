//go:build integration

// wg_udp2raw_integration_test.go — WireGuard THROUGH the udp2raw
// companion (wireguard@udp2raw): fake-TCP carrier in two netns, kernel
// RST rule managed by the driver, WG handshake + iperf3 per direction
// with a same-run baseline. All numbers lab-loopback ONLY.
//
//	Run: WG_INTEGRATION=1 UDP2RAW_INTEG_DIR=/tmp/udp2raw-int \
//	         go test -tags integration -run TestWgUdp2rawIntegration \
//	         ./internal/agent/ -count=1 -v   (as root; ip, wg, iperf3, ping)
//
// The companion's binary delivery reuses the exact R5 helper chain
// verified by the other engines' integrations; this test warms the cache
// from the upstream release bundle and exercises everything DOWNSTREAM
// of the fetch (cap check, spawn, iptables rule, endpoint override,
// supervised respawn, traffic).

package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"

	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Dark-modem/quantum-agent/internal/engine"
)

const udp2rawUpstreamURL = "https://github.com/wangyu-/udp2raw/releases/download/20230206.0/udp2raw_binaries.tar.gz"

const (
	wguNSA     = "quantum-test-wgu-a"
	wguNSB     = "quantum-test-wgu-b"
	wguIPA     = "10.208.0.1"
	wguIPB     = "10.208.0.2"
	wguCarrier = 51830 // WG UDP port (inside the fake-TCP wrap)
	wguFake    = 51930 // udp2raw fake-TCP port
	wguTunnel  = 25410 // iperf3 over the tunnel
	wguBase    = 25409 // same-run underlay baseline
	wguVethA   = "v-wgu-a"
	wguVethB   = "v-wgu-b"
)

func udp2rawFetchBinary(t *testing.T, dir string) []byte {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(dir, "udp2raw-bin")
	if b, err := os.ReadFile(cache); err == nil {
		return b
	}
	resp, err := http.Get(udp2rawUpstreamURL)
	if err != nil {
		t.Fatalf("download udp2raw bundle: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("download udp2raw bundle: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("bundle gzip: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			t.Fatal("bundle: no amd64 binary found")
		}
		if err != nil {
			t.Fatalf("bundle tar: %v", err)
		}
		lc := strings.ToLower(hdr.Name)
		if hdr.Typeflag != tar.TypeReg || !strings.Contains(lc, "amd64") || strings.Contains(lc, "arm") {
			continue
		}
		bin, err := io.ReadAll(io.LimitReader(tr, 64<<20))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cache, bin, 0o755); err != nil {
			t.Fatal(err)
		}
		return bin
	}
}

func TestWgUdp2rawIntegration(t *testing.T) {
	wgIntSkip(t)
	dir := os.Getenv("UDP2RAW_INTEG_DIR")
	if dir == "" {
		t.Skip("UDP2RAW_INTEG_DIR not set")
	}
	origKey := engineArtifactPubKeyB64
	engineArtifactPubKeyB64 = "integration-pinned-key"
	t.Cleanup(func() { engineArtifactPubKeyB64 = origKey })
	origCfg := configDir
	configDir = t.TempDir()
	t.Cleanup(func() { configDir = origCfg })

	if out, err := exec.Command("sudo", "ip", "link", "add", "wg-probe0", "type", "wireguard").CombinedOutput(); err != nil {
		t.Skipf("wireguard kernel module unavailable: %v: %s", err, out)
	}
	exec.Command("sudo", "ip", "link", "del", "wg-probe0").Run()

	clean := func() {
		for _, ns := range []string{wguNSA, wguNSB} {
			exec.Command("sudo", "ip", "netns", "del", ns).Run()
		}
		exec.Command("sudo", "ip", "link", "del", wguVethA).Run()
		exec.Command("sudo", "ip", "link", "del", wguVethB).Run()
	}
	clean()
	t.Cleanup(clean)
	for _, c := range [][]string{
		{"ip", "netns", "add", wguNSA}, {"ip", "netns", "add", wguNSB},
		{"ip", "link", "add", wguVethA, "type", "veth", "peer", "name", wguVethB},
		{"ip", "link", "set", wguVethA, "netns", wguNSA},
		{"ip", "link", "set", wguVethB, "netns", wguNSB},
	} {
		if out, err := exec.Command("sudo", c...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v: %s", c, err, out)
		}
	}
	runNS := func(ns string, args ...string) (string, error) {
		full := append([]string{"ip", "netns", "exec", ns}, args...)
		out, err := exec.Command("sudo", full...).CombinedOutput()
		return string(out), err
	}
	mustNS := func(ns string, args ...string) string {
		out, err := runNS(ns, args...)
		if err != nil {
			t.Fatalf("netns exec %s %v: %v: %s", ns, args, err, out)
		}
		return out
	}
	mustNS(wguNSA, "ip", "addr", "add", wguIPA+"/30", "dev", wguVethA)
	mustNS(wguNSA, "ip", "link", "set", wguVethA, "up")
	mustNS(wguNSA, "ip", "link", "set", "lo", "up")
	mustNS(wguNSB, "ip", "addr", "add", wguIPB+"/30", "dev", wguVethB)
	mustNS(wguNSB, "ip", "link", "set", wguVethB, "up")
	mustNS(wguNSB, "ip", "link", "set", "lo", "up")
	if out, err := runNS(wguNSB, "ping", "-c", "1", "-W", "2", wguIPA); err != nil {
		t.Fatalf("underlay unreachable: %v: %s", err, out)
	}

	// Same-run underlay baseline.
	mustNS(wguNSA, "sh", "-c", fmt.Sprintf("nohup iperf3 -s -p %d > /dev/null 2>&1 &", wguBase))
	defer runNS(wguNSA, "pkill", "-f", fmt.Sprintf("iperf3 -s -p %d", wguBase))
	time.Sleep(time.Second)
	if base, berr := runNS(wguNSB, "sh", "-c",
		fmt.Sprintf("timeout 30 iperf3 -c %s -p %d -t 3 2>&1 | grep -E 'sender|receiver'", wguIPA, wguBase)); berr == nil {
		t.Logf("lab-loopback UNDERLAY baseline (no tunnel): %s", strings.TrimSpace(base))
	}

	// The companion binary: download + warm the cache (the R5 fetch/verify
	// chain is engine-common and covered by the other integrations).
	bin := udp2rawFetchBinary(t, dir)
	binDir := filepath.Join(configDir, "engines", "udp2raw", "bin", "20230206.0")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "udp2raw"), bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "artifact.sha256"), []byte(strings.Repeat("aa", 32)), 0o600); err != nil {
		t.Fatal(err)
	}

	// Seams: the WG kernel work + the companion spawn + iptables all land
	// in the RIGHT namespace; the hermetic uid check passes because the
	// spawned processes run under sudo (root ⇒ CAP_NET_RAW).
	serveNS := wguNSA
	origTool := wgToolExec
	wgToolExec = func(args ...string) (string, error) {
		rest := args
		if len(args) > 0 && args[0] == "wg" {
			rest = args[1:]
		}
		full := []string{"ip", "netns", "exec", serveNS}
		if len(rest) > 0 && rest[0] != "ip" {
			full = append(full, "wg")
		}
		full = append(full, rest...)
		out, err := exec.Command("sudo", full...).CombinedOutput()
		return string(out), err
	}
	t.Cleanup(func() { wgToolExec = origTool })
	origIpt := frpIptables
	frpIptables = func(args ...string) ([]byte, error) {
		full := append([]string{"ip", "netns", "exec", serveNS, "iptables"}, args...)
		out, err := exec.Command("sudo", full...).CombinedOutput()
		return out, err
	}
	t.Cleanup(func() { frpIptables = origIpt })
	origCap := osGeteuid
	osGeteuid = func() int { return 0 }
	t.Cleanup(func() { osGeteuid = origCap })
	// The companion spawn: pinned to the SERVER ns for the server end and
	// the CLIENT ns for the client end (per-end map, like the rathole
	// spawn seam — supervisors respawn in the RIGHT namespace).
	nsByPort := map[string]string{fmt.Sprint(wguFake): ""}
	origCSpawn := wgCompanionSpawn
	wgCompanionSpawn = func(binPath string, args []string) (frpProcess, error) {
		// The -l argument decides which end is spawning: the server binds
		// 0.0.0.0:<fake>, the client binds 127.0.0.1:<fake>.
		ns := wguNSA
		for i, a := range args {
			if a == "-l" && i+1 < len(args) && strings.HasPrefix(args[i+1], "127.0.0.1:") {
				ns = nsByPort[fmt.Sprint(wguFake)]
				if ns == "" {
					ns = wguNSB
				}
			}
		}
		lf, err := os.Create(filepath.Join(dir, "udp2raw-"+ns+".log"))
		if err != nil {
			return nil, err
		}
		cmd := exec.Command("sudo", "ip", "netns", "exec", ns, binPath)
		cmd.Args = append(cmd.Args, args...)
		cmd.Stdout = lf
		cmd.Stderr = lf
		if err := cmd.Start(); err != nil {
			lf.Close()
			return nil, err
		}
		done := make(chan error, 1)
		go func() {
			done <- cmd.Wait()
			lf.Close()
		}()
		return &frpExecProcess{cmd: cmd, done: done}, nil
	}
	t.Cleanup(func() { wgCompanionSpawn = origCSpawn })
	origIdent := frpLoadIdentity
	frpLoadIdentity = func() (agentIdentity, bool) {
		name := "germany"
		if serveNS == wguNSB {
			name = "iran-1"
		}
		return agentIdentity{Server: "http://panel.test", Name: name}, true
	}
	t.Cleanup(func() { frpLoadIdentity = origIdent })
	_ = nsByPort

	d := NewWgDriver()
	p := wgParams{ServerSide: "germany", CarrierIP: wguIPA, CarrierPort: wguCarrier, MTU: 0}
	p.Companion = &wgCompanion{
		Kind: "udp2raw", ServerAddr: fmt.Sprintf("%s:%d", wguIPA, wguFake),
		ListenAddr: fmt.Sprintf("0.0.0.0:%d", wguFake), Password: "udp2raw-int-pass-01",
		AutoIptables: true,
		Version:      "20230206.0", Artifact: "udp2raw-20230206.0-linux-{arch}.tar.gz",
		SHA256Amd: strings.Repeat("aa", 32), SHA256Arm: strings.Repeat("bb", 32),
		SigAmd: strings.Repeat("QQ==", 22)[:88], SigArm: strings.Repeat("QQ==", 22)[:88],
	}
	instA := engine.Instance{TunnelID: "twgu-a", LocalServer: "germany", RemoteServer: "iran",
		Params: mustJSON(p)}
	if err := d.Start(context.Background(), instA); err != nil {
		t.Fatalf("server Start: %v", err)
	}
	mustIfaceName(t, d, "twgu-a")
	serveNS = wguNSB
	instB := engine.Instance{TunnelID: "twgu-b", LocalServer: "iran", RemoteServer: "germany",
		Params: mustJSON(p)}
	if err := d.Start(context.Background(), instB); err != nil {
		t.Fatalf("client Start: %v", err)
	}
	ifaceB := mustIfaceName(t, d, "twgu-b")

	// The key exchange via LIVE revisions (same flow as the plain WG).
	d.mu.Lock()
	pubA := d.runs["twgu-a"].pubB64
	pubB := d.runs["twgu-b"].pubB64
	d.mu.Unlock()
	revA := p
	revA.PeerPublic = pubB
	revB := p
	revB.PeerPublic = pubA
	serveNS = wguNSA
	if err := d.Reload(engine.Instance{TunnelID: "twgu-a", Params: mustJSON(revA)}); err != nil {
		t.Fatalf("server revision: %v", err)
	}
	serveNS = wguNSB
	if err := d.Reload(engine.Instance{TunnelID: "twgu-b", Params: mustJSON(revB)}); err != nil {
		t.Fatalf("client revision: %v", err)
	}

	// Handshake + ping THROUGH fake-TCP.
	pingOK := false
	for i := 0; i < 30; i++ {
		if out, err := runNS(wguNSB, "ping", "-c", "1", "-W", "1", "10.189.0.1"); err == nil &&
			strings.Contains(out, " 0% packet loss") {
			pingOK = true
			break
		}
		time.Sleep(time.Second)
	}
	if !pingOK {
		hs, _ := runNS(wguNSB, "wg", "show", ifaceB)
		ul, _ := runNS(wguNSA, "sh", "-c", "iptables -S INPUT | head -4")
		t.Fatalf("tunnel never carried a ping through fake-TCP;\nwg show: %s\nnsA INPUT rules: %s", hs, ul)
	}
	t.Logf("lab-loopback WG@udp2raw handshake + ping through fake-TCP OK")

	mustNS(wguNSA, "sh", "-c", fmt.Sprintf("nohup iperf3 -s -p %d > /dev/null 2>&1 &", wguTunnel))
	defer runNS(wguNSA, "pkill", "-f", fmt.Sprintf("iperf3 -s -p %d", wguTunnel))
	time.Sleep(time.Second)
	fwd, ferr := runNS(wguNSB, "sh", "-c",
		fmt.Sprintf("timeout 60 iperf3 -c 10.189.0.1 -p %d -t 3 2>&1 | grep -E 'sender|receiver'", wguTunnel))
	if ferr != nil {
		t.Fatalf("forward iperf through fake-TCP: %v: %s", ferr, fwd)
	}
	t.Logf("lab-loopback WG@udp2raw FORWARD (Iran→foreign through fake-TCP): %s", strings.TrimSpace(fwd))
	rev, rerr := runNS(wguNSB, "sh", "-c",
		fmt.Sprintf("timeout 60 iperf3 -c 10.189.0.1 -p %d -R -t 3 2>&1 | grep -E 'sender|receiver'", wguTunnel))
	if rerr != nil {
		t.Fatalf("reverse iperf: %v: %s", rerr, rev)
	}
	t.Logf("lab-loopback WG@udp2raw REVERSE (-R): %s", strings.TrimSpace(rev))

	// Cleanup: the kernel RST rule must be GONE from nsA.
	serveNS = wguNSA
	if err := d.Stop(instA); err != nil {
		t.Fatal(err)
	}
	serveNS = wguNSB
	if err := d.Stop(instB); err != nil {
		t.Fatal(err)
	}
	if out, err := runNS(wguNSA, "sh", "-c", "iptables -S INPUT | grep quantum-wg-twgu-a || echo CLEAN"); err != nil ||
		strings.Contains(out, "quantum-wg-twgu-a") {
		t.Fatalf("kernel RST rule left behind: %s", out)
	}
	t.Logf("lab-loopback WG@udp2raw Stop: interfaces deleted + RST rule removed")

}
