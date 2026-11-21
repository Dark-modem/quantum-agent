package agent

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Dark-modem/quantum-agent/internal/infra"
)

func matrixInstanceLab(t *testing.T) {
	t.Helper()
	oldDir, oldUnit, oldTinc, oldExec := infra.ConfigDir, matrixUnitDir, matrixTincPath, matrixExec
	infra.ConfigDir = t.TempDir()
	matrixUnitDir = t.TempDir()
	matrixTincPath = func() (string, error) { return "/usr/sbin/tincd", nil }
	matrixExec = func(name string, args ...string) (string, error) {
		s := strings.Join(args, " ")
		if name == "iptables" && (strings.Contains(s, " -C ") || strings.Contains(s, " -S ")) {
			return "", fmt.Errorf("chain absent")
		}
		if name == "ip" && strings.Contains(s, "route") {
			return "[]", nil
		}
		if name == "ip" && strings.Contains(s, "link") {
			return "", fmt.Errorf("interface does not exist")
		}
		return "", nil
	}
	t.Cleanup(func() {
		AgentOpsWait() // agent runtime goroutines read infra.ConfigDir/matrix seams
		infra.ConfigDir, matrixUnitDir, matrixTincPath, matrixExec = oldDir, oldUnit, oldTinc, oldExec
	})
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	// Verify BOTH transports are free: matrixSetup's preflight probes TCP as
	// well, and on loaded machines the OS can hand the same ephemeral port's
	// TCP side to another process between our check and tinc's bind.
	for attempt := 0; attempt < 20; attempt++ {
		l, e := net.ListenPacket("udp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		port := l.LocalAddr().(*net.UDPAddr).Port
		ln, e := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if e != nil {
			l.Close()
			continue
		}
		l.Close()
		ln.Close()
		return port
	}
	t.Fatal("no dual-transport-free port found after 20 attempts")
	return 0
}

func TestMatrixInstanceDerivationIsUniquePerInstance(t *testing.T) {
	seen := map[string]string{}
	for _, in := range []matrixInstance{matrixLegacyInstance(), {ID: "matrix2"}, {ID: "matrix3"}, {ID: "matrix17"}} {
		if !in.valid() {
			t.Fatalf("instance %s should be valid", in.ID)
		}
		for _, v := range []string{
			"net:" + in.network(), "iface:" + in.iface(), "unit:" + in.unit(), "tag:" + in.tag(),
			"chain:" + in.chainPfx(), "hub:" + in.hubIP(), "peer:" + in.firstPeer(),
			"subnet:" + in.subnet(), "dir:" + matrixDirOf(in), "state:" + matrixStatePathOf(in),
			"unitpath:" + matrixUnitPathOf(in), "pid:" + in.pidFile(),
		} {
			if prev, dup := seen[v]; dup {
				t.Fatalf("%s collides between %s and %s", v, prev, in.ID)
			}
			seen[v] = in.ID
		}
	}
	legacy := matrixLegacyInstance()
	if legacy.network() != matrixNetname || legacy.iface() != matrixIfaceName || legacy.unit() != matrixUnit ||
		legacy.tag() != matrixTag || legacy.hubIP() != matrixHubIP || legacy.firstPeer() != matrixFirstPeer ||
		legacy.subnet() != matrixSubnet || legacy.chainPfx() != "QMX" {
		t.Fatal("legacy instance must keep every historical constant")
	}
	for _, bad := range []string{"matrix1", "matrixx", "matrix0", "matrix-3", "", "Matrix2", "matrix99999999999999999999"} {
		if (matrixInstance{ID: bad}).valid() {
			t.Fatalf("accepted invalid instance %q", bad)
		}
	}
	if _, ok := matrixInstanceOfNetwork("quantum_matrix2"); !ok {
		t.Fatal("network quantum_matrix2 must map to an instance")
	}
	if in, ok := matrixInstanceOfNetwork("quantum_matrix"); !ok || in.ID != "matrix" {
		t.Fatal("legacy network mapping broken")
	}
	if _, ok := matrixInstanceOfNetwork("quantum_matrix1"); ok {
		t.Fatal("matrix1 network must be refused")
	}
	if _, ok := matrixInstanceOfNetwork("quantum_matrix99999999999999999999"); ok {
		t.Fatal("over-cap instance network accepted")
	}
}

func TestMatrixInstanceRegistryScansStateFiles(t *testing.T) {
	matrixInstanceLab(t)
	if got := matrixInstances(); len(got) != 0 {
		t.Fatalf("empty config dir should list no instances, got %v", got)
	}
	if id := matrixNextInstanceID(); id != "matrix2" {
		t.Fatalf("next id = %q", id)
	}
	for _, name := range []string{"matrix.json", "matrix2.json", "matrix-local-services.json", "matrix-tinc", "topologies.json", "matrix10.json"} {
		if strings.HasSuffix(name, ".json") {
			if e := os.WriteFile(filepath.Join(infra.ConfigDir, name), []byte("{}"), 0600); e != nil {
				t.Fatal(e)
			}
		} else if e := os.MkdirAll(filepath.Join(infra.ConfigDir, name), 0700); e != nil {
			t.Fatal(e)
		}
	}
	got := matrixInstances()
	if len(got) != 3 || got[0].ID != "matrix" || got[1].ID != "matrix2" || got[2].ID != "matrix10" {
		t.Fatalf("registry = %+v", got)
	}
	if id := matrixNextInstanceID(); id != "matrix3" {
		t.Fatalf("next id after scan = %q", id)
	}
	if _, e := matrixResolveInstance("next"); e != nil {
		t.Fatal(e)
	}
	if _, e := matrixResolveInstance("bogus"); e == nil {
		t.Fatal("accepted bogus instance id")
	}
}

// The legacy first instance and an explicitly added second instance must
// coexist with fully disjoint files, service units, interfaces and subnets.
func TestMatrixSecondInstanceCoexistsWithLegacy(t *testing.T) {
	matrixInstanceLab(t)
	port1, port2 := freeUDPPort(t), freeUDPPort(t)
	legacy := matrixLegacyInstance()
	st1 := matrixState{Enabled: true, Role: "hub", Family: "ipv4", Port: port1, Addr: "185.226.119.74", Token: strings.Repeat("a", 64), Ports: []int{18080}, Name: "main", IP: legacy.hubIP()}
	if e := matrixSetup(legacy, st1, ""); e != nil {
		t.Fatal(e)
	}
	next, e := matrixResolveInstance("next")
	if e != nil || next.ID != "matrix2" {
		t.Fatalf("next instance = %+v err=%v", next, e)
	}
	st2 := matrixState{Enabled: true, Role: "hub", Family: "ipv4", Port: port2, Addr: "185.226.119.75", Token: strings.Repeat("b", 64), Ports: []int{18081}, Name: "main", IP: next.hubIP()}
	if e := matrixSetup(next, st2, ""); e != nil {
		t.Fatal(e)
	}
	// Both state files exist and the legacy one is untouched.
	var l1, l2 matrixState
	if b, e := os.ReadFile(matrixStatePath()); e != nil || json.Unmarshal(b, &l1) != nil || !l1.Enabled {
		t.Fatalf("legacy state: %v", e)
	}
	if b, e := os.ReadFile(matrixStatePathOf(next)); e != nil || json.Unmarshal(b, &l2) != nil || !l2.Enabled || l2.Network != "quantum_matrix2" {
		t.Fatalf("second state: %v", e)
	}
	if l1.Network != matrixNetname || l1.Port != port1 || l2.Port != port2 {
		t.Fatal("instance states share mutable fields")
	}
	conf1, _ := os.ReadFile(filepath.Join(matrixDir(), "tinc.conf"))
	conf2, _ := os.ReadFile(filepath.Join(matrixDirOf(next), "tinc.conf"))
	if !strings.Contains(string(conf1), "Interface = qmx0") || strings.Contains(string(conf1), "qmx2") {
		t.Fatal("legacy config iface changed")
	}
	if !strings.Contains(string(conf2), "Interface = qmx2") || strings.Contains(string(conf2), "qmx0") {
		t.Fatal("second instance is not interface-isolated")
	}
	unit2, _ := os.ReadFile(matrixUnitPathOf(next))
	if !strings.Contains(string(unit2), "quantum-matrix2.pid") || !strings.Contains(string(unit2), "matrix2-tinc") || strings.Contains(string(unit2), matrixDir()) {
		t.Fatalf("second unit not isolated:\n%s", unit2)
	}
	if _, e := os.Stat(matrixUnitPath()); e != nil {
		t.Fatal("legacy unit removed")
	}
	// Second removal must not touch the legacy instance.
	if e := matrixRemove(next, l2); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(matrixStatePath()); e != nil {
		t.Fatal("legacy state removed with instance 2")
	}
	if _, e := os.Stat(matrixStatePathOf(next)); !os.IsNotExist(e) {
		t.Fatal("second state remains")
	}
	var still matrixState
	b, _ := os.ReadFile(matrixStatePath())
	_ = json.Unmarshal(b, &still)
	if !still.Enabled || still.Port != port1 {
		t.Fatal("legacy instance mutated by second instance removal")
	}
}

// A new Matrix instance may never take a mesh/user port already owned by
// another topology's tunnel or by another Matrix instance.
// Two hub instances on one server: the registration token selects the instance.
// Multiple topologies on one server are allowed when their tunnels and remote
// endpoints differ; attaching one tunnel to a second topology is refused with
// 409 (exclusive ownership).
// The configured inventory lists every Matrix instance as its own tunnel.

// Every instance in the whole pool derives a disjoint mesh /30, hub IP and
// peer IP; the historic block (matrix2..matrix25) keeps its original
// addresses, and nothing ever lands on the pathtest probe nets (77, 78) or
// the legacy octet 231. The panel's pool must sweep identically — NOT yet
// mirrored there (panel runs the 16-cap 230+N scheme, identical for n <= 25);
// BACKEND-39 candidate.
func TestMatrixInstanceOctetsUniqueAcrossWholePool(t *testing.T) {
	seen := map[int]string{}
	check := func(in matrixInstance, wantSubnet string) {
		if !in.valid() {
			t.Fatalf("instance %s must be valid", in.ID)
		}
		if got := in.subnet(); got != wantSubnet {
			t.Fatalf("%s subnet = %s, want %s", in.ID, got, wantSubnet)
		}
		oct := in.octet()
		if oct == 77 || oct == 78 || oct == 231 {
			t.Fatalf("%s landed on reserved octet %d", in.ID, oct)
		}
		if prev, dup := seen[oct]; dup {
			t.Fatalf("octet %d collides between %s and %s", oct, prev, in.ID)
		}
		seen[oct] = in.ID
	}
	check(matrixLegacyInstance(), matrixSubnet)
	for n := 2; n <= matrixMaxInstances+1; n++ {
		in := matrixInstance{ID: "matrix" + strconv.Itoa(n)}
		want := ""
		switch {
		case n <= 25:
			want = fmt.Sprintf("10.254.%d.0/30", 230+n) // historic block, unchanged
		case n <= 102:
			want = fmt.Sprintf("10.254.%d.0/30", n-26)
		default:
			want = fmt.Sprintf("10.254.%d.0/30", n-24)
		}
		check(in, want)
	}
	if len(seen) != matrixMaxInstances+1 {
		t.Fatalf("pool covers %d octets, want %d", len(seen), matrixMaxInstances+1)
	}
	if !(matrixInstance{ID: "matrix" + strconv.Itoa(matrixMaxInstances+1)}).valid() {
		t.Fatal("top of the pool must be valid")
	}
	if (matrixInstance{ID: "matrix" + strconv.Itoa(matrixMaxInstances+2)}).valid() {
		t.Fatal("instance above the cap accepted")
	}
}
