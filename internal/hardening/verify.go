// verify.go — the Verify stage. The central check is the SSH banner probe:
// a real TCP dial to 127.0.0.1:<port> that requires an "SSH-" banner, the
// same "verify the exact dependency, not a proxy for it" discipline the
// legacy setup.sh applied to its DNS resolver.

package hardening

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// bannerProbeTimeout is how long the banner probe waits.
const bannerProbeTimeout = 3 * time.Second

// bannerProbe is the seam the SSH path check dials through (tests fake the
// remote side).
var bannerProbe = tcpBanner

// tcpBanner dials addr and reads the first line.
func tcpBanner(addr string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// probeSSHBanner dials 127.0.0.1:port through the seam and checks the
// "SSH-" prefix. Refused connections are a failure (sshd must be listening
// on the ports we intend to keep).
func probeSSHBanner(port int) (string, error) {
	banner, err := bannerProbe(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), bannerProbeTimeout)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(banner, "SSH-") {
		return "", fmt.Errorf("connected, but the service did not answer with an SSH banner (got %q)", truncate(banner, 40))
	}
	return banner, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// verifySSHPath probes every port; the first failure becomes the Detail.
func verifySSHPath(ports []int) *VerifyResult {
	var names []string
	for _, p := range ports {
		if _, err := probeSSHBanner(p); err != nil {
			return &VerifyResult{ItemID: "ssh.path", OK: false, Detail: fmt.Sprintf("port %d: %v", p, err)}
		}
		names = append(names, strconv.Itoa(p))
	}
	return &VerifyResult{ItemID: "ssh.path", OK: true, Detail: "SSH banner ok on " + strings.Join(names, ", ")}
}

// verifyItem verifies one applied non-risky item (risky items verify inside
// the safe-apply path). nil = no check for this kind (already covered).
func verifyItem(ctx context.Context, it PlanItem) *VerifyResult {
	switch it.Kind {
	case KindSysctl:
		return nil // read-verified inside applySysctlSet
	case KindFail2Ban:
		if strings.HasSuffix(it.ID, ":remove") {
			_, err := os.Stat(fail2banJailPath)
			return &VerifyResult{ItemID: it.ID, OK: err != nil}
		}
		out, err := run(ctx, "systemctl", "is-active", "fail2ban")
		ok := err == nil && strings.TrimSpace(string(out)) == "active"
		return &VerifyResult{ItemID: it.ID, OK: ok, Detail: strings.TrimSpace(string(out))}
	case KindTimeSync:
		out, err := run(ctx, "timedatectl", "show", "-p", "NTPActive", "--value")
		ok := err == nil && strings.TrimSpace(string(out)) == "yes"
		return &VerifyResult{ItemID: it.ID, OK: ok, Detail: strings.TrimSpace(string(out))}
	case KindJournald:
		_, err := os.Stat(journaldLogDir)
		return &VerifyResult{ItemID: it.ID, OK: err == nil, Detail: journaldLogDir}
	}
	return nil
}

// sshdValidate runs `sshd -t` (config gate before any reload).
func sshdValidate(ctx context.Context) error {
	_, err := run(ctx, "sshd", "-t")
	if err == nil {
		return nil
	}
	var execErr *exec.Error
	if errors.As(err, &execErr) {
		// Some minimal images only expose /usr/sbin/sshd.
		if _, err2 := run(ctx, "/usr/sbin/sshd", "-t"); err2 == nil {
			return nil
		}
		return errors.New("sshd binary not found; cannot validate the config")
	}
	return fmt.Errorf("sshd -t failed: %s", strings.TrimSpace(err.Error()))
}

// sshdReload reloads (NEVER restarts) the SSH service. A reload keeps every
// established session; a restart can cut the operator's only way back in.
func sshdReload(ctx context.Context) error {
	svc := sshServiceName(ctx)
	if _, err := run(ctx, "systemctl", "reload", svc); err == nil {
		return nil
	}
	// Some units lack a reload verb; reload-or-restart still prefers reload.
	if _, err := run(ctx, "systemctl", "reload-or-restart", svc); err != nil {
		return fmt.Errorf("systemctl reload %s failed: %v", svc, err)
	}
	return nil
}
