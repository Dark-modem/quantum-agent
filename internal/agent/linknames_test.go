package agent

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Dark-modem/quantum-agent/internal/infra"
)

func TestLinkNames(t *testing.T) {
	old := infra.ConfigDir
	infra.ConfigDir = t.TempDir()
	t.Cleanup(func() { infra.ConfigDir = old })

	if got := linkLabel("main"); got != "" {
		t.Fatalf("no file: got %q", got)
	}
	if err := setLinkName("main", "  Frankfurt  "); err != nil {
		t.Fatal(err)
	}
	if err := setLinkName("bagher-2", "Helsinki"); err != nil {
		t.Fatal(err)
	}
	if got := linkLabel("main"); got != "Frankfurt" {
		t.Fatalf("main = %q", got)
	}
	for _, key := range []string{"", "peer-1", "bagher-0", "bagher-x", "main "} {
		if setLinkName(key, "x") == nil {
			t.Errorf("key %q accepted", key)
		}
	}
	for _, bad := range []string{"<b>", `a"b`, "a'b", "a\\b", "a\nb", strings.Repeat("ن", 41)} {
		if setLinkName("main", bad) == nil {
			t.Errorf("name %q accepted", bad)
		}
	}
	if err := setLinkName("main", strings.Repeat("ن", 40)); err != nil {
		t.Errorf("40 runes refused: %v", err)
	}
	if err := setLinkName("main", ""); err != nil || linkLabel("main") != "" {
		t.Fatalf("empty name did not clear: %v %q", err, linkLabel("main"))
	}
	dropLinkNames("bagher-")
	if linkLabel("bagher-2") != "" {
		t.Fatal("dropLinkNames left bagher-2")
	}

	rec := httptest.NewRecorder()
	handleLinkName(rec, httptest.NewRequest("POST", "/api/link-name", strings.NewReader(`{"key":"main","name":"Tehran"}`)))
	if rec.Code != 200 || linkLabel("main") != "Tehran" {
		t.Fatalf("handler: %d %s, label %q", rec.Code, rec.Body.String(), linkLabel("main"))
	}
	rec = httptest.NewRecorder()
	handleLinkName(rec, httptest.NewRequest("POST", "/api/link-name", strings.NewReader(`{"key":"peer-3","name":"x"}`)))
	if rec.Code == 200 {
		t.Fatal("handler accepted an unknown key")
	}
}

// TestPatchMainRenameOnly went with peers_edit.go in §6.A3 (its
// handlePeersPatch entry point is deleted dead code).
