package agent

import (
	"os"
	"testing"
)

func readUI(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Nothing in the panel renders below the 12px project minimum.
// White text sits on --ac-fill, which the default blue darkens to 5.5:1; a raw
// var(--ac) fill under --ac-on is 3.6:1.
// Every text field in the static markup has an accessible name.
// With no saved choice the theme follows the system appearance.
// Colors assigned from JS (el.style.color = ...) follow the same rule.
// Colors come from tokens.css: hard-coded colors break the light theme and the
// accent presets. White text on a status fill is the only literal allowed.
// Icons come from the SVG sprite (#i-*), not emoji: emoji render differently on
// every OS, cannot follow the theme color and read as noise in labels.
// The typographic marks check and cross stay.
// A var(--x) that nobody defines silently falls back to the property's initial
// value (square corners, transparent borders); every token used must exist.
// Rem sizes count too: 0.75rem is the 12px floor.
// Styling lives in classes; inline style is only for values computed at runtime
// and a few one-off positions.
// Modals open through modalShow/trapModal so Escape closes them, Tab stays
// inside and focus returns to the opener; flipping .hidden directly skips that.
// A handler referenced but never defined throws at load and stops the rest of
// app.js from running (sshfwdClearDnatClick once took Cluster down).
// Stray control characters (a backspace where a regex \b was meant) break code silently.
