package agent

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// faText loads the Persian phrase map from i18n-fa.js (window.FA_TEXT = {...};).
func faText(t *testing.T) map[string]string {
	t.Helper()
	src := readUI(t, "i18n-fa.js")
	i := strings.Index(src, "window.FA_TEXT = ")
	if i < 0 {
		t.Fatal("i18n-fa.js must assign window.FA_TEXT")
	}
	body := strings.TrimSuffix(strings.TrimSpace(src[i+len("window.FA_TEXT = "):]), ";")
	m := map[string]string{}
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("i18n-fa.js is not a JSON object: %v", err)
	}
	return m
}

var persian = regexp.MustCompile(`[\x{0600}-\x{06FF}]`)

// Every Persian entry is Persian (a copied English value would silently show English).
// Every keyed English string has a Persian phrase, except technical names that stay Latin.
// The phrase file is served and embedded like app.js.
// UI source text is English; Persian lives only in i18n-fa.js. Persian written into
// the markup or app.js shows untranslated to English users.
// A Persian phrase must not hold its own English key: the page translates text
// it shows, so "Path" -> "مسیر (Path)" grows forever and freezes the browser.
