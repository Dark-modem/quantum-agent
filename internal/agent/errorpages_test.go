package agent

// errorpages_test.go — the branded HTML error pages must appear for browser
// page navigations only: every API path, non-HTML client and non-error status
// passes through byte-for-byte (API errors stay JSON — hard requirement).

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// errorPagesCodes is the full required catalog: every handled code must
// render the branded page with a Persian title, its number and the ref id.
var errorPagesCodes = []int{
	400, 401, 403, 404, 405, 408, 409, 413, 422, 429, 500, 502, 503, 504,
}

func errorPagesRequest(t *testing.T, accept, path string) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if accept != "" {
		r.Header.Set("Accept", accept)
	}
	return r, httptest.NewRecorder()
}
