package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// Browsers preflight cross-origin reports (application/reports+json is not
// a simple content type) and drop the report unless the preflight succeeds.
// The preflight carries neither the body nor, for token URLs, anything the
// routes could validate, so it must be answered before routing.
func TestCORSPreflight(t *testing.T) {
	h, _, projects, _ := newKindTestRouter(t)
	q := "?s=" + url.QueryEscape(projects.Token("api"))

	for _, path := range []string{
		"/report" + q, "/reporting" + q, "/analytics" + q,
		"/report/api", "/reporting/site", "/analytics/site",
	} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodOptions, path, nil)
			req.Header.Set("Origin", "https://www.example.com")
			req.Header.Set("Access-Control-Request-Method", http.MethodPost)
			req.Header.Set("Access-Control-Request-Headers", "content-type")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code < 200 || rec.Code > 299 {
				t.Errorf("status = %d, want 2xx; body %q", rec.Code, rec.Body)
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
				t.Errorf("Access-Control-Allow-Origin = %q, want *", got)
			}
			if got := rec.Header().Get("Access-Control-Allow-Methods"); got != http.MethodPost {
				t.Errorf("Access-Control-Allow-Methods = %q, want POST", got)
			}
		})
	}
}
