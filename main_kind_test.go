package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"go.icco.me/reportd/pkg/db"
	"gorm.io/gorm"
)

const (
	nelOK      = `{"type":"network-error","age":0,"url":"https://api.example.com/v1/ping","body":{"type":"ok","phase":"application","elapsed_time":40,"sampling_fraction":0.01,"method":"GET","protocol":"h2","server_ip":"203.0.113.1","status_code":200}}`
	nelTimeout = `{"type":"network-error","age":0,"url":"https://api.example.com/v1/pay","body":{"type":"tcp.timed_out","phase":"connection","elapsed_time":30000,"sampling_fraction":1,"method":"POST","protocol":"","server_ip":"203.0.113.1","status_code":0}}`
	cspEntry   = `{"type":"csp","age":0,"url":"https://www.example.com/","body":{"blockedURL":"https://evil.example/x.js","effectiveDirective":"script-src"}}`
)

// newKindTestRouter makes an app project "site" and an API project "api".
func newKindTestRouter(t *testing.T) (http.Handler, *gorm.DB, *projectStore, *db.Writer) {
	t.Helper()
	h, pgDB, projects, ingest := newProjectTestRouter(t, "site")
	if err := projects.Create(context.Background(), "api", db.KindAPI); err != nil {
		t.Fatalf("Create(api) error = %v", err)
	}
	return h, pgDB, projects, ingest
}

func flushIngest(t *testing.T, ingest *db.Writer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := ingest.Flush(ctx); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
}

func countRows(t *testing.T, pgDB *gorm.DB, model any, service string) int64 {
	t.Helper()
	var n int64
	if err := pgDB.Model(model).Where("service = ?", service).Count(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func TestAPIProjectAcceptsOnlyNetworkErrors(t *testing.T) {
	h, pgDB, _, ingest := newKindTestRouter(t)

	cases := []struct {
		name, path, contentType, body string
		want                          int
	}{
		{"vitals", "/analytics/api", "application/json", testVital, http.StatusUnprocessableEntity},
		{"reporting v1", "/reporting/api", "application/reports+json", "[" + testReport + "]", http.StatusUnprocessableEntity},
		{"legacy csp", "/report/api", "application/csp-report", `{"csp-report":{"document-uri":"https://example.com/"}}`, http.StatusUnprocessableEntity},
		{"report-to without nel", "/report/api", "application/reports+json", "[" + cspEntry + "]", http.StatusUnprocessableEntity},
		{"mixed batch", "/report/api", "application/reports+json", "[" + nelOK + "," + cspEntry + "," + nelTimeout + "]", http.StatusNoContent},
		{"app still takes vitals", "/analytics/site", "application/json", testVital, http.StatusNoContent},
		{"app still takes csp", "/report/site", "application/reports+json", "[" + cspEntry + "]", http.StatusNoContent},
	}
	for _, tc := range cases {
		if rec := request(h, http.MethodPost, tc.path, tc.contentType, tc.body); rec.Code != tc.want {
			t.Errorf("%s: status = %d, want %d (%s)", tc.name, rec.Code, tc.want, rec.Body.String())
		}
	}

	flushIngest(t, ingest)

	if n := countRows(t, pgDB, &db.WebVital{}, "api"); n != 0 {
		t.Errorf("api project stored %d web vitals, want 0", n)
	}
	var rows []db.ReportToEntry
	if err := pgDB.Where("service = ?", "api").Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("find: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("api project stored %d report-to rows, want the 2 NEL ones", len(rows))
	}
	ok, timeout := rows[0], rows[1]
	if ok.NELType != "ok" || ok.SamplingFraction != 0.01 || ok.ElapsedTime != 40 || ok.StatusCode != 200 || ok.Method != "GET" {
		t.Errorf("ok row = %+v", ok)
	}
	if timeout.NELType != "tcp.timed_out" || timeout.Phase != "connection" || timeout.DocumentURI != "https://api.example.com/v1/pay" {
		t.Errorf("timeout row = %+v", timeout)
	}
}

func TestTokenURLs(t *testing.T) {
	h, pgDB, projects, ingest := newKindTestRouter(t)
	token := projects.Token("site")
	if len(token) < 20 {
		t.Fatalf("Token(site) = %q, want a long random token", token)
	}
	if strings.Contains(token, "site") {
		t.Error("token must not reveal the project name")
	}

	q := "?s=" + url.QueryEscape(token)
	if rec := request(h, http.MethodPost, "/analytics"+q, "application/json", testVital); rec.Code != http.StatusNoContent {
		t.Errorf("token analytics: status = %d, want 204", rec.Code)
	}
	if rec := request(h, http.MethodPost, "/reporting"+q, "application/reports+json", "["+testReport+"]"); rec.Code != http.StatusNoContent {
		t.Errorf("token reporting: status = %d, want 204", rec.Code)
	}
	if rec := request(h, http.MethodPost, "/report"+q, "application/reports+json", "["+nelOK+"]"); rec.Code != http.StatusNoContent {
		t.Errorf("token report: status = %d, want 204", rec.Code)
	}
	if rec := request(h, http.MethodPost, "/analytics?s="+url.QueryEscape(projects.Token("api")), "application/json", testVital); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("token analytics for api project: status = %d, want 422", rec.Code)
	}
	for _, path := range []string{"/analytics?s=nope", "/analytics"} {
		if rec := request(h, http.MethodPost, path, "application/json", testVital); rec.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", path, rec.Code)
		}
	}

	flushIngest(t, ingest)
	if n := countRows(t, pgDB, &db.WebVital{}, "site"); n != 1 {
		t.Errorf("stored %d vitals for site, want 1", n)
	}

	// Rotating revokes the old token at once.
	if err := projects.RotateToken(context.Background(), "site"); err != nil {
		t.Fatalf("RotateToken() error = %v", err)
	}
	if rec := request(h, http.MethodPost, "/analytics"+q, "application/json", testVital); rec.Code != http.StatusNotFound {
		t.Errorf("old token after rotation: status = %d, want 404", rec.Code)
	}
	fresh := "?s=" + url.QueryEscape(projects.Token("site"))
	if rec := request(h, http.MethodPost, "/analytics"+fresh, "application/json", testVital); rec.Code != http.StatusNoContent {
		t.Errorf("new token: status = %d, want 204", rec.Code)
	}

	// The rotation survives a reload from the database.
	before := projects.Token("site")
	if err := projects.Reload(context.Background()); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if projects.Token("site") != before {
		t.Error("rotated token was not persisted")
	}

	// With name URLs switched off only the token form works.
	projects.nameURLs = false
	if rec := request(h, http.MethodPost, "/analytics/site", "application/json", testVital); rec.Code != http.StatusNotFound {
		t.Errorf("name URL when disabled: status = %d, want 404", rec.Code)
	}
	if rec := request(h, http.MethodPost, "/analytics"+fresh, "application/json", testVital); rec.Code != http.StatusNoContent {
		t.Errorf("token URL when names disabled: status = %d, want 204", rec.Code)
	}
}

// Projects from before tokens existed get one at startup.
func TestExistingProjectsGetTokens(t *testing.T) {
	_, pgDB, _, _ := newProjectTestRouter(t)
	if err := pgDB.Create(&db.Project{Name: "old", CreatedAt: time.Now(), Kind: db.KindApp}).Error; err != nil {
		t.Fatalf("insert: %v", err)
	}
	projects, err := newProjectStore(context.Background(), pgDB)
	if err != nil {
		t.Fatalf("newProjectStore() error = %v", err)
	}
	if projects.Token("old") == "" || projects.Kind("old") != db.KindApp {
		t.Errorf("old project: token %q kind %q", projects.Token("old"), projects.Kind("old"))
	}
}

func TestCreateProjectKind(t *testing.T) {
	h, _, projects, _ := newProjectTestRouter(t)

	rec := request(h, http.MethodPost, "/projects", "application/x-www-form-urlencoded", "name=svc&kind=api")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/view/svc" {
		t.Fatalf("create: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if projects.Kind("svc") != db.KindAPI {
		t.Errorf("Kind(svc) = %q, want api", projects.Kind("svc"))
	}

	rec = request(h, http.MethodPost, "/projects", "application/x-www-form-urlencoded", "name=other&kind=bogus")
	if rec.Header().Get("Location") != "/?error=kind" || projects.Has("other") {
		t.Errorf("bogus kind: location %q, created %v", rec.Header().Get("Location"), projects.Has("other"))
	}

	rec = request(h, http.MethodPost, "/projects", "application/x-www-form-urlencoded", "name=plain")
	if projects.Kind("plain") != db.KindApp {
		t.Errorf("default kind = %q, want app", projects.Kind("plain"))
	}

	page := request(h, http.MethodGet, "/view/svc", "", "").Body.String()
	if !strings.Contains(page, `id="network-section"`) || strings.Contains(page, `id="vitals"`) {
		t.Error("api project page should show the network panel and no vitals")
	}
	if !strings.Contains(page, projects.Token("svc")) {
		t.Error("project page should carry the token for the setup snippets")
	}
}

// The success rate weights each report by 1/sampling_fraction.
func TestNetworkSummaryWeighting(t *testing.T) {
	h, pgDB, _, ingest := newKindTestRouter(t)
	body := "[" + nelOK + "," + nelOK + "," + nelTimeout + "]"
	if rec := request(h, http.MethodPost, "/report/api", "application/reports+json", body); rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rec.Code)
	}
	flushIngest(t, ingest)

	s, err := db.GetNetworkSummary(context.Background(), pgDB, "api")
	if err != nil {
		t.Fatalf("GetNetworkSummary() error = %v", err)
	}
	// Two sampled successes at 1% stand for 200 requests, plus one failure.
	if s.Requests < 200.9 || s.Requests > 201.1 || s.OK < 199.9 || s.OK > 200.1 {
		t.Errorf("requests %.2f ok %.2f, want 201 and 200", s.Requests, s.OK)
	}
	if len(s.ByType) != 1 || s.ByType[0].Key != "tcp.timed_out" || s.ByType[0].Reports != 1 {
		t.Errorf("ByType = %+v", s.ByType)
	}
	if len(s.ByPhase) != 1 || s.ByPhase[0].Key != "connection" {
		t.Errorf("ByPhase = %+v", s.ByPhase)
	}
	if len(s.RecentFailures) != 1 || s.AvgElapsedOK != 40 || s.AvgElapsedFailed != 30000 {
		t.Errorf("recent %d, elapsed ok %.0f failed %.0f", len(s.RecentFailures), s.AvgElapsedOK, s.AvgElapsedFailed)
	}

	if rec := request(h, http.MethodGet, "/api/network/api", "", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"by_type"`) {
		t.Errorf("GET /api/network/api: %d %s", rec.Code, rec.Body.String())
	}
}

// NEL rows stored before the NEL columns existed are filled from raw JSON.
func TestBackfillNELFields(t *testing.T) {
	_, pgDB, _, _ := newProjectTestRouter(t)
	row := db.ReportToEntry{CreatedAt: time.Now(), Service: "api", ReportType: db.ReportTypeNetworkError, RawJSON: db.JSONText(nelTimeout)}
	if err := pgDB.Create(&row).Error; err != nil {
		t.Fatalf("insert: %v", err)
	}
	n, err := db.BackfillNELFields(context.Background(), pgDB)
	if err != nil || n != 1 {
		t.Fatalf("BackfillNELFields() = %d, %v; want 1", n, err)
	}
	var got db.ReportToEntry
	pgDB.First(&got, row.ID)
	if got.NELType != "tcp.timed_out" || got.Phase != "connection" || got.ElapsedTime != 30000 {
		t.Errorf("backfilled row = %+v", got)
	}
	if n, _ := db.BackfillNELFields(context.Background(), pgDB); n != 0 {
		t.Errorf("second backfill updated %d rows, want 0", n)
	}
}

// Recent failures carry the reporter's address from CF-Connecting-IP; a
// header that is not an IP is dropped rather than stored.
func TestNetworkFailureClientIP(t *testing.T) {
	h, pgDB, _, ingest := newKindTestRouter(t)
	for _, ip := range []string{"198.51.100.7", "not-an-ip"} {
		req := httptest.NewRequest(http.MethodPost, "/report/api", strings.NewReader("["+nelTimeout+"]"))
		req.Header.Set("Content-Type", "application/reports+json")
		req.Header.Set("CF-Connecting-IP", ip)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d", rec.Code)
		}
	}
	flushIngest(t, ingest)

	s, err := db.GetNetworkSummary(context.Background(), pgDB, "api")
	if err != nil {
		t.Fatalf("GetNetworkSummary() error = %v", err)
	}
	var got []string
	for _, f := range s.RecentFailures {
		got = append(got, f.ClientIP)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"", "198.51.100.7"}) {
		t.Errorf("client IPs = %q, want one 198.51.100.7 and one empty", got)
	}
}
