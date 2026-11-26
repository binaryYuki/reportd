package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.icco.me/reportd/pkg/auth"
	"go.icco.me/reportd/pkg/db"
	"gorm.io/gorm"
)

func newAuthedTestRouter(t *testing.T) http.Handler {
	t.Helper()
	ctx := context.Background()
	pgDB, err := db.Connect(ctx, "sqlite://"+filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if err := db.AutoMigrate(ctx, pgDB); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}

	authn, err := newAuthenticator("id", "secret", "me@example.com", strings.Repeat("k", 32), nil)
	if err != nil {
		t.Fatalf("newAuthenticator() error = %v", err)
	}
	ingest := db.NewWriter(pgDB, db.WriterOptions{})
	t.Cleanup(func() { _ = ingest.Close(context.Background()) })
	return newRouter(pgDB, ingest, nil, nil, nil, authn, nil)
}

// The dashboard must be closed to anonymous visitors while ingestion stays
// open: browsers post reports without credentials.
func TestRouterAuthGating(t *testing.T) {
	h := newAuthedTestRouter(t)

	tests := []struct {
		method, path string
		contentType  string
		body         string
		want         int
	}{
		{method: http.MethodGet, path: "/", want: http.StatusFound},
		{method: http.MethodGet, path: "/view/site", want: http.StatusFound},
		{method: http.MethodGet, path: "/services", want: http.StatusUnauthorized},
		{method: http.MethodGet, path: "/reports/site", want: http.StatusUnauthorized},
		{method: http.MethodGet, path: "/analytics/site", want: http.StatusUnauthorized},
		{method: http.MethodGet, path: "/api/vitals/site", want: http.StatusUnauthorized},
		{method: http.MethodGet, path: "/api/reports/site", want: http.StatusUnauthorized},

		{method: http.MethodGet, path: "/api/status", want: http.StatusOK},
		{method: http.MethodGet, path: "/robots.txt", want: http.StatusOK},
		// The sign-in page renders; it does not bounce to GitHub by itself.
		{method: http.MethodGet, path: auth.LoginPath, want: http.StatusOK},
		{
			method: http.MethodPost, path: "/analytics/site", contentType: "application/json",
			body: `{"name":"LCP","value":1200.5,"delta":1200.5,"id":"v5-1","label":"web-vital"}`,
			want: http.StatusNoContent,
		},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d; body %q", rec.Code, tt.want, rec.Body)
			}
		})
	}
}

func TestNewAuthenticatorRequiresConfig(t *testing.T) {
	if _, err := newAuthenticator("", "", "", "", nil); err == nil {
		t.Fatal("newAuthenticator() error = nil, want an error when GitHub OAuth is unconfigured")
	}
	// An unset session secret is generated rather than rejected.
	if _, err := newAuthenticator("id", "secret", "me@example.com", "", nil); err != nil {
		t.Fatalf("newAuthenticator() with generated secret error = %v", err)
	}
}

func TestEnforceStorageLimitLoopPrunesAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d, err := db.Connect(ctx, "sqlite://"+filepath.Join(t.TempDir(), "loop.db"))
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if err := db.AutoMigrate(ctx, d); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}

	rows := make([]*db.WebVital, 0, 2000)
	for i := range 2000 {
		rows = append(rows, &db.WebVital{
			CreatedAt: time.Now().Add(time.Duration(i) * time.Second),
			Service:   "svc", Name: "LCP", Value: 1, Label: strings.Repeat("x", 512),
		})
	}
	if err := d.CreateInBatches(rows, 200).Error; err != nil {
		t.Fatalf("seeding rows: %v", err)
	}
	before, err := db.StorageBytes(ctx, d)
	if err != nil {
		t.Fatalf("StorageBytes() error = %v", err)
	}

	done := make(chan struct{})
	go func() {
		enforceStorageLimitLoop(ctx, d, before/2, time.Hour)
		close(done)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		var n int64
		if err := d.Unscoped().Model(&db.WebVital{}).Count(&n).Error; err != nil {
			t.Fatalf("counting rows: %v", err)
		}
		if n < 2000 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the loop never pruned")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop did not stop when its context was cancelled")
	}
}

// newProjectTestRouter builds a router backed by a project store holding
// the given names.
func newProjectTestRouter(t *testing.T, names ...string) (http.Handler, *gorm.DB, *projectStore, *db.Writer) {
	t.Helper()
	ctx := context.Background()
	pgDB, err := db.Connect(ctx, "sqlite://"+filepath.Join(t.TempDir(), "projects.db"))
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if err := db.AutoMigrate(ctx, pgDB); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}
	for _, name := range names {
		if err := db.CreateProject(ctx, pgDB, name, db.KindApp); err != nil {
			t.Fatalf("CreateProject(%q) error = %v", name, err)
		}
	}
	projects, err := newProjectStore(ctx, pgDB)
	if err != nil {
		t.Fatalf("newProjectStore() error = %v", err)
	}
	ingest := db.NewWriter(pgDB, db.WriterOptions{})
	t.Cleanup(func() { _ = ingest.Close(context.Background()) })
	return newRouter(pgDB, ingest, nil, nil, nil, nil, projects), pgDB, projects, ingest
}

func request(h http.Handler, method, path, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const (
	testVital  = `{"name":"LCP","value":1200.5,"delta":1200.5,"id":"v5-1","label":"web-vital"}`
	testReport = `{"type":"crash","url":"https://example.com/","body":{"reason":"oom"}}`
	formType   = "application/x-www-form-urlencoded"
)

// Only projects in the database exist: other names are refused on every
// route, including ingestion, so posting to a new name cannot create one.
func TestProjectAllowlist(t *testing.T) {
	ctx := context.Background()
	h, pgDB, _, ingest := newProjectTestRouter(t, "blog", "shop")
	// Data stored under a name that is not a project must not resurface.
	if err := pgDB.Create(&db.WebVital{CreatedAt: time.Now(), Service: "legacy", Name: "LCP", Value: 1}).Error; err != nil {
		t.Fatalf("seeding: %v", err)
	}

	tests := []struct {
		method, path, contentType, body string
		want                            int
	}{
		{http.MethodPost, "/analytics/blog", "application/json", testVital, http.StatusNoContent},
		{http.MethodPost, "/reporting/shop", "application/reports+json", testReport, http.StatusNoContent},
		{http.MethodGet, "/view/blog", "", "", http.StatusOK},
		{http.MethodGet, "/api/vitals/shop", "", "", http.StatusOK},

		{http.MethodPost, "/analytics/stranger", "application/json", testVital, http.StatusNotFound},
		{http.MethodPost, "/reporting/stranger", "application/reports+json", testReport, http.StatusNotFound},
		{http.MethodPost, "/report/stranger", "application/reports+json", "[]", http.StatusNotFound},
		{http.MethodOptions, "/analytics/stranger", "", "", http.StatusNotFound},
		{http.MethodGet, "/view/legacy", "", "", http.StatusNotFound},
		{http.MethodGet, "/api/reports/legacy", "", "", http.StatusNotFound},
		{http.MethodPost, "/projects/stranger/delete", formType, "", http.StatusNotFound},
		// Malformed names keep their 400.
		{http.MethodPost, "/analytics/bad.name", "application/json", testVital, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			if rec := request(h, tt.method, tt.path, tt.contentType, tt.body); rec.Code != tt.want {
				t.Errorf("status = %d, want %d; body %q", rec.Code, tt.want, rec.Body)
			}
		})
	}

	if err := ingest.Flush(ctx); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	var strangers int64
	if err := pgDB.Model(&db.WebVital{}).Where("service = ?", "stranger").Count(&strangers).Error; err != nil {
		t.Fatalf("counting: %v", err)
	}
	if strangers != 0 {
		t.Errorf("rows stored for an unknown project = %d, want 0", strangers)
	}

	if got := strings.TrimSpace(request(h, http.MethodGet, "/services", "", "").Body.String()); got != `["blog","shop"]` {
		t.Errorf("/services = %s, want [\"blog\",\"shop\"]", got)
	}

	rec := request(h, http.MethodGet, "/", "", "")
	page := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("index status = %d, want 200", rec.Code)
	}
	if strings.Contains(page, "legacy") {
		t.Error("index shows data for a name that is not a project")
	}
	if strings.Contains(page, "Source on GitHub") {
		t.Error("index still shows the old subtitle")
	}
	// 1 vital (blog) + 1 report (shop); the legacy row belongs to no project.
	for _, want := range []string{
		`<span class="text-blue-500" title="总数">2</span>`,
		`<span class="text-green-500" title="性能指标（Web Vitals）">1</span>`,
		`<span class="text-red-500" title="浏览器报告（CSP 违规、崩溃等）">1</span>`,
		"全部数据：",
		`href="/view/blog"`,
		`href="/view/shop"`,
		`action="/projects"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("index is missing %q", want)
		}
	}
}

// With no projects nothing is counted and nothing is accepted.
func TestNoProjects(t *testing.T) {
	h, pgDB, _, _ := newProjectTestRouter(t)
	if err := pgDB.Create(&db.WebVital{CreatedAt: time.Now(), Service: "legacy", Name: "LCP", Value: 1}).Error; err != nil {
		t.Fatalf("seeding: %v", err)
	}

	if rec := request(h, http.MethodPost, "/analytics/blog", "application/json", testVital); rec.Code != http.StatusNotFound {
		t.Errorf("POST with no projects: status = %d, want 404", rec.Code)
	}
	page := request(h, http.MethodGet, "/", "", "").Body.String()
	if !strings.Contains(page, "还没有项目") {
		t.Error("index should explain that there are no projects yet")
	}
	if !strings.Contains(page, `<span class="text-blue-500" title="总数">0</span>`) {
		t.Error("index should count nothing when there are no projects")
	}
}

func TestCreateAndDeleteProject(t *testing.T) {
	ctx := context.Background()
	h, pgDB, projects, ingest := newProjectTestRouter(t)

	// Invalid names are refused and explained.
	for _, name := range []string{"", "bad.name", strings.Repeat("x", 33)} {
		rec := request(h, http.MethodPost, "/projects", formType, "name="+name)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/?error=name" {
			t.Errorf("create %q: %d -> %q, want 303 -> /?error=name", name, rec.Code, rec.Header().Get("Location"))
		}
	}
	if page := request(h, http.MethodGet, "/?error=name", "", "").Body.String(); !strings.Contains(page, "项目名只能包含") {
		t.Error("index should explain a rejected project name")
	}

	// Creating a project makes it accept reports at once, and persists it.
	rec := request(h, http.MethodPost, "/projects", formType, "name=blog")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/view/blog" {
		t.Fatalf("create: %d -> %q, want 303 -> /view/blog", rec.Code, rec.Header().Get("Location"))
	}
	if rec := request(h, http.MethodPost, "/projects", formType, "name=blog"); rec.Code != http.StatusSeeOther {
		t.Errorf("creating an existing project: status = %d, want 303", rec.Code)
	}
	if rec := request(h, http.MethodPost, "/analytics/blog", "application/json", testVital); rec.Code != http.StatusNoContent {
		t.Fatalf("POST to the new project: status = %d, want 204", rec.Code)
	}
	if err := ingest.Flush(ctx); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	stored, err := db.ListProjects(ctx, pgDB)
	if err != nil || len(stored) != 1 || stored[0] != "blog" {
		t.Fatalf("ListProjects() = %v, %v; want [blog]", stored, err)
	}

	// A cross-site form post is refused.
	req := httptest.NewRequest(http.MethodPost, "/projects/blog/delete", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	cross := httptest.NewRecorder()
	h.ServeHTTP(cross, req)
	if cross.Code != http.StatusForbidden || !projects.Has("blog") {
		t.Fatalf("cross-site delete: status = %d, project kept = %v; want 403 and kept", cross.Code, projects.Has("blog"))
	}

	// Deleting stops ingestion immediately and purges the data.
	done := make(chan struct{})
	if err := projects.Delete(ctx, "blog", done); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if rec := request(h, http.MethodPost, "/analytics/blog", "application/json", testVital); rec.Code != http.StatusNotFound {
		t.Errorf("POST after delete: status = %d, want 404", rec.Code)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("purge did not finish")
	}
	var rows int64
	if err := pgDB.Unscoped().Model(&db.WebVital{}).Where("service = ?", "blog").Count(&rows).Error; err != nil {
		t.Fatalf("counting: %v", err)
	}
	if rows != 0 {
		t.Errorf("rows left after deleting the project = %d, want 0", rows)
	}

	// The delete route itself: recreate, delete over HTTP, land on the index.
	request(h, http.MethodPost, "/projects", formType, "name=shop")
	rec = request(h, http.MethodPost, "/projects/shop/delete", formType, "")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" || projects.Has("shop") {
		t.Errorf("delete route: %d -> %q, still a project = %v", rec.Code, rec.Header().Get("Location"), projects.Has("shop"))
	}
}

// Changes made directly in the database show up after a reload.
func TestProjectStoreReload(t *testing.T) {
	ctx := context.Background()
	_, pgDB, projects, _ := newProjectTestRouter(t, "blog")

	if err := db.CreateProject(ctx, pgDB, "added-elsewhere", db.KindApp); err != nil {
		t.Fatalf("CreateProject() error = %v", err)
	}
	if projects.Has("added-elsewhere") {
		t.Fatal("store saw the new project before reloading")
	}
	if err := projects.Reload(ctx); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if got := strings.Join(projects.List(), ","); got != "added-elsewhere,blog" {
		t.Errorf("List() after reload = %q, want added-elsewhere,blog", got)
	}
}

func TestLoginPageRenders(t *testing.T) {
	h := newAuthedTestRouter(t)
	rec := request(h, http.MethodGet, auth.LoginPath+"?next=%2Fview%2Fblog", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"使用 GitHub 登录", `action="/auth/login"`, `name="next" value="/view/blog"`} {
		if !strings.Contains(body, want) {
			t.Errorf("login page is missing %q", want)
		}
	}
	if strings.Contains(body, "github.com/login") {
		t.Error("login page must not link or redirect to GitHub directly")
	}
}

// The dashboard reports its own Web Vitals only once a "reportd" project
// exists: otherwise the request is rejected on every page view.
func TestSelfReportNeedsProject(t *testing.T) {
	// html/template escapes "/" inside JS strings.
	const beacon = `sendBeacon('\/analytics?s=`

	h, _, _, _ := newProjectTestRouter(t, "blog")
	if body := request(h, http.MethodGet, "/", "", "").Body.String(); strings.Contains(body, beacon) {
		t.Error("page self-reports although the project does not exist")
	}

	h, _, _, _ = newProjectTestRouter(t, "blog", selfReportProject)
	if body := request(h, http.MethodGet, "/", "", "").Body.String(); !strings.Contains(body, beacon) {
		t.Error("page does not self-report although the project exists")
	}
}

// Flushing deletes a project's stored data but keeps the project, its
// token and ingestion; cross-site posts are refused.
func TestFlushProject(t *testing.T) {
	ctx := context.Background()
	h, pgDB, projects, ingest := newProjectTestRouter(t, "blog", "shop")
	token := projects.Token("blog")
	for _, svc := range []string{"blog", "shop"} {
		if rec := request(h, http.MethodPost, "/analytics/"+svc, "application/json", testVital); rec.Code != http.StatusNoContent {
			t.Fatalf("POST /analytics/%s: status = %d", svc, rec.Code)
		}
	}
	if err := ingest.Flush(ctx); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	count := func(svc string) int64 {
		t.Helper()
		var n int64
		if err := pgDB.Unscoped().Model(&db.WebVital{}).Where("service = ?", svc).Count(&n).Error; err != nil {
			t.Fatalf("counting: %v", err)
		}
		return n
	}

	req := httptest.NewRequest(http.MethodPost, "/projects/blog/flush", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	cross := httptest.NewRecorder()
	h.ServeHTTP(cross, req)
	if cross.Code != http.StatusForbidden {
		t.Fatalf("cross-site flush: status = %d, want 403", cross.Code)
	}

	rec := request(h, http.MethodPost, "/projects/blog/flush", formType, "")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/view/blog?flushed=1" {
		t.Fatalf("flush route: %d -> %q", rec.Code, rec.Header().Get("Location"))
	}
	deadline := time.Now().Add(5 * time.Second)
	for projects.Flushing("blog") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if projects.Flushing("blog") {
		t.Fatal("flush did not finish")
	}
	if n := count("blog"); n != 0 {
		t.Errorf("blog rows after flush = %d, want 0", n)
	}
	if n := count("shop"); n != 1 {
		t.Errorf("shop rows after flushing blog = %d, want 1", n)
	}
	if !projects.Has("blog") || projects.Token("blog") != token {
		t.Error("flush should keep the project and its token")
	}
	if rec := request(h, http.MethodPost, "/analytics/blog", "application/json", testVital); rec.Code != http.StatusNoContent {
		t.Errorf("POST after flush: status = %d, want 204", rec.Code)
	}
	if page := request(h, http.MethodGet, "/view/blog?flushed=1", "", "").Body.String(); !strings.Contains(page, "数据已清空") {
		t.Error("project page should confirm the flush")
	}
}
