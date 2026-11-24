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

	authn, err := newAuthenticator("id", "secret", "me@example.com", strings.Repeat("k", 32))
	if err != nil {
		t.Fatalf("newAuthenticator() error = %v", err)
	}
	ingest := db.NewWriter(pgDB, db.WriterOptions{})
	t.Cleanup(func() { _ = ingest.Close(context.Background()) })
	return newRouter(pgDB, ingest, nil, nil, nil, authn)
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
		{method: http.MethodGet, path: auth.LoginPath, want: http.StatusFound},
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
	if _, err := newAuthenticator("", "", "", ""); err == nil {
		t.Fatal("newAuthenticator() error = nil, want an error when GitHub OAuth is unconfigured")
	}
	// An unset session secret is generated rather than rejected.
	if _, err := newAuthenticator("id", "secret", "me@example.com", ""); err != nil {
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
