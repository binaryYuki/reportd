package db

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// Skipped unless TEST_MYSQL_URL is a mysql:// URL for a throwaway database.
// Checks that projects from before kinds and tokens migrate cleanly and that
// the network queries run on MySQL.
func TestMySQLProjectKindsAndNetwork(t *testing.T) {
	dsn := os.Getenv("TEST_MYSQL_URL")
	if !strings.HasPrefix(dsn, "mysql://") {
		t.Skip("TEST_MYSQL_URL not set to a mysql:// URL; skipping mysql integration test")
	}
	ctx := context.Background()
	d, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if err := AutoMigrate(ctx, d); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}
	if _, err := EnsureProjectTokens(ctx, d); err != nil {
		t.Fatalf("EnsureProjectTokens() error = %v", err)
	}
	if err := CreateProject(ctx, d, "mysql-api", KindAPI); err != nil {
		t.Fatalf("CreateProject() error = %v", err)
	}
	records, err := ListProjectRecords(ctx, d)
	if err != nil {
		t.Fatalf("ListProjectRecords() error = %v", err)
	}
	seen := map[string]bool{}
	for _, p := range records {
		if p.Token == nil || *p.Token == "" || seen[*p.Token] {
			t.Errorf("project %q has a missing or duplicate token", p.Name)
		} else {
			seen[*p.Token] = true
		}
		t.Logf("project %s kind=%s", p.Name, p.Kind)
	}

	now := time.Now()
	rows := []*ReportToEntry{
		{CreatedAt: now, Service: "mysql-api", ReportType: ReportTypeNetworkError, NELType: "ok", SamplingFraction: 0.01, ElapsedTime: 40, DocumentURI: "https://api/x", RawJSON: "{}"},
		{CreatedAt: now, Service: "mysql-api", ReportType: ReportTypeNetworkError, NELType: "tcp.reset", Phase: "connection", SamplingFraction: 1, ElapsedTime: 900, DocumentURI: "https://api/y", RawJSON: "{}"},
	}
	if err := d.Create(rows).Error; err != nil {
		t.Fatalf("insert: %v", err)
	}
	s, err := GetNetworkSummary(ctx, d, "mysql-api")
	if err != nil {
		t.Fatalf("GetNetworkSummary() error = %v", err)
	}
	if s.Requests < 100.9 || s.Requests > 101.1 || len(s.ByType) != 1 || len(s.Days) != 1 {
		t.Errorf("summary = %+v", s)
	}
	all, err := GetAllServicesNetwork(ctx, d)
	if err != nil || all["mysql-api"].Requests < 100.9 {
		t.Errorf("GetAllServicesNetwork() = %+v, %v", all, err)
	}
}
