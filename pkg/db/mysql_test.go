package db

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestMySQLDSN(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		want    []string
		wantErr bool
	}{
		{
			name: "full url",
			url:  "mysql://reportd:s3cret@db.example.com:3307/reportd?tls=true",
			want: []string{"reportd:s3cret@tcp(db.example.com:3307)/reportd?", "parseTime=true", "tls=true"},
		},
		{
			name: "default port",
			url:  "mysql://root@localhost/reportd",
			want: []string{"root@tcp(localhost:3306)/reportd?", "parseTime=true"},
		},
		{
			name: "parseTime cannot be disabled",
			url:  "mysql://root@localhost/reportd?parseTime=false",
			want: []string{"parseTime=true"},
		},
		{name: "missing database", url: "mysql://root@localhost", wantErr: true},
		{name: "missing host", url: "mysql:///reportd", wantErr: true},
		{name: "bad parameter", url: "mysql://root@localhost/reportd?parseTime=maybe", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mysqlDSN(tt.url)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("mysqlDSN() = %q, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("mysqlDSN() error = %v", err)
			}
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("mysqlDSN() = %q, want it to contain %q", got, w)
				}
			}
		})
	}
}

func TestMySQLDSNErrorHidesPassword(t *testing.T) {
	_, err := mysqlDSN("mysql://root:hunter2@local host/reportd")
	if err == nil {
		t.Fatal("mysqlDSN() error = nil, want an error")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("error leaks the password: %v", err)
	}
}

// TestConnectMySQLAndQueryHelpers runs the shared query-helper assertions and
// the storage cap against a real MySQL (the dialect MySQL HeatWave speaks).
// Skipped unless TEST_MYSQL_URL is a mysql:// URL for a throwaway database.
func TestConnectMySQLAndQueryHelpers(t *testing.T) {
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
	// A second run must be a no-op, as it is on every server start.
	if err := AutoMigrate(ctx, d); err != nil {
		t.Fatalf("second AutoMigrate() error = %v", err)
	}

	service := "test-" + randHex(t, 8)
	t.Cleanup(func() { cleanupService(t, d, service) })

	seedQueryFixtures(t, d, service)
	assertQueryHelpers(ctx, t, d, service)

	t.Run("logins and counts", func(t *testing.T) {
		assertLoginsAndCounts(ctx, t, d, "test-"+randHex(t, 8))
	})

	t.Run("projects", func(t *testing.T) {
		assertProjects(ctx, t, d, "test-"+randHex(t, 8))
	})

	t.Run("storage limit", func(t *testing.T) {
		assertStorageLimit(ctx, t, d, service)
	})
}
