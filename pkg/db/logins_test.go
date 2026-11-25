package db

import (
	"context"
	"testing"
	"time"

	"gorm.io/gorm"
)

// assertLoginsAndCounts covers RecordLogin and CountSince for one dialect.
func assertLoginsAndCounts(ctx context.Context, t *testing.T, d *gorm.DB, service string) {
	t.Helper()

	email := service + "@example.com"
	t.Cleanup(func() { d.Where("email = ?", email).Delete(&UserLogin{}) })

	first := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	second := first.Add(time.Hour)

	prev, err := RecordLogin(ctx, d, email, first)
	if err != nil {
		t.Fatalf("RecordLogin(first) error = %v", err)
	}
	if !prev.IsZero() {
		t.Errorf("first login: previous = %v, want the zero time", prev)
	}
	prev, err = RecordLogin(ctx, d, email, second)
	if err != nil {
		t.Fatalf("RecordLogin(second) error = %v", err)
	}
	if !prev.Equal(first) {
		t.Errorf("second login: previous = %v, want %v", prev, first)
	}

	// Two rows before the cutoff, three after; another service's rows and a
	// soft-deleted row must not be counted.
	cutoff := time.Now().Add(-30 * time.Minute)
	old, recent := cutoff.Add(-time.Hour), cutoff.Add(time.Minute)
	other := service + "-other"
	t.Cleanup(func() { cleanupService(t, d, other) })

	deleted := &WebVital{CreatedAt: recent, Service: service, Name: "LCP", Value: 1}
	rows := []any{
		&WebVital{CreatedAt: old, Service: service, Name: "LCP", Value: 1},
		&ReportToEntry{CreatedAt: old, Service: service, ReportType: "count-test", RawJSON: `{}`},
		&WebVital{CreatedAt: recent, Service: service, Name: "LCP", Value: 1},
		&ReportToEntry{CreatedAt: recent, Service: service, ReportType: "count-test", RawJSON: `{}`},
		&SecurityReportEntry{CreatedAt: recent, Service: service, ReportType: "count-test", RawJSON: `{}`},
		&WebVital{CreatedAt: recent, Service: other, Name: "LCP", Value: 1},
		deleted,
	}
	for _, row := range rows {
		if err := d.WithContext(ctx).Create(row).Error; err != nil {
			t.Fatalf("seeding %T: %v", row, err)
		}
	}
	if err := d.WithContext(ctx).Delete(deleted).Error; err != nil {
		t.Fatalf("soft-deleting: %v", err)
	}

	got, err := CountSince(ctx, d, cutoff, []string{service})
	if err != nil {
		t.Fatalf("CountSince() error = %v", err)
	}
	if got.Vitals != 1 || got.Reports != 2 || got.Total() != 3 {
		t.Errorf("CountSince(cutoff, service) = %+v, want 1 vital and 2 reports", got)
	}

	both, err := CountSince(ctx, d, cutoff, []string{service, other})
	if err != nil {
		t.Fatalf("CountSince(two services) error = %v", err)
	}
	if both.Vitals != 2 || both.Reports != 2 {
		t.Errorf("CountSince(cutoff, both) = %+v, want 2 vitals and 2 reports", both)
	}
}

func TestLoginsAndCountsSQLite(t *testing.T) {
	ctx := context.Background()
	d := newWriterDB(t)
	assertLoginsAndCounts(ctx, t, d, "svc")

	// With no service filter and the zero time, every live row counts.
	all, err := CountSince(ctx, d, time.Time{}, nil)
	if err != nil {
		t.Fatalf("CountSince(all) error = %v", err)
	}
	if all.Vitals != 3 || all.Reports != 3 {
		t.Errorf("CountSince(all) = %+v, want 3 vitals and 3 reports", all)
	}
}

// assertProjects covers the project table for one dialect.
func assertProjects(ctx context.Context, t *testing.T, d *gorm.DB, name string) {
	t.Helper()
	t.Cleanup(func() { _ = DeleteProject(ctx, d, name) })

	// Creating twice must not fail or duplicate.
	for range 2 {
		if err := CreateProject(ctx, d, name); err != nil {
			t.Fatalf("CreateProject() error = %v", err)
		}
	}
	names, err := ListProjects(ctx, d)
	if err != nil {
		t.Fatalf("ListProjects() error = %v", err)
	}
	found := 0
	for _, n := range names {
		if n == name {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("ListProjects() has %q %d times, want once (%v)", name, found, names)
	}

	if err := d.WithContext(ctx).Create(&WebVital{CreatedAt: time.Now(), Service: name, Name: "LCP", Value: 1}).Error; err != nil {
		t.Fatalf("seeding: %v", err)
	}
	if err := d.WithContext(ctx).Create(&ReportToEntry{CreatedAt: time.Now(), Service: name, ReportType: "x", RawJSON: `{}`}).Error; err != nil {
		t.Fatalf("seeding: %v", err)
	}
	rows, err := PurgeProjectData(ctx, d, name)
	if err != nil || rows != 2 {
		t.Fatalf("PurgeProjectData() = %d, %v; want 2 rows", rows, err)
	}
	if left, err := CountSince(ctx, d, time.Time{}, []string{name}); err != nil || left.Total() != 0 {
		t.Errorf("rows left after purge = %+v, %v", left, err)
	}

	if err := DeleteProject(ctx, d, name); err != nil {
		t.Fatalf("DeleteProject() error = %v", err)
	}
	names, err = ListProjects(ctx, d)
	if err != nil {
		t.Fatalf("ListProjects() error = %v", err)
	}
	for _, n := range names {
		if n == name {
			t.Errorf("project %q still listed after delete", name)
		}
	}
}

func TestProjectsSQLite(t *testing.T) {
	assertProjects(context.Background(), t, newWriterDB(t), "proj")
}
