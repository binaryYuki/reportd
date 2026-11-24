package db

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

// assertStorageLimit fills the tables past a cap, enforces it, and checks
// that the oldest rows went first and the newest survived.
func assertStorageLimit(ctx context.Context, t *testing.T, d *gorm.DB, service string) {
	t.Helper()

	const rows = 400
	payload := JSONText(`{"pad":"` + strings.Repeat("x", 4096) + `"}`)
	base := time.Now().Add(-rows * time.Minute)

	batch := make([]*SecurityReportEntry, 0, rows)
	for i := range rows {
		batch = append(batch, &SecurityReportEntry{
			CreatedAt:  base.Add(time.Duration(i) * time.Minute),
			Service:    service,
			ReportType: "retention-test",
			RawJSON:    payload,
		})
	}
	if err := d.WithContext(ctx).CreateInBatches(batch, 100).Error; err != nil {
		t.Fatalf("seeding rows: %v", err)
	}
	oldestID, newestID := batch[0].ID, batch[rows-1].ID

	before, err := StorageBytes(ctx, d)
	if err != nil {
		t.Fatalf("StorageBytes() error = %v", err)
	}
	if before < rows*2048 {
		t.Fatalf("StorageBytes() = %d, want it to reflect ~%d bytes of payload", before, rows*4096)
	}

	// Under the cap: nothing may be deleted.
	res, err := EnforceStorageLimit(ctx, d, before*2)
	if err != nil {
		t.Fatalf("EnforceStorageLimit(under cap) error = %v", err)
	}
	if res.RowsDeleted != 0 {
		t.Fatalf("under the cap RowsDeleted = %d, want 0", res.RowsDeleted)
	}

	limit := before / 2
	res, err = EnforceStorageLimit(ctx, d, limit)
	if err != nil {
		t.Fatalf("EnforceStorageLimit() error = %v", err)
	}
	if res.RowsDeleted == 0 {
		t.Fatal("RowsDeleted = 0, want old rows pruned")
	}
	if res.BytesAfter > limit {
		t.Errorf("BytesAfter = %d, want <= limit %d (before %d)", res.BytesAfter, limit, res.BytesBefore)
	}

	// Unscoped: the rows must be gone, not soft-deleted.
	var n int64
	if err := d.WithContext(ctx).Unscoped().Model(&SecurityReportEntry{}).Where("id = ?", oldestID).Count(&n).Error; err != nil {
		t.Fatalf("counting oldest row: %v", err)
	}
	if n != 0 {
		t.Error("oldest row survived the prune")
	}
	if err := d.WithContext(ctx).Model(&SecurityReportEntry{}).Where("id = ?", newestID).Count(&n).Error; err != nil {
		t.Fatalf("counting newest row: %v", err)
	}
	if n != 1 {
		t.Error("newest row was pruned")
	}
}

func TestEnforceStorageLimitSQLite(t *testing.T) {
	ctx := context.Background()
	d, err := Connect(ctx, "sqlite://"+filepath.Join(t.TempDir(), "retention.db"))
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if err := AutoMigrate(ctx, d); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}

	assertStorageLimit(ctx, t, d, "svc")
}

func TestEnforceStorageLimitRejectsNonPositiveCap(t *testing.T) {
	ctx := context.Background()
	d, err := Connect(ctx, "sqlite://"+filepath.Join(t.TempDir(), "cap.db"))
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if _, err := EnforceStorageLimit(ctx, d, 0); err == nil {
		t.Fatal("EnforceStorageLimit(0) error = nil, want an error")
	}
}

func TestJSONTextScan(t *testing.T) {
	var j JSONText
	for _, in := range []any{[]byte(`{"a":1}`), `{"a":1}`} {
		if err := j.Scan(in); err != nil || j != `{"a":1}` {
			t.Errorf("Scan(%T) = %q, %v", in, j, err)
		}
	}
	if err := j.Scan(nil); err != nil || j != "" {
		t.Errorf("Scan(nil) = %q, %v", j, err)
	}
	if err := j.Scan(42); err == nil {
		t.Error("Scan(42) error = nil, want an error")
	}
}
