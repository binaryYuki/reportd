package db

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
)

func newWriterDB(t *testing.T) *gorm.DB {
	t.Helper()
	ctx := context.Background()
	d, err := Connect(ctx, "sqlite://"+filepath.Join(t.TempDir(), "writer.db"))
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if err := AutoMigrate(ctx, d); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}
	return d
}

// dropLog collects OnDrop calls.
type dropLog struct {
	mu   sync.Mutex
	rows int
	errs []error
}

func (l *dropLog) record(rows int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rows += rows
	l.errs = append(l.errs, err)
}

func (l *dropLog) snapshot() (int, []error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rows, append([]error(nil), l.errs...)
}

func count(t *testing.T, d *gorm.DB, model any) int64 {
	t.Helper()
	var n int64
	if err := d.Model(model).Count(&n).Error; err != nil {
		t.Fatalf("counting %T: %v", model, err)
	}
	return n
}

func TestWriterPersistsAllRowTypes(t *testing.T) {
	d := newWriterDB(t)
	var drops dropLog
	// BatchSize 2 forces several INSERTs per table.
	w := NewWriter(d, WriterOptions{BatchSize: 2, FlushInterval: time.Hour, OnDrop: drops.record})

	for range 5 {
		w.Enqueue(
			&WebVital{Service: "svc", Name: "LCP", Value: 1},
			&ReportToEntry{Service: "svc", ReportType: "csp", RawJSON: `{}`},
			&SecurityReportEntry{Service: "svc", ReportType: "crash", RawJSON: `{}`},
		)
	}
	if err := w.Flush(context.Background()); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	for _, model := range []any{&WebVital{}, &ReportToEntry{}, &SecurityReportEntry{}} {
		if got := count(t, d, model); got != 5 {
			t.Errorf("%T rows = %d, want 5", model, got)
		}
	}
	if rows, _ := drops.snapshot(); rows != 0 {
		t.Errorf("dropped %d rows, want 0", rows)
	}
	if err := w.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestWriterFlushesOnInterval(t *testing.T) {
	d := newWriterDB(t)
	w := NewWriter(d, WriterOptions{FlushInterval: 10 * time.Millisecond})
	t.Cleanup(func() { _ = w.Close(context.Background()) })

	w.Enqueue(&WebVital{Service: "svc", Name: "LCP", Value: 1})

	deadline := time.Now().Add(5 * time.Second)
	for count(t, d, &WebVital{}) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("row was not written without an explicit Flush")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestWriterCloseDrainsQueue(t *testing.T) {
	d := newWriterDB(t)
	w := NewWriter(d, WriterOptions{FlushInterval: time.Hour})

	for range 450 {
		w.Enqueue(&WebVital{Service: "svc", Name: "LCP", Value: 1})
	}
	if err := w.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := count(t, d, &WebVital{}); got != 450 {
		t.Errorf("rows after Close = %d, want 450", got)
	}

	// Flush and a second Close on a stopped writer must not hang.
	if err := w.Flush(context.Background()); err != nil {
		t.Errorf("Flush() after Close error = %v", err)
	}
	if err := w.Close(context.Background()); err != nil {
		t.Errorf("second Close() error = %v", err)
	}
}

// A failing insert is retried and then dropped, without taking down the
// rows bound for healthy tables.
func TestWriterDropsAfterRetries(t *testing.T) {
	d := newWriterDB(t)
	if err := d.Migrator().DropTable(&WebVital{}); err != nil {
		t.Fatalf("DropTable: %v", err)
	}

	var drops dropLog
	w := NewWriter(d, WriterOptions{Attempts: 3, RetryBackoff: time.Millisecond, OnDrop: drops.record})
	t.Cleanup(func() { _ = w.Close(context.Background()) })

	w.Enqueue(
		&WebVital{Service: "svc", Name: "LCP", Value: 1},
		&WebVital{Service: "svc", Name: "CLS", Value: 1},
		&ReportToEntry{Service: "svc", ReportType: "csp", RawJSON: `{}`},
	)
	if err := w.Flush(context.Background()); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	rows, errs := drops.snapshot()
	if rows != 2 || len(errs) != 1 || errs[0] == nil {
		t.Errorf("drops = %d rows, errs %v; want the 2 web vitals dropped once with the insert error", rows, errs)
	}
	if got := count(t, d, &ReportToEntry{}); got != 1 {
		t.Errorf("report-to rows = %d, want 1", got)
	}
}

// With the database stalled, Enqueue must return at once and shed the rows
// that do not fit rather than block the request.
func TestWriterShedsWhenQueueIsFull(t *testing.T) {
	d := newWriterDB(t)

	// Hold SQLite's only write lock so the writer's INSERT stalls.
	sqlDB, err := d.DB()
	if err != nil {
		t.Fatalf("DB() error = %v", err)
	}
	conn, err := sqlDB.Conn(context.Background())
	if err != nil {
		t.Fatalf("Conn() error = %v", err)
	}
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("BEGIN IMMEDIATE: %v", err)
	}
	released := false
	release := func() {
		if !released {
			released = true
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
			_ = conn.Close()
		}
	}
	t.Cleanup(release)

	var drops dropLog
	w := NewWriter(d, WriterOptions{
		QueueSize: 10, BatchSize: 1, FlushInterval: 10 * time.Millisecond,
		Attempts: 1000, RetryBackoff: time.Millisecond, OnDrop: drops.record,
	})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = w.Close(ctx)
	})

	start := time.Now()
	for range 200 {
		w.Enqueue(&WebVital{Service: "svc", Name: "LCP", Value: 1})
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Enqueue blocked for %v with the database stalled", elapsed)
	}

	// Let the database recover: what was queued gets written, the overflow
	// is reported as ErrQueueFull.
	release()
	if err := w.Flush(context.Background()); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		rows, errs := drops.snapshot()
		written := count(t, d, &WebVital{})
		if rows > 0 && written+int64(rows) == 200 {
			for _, err := range errs {
				if !errors.Is(err, ErrQueueFull) {
					t.Errorf("drop error = %v, want ErrQueueFull", err)
				}
			}
			if written < 10 {
				t.Errorf("written = %d, want at least the queue's 10 rows", written)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("written %d + dropped %d never reached 200", written, rows)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The byte budget sheds large rows even when the row count is far below
// QueueSize, and the budget is returned once rows are written.
func TestWriterBoundsQueuedBytes(t *testing.T) {
	d := newWriterDB(t)
	var drops dropLog
	w := NewWriter(d, WriterOptions{QueueBytes: 10 << 10, FlushInterval: 10 * time.Millisecond, OnDrop: drops.record})
	t.Cleanup(func() { _ = w.Close(context.Background()) })

	big := JSONText(`"` + strings.Repeat("x", 4<<10) + `"`)
	enqueue := func() {
		w.Enqueue(
			&SecurityReportEntry{Service: "svc", ReportType: "crash", RawJSON: big},
			&SecurityReportEntry{Service: "svc", ReportType: "crash", RawJSON: big},
			&SecurityReportEntry{Service: "svc", ReportType: "crash", RawJSON: big},
		)
	}

	enqueue() // 3 x ~4 KiB against a 10 KiB budget: the third does not fit
	if err := w.Flush(context.Background()); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if got := count(t, d, &SecurityReportEntry{}); got != 2 {
		t.Fatalf("rows = %d, want 2 within the byte budget", got)
	}

	enqueue() // budget was released by the write, so two more fit
	if err := w.Flush(context.Background()); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if got := count(t, d, &SecurityReportEntry{}); got != 4 {
		t.Errorf("rows = %d, want 4 after the budget was released", got)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		if rows, _ := drops.snapshot(); rows == 2 {
			break
		}
		if time.Now().After(deadline) {
			rows, _ := drops.snapshot()
			t.Fatalf("dropped rows = %d, want 2", rows)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
