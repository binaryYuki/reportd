package db

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"
)

// ErrQueueFull is passed to WriterOptions.OnDrop for rows rejected because
// the queue was at capacity.
var ErrQueueFull = errors.New("ingest queue full")

// WriterOptions tunes a Writer; zero values pick the defaults.
type WriterOptions struct {
	// QueueSize bounds the rows held in memory while the database is slow
	// or down. Default 5000.
	QueueSize int
	// QueueBytes bounds the approximate memory held by queued rows, so a
	// burst of large reports cannot exhaust a small instance. Default 32 MiB.
	QueueBytes int64
	// BatchSize is the most rows sent in one INSERT. Default 200.
	BatchSize int
	// FlushInterval is the longest a row waits before being written.
	// Default 1s.
	FlushInterval time.Duration
	// WriteTimeout bounds one INSERT. Default 15s.
	WriteTimeout time.Duration
	// Attempts is how many times a failed batch is tried before it is
	// dropped. Default 3.
	Attempts int
	// RetryBackoff is the wait before the first retry; it doubles after
	// each failure. Default 1s.
	RetryBackoff time.Duration
	// OnDrop is called from the writer goroutine when rows are lost: with
	// ErrQueueFull on overflow, or the insert error once retries run out.
	OnDrop func(rows int, err error)
}

// Writer persists ingested rows in the background so request handlers never
// wait on the database. Rows are batched into multi-row INSERTs, which keeps
// throughput up when every round trip to the database is slow.
//
// Delivery is best effort: rows are dropped when the queue overflows or a
// batch keeps failing, and a batch whose INSERT timed out after reaching the
// server can be written twice by the retry.
type Writer struct {
	d    *gorm.DB
	opts WriterOptions

	queue    chan any
	flush    chan chan struct{}
	quit     chan struct{}
	done     chan struct{}
	overflow atomic.Int64
	bytes    atomic.Int64 // approximate size of rows queued or being written
	stop     sync.Once

	mu      sync.Mutex
	lastErr error // outcome of the most recent batch; nil when it was written
}

// LastError reports whether the most recent batch failed: it returns that
// batch's insert error, or nil once a later batch is written in full.
func (w *Writer) LastError() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lastErr
}

// NewWriter starts a Writer on d. Call Close to drain it.
func NewWriter(d *gorm.DB, opts WriterOptions) *Writer {
	if opts.QueueSize <= 0 {
		opts.QueueSize = 5000
	}
	if opts.QueueBytes <= 0 {
		opts.QueueBytes = 32 << 20
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 200
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = time.Second
	}
	if opts.WriteTimeout <= 0 {
		opts.WriteTimeout = 15 * time.Second
	}
	if opts.Attempts <= 0 {
		opts.Attempts = 3
	}
	if opts.RetryBackoff <= 0 {
		opts.RetryBackoff = time.Second
	}
	if opts.OnDrop == nil {
		opts.OnDrop = func(int, error) {}
	}

	w := &Writer{
		d:     d,
		opts:  opts,
		queue: make(chan any, opts.QueueSize),
		flush: make(chan chan struct{}),
		quit:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	go w.run()
	return w
}

// Enqueue queues rows (*WebVital, *ReportToEntry, or *SecurityReportEntry)
// for writing and returns immediately. Rows that do not fit are dropped and
// reported through OnDrop.
func (w *Writer) Enqueue(rows ...any) {
	for _, row := range rows {
		size := rowSize(row)
		if w.bytes.Add(size) > w.opts.QueueBytes {
			w.bytes.Add(-size)
			w.overflow.Add(1)
			continue
		}
		select {
		case w.queue <- row:
		default:
			w.bytes.Add(-size)
			w.overflow.Add(1)
		}
	}
}

// rowSize approximates the memory a queued row pins: its variable-length
// fields plus a fixed allowance for the struct itself.
func rowSize(row any) int64 {
	const overhead = 256
	n := overhead
	switch r := row.(type) {
	case *WebVital:
		n += len(r.Service) + len(r.Name) + len(r.VitalID) + len(r.Label)
	case *ReportToEntry:
		n += len(r.Service) + len(r.ReportType) + len(r.DocumentURI) + len(r.BlockedURI) +
			len(r.ViolatedDirective) + len(r.EffectiveDirective) + len(r.OriginalPolicy) +
			len(r.SourceFile) + len(r.RawJSON)
	case *SecurityReportEntry:
		n += len(r.Service) + len(r.ReportType) + len(r.URL) + len(r.DocumentURI) + len(r.BlockedURI) +
			len(r.ViolatedDirective) + len(r.EffectiveDirective) + len(r.SourceFile) +
			len(r.Message) + len(r.RawJSON)
	}
	return int64(n)
}

// Flush blocks until every row enqueued before the call has been written or
// dropped, or ctx ends.
func (w *Writer) Flush(ctx context.Context) error {
	ack := make(chan struct{})
	select {
	case w.flush <- ack:
	case <-w.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-ack:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close writes whatever is queued and stops the Writer, or gives up when ctx
// ends. Rows enqueued after Close are lost.
func (w *Writer) Close(ctx context.Context) error {
	w.stop.Do(func() { close(w.quit) })
	select {
	case <-w.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *Writer) run() {
	defer close(w.done)

	ticker := time.NewTicker(w.opts.FlushInterval)
	defer ticker.Stop()

	batch := make([]any, 0, w.opts.BatchSize)
	write := func() {
		if len(batch) > 0 {
			var size int64
			for _, row := range batch {
				size += rowSize(row)
			}
			w.write(batch)
			w.bytes.Add(-size)
			batch = batch[:0]
		}
	}
	// drain writes everything currently queued, in BatchSize chunks.
	drain := func() {
		for {
			select {
			case row := <-w.queue:
				if batch = append(batch, row); len(batch) >= w.opts.BatchSize {
					write()
				}
			default:
				write()
				return
			}
		}
	}

	for {
		select {
		case row := <-w.queue:
			if batch = append(batch, row); len(batch) >= w.opts.BatchSize {
				write()
			}
		case <-ticker.C:
			write()
			if n := w.overflow.Swap(0); n > 0 {
				w.opts.OnDrop(int(n), ErrQueueFull)
			}
		case ack := <-w.flush:
			drain()
			close(ack)
		case <-w.quit:
			drain()
			return
		}
	}
}

// write inserts batch, one multi-row INSERT per table.
func (w *Writer) write(batch []any) {
	var (
		vitals   []*WebVital
		reportTo []*ReportToEntry
		security []*SecurityReportEntry
	)
	for _, row := range batch {
		switch r := row.(type) {
		case *WebVital:
			vitals = append(vitals, r)
		case *ReportToEntry:
			reportTo = append(reportTo, r)
		case *SecurityReportEntry:
			security = append(security, r)
		default:
			w.opts.OnDrop(1, fmt.Errorf("unsupported row type %T", row))
		}
	}

	var err error
	if len(vitals) > 0 {
		err = errors.Join(err, w.insert(&vitals, len(vitals)))
	}
	if len(reportTo) > 0 {
		err = errors.Join(err, w.insert(&reportTo, len(reportTo)))
	}
	if len(security) > 0 {
		err = errors.Join(err, w.insert(&security, len(security)))
	}

	w.mu.Lock()
	w.lastErr = err
	w.mu.Unlock()
}

// insert writes rows (a pointer to a slice of models), retrying with backoff
// and dropping them when the attempts run out. Shutdown cuts the waits short.
// It returns the error that caused a drop, or nil when the rows were written.
func (w *Writer) insert(rows any, n int) error {
	backoff := w.opts.RetryBackoff

	var err error
	for attempt := 1; attempt <= w.opts.Attempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), w.opts.WriteTimeout)
		err = w.d.WithContext(ctx).Create(rows).Error
		cancel()
		if err == nil {
			return nil
		}
		if attempt == w.opts.Attempts {
			break
		}

		select {
		case <-time.After(backoff):
			backoff *= 2
		case <-w.quit:
			// One last try below would only delay shutdown further.
			w.opts.OnDrop(n, err)
			return err
		}
	}
	w.opts.OnDrop(n, err)
	return err
}
