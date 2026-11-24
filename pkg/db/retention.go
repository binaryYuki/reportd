package db

import (
	"context"
	"errors"
	"fmt"
	"math"

	"gorm.io/gorm"
)

const (
	// pruneTargetRatio is how far below the cap a prune shrinks the data, so
	// the next few ingests do not immediately trigger another prune.
	pruneTargetRatio = 0.8
	pruneBatchSize   = 2000
	pruneMaxPasses   = 5
)

// retentionTables are the ingestion tables counted against the storage cap.
var retentionTables = []struct {
	name  string
	model any
}{
	{"web_vitals", &WebVital{}},
	{"report_to_entries", &ReportToEntry{}},
	{"security_report_entries", &SecurityReportEntry{}},
}

// PruneResult describes one EnforceStorageLimit run.
type PruneResult struct {
	BytesBefore int64
	BytesAfter  int64
	RowsDeleted int64
}

// StorageBytes returns the bytes used by the ingestion tables (data plus
// indexes). It does not see server-side overhead such as MySQL binary logs.
func StorageBytes(ctx context.Context, d *gorm.DB) (int64, error) {
	var size int64

	switch d.Name() {
	case dialectMySQL:
		names := make([]string, 0, len(retentionTables))
		for _, t := range retentionTables {
			names = append(names, t.name)
		}
		// One pinned connection: the session variable below must apply to the
		// size query. Without it MySQL 8 serves day-old cached table stats.
		err := d.WithContext(ctx).Connection(func(tx *gorm.DB) error {
			if err := tx.Exec("SET SESSION information_schema_stats_expiry = 0").Error; err != nil {
				return err
			}
			for _, name := range names {
				// ANALYZE returns a result set; Raw+Rows drains it.
				rows, err := tx.Raw("ANALYZE TABLE " + name).Rows() //nolint:gosec // name is from a hardcoded list
				if err != nil {
					return err
				}
				if err := rows.Close(); err != nil {
					return err
				}
			}
			return tx.Raw(
				"SELECT COALESCE(SUM(data_length + index_length), 0) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name IN ?",
				names,
			).Scan(&size).Error
		})
		if err != nil {
			return 0, fmt.Errorf("measuring mysql storage: %w", err)
		}
	case dialectSQLite:
		var pages, free, pageSize int64
		for _, q := range []struct {
			pragma string
			dst    *int64
		}{{"page_count", &pages}, {"freelist_count", &free}, {"page_size", &pageSize}} {
			if err := d.WithContext(ctx).Raw("PRAGMA " + q.pragma).Scan(q.dst).Error; err != nil {
				return 0, fmt.Errorf("measuring sqlite storage: %w", err)
			}
		}
		size = (pages - free) * pageSize
	case dialectPostgres:
		for _, t := range retentionTables {
			var n int64
			if err := d.WithContext(ctx).Raw("SELECT pg_total_relation_size(?::regclass)", t.name).Scan(&n).Error; err != nil {
				return 0, fmt.Errorf("measuring postgres storage: %w", err)
			}
			size += n
		}
	default:
		return 0, fmt.Errorf("storage measurement unsupported for dialect %q", d.Name())
	}

	return size, nil
}

// EnforceStorageLimit hard-deletes the oldest rows until the ingestion tables
// fit in maxBytes, then compacts so the space is actually returned. Each table
// loses the same fraction of its rows, oldest first.
func EnforceStorageLimit(ctx context.Context, d *gorm.DB, maxBytes int64) (PruneResult, error) {
	var res PruneResult
	if maxBytes <= 0 {
		return res, errors.New("maxBytes must be positive")
	}

	size, err := StorageBytes(ctx, d)
	if err != nil {
		return res, err
	}
	res.BytesBefore, res.BytesAfter = size, size

	for pass := 0; size > maxBytes && pass < pruneMaxPasses; pass++ {
		fraction := 1 - pruneTargetRatio*float64(maxBytes)/float64(size)

		var deleted int64
		for _, t := range retentionTables {
			n, err := deleteOldest(ctx, d, t.model, fraction)
			res.RowsDeleted += n
			deleted += n
			if err != nil {
				return res, fmt.Errorf("pruning %s: %w", t.name, err)
			}
		}
		if deleted == 0 {
			break // nothing left to delete; the remainder is fixed overhead
		}

		if err := compact(ctx, d); err != nil {
			return res, err
		}
		if size, err = StorageBytes(ctx, d); err != nil {
			return res, err
		}
		res.BytesAfter = size
	}

	return res, nil
}

// deleteOldest hard-deletes the oldest fraction of model's rows in batches
// and returns how many rows went.
func deleteOldest(ctx context.Context, d *gorm.DB, model any, fraction float64) (int64, error) {
	var total int64
	if err := d.WithContext(ctx).Unscoped().Model(model).Count(&total).Error; err != nil {
		return 0, err
	}
	remaining := int64(math.Ceil(float64(total) * fraction))

	var deleted int64
	for remaining > 0 {
		var ids []uint
		err := d.WithContext(ctx).Unscoped().Model(model).
			Order("created_at ASC, id ASC").
			Limit(int(min(remaining, pruneBatchSize))).
			Pluck("id", &ids).Error
		if err != nil {
			return deleted, err
		}
		if len(ids) == 0 {
			break
		}

		// Unscoped: these models soft-delete by default, which frees nothing.
		tx := d.WithContext(ctx).Unscoped().Where("id IN ?", ids).Delete(model)
		if tx.Error != nil {
			return deleted, tx.Error
		}
		deleted += tx.RowsAffected
		remaining -= int64(len(ids))
	}
	return deleted, nil
}

// compact returns freed pages to the server so the measured size (and the
// disk footprint) drops after a prune. SQLite needs nothing: StorageBytes
// already excludes its free pages.
func compact(ctx context.Context, d *gorm.DB) error {
	var stmt string
	switch d.Name() {
	case dialectMySQL:
		stmt = "OPTIMIZE TABLE "
	case dialectPostgres:
		stmt = "VACUUM FULL "
	default:
		return nil
	}

	for _, t := range retentionTables {
		rows, err := d.WithContext(ctx).Raw(stmt + t.name).Rows() //nolint:gosec // name is from a hardcoded list
		if err != nil {
			return fmt.Errorf("compacting %s: %w", t.name, err)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("compacting %s: %w", t.name, err)
		}
	}
	return nil
}
