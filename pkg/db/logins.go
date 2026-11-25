package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// UserLogin remembers when a dashboard user last signed in, so the dashboard
// can show what arrived since then.
type UserLogin struct {
	Email       string    `gorm:"primaryKey;size:191" json:"email"`
	LastLoginAt time.Time `json:"last_login_at"`
}

// RecordLogin stores at as email's latest sign-in and returns the one before
// it; the zero time means this is the first.
func RecordLogin(ctx context.Context, d *gorm.DB, email string, at time.Time) (time.Time, error) {
	var previous time.Time
	err := d.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var row UserLogin
		err := tx.Where("email = ?", email).Take(&row).Error
		switch {
		case err == nil:
			previous = row.LastLoginAt
		case !errors.Is(err, gorm.ErrRecordNotFound):
			return err
		}
		return tx.Save(&UserLogin{Email: email, LastLoginAt: at}).Error
	})
	if err != nil {
		return time.Time{}, fmt.Errorf("recording login: %w", err)
	}
	return previous, nil
}

// IngestCounts is how many rows arrived in a period, split by kind.
type IngestCounts struct {
	// Vitals counts Web Vitals measurements.
	Vitals int64 `json:"vitals"`
	// Reports counts browser reports: CSP violations, crashes, and so on.
	Reports int64 `json:"reports"`
}

// Total is every row counted.
func (c IngestCounts) Total() int64 { return c.Vitals + c.Reports }

// CountSince counts the rows ingested at or after since, in one round trip.
// A non-empty services restricts the count to those services.
func CountSince(ctx context.Context, d *gorm.DB, since time.Time, services []string) (IngestCounts, error) {
	where := "created_at >= ? AND deleted_at IS NULL"
	args := []any{since}
	if len(services) > 0 {
		where += " AND service IN ?"
		args = append(args, services)
	}

	var all []any
	query := "SELECT"
	for i, t := range retentionTables {
		if i > 0 {
			query += ","
		}
		query += fmt.Sprintf(" (SELECT COUNT(*) FROM %s WHERE %s) AS c%d", t.name, where, i)
		all = append(all, args...)
	}

	var row struct{ C0, C1, C2 int64 }
	if err := d.WithContext(ctx).Raw(query, all...).Scan(&row).Error; err != nil {
		return IngestCounts{}, fmt.Errorf("counting rows since %s: %w", since.Format(time.RFC3339), err)
	}
	// retentionTables order: web_vitals, report_to_entries, security_report_entries.
	return IngestCounts{Vitals: row.C0, Reports: row.C1 + row.C2}, nil
}
