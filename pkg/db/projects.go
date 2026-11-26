package db

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Project kinds. An app is a website: it sends Web Vitals, page reports
// (CSP, deprecation, ...) and network errors. An API only sends network
// errors (NEL), which browsers report for requests to its origin.
const (
	KindApp = "app"
	KindAPI = "api"
)

// ValidKind reports whether k is a known project kind.
func ValidKind(k string) bool { return k == KindApp || k == KindAPI }

// Project is a site that may send reports. Ingestion and the dashboard only
// serve names that have a row here.
type Project struct {
	Name      string    `gorm:"primaryKey;size:64" json:"name"`
	CreatedAt time.Time `json:"created_at"`
	Kind      string    `gorm:"size:16;not null;default:app" json:"kind"`
	// Token is the opaque ingestion credential used in ?s= URLs. It is
	// nullable so the column can be added to existing rows before they are
	// backfilled by EnsureProjectTokens.
	Token *string `gorm:"size:64;uniqueIndex" json:"-"`
}

// NewProjectToken returns a fresh random, URL-safe token.
func NewProjectToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating project token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ListProjects returns every project name, sorted.
func ListProjects(ctx context.Context, d *gorm.DB) ([]string, error) {
	var names []string
	if err := d.WithContext(ctx).Model(&Project{}).Order("name").Pluck("name", &names).Error; err != nil {
		return nil, fmt.Errorf("listing projects: %w", err)
	}
	return names, nil
}

// ListProjectRecords returns every project, sorted by name.
func ListProjectRecords(ctx context.Context, d *gorm.DB) ([]Project, error) {
	var out []Project
	if err := d.WithContext(ctx).Order("name").Find(&out).Error; err != nil {
		return nil, fmt.Errorf("listing projects: %w", err)
	}
	return out, nil
}

// CreateProject adds name with the given kind and a new token; creating an
// existing project is a no-op and keeps its kind and token.
func CreateProject(ctx context.Context, d *gorm.DB, name, kind string) error {
	if !ValidKind(kind) {
		return fmt.Errorf("creating project: unknown kind %q", kind)
	}
	token, err := NewProjectToken()
	if err != nil {
		return err
	}
	err = d.WithContext(ctx).
		Clauses(clause.OnConflict{DoNothing: true}).
		Create(&Project{Name: name, CreatedAt: time.Now(), Kind: kind, Token: &token}).Error
	if err != nil {
		return fmt.Errorf("creating project: %w", err)
	}
	return nil
}

// RotateProjectToken gives name a new token; URLs with the old one stop
// working. It returns the new token.
func RotateProjectToken(ctx context.Context, d *gorm.DB, name string) (string, error) {
	token, err := NewProjectToken()
	if err != nil {
		return "", err
	}
	tx := d.WithContext(ctx).Model(&Project{}).Where("name = ?", name).Update("token", token)
	if tx.Error != nil {
		return "", fmt.Errorf("rotating project token: %w", tx.Error)
	}
	if tx.RowsAffected == 0 {
		return "", fmt.Errorf("rotating project token: no project %q", name)
	}
	return token, nil
}

// EnsureProjectTokens gives a token to every project that lacks one
// (projects created before tokens existed). It returns how many it set.
func EnsureProjectTokens(ctx context.Context, d *gorm.DB) (int, error) {
	var names []string
	if err := d.WithContext(ctx).Model(&Project{}).Where("token IS NULL OR token = ''").Pluck("name", &names).Error; err != nil {
		return 0, fmt.Errorf("finding projects without tokens: %w", err)
	}
	for i, name := range names {
		token, err := NewProjectToken()
		if err != nil {
			return i, err
		}
		err = d.WithContext(ctx).Model(&Project{}).
			Where("name = ? AND (token IS NULL OR token = '')", name).Update("token", token).Error
		if err != nil {
			return i, fmt.Errorf("setting token for %q: %w", name, err)
		}
	}
	return len(names), nil
}

// DeleteProject removes the project row, which stops ingestion for name.
// Its stored data is removed separately by PurgeProjectData.
func DeleteProject(ctx context.Context, d *gorm.DB, name string) error {
	if err := d.WithContext(ctx).Where("name = ?", name).Delete(&Project{}).Error; err != nil {
		return fmt.Errorf("deleting project: %w", err)
	}
	return nil
}

// PurgeProjectData permanently deletes every row stored for the service
// name, in batches so no single statement holds locks for long. It returns
// how many rows went.
func PurgeProjectData(ctx context.Context, d *gorm.DB, name string) (int64, error) {
	return purgeProjectRows(ctx, d, name, time.Time{})
}

// FlushProjectData permanently deletes the rows stored for the service name
// up to before, in batches like PurgeProjectData. Reports that arrive while
// it runs are kept. It returns how many rows went.
func FlushProjectData(ctx context.Context, d *gorm.DB, name string, before time.Time) (int64, error) {
	return purgeProjectRows(ctx, d, name, before)
}

// purgeProjectRows deletes name's rows, only those created at or before
// before unless it is zero.
func purgeProjectRows(ctx context.Context, d *gorm.DB, name string, before time.Time) (int64, error) {
	var total int64
	for _, t := range retentionTables {
		for {
			var ids []uint
			q := d.WithContext(ctx).Unscoped().Model(t.model).Where("service = ?", name)
			if !before.IsZero() {
				q = q.Where("created_at <= ?", before)
			}
			err := q.Limit(pruneBatchSize).Pluck("id", &ids).Error
			if err != nil {
				return total, fmt.Errorf("purging %s: %w", t.name, err)
			}
			if len(ids) == 0 {
				break
			}
			tx := d.WithContext(ctx).Unscoped().Where("id IN ?", ids).Delete(t.model)
			if tx.Error != nil {
				return total, fmt.Errorf("purging %s: %w", t.name, tx.Error)
			}
			total += tx.RowsAffected
		}
	}
	return total, nil
}
