package db

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Project is a site that may send reports. Ingestion and the dashboard only
// serve names that have a row here.
type Project struct {
	Name      string    `gorm:"primaryKey;size:64" json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// ListProjects returns every project name, sorted.
func ListProjects(ctx context.Context, d *gorm.DB) ([]string, error) {
	var names []string
	if err := d.WithContext(ctx).Model(&Project{}).Order("name").Pluck("name", &names).Error; err != nil {
		return nil, fmt.Errorf("listing projects: %w", err)
	}
	return names, nil
}

// CreateProject adds name; creating an existing project is a no-op.
func CreateProject(ctx context.Context, d *gorm.DB, name string) error {
	err := d.WithContext(ctx).
		Clauses(clause.OnConflict{DoNothing: true}).
		Create(&Project{Name: name, CreatedAt: time.Now()}).Error
	if err != nil {
		return fmt.Errorf("creating project: %w", err)
	}
	return nil
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
	var total int64
	for _, t := range retentionTables {
		for {
			var ids []uint
			err := d.WithContext(ctx).Unscoped().Model(t.model).
				Where("service = ?", name).Limit(pruneBatchSize).Pluck("id", &ids).Error
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
