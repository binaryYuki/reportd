package db

import (
	"database/sql/driver"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// JSONText is a raw JSON document stored in the dialect's JSON column type.
type JSONText string

// GormDBDataType picks the JSON column type per dialect: MySQL has no jsonb.
// SQLite keeps "jsonb" (it accepts any type name) so existing files are not
// rewritten by AutoMigrate.
func (JSONText) GormDBDataType(d *gorm.DB, _ *schema.Field) string {
	if d.Name() == dialectMySQL {
		return "json"
	}
	return "jsonb"
}

// Value implements driver.Valuer.
func (j JSONText) Value() (driver.Value, error) {
	return string(j), nil
}

// Scan implements sql.Scanner.
func (j *JSONText) Scan(v any) error {
	switch x := v.(type) {
	case nil:
		*j = ""
	case []byte:
		*j = JSONText(x)
	case string:
		*j = JSONText(x)
	default:
		return fmt.Errorf("unsupported type for JSONText: %T", v)
	}
	return nil
}

// WebVital is a row from POST /analytics.
type WebVital struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `gorm:"index" json:"created_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
	Service   string         `gorm:"index;not null" json:"service"`
	Name      string         `gorm:"index;not null" json:"name"`
	Value     float64        `gorm:"not null" json:"value"`
	Delta     float64        `json:"delta"`
	VitalID   string         `json:"vital_id"`
	Label     string         `json:"label"`
}

// ReportToEntry is a row from POST /report (legacy Report-To API).
type ReportToEntry struct {
	ID                 uint           `gorm:"primaryKey" json:"id"`
	CreatedAt          time.Time      `gorm:"index" json:"created_at"`
	DeletedAt          gorm.DeletedAt `gorm:"index" json:"-"`
	Service            string         `gorm:"index;not null" json:"service"`
	ReportType         string         `gorm:"index" json:"report_type"`
	DocumentURI        string         `json:"document_uri"`
	BlockedURI         string         `json:"blocked_uri"`
	ViolatedDirective  string         `json:"violated_directive"`
	EffectiveDirective string         `json:"effective_directive"`
	OriginalPolicy     string         `json:"original_policy"`
	SourceFile         string         `json:"source_file"`
	LineNumber         int            `json:"line_number"`
	ColumnNumber       int            `json:"column_number"`
	StatusCode         int            `json:"status_code"`
	RawJSON            JSONText       `json:"raw_json,omitempty"`

	// Network Error Logging (report_type "network-error") fields.
	NELType          string  `gorm:"size:64" json:"nel_type,omitempty"` // "ok", "dns.name_not_resolved", "tcp.timed_out", "http.error", ...
	Phase            string  `gorm:"size:16" json:"phase,omitempty"`    // "dns", "connection" or "application"
	ElapsedTime      int64   `json:"elapsed_time,omitempty"`            // ms
	SamplingFraction float64 `json:"sampling_fraction,omitempty"`
	Method           string  `gorm:"size:16" json:"method,omitempty"`
	Protocol         string  `gorm:"size:32" json:"protocol,omitempty"`
	ServerIP         string  `gorm:"size:64" json:"server_ip,omitempty"`
}

// SecurityReportEntry is a row from POST /reporting (Reporting API v1).
type SecurityReportEntry struct {
	ID                 uint           `gorm:"primaryKey" json:"id"`
	CreatedAt          time.Time      `gorm:"index" json:"created_at"`
	DeletedAt          gorm.DeletedAt `gorm:"index" json:"-"`
	Service            string         `gorm:"index;not null" json:"service"`
	ReportType         string         `gorm:"index;not null" json:"report_type"`
	URL                string         `json:"url"`
	DocumentURI        string         `json:"document_uri"`
	BlockedURI         string         `json:"blocked_uri"`
	ViolatedDirective  string         `json:"violated_directive"`
	EffectiveDirective string         `json:"effective_directive"`
	SourceFile         string         `json:"source_file"`
	LineNumber         int            `json:"line_number"`
	ColumnNumber       int            `json:"column_number"`
	Message            string         `json:"message"`
	RawJSON            JSONText       `json:"raw_json,omitempty"`
}
