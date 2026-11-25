package db

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.icco.me/reportd/pkg/reportto"
	"gorm.io/gorm"
)

// networkWindow is how far back the network panels look.
const networkWindow = 30 * 24 * time.Hour

// nelWeight is how many requests one NEL report stands for. Browsers sample
// successes (success_fraction, often 1% or less) and failures
// (failure_fraction) separately and put the rate in sampling_fraction, so
// counting reports would make the success rate look far lower than it is.
const nelWeight = "CASE WHEN sampling_fraction > 0 THEN 1.0 / sampling_fraction ELSE 1 END"

// NetworkDay is one day of estimated request volume.
type NetworkDay struct {
	Day Day `json:"day"`
	// Requests and OK are estimates: reports weighted by 1/sampling_fraction.
	Requests float64 `json:"requests"`
	OK       float64 `json:"ok"`
	// Reports is the number of reports actually received.
	Reports int64 `json:"reports"`
}

// NetworkBreakdown is the failure count for one value of a dimension.
type NetworkBreakdown struct {
	Key       string  `gorm:"column:name" json:"key"`
	Reports   int64   `json:"reports"`
	Estimated float64 `json:"estimated"`
}

// NetworkSummary is everything the network panel shows for a service.
type NetworkSummary struct {
	Days []NetworkDay `json:"days"`
	// Requests and OK are window totals, estimated like NetworkDay's.
	Requests float64 `json:"requests"`
	OK       float64 `json:"ok"`
	// AvgElapsedOK and AvgElapsedFailed are mean elapsed_time in ms.
	AvgElapsedOK     float64            `json:"avg_elapsed_ok"`
	AvgElapsedFailed float64            `json:"avg_elapsed_failed"`
	ByType           []NetworkBreakdown `json:"by_type"`
	ByPhase          []NetworkBreakdown `json:"by_phase"`
	ByURL            []NetworkBreakdown `json:"by_url"`
	RecentFailures   []ReportToEntry    `json:"recent_failures"`
}

// nelScope selects service's NEL reports inside the window.
func nelScope(ctx context.Context, d *gorm.DB, service string, cutoff time.Time) *gorm.DB {
	return d.WithContext(ctx).Model(&ReportToEntry{}).
		Where("service = ? AND report_type = ? AND created_at >= ?", service, ReportTypeNetworkError, cutoff)
}

// GetNetworkSummary aggregates service's NEL reports over the trailing 30
// days.
func GetNetworkSummary(ctx context.Context, d *gorm.DB, service string) (*NetworkSummary, error) {
	cutoff := time.Now().Add(-networkWindow)
	out := &NetworkSummary{}

	err := nelScope(ctx, d, service, cutoff).
		Select("DATE(created_at) AS day, " +
			"SUM(" + nelWeight + ") AS requests, " +
			"SUM(CASE WHEN nel_type = 'ok' THEN " + nelWeight + " ELSE 0 END) AS ok, " +
			"COUNT(*) AS reports").
		Group("DATE(created_at)").
		Order("DATE(created_at)").
		Find(&out.Days).Error
	if err != nil {
		return nil, fmt.Errorf("querying network days: %w", err)
	}
	for _, day := range out.Days {
		out.Requests += day.Requests
		out.OK += day.OK
	}

	var elapsed struct {
		OK     *float64
		Failed *float64
	}
	err = nelScope(ctx, d, service, cutoff).
		Select("AVG(CASE WHEN nel_type = 'ok' THEN elapsed_time END) AS ok, " +
			"AVG(CASE WHEN nel_type <> 'ok' THEN elapsed_time END) AS failed").
		Scan(&elapsed).Error
	if err != nil {
		return nil, fmt.Errorf("querying network latency: %w", err)
	}
	if elapsed.OK != nil {
		out.AvgElapsedOK = *elapsed.OK
	}
	if elapsed.Failed != nil {
		out.AvgElapsedFailed = *elapsed.Failed
	}

	for _, dim := range []struct {
		column string
		dst    *[]NetworkBreakdown
	}{
		{"nel_type", &out.ByType},
		{"phase", &out.ByPhase},
		{"document_uri", &out.ByURL},
	} {
		err := nelScope(ctx, d, service, cutoff).
			Select(dim.column + " AS name, COUNT(*) AS reports, SUM(" + nelWeight + ") AS estimated").
			Where("nel_type <> 'ok'").
			Group(dim.column).
			Order("reports DESC").
			Limit(10).
			Find(dim.dst).Error
		if err != nil {
			return nil, fmt.Errorf("querying network failures by %s: %w", dim.column, err)
		}
	}

	err = d.WithContext(ctx).
		Where("service = ? AND report_type = ? AND nel_type <> 'ok'", service, ReportTypeNetworkError).
		Order("created_at DESC").
		Limit(20).
		Find(&out.RecentFailures).Error
	if err != nil {
		return nil, fmt.Errorf("querying recent network failures: %w", err)
	}

	return out, nil
}

// NetworkRate is one service's estimated request volume over the window.
type NetworkRate struct {
	Service  string  `json:"service"`
	Requests float64 `json:"requests"`
	OK       float64 `json:"ok"`
}

// GetAllServicesNetwork returns trailing-30-day estimated volume and
// successes keyed by service, for services with NEL reports.
func GetAllServicesNetwork(ctx context.Context, d *gorm.DB) (map[string]NetworkRate, error) {
	var rows []NetworkRate
	err := d.WithContext(ctx).Model(&ReportToEntry{}).
		Select("service, SUM("+nelWeight+") AS requests, "+
			"SUM(CASE WHEN nel_type = 'ok' THEN "+nelWeight+" ELSE 0 END) AS ok").
		Where("report_type = ? AND created_at >= ?", ReportTypeNetworkError, time.Now().Add(-networkWindow)).
		Group("service").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("querying network rates: %w", err)
	}
	out := make(map[string]NetworkRate, len(rows))
	for _, r := range rows {
		out[r.Service] = r
	}
	return out, nil
}

// BackfillNELFields fills the NEL columns of network-error rows stored
// before those columns existed, from each row's raw JSON. It returns how
// many rows it updated.
func BackfillNELFields(ctx context.Context, d *gorm.DB) (int, error) {
	updated := 0
	var lastID uint
	for {
		var rows []ReportToEntry
		err := d.WithContext(ctx).
			Select("id", "raw_json").
			Where("report_type = ? AND nel_type = '' AND id > ?", ReportTypeNetworkError, lastID).
			Order("id").Limit(pruneBatchSize).
			Find(&rows).Error
		if err != nil {
			return updated, fmt.Errorf("finding NEL rows to backfill: %w", err)
		}
		if len(rows) == 0 {
			return updated, nil
		}
		for _, row := range rows {
			lastID = row.ID
			var e reportto.Entry
			if json.Unmarshal([]byte(row.RawJSON), &e) != nil || e.Body.Type == "" {
				continue
			}
			err := d.WithContext(ctx).Model(&ReportToEntry{}).Where("id = ?", row.ID).Updates(map[string]any{
				"nel_type":          e.Body.Type,
				"phase":             e.Body.Phase,
				"elapsed_time":      e.Body.ElapsedTime,
				"sampling_fraction": e.Body.SamplingFraction,
				"method":            e.Body.Method,
				"protocol":          e.Body.Protocol,
				"server_ip":         e.Body.ServerIP,
				"status_code":       cmp.Or(e.Body.StatusCode, e.Body.Status),
			}).Error
			if err != nil {
				return updated, fmt.Errorf("backfilling NEL row %d: %w", row.ID, err)
			}
			updated++
		}
	}
}
