package db

import (
	"context"
	"errors"
	"fmt"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestErrorCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"mysql errno", fmt.Errorf("insert: %w", &mysqldriver.MySQLError{Number: 1146, Message: "Table 'reportd.web_vitals' doesn't exist"}), "1146"},
		{"postgres sqlstate", fmt.Errorf("insert: %w", &pgconn.PgError{Code: "42P01"}), "42P01"},
		{"timeout", fmt.Errorf("insert: %w", context.DeadlineExceeded), "timeout"},
		{"joined errors use the first known code", errors.Join(errors.New("x"), &mysqldriver.MySQLError{Number: 1040}), "1040"},
		{"anything else", errors.New("dial tcp 10.0.0.1:3306: connection refused"), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ErrorCode(tt.err); got != tt.want {
				t.Errorf("ErrorCode() = %q, want %q", got, tt.want)
			}
		})
	}
}
