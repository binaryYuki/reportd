package db

import (
	"context"
	"errors"
	"strconv"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	sqlite3 "github.com/mattn/go-sqlite3"
)

// ErrorCode reduces a database error to a short code that is safe to show
// publicly: the server's own error number where there is one (MySQL errno,
// Postgres SQLSTATE, SQLite result code), otherwise "timeout" or "unknown".
// Unlike err.Error() it never carries table names, hosts, or SQL.
func ErrorCode(err error) string {
	var myErr *mysqldriver.MySQLError
	if errors.As(err, &myErr) {
		return strconv.Itoa(int(myErr.Number))
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}

	var liteErr sqlite3.Error
	if errors.As(err, &liteErr) {
		return strconv.Itoa(int(liteErr.Code))
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "unknown"
}
