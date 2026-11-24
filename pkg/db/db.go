// Package db owns the SQL persistence layer: GORM models, dialect
// detection, and dashboard query helpers.
package db

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	dialectSQLite   = "sqlite"
	dialectMySQL    = "mysql"
	dialectPostgres = "postgres"
)

// Connect opens databaseURL ("mysql://...", "sqlite://<dsn>", "file:...",
// or "postgres://...") and verifies it with PingContext.
func Connect(ctx context.Context, databaseURL string) (*gorm.DB, error) {
	dialector, dbType, err := dialector(databaseURL)
	if err != nil {
		return nil, err
	}

	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", dbType, err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("getting underlying %s connection: %w", dbType, err)
	}

	// A small pool suits a small instance, and keeping connections warm
	// avoids repeating the TCP+TLS handshake to a remote database. SQLite is
	// left alone: closing an in-memory database's last connection erases it.
	if dbType != dialectSQLite {
		sqlDB.SetMaxOpenConns(4)
		sqlDB.SetMaxIdleConns(2)
		sqlDB.SetConnMaxIdleTime(5 * time.Minute)
		sqlDB.SetConnMaxLifetime(time.Hour)
	}

	if err := sqlDB.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("pinging %s: %w", dbType, err)
	}

	return db, nil
}

// dialector returns the GORM dialector and dialect name for databaseURL.
func dialector(databaseURL string) (gorm.Dialector, string, error) {
	if dsn, ok := strings.CutPrefix(databaseURL, "sqlite://"); ok {
		if dsn == "" {
			return nil, "", errors.New("missing sqlite dsn")
		}
		return sqlite.Open(dsn), dialectSQLite, nil
	}

	if strings.HasPrefix(databaseURL, "file:") {
		return sqlite.Open(databaseURL), dialectSQLite, nil
	}

	if strings.HasPrefix(databaseURL, "mysql://") {
		dsn, err := mysqlDSN(databaseURL)
		if err != nil {
			return nil, "", err
		}
		return mysql.Open(dsn), dialectMySQL, nil
	}

	return postgres.Open(databaseURL), dialectPostgres, nil
}

// mysqlDSN converts "mysql://user:pass@host:3306/db?tls=true" into the
// go-sql-driver DSN form. Query parameters pass through to the driver (e.g.
// tls=true for MySQL HeatWave); parseTime and a UTC location are forced
// because the models and the Day scanner rely on them.
func mysqlDSN(databaseURL string) (string, error) {
	u, err := url.Parse(databaseURL)
	if err != nil {
		// url.Parse errors echo the input, which may hold a password.
		return "", errors.New("parsing mysql url: invalid url")
	}

	dbName := strings.TrimPrefix(u.Path, "/")
	if u.Hostname() == "" || dbName == "" {
		return "", errors.New("mysql url must look like mysql://user:pass@host:3306/dbname")
	}

	port := u.Port()
	if port == "" {
		port = "3306"
	}

	cfg, err := mysqldriver.ParseDSN("/" + dbName + "?" + u.RawQuery)
	if err != nil {
		return "", fmt.Errorf("parsing mysql url parameters: %w", err)
	}
	cfg.User = u.User.Username()
	cfg.Passwd, _ = u.User.Password()
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(u.Hostname(), port)
	cfg.ParseTime = true
	cfg.Loc = time.UTC

	return cfg.FormatDSN(), nil
}

// AutoMigrate syncs the schema with the current models; safe on every startup.
func AutoMigrate(ctx context.Context, db *gorm.DB) error {
	if err := db.WithContext(ctx).AutoMigrate(
		&WebVital{},
		&ReportToEntry{},
		&SecurityReportEntry{},
	); err != nil {
		return fmt.Errorf("auto-migrating: %w", err)
	}

	return nil
}
