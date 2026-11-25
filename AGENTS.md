# AGENTS.md

Guidance for coding agents working on reportd.

## Project Overview

A collector daemon written in Go (`go.icco.me/reportd`) for ingesting browser reporting API payloads (such as Content Security Policy violations and deprecation reports).

## Commands

```sh
go test ./...    # Run tests
go vet ./...     # Vet code
go run main.go   # Run locally (port 8080 by default)
go build .       # Build binary
```

## Architecture & Conventions

- `main.go` — Server entrypoint, Chi router, and report parsing handlers.
- `pkg/db` — GORM models, dialects (MySQL, Postgres, SQLite), dashboard queries, and the storage cap (`retention.go`).
- Projects live in the `projects` table and are cached in memory (`projects.go`), so ingestion never queries the database to check a name. Every `{service}` route goes through `requireProject`; unknown names get 404. Projects are `app` (website) or `api`; `appOnly` answers 422 to Web Vitals and page reports for `api` projects, and `postReportHandler` keeps only NEL entries for them. Ingestion also answers at `?s=<token>` URLs (`projectFromToken`), which set the `{service}` URL parameter so handlers serve both forms alike.
- Templates: `head.tmpl` and `topbar.tmpl` are partials shared by `index.tmpl` and `view.tmpl`. Build DOM with the `el()` helper, never `innerHTML`: report contents are untrusted.
- `pkg/auth` — GitHub OAuth sign-in with an email allowlist. Dashboard pages and read APIs are gated; ingestion POSTs and `/api/status` must stay public.
- `TEST_MYSQL_URL` / `TEST_DATABASE_URL` enable the MySQL / Postgres integration tests in `pkg/db`.
- Follow icco Go conventions (`go.icco.me/gutil` for logging and structured JSON).
- PR titles and commits must follow Conventional Commits with lowercase subjects.
- Ensure all tests pass before submitting PRs.
