# reportd

[![GoDoc](https://pkg.go.dev/badge/go.icco.me/reportd.svg)](https://pkg.go.dev/go.icco.me/reportd)
[![Go Report Card](https://goreportcard.com/badge/github.com/icco/reportd)](https://goreportcard.com/report/github.com/icco/reportd)

A self-hosted service for collecting browser security reports and Web Vitals, with a dashboard for understanding your site's health.

## What it does

reportd receives data from two browser APIs and presents it in a dashboard:

- **Web Vitals** (LCP, CLS, INP, FCP, TTFB) -- performance metrics sent by the [web-vitals](https://github.com/GoogleChrome/web-vitals) library
- **Browser Reports** (CSP violations, deprecation warnings, interventions, crashes, COOP/COEP violations, permissions policy violations) -- sent automatically by browsers via the [Reporting API](https://developer.chrome.com/docs/capabilities/web-apis/reporting-api)

Data is stored in a SQL database via GORM -- **MySQL** (including Oracle **MySQL HeatWave**, which fits the OCI Always Free tier), **Postgres**, or **SQLite**. Forwarding to **BigQuery** for long-term analytics is optional.

The dashboard and its read APIs require **GitHub sign-in** from an allowlisted email. Ingestion endpoints stay public, because browsers send reports anonymously.

## Supported report types

| Type | Source | Description |
|------|--------|-------------|
| CSP violation | `report-to` / Reporting API | Content Security Policy violations |
| Expect-CT | `report-to` | Certificate Transparency violations (legacy) |
| Deprecation | Reporting API | Usage of deprecated browser APIs |
| Permissions Policy | Reporting API | Blocked access to browser features (camera, geolocation, etc.) |
| Intervention | Reporting API | Browser blocked something for performance/UX |
| Crash | Reporting API | Tab crash (OOM) or unresponsive page |
| COEP | Reporting API | Cross-Origin-Embedder-Policy violations |
| COOP | Reporting API | Cross-Origin-Opener-Policy violations |
| Document Policy | Reporting API | Document-Policy violations |

Unknown report types are stored as raw JSON for forward compatibility.

## Setup

### Configuration

reportd is configured via environment variables (prefix `REPORTD_`) or command-line flags:

| Variable | Flag | Required | Description |
|----------|------|----------|-------------|
| `REPORTD_DATABASE_URL` | `--database_url` | Yes | Database connection string: `mysql://`, `postgres://`, or `sqlite://` |
| `REPORTD_GITHUB_CLIENT_ID` | `--github_client_id` | Yes | GitHub OAuth app client ID |
| `REPORTD_GITHUB_CLIENT_SECRET` | `--github_client_secret` | Yes | GitHub OAuth app client secret |
| `REPORTD_ALLOWED_EMAILS` | `--allowed_emails` | Yes | Comma-separated allowlist of emails that may sign in |
| `REPORTD_SESSION_SECRET` | `--session_secret` | No | Secret (32+ characters) that signs session cookies. When unset a random one is generated at startup, so every restart signs everyone out |
| `REPORTD_MAX_STORAGE_GB` | `--max_storage_gb` | No | Storage cap in GB (default: `5`). `0` disables the cap |
| `REPORTD_PROJECT` | `--project` | No | GCP project ID. Setting it enables BigQuery forwarding |
| `REPORTD_DATASET` | `--dataset` | With project | BigQuery dataset name |
| `REPORTD_ANALYTICS_TABLE` | `--analytics_table` | With project | BigQuery table for Web Vitals |
| `REPORTD_REPORTS_TABLE` | `--reports_table` | With project | BigQuery table for Report-To data |
| `REPORTD_REPORTS_V2_TABLE` | `--reports_v2_table` | No | BigQuery table for Reporting API v1 data |
| `PORT` | -- | No | HTTP port (default: 8080) |

### Sign-in (GitHub OAuth)

reportd refuses to start without sign-in configured.

1. Create an OAuth app at <https://github.com/settings/developers>.
2. Set its **Authorization callback URL** to `https://your-reportd-instance/auth/callback`.
3. Set `REPORTD_GITHUB_CLIENT_ID` and `REPORTD_GITHUB_CLIENT_SECRET` from the app, and list who may sign in in `REPORTD_ALLOWED_EMAILS`:

```bash
REPORTD_ALLOWED_EMAILS=you@example.com,teammate@example.com
REPORTD_SESSION_SECRET=$(openssl rand -hex 32)
```

A GitHub account gets in when one of its **verified** emails is on the allowlist (matching is case-insensitive). Sessions last 7 days; removing an email from the allowlist and restarting revokes its sessions.

| Routes | Access |
|--------|--------|
| `GET /`, `GET /view/{service}` | Sign-in required; anonymous visitors are redirected to GitHub |
| `GET /api/*`, `GET /services`, `GET /reports/{service}`, `GET /analytics/{service}`, `GET /metrics` | Sign-in required; anonymous requests get `401` |
| `POST /analytics/{service}`, `POST /report/{service}`, `POST /reporting/{service}`, `GET /api/status` | Public |

`/metrics` needs a session cookie, so a Prometheus scraper cannot read it directly.

### Storage cap

Every 10 minutes (and at startup) reportd measures the size of its tables, data plus indexes. Above `REPORTD_MAX_STORAGE_GB` it **permanently deletes the oldest rows** from each table until usage is back to 80% of the cap, then compacts the tables (`OPTIMIZE TABLE` on MySQL, `VACUUM FULL` on Postgres) so the space is actually released.

The cap covers reportd's own tables only. Server-side overhead such as MySQL binary logs and backups is outside its view, so keep some headroom below what your provider bills for.

### Ingestion and small instances

Ingestion endpoints never wait on the database. A report is parsed, queued in memory, and answered with `204` straight away; a background writer batches the queue into multi-row `INSERT`s about once a second. A slow, distant, or briefly unreachable database therefore does not slow down or fail report uploads.

Delivery is best effort, and losses show up only in the logs as `dropped ingested rows`:

- The queue holds at most 5000 rows or about 32 MiB. Beyond that, new rows are dropped.
- A failed batch is retried 3 times with backoff, then dropped.
- On `SIGTERM` the queue is written out before exit. A hard kill or crash loses what was queued, up to about a second of reports.
- Dashboards lag ingestion by about a second.

Because uploads always get `204`, `GET /api/status` is where failing writes surface. While the most recent batch could not be written it returns `503` with `orm: error <code>`, where the code is the database's own error number (for example MySQL `1146`, table missing), `timeout`, or `unknown`. It returns to `200` once a later batch is written. The full error is in the logs.

Other limits that keep a small instance (for example 0.1 vCPU / 512 MB) stable: uploads over 1 MiB get `413`, and the database pool is capped at 4 connections that are kept warm to avoid repeated TLS handshakes. Setting `GOMEMLIMIT=400MiB` in the environment is recommended on a 512 MB instance so the Go runtime collects garbage before the container is killed.

### Oracle MySQL HeatWave

Point `REPORTD_DATABASE_URL` at the DB system. The schema is created on first start.

```bash
REPORTD_DATABASE_URL='mysql://reportd:PASSWORD@10.0.1.23:3306/reportd?tls=true'
```

Query parameters are passed to the [MySQL driver](https://github.com/go-sql-driver/mysql#dsn-data-source-name): `tls=true` verifies the server certificate, `tls=skip-verify` encrypts without verifying. A HeatWave DB system only has a private IP, so run reportd in the same VCN (for example on an Always Free compute instance) or reach it through a bastion or VPN. Create the database and user first:

```sql
CREATE DATABASE reportd CHARACTER SET utf8mb4;
CREATE USER 'reportd'@'%' IDENTIFIED BY 'PASSWORD';
GRANT ALL ON reportd.* TO 'reportd'@'%';
```

### Docker

```bash
docker run -p 8080:8080 \
  -e REPORTD_DATABASE_URL='mysql://reportd:PASSWORD@host:3306/reportd?tls=true' \
  -e REPORTD_GITHUB_CLIENT_ID=your-client-id \
  -e REPORTD_GITHUB_CLIENT_SECRET=your-client-secret \
  -e REPORTD_ALLOWED_EMAILS=you@example.com \
  -e REPORTD_SESSION_SECRET=a-long-random-string-of-32-or-more-chars \
  ghcr.io/icco/reportd
```

### Docker Compose (self-hosting)

The example below runs reportd with its own MySQL database in a single `docker compose up -d`.

Save this as `docker-compose.yml`:

```yaml
services:
  reportd:
    image: ghcr.io/icco/reportd:main
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      REPORTD_DATABASE_URL: mysql://reportd:reportd@db:3306/reportd
      REPORTD_GITHUB_CLIENT_ID: your-client-id
      REPORTD_GITHUB_CLIENT_SECRET: your-client-secret
      REPORTD_ALLOWED_EMAILS: you@example.com
      REPORTD_SESSION_SECRET: a-long-random-string-of-32-or-more-chars
    depends_on:
      db:
        condition: service_healthy

  db:
    image: mysql:8.4
    restart: unless-stopped
    environment:
      MYSQL_USER: reportd
      MYSQL_PASSWORD: reportd
      MYSQL_DATABASE: reportd
      MYSQL_RANDOM_ROOT_PASSWORD: "yes"
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "127.0.0.1", "-ureportd", "-preportd"]
      interval: 5s
      retries: 20
    volumes:
      - reportd-mysql:/var/lib/mysql

volumes:
  reportd-mysql:
```

reportd will be reachable at `http://localhost:8080`. Put it behind a reverse proxy (Caddy, nginx, Traefik) to expose it on a public hostname over HTTPS — browser reporting endpoints must be HTTPS. The proxy must send `X-Forwarded-Proto: https` so session cookies are marked `Secure`.

Other databases use the same variable: `postgresql://reportd:reportd@db:5432/reportd?sslmode=disable` for Postgres, or `sqlite:///data/reportd.db` with a volume mounted at `/data` for SQLite.

To also forward to BigQuery, set `REPORTD_PROJECT`, `REPORTD_DATASET`, `REPORTD_ANALYTICS_TABLE`, `REPORTD_REPORTS_TABLE` and `REPORTD_REPORTS_V2_TABLE`, mount a service account key, and point `GOOGLE_APPLICATION_CREDENTIALS` at it.

### Local development

```bash
# Start MySQL
docker run -d --name reportd-mysql -p 3306:3306 \
  -e MYSQL_ROOT_PASSWORD=reportd -e MYSQL_DATABASE=reportd \
  mysql:8.4

# Run reportd (OAuth app callback: http://localhost:8080/auth/callback)
export REPORTD_DATABASE_URL=mysql://root:reportd@localhost:3306/reportd
export REPORTD_GITHUB_CLIENT_ID=your-client-id
export REPORTD_GITHUB_CLIENT_SECRET=your-client-secret
export REPORTD_ALLOWED_EMAILS=you@example.com
go run main.go
```

For SQLite instead of MySQL:

```bash
export REPORTD_DATABASE_URL=sqlite:///tmp/reportd.db
```

The MySQL integration test runs when `TEST_MYSQL_URL` is set:

```bash
TEST_MYSQL_URL=mysql://root:reportd@localhost:3306/reportd go test ./pkg/db/
```

## Syncing with upstream

`.github/workflows/sync-upstream.yml` merges [icco/reportd](https://github.com/icco/reportd) `main` into this repository's `main` every day (and on demand from the Actions tab). The merge is built and tested before it is pushed. When upstream conflicts with local changes, or the merged code fails its tests, the run fails and nothing is pushed; merge by hand in that case.

This repository keeps no other workflow: anything upstream adds or changes under `.github/workflows` is dropped during the merge.

## Integrating with your site

### Web Vitals

Add this snippet to your site to send Web Vitals to reportd:

```html
<script type="module">
  import { onCLS, onINP, onLCP, onFCP, onTTFB } from 'https://unpkg.com/web-vitals@5?module';

  function sendToAnalytics(metric) {
    const body = JSON.stringify(metric);
    (navigator.sendBeacon && navigator.sendBeacon('https://your-reportd-instance/analytics/yoursite', body)) ||
      fetch('https://your-reportd-instance/analytics/yoursite', { body, method: 'POST', keepalive: true });
  }

  onCLS(sendToAnalytics);
  onFCP(sendToAnalytics);
  onINP(sendToAnalytics);
  onLCP(sendToAnalytics);
  onTTFB(sendToAnalytics);
</script>
```

### Browser reports

Add these HTTP headers to your site's responses:

```
Reporting-Endpoints: default="https://your-reportd-instance/reporting/yoursite"
Content-Security-Policy: ...; report-to default;
Cross-Origin-Opener-Policy: same-origin; report-to="default"
Cross-Origin-Embedder-Policy: require-corp; report-to="default"
Permissions-Policy: camera=(), geolocation=(); report-to="default"
```

For legacy `Report-To` support:

```
Report-To: {"group":"default","max_age":10886400,"endpoints":[{"url":"https://your-reportd-instance/report/yoursite"}]}
```

## API reference

### Ingestion (POST)

| Endpoint | Content-Type | Description |
|----------|-------------|-------------|
| `POST /analytics/{service}` | `application/json` | Web Vitals data |
| `POST /report/{service}` | `application/csp-report`, `application/expect-ct-report+json`, `application/reports+json` | Legacy Report-To data |
| `POST /reporting/{service}` | `application/reports+json`, `application/csp-report` | Reporting API v1 data |

### Dashboard (GET, sign-in required except `/api/status`)

| Endpoint | Description |
|----------|-------------|
| `GET /` | Service index with health indicators |
| `GET /view/{service}` | Dashboard for a specific service |
| `GET /api/vitals/{service}` | JSON: p75 summaries and daily time series |
| `GET /api/reports/{service}` | JSON: report counts, recent reports, top violated directives |
| `GET /analytics/{service}` | JSON: daily average Web Vitals |
| `GET /reports/{service}` | JSON: daily report counts |
| `GET /services` | JSON: list of all services |
| `GET /metrics` | Prometheus metrics |
| `GET /api/status` | Health check (public): `200 ok.`, or `503 orm: error <code>` while database writes are failing |

### Sign-in

| Endpoint | Description |
|----------|-------------|
| `GET /auth/login` | Start GitHub sign-in |
| `GET /auth/callback` | OAuth callback (register this on the GitHub OAuth app) |
| `POST /auth/logout` | Sign out |

## Dashboard features

The service view page provides:

- **Core Web Vitals cards** with p75 values rated against Google's thresholds (good / needs improvement / poor)
- **Time-series charts** for each metric with threshold bands
- **Report volume chart** showing report counts by type over time
- **Recent CSP violations table** with violated directive, blocked URI, document URI, and source location
- **Recent reports table** for deprecation warnings, interventions, crashes, and other browser reports
- **Top violated directives** bar chart showing the most frequently violated CSP directives
