// Command reportd ingests browser security reports and Web Vitals,
// persists them to SQL, and optionally forwards them to BigQuery. The
// dashboard is gated behind GitHub OAuth sign-in.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	chi "github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/peterbourgon/ff/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/unrolled/render"
	"github.com/unrolled/secure"
	"go.icco.me/gutil/logging"
	"go.icco.me/gutil/tracing"
	"go.icco.me/reportd/pkg/analytics"
	"go.icco.me/reportd/pkg/auth"
	"go.icco.me/reportd/pkg/db"
	"go.icco.me/reportd/pkg/lib"
	"go.icco.me/reportd/pkg/reporting"
	"go.icco.me/reportd/pkg/reportto"
	"go.icco.me/reportd/templates"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
	"go.uber.org/zap"
	"gorm.io/gorm"
	gormtracing "gorm.io/plugin/opentelemetry/tracing"
)

const serverName = "reportd"

var (
	service = "reportd"
	log     = logging.Must(logging.NewLogger(service))
)

// BigQuery writer hooks injected into post handlers so tests can no-op.
type (
	reportToBQWriter       func(ctx context.Context, r *reportto.Report)
	analyticsBQWriter      func(ctx context.Context, r *analytics.WebVital)
	securityReportBQWriter func(ctx context.Context, r *reporting.SecurityReport)
)

func writeJSON(w http.ResponseWriter, data any) error {
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(data)
}

// routeTag stamps the chi route pattern onto otelhttp metric labels.
func routeTag(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		labeler, ok := otelhttp.LabelerFromContext(r.Context())
		if !ok {
			return
		}
		if pattern := chi.RouteContext(r.Context()).RoutePattern(); pattern != "" {
			labeler.Add(semconv.HTTPRoute(pattern))
		}
	})
}

func main() {
	shutdownTracer, err := tracing.Init(context.Background(), service)
	if err != nil {
		log.Fatalw("tracing init", zap.Error(err))
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTracer(shutdownCtx); err != nil {
			log.Warnw("tracing shutdown", zap.Error(err))
		}
	}()

	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	project := fs.String("project", "", "Project ID containing the bigquery dataset to upload to.")
	dataset := fs.String("dataset", "", "The bigquery dataset to upload to.")
	aTable := fs.String("analytics_table", "", "The bigquery table to upload analytics to.")
	rTable := fs.String("reports_table", "", "The bigquery table to upload reports to.")
	rv2Table := fs.String("reports_v2_table", "", "The bigquery table to upload reports to.")
	databaseURL := fs.String("database_url", "", "Database connection string (e.g. postgres://user:pass@host/reportd or sqlite:///tmp/reportd.db).")
	githubClientID := fs.String("github_client_id", "", "GitHub OAuth app client ID used for dashboard sign-in.")
	githubClientSecret := fs.String("github_client_secret", "", "GitHub OAuth app client secret.")
	allowedEmails := fs.String("allowed_emails", "", "Comma-separated allowlist of verified GitHub emails that may sign in.")
	sessionSecret := fs.String("session_secret", "", "Secret (32+ chars) signing session cookies. Random per start when unset.")
	maxStorageGB := fs.Float64("max_storage_gb", 5, "Storage cap in GB; the oldest rows are deleted beyond it. 0 disables the cap.")
	if err := ff.Parse(fs, os.Args[1:], ff.WithEnvVarPrefix("REPORTD")); err != nil {
		log.Fatalw("error parsing flags", zap.Error(err))
	}

	port := "8080"
	if fromEnv := os.Getenv("PORT"); fromEnv != "" {
		port = fromEnv
	}
	log.Infow("Starting up", "host", fmt.Sprintf("http://localhost:%s", port))

	// BigQuery is optional: it is only used when a project is configured.
	bigQuery := *project != ""
	if bigQuery {
		if *dataset == "" {
			log.Fatalw("dataset is required when project is set")
		}

		if *aTable == "" {
			log.Fatalw("analytics_table is required when project is set")
		}

		if *rTable == "" {
			log.Fatalw("reports_table is required when project is set")
		}
	}

	if *databaseURL == "" {
		log.Fatalw("database_url is required")
	}

	authn, err := newAuthenticator(*githubClientID, *githubClientSecret, *allowedEmails, *sessionSecret)
	if err != nil {
		log.Fatalw("dashboard sign-in is not configured", zap.Error(err))
	}

	ctx := context.Background()

	registry := prometheus.NewRegistry()
	exporter, err := otelprom.New(otelprom.WithRegisterer(registry))
	if err != nil {
		log.Fatalw("otel prometheus exporter", zap.Error(err))
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	otel.SetMeterProvider(mp)
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := mp.Shutdown(shutdownCtx); err != nil {
			log.Warnw("meter provider shutdown", zap.Error(err))
		}
	}()

	pgDB, err := db.Connect(ctx, *databaseURL)
	if err != nil {
		log.Fatalw("could not connect to database", zap.Error(err))
	}
	if err := pgDB.Use(gormtracing.NewPlugin(
		gormtracing.WithoutMetrics(),
		gormtracing.WithoutQueryVariables(),
	)); err != nil {
		log.Fatalw("could not register otel plugin", zap.Error(err))
	}
	if err := db.AutoMigrate(ctx, pgDB); err != nil {
		log.Fatalw("could not auto-migrate database", zap.Error(err))
	}
	log.Infow("Database connected and migrated")

	var (
		writeReport         reportToBQWriter
		writeAnalytics      analyticsBQWriter
		writeSecurityReport securityReportBQWriter
	)
	if bigQuery {
		if err := reportto.UpdateReportsBQSchema(ctx, *project, *dataset, *rTable); err != nil {
			log.Errorw("report table update", zap.Error(err))
		}

		if err := analytics.UpdateAnalyticsBQSchema(ctx, *project, *dataset, *aTable); err != nil {
			log.Errorw("analytics table update", zap.Error(err))
		}

		if err := reporting.UpdateReportsBQSchema(ctx, *project, *dataset, *rv2Table); err != nil {
			log.Errorw("reporting table update", zap.Error(err))
		}

		writeReport = func(ctx context.Context, r *reportto.Report) {
			if err := reportto.WriteReportToBigQuery(ctx, *project, *dataset, *rTable, []*reportto.Report{r}); err != nil {
				log.Errorw("error during report upload to bigquery", "dataset", *dataset, "project", *project, "table", *rTable, zap.Error(err))
			}
		}
		writeAnalytics = func(ctx context.Context, wv *analytics.WebVital) {
			if err := analytics.WriteAnalyticsToBigQuery(ctx, *project, *dataset, *aTable, []*analytics.WebVital{wv}); err != nil {
				log.Errorw("error during analytics upload to bigquery", "dataset", *dataset, "project", *project, "table", *aTable, zap.Error(err))
			}
		}
		writeSecurityReport = func(ctx context.Context, sr *reporting.SecurityReport) {
			if err := reporting.WriteReportsToBigQuery(ctx, *project, *dataset, *rv2Table, sr); err != nil {
				log.Errorw("error during reporting upload to bigquery", "dataset", *dataset, "project", *project, "table", *rv2Table, zap.Error(err))
			}
		}
	} else {
		log.Infow("BigQuery disabled: no project configured")
	}

	pruneCtx, stopPrune := context.WithCancel(ctx)
	defer stopPrune()
	if *maxStorageGB > 0 {
		maxBytes := int64(*maxStorageGB * (1 << 30))
		log.Infow("Storage cap enabled", "max_bytes", maxBytes)
		go enforceStorageLimitLoop(pruneCtx, pgDB, maxBytes, storageCheckInterval)
	} else {
		log.Warnw("Storage cap disabled: the database can grow without bound")
	}

	ingest := db.NewWriter(pgDB, db.WriterOptions{OnDrop: logDroppedRows})

	r := newRouter(pgDB, ingest, writeReport, writeAnalytics, writeSecurityReport, authn)
	r.Method(http.MethodGet, "/metrics", authn.RequireAPI(promhttp.HandlerFor(registry, promhttp.HandlerOpts{})))

	handler := otelhttp.NewHandler(r, serverName,
		otelhttp.WithFilter(func(req *http.Request) bool {
			return req.URL.Path != "/metrics" && req.URL.Path != statusPath
		}),
	)

	srv := http.Server{
		Addr:              ":" + port,
		WriteTimeout:      30 * time.Second,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
		Handler:           handler,
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalw("Server failed", zap.Error(err))
		}
	}()

	log.Infow("Server ready", "addr", srv.Addr)
	<-done
	log.Infow("Shutting down")

	shutdownCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Errorw("Shutdown failed", zap.Error(err))
	}

	// After the server stops accepting requests, write what is still queued.
	if err := ingest.Close(shutdownCtx); err != nil {
		log.Errorw("ingest queue did not drain before shutdown", zap.Error(err))
	}

	log.Infow("Server stopped")
}

// storageCheckInterval is how often the storage cap is checked.
const storageCheckInterval = 10 * time.Minute

// newAuthenticator builds the dashboard authenticator from flag values. An
// unset session secret gets a random one, which signs everyone out on restart.
func newAuthenticator(clientID, clientSecret, allowedEmails, sessionSecret string) (*auth.Authenticator, error) {
	secret := []byte(sessionSecret)
	if len(secret) == 0 {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("generating session secret: %w", err)
		}
		log.Warnw("session_secret is not set; sessions will not survive a restart")
	}

	return auth.New(auth.Config{
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		AllowedEmails: auth.ParseAllowedEmails(allowedEmails),
		SessionSecret: secret,
	})
}

// enforceStorageLimitLoop prunes the oldest rows whenever the database grows
// past maxBytes, checking at startup and then every interval until ctx ends.
func enforceStorageLimitLoop(ctx context.Context, d *gorm.DB, maxBytes int64, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		res, err := db.EnforceStorageLimit(ctx, d, maxBytes)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			log.Errorw("enforcing storage cap", zap.Error(err), "max_bytes", maxBytes)
		case res.RowsDeleted > 0:
			log.Warnw("storage cap exceeded; pruned oldest rows", "max_bytes", maxBytes,
				"bytes_before", res.BytesBefore, "bytes_after", res.BytesAfter, "rows_deleted", res.RowsDeleted)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// newRouter builds the chi router shared by main() and the handler tests;
// /metrics is mounted by main() because it owns the prometheus registry.
// Ingested rows go through ingest so handlers never wait on the database.
// A nil authn leaves the dashboard open, which only the tests rely on.
func newRouter(pgDB *gorm.DB, ingest *db.Writer, writeReport reportToBQWriter, writeAnalytics analyticsBQWriter, writeSecurityReport securityReportBQWriter, authn *auth.Authenticator) *chi.Mux {
	r := chi.NewRouter()
	r.Use(logging.Middleware(log.Desugar()))
	r.Use(routeTag)
	r.Use(middleware.Compress(5))

	r.Use(cors.New(cors.Options{
		// AllowCredentials must stay false to keep the wildcard origin safe (CORS bypass).
		AllowCredentials:   false,
		OptionsPassthrough: true,
		AllowedOrigins:     []string{"*"},
		AllowedMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:     []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:     []string{"Link"},
		MaxAge:             300,
	}).Handler)

	r.Use(middleware.Timeout(30 * time.Second))

	r.Use(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("report-to", `{"group":"default","max_age":10886400,"endpoints":[{"url":"https://reportd.natwelch.com/report/reportd"}]}`)
			w.Header().Set("reporting-endpoints", `default="https://reportd.natwelch.com/reporting/reportd"`)

			h.ServeHTTP(w, r)
		})
	})

	secureMiddleware := secure.New(secure.Options{
		SSLRedirect:          false,
		SSLProxyHeaders:      map[string]string{"X-Forwarded-Proto": "https"},
		STSSeconds:           63072000,
		STSIncludeSubdomains: true,
		STSPreload:           true,
		FrameDeny:            true,
		ContentTypeNosniff:   true,
		BrowserXssFilter:     true,
		ReferrerPolicy:       "no-referrer",
		PermissionsPolicy:    "geolocation=(), midi=(), sync-xhr=(), microphone=(), camera=(), magnetometer=(), gyroscope=(), fullscreen=(), payment=(), usb=()",
	})
	r.Use(secureMiddleware.Handler)

	re := render.New(render.Options{
		Directory:  ".",
		FileSystem: &render.EmbedFileSystem{FS: templates.FS},
		Extensions: []string{".tmpl"},
	})

	r.Get("/robots.txt", robotsTxtHandler())
	r.Get("/favicon.ico", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	// Dashboard pages and read APIs need a signed-in, allowlisted user. The
	// ingestion POSTs below stay public: browsers send reports anonymously.
	page := func(h http.Handler) http.Handler { return h }
	api := page
	if authn != nil {
		authn.Routes(r)
		page, api = authn.RequirePage, authn.RequireAPI
	}

	r.With(page).Get("/", indexHandler(re, pgDB))
	r.With(page).Get("/view/{service}", viewHandler(re))
	r.Get(statusPath, statusHandler(ingest))

	r.Options("/report/{service}", corsPreflightHandler())
	r.Options("/analytics/{service}", corsPreflightHandler())

	r.With(api).Get("/reports/{service}", getReportsHandler(pgDB))
	r.Post("/report/{service}", postReportHandler(ingest, writeReport))

	r.With(api).Get("/services", getServicesHandler(pgDB))
	r.With(api).Get("/analytics/{service}", getAnalyticsHandler(pgDB))
	r.Post("/analytics/{service}", postAnalyticsHandler(ingest, writeAnalytics))

	r.Post("/reporting/{service}", postReportingHandler(ingest, writeSecurityReport))

	r.With(api).Get("/api/vitals/{service}", apiVitalsHandler(pgDB))
	r.With(api).Get("/api/reports/{service}", apiReportsHandler(pgDB))

	return r
}

func indexHandler(re *render.Render, pgDB *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := queryContext(r.Context())
		defer cancel()
		l := logging.FromContext(ctx)

		services, err := db.GetServices(ctx, pgDB)
		if err != nil {
			l.Errorw("error getting services", zap.Error(err))
			http.Error(w, "could not get services", 500)
			return
		}

		health, err := db.GetAllServicesHealth(ctx, pgDB)
		if err != nil {
			l.Errorw("error getting services health", zap.Error(err))
			health = make(map[string][]db.ServiceHealth)
		}

		healthJSON, _ := json.Marshal(health)

		if err := re.HTML(w, http.StatusOK, "index", struct {
			Services   []string
			HealthJSON string
			User       string
		}{
			User:       auth.EmailFromContext(r.Context()),
			Services:   services,
			HealthJSON: string(healthJSON),
		}); err != nil {
			l.Errorw("error rendering index", zap.Error(err))
			http.Error(w, "could not render index", 500)
			return
		}
	}
}

func viewHandler(re *render.Render) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		l := logging.FromContext(r.Context())
		service := chi.URLParam(r, "service")

		if err := lib.ValidateService(service); err != nil {
			l.Warnw("invalid service", zap.Error(err), "service", service)
			http.Error(w, "could not validate service", 400)
			return
		}

		if err := re.HTML(w, http.StatusOK, "view", struct {
			Service string
			User    string
		}{
			User:    auth.EmailFromContext(r.Context()),
			Service: service,
		}); err != nil {
			l.Errorw("error rendering view", zap.Error(err), "service", service)
			http.Error(w, "could not render view", 500)
			return
		}
	}
}

// statusPath is the public health endpoint.
const statusPath = "/api/status"

// statusHandler reports whether ingested rows are reaching the database.
// Writes are asynchronous, so this is where a failing write becomes visible:
// while the most recent batch failed it answers 503 "orm: error <code>".
// Only the code is exposed; the endpoint is public and the full error is in
// the logs.
func statusHandler(ingest *db.Writer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status, body := http.StatusOK, "ok."
		if ingest != nil {
			if err := ingest.LastError(); err != nil {
				status, body = http.StatusServiceUnavailable, "orm: error "+db.ErrorCode(err)
			}
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		if _, err := w.Write([]byte(body)); err != nil {
			logging.FromContext(r.Context()).Errorw("error writing status", zap.Error(err))
		}
	}
}

func robotsTxtHandler() http.HandlerFunc {
	body, err := fs.ReadFile(templates.FS, "robots.txt")
	if err != nil {
		log.Fatalw("could not read embedded robots.txt", zap.Error(err))
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		if _, err := w.Write(body); err != nil {
			logging.FromContext(r.Context()).Errorw("error writing robots.txt", zap.Error(err))
		}
	}
}

func corsPreflightHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		l := logging.FromContext(r.Context())
		service := chi.URLParam(r, "service")
		if err := lib.ValidateService(service); err != nil {
			l.Warnw("invalid service", zap.Error(err), "service", service)
			http.Error(w, "could not validate service", 400)
			return
		}
		if _, err := w.Write([]byte("")); err != nil {
			l.Errorw("error writing options", zap.Error(err))
		}
	}
}

func getReportsHandler(pgDB *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		l := logging.FromContext(ctx)
		service := chi.URLParam(r, "service")

		if err := lib.ValidateService(service); err != nil {
			l.Warnw("invalid service", zap.Error(err), "service", service)
			http.Error(w, "could not validate service", 400)
			return
		}

		data, err := db.GetReportCounts(ctx, pgDB, service)
		if err != nil {
			l.Errorw("error getting report counts from postgres", zap.Error(err), "service", service)
			http.Error(w, "processing error", 500)
			return
		}

		if err := writeJSON(w, data); err != nil {
			l.Errorw("error writing reports", zap.Error(err), "service", service)
		}
	}
}

// maxIngestBodyBytes caps a report upload. It bounds the memory one request
// can pin, and with it the worst-case size of the ingest queue.
const maxIngestBodyBytes = 1 << 20

// logDroppedRows reports rows the ingest writer could not persist. Clients
// were already answered, so the log is the only trace of the loss.
func logDroppedRows(rows int, err error) {
	log.Errorw("dropped ingested rows", "rows", rows, zap.Error(err))
}

// queryContext detaches a request context so a client hanging up does not
// cancel a short dashboard query mid-flight, which Postgres logs as an error.
func queryContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
}

func handleBodyReadError(w http.ResponseWriter, r *http.Request, service string, err error) {
	l := logging.FromContext(r.Context())
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		l.Warnw("request body too large", "service", service, "limit", tooLarge.Limit)
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		l.Warnw("incomplete request body", zap.Error(err), "service", service, "content-type", r.Header.Get("Content-Type"))
		http.Error(w, "incomplete request body", http.StatusBadRequest)
		return
	}
	l.Errorw("error reading body", zap.Error(err), "service", service, "content-type", r.Header.Get("Content-Type"))
	http.Error(w, "uploading error", http.StatusInternalServerError)
}

func postReportHandler(ingest *db.Writer, writeBQ reportToBQWriter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		l := logging.FromContext(ctx)
		service := chi.URLParam(r, "service")

		if err := lib.ValidateService(service); err != nil {
			l.Warnw("invalid service", zap.Error(err), "service", service)
			http.Error(w, "could not validate service", 400)
			return
		}

		buf := new(bytes.Buffer)
		if _, err := buf.ReadFrom(http.MaxBytesReader(w, r.Body, maxIngestBodyBytes)); err != nil {
			handleBodyReadError(w, r, service, err)
			return
		}
		bodyStr := buf.String()
		ct := r.Header.Get("content-type")

		data, err := reportto.ParseReport(ct, bodyStr, service)
		if err != nil {
			l.Errorw("error seen during report parse", "content-type", ct, "user-agent", r.UserAgent(), "bodyJson", bodyStr, zap.Error(err), "service", service)
			http.Error(w, "processing error", 500)
			return
		}

		l.Infow("report received", "content-type", ct, "service", service, "user-agent", r.UserAgent(), "report", data)

		for _, entry := range db.ReportToEntriesFromReport(data) {
			ingest.Enqueue(entry)
		}

		w.WriteHeader(http.StatusNoContent)

		if writeBQ != nil {
			go writeBQ(context.WithoutCancel(ctx), data)
		}
	}
}

func getServicesHandler(pgDB *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		l := logging.FromContext(ctx)

		data, err := db.GetServices(ctx, pgDB)
		if err != nil {
			l.Errorw("error seen during services get", zap.Error(err))
			http.Error(w, "processing error", 500)
			return
		}

		if err := writeJSON(w, data); err != nil {
			l.Errorw("error writing services", zap.Error(err))
		}
	}
}

func getAnalyticsHandler(pgDB *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		l := logging.FromContext(ctx)
		service := chi.URLParam(r, "service")

		if err := lib.ValidateService(service); err != nil {
			l.Warnw("invalid service", zap.Error(err), "service", service)
			http.Error(w, "could not validate service", 400)
			return
		}

		data, err := db.GetWebVitalSummaries(ctx, pgDB, service)
		if err != nil {
			l.Errorw("error getting analytics from postgres", zap.Error(err), "service", service)
			http.Error(w, "processing error", 500)
			return
		}

		if err := writeJSON(w, data); err != nil {
			l.Errorw("error writing analytics", zap.Error(err), "service", service)
		}
	}
}

func postAnalyticsHandler(ingest *db.Writer, writeBQ analyticsBQWriter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		l := logging.FromContext(ctx)
		service := chi.URLParam(r, "service")
		ct := r.Header.Get("content-type")

		if err := lib.ValidateService(service); err != nil {
			l.Warnw("invalid service", zap.Error(err), "service", service)
			http.Error(w, "could not validate service", 400)
			return
		}

		buf := new(bytes.Buffer)
		if _, err := buf.ReadFrom(http.MaxBytesReader(w, r.Body, maxIngestBodyBytes)); err != nil {
			handleBodyReadError(w, r, service, err)
			return
		}
		bodyStr := buf.String()
		data, err := analytics.ParseAnalytics(bodyStr, service)
		if err != nil {
			l.Errorw("error seen during analytics parse", zap.Error(err), "content-type", ct, "user-agent", r.UserAgent(), "bodyJson", bodyStr, "service", service)
			http.Error(w, "processing error", 500)
			return
		}

		l.Infow("analytics received", "content-type", ct, "service", service, "user-agent", r.UserAgent(), "analytics", data)

		ingest.Enqueue(db.WebVitalFromAnalytics(data))

		w.WriteHeader(http.StatusNoContent)

		if writeBQ != nil {
			go writeBQ(context.WithoutCancel(ctx), data)
		}
	}
}

func postReportingHandler(ingest *db.Writer, writeBQ securityReportBQWriter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		l := logging.FromContext(ctx)
		service := chi.URLParam(r, "service")
		contentType := r.Header.Get("Content-Type")
		media, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			l.Errorw("error parsing Content-Type header", zap.Error(err), "service", service, "content-type", contentType)
			http.Error(w, "uploading error", 400)
			return
		}
		if media != "application/reports+json" && media != "application/csp-report" {
			l.Errorw("unsupported Content-Type for reporting", "service", service, "content-type", contentType)
			http.Error(w, "uploading error", 400)
			return
		}

		if err := lib.ValidateService(service); err != nil {
			l.Warnw("invalid service", zap.Error(err), "service", service)
			http.Error(w, "could not validate service", 400)
			return
		}

		buf := new(bytes.Buffer)
		if _, err := buf.ReadFrom(http.MaxBytesReader(w, r.Body, maxIngestBodyBytes)); err != nil {
			handleBodyReadError(w, r, service, err)
			return
		}
		bodyStr := buf.String()

		l.Infow("reporting received", "content-type", contentType, "service", service, "user-agent", r.UserAgent())
		var reports *reporting.SecurityReport
		if media == "application/csp-report" {
			reports, err = reporting.ParseLegacyCSPReport(bodyStr, service)
		} else {
			reports, err = reporting.ParseReport(bodyStr, service)
		}
		if err != nil {
			l.Errorw("error on parsing reporting data", zap.Error(err), "service", service, "content-type", contentType, "body", bodyStr)
			http.Error(w, "uploading error", 500)
			return
		}

		l.Infow("reporting parsed", "reports", reports, "service", service, "content-type", contentType, "user-agent", r.UserAgent())

		ingest.Enqueue(db.SecurityReportEntryFromReport(reports))

		w.WriteHeader(http.StatusNoContent)

		if writeBQ != nil {
			go writeBQ(context.WithoutCancel(ctx), reports)
		}
	}
}

func apiVitalsHandler(pgDB *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		l := logging.FromContext(ctx)
		service := chi.URLParam(r, "service")

		if err := lib.ValidateService(service); err != nil {
			l.Warnw("invalid service", zap.Error(err), "service", service)
			http.Error(w, "could not validate service", 400)
			return
		}

		averages, err := db.GetWebVitalAverages(ctx, pgDB, service)
		if err != nil {
			l.Errorw("error getting averages", zap.Error(err), "service", service)
			http.Error(w, "processing error", 500)
			return
		}

		summaries, err := db.GetWebVitalSummaries(ctx, pgDB, service)
		if err != nil {
			l.Errorw("error getting summaries", zap.Error(err), "service", service)
			http.Error(w, "processing error", 500)
			return
		}

		out := struct {
			Averages  []db.WebVitalAverage      `json:"averages"`
			Summaries []db.WebVitalDailySummary `json:"summaries"`
		}{
			Averages:  averages,
			Summaries: summaries,
		}

		if err := writeJSON(w, out); err != nil {
			l.Errorw("error writing vitals", zap.Error(err), "service", service)
		}
	}
}

func apiReportsHandler(pgDB *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		l := logging.FromContext(ctx)
		service := chi.URLParam(r, "service")

		if err := lib.ValidateService(service); err != nil {
			l.Warnw("invalid service", zap.Error(err), "service", service)
			http.Error(w, "could not validate service", 400)
			return
		}

		counts, err := db.GetReportCounts(ctx, pgDB, service)
		if err != nil {
			l.Errorw("error getting report counts", zap.Error(err), "service", service)
			http.Error(w, "processing error", 500)
			return
		}

		recent, err := db.GetRecentReports(ctx, pgDB, service, 50)
		if err != nil {
			l.Errorw("error getting recent reports", zap.Error(err), "service", service)
			http.Error(w, "processing error", 500)
			return
		}

		recentRT, err := db.GetRecentReportToEntries(ctx, pgDB, service, 50)
		if err != nil {
			l.Errorw("error getting recent report-to entries", zap.Error(err), "service", service)
			http.Error(w, "processing error", 500)
			return
		}

		topDirectives, err := db.GetTopViolatedDirectives(ctx, pgDB, service, 10)
		if err != nil {
			l.Errorw("error getting top violated directives", zap.Error(err), "service", service)
			http.Error(w, "processing error", 500)
			return
		}

		out := struct {
			Counts         []db.ReportDailyCount    `json:"counts"`
			RecentReports  []db.SecurityReportEntry `json:"recent_reports"`
			RecentReportTo []db.ReportToEntry       `json:"recent_report_to"`
			TopDirectives  []db.DirectiveCount      `json:"top_directives"`
		}{
			Counts:         counts,
			RecentReports:  recent,
			RecentReportTo: recentRT,
			TopDirectives:  topDirectives,
		}

		if err := writeJSON(w, out); err != nil {
			l.Errorw("error writing reports", zap.Error(err), "service", service)
		}
	}
}
