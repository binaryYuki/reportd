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
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
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
	nameURLs := fs.Bool("name_urls", true, "Also accept reports at /report/<project>-style URLs; when false only the opaque ?s=<token> URLs work.")
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
	go func() {
		backfillCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		if n, err := db.BackfillNELFields(backfillCtx, pgDB); err != nil {
			log.Warnw("backfilling network error fields", zap.Error(err), "rows", n)
		} else if n > 0 {
			log.Infow("backfilled network error fields", "rows", n)
		}
	}()

	projects, err := newProjectStore(ctx, pgDB)
	if err != nil {
		log.Fatalw("could not load projects", zap.Error(err))
	}
	projects.nameURLs = *nameURLs
	log.Infow("Projects loaded", "projects", projects.List(), "name_urls", *nameURLs)

	recordLogin := func(ctx context.Context, email string, at time.Time) (time.Time, error) {
		return db.RecordLogin(ctx, pgDB, email, at)
	}
	authn, err := newAuthenticator(*githubClientID, *githubClientSecret, *allowedEmails, *sessionSecret, recordLogin)
	if err != nil {
		log.Fatalw("dashboard sign-in is not configured", zap.Error(err))
	}

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
	go projects.refreshLoop(pruneCtx, projectRefreshInterval)
	if *maxStorageGB > 0 {
		maxBytes := int64(*maxStorageGB * (1 << 30))
		log.Infow("Storage cap enabled", "max_bytes", maxBytes)
		go enforceStorageLimitLoop(pruneCtx, pgDB, maxBytes, storageCheckInterval)
	} else {
		log.Warnw("Storage cap disabled: the database can grow without bound")
	}

	ingest := db.NewWriter(pgDB, db.WriterOptions{OnDrop: logDroppedRows})

	r := newRouter(pgDB, ingest, writeReport, writeAnalytics, writeSecurityReport, authn, projects)
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

// projectRefreshInterval is how often the project list is re-read from the
// database, to notice changes made by another instance or by hand.
const projectRefreshInterval = time.Minute

// newAuthenticator builds the dashboard authenticator from flag values. An
// unset session secret gets a random one, which signs everyone out on restart.
func newAuthenticator(clientID, clientSecret, allowedEmails, sessionSecret string, onLogin func(context.Context, string, time.Time) (time.Time, error)) (*auth.Authenticator, error) {
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
		OnLogin:       onLogin,
	})
}

// requireProject answers 404 for a {service} that is not a project, so
// nobody can conjure one by posting to a new name. A nil store (tests only)
// allows every name. Malformed names fall through to the handlers, which
// reject them with 400.
func requireProject(projects *projectStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if projects == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			service := chi.URLParam(r, "service")
			if lib.ValidateService(service) == nil && !projects.Has(service) {
				http.Error(w, "unknown project", http.StatusNotFound)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// projectFromToken resolves the opaque ?s=<token> of an ingestion URL to its
// project and exposes it as the {service} URL parameter, so the handlers
// serve both URL styles alike. Unknown tokens get 404.
func projectFromToken(projects *projectStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			name, ok := projects.ByToken(r.URL.Query().Get("s"))
			if !ok {
				http.Error(w, "unknown project", http.StatusNotFound)
				return
			}
			chi.RouteContext(r.Context()).URLParams.Add("service", name)
			next.ServeHTTP(w, r)
		})
	}
}

// nameIngest closes the /<kind>/{service} ingestion URLs when the
// deployment only accepts token URLs.
func nameIngest(projects *projectStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if projects == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !projects.nameURLs {
				http.Error(w, "unknown project", http.StatusNotFound)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// statusWrongKind answers data an API project does not take (Web Vitals,
// page reports). 422 rather than 404 so a misconfigured site is easy to
// spot: the project exists, the data is wrong for it.
const statusWrongKind = http.StatusUnprocessableEntity

// appOnly rejects requests for API projects: Web Vitals and Reporting API
// page reports only make sense for websites.
func appOnly(projects *projectStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if projects == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if projects.Kind(chi.URLParam(r, "service")) == db.KindAPI {
				http.Error(w, "api projects only accept network error (NEL) reports", statusWrongKind)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
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
// A nil authn leaves the dashboard open, and a nil projects accepts every
// project name; only the tests rely on either.
func newRouter(pgDB *gorm.DB, ingest *db.Writer, writeReport reportToBQWriter, writeAnalytics analyticsBQWriter, writeSecurityReport securityReportBQWriter, authn *auth.Authenticator, projects *projectStore) *chi.Mux {
	r := chi.NewRouter()
	r.Use(logging.Middleware(log.Desugar()))
	r.Use(routeTag)
	r.Use(middleware.Compress(5))

	r.Use(cors.New(cors.Options{
		// AllowCredentials must stay false to keep the wildcard origin safe (CORS bypass).
		AllowCredentials: false,
		// Answer preflights here, before routing: they carry no body and,
		// on ?s= URLs, nothing the routes could validate, and a browser that
		// gets a non-2xx preflight drops the report.
		OptionsPassthrough: false,
		AllowedOrigins:     []string{"*"},
		AllowedMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:     []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:     []string{"Link"},
		MaxAge:             300,
	}).Handler)

	r.Use(middleware.Timeout(30 * time.Second))

	r.Use(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("report-to", `{"group":"default","max_age":10886400,"endpoints":[{"url":"https://pawprint.catyuki.com/report/reportd"}]}`)
			w.Header().Set("reporting-endpoints", `default="https://pawprint.catyuki.com/reporting/reportd"`)

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
		// The dashboard reports its own Web Vitals to the selfReportProject
		// project, but only once that project exists: otherwise every page
		// view would log a rejected request in the browser console.
		Funcs: []template.FuncMap{{
			"selfReportURL": func() string {
				if projects == nil || projects.Kind(selfReportProject) != db.KindApp {
					return ""
				}
				return "/analytics?s=" + url.QueryEscape(projects.Token(selfReportProject))
			},
		}},
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
		authn.Routes(r, func(w http.ResponseWriter, r *http.Request, data auth.LoginData) {
			if err := re.HTML(w, data.Status, "login", data); err != nil {
				logging.FromContext(r.Context()).Errorw("error rendering login", zap.Error(err))
				http.Error(w, "could not render sign-in page", http.StatusInternalServerError)
			}
		})
		page, api = authn.RequirePage, authn.RequireAPI
	}

	// Every {service} route is limited to existing projects.
	project := requireProject(projects)

	if projects != nil {
		r.With(page, sameOrigin).Post("/projects", createProjectHandler(projects))
		r.With(page, sameOrigin, project).Post("/projects/{service}/delete", deleteProjectHandler(projects))
		r.With(page, sameOrigin, project).Post("/projects/{service}/token", rotateTokenHandler(projects))
	}

	r.With(page).Get("/", indexHandler(re, pgDB, projects))
	r.With(page, project).Get("/view/{service}", viewHandler(re, projects))
	r.Get(statusPath, statusHandler(ingest))

	// Ingestion. Every endpoint exists twice: under the project name, and
	// under an opaque token (?s=) that reveals nothing about the project.
	var kindOf func(string) string
	if projects != nil {
		kindOf = projects.Kind
	}
	postReport := postReportHandler(ingest, writeReport, kindOf)
	postAnalytics := postAnalyticsHandler(ingest, writeAnalytics)
	postReporting := postReportingHandler(ingest, writeSecurityReport)
	appOnly := appOnly(projects)

	named := r.With(nameIngest(projects), project)
	named.Options("/report/{service}", corsPreflightHandler())
	named.Options("/analytics/{service}", corsPreflightHandler())
	named.Post("/report/{service}", postReport)
	named.With(appOnly).Post("/analytics/{service}", postAnalytics)
	named.With(appOnly).Post("/reporting/{service}", postReporting)

	if projects != nil {
		tokened := r.With(projectFromToken(projects))
		tokened.Options("/report", corsPreflightHandler())
		tokened.Options("/analytics", corsPreflightHandler())
		tokened.Post("/report", postReport)
		tokened.With(appOnly).Post("/analytics", postAnalytics)
		tokened.With(appOnly).Post("/reporting", postReporting)
	}

	// Read APIs.
	r.With(api, project).Get("/reports/{service}", getReportsHandler(pgDB))
	r.With(api).Get("/services", getServicesHandler(pgDB, projects))
	r.With(api, project).Get("/analytics/{service}", getAnalyticsHandler(pgDB))
	r.With(api, project).Get("/api/vitals/{service}", apiVitalsHandler(pgDB))
	r.With(api, project).Get("/api/reports/{service}", apiReportsHandler(pgDB))
	r.With(api, project).Get("/api/network/{service}", apiNetworkHandler(pgDB))

	return r
}

// listServices returns the projects, or (with a nil store, tests only) every
// service that has data.
func listServices(ctx context.Context, pgDB *gorm.DB, projects *projectStore) ([]string, error) {
	if projects != nil {
		return projects.List(), nil
	}
	return db.GetServices(ctx, pgDB)
}

// sameOrigin rejects state-changing requests that a browser marks as coming
// from another site. The session cookie is SameSite=Lax, which already keeps
// it off cross-site POSTs; this is a second line of defence.
func sameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
			http.Error(w, "cross-site request refused", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// createProjectHandler adds the project named in the form and returns to the
// index, which shows it (or the reason it was refused).
func createProjectHandler(projects *projectStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := queryContext(r.Context())
		defer cancel()
		l := logging.FromContext(ctx)

		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		name := strings.TrimSpace(r.PostFormValue("name"))
		if err := lib.ValidateService(name); err != nil {
			http.Redirect(w, r, "/?error=name", http.StatusSeeOther)
			return
		}

		kind := r.PostFormValue("kind")
		if kind == "" {
			kind = db.KindApp
		}
		if !db.ValidKind(kind) {
			http.Redirect(w, r, "/?error=kind", http.StatusSeeOther)
			return
		}

		if err := projects.Create(ctx, name, kind); err != nil {
			l.Errorw("error creating project", zap.Error(err), "project", name)
			http.Redirect(w, r, "/?error=storage", http.StatusSeeOther)
			return
		}
		l.Infow("project created", "project", name, "kind", kind, "by", auth.EmailFromContext(ctx))
		http.Redirect(w, r, "/view/"+name, http.StatusSeeOther)
	}
}

// deleteProjectHandler removes a project and, in the background, its data.
func deleteProjectHandler(projects *projectStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := queryContext(r.Context())
		defer cancel()
		l := logging.FromContext(ctx)
		name := chi.URLParam(r, "service")

		if err := projects.Delete(ctx, name, nil); err != nil {
			l.Errorw("error deleting project", zap.Error(err), "project", name)
			http.Redirect(w, r, "/?error=storage", http.StatusSeeOther)
			return
		}
		l.Infow("project deleted", "project", name, "by", auth.EmailFromContext(ctx))
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// rotateTokenHandler replaces a project's ingestion token and returns to
// its page, which shows the new URLs.
func rotateTokenHandler(projects *projectStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := queryContext(r.Context())
		defer cancel()
		l := logging.FromContext(ctx)
		name := chi.URLParam(r, "service")

		if err := projects.RotateToken(ctx, name); err != nil {
			l.Errorw("error rotating project token", zap.Error(err), "project", name)
			http.Redirect(w, r, "/view/"+name+"?error=storage", http.StatusSeeOther)
			return
		}
		l.Infow("project token rotated", "project", name, "by", auth.EmailFromContext(ctx))
		http.Redirect(w, r, "/view/"+name+"#setup", http.StatusSeeOther)
	}
}

func indexHandler(re *render.Render, pgDB *gorm.DB, projects *projectStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := queryContext(r.Context())
		defer cancel()
		l := logging.FromContext(ctx)

		services, err := listServices(ctx, pgDB, projects)
		if err != nil {
			l.Errorw("error getting services", zap.Error(err))
			http.Error(w, "could not get services", 500)
			return
		}

		// What arrived since the user's previous sign-in; everything when
		// that is unknown (first sign-in).
		since := auth.SinceFromContext(r.Context())
		// With no projects there is nothing to count; an empty filter would
		// mean "everything".
		var counts db.IngestCounts
		if projects == nil || len(services) > 0 {
			var filter []string
			if projects != nil {
				filter = services
			}
			counts, err = db.CountSince(ctx, pgDB, since, filter)
		}
		if err != nil {
			l.Errorw("error counting rows since last login", zap.Error(err))
			http.Error(w, "could not get statistics", 500)
			return
		}

		health, err := db.GetAllServicesHealth(ctx, pgDB)
		if err != nil {
			l.Errorw("error getting services health", zap.Error(err))
			health = make(map[string][]db.ServiceHealth)
		}

		// Health is computed over everything stored; show only the listed
		// projects so data from unconfigured names stays hidden.
		shown := make(map[string][]db.ServiceHealth, len(services))
		for _, name := range services {
			if h, ok := health[name]; ok {
				shown[name] = h
			}
		}

		healthJSON, _ := json.Marshal(shown)

		network, err := db.GetAllServicesNetwork(ctx, pgDB)
		if err != nil {
			l.Errorw("error getting network rates", zap.Error(err))
			network = make(map[string]db.NetworkRate)
		}
		type card struct {
			Name string
			Kind string
		}
		cards := make([]card, 0, len(services))
		shownNetwork := make(map[string]db.NetworkRate, len(services))
		for _, name := range services {
			kind := db.KindApp
			if projects != nil {
				kind = projects.Kind(name)
			}
			cards = append(cards, card{Name: name, Kind: kind})
			if n, ok := network[name]; ok {
				shownNetwork[name] = n
			}
		}
		networkJSON, _ := json.Marshal(shownNetwork)

		if err := re.HTML(w, http.StatusOK, "index", struct {
			Services    []string
			Projects    []card
			HealthJSON  string
			NetworkJSON string
			User        string
			Counts      db.IngestCounts
			// HasSince is false when Counts covers all stored data.
			HasSince bool
			Since    string
			// CanManage is whether projects can be created here.
			CanManage bool
			Error     string
		}{
			CanManage:  projects != nil,
			Error:      r.URL.Query().Get("error"),
			Counts:     counts,
			HasSince:   !since.IsZero(),
			Since:      since.UTC().Format("2006-01-02 15:04 UTC"),
			User:       auth.EmailFromContext(r.Context()),
			Services:   services,
			HealthJSON: string(healthJSON),
			Projects:   cards,
			// NetworkJSON is the 30-day NEL volume per project.
			NetworkJSON: string(networkJSON),
		}); err != nil {
			l.Errorw("error rendering index", zap.Error(err))
			http.Error(w, "could not render index", 500)
			return
		}
	}
}

func viewHandler(re *render.Render, projects *projectStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		l := logging.FromContext(r.Context())
		service := chi.URLParam(r, "service")

		if err := lib.ValidateService(service); err != nil {
			l.Warnw("invalid service", zap.Error(err), "service", service)
			http.Error(w, "could not validate service", 400)
			return
		}

		data := struct {
			Service string
			User    string
			// Kind is "app" or "api".
			Kind string
			// Token is the opaque ingestion token; empty without a store.
			Token string
			// NameURLs is whether /<kind>/<name> ingestion URLs still work.
			NameURLs bool
			// CanManage is whether the project can be deleted here.
			CanManage bool
			Error     string
		}{
			CanManage: projects != nil,
			User:      auth.EmailFromContext(r.Context()),
			Service:   service,
			Kind:      db.KindApp,
			NameURLs:  true,
			Error:     r.URL.Query().Get("error"),
		}
		if projects != nil {
			data.Kind = projects.Kind(service)
			data.Token = projects.Token(service)
			data.NameURLs = projects.nameURLs
		}

		if err := re.HTML(w, http.StatusOK, "view", data); err != nil {
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

// maxReportsPerRequest caps how many reports one batched POST may add, so a
// single anonymous request cannot fill the ingest queue.
const maxReportsPerRequest = 500

// selfReportProject is the project the dashboard's own pages report to.
const selfReportProject = "reportd"

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

// cfConnectingIP returns the client address Cloudflare puts in
// CF-Connecting-IP, or "" when the header is missing or not an IP.
func cfConnectingIP(r *http.Request) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("CF-Connecting-IP")))
	if err != nil {
		return ""
	}
	return addr.Unmap().String()
}

// postReportHandler takes legacy Report-To payloads. API projects (per
// kindOf; nil treats every project as an app) keep only the network-error
// (NEL) entries; a payload with nothing they accept is answered 422.
func postReportHandler(ingest *db.Writer, writeBQ reportToBQWriter, kindOf func(string) string) http.HandlerFunc {
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

		entries := db.ReportToEntriesFromReport(data)
		if kindOf != nil && kindOf(service) == db.KindAPI {
			kept := slices.DeleteFunc(slices.Clone(entries), func(e *db.ReportToEntry) bool {
				return e.ReportType != db.ReportTypeNetworkError
			})
			if dropped := len(entries) - len(kept); dropped > 0 {
				if len(kept) == 0 {
					l.Warnw("api project received no network error reports", "service", service, "dropped", dropped)
					http.Error(w, "api projects only accept network error (NEL) reports", statusWrongKind)
					return
				}
				l.Infow("dropped non-network reports for api project", "service", service, "dropped", dropped)
			}
			entries = kept
			data.ReportTo = slices.DeleteFunc(data.ReportTo, func(e *reportto.Entry) bool {
				return e.Type != db.ReportTypeNetworkError
			})
		}
		if len(entries) > maxReportsPerRequest {
			l.Warnw("truncating oversized report batch", "service", service, "received", len(entries), "kept", maxReportsPerRequest)
			entries = entries[:maxReportsPerRequest]
		}

		clientIP := cfConnectingIP(r)
		for _, entry := range entries {
			entry.ClientIP = clientIP
			ingest.Enqueue(entry)
		}

		w.WriteHeader(http.StatusNoContent)

		if writeBQ != nil {
			go writeBQ(context.WithoutCancel(ctx), data)
		}
	}
}

func getServicesHandler(pgDB *gorm.DB, projects *projectStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		l := logging.FromContext(ctx)

		data, err := listServices(ctx, pgDB, projects)
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
		var reports []*reporting.SecurityReport
		if media == "application/csp-report" {
			var one *reporting.SecurityReport
			if one, err = reporting.ParseLegacyCSPReport(bodyStr, service); err == nil {
				reports = []*reporting.SecurityReport{one}
			}
		} else {
			reports, err = reporting.ParseReports(bodyStr, service)
		}
		if err != nil && len(reports) == 0 {
			l.Errorw("error on parsing reporting data", zap.Error(err), "service", service, "content-type", contentType, "body", bodyStr)
			http.Error(w, "uploading error", 500)
			return
		}
		if err != nil {
			l.Warnw("skipped unparseable reports in batch", zap.Error(err), "service", service, "parsed", len(reports))
		}
		if len(reports) > maxReportsPerRequest {
			l.Warnw("truncating oversized report batch", "service", service, "received", len(reports), "kept", maxReportsPerRequest)
			reports = reports[:maxReportsPerRequest]
		}

		l.Infow("reporting parsed", "count", len(reports), "service", service, "content-type", contentType, "user-agent", r.UserAgent())

		for _, report := range reports {
			ingest.Enqueue(db.SecurityReportEntryFromReport(report))
		}

		w.WriteHeader(http.StatusNoContent)

		if writeBQ != nil {
			go func(ctx context.Context) {
				for _, report := range reports {
					writeBQ(ctx, report)
				}
			}(context.WithoutCancel(ctx))
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

func apiNetworkHandler(pgDB *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		l := logging.FromContext(ctx)
		service := chi.URLParam(r, "service")

		if err := lib.ValidateService(service); err != nil {
			l.Warnw("invalid service", zap.Error(err), "service", service)
			http.Error(w, "could not validate service", 400)
			return
		}

		summary, err := db.GetNetworkSummary(ctx, pgDB, service)
		if err != nil {
			l.Errorw("error getting network summary", zap.Error(err), "service", service)
			http.Error(w, "processing error", 500)
			return
		}
		if err := writeJSON(w, summary); err != nil {
			l.Errorw("error writing network summary", zap.Error(err), "service", service)
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
