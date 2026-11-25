// Package auth gates the dashboard behind GitHub OAuth sign-in restricted to
// an allowlist of verified email addresses.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	chi "github.com/go-chi/chi/v5"
	"go.icco.me/gutil/logging"
	"go.uber.org/zap"
)

const (
	sessionCookie = "reportd_session"
	stateCookie   = "reportd_oauth_state"
	sessionTTL    = 7 * 24 * time.Hour
	stateTTL      = 10 * time.Minute
	maxBodyBytes  = 1 << 20

	// LoginPath shows the sign-in page (GET) and starts the OAuth flow
	// (POST); CallbackPath is the path to register as the GitHub OAuth app's
	// authorization callback.
	LoginPath    = "/auth/login"
	CallbackPath = "/auth/callback"
	LogoutPath   = "/auth/logout"

	githubAuthURL   = "https://github.com/login/oauth/authorize"
	githubTokenURL  = "https://github.com/login/oauth/access_token" //nolint:gosec // endpoint URL, not a credential
	githubEmailsURL = "https://api.github.com/user/emails"
)

// Config configures an Authenticator.
type Config struct {
	ClientID     string
	ClientSecret string
	// AllowedEmails are the addresses allowed to sign in (case-insensitive).
	AllowedEmails []string
	// SessionSecret signs session cookies; at least 32 bytes.
	SessionSecret []byte

	// OnLogin, when set, is told about each successful sign-in and returns
	// the time of that user's previous one (zero if none). The result is
	// kept in the session; see SinceFromContext.
	OnLogin func(ctx context.Context, email string, at time.Time) (time.Time, error)

	// The fields below default to GitHub and the real clock; tests override.
	AuthURL    string
	TokenURL   string
	EmailsURL  string
	HTTPClient *http.Client
	Now        func() time.Time
}

// Authenticator runs the OAuth flow and guards handlers.
type Authenticator struct {
	cfg       Config
	allowed   map[string]bool
	loginPage LoginPage
}

// Sign-in failures, as LoginData.Error codes.
const (
	ErrorDenied    = "denied"    // no allowlisted verified email
	ErrorState     = "state"     // missing or mismatched OAuth state
	ErrorCancelled = "cancelled" // GitHub returned no code
	ErrorFailed    = "failed"    // GitHub could not be reached or refused
)

// LoginData is what a sign-in page needs to render.
type LoginData struct {
	// Next is the local path to return to after signing in.
	Next string
	// Error is "" or one of the Error* codes.
	Error string
	// Status is the HTTP status the page must be sent with.
	Status int
}

// LoginPage renders the sign-in page: a form that POSTs "next" to LoginPath.
type LoginPage func(w http.ResponseWriter, r *http.Request, data LoginData)

// defaultLoginPage is the plain page used when Routes is given none.
var defaultLoginPage = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="robots" content="noindex"><title>Sign in</title></head>
<body>
{{if .Error}}<p role="alert">Sign-in failed ({{.Error}}).</p>{{end}}
<form method="post" action="` + LoginPath + `">
<input type="hidden" name="next" value="{{.Next}}">
<button type="submit">Sign in with GitHub</button>
</form>
</body></html>`))

func renderDefaultLoginPage(w http.ResponseWriter, _ *http.Request, data LoginData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(data.Status)
	_ = defaultLoginPage.Execute(w, data)
}

type ctxKey struct{}

// session is what a valid session cookie carries.
type session struct {
	email string
	// since is the user's previous sign-in; zero when unknown.
	since time.Time
}

// ParseAllowedEmails splits a comma- or whitespace-separated allowlist.
func ParseAllowedEmails(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t'
	})
}

// New validates cfg and returns an Authenticator.
func New(cfg Config) (*Authenticator, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("github client id and secret are required")
	}
	if len(cfg.SessionSecret) < 32 {
		return nil, errors.New("session secret must be at least 32 bytes")
	}

	allowed := make(map[string]bool, len(cfg.AllowedEmails))
	for _, e := range cfg.AllowedEmails {
		if e = normalize(e); e != "" {
			allowed[e] = true
		}
	}
	if len(allowed) == 0 {
		return nil, errors.New("at least one allowed email is required")
	}

	if cfg.AuthURL == "" {
		cfg.AuthURL = githubAuthURL
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = githubTokenURL
	}
	if cfg.EmailsURL == "" {
		cfg.EmailsURL = githubEmailsURL
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	return &Authenticator{cfg: cfg, allowed: allowed}, nil
}

func normalize(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// EmailFromContext returns the signed-in email set by the Require
// middlewares, or "".
func EmailFromContext(ctx context.Context) string {
	s, _ := ctx.Value(ctxKey{}).(session)
	return s.email
}

// SinceFromContext returns when the signed-in user had last signed in before
// this session, or the zero time when that is unknown (first sign-in, or no
// OnLogin hook).
func SinceFromContext(ctx context.Context) time.Time {
	s, _ := ctx.Value(ctxKey{}).(session)
	return s.since
}

// Routes mounts the sign-in page, login, callback, and logout handlers. A nil
// page uses a plain built-in one.
func (a *Authenticator) Routes(r chi.Router, page LoginPage) {
	if page == nil {
		page = renderDefaultLoginPage
	}
	a.loginPage = page

	r.Get(LoginPath, a.handleLoginPage)
	r.Post(LoginPath, a.handleLogin)
	r.Get(CallbackPath, a.handleCallback)
	r.Post(LogoutPath, a.handleLogout)
}

// RequirePage guards an HTML page: anonymous visitors are sent to sign in
// and returned to the page afterwards.
func (a *Authenticator) RequirePage(next http.Handler) http.Handler {
	return a.require(next, func(w http.ResponseWriter, r *http.Request) {
		target := LoginPath + "?next=" + url.QueryEscape(r.URL.RequestURI())
		http.Redirect(w, r, target, http.StatusFound)
	})
}

// RequireAPI guards a JSON/metrics endpoint: anonymous callers get a 401.
func (a *Authenticator) RequireAPI(next http.Handler) http.Handler {
	return a.require(next, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "authentication required", http.StatusUnauthorized)
	})
}

func (a *Authenticator) require(next http.Handler, deny http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Dashboard data is per-login; keep it out of shared caches.
		w.Header().Set("Cache-Control", "private, no-store")

		s, ok := a.session(r)
		if !ok {
			deny(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, s)))
	})
}

// session returns the request's session when its cookie is valid, unexpired,
// and for an address still on the allowlist. The payload is
// "email|expiry|since", all times in Unix seconds; since is optional.
func (a *Authenticator) session(r *http.Request) (session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return session{}, false
	}
	payload, ok := a.verify(c.Value)
	if !ok {
		return session{}, false
	}
	fields := strings.Split(payload, "|")
	if len(fields) < 2 {
		return session{}, false
	}
	exp, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || a.cfg.Now().Unix() >= exp {
		return session{}, false
	}
	if !a.allowed[fields[0]] {
		return session{}, false
	}

	s := session{email: fields[0]}
	if len(fields) > 2 {
		if since, err := strconv.ParseInt(fields[2], 10, 64); err == nil && since > 0 {
			s.since = time.Unix(since, 0)
		}
	}
	return s, true
}

func (a *Authenticator) sign(payload string) string {
	mac := hmac.New(sha256.New, a.cfg.SessionSecret)
	mac.Write([]byte(payload))
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(payload)) + "." + enc.EncodeToString(mac.Sum(nil))
}

func (a *Authenticator) verify(token string) (string, bool) {
	p, s, ok := strings.Cut(token, ".")
	if !ok {
		return "", false
	}
	enc := base64.RawURLEncoding
	payload, err := enc.DecodeString(p)
	if err != nil {
		return "", false
	}
	sig, err := enc.DecodeString(s)
	if err != nil {
		return "", false
	}
	mac := hmac.New(sha256.New, a.cfg.SessionSecret)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return "", false
	}
	return string(payload), true
}

// safeNext keeps post-login redirects on this site: only absolute paths, and
// never "//host" or "/\host", which browsers treat as another origin.
func safeNext(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, `/\`) {
		return "/"
	}
	if strings.ContainsAny(next, "\r\n") {
		return "/"
	}
	return next
}

// isHTTPS reports whether the client reached us over TLS, directly or via a
// reverse proxy.
func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (a *Authenticator) setCookie(w http.ResponseWriter, r *http.Request, name, value string, ttl time.Duration) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	}
	if ttl <= 0 {
		c.MaxAge = -1
	}
	http.SetCookie(w, c)
}

// showLogin renders the sign-in page. It must never be cached or indexed:
// it reflects the visitor's own sign-in attempt.
func (a *Authenticator) showLogin(w http.ResponseWriter, r *http.Request, data LoginData) {
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Robots-Tag", "noindex")
	a.loginPage(w, r, data)
}

// handleLoginPage shows the sign-in page. It deliberately does not redirect
// to GitHub by itself: crawlers and stray visits would otherwise send GitHub
// a steady stream of automated authorization requests from this site. The
// flow starts only when a person presses the button (handleLogin).
func (a *Authenticator) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	next := safeNext(r.URL.Query().Get("next"))
	if _, ok := a.session(r); ok {
		http.Redirect(w, r, next, http.StatusFound)
		return
	}
	a.showLogin(w, r, LoginData{Next: next, Status: http.StatusOK})
}

func (a *Authenticator) handleLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	next := safeNext(r.PostFormValue("next"))
	if _, ok := a.session(r); ok {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}

	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		http.Error(w, "could not start sign-in", http.StatusInternalServerError)
		return
	}
	state := hex.EncodeToString(buf)
	a.setCookie(w, r, stateCookie, a.sign(state+"|"+next), stateTTL)

	// No redirect_uri: GitHub falls back to the callback URL registered on
	// the OAuth app, so the Host header is never trusted to build one.
	q := url.Values{
		"client_id": {a.cfg.ClientID},
		"scope":     {"user:email"},
		"state":     {state},
	}
	http.Redirect(w, r, a.cfg.AuthURL+"?"+q.Encode(), http.StatusSeeOther)
}

func (a *Authenticator) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	l := logging.FromContext(ctx)

	var state, next string
	if c, err := r.Cookie(stateCookie); err == nil {
		if payload, ok := a.verify(c.Value); ok {
			state, next, _ = strings.Cut(payload, "|")
		}
	}
	a.setCookie(w, r, stateCookie, "", 0)

	next = safeNext(next)
	// Failures land back on the sign-in page, where the user can retry.
	fail := func(code string, status int) {
		a.showLogin(w, r, LoginData{Next: next, Error: code, Status: status})
	}

	got := r.URL.Query().Get("state")
	if state == "" || subtle.ConstantTimeCompare([]byte(state), []byte(got)) != 1 {
		fail(ErrorState, http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		fail(ErrorCancelled, http.StatusBadRequest)
		return
	}

	emails, err := a.verifiedEmails(ctx, code)
	if err != nil {
		l.Errorw("github oauth exchange failed", zap.Error(err))
		fail(ErrorFailed, http.StatusBadGateway)
		return
	}

	var email string
	for _, e := range emails {
		if a.allowed[e] {
			email = e
			break
		}
	}
	if email == "" {
		l.Warnw("sign-in denied: no allowlisted verified email", "emails", emails)
		fail(ErrorDenied, http.StatusForbidden)
		return
	}

	now := a.cfg.Now()
	var since int64
	if a.cfg.OnLogin != nil {
		// Losing the "since" marker only blunts a dashboard statistic, so a
		// failure here must not block the sign-in.
		previous, err := a.cfg.OnLogin(ctx, email, now)
		switch {
		case err != nil:
			l.Errorw("recording sign-in failed", zap.Error(err), "email", email)
		case !previous.IsZero():
			since = previous.Unix()
		}
	}

	payload := fmt.Sprintf("%s|%d|%d", email, now.Add(sessionTTL).Unix(), since)
	a.setCookie(w, r, sessionCookie, a.sign(payload), sessionTTL)
	l.Infow("sign-in", "email", email)
	http.Redirect(w, r, next, http.StatusFound)
}

func (a *Authenticator) handleLogout(w http.ResponseWriter, r *http.Request) {
	a.setCookie(w, r, sessionCookie, "", 0)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// verifiedEmails exchanges code for a token and returns the account's
// verified, normalized email addresses.
func (a *Authenticator) verifiedEmails(ctx context.Context, code string) ([]string, error) {
	form := url.Values{
		"client_id":     {a.cfg.ClientID},
		"client_secret": {a.cfg.ClientSecret},
		"code":          {code},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := a.doJSON(req, &tok); err != nil {
		return nil, fmt.Errorf("exchanging code: %w", err)
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("exchanging code: github returned %q", tok.Error)
	}

	req, err = http.NewRequestWithContext(ctx, http.MethodGet, a.cfg.EmailsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	var list []struct {
		Email    string `json:"email"`
		Verified bool   `json:"verified"`
	}
	if err := a.doJSON(req, &list); err != nil {
		return nil, fmt.Errorf("fetching emails: %w", err)
	}

	var out []string
	for _, e := range list {
		// Unverified addresses are self-asserted; anyone can add yours.
		if e.Verified {
			out = append(out, normalize(e.Email))
		}
	}
	return out, nil
}

func (a *Authenticator) doJSON(req *http.Request, dst any) error {
	resp, err := a.cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(dst)
}
