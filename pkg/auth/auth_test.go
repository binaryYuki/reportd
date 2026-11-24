package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	chi "github.com/go-chi/chi/v5"
)

type ghEmail struct {
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
}

// fakeGitHub serves the token and emails endpoints.
func fakeGitHub(t *testing.T, emails []ghEmail) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("code") != "good-code" || r.FormValue("client_secret") != "secret" {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "bad_verification_code"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
	})
	mux.HandleFunc("/emails", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(emails)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newTestAuth(t *testing.T, gh *httptest.Server, now func() time.Time) (*Authenticator, http.Handler) {
	t.Helper()
	cfg := Config{
		ClientID:      "id",
		ClientSecret:  "secret",
		AllowedEmails: []string{"Me@Example.com"},
		SessionSecret: []byte(strings.Repeat("k", 32)),
		AuthURL:       "https://github.test/authorize",
		Now:           now,
	}
	if gh != nil {
		cfg.TokenURL = gh.URL + "/token"
		cfg.EmailsURL = gh.URL + "/emails"
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	r := chi.NewRouter()
	a.Routes(r)
	r.With(a.RequirePage).Get("/page", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("page:" + EmailFromContext(r.Context())))
	})
	r.With(a.RequireAPI).Get("/api", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("api"))
	})
	return a, r
}

func do(h http.Handler, method, target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func cookie(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("response has no %q cookie", name)
	return nil
}

// login walks the whole flow and returns the callback response.
func login(t *testing.T, h http.Handler, next, code string) *httptest.ResponseRecorder {
	t.Helper()
	rec := do(h, http.MethodGet, LoginPath+"?next="+url.QueryEscape(next))
	if rec.Code != http.StatusFound {
		t.Fatalf("login status = %d, want 302", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing login redirect: %v", err)
	}
	if !strings.HasPrefix(loc.String(), "https://github.test/authorize?") {
		t.Fatalf("login redirect = %q, want the GitHub authorize URL", loc)
	}
	if got := loc.Query().Get("scope"); got != "user:email" {
		t.Errorf("scope = %q, want user:email", got)
	}
	state := loc.Query().Get("state")
	return do(h, http.MethodGet, CallbackPath+"?code="+code+"&state="+state, cookie(t, rec, stateCookie))
}

func TestLoginFlowGrantsSession(t *testing.T) {
	gh := fakeGitHub(t, []ghEmail{
		{Email: "other@example.com", Verified: true},
		{Email: "me@example.com", Verified: true},
	})
	_, h := newTestAuth(t, gh, nil)

	rec := login(t, h, "/view/site?x=1", "good-code")
	if rec.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302; body %q", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Location"); got != "/view/site?x=1" {
		t.Errorf("callback redirect = %q, want the original page", got)
	}
	session := cookie(t, rec, sessionCookie)
	if !session.HttpOnly || session.SameSite != http.SameSiteLaxMode {
		t.Errorf("session cookie must be HttpOnly and SameSite=Lax: %+v", session)
	}

	if rec := do(h, http.MethodGet, "/page", session); rec.Code != http.StatusOK || rec.Body.String() != "page:me@example.com" {
		t.Errorf("/page = %d %q, want 200 with the signed-in email", rec.Code, rec.Body)
	}
	if rec := do(h, http.MethodGet, "/api", session); rec.Code != http.StatusOK {
		t.Errorf("/api status = %d, want 200", rec.Code)
	}
}

func TestLoginDenied(t *testing.T) {
	tests := []struct {
		name   string
		emails []ghEmail
		code   string
		want   int
	}{
		{name: "email not on allowlist", emails: []ghEmail{{Email: "stranger@example.com", Verified: true}}, code: "good-code", want: http.StatusForbidden},
		{name: "allowlisted but unverified", emails: []ghEmail{{Email: "me@example.com", Verified: false}}, code: "good-code", want: http.StatusForbidden},
		{name: "bad code", emails: []ghEmail{{Email: "me@example.com", Verified: true}}, code: "bad-code", want: http.StatusBadGateway},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, h := newTestAuth(t, fakeGitHub(t, tt.emails), nil)
			rec := login(t, h, "/", tt.code)
			if rec.Code != tt.want {
				t.Fatalf("callback status = %d, want %d", rec.Code, tt.want)
			}
			for _, c := range rec.Result().Cookies() {
				if c.Name == sessionCookie && c.Value != "" {
					t.Error("a session cookie was issued on a denied sign-in")
				}
			}
		})
	}
}

func TestCallbackRejectsBadState(t *testing.T) {
	_, h := newTestAuth(t, fakeGitHub(t, []ghEmail{{Email: "me@example.com", Verified: true}}), nil)

	// No state cookie at all.
	if rec := do(h, http.MethodGet, CallbackPath+"?code=good-code&state=abc"); rec.Code != http.StatusBadRequest {
		t.Errorf("no cookie: status = %d, want 400", rec.Code)
	}

	// Cookie present but the query state does not match it.
	start := do(h, http.MethodGet, LoginPath)
	rec := do(h, http.MethodGet, CallbackPath+"?code=good-code&state=forged", cookie(t, start, stateCookie))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("mismatched state: status = %d, want 400", rec.Code)
	}
}

func TestRequireWithoutSession(t *testing.T) {
	_, h := newTestAuth(t, nil, nil)

	rec := do(h, http.MethodGet, "/page?a=b")
	if rec.Code != http.StatusFound {
		t.Fatalf("/page status = %d, want 302", rec.Code)
	}
	if got, want := rec.Header().Get("Location"), LoginPath+"?next=%2Fpage%3Fa%3Db"; got != want {
		t.Errorf("redirect = %q, want %q", got, want)
	}

	if rec := do(h, http.MethodGet, "/api"); rec.Code != http.StatusUnauthorized {
		t.Errorf("/api status = %d, want 401", rec.Code)
	}
}

func TestSessionRejections(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	a, h := newTestAuth(t, nil, clock)

	valid := a.sign("me@example.com|" + "99999999999")
	other, err := New(Config{
		ClientID: "id", ClientSecret: "secret", AllowedEmails: []string{"me@example.com"},
		SessionSecret: []byte(strings.Repeat("z", 32)),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		name  string
		value string
		want  int
	}{
		{name: "valid", value: valid, want: http.StatusOK},
		{name: "signed with another key", value: other.sign("me@example.com|99999999999"), want: http.StatusUnauthorized},
		{name: "tampered payload", value: "x" + valid, want: http.StatusUnauthorized},
		{name: "expired", value: a.sign("me@example.com|1"), want: http.StatusUnauthorized},
		{name: "email removed from allowlist", value: a.sign("gone@example.com|99999999999"), want: http.StatusUnauthorized},
		{name: "garbage", value: "not-a-token", want: http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := do(h, http.MethodGet, "/api", &http.Cookie{Name: sessionCookie, Value: tt.value})
			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestLogoutClearsSession(t *testing.T) {
	a, h := newTestAuth(t, nil, nil)
	session := &http.Cookie{Name: sessionCookie, Value: a.sign("me@example.com|99999999999")}

	rec := do(h, http.MethodPost, LogoutPath, session)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("logout status = %d, want 303", rec.Code)
	}
	if c := cookie(t, rec, sessionCookie); c.MaxAge >= 0 || c.Value != "" {
		t.Errorf("logout must expire the session cookie: %+v", c)
	}
}

func TestSecureCookieBehindHTTPSProxy(t *testing.T) {
	_, h := newTestAuth(t, nil, nil)
	req := httptest.NewRequest(http.MethodGet, LoginPath, nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !cookie(t, rec, stateCookie).Secure {
		t.Error("cookies must be Secure when the request arrived over HTTPS")
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"":                  "/",
		"/view/site":        "/view/site",
		"https://evil.test": "/",
		"//evil.test":       "/",
		`/\evil.test`:       "/",
		"view":              "/",
		"/a\r\nSet-Cookie:": "/",
	} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewValidatesConfig(t *testing.T) {
	good := Config{ClientID: "id", ClientSecret: "s", AllowedEmails: []string{"a@b.c"}, SessionSecret: []byte(strings.Repeat("k", 32))}
	if _, err := New(good); err != nil {
		t.Fatalf("New(good) error = %v", err)
	}

	noID := good
	noID.ClientID = ""
	noEmails := good
	noEmails.AllowedEmails = []string{" "}
	shortSecret := good
	shortSecret.SessionSecret = []byte("short")

	for name, cfg := range map[string]Config{"no client id": noID, "empty allowlist": noEmails, "short secret": shortSecret} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New() error = nil, want an error", name)
		}
	}
}

func TestParseAllowedEmails(t *testing.T) {
	got := ParseAllowedEmails(" a@x.com, b@x.com;c@x.com\n")
	want := []string{"a@x.com", "b@x.com", "c@x.com"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("ParseAllowedEmails() = %v, want %v", got, want)
	}
}
