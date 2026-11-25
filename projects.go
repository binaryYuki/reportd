package main

import (
	"context"
	"slices"
	"sync"
	"time"

	"go.icco.me/reportd/pkg/db"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// projectStore is the set of projects, kept in memory so that ingestion can
// check a name or token without a database round trip (or a working
// database). The database is the source of truth: the store loads it at
// startup, applies its own changes at once, and re-reads periodically to
// pick up changes made elsewhere.
type projectStore struct {
	d *gorm.DB

	// nameURLs is whether ingestion still accepts /<kind>/{name} URLs
	// besides the opaque ?s=<token> ones. Set before serving.
	nameURLs bool

	mu      sync.RWMutex
	names   []string // sorted
	byName  map[string]projectInfo
	byToken map[string]string // token -> name
}

type projectInfo struct {
	Kind  string
	Token string
}

func newProjectStore(ctx context.Context, d *gorm.DB) (*projectStore, error) {
	s := &projectStore{d: d, nameURLs: true}
	if n, err := db.EnsureProjectTokens(ctx, d); err != nil {
		return nil, err
	} else if n > 0 {
		log.Infow("issued tokens to existing projects", "projects", n)
	}
	return s, s.Reload(ctx)
}

// Reload replaces the in-memory set with what the database holds.
func (s *projectStore) Reload(ctx context.Context) error {
	records, err := db.ListProjectRecords(ctx, s.d)
	if err != nil {
		return err
	}
	s.replace(records)
	return nil
}

func (s *projectStore) replace(records []db.Project) {
	names := make([]string, 0, len(records))
	byName := make(map[string]projectInfo, len(records))
	byToken := make(map[string]string, len(records))
	for _, p := range records {
		info := projectInfo{Kind: p.Kind}
		if !db.ValidKind(info.Kind) {
			info.Kind = db.KindApp
		}
		if p.Token != nil && *p.Token != "" {
			info.Token = *p.Token
			byToken[info.Token] = p.Name
		}
		names = append(names, p.Name)
		byName[p.Name] = info
	}
	slices.Sort(names)
	s.mu.Lock()
	s.names, s.byName, s.byToken = names, byName, byToken
	s.mu.Unlock()
}

// records returns the in-memory state as rows, for local updates.
func (s *projectStore) records() []db.Project {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]db.Project, 0, len(s.names))
	for _, name := range s.names {
		info := s.byName[name]
		token := info.Token
		out = append(out, db.Project{Name: name, Kind: info.Kind, Token: &token})
	}
	return out
}

// Has reports whether name is a project.
func (s *projectStore) Has(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.byName[name]
	return ok
}

// Kind returns name's kind, or "" when it is not a project.
func (s *projectStore) Kind(name string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byName[name].Kind
}

// Token returns name's ingestion token, or "" when it has none.
func (s *projectStore) Token(name string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byName[name].Token
}

// ByToken returns the project that token belongs to.
func (s *projectStore) ByToken(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	name, ok := s.byToken[token]
	return name, ok
}

// List returns the project names, sorted.
func (s *projectStore) List() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.names)
}

// Create adds a project and makes it accept reports immediately. It
// re-reads the database so the new row's token is known; an existing
// project keeps its kind and token.
func (s *projectStore) Create(ctx context.Context, name, kind string) error {
	if err := db.CreateProject(ctx, s.d, name, kind); err != nil {
		return err
	}
	return s.Reload(ctx)
}

// RotateToken gives name a new token; the old one stops working at once.
func (s *projectStore) RotateToken(ctx context.Context, name string) error {
	token, err := db.RotateProjectToken(ctx, s.d, name)
	if err != nil {
		return err
	}
	records := s.records()
	for i := range records {
		if records[i].Name == name {
			records[i].Token = &token
		}
	}
	s.replace(records)
	return nil
}

// Delete removes a project so it stops accepting reports at once. Its stored
// data is purged in the background, since that can outlast a request; done
// (optional) is closed when the purge ends.
func (s *projectStore) Delete(ctx context.Context, name string, done chan<- struct{}) error {
	if err := db.DeleteProject(ctx, s.d, name); err != nil {
		return err
	}
	s.replace(slices.DeleteFunc(s.records(), func(p db.Project) bool { return p.Name == name }))

	go func() {
		if done != nil {
			defer close(done)
		}
		purgeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		rows, err := db.PurgeProjectData(purgeCtx, s.d, name)
		if err != nil {
			log.Errorw("purging deleted project", "project", name, "rows_deleted", rows, zap.Error(err))
			return
		}
		log.Infow("purged deleted project", "project", name, "rows_deleted", rows)
	}()
	return nil
}

// refreshLoop re-reads the database every interval until ctx ends. A failed
// read keeps the last known set, so a database outage does not stop
// ingestion.
func (s *projectStore) refreshLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reloadCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			if err := s.Reload(reloadCtx); err != nil && ctx.Err() == nil {
				log.Warnw("reloading projects", zap.Error(err))
			}
			cancel()
		}
	}
}
