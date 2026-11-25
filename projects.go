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
// check a name without a database round trip (or a working database). The
// database is the source of truth: the store loads it at startup, applies
// its own creates and deletes at once, and re-reads periodically to pick up
// changes made elsewhere.
type projectStore struct {
	d *gorm.DB

	mu    sync.RWMutex
	names []string // sorted
	set   map[string]bool
}

func newProjectStore(ctx context.Context, d *gorm.DB) (*projectStore, error) {
	s := &projectStore{d: d}
	return s, s.Reload(ctx)
}

// Reload replaces the in-memory set with what the database holds.
func (s *projectStore) Reload(ctx context.Context) error {
	names, err := db.ListProjects(ctx, s.d)
	if err != nil {
		return err
	}
	s.replace(names)
	return nil
}

func (s *projectStore) replace(names []string) {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}
	s.mu.Lock()
	s.names, s.set = names, set
	s.mu.Unlock()
}

// Has reports whether name is a project.
func (s *projectStore) Has(name string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.set[name]
}

// List returns the project names, sorted.
func (s *projectStore) List() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.names)
}

// Create adds a project and makes it accept reports immediately.
func (s *projectStore) Create(ctx context.Context, name string) error {
	if err := db.CreateProject(ctx, s.d, name); err != nil {
		return err
	}
	if names := s.List(); !slices.Contains(names, name) {
		names = append(names, name)
		slices.Sort(names)
		s.replace(names)
	}
	return nil
}

// Delete removes a project so it stops accepting reports at once. Its stored
// data is purged in the background, since that can outlast a request; done
// (optional) is closed when the purge ends.
func (s *projectStore) Delete(ctx context.Context, name string, done chan<- struct{}) error {
	if err := db.DeleteProject(ctx, s.d, name); err != nil {
		return err
	}
	s.replace(slices.DeleteFunc(s.List(), func(n string) bool { return n == name }))

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
