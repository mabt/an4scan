package main

import (
	"encoding/gob"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"sync"
)

// scanCache remembers files that were scanned clean (no findings) so
// subsequent runs can skip them if mtime+size are unchanged. Files with
// findings are always rescanned. The cache is invalidated whenever the
// signature set or scanner version changes.
type scanCache struct {
	Key     string
	Entries map[uint64][2]int64 // fnv64(relpath) -> {mtime unix, size}

	path  string
	dirty bool
	mu    sync.Mutex
}

type cacheFileFormat struct {
	Key     string
	Entries map[uint64][2]int64
}

func pathHash(rel string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(rel))
	return h.Sum64()
}

// cacheKey changes whenever anything that affects per-file findings changes.
func (s *An4Scanner) cacheKey() string {
	h := fnv.New64a()
	h.Write([]byte(version))
	h.Write([]byte(s.MinSeverity))
	for _, sig := range s.compiledSigs {
		h.Write([]byte(sig.ID))
		h.Write([]byte(sig.Regex.String()))
	}
	for _, fp := range s.compiledFilenames {
		h.Write([]byte(fp.Regex.String()))
	}
	for _, w := range s.Whitelist {
		h.Write([]byte(w))
	}
	return string(rune(0)) + string(h.Sum(nil))
}

// defaultCacheBase returns the base directory for the incremental cache when no
// --cache-dir is given. It is deliberately OUTSIDE any scanned tree: an4scan
// often runs as root against client directories (e.g. Capistrano releases/),
// and a cache written in-tree would be root-owned and block the deploy user's
// cleanup. Root gets a system path; otherwise the user cache dir.
func defaultCacheBase() string {
	if os.Geteuid() == 0 {
		return "/var/lib/an4scan/cache"
	}
	if x := os.Getenv("XDG_CACHE_HOME"); x != "" {
		return filepath.Join(x, "an4scan")
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".cache", "an4scan")
	}
	return filepath.Join(os.TempDir(), "an4scan-cache")
}

// cachePathFor returns the on-disk location of the incremental cache for a given
// scan root. The cache lives under a base dir (cacheDir override, else
// defaultCacheBase) in a subdirectory keyed by the absolute scan path, so
// multi-site scans keep separate caches without ever writing inside the target.
func cachePathFor(cacheDir, scanRoot string) string {
	abs, err := filepath.Abs(scanRoot)
	if err != nil {
		abs = scanRoot
	}
	base := cacheDir
	if base == "" {
		base = defaultCacheBase()
	}
	return filepath.Join(base, fmt.Sprintf("%016x", pathHash(abs)), "filecache.gob")
}

func loadScanCache(cacheDir, root, key string) *scanCache {
	c := &scanCache{
		Key:     key,
		Entries: make(map[uint64][2]int64),
		path:    cachePathFor(cacheDir, root),
	}
	f, err := os.Open(c.path)
	if err != nil {
		return c
	}
	defer f.Close()

	var ff cacheFileFormat
	if err := gob.NewDecoder(f).Decode(&ff); err != nil || ff.Key != key {
		return c // corrupt or signature set changed: start fresh
	}
	c.Entries = ff.Entries
	return c
}

func (c *scanCache) isClean(rel string, mtime, size int64) bool {
	c.mu.Lock()
	e, ok := c.Entries[pathHash(rel)]
	c.mu.Unlock()
	return ok && e[0] == mtime && e[1] == size
}

func (c *scanCache) markClean(rel string, mtime, size int64) {
	c.mu.Lock()
	c.Entries[pathHash(rel)] = [2]int64{mtime, size}
	c.dirty = true
	c.mu.Unlock()
}

func (c *scanCache) save() error {
	if !c.dirty {
		return nil
	}
	os.MkdirAll(filepath.Dir(c.path), 0755)
	tmp := c.path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	err = gob.NewEncoder(f).Encode(cacheFileFormat{Key: c.Key, Entries: c.Entries})
	f.Close()
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, c.path)
}
