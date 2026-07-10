package datasource

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hashicorp/hcl/v2/hcldec"
	"github.com/zclconf/go-cty/cty"
	_ "modernc.org/sqlite"
)

type Entry struct {
	URLs    []string // len==1 for single-URL entries; len>1 for multipart archives
	Extract bool
	Dir     bool
	Creds   Credentials
}

type Datasource struct {
	globalCreds Credentials
	entries     map[string]Entry
	progress    bool
}

var entrySpec = hcldec.ObjectSpec{
	"url":     &hcldec.AttrSpec{Name: "url", Type: cty.String, Required: false},
	"urls":    &hcldec.AttrSpec{Name: "urls", Type: cty.List(cty.String), Required: false},
	"extract": &hcldec.AttrSpec{Name: "extract", Type: cty.Bool, Required: false},
	"dir":     &hcldec.AttrSpec{Name: "dir", Type: cty.Bool, Required: false},
	"credentials": &hcldec.BlockMapSpec{
		TypeName:   "credentials",
		LabelNames: []string{"scheme"},
		Nested:     credentialsSpec,
	},
}

func (d *Datasource) ConfigSpec() hcldec.ObjectSpec {
	return hcldec.ObjectSpec{
		"progress":    &hcldec.AttrSpec{Name: "progress", Type: cty.Bool, Required: false},
		"credentials": credentialsBlockMapSpec,
		"entry": &hcldec.BlockMapSpec{
			TypeName:   "entry",
			LabelNames: []string{"name"},
			Nested:     entrySpec,
		},
	}
}

func (d *Datasource) OutputSpec() hcldec.ObjectSpec {
	return hcldec.ObjectSpec{
		"paths": &hcldec.AttrSpec{
			Name: "paths",
			Type: cty.Map(cty.String),
		},
	}
}

func (d *Datasource) Configure(configs ...interface{}) error {
	d.entries = map[string]Entry{}
	for _, raw := range configs {
		cval, ok := raw.(cty.Value)
		if !ok || cval.IsNull() || !cval.IsKnown() {
			continue
		}

		if pv := cval.GetAttr("progress"); pv.IsKnown() && !pv.IsNull() {
			d.progress = pv.True()
		}
		if cv := cval.GetAttr("credentials"); cv.IsKnown() && !cv.IsNull() {
			d.globalCreds = parseCredentials(cv)
		}

		entryMap := cval.GetAttr("entry")
		if !entryMap.IsKnown() || entryMap.IsNull() {
			continue
		}
		for name, ev := range entryMap.AsValueMap() {
			var entry Entry

			urlVal := ev.GetAttr("url")
			urlsVal := ev.GetAttr("urls")
			hasURL := urlVal.IsKnown() && !urlVal.IsNull()
			hasURLs := urlsVal.IsKnown() && !urlsVal.IsNull()
			switch {
			case hasURL && hasURLs:
				return fmt.Errorf("entry %q: specify either 'url' or 'urls', not both", name)
			case hasURL:
				entry.URLs = []string{urlVal.AsString()}
			case hasURLs:
				for it := urlsVal.ElementIterator(); it.Next(); {
					_, v := it.Element()
					entry.URLs = append(entry.URLs, v.AsString())
				}
				if len(entry.URLs) == 0 {
					return fmt.Errorf("entry %q: 'urls' must not be empty", name)
				}
			default:
				return fmt.Errorf("entry %q: must specify either 'url' or 'urls'", name)
			}

			if ex := ev.GetAttr("extract"); ex.IsKnown() && !ex.IsNull() {
				entry.Extract = ex.True()
			}
			if dv := ev.GetAttr("dir"); dv.IsKnown() && !dv.IsNull() {
				entry.Dir = dv.True()
			}
			if cv := ev.GetAttr("credentials"); cv.IsKnown() && !cv.IsNull() {
				entry.Creds = parseCredentials(cv)
			}
			d.entries[name] = entry
		}
	}
	return nil
}

func (d *Datasource) Execute() (cty.Value, error) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cacheDir, err := pluginCacheDir()
	if err != nil {
		return cty.NilVal, err
	}
	filesDir := filepath.Join(cacheDir, "files")
	if err := os.MkdirAll(filesDir, 0o755); err != nil {
		return cty.NilVal, fmt.Errorf("creating cache files dir: %w", err)
	}

	db, err := openDB(cacheDir)
	if err != nil {
		return cty.NilVal, fmt.Errorf("opening cache db: %w", err)
	}
	defer db.Close()

	type result struct {
		name, path string
		err        error
	}
	ch := make(chan result, len(d.entries))
	var wg sync.WaitGroup

	for name, entry := range d.entries {
		wg.Add(1)
		go func(name string, entry Entry) {
			defer wg.Done()
			creds := d.globalCreds.Merge(entry.Creds)
			path, err := process(ctx, entry, creds, filesDir, db, d.progress)
			ch <- result{name: name, path: path, err: err}
		}(name, entry)
	}
	go func() { wg.Wait(); close(ch) }()

	paths := map[string]cty.Value{}
	for r := range ch {
		if r.err != nil {
			return cty.NilVal, fmt.Errorf("processing %q: %w", r.name, r.err)
		}
		paths[r.name] = cty.StringVal(r.path)
	}

	var pathsVal cty.Value
	if len(paths) == 0 {
		pathsVal = cty.MapValEmpty(cty.String)
	} else {
		pathsVal = cty.MapVal(paths)
	}
	return cty.ObjectVal(map[string]cty.Value{"paths": pathsVal}), nil
}

func process(ctx context.Context, entry Entry, creds Credentials, filesDir string, db *sql.DB, showProgress bool) (string, error) {
	primaryURL := entry.URLs[0]

	var cached string
	if err := db.QueryRow("SELECT path FROM entries WHERE url = ?", primaryURL).Scan(&cached); err == nil {
		if _, statErr := os.Stat(cached); statErr == nil {
			return cached, nil
		}
		db.Exec("DELETE FROM entries WHERE url = ?", primaryURL) //nolint:errcheck
	}

	if entry.Dir {
		fetcher, err := fetcherFor(primaryURL)
		if err != nil {
			return "", err
		}
		df, ok := fetcher.(DirFetcher)
		if !ok {
			return "", fmt.Errorf("fetcher for %q does not support dir downloads", primaryURL)
		}
		dest := filepath.Join(filesDir, filenameOf(primaryURL))
		if err := os.MkdirAll(dest, 0o755); err != nil {
			return "", err
		}
		if err := df.FetchDir(ctx, primaryURL, creds, dest, showProgress); err != nil {
			return "", err
		}
		if _, err := db.Exec("INSERT OR REPLACE INTO entries (url, path) VALUES (?, ?)", primaryURL, dest); err != nil {
			return "", fmt.Errorf("updating cache db: %w", err)
		}
		return dest, nil
	}

	type dlResult struct {
		mime string
		err  error
	}
	results := make([]dlResult, len(entry.URLs))
	var dlWg sync.WaitGroup
	for i, rawURL := range entry.URLs {
		dlWg.Add(1)
		go func(i int, rawURL string) {
			defer dlWg.Done()
			fetcher, err := fetcherFor(rawURL)
			if err != nil {
				results[i] = dlResult{err: err}
				return
			}
			archivePath := filepath.Join(filesDir, filenameOf(rawURL))
			mime, err := downloadTo(ctx, fetcher, rawURL, creds, archivePath, showProgress)
			results[i] = dlResult{mime: mime, err: err}
		}(i, rawURL)
	}
	dlWg.Wait()
	for _, r := range results {
		if r.err != nil {
			return "", r.err
		}
	}
	primaryMIME := results[0].mime

	primaryFilename := filenameOf(primaryURL)
	primaryArchivePath := filepath.Join(filesDir, primaryFilename)

	var finalPath string
	if entry.Extract {
		mimeType := sniffMIME(primaryArchivePath, primaryMIME)
		ext := extractorFor(mimeType)
		if ext == nil {
			return "", fmt.Errorf("no extractor for MIME type %q (file: %s)", mimeType, filepath.Base(primaryArchivePath))
		}
		dest := filepath.Join(filesDir, stemOf(primaryFilename))
		if err := os.MkdirAll(dest, 0o755); err != nil {
			return "", err
		}
		if err := ext.Extract(primaryArchivePath, dest, mimeType); err != nil {
			return "", err
		}
		finalPath = dest
	} else {
		finalPath = primaryArchivePath
	}

	if _, err := db.Exec("INSERT OR REPLACE INTO entries (url, path) VALUES (?, ?)", primaryURL, finalPath); err != nil {
		return "", fmt.Errorf("updating cache db: %w", err)
	}
	return finalPath, nil
}

// downloadTo fetches rawURL to dest (skipping if already present) and returns the fetcher-reported MIME type.
// If a .part file exists from a previous interrupted download, it resumes from that offset.
func downloadTo(ctx context.Context, fetcher Fetcher, rawURL string, creds Credentials, dest string, showProgress bool) (string, error) {
	if _, err := os.Stat(dest); err == nil {
		return "", nil // already on disk; MIME will be sniffed from the file
	}

	tmp := dest + ".part"
	var requestOffset int64
	if fi, err := os.Stat(tmp); err == nil {
		requestOffset = fi.Size()
	}

	result, err := fetcher.Fetch(ctx, rawURL, creds, requestOffset)
	if err != nil {
		return "", err
	}
	defer result.Body.Close()

	// Open the part file: append if the server honoured our range request, otherwise start fresh.
	var f *os.File
	if result.BodyOffset > 0 {
		f, err = os.OpenFile(tmp, os.O_WRONLY|os.O_APPEND, 0o644)
	} else {
		f, err = os.Create(tmp)
	}
	if err != nil {
		return "", err
	}

	name := filepath.Base(dest)
	var bytesRead atomic.Int64
	bytesRead.Store(result.BodyOffset)

	if showProgress {
		if result.BodyOffset > 0 {
			log.Printf("[download] resuming %s from %.1f MB", name, float64(result.BodyOffset)/1e6)
		} else {
			log.Printf("[download] starting %s", name)
		}
		stop := make(chan struct{})
		defer close(stop)
		sessionStart := time.Now()
		sessionBase := result.BodyOffset
		go func() {
			tick := time.NewTicker(5 * time.Second)
			defer tick.Stop()
			for {
				select {
				case <-stop:
					return
				case <-tick.C:
					total := bytesRead.Load()
					sessionBytes := total - sessionBase
					elapsed := time.Since(sessionStart).Seconds()
					mbps := float64(sessionBytes) / elapsed / 1e6
					if result.TotalSize > 0 {
						log.Printf("[download] %s: %.1f%% (%.1f MB/s)", name, float64(total)/float64(result.TotalSize)*100, mbps)
					} else {
						log.Printf("[download] %s: %.1f MB (%.1f MB/s)", name, float64(total)/1e6, mbps)
					}
				}
			}
		}()
	}

	counted := &countingReader{r: result.Body, n: &bytesRead}
	if _, err = io.Copy(f, counted); err != nil {
		f.Close()
		if ctx.Err() == nil {
			os.Remove(tmp)
		}
		return "", err
	}
	if err = f.Close(); err != nil {
		if ctx.Err() == nil {
			os.Remove(tmp)
		}
		return "", err
	}
	if showProgress {
		log.Printf("[download] %s: done (%.1f MB)", name, float64(bytesRead.Load())/1e6)
	}
	return result.MIMEType, os.Rename(tmp, dest)
}

type countingReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

func pluginCacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolving user cache dir: %w", err)
	}
	return filepath.Join(base, "packer-download-cache"), nil
}

func openDB(dir string) (*sql.DB, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "cache.db"))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;"); err != nil {
		db.Close()
		return nil, err
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS entries (
		url  TEXT PRIMARY KEY,
		path TEXT NOT NULL
	)`)
	if err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func filenameOf(rawURL string) string {
	withoutQuery := strings.SplitN(rawURL, "?", 2)[0]
	if strings.HasPrefix(withoutQuery, "s3://") {
		parts := strings.SplitN(withoutQuery[5:], "/", 2)
		if len(parts) == 2 {
			withoutQuery = parts[1]
		}
	}
	name := filepath.Base(withoutQuery)
	decoded, err := url.PathUnescape(name)
	if err != nil {
		return name
	}
	return decoded
}
