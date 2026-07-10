package datasource

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	smb2 "github.com/hirochachacha/go-smb2"
)

// SMBFetcher handles smb:// URLs for both single files and directory trees.
type SMBFetcher struct{}

func (f *SMBFetcher) Schemes() []string { return []string{"smb"} }

// smbConn holds an open SMB session and mounted share, and closes them in order.
type smbConn struct {
	conn    net.Conn
	session *smb2.Session
	share   *smb2.Share
}

func (c *smbConn) close() {
	c.share.Umount()
	c.session.Logoff()
	c.conn.Close()
}

// smbFileCloser wraps an SMB file so that closing it also tears down the session.
type smbFileCloser struct {
	file *smb2.File
	conn *smbConn
}

func (r *smbFileCloser) Read(p []byte) (int, error) { return r.file.Read(p) }
func (r *smbFileCloser) Close() error {
	r.file.Close()
	r.conn.close()
	return nil
}

func dialSMB(ctx context.Context, rawURL string, creds Credentials) (*smbConn, string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, "", fmt.Errorf("invalid smb URL: %w", err)
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "445"
	}

	// Path: /share/rest/of/path
	parts := strings.SplitN(strings.TrimPrefix(u.Path, "/"), "/", 2)
	shareName := parts[0]
	remotePath := ""
	if len(parts) == 2 {
		remotePath = parts[1]
	}

	initiator := &smb2.NTLMInitiator{}
	if sc := creds.SMB; sc != nil {
		initiator.User = sc.Username
		initiator.Password = sc.Password
		initiator.Domain = sc.Domain
	} else if u.User != nil {
		initiator.User = u.User.Username()
		initiator.Password, _ = u.User.Password()
	}

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, "", fmt.Errorf("smb connect to %s: %w", host, err)
	}

	d := &smb2.Dialer{Initiator: initiator}
	session, err := d.DialContext(ctx, conn)
	if err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("smb auth: %w", err)
	}

	share, err := session.Mount(shareName)
	if err != nil {
		session.Logoff()
		conn.Close()
		return nil, "", fmt.Errorf("smb mount %q: %w", shareName, err)
	}

	return &smbConn{conn: conn, session: session, share: share}, remotePath, nil
}

func (f *SMBFetcher) Fetch(ctx context.Context, rawURL string, creds Credentials, offset int64) (FetchResult, error) {
	sc, remotePath, err := dialSMB(ctx, rawURL, creds)
	if err != nil {
		return FetchResult{}, err
	}

	file, err := sc.share.Open(remotePath)
	if err != nil {
		sc.close()
		return FetchResult{}, fmt.Errorf("smb open %q: %w", remotePath, err)
	}

	stat, err := file.Stat()
	if err != nil {
		file.Close()
		sc.close()
		return FetchResult{}, fmt.Errorf("smb stat %q: %w", remotePath, err)
	}
	totalSize := stat.Size()

	if offset > 0 {
		if _, err := file.Seek(offset, io.SeekStart); err != nil {
			file.Close()
			sc.close()
			return FetchResult{}, fmt.Errorf("smb seek: %w", err)
		}
	}

	return FetchResult{
		Body:       &smbFileCloser{file: file, conn: sc},
		BodyOffset: offset,
		TotalSize:  totalSize,
	}, nil
}

func (f *SMBFetcher) FetchDir(ctx context.Context, rawURL string, creds Credentials, destPath string, showProgress bool) error {
	sc, remotePath, err := dialSMB(ctx, rawURL, creds)
	if err != nil {
		return err
	}
	defer sc.close()

	root := sc.share.DirFS(remotePath)

	// Collect all entries first, creating directories as we go.
	type fileEntry struct {
		path string
		size int64
	}
	var files []fileEntry

	if err := fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(destPath, filepath.FromSlash(path)), 0o755)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		files = append(files, fileEntry{path: path, size: info.Size()})
		return nil
	}); err != nil {
		return err
	}

	var wg sync.WaitGroup
	errc := make(chan error, len(files))
	var done atomic.Int64
	total := int64(len(files))

	if showProgress {
		stop := make(chan struct{})
		defer close(stop)
		go func() {
			tick := time.NewTicker(5 * time.Second)
			defer tick.Stop()
			for {
				select {
				case <-stop:
					return
				case <-tick.C:
					log.Printf("[download] smb dir: %d/%d files done", done.Load(), total)
				}
			}
		}()
	}

	for _, fe := range files {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(fe fileEntry) {
			defer wg.Done()
			if ctx.Err() != nil {
				return
			}
			src, err := root.Open(fe.path)
			if err != nil {
				errc <- fmt.Errorf("smb open %q: %w", fe.path, err)
				return
			}
			defer src.Close()
			dst, err := os.Create(filepath.Join(destPath, filepath.FromSlash(fe.path)))
			if err != nil {
				errc <- err
				return
			}
			defer dst.Close()
			if _, err = io.Copy(dst, &ctxReader{ctx: ctx, r: src}); err != nil {
				errc <- err
				return
			}
			done.Add(1)
			if showProgress {
				log.Printf("[download] smb %s done (%.1f MB)", fe.path, float64(fe.size)/1e6)
			}
		}(fe)
	}

	wg.Wait()
	close(errc)
	if err := <-errc; err != nil {
		return err
	}
	return ctx.Err()
}

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *ctxReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}
