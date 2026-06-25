package datasource

import (
	"archive/tar"
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bodgit/sevenzip"
	"github.com/ulikunitz/xz"
)

// Extractor unpacks an archive file into dest.
// mimeType is the resolved MIME (from sniffMIME) so the extractor can choose a decompressor.
type Extractor interface {
	MIMETypes() []string
	Extract(archive, dest, mimeType string) error
}

var extractors = []Extractor{
	&ZipExtractor{},
	&TarExtractor{},
	&SevenZipExtractor{},
	&ISOExtractor{},
}

// extractorFor returns the extractor that handles mimeType, or nil.
func extractorFor(mimeType string) Extractor {
	for _, e := range extractors {
		for _, m := range e.MIMETypes() {
			if m == mimeType {
				return e
			}
		}
	}
	return nil
}

// sniffMIME resolves the MIME type for an already-downloaded archive.
// Priority: fetcherMIME (if useful) → magic bytes → extension.
func sniffMIME(archivePath, fetcherMIME string) string {
	if fetcherMIME != "" && fetcherMIME != "application/octet-stream" {
		return fetcherMIME
	}
	if m := sniffBytes(archivePath); m != "" {
		return m
	}
	return mimeFromExtension(archivePath)
}

// magic-byte table checked against the first 512 bytes of the file.
// tar detection requires checking offset 257, so we need at least 262 bytes.
var magicSigs = []struct {
	offset   int
	sig      []byte
	mimeType string
}{
	{0, []byte{0x50, 0x4B, 0x03, 0x04}, "application/zip"},
	{0, []byte{0x1F, 0x8B}, "application/gzip"},
	{0, []byte{'B', 'Z', 'h'}, "application/x-bzip2"},
	{0, []byte{0xFD, '7', 'z', 'X', 'Z', 0x00}, "application/x-xz"},
	{0, []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, "application/x-7z-compressed"},
	{257, []byte{'u', 's', 't', 'a', 'r'}, "application/x-tar"},
}

func sniffBytes(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	buf := make([]byte, 512)
	n, _ := io.ReadFull(f, buf)
	buf = buf[:n]

	for _, sig := range magicSigs {
		end := sig.offset + len(sig.sig)
		if end > len(buf) {
			continue
		}
		if string(buf[sig.offset:end]) == string(sig.sig) {
			return sig.mimeType
		}
	}
	return ""
}

var extensionMIME = map[string]string{
	".zip":     "application/zip",
	".tar":     "application/x-tar",
	".tar.gz":  "application/gzip",
	".tgz":     "application/gzip",
	".tar.bz2": "application/x-bzip2",
	".tar.xz":  "application/x-xz",
	".gz":      "application/gzip",
	".bz2":     "application/x-bzip2",
	".xz":      "application/x-xz",
	".7z":      "application/x-7z-compressed",
	".iso":     "application/x-iso9660-image",
}

func mimeFromExtension(path string) string {
	lower := strings.ToLower(path)
	// check compound extensions first
	for _, suf := range []string{".tar.gz", ".tar.bz2", ".tar.xz"} {
		if strings.HasSuffix(lower, suf) {
			return extensionMIME[suf]
		}
	}
	// .7z.001 (and higher parts) are multipart 7z volumes
	if strings.HasSuffix(lower, ".7z.001") || is7zPart(lower) {
		return "application/x-7z-compressed"
	}
	return extensionMIME[filepath.Ext(lower)]
}

// is7zPart reports whether path ends in .7z.NNN (NNN ≥ 002).
func is7zPart(lower string) bool {
	ext := filepath.Ext(lower)
	if len(ext) != 4 {
		return false
	}
	for _, c := range ext[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return strings.HasSuffix(strings.TrimSuffix(lower, ext), ".7z")
}

// stemOf strips the archive extension from a filename to produce a directory name.
func stemOf(name string) string {
	lower := strings.ToLower(name)
	for _, s := range []string{".tar.gz", ".tar.xz", ".tar.bz2", ".tgz"} {
		if strings.HasSuffix(lower, s) {
			return name[:len(name)-len(s)]
		}
	}
	// strip .7z.001, .7z.002, … → base stem
	if strings.HasSuffix(lower, ".7z.001") {
		return name[:len(name)-len(".7z.001")]
	}
	if is7zPart(lower) {
		ext := filepath.Ext(lower)
		return name[:len(name)-len(ext)-len(".7z")]
	}
	return strings.TrimSuffix(name, filepath.Ext(name))
}

// ZipExtractor handles application/zip.
type ZipExtractor struct{}

func (e *ZipExtractor) MIMETypes() []string { return []string{"application/zip"} }

func (e *ZipExtractor) Extract(archive, dest, _ string) error {
	r, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		if err := extractZipEntry(f, dest); err != nil {
			return err
		}
	}
	return nil
}

func extractZipEntry(f *zip.File, dest string) error {
	path := filepath.Join(dest, filepath.Clean(f.Name))
	if !strings.HasPrefix(path, filepath.Clean(dest)+string(os.PathSeparator)) {
		return fmt.Errorf("zip slip: %s", f.Name)
	}
	if f.FileInfo().IsDir() {
		return os.MkdirAll(path, f.Mode())
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}
	defer out.Close()
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	_, err = io.Copy(out, rc) //nolint:gosec
	return err
}

// TarExtractor handles plain tar and all compressed variants.
type TarExtractor struct{}

func (e *TarExtractor) MIMETypes() []string {
	return []string{
		"application/x-tar",
		"application/gzip",
		"application/x-gzip",
		"application/x-bzip2",
		"application/x-xz",
	}
}

func (e *TarExtractor) Extract(archive, dest, mimeType string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()

	var r io.Reader = f
	switch mimeType {
	case "application/gzip", "application/x-gzip":
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		r = gz
	case "application/x-bzip2":
		r = bzip2.NewReader(f)
	case "application/x-xz":
		xzr, err := xz.NewReader(f)
		if err != nil {
			return err
		}
		r = xzr
	}

	return extractTarStream(r, dest)
}

func extractTarStream(r io.Reader, dest string) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		path := filepath.Join(dest, filepath.Clean(hdr.Name))
		if !strings.HasPrefix(path, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("tar slip: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, os.FileMode(hdr.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			_, err = io.Copy(out, tr) //nolint:gosec
			out.Close()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// SevenZipExtractor handles application/x-7z-compressed (single and multipart volumes).
// For multipart archives the first volume must end in ".7z.001"; subsequent volumes
// (.7z.002, .7z.003, …) must already be present in the same directory — download
// them as separate non-extract entries before extracting the first part.
type SevenZipExtractor struct{}

func (e *SevenZipExtractor) MIMETypes() []string {
	return []string{"application/x-7z-compressed"}
}

func (e *SevenZipExtractor) Extract(archive, dest, _ string) error {
	r, err := sevenzip.OpenReader(archive)
	if err != nil {
		return fmt.Errorf("7z open: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		if err := extract7zEntry(f, dest); err != nil {
			return err
		}
	}
	return nil
}

func extract7zEntry(f *sevenzip.File, dest string) error {
	path := filepath.Join(dest, filepath.Clean(f.Name))
	if !strings.HasPrefix(path, filepath.Clean(dest)+string(os.PathSeparator)) {
		return fmt.Errorf("7z slip: %s", f.Name)
	}
	if f.FileInfo().IsDir() {
		return os.MkdirAll(path, f.Mode())
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}
	defer out.Close()
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	_, err = io.Copy(out, rc) //nolint:gosec
	return err
}

// ISOExtractor handles application/x-iso9660-image via bsdtar.
type ISOExtractor struct{}

func (e *ISOExtractor) MIMETypes() []string {
	return []string{"application/x-iso9660-image"}
}

func (e *ISOExtractor) Extract(archive, dest, _ string) error {
	out, err := exec.Command("bsdtar", "-xf", archive, "-C", dest).CombinedOutput()
	if err != nil {
		return fmt.Errorf("bsdtar: %s", out)
	}
	return nil
}
