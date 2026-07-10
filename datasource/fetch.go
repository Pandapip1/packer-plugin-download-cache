package datasource

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/Pandapip1/packer-plugin-download-cache/version"
)

var userAgent = "packer-plugin-download-cache/" + version.PluginVersion.FormattedVersion()

// FetchResult holds the response from a Fetcher.
type FetchResult struct {
	Body       io.ReadCloser
	BodyOffset int64 // byte offset where Body starts in the complete file (0 if server ignored the range request)
	TotalSize  int64 // complete file size (-1 if unknown)
	MIMEType   string
}

// Fetcher retrieves a URL, optionally resuming from offset bytes into the file.
type Fetcher interface {
	Schemes() []string
	Fetch(ctx context.Context, rawURL string, creds Credentials, offset int64) (FetchResult, error)
}

// DirFetcher is an optional extension of Fetcher for fetchers that support
// downloading an entire remote directory tree to a local destination path.
type DirFetcher interface {
	Fetcher
	FetchDir(ctx context.Context, rawURL string, creds Credentials, destPath string, showProgress bool) error
}

var fetchers = []Fetcher{
	&HTTPFetcher{},
	&S3Fetcher{},
	&SMBFetcher{},
}

func fetcherFor(rawURL string) (Fetcher, error) {
	scheme := strings.SplitN(rawURL, "://", 2)[0]
	for _, f := range fetchers {
		for _, s := range f.Schemes() {
			if s == scheme {
				return f, nil
			}
		}
	}
	return nil, fmt.Errorf("no fetcher registered for scheme %q", scheme)
}

// HTTPFetcher handles http:// and https://.
type HTTPFetcher struct{}

func (f *HTTPFetcher) Schemes() []string { return []string{"http", "https"} }

func (f *HTTPFetcher) Fetch(ctx context.Context, rawURL string, creds Credentials, offset int64) (FetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return FetchResult{}, err
	}

	if h := creds.HTTP; h != nil {
		switch {
		case h.BearerToken != "":
			req.Header.Set("Authorization", "Bearer "+h.BearerToken)
		case h.Username != "":
			req.SetBasicAuth(h.Username, h.Password)
		}
		for k, v := range h.Headers {
			req.Header.Set(k, v)
		}
	}

	req.Header.Set("User-Agent", userAgent)
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}

	resp, err := http.DefaultClient.Do(req) //nolint:gosec
	if err != nil {
		return FetchResult{}, err
	}
	if resp.StatusCode/100 != 2 {
		resp.Body.Close()
		return FetchResult{}, fmt.Errorf("HTTP %d for %s", resp.StatusCode, rawURL)
	}

	ct := resp.Header.Get("Content-Type")
	mimeType, _, _ := mime.ParseMediaType(ct)

	if resp.StatusCode == http.StatusPartialContent {
		total := parseTotalFromContentRange(resp.Header.Get("Content-Range"))
		return FetchResult{Body: resp.Body, BodyOffset: offset, TotalSize: total, MIMEType: mimeType}, nil
	}

	// Server returned 200: it ignored the Range header, send the full file.
	return FetchResult{Body: resp.Body, BodyOffset: 0, TotalSize: resp.ContentLength, MIMEType: mimeType}, nil
}

// parseTotalFromContentRange extracts the complete file size from a
// "Content-Range: bytes N-M/Total" header value, returning -1 on failure.
func parseTotalFromContentRange(cr string) int64 {
	// "bytes 500-999/1234" → 1234
	slash := strings.LastIndex(cr, "/")
	if slash < 0 {
		return -1
	}
	total, err := strconv.ParseInt(strings.TrimSpace(cr[slash+1:]), 10, 64)
	if err != nil {
		return -1
	}
	return total
}

// S3Fetcher handles s3://.
type S3Fetcher struct{}

func (f *S3Fetcher) Schemes() []string { return []string{"s3"} }

func (f *S3Fetcher) Fetch(ctx context.Context, rawURL string, creds Credentials, offset int64) (FetchResult, error) {
	rest := strings.TrimPrefix(rawURL, "s3://")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 {
		return FetchResult{}, fmt.Errorf("invalid s3 URL: %s", rawURL)
	}
	bucket, key := parts[0], parts[1]

	cfg, err := buildAWSConfig(ctx, creds.AWS)
	if err != nil {
		return FetchResult{}, fmt.Errorf("building AWS config: %w", err)
	}

	input := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}
	if offset > 0 {
		input.Range = aws.String(fmt.Sprintf("bytes=%d-", offset))
	}

	out, err := s3.NewFromConfig(cfg).GetObject(ctx, input)
	if err != nil {
		return FetchResult{}, err
	}

	var bodyOffset, totalSize int64 = 0, -1
	if offset > 0 && out.ContentRange != nil {
		totalSize = parseTotalFromContentRange(*out.ContentRange)
		bodyOffset = offset
	} else if out.ContentLength != nil {
		totalSize = *out.ContentLength
	}

	mimeType := ""
	if out.ContentType != nil {
		mimeType, _, _ = mime.ParseMediaType(*out.ContentType)
	}
	return FetchResult{Body: out.Body, BodyOffset: bodyOffset, TotalSize: totalSize, MIMEType: mimeType}, nil
}

// buildAWSConfig builds an AWS config from the standard credential chain
// (env vars, ~/.aws/credentials, SSO cache, IMDS, ECS, …) and then applies
// any explicit overrides from ac on top. ac may be nil, in which case only
// the ambient credentials are used.
func buildAWSConfig(ctx context.Context, ac *AWSCreds) (aws.Config, error) {
	var opts []func(*awsconfig.LoadOptions) error

	if ac != nil {
		if ac.Profile != "" {
			opts = append(opts, awsconfig.WithSharedConfigProfile(ac.Profile))
		}
		if ac.Region != "" {
			opts = append(opts, awsconfig.WithRegion(ac.Region))
		}
		if ac.AccessKey != "" {
			opts = append(opts, awsconfig.WithCredentialsProvider(
				credentials.NewStaticCredentialsProvider(ac.AccessKey, ac.SecretKey, ac.SessionToken),
			))
		}
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, err
	}

	// Role assumption wraps whatever credentials we already have.
	if ac != nil && ac.RoleARN != "" {
		cfg.Credentials = aws.NewCredentialsCache(
			stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), ac.RoleARN),
		)
	}

	return cfg, nil
}
