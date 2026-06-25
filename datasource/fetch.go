package datasource

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Fetcher retrieves a URL and optionally reports the MIME type (empty = unknown).
type Fetcher interface {
	Schemes() []string
	Fetch(ctx context.Context, rawURL string, creds Credentials) (body io.ReadCloser, mimeType string, err error)
}

var fetchers = []Fetcher{
	&HTTPFetcher{},
	&S3Fetcher{},
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

func (f *HTTPFetcher) Fetch(ctx context.Context, rawURL string, creds Credentials) (io.ReadCloser, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", err
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

	resp, err := http.DefaultClient.Do(req) //nolint:gosec
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode/100 != 2 {
		resp.Body.Close()
		return nil, "", fmt.Errorf("HTTP %d for %s", resp.StatusCode, rawURL)
	}

	ct := resp.Header.Get("Content-Type")
	mimeType, _, _ := mime.ParseMediaType(ct)
	return resp.Body, mimeType, nil
}

// S3Fetcher handles s3://.
type S3Fetcher struct{}

func (f *S3Fetcher) Schemes() []string { return []string{"s3"} }

func (f *S3Fetcher) Fetch(ctx context.Context, rawURL string, creds Credentials) (io.ReadCloser, string, error) {
	rest := strings.TrimPrefix(rawURL, "s3://")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 {
		return nil, "", fmt.Errorf("invalid s3 URL: %s", rawURL)
	}
	bucket, key := parts[0], parts[1]

	cfg, err := buildAWSConfig(ctx, creds.AWS)
	if err != nil {
		return nil, "", fmt.Errorf("building AWS config: %w", err)
	}

	out, err := s3.NewFromConfig(cfg).GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, "", err
	}

	mimeType := ""
	if out.ContentType != nil {
		mimeType, _, _ = mime.ParseMediaType(*out.ContentType)
	}
	return out.Body, mimeType, nil
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
