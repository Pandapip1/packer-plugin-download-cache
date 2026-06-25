package datasource

import (
	"github.com/hashicorp/hcl/v2/hcldec"
	"github.com/zclconf/go-cty/cty"
)

type AWSCreds struct {
	Profile      string
	AccessKey    string
	SecretKey    string
	SessionToken string
	RoleARN      string
	Region       string
}

type HTTPCreds struct {
	BearerToken string
	Username    string
	Password    string
	Headers     map[string]string
}

type Credentials struct {
	AWS  *AWSCreds
	HTTP *HTTPCreds
}

// credentialsSpec is the shared hcldec spec for a credentials "…" { } block.
// All fields are optional; runtime validation rejects cross-scheme misuse.
// The same spec is used at the top level and nested inside entry blocks.
var credentialsSpec = hcldec.ObjectSpec{
	// AWS fields
	"profile":       &hcldec.AttrSpec{Name: "profile", Type: cty.String, Required: false},
	"access_key":    &hcldec.AttrSpec{Name: "access_key", Type: cty.String, Required: false},
	"secret_key":    &hcldec.AttrSpec{Name: "secret_key", Type: cty.String, Required: false},
	"session_token": &hcldec.AttrSpec{Name: "session_token", Type: cty.String, Required: false},
	"role_arn":      &hcldec.AttrSpec{Name: "role_arn", Type: cty.String, Required: false},
	"region":        &hcldec.AttrSpec{Name: "region", Type: cty.String, Required: false},
	// HTTP fields
	"bearer_token": &hcldec.AttrSpec{Name: "bearer_token", Type: cty.String, Required: false},
	"username":     &hcldec.AttrSpec{Name: "username", Type: cty.String, Required: false},
	"password":     &hcldec.AttrSpec{Name: "password", Type: cty.String, Required: false},
	"headers":      &hcldec.AttrSpec{Name: "headers", Type: cty.Map(cty.String), Required: false},
}

// credentialsBlockMapSpec is the BlockMapSpec used wherever credentials blocks appear.
var credentialsBlockMapSpec = &hcldec.BlockMapSpec{
	TypeName:   "credentials",
	LabelNames: []string{"scheme"},
	Nested:     credentialsSpec,
}

// parseCredentials converts a cty.Map from a credentials BlockMapSpec into a Credentials value.
func parseCredentials(val cty.Value) Credentials {
	var creds Credentials
	if val.IsNull() || !val.IsKnown() {
		return creds
	}
	for scheme, cv := range val.AsValueMap() {
		switch scheme {
		case "aws":
			creds.AWS = &AWSCreds{
				Profile:      strAttr(cv, "profile"),
				AccessKey:    strAttr(cv, "access_key"),
				SecretKey:    strAttr(cv, "secret_key"),
				SessionToken: strAttr(cv, "session_token"),
				RoleARN:      strAttr(cv, "role_arn"),
				Region:       strAttr(cv, "region"),
			}
		case "http":
			creds.HTTP = &HTTPCreds{
				BearerToken: strAttr(cv, "bearer_token"),
				Username:    strAttr(cv, "username"),
				Password:    strAttr(cv, "password"),
				Headers:     mapAttr(cv, "headers"),
			}
		}
	}
	return creds
}

// Merge returns a copy of base with non-zero fields from override applied.
// A non-nil override.AWS completely replaces base.AWS; same for HTTP.
func (base Credentials) Merge(override Credentials) Credentials {
	out := base
	if override.AWS != nil {
		out.AWS = override.AWS
	}
	if override.HTTP != nil {
		out.HTTP = override.HTTP
	}
	return out
}

func strAttr(v cty.Value, name string) string {
	a := v.GetAttr(name)
	if a.IsKnown() && !a.IsNull() {
		return a.AsString()
	}
	return ""
}

func mapAttr(v cty.Value, name string) map[string]string {
	a := v.GetAttr(name)
	if !a.IsKnown() || a.IsNull() {
		return nil
	}
	out := make(map[string]string)
	for k, val := range a.AsValueMap() {
		if val.IsKnown() && !val.IsNull() {
			out[k] = val.AsString()
		}
	}
	return out
}
