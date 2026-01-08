package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema returns the JSON schema for crtsh tool input.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"domain": schema.StringWithDesc("Target domain for certificate transparency search (required)"),
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Execution timeout in seconds (optional)",
		},
		"include_expired": schema.JSON{
			Type:        "boolean",
			Description: "Include expired certificates in results (optional)",
			Default:     true,
		},
		"wildcard_search": schema.JSON{
			Type:        "boolean",
			Description: "Use wildcard search to find all subdomains (optional)",
			Default:     true,
		},
	}, "domain") // domain is required
}

// OutputSchema returns the JSON schema for crtsh tool output.
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"domain":     schema.String(),
		"subdomains": schema.Array(schema.String()),
		"count":      schema.Int(),
		"certificates": schema.Array(schema.Object(map[string]schema.JSON{
			"id":            schema.Int(),
			"logged_at":     schema.String(),
			"not_before":    schema.String(),
			"not_after":     schema.String(),
			"common_name":   schema.String(),
			"issuer_name":   schema.String(),
			"serial_number": schema.String(),
		})),
		"total_certs":  schema.Int(),
		"scan_time_ms": schema.Int(),
	})
}
