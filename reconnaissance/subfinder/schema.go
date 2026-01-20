package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema returns the JSON schema for subfinder tool input.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"domain": schema.StringWithDesc("Target domain for subdomain enumeration (required)"),
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Execution timeout in seconds (optional)",
		},
		"silent": schema.JSON{
			Type:        "boolean",
			Description: "Silent mode, only output subdomains (optional)",
			Default:     false,
		},
		"recursive": schema.JSON{
			Type:        "boolean",
			Description: "Recursive subdomain enumeration (optional)",
			Default:     false,
		},
		"all": schema.JSON{
			Type:        "boolean",
			Description: "Use all sources for enumeration (optional)",
			Default:     true,
		},
	}, "domain") // domain is required
}

// OutputSchema returns the JSON schema for subfinder tool output.
// Note: subdomains is now an array of objects with name, ips, and sources.
func OutputSchema() schema.JSON {
	// IP address schema
	ipSchema := schema.String()

	// Subdomain schema - each object contains name, ips, and sources
	subdomainSchema := schema.Object(map[string]schema.JSON{
		"name":    schema.String(),
		"ips":     schema.Array(ipSchema),
		"sources": schema.Array(schema.String()),
	})

	// Domain field
	domainSchema := schema.String()

	return schema.Object(map[string]schema.JSON{
		"domain":       domainSchema,
		"subdomains":   schema.Array(subdomainSchema),
		"count":        schema.Int(),
		"scan_time_ms": schema.Int(),
	})
}
