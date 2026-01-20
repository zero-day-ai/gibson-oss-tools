package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema returns the JSON schema for testssl tool input.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"targets": schema.JSON{
			Type:        "array",
			Description: "List of hosts/URLs to test (hostname:port or URL format) (required)",
			Items:       &schema.JSON{Type: "string"},
		},
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Execution timeout in seconds (optional)",
		},
		"severity": schema.JSON{
			Type:        "string",
			Description: "Minimum severity level to include (LOW, MEDIUM, HIGH, CRITICAL)",
			Default:     "LOW",
		},
	}, "targets") // targets is required
}

// OutputSchema returns the JSON schema for testssl tool output.
func OutputSchema() schema.JSON {
	// Vulnerability schema - represents SSL/TLS vulnerabilities
	vulnerabilitySchema := schema.Object(map[string]schema.JSON{
		"id":          schema.String(),
		"severity":    schema.String(),
		"finding":     schema.String(),
		"cve":         schema.String(),
		"description": schema.String(),
	})

	// Protocol schema - represents supported SSL/TLS protocols
	protocolSchema := schema.Object(map[string]schema.JSON{
		"name":     schema.String(),
		"severity": schema.String(),
		"finding":  schema.String(),
	})

	// Cipher schema - represents supported cipher suites
	cipherSchema := schema.Object(map[string]schema.JSON{
		"name":     schema.String(),
		"severity": schema.String(),
		"finding":  schema.String(),
	})

	// Certificate schema - represents SSL/TLS certificate info
	certificateSchema := schema.Object(map[string]schema.JSON{
		"subject":    schema.String(),
		"issuer":     schema.String(),
		"not_before": schema.String(),
		"not_after":  schema.String(),
		"sans":       schema.Array(schema.String()),
		"expired":    schema.Bool(),
	})

	// Result schema - represents a single host analysis
	resultSchema := schema.Object(map[string]schema.JSON{
		"target":          schema.String(),
		"ip":              schema.String(),
		"port":            schema.Int(),
		"protocols":       schema.Array(protocolSchema),
		"ciphers":         schema.Array(cipherSchema),
		"certificate":     certificateSchema,
		"vulnerabilities": schema.Array(vulnerabilitySchema),
	})

	return schema.Object(map[string]schema.JSON{
		"results":       schema.Array(resultSchema),
		"total_scanned": schema.Int(),
		"scan_time_ms":  schema.Int(),
	})
}
