package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema returns the JSON schema for httpx tool input.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"targets": schema.JSON{
			Type:        "array",
			Description: "List of URLs or hosts to probe (required)",
			Items:       &schema.JSON{Type: "string"},
		},
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Execution timeout in seconds (optional)",
		},
		"follow_redirects": schema.JSON{
			Type:        "boolean",
			Description: "Follow HTTP redirects (optional)",
			Default:     true,
		},
		"status_code": schema.JSON{
			Type:        "boolean",
			Description: "Display status code (optional)",
			Default:     true,
		},
		"title": schema.JSON{
			Type:        "boolean",
			Description: "Display page title (optional)",
			Default:     true,
		},
		"tech_detect": schema.JSON{
			Type:        "boolean",
			Description: "Detect technologies (optional)",
			Default:     false,
		},
	}, "targets") // targets is required
}

// OutputSchema returns the JSON schema for httpx tool output.
func OutputSchema() schema.JSON {
	// Technology schema - each string in the array is a technology name
	technologySchema := schema.String()

	// Certificate schema - created when cert_issuer is present (HTTPS only)
	certificateSchema := schema.Object(map[string]schema.JSON{
		"issuer":  schema.String(),
		"subject": schema.String(),
		"expiry":  schema.String(),
		"sans":    schema.Array(schema.String()),
	})

	// Redirect hop schema
	redirectHopSchema := schema.Object(map[string]schema.JSON{
		"url":         schema.String(),
		"status_code": schema.Int(),
	})

	// Response headers schema - generic object for dynamic headers
	responseHeadersSchema := schema.Object(map[string]schema.JSON{})

	// Result/endpoint schema
	resultSchema := schema.Object(map[string]schema.JSON{
		"url":              schema.String(),
		"status_code":      schema.Int(),
		"title":            schema.String(),
		"content_type":     schema.String(),
		"technologies":     schema.Array(technologySchema),
		"server":           schema.String(),
		"x_powered_by":     schema.String(),
		"response_headers": responseHeadersSchema,
		"final_url":        schema.String(),
		"redirect_chain":   schema.Array(redirectHopSchema),
		"cert_issuer":      schema.String(),
		"cert_subject":     schema.String(),
		"cert_expiry":      schema.String(),
		"cert_sans":        schema.Array(schema.String()),
		"certificate":      certificateSchema, // Nested certificate object (only present for HTTPS)
		"host":             schema.String(),   // Extracted host/IP from URL (for cross-tool linking)
		"port":             schema.Int(),      // Extracted port from URL (for cross-tool linking)
		"scheme":           schema.String(),   // http or https (for protocol detection)
	})

	return schema.Object(map[string]schema.JSON{
		"results":      schema.Array(resultSchema),
		"total_probed": schema.Int(),
		"alive_count":  schema.Int(),
		"scan_time_ms": schema.Int(),
	})
}
