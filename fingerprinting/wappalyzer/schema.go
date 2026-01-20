package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema returns the JSON schema for wappalyzer tool input.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"targets": schema.JSON{
			Type:        "array",
			Description: "List of URLs to analyze for technology detection (required)",
			Items:       &schema.JSON{Type: "string"},
		},
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Execution timeout in seconds (optional)",
		},
	}, "targets") // targets is required
}

// OutputSchema returns the JSON schema for wappalyzer tool output.
func OutputSchema() schema.JSON {
	// Technology schema - represents detected technologies/frameworks
	technologySchema := schema.Object(map[string]schema.JSON{
		"name":       schema.String(),
		"version":    schema.String(),
		"categories": schema.Array(schema.String()),
		"confidence": schema.Int(),
	})

	// Result schema - represents a single URL analysis
	resultSchema := schema.Object(map[string]schema.JSON{
		"url":          schema.String(),
		"host":         schema.String(),
		"technologies": schema.Array(technologySchema),
	})

	return schema.Object(map[string]schema.JSON{
		"results":      schema.Array(resultSchema),
		"total_scanned": schema.Int(),
		"scan_time_ms": schema.Int(),
	})
}
