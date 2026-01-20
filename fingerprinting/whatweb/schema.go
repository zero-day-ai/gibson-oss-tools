package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema returns the JSON schema for whatweb tool input.
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
		"aggression": schema.JSON{
			Type:        "integer",
			Description: "Aggression level 1-4 (1=stealthy, 4=aggressive, default=1)",
			Default:     1,
		},
	}, "targets") // targets is required
}

// OutputSchema returns the JSON schema for whatweb tool output.
func OutputSchema() schema.JSON {
	// Plugin match schema - represents detected technology/feature
	pluginSchema := schema.Object(map[string]schema.JSON{
		"name":       schema.String(),
		"version":    schema.Array(schema.String()),
		"categories": schema.Array(schema.String()),
		"string":     schema.Array(schema.String()),
	})

	// Result schema - represents a single URL analysis
	resultSchema := schema.Object(map[string]schema.JSON{
		"target":      schema.String(),
		"http_status": schema.Int(),
		"request_url": schema.String(),
		"plugins":     schema.Array(pluginSchema),
		"ip":          schema.String(),
		"host":        schema.String(),
	})

	return schema.Object(map[string]schema.JSON{
		"results":       schema.Array(resultSchema),
		"total_scanned": schema.Int(),
		"scan_time_ms":  schema.Int(),
	})
}
