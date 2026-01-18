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
// Includes embedded taxonomy mappings for GraphRAG integration.
func OutputSchema() schema.JSON {
	// Plugin match schema - represents detected technology/feature
	pluginSchema := schema.Object(map[string]schema.JSON{
		"name":       schema.String(),
		"version":    schema.Array(schema.String()),
		"categories": schema.Array(schema.String()),
		"string":     schema.Array(schema.String()),
	}).WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "technology",
		IDTemplate: "technology:{.name}",
		Properties: []schema.PropertyMapping{
			schema.PropMap("name", "name"),
			schema.PropMap("version", "version"),
			schema.PropMap("categories", "categories"),
		},
		Relationships: []schema.RelationshipMapping{
			// Link endpoint to technology
			schema.Rel("USES_TECHNOLOGY", "endpoint:{_parent.target}", "technology:{.name}"),
		},
	})

	// Result schema - represents a single URL analysis
	resultSchema := schema.Object(map[string]schema.JSON{
		"target":      schema.String(),
		"http_status": schema.Int(),
		"request_url": schema.String(),
		"plugins":     schema.Array(pluginSchema),
		"ip":          schema.String(),
		"host":        schema.String(),
	}).WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "endpoint",
		IDTemplate: "endpoint:{.target}",
		Properties: []schema.PropertyMapping{
			schema.PropMap("target", "url"),
			schema.PropMap("http_status", "status_code"),
			schema.PropMap("request_url", "request_url"),
			schema.PropMap("ip", "ip"),
			schema.PropMap("host", "host"),
		},
		Relationships: []schema.RelationshipMapping{
			// Link agent run to discovered endpoint
			schema.Rel("DISCOVERED", "agent_run:{_context.agent_run_id}", "endpoint:{.target}"),
			// Link endpoint to host
			schema.Rel("HOSTED_ON", "endpoint:{.target}", "host:{.host}"),
		},
	})

	return schema.Object(map[string]schema.JSON{
		"results":       schema.Array(resultSchema),
		"total_scanned": schema.Int(),
		"scan_time_ms":  schema.Int(),
	})
}
