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
// Includes embedded taxonomy mappings for GraphRAG integration.
func OutputSchema() schema.JSON {
	// Technology schema - each string in the array is a technology name
	// Since technologies are simple strings, we create nodes from them
	technologySchema := schema.String().WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "technology",
		IDTemplate: "technology:{.}", // {.} refers to the string value itself
		Properties: []schema.PropertyMapping{
			schema.PropMap(".", "name"),
		},
		Relationships: []schema.RelationshipMapping{
			// Link endpoint to technology
			schema.Rel("USES_TECHNOLOGY", "endpoint:{_parent.url}", "technology:{.}"),
		},
	})

	// Result/endpoint schema with taxonomy
	resultSchema := schema.Object(map[string]schema.JSON{
		"url":          schema.String(),
		"status_code":  schema.Int(),
		"title":        schema.String(),
		"content_type": schema.String(),
		"technologies": schema.Array(technologySchema),
	}).WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "endpoint",
		IDTemplate: "endpoint:{.url}",
		Properties: []schema.PropertyMapping{
			schema.PropMap("url", "url"),
			schema.PropMap("status_code", "status_code"),
			schema.PropMap("title", "page_title"),
			schema.PropMap("content_type", "content_type"),
		},
		Relationships: []schema.RelationshipMapping{
			// Link agent run to discovered endpoint
			schema.Rel("DISCOVERED", "agent_run:{_context.agent_run_id}", "endpoint:{.url}"),
		},
	})

	return schema.Object(map[string]schema.JSON{
		"results":      schema.Array(resultSchema),
		"total_probed": schema.Int(),
		"alive_count":  schema.Int(),
		"scan_time_ms": schema.Int(),
	})
}
