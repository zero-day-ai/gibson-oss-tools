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
// Includes embedded taxonomy mappings for GraphRAG integration.
func OutputSchema() schema.JSON {
	// Technology schema - represents detected technologies/frameworks
	technologySchema := schema.Object(map[string]schema.JSON{
		"name":       schema.String(),
		"version":    schema.String(),
		"categories": schema.Array(schema.String()),
		"confidence": schema.Int(),
	}).WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "technology",
		IDTemplate: "technology:{.name}",
		Properties: []schema.PropertyMapping{
			schema.PropMap("name", "name"),
			schema.PropMap("version", "version"),
			schema.PropMap("categories", "categories"),
			schema.PropMap("confidence", "confidence"),
		},
		Relationships: []schema.RelationshipMapping{
			// Link endpoint to technology
			schema.Rel("USES_TECHNOLOGY", "endpoint:{_parent.url}", "technology:{.name}"),
		},
	})

	// Result schema - represents a single URL analysis
	resultSchema := schema.Object(map[string]schema.JSON{
		"url":          schema.String(),
		"host":         schema.String(),
		"technologies": schema.Array(technologySchema),
	}).WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "endpoint",
		IDTemplate: "endpoint:{.url}",
		Properties: []schema.PropertyMapping{
			schema.PropMap("url", "url"),
			schema.PropMap("host", "host"),
		},
		Relationships: []schema.RelationshipMapping{
			// Link agent run to discovered endpoint
			schema.Rel("DISCOVERED", "agent_run:{_context.agent_run_id}", "endpoint:{.url}"),
			// Link endpoint to host
			schema.Rel("HOSTED_ON", "endpoint:{.url}", "host:{.host}"),
		},
	})

	return schema.Object(map[string]schema.JSON{
		"results":      schema.Array(resultSchema),
		"total_scanned": schema.Int(),
		"scan_time_ms": schema.Int(),
	})
}
