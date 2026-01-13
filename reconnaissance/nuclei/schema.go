package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema returns the JSON schema for nuclei tool input.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"target": schema.StringWithDesc("Target URL or host to scan (required)"),
		"templates": schema.JSON{
			Type:        "array",
			Description: "Specific template IDs to use (optional)",
			Items:       &schema.JSON{Type: "string"},
		},
		"severity": schema.JSON{
			Type:        "array",
			Description: "Filter templates by severity (info, low, medium, high, critical)",
			Items:       &schema.JSON{Type: "string"},
		},
		"tags": schema.JSON{
			Type:        "array",
			Description: "Filter templates by tags (optional)",
			Items:       &schema.JSON{Type: "string"},
		},
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Execution timeout in seconds (optional)",
		},
		"rate_limit": schema.JSON{
			Type:        "integer",
			Description: "Maximum requests per second (optional)",
			Default:     150,
		},
	}, "target") // target is required
}

// OutputSchema returns the JSON schema for nuclei tool output.
// Includes embedded taxonomy mappings for GraphRAG integration.
func OutputSchema() schema.JSON {
	// Finding schema with taxonomy for vulnerability/finding nodes
	findingSchema := schema.Object(map[string]schema.JSON{
		"template_id":   schema.String(),
		"template_name": schema.String(),
		"severity":      schema.String(),
		"type":          schema.String(),
		"matched_at":    schema.String(),
		"extracted":     schema.Array(schema.String()),
	}).WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "finding",
		IDTemplate: "finding:{.template_id}:{.matched_at}",
		Properties: []schema.PropertyMapping{
			schema.PropMap("template_id", "template_id"),
			schema.PropMap("template_name", "title"),
			schema.PropMapWithTransform("severity", "severity", "lowercase"),
			schema.PropMap("type", "category"),
			schema.PropMap("matched_at", "affected_component"),
		},
		Relationships: []schema.RelationshipMapping{
			// Link finding to affected endpoint
			schema.Rel("AFFECTS", "finding:{.template_id}:{.matched_at}", "endpoint:{.matched_at}"),
			// Link agent run to discovered finding
			schema.Rel("DISCOVERED", "agent_run:{_context.agent_run_id}", "finding:{.template_id}:{.matched_at}"),
		},
	})

	return schema.Object(map[string]schema.JSON{
		"target":         schema.String(),
		"findings":       schema.Array(findingSchema),
		"total_findings": schema.Int(),
		"scan_time_ms":   schema.Int(),
	})
}
