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
// Includes embedded taxonomy mappings for GraphRAG integration.
func OutputSchema() schema.JSON {
	// Vulnerability schema - represents SSL/TLS vulnerabilities
	vulnerabilitySchema := schema.Object(map[string]schema.JSON{
		"id":          schema.String(),
		"severity":    schema.String(),
		"finding":     schema.String(),
		"cve":         schema.String(),
		"description": schema.String(),
	}).WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "vulnerability",
		IDTemplate: "vulnerability:{.id}:{_parent.target}",
		Properties: []schema.PropertyMapping{
			schema.PropMap("id", "vulnerability_id"),
			schema.PropMap("severity", "severity"),
			schema.PropMap("finding", "finding"),
			schema.PropMap("cve", "cve"),
			schema.PropMap("description", "description"),
		},
		Relationships: []schema.RelationshipMapping{
			// Link vulnerability to endpoint
			schema.Rel("HAS_VULNERABILITY", "endpoint:{_parent.target}", "vulnerability:{.id}:{_parent.target}"),
		},
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
	}).WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "certificate",
		IDTemplate: "certificate:{.subject}",
		Properties: []schema.PropertyMapping{
			schema.PropMap("subject", "subject"),
			schema.PropMap("issuer", "issuer"),
			schema.PropMap("not_before", "not_before"),
			schema.PropMap("not_after", "not_after"),
			schema.PropMap("sans", "subject_alternative_names"),
			schema.PropMap("expired", "expired"),
		},
		Relationships: []schema.RelationshipMapping{
			// Link certificate to endpoint
			schema.Rel("SERVED_BY", "certificate:{.subject}", "endpoint:{_parent.target}"),
		},
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
	}).WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "endpoint",
		IDTemplate: "endpoint:{.target}",
		Properties: []schema.PropertyMapping{
			schema.PropMap("target", "url"),
			schema.PropMap("ip", "ip"),
			schema.PropMap("port", "port"),
		},
		Relationships: []schema.RelationshipMapping{
			// Link agent run to discovered endpoint
			schema.Rel("DISCOVERED", "agent_run:{_context.agent_run_id}", "endpoint:{.target}"),
			// Link endpoint to certificate
			schema.Rel("SERVES_CERTIFICATE", "endpoint:{.target}", "certificate:{.certificate.subject}"),
		},
	})

	return schema.Object(map[string]schema.JSON{
		"results":       schema.Array(resultSchema),
		"total_scanned": schema.Int(),
		"scan_time_ms":  schema.Int(),
	})
}
