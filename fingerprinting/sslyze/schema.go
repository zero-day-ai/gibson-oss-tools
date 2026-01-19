package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema returns the JSON schema for sslyze tool input.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"targets": schema.JSON{
			Type:        "array",
			Description: "List of hosts to scan (hostname:port format) (required)",
			Items:       &schema.JSON{Type: "string"},
		},
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Execution timeout in seconds (optional)",
		},
	}, "targets") // targets is required
}

// OutputSchema returns the JSON schema for sslyze tool output.
// Includes embedded taxonomy mappings for GraphRAG integration.
// Schema is compatible with testssl output for agent fallback logic.
func OutputSchema() schema.JSON {
	// Vulnerability schema - represents SSL/TLS vulnerabilities
	vulnerabilitySchema := schema.Object(map[string]schema.JSON{
		"id":          schema.String(),
		"severity":    schema.String(),
		"finding":     schema.String(),
		"cve":         schema.String(),
		"description": schema.String(),
	}).WithTaxonomy(schema.TaxonomyMapping{
		NodeType: "vulnerability",
		IdentifyingProperties: map[string]string{
			"vulnerability_id": "$.id",
			"target":           "$._parent.target",
		},
		Properties: []schema.PropertyMapping{
			schema.PropMap("severity", "severity"),
			schema.PropMap("finding", "finding"),
			schema.PropMap("cve", "cve"),
			schema.PropMap("description", "description"),
		},
		Relationships: []schema.RelationshipMapping{
			// Link endpoint to vulnerability
			schema.Rel("HAS_VULNERABILITY",
				schema.Node("endpoint", map[string]string{
					"url": "$._parent.target",
				}),
				schema.SelfNode(),
			),
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
		NodeType: "certificate",
		IdentifyingProperties: map[string]string{
			"subject": "$.subject",
		},
		Properties: []schema.PropertyMapping{
			schema.PropMap("issuer", "issuer"),
			schema.PropMap("not_before", "not_before"),
			schema.PropMap("not_after", "not_after"),
			schema.PropMap("sans", "subject_alternative_names"),
			schema.PropMap("expired", "expired"),
		},
		Relationships: []schema.RelationshipMapping{
			// Link endpoint to certificate (endpoint serves certificate)
			schema.Rel("SERVED_BY",
				schema.SelfNode(),
				schema.Node("endpoint", map[string]string{
					"url": "$._parent.target",
				}),
			),
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
		NodeType: "endpoint",
		IdentifyingProperties: map[string]string{
			"url": "$.target",
		},
		Properties: []schema.PropertyMapping{
			schema.PropMap("ip", "ip"),
			schema.PropMap("port", "port"),
		},
		Relationships: []schema.RelationshipMapping{
			// Link agent run to discovered endpoint
			schema.Rel("DISCOVERED",
				schema.Node("agent_run", map[string]string{
					"agent_run_id": "$._context.agent_run_id",
				}),
				schema.SelfNode(),
			),
			// Link endpoint to certificate
			schema.Rel("SERVES_CERTIFICATE",
				schema.SelfNode(),
				schema.Node("certificate", map[string]string{
					"subject": "$.certificate.subject",
				}),
			),
		},
	})

	return schema.Object(map[string]schema.JSON{
		"results":       schema.Array(resultSchema),
		"total_scanned": schema.Int(),
		"scan_time_ms":  schema.Int(),
	})
}
