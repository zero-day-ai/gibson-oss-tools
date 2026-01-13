package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema returns the JSON schema for subfinder tool input.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"domain": schema.StringWithDesc("Target domain for subdomain enumeration (required)"),
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Execution timeout in seconds (optional)",
		},
		"silent": schema.JSON{
			Type:        "boolean",
			Description: "Silent mode, only output subdomains (optional)",
			Default:     false,
		},
		"recursive": schema.JSON{
			Type:        "boolean",
			Description: "Recursive subdomain enumeration (optional)",
			Default:     false,
		},
		"all": schema.JSON{
			Type:        "boolean",
			Description: "Use all sources for enumeration (optional)",
			Default:     true,
		},
	}, "domain") // domain is required
}

// OutputSchema returns the JSON schema for subfinder tool output.
// Includes embedded taxonomy mappings for GraphRAG integration.
// Note: subdomains is a string array where each element is the subdomain FQDN.
func OutputSchema() schema.JSON {
	// Subdomain schema - each string in the array is a subdomain FQDN
	// The taxonomy treats each string as the node ID and name
	subdomainSchema := schema.String().WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "subdomain",
		IDTemplate: "subdomain:{.}", // {.} refers to the string value itself
		Properties: []schema.PropertyMapping{
			schema.PropMap(".", "name"), // The string value is the name
		},
		Relationships: []schema.RelationshipMapping{
			// Link subdomain to parent domain (from root output)
			schema.Rel("HAS_SUBDOMAIN", "domain:{_root.domain}", "subdomain:{.}"),
			// Link agent run to discovered subdomain
			schema.Rel("DISCOVERED", "agent_run:{_context.agent_run_id}", "subdomain:{.}"),
		},
	})

	// Domain field with taxonomy for domain node creation
	domainSchema := schema.String().WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "domain",
		IDTemplate: "domain:{.}",
		Properties: []schema.PropertyMapping{
			schema.PropMap(".", "name"),
		},
		Relationships: []schema.RelationshipMapping{
			schema.Rel("DISCOVERED", "agent_run:{_context.agent_run_id}", "domain:{.}"),
		},
	})

	return schema.Object(map[string]schema.JSON{
		"domain":       domainSchema,
		"subdomains":   schema.Array(subdomainSchema),
		"count":        schema.Int(),
		"scan_time_ms": schema.Int(),
	})
}
