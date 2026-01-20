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
func OutputSchema() schema.JSON {
	// Finding schema for vulnerability/finding nodes
	findingSchema := schema.Object(map[string]schema.JSON{
		"template_id":   schema.String(),
		"template_name": schema.String(),
		"severity":      schema.String(),
		"type":          schema.String(),
		"matched_at":    schema.String(),
		"extracted":     schema.Array(schema.String()),
		"matcher_name":  schema.String(),
		"description":   schema.String(),
		"remediation":   schema.String(),
		"references":    schema.Array(schema.String()),
		"cve_id":        schema.Array(schema.String()),
		"cwe_id":        schema.Array(schema.String()),
		"cvss_score":    schema.Number(),
		"cvss_metrics":  schema.String(),
		"host":          schema.String(), // Extracted host/IP from matched_at URL
		"port":          schema.Int(),    // Extracted port from matched_at URL
		"scheme":        schema.String(), // http or https
	})

	return schema.Object(map[string]schema.JSON{
		"target":         schema.String(),
		"findings":       schema.Array(findingSchema),
		"total_findings": schema.Int(),
		"scan_time_ms":   schema.Int(),
	})
}
