package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema returns the JSON schema for massdns tool input.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"domain": schema.JSON{
			Type:        "string",
			Description: "Single target domain for bulk DNS resolution (optional if domains is provided)",
		},
		"domains": schema.JSON{
			Type:        "array",
			Description: "List of target domains for bulk DNS resolution (optional if domain is provided)",
			Items: &schema.JSON{
				Type: "string",
			},
		},
		"record_type": schema.JSON{
			Type:        "string",
			Description: "DNS record type to query (A, AAAA, CNAME, MX, NS, TXT, etc.) (optional)",
			Default:     "A",
		},
		"resolvers": schema.JSON{
			Type:        "string",
			Description: "Path to file containing DNS resolvers (one per line) (optional)",
		},
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Execution timeout in seconds (optional)",
		},
		"threads": schema.JSON{
			Type:        "integer",
			Description: "Number of concurrent resolution threads (optional)",
			Default:     1000,
		},
		"rate_limit": schema.JSON{
			Type:        "integer",
			Description: "Maximum queries per second (0 for unlimited) (optional)",
			Default:     0,
		},
	})
}

// OutputSchema returns the JSON schema for massdns tool output.
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"domains": schema.Array(schema.String()),
		"records": schema.Array(schema.Object(map[string]schema.JSON{
			"domain": schema.String(),
			"type":   schema.String(),
			"value":  schema.String(),
		})),
		"total":        schema.Int(),
		"resolved":     schema.Int(),
		"failed":       schema.Int(),
		"scan_time_ms": schema.Int(),
	})
}
