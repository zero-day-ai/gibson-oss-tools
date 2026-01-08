package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema returns the JSON schema for dnsx tool input.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"domain": schema.JSON{
			Type:        "string",
			Description: "Single target domain for DNS resolution (optional if domains is provided)",
		},
		"domains": schema.JSON{
			Type:        "array",
			Description: "List of target domains for DNS resolution (optional if domain is provided)",
			Items: &schema.JSON{
				Type: "string",
			},
		},
		"query_types": schema.JSON{
			Type:        "array",
			Description: "DNS query types to perform (A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, SRV) (optional)",
			Items: &schema.JSON{
				Type: "string",
				Enum: []any{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "SRV"},
			},
			Default: []any{"A"},
		},
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Execution timeout in seconds (optional)",
		},
		"retries": schema.JSON{
			Type:        "integer",
			Description: "Number of DNS resolution retries (optional)",
			Default:     2,
		},
		"threads": schema.JSON{
			Type:        "integer",
			Description: "Number of concurrent threads (optional)",
			Default:     100,
		},
		"wildcard_check": schema.JSON{
			Type:        "boolean",
			Description: "Enable wildcard domain detection (optional)",
			Default:     true,
		},
	})
}

// OutputSchema returns the JSON schema for dnsx tool output.
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"domains": schema.Array(schema.String()),
		"records": schema.Array(schema.Object(map[string]schema.JSON{
			"host":        schema.String(),
			"a":           schema.Array(schema.String()),
			"aaaa":        schema.Array(schema.String()),
			"cname":       schema.Array(schema.String()),
			"mx":          schema.Array(schema.String()),
			"ns":          schema.Array(schema.String()),
			"txt":         schema.Array(schema.String()),
			"soa":         schema.Array(schema.String()),
			"ptr":         schema.Array(schema.String()),
			"srv":         schema.Array(schema.String()),
			"status_code": schema.String(),
		})),
		"total":        schema.Int(),
		"resolved":     schema.Int(),
		"failed":       schema.Int(),
		"scan_time_ms": schema.Int(),
	})
}
