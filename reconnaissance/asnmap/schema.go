package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema returns the JSON schema for asnmap tool input.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"domain": schema.JSON{
			Type:        "string",
			Description: "Target domain for ASN lookup (optional)",
		},
		"ip": schema.JSON{
			Type:        "string",
			Description: "Target IP address for ASN lookup (optional)",
		},
		"asn": schema.JSON{
			Type:        "string",
			Description: "Target ASN number (e.g., AS15169) for IP range lookup (optional)",
		},
		"org": schema.JSON{
			Type:        "string",
			Description: "Organization name for ASN lookup (optional)",
		},
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Execution timeout in seconds (optional)",
		},
		"include_cidr": schema.JSON{
			Type:        "boolean",
			Description: "Include CIDR ranges in output (optional)",
			Default:     true,
		},
		"include_ipv6": schema.JSON{
			Type:        "boolean",
			Description: "Include IPv6 addresses in output (optional)",
			Default:     false,
		},
	})
}

// OutputSchema returns the JSON schema for asnmap tool output.
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"targets": schema.Array(schema.String()),
		"asn_info": schema.Array(schema.Object(map[string]schema.JSON{
			"timestamp": schema.String(),
			"input":     schema.String(),
			"asn":       schema.String(),
			"country":   schema.String(),
			"name":      schema.String(),
			"domain":    schema.String(),
			"ip":        schema.String(),
			"cidr":      schema.Array(schema.String()),
			"org":       schema.String(),
			"registry":  schema.String(),
			"ports":     schema.Array(schema.Int()),
		})),
		"total_asns":   schema.Int(),
		"asns":         schema.Array(schema.String()),
		"cidrs":        schema.Array(schema.String()),
		"total_cidrs":  schema.Int(),
		"scan_time_ms": schema.Int(),
	})
}
