package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema returns the JSON schema for amass tool input.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"domain": schema.StringWithDesc("Target domain for enumeration (required)"),
		"mode": schema.JSON{
			Type:        "string",
			Description: "Enumeration mode: passive or active",
			Enum:        []any{"passive", "active"},
			Default:     "passive",
		},
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Execution timeout in seconds (optional)",
		},
		"max_depth": schema.JSON{
			Type:        "integer",
			Description: "DNS recursion depth (optional)",
		},
		"include_whois": schema.JSON{
			Type:        "boolean",
			Description: "Include WHOIS information (optional)",
		},
		"include_asn": schema.JSON{
			Type:        "boolean",
			Description: "Include ASN information (optional)",
		},
	}, "domain") // domain is required
}

// OutputSchema returns the JSON schema for amass tool output.
func OutputSchema() schema.JSON {
	// Domain field
	domainSchema := schema.String()

	// Subdomain schema - each string is a subdomain FQDN
	subdomainSchema := schema.String()

	// IP address schema - each string is a host IP
	ipSchema := schema.String()

	// ASN info schema with associated IPs
	asnIPSchema := schema.String()

	asnSchema := schema.Object(map[string]schema.JSON{
		"number":      schema.Int(),
		"description": schema.String(),
		"country":     schema.String(),
		"ips":         schema.Array(asnIPSchema),
	})

	// DNS record schema
	dnsRecordSchema := schema.Object(map[string]schema.JSON{
		"name":     schema.String(),
		"type":     schema.String(),
		"value":    schema.String(),
		"priority": schema.Int(),
		"ttl":      schema.Int(),
	})

	return schema.Object(map[string]schema.JSON{
		"domain":       domainSchema,
		"subdomains":   schema.Array(subdomainSchema),
		"ip_addresses": schema.Array(ipSchema),
		"asn_info":     schema.Array(asnSchema),
		"dns_records":  schema.Array(dnsRecordSchema),
		"whois":        schema.Object(map[string]schema.JSON{}), // Generic object for WHOIS data
		"scan_time_ms": schema.Int(),
	})
}
