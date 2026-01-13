package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema returns the JSON schema for nmap tool input.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"target": schema.StringWithDesc("Target host, IP, or CIDR range to scan (required)"),
		"ports": schema.JSON{
			Type:        "string",
			Description: "Port specification (e.g., '22,80,443' or '1-1000')",
			Default:     "1-1000",
		},
		"scan_type": schema.JSON{
			Type:        "string",
			Description: "Scan type: connect (default, no root), syn (requires root), udp, ack, window, maimon",
			Enum:        []any{"connect", "syn", "udp", "ack", "window", "maimon"},
			Default:     "connect",
		},
		"service_detection": schema.JSON{
			Type:        "boolean",
			Description: "Enable service/version detection",
			Default:     true,
		},
		"os_detection": schema.JSON{
			Type:        "boolean",
			Description: "Enable OS detection",
			Default:     false,
		},
		"scripts": schema.JSON{
			Type:        "array",
			Description: "NSE scripts to run (optional)",
			Items:       &schema.JSON{Type: "string"},
		},
		"timing": schema.JSON{
			Type:        "integer",
			Description: "Timing template (0-5, higher is faster)",
			Default:     3,
		},
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Execution timeout in seconds (optional)",
		},
	}, "target") // target is required
}

// OutputSchema returns the JSON schema for nmap tool output.
// Includes embedded taxonomy mappings for GraphRAG integration.
func OutputSchema() schema.JSON {
	// Port schema with taxonomy for port nodes
	portSchema := schema.Object(map[string]schema.JSON{
		"port":     schema.Int(),
		"protocol": schema.String(),
		"state":    schema.String(),
		"service":  schema.String(),
		"version":  schema.String(),
	}).WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "port",
		IDTemplate: "port:{_parent.ip}:{.port}:{.protocol}",
		Properties: []schema.PropertyMapping{
			schema.PropMap("port", "number"),
			schema.PropMap("protocol", "protocol"),
			schema.PropMap("state", "state"),
		},
		Relationships: []schema.RelationshipMapping{
			schema.Rel("HAS_PORT", "host:{_parent.ip}", "port:{_parent.ip}:{.port}:{.protocol}"),
		},
	})

	// Host schema with taxonomy for host nodes
	hostSchema := schema.Object(map[string]schema.JSON{
		"ip":       schema.String(),
		"hostname": schema.String(),
		"state":    schema.String(),
		"os":       schema.String(),
		"ports":    schema.Array(portSchema),
	}).WithTaxonomy(schema.TaxonomyMapping{
		NodeType:   "host",
		IDTemplate: "host:{.ip}",
		Properties: []schema.PropertyMapping{
			schema.PropMap("ip", "ip"),
			schema.PropMap("hostname", "hostname"),
			schema.PropMap("state", "state"),
			schema.PropMap("os", "os"),
		},
		Relationships: []schema.RelationshipMapping{
			schema.Rel("DISCOVERED", "agent_run:{_context.agent_run_id}", "host:{.ip}"),
		},
	})

	return schema.Object(map[string]schema.JSON{
		"target":       schema.String(),
		"hosts":        schema.Array(hostSchema),
		"total_hosts":  schema.Int(),
		"hosts_up":     schema.Int(),
		"scan_time_ms": schema.Int(),
	})
}
