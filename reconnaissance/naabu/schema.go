package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the naabu tool
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"hosts": schema.StringWithDesc("Target hosts (comma-separated IPs or hostnames, CIDR notation, or IP ranges)"),
		"ports": schema.JSON{
			Type:        "string",
			Description: "Port specification (e.g., '80,443', '1-1000', '0-65535') - optional if top_ports is used",
		},
		"rate": schema.JSON{
			Type:        "integer",
			Description: "Packets per second (optional, default: 1000)",
			Default:     1000,
		},
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Execution timeout in seconds (optional)",
		},
		"exclude_ports": schema.JSON{
			Type:        "string",
			Description: "Ports to exclude from scan (e.g., '80,443') (optional)",
		},
		"top_ports": schema.JSON{
			Type:        "string",
			Description: "Scan top N ports (e.g., 'full', '100', '1000') (optional, mutually exclusive with ports)",
		},
	}, "hosts") // hosts is required
}

// OutputSchema defines the output schema for the naabu tool
func OutputSchema() schema.JSON {
	portSchema := schema.Object(map[string]schema.JSON{
		"port":     schema.JSON{Type: "integer", Description: "Port number"},
		"protocol": schema.StringWithDesc("Protocol (tcp)"),
		"state":    schema.StringWithDesc("Port state (open)"),
		"ip":       schema.StringWithDesc("IP address (if hostname was scanned)"),
	})

	portsArray := schema.Array(portSchema)
	portsArray.Description = "List of open ports"

	hostSchema := schema.Object(map[string]schema.JSON{
		"host":  schema.StringWithDesc("Host identifier (hostname or IP)"),
		"ports": portsArray,
	})

	hostsArray := schema.Array(hostSchema)
	hostsArray.Description = "List of hosts with open ports"

	return schema.Object(map[string]schema.JSON{
		"hosts": hostsArray,
		"total_hosts": schema.JSON{
			Type:        "integer",
			Description: "Total number of hosts with open ports",
		},
		"total_ports": schema.JSON{
			Type:        "integer",
			Description: "Total number of open ports found",
		},
		"scan_rate": schema.JSON{
			Type:        "integer",
			Description: "Actual scan rate in packets per second",
		},
		"scan_time_ms": schema.JSON{
			Type:        "integer",
			Description: "Scan duration in milliseconds",
		},
	})
}
