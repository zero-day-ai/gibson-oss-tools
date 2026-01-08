package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the Censys tool
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"search_type": schema.JSON{
			Type:        "string",
			Description: "Type of search to perform: 'hosts' or 'certificates'",
			Enum:        []any{"hosts", "certificates"},
			Default:     "hosts",
		},
		"query": schema.JSON{
			Type:        "string",
			Description: "Censys search query (e.g., 'services.http.response.headers.server: nginx', 'parsed.subject.common_name: example.com')",
		},
		"api_id": schema.JSON{
			Type:        "string",
			Description: "Censys API ID (required for searches)",
		},
		"api_secret": schema.JSON{
			Type:        "string",
			Description: "Censys API Secret (required for searches)",
		},
		"pages": schema.JSON{
			Type:        "integer",
			Description: "Number of pages to retrieve (default: 1, max: 100)",
			Default:     1,
			Minimum:     ptrFloat64(1),
			Maximum:     ptrFloat64(100),
		},
		"per_page": schema.JSON{
			Type:        "integer",
			Description: "Results per page (default: 100, max: 100)",
			Default:     100,
			Minimum:     ptrFloat64(1),
			Maximum:     ptrFloat64(100),
		},
		"fields": schema.JSON{
			Type:        "array",
			Description: "Specific fields to return (e.g., 'ip', 'services.port', 'location.country')",
			Items: &schema.JSON{
				Type: "string",
			},
		},
	}, "query", "api_id", "api_secret") // query and credentials are required
}

// OutputSchema defines the output schema for the Censys tool
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"total_results": schema.JSON{
			Type:        "integer",
			Description: "Total number of results available",
		},
		"returned_results": schema.JSON{
			Type:        "integer",
			Description: "Number of results returned in this response",
		},
		"hosts": schema.JSON{
			Type:        "array",
			Description: "Host search results (when search_type is 'hosts')",
			Items: &schema.JSON{
				Type: "object",
				Properties: map[string]schema.JSON{
					"ip": schema.JSON{
						Type:        "string",
						Description: "IP address",
					},
					"services": schema.JSON{
						Type:        "array",
						Description: "Services running on the host",
						Items: &schema.JSON{
							Type: "object",
							Properties: map[string]schema.JSON{
								"port":            schema.JSON{Type: "integer"},
								"service_name":    schema.JSON{Type: "string"},
								"transport_protocol": schema.JSON{Type: "string"},
								"extended_service_name": schema.JSON{Type: "string"},
								"certificate":     schema.JSON{Type: "string"},
								"banner":          schema.JSON{Type: "string"},
							},
						},
					},
					"location": schema.JSON{
						Type:        "object",
						Description: "Geographic location",
						Properties: map[string]schema.JSON{
							"continent":     schema.JSON{Type: "string"},
							"country":       schema.JSON{Type: "string"},
							"country_code":  schema.JSON{Type: "string"},
							"city":          schema.JSON{Type: "string"},
							"province":      schema.JSON{Type: "string"},
							"postal_code":   schema.JSON{Type: "string"},
							"timezone":      schema.JSON{Type: "string"},
							"coordinates":   schema.JSON{
								Type: "object",
								Properties: map[string]schema.JSON{
									"latitude":  schema.JSON{Type: "number"},
									"longitude": schema.JSON{Type: "number"},
								},
							},
						},
					},
					"autonomous_system": schema.JSON{
						Type:        "object",
						Description: "Autonomous System information",
						Properties: map[string]schema.JSON{
							"asn":         schema.JSON{Type: "integer"},
							"description": schema.JSON{Type: "string"},
							"name":        schema.JSON{Type: "string"},
							"country_code": schema.JSON{Type: "string"},
						},
					},
					"operating_system": schema.JSON{
						Type:        "object",
						Description: "Operating system information",
						Properties: map[string]schema.JSON{
							"vendor":  schema.JSON{Type: "string"},
							"product": schema.JSON{Type: "string"},
							"version": schema.JSON{Type: "string"},
						},
					},
					"last_updated_at": schema.JSON{
						Type:        "string",
						Description: "Timestamp of last update",
					},
				},
			},
		},
		"certificates": schema.JSON{
			Type:        "array",
			Description: "Certificate search results (when search_type is 'certificates')",
			Items: &schema.JSON{
				Type: "object",
				Properties: map[string]schema.JSON{
					"fingerprint_sha256": schema.JSON{
						Type:        "string",
						Description: "SHA256 fingerprint of the certificate",
					},
					"parsed": schema.JSON{
						Type:        "object",
						Description: "Parsed certificate data",
						Properties: map[string]schema.JSON{
							"subject": schema.JSON{
								Type: "object",
								Properties: map[string]schema.JSON{
									"common_name":         schema.JSON{Type: "array", Items: &schema.JSON{Type: "string"}},
									"organization":        schema.JSON{Type: "array", Items: &schema.JSON{Type: "string"}},
									"organizational_unit": schema.JSON{Type: "array", Items: &schema.JSON{Type: "string"}},
									"country":             schema.JSON{Type: "array", Items: &schema.JSON{Type: "string"}},
									"locality":            schema.JSON{Type: "array", Items: &schema.JSON{Type: "string"}},
								},
							},
							"issuer": schema.JSON{
								Type: "object",
								Properties: map[string]schema.JSON{
									"common_name":         schema.JSON{Type: "array", Items: &schema.JSON{Type: "string"}},
									"organization":        schema.JSON{Type: "array", Items: &schema.JSON{Type: "string"}},
									"country":             schema.JSON{Type: "array", Items: &schema.JSON{Type: "string"}},
								},
							},
							"subject_alternative_names": schema.JSON{
								Type:        "object",
								Description: "Subject Alternative Names",
								Properties: map[string]schema.JSON{
									"dns_names": schema.JSON{Type: "array", Items: &schema.JSON{Type: "string"}},
								},
							},
							"validity": schema.JSON{
								Type: "object",
								Properties: map[string]schema.JSON{
									"start": schema.JSON{Type: "string"},
									"end":   schema.JSON{Type: "string"},
								},
							},
						},
					},
					"names": schema.JSON{
						Type:        "array",
						Description: "All names from the certificate",
						Items: &schema.JSON{
							Type: "string",
						},
					},
				},
			},
		},
		"pages": schema.JSON{
			Type:        "integer",
			Description: "Number of pages retrieved",
		},
		"links": schema.JSON{
			Type:        "object",
			Description: "Pagination links",
			Properties: map[string]schema.JSON{
				"next": schema.JSON{Type: "string"},
				"prev": schema.JSON{Type: "string"},
			},
		},
	})
}

// ptrFloat64 is a helper to create a pointer to a float64 value
func ptrFloat64(f float64) *float64 {
	return &f
}
