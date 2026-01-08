package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the cloud_enum tool
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"keyword": schema.JSON{
			Type:        "string",
			Description: "Keyword to search for (e.g., company name, domain)",
		},
		"providers": schema.JSON{
			Type:        "array",
			Description: "Cloud providers to enumerate (aws, azure, gcp). Empty array searches all providers.",
			Items: &schema.JSON{
				Type: "string",
				Enum: []any{"aws", "azure", "gcp"},
			},
			Default: []any{},
		},
		"brute": schema.JSON{
			Type:        "boolean",
			Description: "Enable brute-force enumeration (default: false)",
			Default:     false,
		},
		"wordlist": schema.JSON{
			Type:        "string",
			Description: "Path to custom wordlist file for brute-force mode",
		},
		"threads": schema.JSON{
			Type:        "integer",
			Description: "Number of concurrent threads (default: 5)",
			Default:     5,
			Minimum:     ptrFloat64(1),
			Maximum:     ptrFloat64(100),
		},
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Timeout in seconds for cloud requests (default: 10)",
			Default:     10,
			Minimum:     ptrFloat64(1),
			Maximum:     ptrFloat64(300),
		},
	}, "keyword") // keyword is required
}

// OutputSchema defines the output schema for the cloud_enum tool
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"total_found": schema.JSON{
			Type:        "integer",
			Description: "Total number of discovered cloud resources",
		},
		"aws_resources": schema.JSON{
			Type:        "array",
			Description: "Discovered AWS resources",
			Items: &schema.JSON{
				Type: "object",
				Properties: map[string]schema.JSON{
					"type": schema.JSON{
						Type:        "string",
						Description: "Resource type (s3, cloudfront, lambda, etc.)",
					},
					"name": schema.JSON{
						Type:        "string",
						Description: "Resource name/identifier",
					},
					"url": schema.JSON{
						Type:        "string",
						Description: "Full URL to the resource",
					},
					"access": schema.JSON{
						Type:        "string",
						Description: "Access level (public, authenticated, private, error)",
					},
					"exists": schema.JSON{
						Type:        "boolean",
						Description: "Whether the resource exists",
					},
				},
			},
		},
		"azure_resources": schema.JSON{
			Type:        "array",
			Description: "Discovered Azure resources",
			Items: &schema.JSON{
				Type: "object",
				Properties: map[string]schema.JSON{
					"type": schema.JSON{
						Type:        "string",
						Description: "Resource type (blob, function, webapp, etc.)",
					},
					"name": schema.JSON{
						Type:        "string",
						Description: "Resource name/identifier",
					},
					"url": schema.JSON{
						Type:        "string",
						Description: "Full URL to the resource",
					},
					"access": schema.JSON{
						Type:        "string",
						Description: "Access level (public, authenticated, private, error)",
					},
					"exists": schema.JSON{
						Type:        "boolean",
						Description: "Whether the resource exists",
					},
				},
			},
		},
		"gcp_resources": schema.JSON{
			Type:        "array",
			Description: "Discovered GCP resources",
			Items: &schema.JSON{
				Type: "object",
				Properties: map[string]schema.JSON{
					"type": schema.JSON{
						Type:        "string",
						Description: "Resource type (storage, function, cloudrun, etc.)",
					},
					"name": schema.JSON{
						Type:        "string",
						Description: "Resource name/identifier",
					},
					"url": schema.JSON{
						Type:        "string",
						Description: "Full URL to the resource",
					},
					"access": schema.JSON{
						Type:        "string",
						Description: "Access level (public, authenticated, private, error)",
					},
					"exists": schema.JSON{
						Type:        "boolean",
						Description: "Whether the resource exists",
					},
				},
			},
		},
		"execution_time_seconds": schema.JSON{
			Type:        "number",
			Description: "Total execution time in seconds",
		},
	})
}

// ptrFloat64 is a helper to create a pointer to a float64 value
func ptrFloat64(f float64) *float64 {
	return &f
}
