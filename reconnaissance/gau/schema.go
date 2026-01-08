package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the gau tool
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"domain": schema.StringWithDesc("Target domain to fetch URLs for"),
		"providers": schema.JSON{
			Type:        "string",
			Description: "Providers to use (comma-separated: wayback, commoncrawl, otx, urlscan) (optional, default: all)",
			Default:     "wayback,commoncrawl,otx,urlscan",
		},
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Execution timeout in seconds (optional)",
		},
		"include_subdomains": schema.JSON{
			Type:        "boolean",
			Description: "Include subdomains in the search (optional, default: true)",
			Default:     true,
		},
		"filter_extensions": schema.JSON{
			Type:        "string",
			Description: "File extensions to exclude (comma-separated, e.g., 'png,jpg,css') (optional)",
		},
		"max_retries": schema.JSON{
			Type:        "integer",
			Description: "Maximum number of retries for failed requests (optional, default: 5)",
			Default:     5,
		},
	}, "domain") // domain is required
}

// OutputSchema defines the output schema for the gau tool
func OutputSchema() schema.JSON {
	urlsArray := schema.Array(schema.String())
	urlsArray.Description = "List of discovered URLs"

	pathsByExtensionSchema := schema.JSON{
		Type:        "object",
		Description: "Distribution of URLs by file extension (extension -> count)",
	}

	parameterSchema := schema.Object(map[string]schema.JSON{
		"name":  schema.StringWithDesc("Parameter name"),
		"count": schema.JSON{Type: "integer", Description: "Number of times parameter appears"},
	})

	parametersArray := schema.Array(parameterSchema)
	parametersArray.Description = "List of discovered query parameters with usage counts"

	providersArray := schema.Array(schema.String())
	providersArray.Description = "List of providers used"

	return schema.Object(map[string]schema.JSON{
		"urls": urlsArray,
		"total_urls": schema.JSON{
			Type:        "integer",
			Description: "Total number of unique URLs discovered",
		},
		"paths_by_extension": pathsByExtensionSchema,
		"parameters":         parametersArray,
		"unique_parameters": schema.JSON{
			Type:        "integer",
			Description: "Total number of unique query parameters",
		},
		"scan_time_ms": schema.JSON{
			Type:        "integer",
			Description: "Scan duration in milliseconds",
		},
		"providers": providersArray,
	})
}
