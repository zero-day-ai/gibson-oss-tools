package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the katana tool
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"urls": schema.StringWithDesc("Target URLs (comma-separated)"),
		"depth": schema.JSON{
			Type:        "integer",
			Description: "Maximum depth to crawl (optional, default: 3)",
			Default:     3,
		},
		"concurrency": schema.JSON{
			Type:        "integer",
			Description: "Number of concurrent requests (optional, default: 10)",
			Default:     10,
		},
		"headless": schema.JSON{
			Type:        "boolean",
			Description: "Enable headless browser mode (optional, default: false)",
			Default:     false,
		},
		"js_rendering": schema.JSON{
			Type:        "boolean",
			Description: "Enable JavaScript rendering and crawling (optional, default: false)",
			Default:     false,
		},
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Execution timeout in seconds (optional)",
		},
		"extract_js": schema.JSON{
			Type:        "boolean",
			Description: "Extract JavaScript files (optional, default: false)",
			Default:     false,
		},
		"scope": schema.JSON{
			Type:        "string",
			Description: "Scope filter regex pattern (optional)",
		},
	}, "urls") // urls is required
}

// OutputSchema defines the output schema for the katana tool
func OutputSchema() schema.JSON {
	endpointSchema := schema.Object(map[string]schema.JSON{
		"url":          schema.StringWithDesc("Discovered URL"),
		"method":       schema.StringWithDesc("HTTP method"),
		"status_code":  schema.JSON{Type: "integer", Description: "HTTP status code"},
		"technologies": schema.JSON{Type: "array", Items: &schema.JSON{Type: "string"}, Description: "Detected technologies"},
	})

	endpointsArray := schema.Array(endpointSchema)
	endpointsArray.Description = "List of discovered endpoints"

	formSchema := schema.Object(map[string]schema.JSON{
		"url":       schema.StringWithDesc("URL containing the form"),
		"form_data": schema.JSON{Type: "object", Description: "Form data and fields"},
	})

	formsArray := schema.Array(formSchema)
	formsArray.Description = "List of discovered forms"

	jsFilesArray := schema.Array(schema.String())
	jsFilesArray.Description = "List of discovered JavaScript files"

	statusCodesSchema := schema.JSON{
		Type:        "object",
		Description: "Status code distribution (status code -> count)",
	}

	return schema.Object(map[string]schema.JSON{
		"endpoints":       endpointsArray,
		"total_endpoints": schema.JSON{Type: "integer", Description: "Total number of unique endpoints discovered"},
		"js_files":        jsFilesArray,
		"forms":           formsArray,
		"status_codes":    statusCodesSchema,
		"scan_time_ms":    schema.JSON{Type: "integer", Description: "Scan duration in milliseconds"},
		"depth":           schema.JSON{Type: "integer", Description: "Actual crawl depth used"},
		"headless":        schema.JSON{Type: "boolean", Description: "Whether headless mode was enabled"},
	})
}
