package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the feroxbuster tool
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"url":      schema.StringWithDesc("Target URL to fuzz"),
		"wordlist": schema.StringWithDesc("Path to wordlist file for fuzzing"),
		"extensions": schema.JSON{
			Type:        "string",
			Description: "File extensions to append (comma-separated, e.g., 'php,html,js') (optional)",
		},
		"threads": schema.JSON{
			Type:        "integer",
			Description: "Number of concurrent threads (optional, default: 50)",
			Default:     50,
		},
		"depth": schema.JSON{
			Type:        "integer",
			Description: "Maximum recursion depth (optional, default: 4)",
			Default:     4,
		},
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Execution timeout in seconds (optional)",
		},
		"status_codes": schema.JSON{
			Type:        "string",
			Description: "Status codes to include (comma-separated) (optional, default: '200,204,301,302,307,308,401,403,405')",
			Default:     "200,204,301,302,307,308,401,403,405",
		},
		"filter_size": schema.JSON{
			Type:        "string",
			Description: "Filter responses by size (e.g., '1234' or '100-200') (optional)",
		},
	}, "url", "wordlist") // url and wordlist are required
}

// OutputSchema defines the output schema for the feroxbuster tool
func OutputSchema() schema.JSON {
	pathSchema := schema.Object(map[string]schema.JSON{
		"path":           schema.StringWithDesc("Discovered path"),
		"url":            schema.StringWithDesc("Full URL"),
		"status_code":    schema.JSON{Type: "integer", Description: "HTTP status code"},
		"method":         schema.StringWithDesc("HTTP method used"),
		"content_length": schema.JSON{Type: "integer", Description: "Response content length"},
		"line_count":     schema.JSON{Type: "integer", Description: "Number of lines in response"},
		"word_count":     schema.JSON{Type: "integer", Description: "Number of words in response"},
	})

	pathsArray := schema.Array(pathSchema)
	pathsArray.Description = "List of discovered paths"

	directoriesArray := schema.Array(schema.String())
	directoriesArray.Description = "List of discovered directories"

	filesArray := schema.Array(schema.String())
	filesArray.Description = "List of discovered files"

	statusCodesSchema := schema.JSON{
		Type:        "object",
		Description: "Status code distribution (status code -> count)",
	}

	return schema.Object(map[string]schema.JSON{
		"paths":        pathsArray,
		"total_paths":  schema.JSON{Type: "integer", Description: "Total number of paths discovered"},
		"directories":  directoriesArray,
		"files":        filesArray,
		"status_codes": statusCodesSchema,
		"scan_time_ms": schema.JSON{Type: "integer", Description: "Scan duration in milliseconds"},
		"threads":      schema.JSON{Type: "integer", Description: "Number of threads used"},
		"depth":        schema.JSON{Type: "integer", Description: "Recursion depth used"},
	})
}
