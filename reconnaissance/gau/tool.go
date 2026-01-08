package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	sdkinput "github.com/zero-day-ai/sdk/input"
	"github.com/zero-day-ai/sdk/toolerr"
	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/health"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "gau"
	ToolVersion     = "1.0.0"
	ToolDescription = "Fetch known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, and Common Crawl"
	BinaryName      = "gau"
)

// ToolImpl implements the gau tool logic
type ToolImpl struct{}

// NewTool creates a new gau tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"reconnaissance",
			"osint",
			"url-discovery",
			"wayback",
			"T1593", // Search Open Websites/Domains
		}).
		SetInputSchema(InputSchema()).
		SetOutputSchema(OutputSchema()).
		SetExecuteFunc((&ToolImpl{}).Execute)

	t, _ := tool.New(cfg)
	return &toolWithHealth{Tool: t, impl: &ToolImpl{}}
}

// toolWithHealth wraps the tool to add custom health checks
type toolWithHealth struct {
	tool.Tool
	impl *ToolImpl
}

func (t *toolWithHealth) Health(ctx context.Context) types.HealthStatus {
	return t.impl.Health(ctx)
}

// Execute runs the gau tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract input parameters
	domain := sdkinput.GetString(input, "domain", "")
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	providers := sdkinput.GetString(input, "providers", "wayback,commoncrawl,otx,urlscan")
	timeout := sdkinput.GetTimeout(input, "timeout", sdkinput.DefaultTimeout())
	includeSubdomains := sdkinput.GetBool(input, "include_subdomains", true)
	filterExtensions := sdkinput.GetString(input, "filter_extensions", "")
	maxRetries := sdkinput.GetInt(input, "max_retries", 5)

	// Build gau command arguments
	args := buildGauArgs(domain, providers, includeSubdomains, filterExtensions, maxRetries)

	// Execute gau command
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: timeout,
	})

	if err != nil {
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeExecutionFailed, err.Error()).WithCause(err)
	}

	// Parse gau output
	output, err := parseGauOutput(result.Stdout, domain)
	if err != nil {
		return nil, toolerr.New(ToolName, "parse", toolerr.ErrCodeParseError, err.Error()).WithCause(err)
	}

	// Add scan metadata
	output["scan_time_ms"] = int(time.Since(startTime).Milliseconds())
	output["providers"] = strings.Split(providers, ",")

	return output, nil
}

// Health checks if the gau binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// buildGauArgs constructs the command line arguments for gau
func buildGauArgs(domain, providers string, includeSubdomains bool, filterExtensions string, maxRetries int) []string {
	args := []string{
		domain,
		"--providers", providers,
		"--retries", fmt.Sprintf("%d", maxRetries),
	}

	// Add subdomain inclusion flag
	if includeSubdomains {
		args = append(args, "--subs")
	}

	// Add extension filtering if specified
	if filterExtensions != "" {
		// GAU uses --blacklist to exclude extensions
		args = append(args, "--blacklist", filterExtensions)
	}

	return args
}

// parseGauOutput parses the output from gau
func parseGauOutput(output []byte, domain string) (map[string]any, error) {
	lines := strings.Split(string(output), "\n")

	urls := []string{}
	uniqueURLs := make(map[string]bool)
	pathsByExtension := make(map[string]int)
	parameterNames := make(map[string]int)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Deduplicate URLs
		if !uniqueURLs[line] {
			uniqueURLs[line] = true
			urls = append(urls, line)

			// Extract file extension
			if ext := extractExtension(line); ext != "" {
				pathsByExtension[ext]++
			}

			// Extract parameter names
			params := extractParameters(line)
			for _, param := range params {
				parameterNames[param]++
			}
		}
	}

	// Convert parameter map to sorted list
	parameters := []map[string]any{}
	for param, count := range parameterNames {
		parameters = append(parameters, map[string]any{
			"name":  param,
			"count": count,
		})
	}

	return map[string]any{
		"urls":                urls,
		"total_urls":          len(urls),
		"paths_by_extension":  pathsByExtension,
		"parameters":          parameters,
		"unique_parameters":   len(parameterNames),
	}, nil
}

// extractExtension extracts the file extension from a URL
func extractExtension(url string) string {
	// Remove query string
	if idx := strings.Index(url, "?"); idx != -1 {
		url = url[:idx]
	}

	// Get the path component
	parts := strings.Split(url, "/")
	if len(parts) == 0 {
		return ""
	}

	filename := parts[len(parts)-1]

	// Extract extension
	if idx := strings.LastIndex(filename, "."); idx != -1 && idx < len(filename)-1 {
		return filename[idx+1:]
	}

	return ""
}

// extractParameters extracts query parameter names from a URL
func extractParameters(url string) []string {
	params := []string{}

	// Find query string
	if idx := strings.Index(url, "?"); idx != -1 {
		queryString := url[idx+1:]

		// Split by & to get individual parameters
		paramPairs := strings.Split(queryString, "&")
		for _, pair := range paramPairs {
			// Split by = to get parameter name
			if eqIdx := strings.Index(pair, "="); eqIdx != -1 {
				paramName := pair[:eqIdx]
				if paramName != "" {
					params = append(params, paramName)
				}
			} else if pair != "" {
				// Parameter without value
				params = append(params, pair)
			}
		}
	}

	return params
}
