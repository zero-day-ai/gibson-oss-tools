package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "censys"
	ToolVersion     = "1.0.0"
	ToolDescription = "Search Censys for hosts, certificates, and internet-wide scan data"
	BinaryName      = "censys"
)

// ToolImpl implements the Censys tool
type ToolImpl struct{}

// NewTool creates a new Censys tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"reconnaissance",
			"osint",
			"internet-scanning",
			"certificates",
			"T1596", // Search Open Technical Databases
			"TA0043", // Reconnaissance
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

// Execute runs the Censys search
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	// Extract input parameters
	searchType := "hosts"
	if st, ok := input["search_type"].(string); ok {
		searchType = st
	}

	query, _ := input["query"].(string)
	apiID, _ := input["api_id"].(string)
	apiSecret, _ := input["api_secret"].(string)

	// Extract optional parameters
	pages := 1
	if p, ok := input["pages"].(float64); ok {
		pages = int(p)
	} else if p, ok := input["pages"].(int); ok {
		pages = p
	}

	perPage := 100
	if pp, ok := input["per_page"].(float64); ok {
		perPage = int(pp)
	} else if pp, ok := input["per_page"].(int); ok {
		perPage = pp
	}

	// Extract optional fields
	var fields []string
	if fieldsRaw, ok := input["fields"].([]any); ok {
		for _, f := range fieldsRaw {
			if fieldStr, ok := f.(string); ok {
				fields = append(fields, fieldStr)
			}
		}
	}

	// Build censys command arguments
	// censys CLI: censys search <index> <query> [flags]
	var args []string

	switch searchType {
	case "hosts":
		args = []string{"search", "hosts", query}
	case "certificates":
		args = []string{"search", "certificates", query}
	default:
		return nil, fmt.Errorf("invalid search_type: %s (must be 'hosts' or 'certificates')", searchType)
	}

	// Add pages and per-page options
	args = append(args, "--pages", strconv.Itoa(pages))
	args = append(args, "--per-page", strconv.Itoa(perPage))

	// Add fields if specified
	if len(fields) > 0 {
		// Censys CLI uses --fields flag with comma-separated values
		args = append(args, "--fields", strings.Join(fields, ","))
	}

	// Set API credentials in environment
	cmd := exec.CommandContext(ctx, BinaryName, args...)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("CENSYS_API_ID=%s", apiID),
		fmt.Sprintf("CENSYS_API_SECRET=%s", apiSecret),
	)

	// Execute command
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("censys execution timeout or cancelled: %w", ctx.Err())
		}
		return nil, fmt.Errorf("censys execution failed: %w (stderr: %s)", err, stderr.String())
	}

	// Parse the output
	results, err := parseOutput(stdout.Bytes(), searchType)
	if err != nil {
		return nil, fmt.Errorf("failed to parse censys output: %w", err)
	}

	return results, nil
}

// parseOutput parses the Censys CLI output
// The censys CLI can return JSON output
func parseOutput(output []byte, searchType string) (map[string]any, error) {
	// Try to parse as JSON first
	var jsonOutput map[string]any
	if err := json.Unmarshal(output, &jsonOutput); err != nil {
		// If JSON parsing fails, try to parse as newline-delimited JSON
		return parseNDJSON(output, searchType)
	}

	// Extract results based on search type
	var hosts []map[string]any
	var certificates []map[string]any
	totalResults := 0
	returnedResults := 0

	if searchType == "hosts" {
		if hits, ok := jsonOutput["hits"].([]any); ok {
			returnedResults = len(hits)
			for _, hit := range hits {
				if hostMap, ok := hit.(map[string]any); ok {
					hosts = append(hosts, normalizeHost(hostMap))
				}
			}
		}

		// Check for result metadata
		if result, ok := jsonOutput["result"].(map[string]any); ok {
			if hits, ok := result["hits"].([]any); ok {
				returnedResults = len(hits)
				for _, hit := range hits {
					if hostMap, ok := hit.(map[string]any); ok {
						hosts = append(hosts, normalizeHost(hostMap))
					}
				}
			}

			if total, ok := result["total"].(float64); ok {
				totalResults = int(total)
			}
		}

		if total, ok := jsonOutput["total"].(float64); ok {
			totalResults = int(total)
		}
	} else if searchType == "certificates" {
		if hits, ok := jsonOutput["hits"].([]any); ok {
			returnedResults = len(hits)
			for _, hit := range hits {
				if certMap, ok := hit.(map[string]any); ok {
					certificates = append(certificates, normalizeCertificate(certMap))
				}
			}
		}

		// Check for result metadata
		if result, ok := jsonOutput["result"].(map[string]any); ok {
			if hits, ok := result["hits"].([]any); ok {
				returnedResults = len(hits)
				for _, hit := range hits {
					if certMap, ok := hit.(map[string]any); ok {
						certificates = append(certificates, normalizeCertificate(certMap))
					}
				}
			}

			if total, ok := result["total"].(float64); ok {
				totalResults = int(total)
			}
		}

		if total, ok := jsonOutput["total"].(float64); ok {
			totalResults = int(total)
		}
	}

	// Extract pagination links
	links := map[string]any{}
	if linksData, ok := jsonOutput["links"].(map[string]any); ok {
		links = linksData
	}

	return map[string]any{
		"total_results":    totalResults,
		"returned_results": returnedResults,
		"hosts":            hosts,
		"certificates":     certificates,
		"pages":            1,
		"links":            links,
	}, nil
}

// parseNDJSON parses newline-delimited JSON output
func parseNDJSON(output []byte, searchType string) (map[string]any, error) {
	lines := bytes.Split(output, []byte("\n"))

	var hosts []map[string]any
	var certificates []map[string]any

	for _, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		var item map[string]any
		if err := json.Unmarshal(line, &item); err != nil {
			continue // Skip invalid JSON lines
		}

		if searchType == "hosts" {
			hosts = append(hosts, normalizeHost(item))
		} else if searchType == "certificates" {
			certificates = append(certificates, normalizeCertificate(item))
		}
	}

	returnedResults := len(hosts) + len(certificates)

	return map[string]any{
		"total_results":    returnedResults,
		"returned_results": returnedResults,
		"hosts":            hosts,
		"certificates":     certificates,
		"pages":            1,
		"links":            map[string]any{},
	}, nil
}

// normalizeHost normalizes a host result to the expected schema
func normalizeHost(hostData map[string]any) map[string]any {
	normalized := map[string]any{
		"ip":                 hostData["ip"],
		"services":           []map[string]any{},
		"location":           map[string]any{},
		"autonomous_system":  map[string]any{},
		"operating_system":   map[string]any{},
		"last_updated_at":    hostData["last_updated_at"],
	}

	// Extract services
	if services, ok := hostData["services"].([]any); ok {
		svcList := []map[string]any{}
		for _, svc := range services {
			if svcMap, ok := svc.(map[string]any); ok {
				svcList = append(svcList, svcMap)
			}
		}
		normalized["services"] = svcList
	}

	// Extract location
	if location, ok := hostData["location"].(map[string]any); ok {
		normalized["location"] = location
	}

	// Extract autonomous system
	if as, ok := hostData["autonomous_system"].(map[string]any); ok {
		normalized["autonomous_system"] = as
	}

	// Extract operating system
	if os, ok := hostData["operating_system"].(map[string]any); ok {
		normalized["operating_system"] = os
	}

	return normalized
}

// normalizeCertificate normalizes a certificate result to the expected schema
func normalizeCertificate(certData map[string]any) map[string]any {
	normalized := map[string]any{
		"fingerprint_sha256": certData["fingerprint_sha256"],
		"parsed":             map[string]any{},
		"names":              []string{},
	}

	// Extract parsed certificate data
	if parsed, ok := certData["parsed"].(map[string]any); ok {
		normalized["parsed"] = parsed
	}

	// Extract names
	if names, ok := certData["names"].([]any); ok {
		nameList := []string{}
		for _, name := range names {
			if nameStr, ok := name.(string); ok {
				nameList = append(nameList, nameStr)
			}
		}
		normalized["names"] = nameList
	}

	return normalized
}

// Health checks if the Censys CLI is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	// Check if binary exists
	if _, err := exec.LookPath(BinaryName); err != nil {
		return types.HealthStatus{
			Status:  "unhealthy",
			Message: fmt.Sprintf("censys binary not found in PATH: %v", err),
		}
	}

	// Check if API credentials are configured
	apiID := os.Getenv("CENSYS_API_ID")
	apiSecret := os.Getenv("CENSYS_API_SECRET")

	if apiID != "" && apiSecret != "" {
		// Try to verify credentials with a simple command
		cmd := exec.CommandContext(ctx, BinaryName, "account")
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("CENSYS_API_ID=%s", apiID),
			fmt.Sprintf("CENSYS_API_SECRET=%s", apiSecret),
		)

		if err := cmd.Run(); err != nil {
			return types.HealthStatus{
				Status:  "degraded",
				Message: "censys binary found but API credentials may be invalid",
			}
		}
	}

	return types.HealthStatus{
		Status:  "healthy",
		Message: "censys binary is available",
	}
}
