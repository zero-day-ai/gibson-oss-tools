package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "shodan"
	ToolVersion     = "1.1.0"
	ToolDescription = "Search Shodan for exposed services, perform host lookups, and extract vulnerability data"
	BinaryName      = "shodan"
)

// ToolImpl implements the Shodan tool
type ToolImpl struct{}

// NewTool creates a new Shodan tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"reconnaissance",
			"osint",
			"internet-scanning",
			"T1596",        // Search Open Technical Databases
			"TA0043",       // Reconnaissance
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

// Execute runs the Shodan search query or host lookup
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	// Extract input parameters
	mode := "search"
	if m, ok := input["mode"].(string); ok {
		mode = m
	}

	query, _ := input["query"].(string)
	apiKey, _ := input["api_key"].(string)

	// Extract optional limit parameter
	limit := 100
	if l, ok := input["limit"].(float64); ok {
		limit = int(l)
	} else if l, ok := input["limit"].(int); ok {
		limit = l
	}

	// Extract optional facets
	var facets []string
	if facetsRaw, ok := input["facets"].([]any); ok {
		for _, f := range facetsRaw {
			if facetStr, ok := f.(string); ok {
				facets = append(facets, facetStr)
			}
		}
	}

	// Extract history flag
	history := false
	if h, ok := input["history"].(bool); ok {
		history = h
	}

	var args []string
	var isHostMode bool

	// Build command based on mode
	if mode == "host" {
		// Host lookup mode - provides detailed information about a specific host
		isHostMode = true
		args = []string{"host", query}
		if history {
			args = append(args, "--history")
		}
	} else {
		// Search mode - general search query
		isHostMode = false
		args = []string{"search", "--fields", "ip_str,port,org,isp,os,product,version,data,vulns,location,tags,hostnames,domains", query}

		// Add limit
		if limit > 0 {
			args = append(args, "--limit", strconv.Itoa(limit))
		}

		// Add facets if specified
		if len(facets) > 0 {
			for _, facet := range facets {
				args = append(args, "--facets", facet)
			}
		}
	}

	// Set API key in environment
	cmd := exec.CommandContext(ctx, BinaryName, args...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("SHODAN_API_KEY=%s", apiKey))

	// Execute command
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("shodan execution failed: %w (output: %s)", err, string(output))
	}

	// Parse the output
	var results map[string]any
	if isHostMode {
		results, err = parseHostOutput(output)
	} else {
		results, err = parseOutput(output)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse shodan output: %w", err)
	}

	return results, nil
}

// parseOutput parses the Shodan CLI output
// The shodan CLI returns newline-delimited JSON when --fields is used
func parseOutput(output []byte) (map[string]any, error) {
	// The shodan CLI with --fields returns tab-separated values by default
	// We need to parse this into our structured format

	// For now, we'll return a simplified structure
	// In a real implementation, we would parse the actual output format

	// Try to parse as JSON lines first (in case shodan supports JSON output in future)
	var results []map[string]any
	lines := splitLines(output)

	for _, line := range lines {
		if len(line) == 0 {
			continue
		}

		var result map[string]any
		if err := json.Unmarshal(line, &result); err != nil {
			// If not JSON, parse as tab-separated values
			// This is a simplified parsing - real implementation would be more robust
			result = parseTabSeparated(line)
		}
		results = append(results, result)
	}

	return map[string]any{
		"total":              len(results),
		"results":            results,
		"facets":             map[string]any{},
		"query_credits_used": 1, // Estimate
	}, nil
}

// splitLines splits output into lines
func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}

// parseTabSeparated parses a tab-separated line
func parseTabSeparated(line []byte) map[string]any {
	// This is a simplified parser
	// The actual format depends on the --fields parameter order
	fields := splitByTab(line)

	result := map[string]any{
		"banner": string(line), // Store raw data
	}

	// Try to extract basic fields
	if len(fields) > 0 {
		result["ip"] = string(fields[0])
	}
	if len(fields) > 1 {
		if port, err := strconv.Atoi(string(fields[1])); err == nil {
			result["port"] = port
		}
	}
	if len(fields) > 2 {
		result["org"] = string(fields[2])
	}
	if len(fields) > 3 {
		result["isp"] = string(fields[3])
	}
	if len(fields) > 4 {
		result["os"] = string(fields[4])
	}
	if len(fields) > 5 {
		result["product"] = string(fields[5])
	}
	if len(fields) > 6 {
		result["version"] = string(fields[6])
	}

	// Initialize empty arrays and objects
	result["vulns"] = []string{}
	result["vulnerabilities"] = []map[string]any{}
	result["location"] = map[string]any{}
	result["tags"] = []string{}
	result["hostnames"] = []string{}
	result["domains"] = []string{}
	result["screenshot"] = map[string]any{}

	return result
}

// parseHostOutput parses the output from 'shodan host' command
// The host command returns JSON data about a specific host
func parseHostOutput(output []byte) (map[string]any, error) {
	// The 'shodan host' command returns JSON output
	var hostData map[string]any
	if err := json.Unmarshal(output, &hostData); err != nil {
		return nil, fmt.Errorf("failed to parse host JSON: %w", err)
	}

	// Extract and structure the data
	results := []map[string]any{}

	// The host data contains detailed information
	result := map[string]any{
		"ip":               hostData["ip_str"],
		"org":              hostData["org"],
		"isp":              hostData["isp"],
		"os":               hostData["os"],
		"hostnames":        hostData["hostnames"],
		"domains":          hostData["domains"],
		"tags":             hostData["tags"],
		"vulns":            []string{},
		"vulnerabilities":  []map[string]any{},
		"location":         map[string]any{},
		"screenshot":       map[string]any{},
	}

	// Extract location data
	if loc, ok := hostData["location"].(map[string]any); ok {
		result["location"] = map[string]any{
			"country_code": loc["country_code"],
			"country_name": loc["country_name"],
			"city":         loc["city"],
			"latitude":     loc["latitude"],
			"longitude":    loc["longitude"],
		}
	}

	// Extract vulnerability data
	if vulns, ok := hostData["vulns"].([]any); ok {
		vulnList := []string{}
		vulnDetails := []map[string]any{}

		for _, v := range vulns {
			if vulnStr, ok := v.(string); ok {
				vulnList = append(vulnList, vulnStr)
			} else if vulnMap, ok := v.(map[string]any); ok {
				// Detailed vulnerability object
				detail := map[string]any{
					"cve":      vulnMap["cve"],
					"cvss":     vulnMap["cvss"],
					"summary":  vulnMap["summary"],
					"verified": vulnMap["verified"],
				}
				vulnDetails = append(vulnDetails, detail)

				// Also add to simple list
				if cve, ok := vulnMap["cve"].(string); ok {
					vulnList = append(vulnList, cve)
				}
			}
		}

		result["vulns"] = vulnList
		result["vulnerabilities"] = vulnDetails
	}

	// Extract screenshot data if available
	if screenshot, ok := hostData["screenshot"].(map[string]any); ok {
		result["screenshot"] = map[string]any{
			"data":   screenshot["data"],
			"labels": screenshot["labels"],
		}
	}

	// Extract service/port information from the 'data' field
	if dataArray, ok := hostData["data"].([]any); ok {
		for _, item := range dataArray {
			if serviceData, ok := item.(map[string]any); ok {
				serviceResult := map[string]any{
					"ip":               result["ip"],
					"port":             serviceData["port"],
					"org":              result["org"],
					"isp":              result["isp"],
					"os":               result["os"],
					"product":          serviceData["product"],
					"version":          serviceData["version"],
					"banner":           serviceData["data"],
					"vulns":            result["vulns"],
					"vulnerabilities":  result["vulnerabilities"],
					"location":         result["location"],
					"screenshot":       result["screenshot"],
					"tags":             result["tags"],
					"hostnames":        result["hostnames"],
					"domains":          result["domains"],
				}
				results = append(results, serviceResult)
			}
		}
	}

	// If no service data was found, return the host info as a single result
	if len(results) == 0 {
		results = append(results, result)
	}

	return map[string]any{
		"total":              len(results),
		"results":            results,
		"facets":             map[string]any{},
		"query_credits_used": 1,
	}, nil
}

// splitByTab splits a byte slice by tab characters
func splitByTab(data []byte) [][]byte {
	var fields [][]byte
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\t' {
			fields = append(fields, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		fields = append(fields, data[start:])
	}
	return fields
}

// Health checks if the Shodan CLI is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	// Check if binary exists
	if _, err := exec.LookPath(BinaryName); err != nil {
		return types.HealthStatus{
			Status:  "unhealthy",
			Message: fmt.Sprintf("shodan binary not found in PATH: %v", err),
		}
	}

	// Check if API key is configured (if available in environment)
	if apiKey := os.Getenv("SHODAN_API_KEY"); apiKey != "" {
		// Try to verify API key by running a simple command
		cmd := exec.CommandContext(ctx, BinaryName, "info")
		cmd.Env = append(os.Environ(), fmt.Sprintf("SHODAN_API_KEY=%s", apiKey))

		if err := cmd.Run(); err != nil {
			return types.HealthStatus{
				Status:  "degraded",
				Message: "shodan binary found but API key may be invalid",
			}
		}
	}

	return types.HealthStatus{
		Status:  "healthy",
		Message: "shodan binary is available",
	}
}
