package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "cloud_enum"
	ToolVersion     = "1.0.0"
	ToolDescription = "Enumerate cloud storage buckets and resources across AWS, Azure, and GCP"
	BinaryName      = "cloud_enum"
)

// ToolImpl implements the cloud_enum tool
type ToolImpl struct{}

// NewTool creates a new cloud_enum tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"reconnaissance",
			"cloud",
			"enumeration",
			"aws",
			"azure",
			"gcp",
			"T1580", // Cloud Infrastructure Discovery
			"T1619", // Cloud Storage Object Discovery
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

// CloudResource represents a discovered cloud resource
type CloudResource struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	URL    string `json:"url"`
	Access string `json:"access"`
	Exists bool   `json:"exists"`
}

// Execute runs the cloud_enum enumeration
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract input parameters
	keyword, _ := input["keyword"].(string)

	// Extract optional providers
	var providers []string
	if providersRaw, ok := input["providers"].([]any); ok && len(providersRaw) > 0 {
		for _, p := range providersRaw {
			if provStr, ok := p.(string); ok {
				providers = append(providers, provStr)
			}
		}
	}

	// Extract optional parameters
	brute := false
	if b, ok := input["brute"].(bool); ok {
		brute = b
	}

	wordlist := ""
	if w, ok := input["wordlist"].(string); ok {
		wordlist = w
	}

	threads := 5
	if t, ok := input["threads"].(float64); ok {
		threads = int(t)
	} else if t, ok := input["threads"].(int); ok {
		threads = t
	}

	timeout := 10
	if t, ok := input["timeout"].(float64); ok {
		timeout = int(t)
	} else if t, ok := input["timeout"].(int); ok {
		timeout = t
	}

	// Build cloud_enum command arguments
	args := []string{"-k", keyword, "-t", strconv.Itoa(threads), "--timeout", strconv.Itoa(timeout)}

	// Add provider selection if specified
	if len(providers) > 0 {
		// cloud_enum uses flags like --aws, --azure, --gcp
		for _, provider := range providers {
			switch provider {
			case "aws":
				args = append(args, "--aws")
			case "azure":
				args = append(args, "--azure")
			case "gcp":
				args = append(args, "--gcp")
			}
		}
	}

	// Add brute-force mode if enabled
	if brute {
		args = append(args, "--brute")
		if wordlist != "" {
			args = append(args, "-w", wordlist)
		}
	}

	// cloud_enum typically outputs to a directory, let's use a temp dir
	// and capture stdout for JSON output if supported
	args = append(args, "--disable-status")

	// Execute command
	cmd := exec.CommandContext(ctx, BinaryName, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// Check if it's a timeout or context cancellation
		if ctx.Err() != nil {
			return nil, fmt.Errorf("cloud_enum execution timeout or cancelled: %w", ctx.Err())
		}
		return nil, fmt.Errorf("cloud_enum execution failed: %w (stderr: %s)", err, stderr.String())
	}

	// Parse the output
	results, err := parseOutput(stdout.Bytes(), stderr.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to parse cloud_enum output: %w", err)
	}

	// Add execution time
	results["execution_time_seconds"] = time.Since(startTime).Seconds()

	return results, nil
}

// parseOutput parses the cloud_enum output
// cloud_enum typically outputs text format, we need to parse it
func parseOutput(stdout, stderr []byte) (map[string]any, error) {
	awsResources := []map[string]any{}
	azureResources := []map[string]any{}
	gcpResources := []map[string]any{}

	// Try to parse as JSON first (if cloud_enum supports JSON output)
	var jsonOutput map[string]any
	if err := json.Unmarshal(stdout, &jsonOutput); err == nil {
		// JSON parsing succeeded, use it directly
		if aws, ok := jsonOutput["aws"].([]any); ok {
			for _, item := range aws {
				if m, ok := item.(map[string]any); ok {
					awsResources = append(awsResources, m)
				}
			}
		}
		if azure, ok := jsonOutput["azure"].([]any); ok {
			for _, item := range azure {
				if m, ok := item.(map[string]any); ok {
					azureResources = append(azureResources, m)
				}
			}
		}
		if gcp, ok := jsonOutput["gcp"].([]any); ok {
			for _, item := range gcp {
				if m, ok := item.(map[string]any); ok {
					gcpResources = append(gcpResources, m)
				}
			}
		}
	} else {
		// Parse text output
		lines := strings.Split(string(stdout), "\n")

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			// Parse different cloud provider resource formats
			// cloud_enum typically outputs like:
			// [+] Found AWS S3 bucket: bucket-name (public)
			// [+] Found Azure Blob: storage-account (authenticated)

			resource := parseResourceLine(line)
			if resource != nil {
				switch resource.Type {
				case "s3", "cloudfront", "lambda", "apigateway":
					awsResources = append(awsResources, map[string]any{
						"type":   resource.Type,
						"name":   resource.Name,
						"url":    resource.URL,
						"access": resource.Access,
						"exists": resource.Exists,
					})
				case "blob", "function", "webapp", "database":
					azureResources = append(azureResources, map[string]any{
						"type":   resource.Type,
						"name":   resource.Name,
						"url":    resource.URL,
						"access": resource.Access,
						"exists": resource.Exists,
					})
				case "storage", "cloudfunction", "cloudrun", "appengine":
					gcpResources = append(gcpResources, map[string]any{
						"type":   resource.Type,
						"name":   resource.Name,
						"url":    resource.URL,
						"access": resource.Access,
						"exists": resource.Exists,
					})
				}
			}
		}
	}

	totalFound := len(awsResources) + len(azureResources) + len(gcpResources)

	return map[string]any{
		"total_found":     totalFound,
		"aws_resources":   awsResources,
		"azure_resources": azureResources,
		"gcp_resources":   gcpResources,
	}, nil
}

// parseResourceLine parses a single line of cloud_enum output
func parseResourceLine(line string) *CloudResource {
	// This is a simplified parser for cloud_enum output
	// Actual parsing would depend on cloud_enum's exact output format

	if !strings.Contains(line, "Found") && !strings.Contains(line, "[+]") {
		return nil
	}

	resource := &CloudResource{
		Exists: true,
		Access: "unknown",
	}

	// Extract access level
	if strings.Contains(line, "(public)") {
		resource.Access = "public"
	} else if strings.Contains(line, "(authenticated)") {
		resource.Access = "authenticated"
	} else if strings.Contains(line, "(private)") {
		resource.Access = "private"
	} else if strings.Contains(line, "(error)") {
		resource.Access = "error"
	}

	// Determine resource type and provider
	lowerLine := strings.ToLower(line)

	// AWS resources
	if strings.Contains(lowerLine, "s3") {
		resource.Type = "s3"
		resource.Name = extractResourceName(line)
		resource.URL = fmt.Sprintf("https://%s.s3.amazonaws.com", resource.Name)
	} else if strings.Contains(lowerLine, "cloudfront") {
		resource.Type = "cloudfront"
		resource.Name = extractResourceName(line)
		resource.URL = fmt.Sprintf("https://%s.cloudfront.net", resource.Name)
	} else if strings.Contains(lowerLine, "lambda") {
		resource.Type = "lambda"
		resource.Name = extractResourceName(line)
		resource.URL = resource.Name
	} else if strings.Contains(lowerLine, "apigateway") || strings.Contains(lowerLine, "api gateway") {
		resource.Type = "apigateway"
		resource.Name = extractResourceName(line)
		resource.URL = resource.Name
	}

	// Azure resources
	if strings.Contains(lowerLine, "blob") {
		resource.Type = "blob"
		resource.Name = extractResourceName(line)
		resource.URL = fmt.Sprintf("https://%s.blob.core.windows.net", resource.Name)
	} else if strings.Contains(lowerLine, "function") {
		resource.Type = "function"
		resource.Name = extractResourceName(line)
		resource.URL = fmt.Sprintf("https://%s.azurewebsites.net", resource.Name)
	} else if strings.Contains(lowerLine, "webapp") || strings.Contains(lowerLine, "web app") {
		resource.Type = "webapp"
		resource.Name = extractResourceName(line)
		resource.URL = fmt.Sprintf("https://%s.azurewebsites.net", resource.Name)
	} else if strings.Contains(lowerLine, "database") {
		resource.Type = "database"
		resource.Name = extractResourceName(line)
		resource.URL = resource.Name
	}

	// GCP resources
	if strings.Contains(lowerLine, "storage") && strings.Contains(lowerLine, "gcp") {
		resource.Type = "storage"
		resource.Name = extractResourceName(line)
		resource.URL = fmt.Sprintf("https://storage.googleapis.com/%s", resource.Name)
	} else if strings.Contains(lowerLine, "cloud function") {
		resource.Type = "cloudfunction"
		resource.Name = extractResourceName(line)
		resource.URL = resource.Name
	} else if strings.Contains(lowerLine, "cloud run") {
		resource.Type = "cloudrun"
		resource.Name = extractResourceName(line)
		resource.URL = resource.Name
	} else if strings.Contains(lowerLine, "app engine") {
		resource.Type = "appengine"
		resource.Name = extractResourceName(line)
		resource.URL = resource.Name
	}

	if resource.Type == "" {
		return nil
	}

	return resource
}

// extractResourceName extracts the resource name from a cloud_enum output line
func extractResourceName(line string) string {
	// Remove common prefixes
	line = strings.TrimPrefix(line, "[+]")
	line = strings.TrimSpace(line)

	// Extract the name between ":" and "("
	if idx := strings.Index(line, ":"); idx != -1 {
		line = line[idx+1:]
	}
	if idx := strings.Index(line, "("); idx != -1 {
		line = line[:idx]
	}

	return strings.TrimSpace(line)
}

// Health checks if the cloud_enum binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	// Check if binary exists
	if _, err := exec.LookPath(BinaryName); err != nil {
		return types.HealthStatus{
			Status:  "unhealthy",
			Message: fmt.Sprintf("cloud_enum binary not found in PATH: %v", err),
		}
	}

	// Try to run with --help to verify it's working
	cmd := exec.CommandContext(ctx, BinaryName, "--help")
	if err := cmd.Run(); err != nil {
		return types.HealthStatus{
			Status:  "degraded",
			Message: "cloud_enum binary found but may not be functioning correctly",
		}
	}

	return types.HealthStatus{
		Status:  "healthy",
		Message: "cloud_enum binary is available and functioning",
	}
}
