package main

import (
	"context"
	"encoding/json"
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
	ToolName        = "katana"
	ToolVersion     = "1.0.0"
	ToolDescription = "Next-generation web crawling framework with headless browser support"
	BinaryName      = "katana"
)

// ToolImpl implements the katana tool logic
type ToolImpl struct{}

// NewTool creates a new katana tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"reconnaissance",
			"web-crawling",
			"endpoint-discovery",
			"T1595", // Active Scanning
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

// Execute runs the katana tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract input parameters
	urls := sdkinput.GetString(input, "urls", "")
	if urls == "" {
		return nil, fmt.Errorf("urls is required")
	}

	depth := sdkinput.GetInt(input, "depth", 3)
	concurrency := sdkinput.GetInt(input, "concurrency", 10)
	headless := sdkinput.GetBool(input, "headless", false)
	jsRendering := sdkinput.GetBool(input, "js_rendering", false)
	timeout := sdkinput.GetTimeout(input, "timeout", sdkinput.DefaultTimeout())
	extractJS := sdkinput.GetBool(input, "extract_js", false)
	scope := sdkinput.GetString(input, "scope", "")

	// Build katana command arguments
	args := buildKatanaArgs(urls, depth, concurrency, headless, jsRendering, extractJS, scope)

	// Execute katana command
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: timeout,
	})

	if err != nil {
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeExecutionFailed, err.Error()).WithCause(err)
	}

	// Parse katana output
	output, err := parseKatanaOutput(result.Stdout, urls)
	if err != nil {
		return nil, toolerr.New(ToolName, "parse", toolerr.ErrCodeParseError, err.Error()).WithCause(err)
	}

	// Add scan metadata
	output["scan_time_ms"] = int(time.Since(startTime).Milliseconds())
	output["depth"] = depth
	output["headless"] = headless

	return output, nil
}

// Health checks if the katana binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// buildKatanaArgs constructs the command line arguments for katana
func buildKatanaArgs(urls string, depth, concurrency int, headless, jsRendering, extractJS bool, scope string) []string {
	args := []string{
		"-u", urls,
		"-d", fmt.Sprintf("%d", depth),
		"-c", fmt.Sprintf("%d", concurrency),
		"-json", // Output in JSON format
		"-silent", // Silent mode
	}

	// Add headless mode if enabled
	if headless {
		args = append(args, "-headless")
	}

	// Add JavaScript rendering if enabled
	if jsRendering {
		args = append(args, "-js-crawl")
	}

	// Add JavaScript file extraction if enabled
	if extractJS {
		args = append(args, "-ef", "js")
	}

	// Add scope filter if specified
	if scope != "" {
		args = append(args, "-f", scope)
	}

	return args
}

// KatanaResult represents a single katana crawl result
type KatanaResult struct {
	Timestamp string                 `json:"timestamp"`
	Request   KatanaRequest          `json:"request"`
	Response  KatanaResponse         `json:"response"`
	Tag       map[string]interface{} `json:"tag,omitempty"`
}

// KatanaRequest represents the request information
type KatanaRequest struct {
	Method   string `json:"method"`
	Endpoint string `json:"endpoint"`
	Raw      string `json:"raw,omitempty"`
}

// KatanaResponse represents the response information
type KatanaResponse struct {
	StatusCode    int                    `json:"status_code"`
	Headers       map[string]string      `json:"headers,omitempty"`
	Body          string                 `json:"body,omitempty"`
	Technologies  []string               `json:"technologies,omitempty"`
	ResponseTime  string                 `json:"response_time,omitempty"`
}

// parseKatanaOutput parses the JSON output from katana
func parseKatanaOutput(output []byte, urls string) (map[string]any, error) {
	lines := strings.Split(string(output), "\n")

	endpoints := []map[string]any{}
	jsFiles := []string{}
	forms := []map[string]any{}
	uniqueEndpoints := make(map[string]bool)
	statusCodes := make(map[int]int)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var result KatanaResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			// Skip lines that can't be parsed
			continue
		}

		endpoint := result.Request.Endpoint

		// Track unique endpoints
		if !uniqueEndpoints[endpoint] {
			uniqueEndpoints[endpoint] = true

			endpointInfo := map[string]any{
				"url":         endpoint,
				"method":      result.Request.Method,
				"status_code": result.Response.StatusCode,
			}

			// Add technologies if available
			if len(result.Response.Technologies) > 0 {
				endpointInfo["technologies"] = result.Response.Technologies
			}

			endpoints = append(endpoints, endpointInfo)
		}

		// Track status codes
		statusCodes[result.Response.StatusCode]++

		// Extract JavaScript files
		if strings.HasSuffix(endpoint, ".js") {
			jsFiles = append(jsFiles, endpoint)
		}

		// Detect forms
		if result.Tag != nil {
			if formData, ok := result.Tag["form"]; ok && formData != nil {
				forms = append(forms, map[string]any{
					"url":      endpoint,
					"form_data": formData,
				})
			}
		}
	}

	return map[string]any{
		"endpoints":       endpoints,
		"total_endpoints": len(endpoints),
		"js_files":        jsFiles,
		"forms":           forms,
		"status_codes":    statusCodes,
	}, nil
}
