package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	sdkinput "github.com/zero-day-ai/sdk/input"
	"github.com/zero-day-ai/sdk/toolerr"
	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/health"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "wappalyzer"
	ToolVersion     = "1.0.0"
	ToolDescription = "Technology detection tool using webanalyze for identifying web technologies and frameworks"
	BinaryName      = "webanalyze"
)

// ToolImpl implements the wappalyzer tool
type ToolImpl struct{}

// NewTool creates a new wappalyzer tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"fingerprinting",
			"technology-detection",
			"web",
			"T1595", // Active Scanning
			"T1594", // Search Victim-Owned Websites
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

// Execute runs the wappalyzer tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract input parameters
	targets := sdkinput.GetStringSlice(input, "targets")
	if len(targets) == 0 {
		return nil, fmt.Errorf("targets is required")
	}

	timeout := sdkinput.GetTimeout(input, "timeout", sdkinput.DefaultTimeout())

	// Build webanalyze command arguments
	args := []string{"-output", "json"}

	// Add all targets
	for _, target := range targets {
		args = append(args, "-host", target)
	}

	// Execute webanalyze command
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: timeout,
	})

	if err != nil {
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeExecutionFailed, err.Error()).WithCause(err)
	}

	// Parse webanalyze JSON output
	output, err := parseOutput(result.Stdout)
	if err != nil {
		return nil, toolerr.New(ToolName, "parse", toolerr.ErrCodeParseError, err.Error()).WithCause(err)
	}

	// Add scan time
	output["scan_time_ms"] = int(time.Since(startTime).Milliseconds())

	return output, nil
}

// Health checks if the webanalyze binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// WebanalyzeApp represents a detected technology from webanalyze
type WebanalyzeApp struct {
	Name       string   `json:"app"`
	Version    string   `json:"version"`
	Categories []string `json:"categories"`
	Confidence int      `json:"confidence"`
}

// WebanalyzeOutput represents the JSON output from webanalyze
type WebanalyzeOutput struct {
	Hostname string          `json:"host"`
	Apps     []WebanalyzeApp `json:"matches"`
}

// parseOutput parses the JSON output from webanalyze
func parseOutput(data []byte) (map[string]any, error) {
	var entries []WebanalyzeOutput
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse webanalyze output: %w", err)
	}

	results := []map[string]any{}

	for _, entry := range entries {
		// Extract host from URL
		host := entry.Hostname
		parsedURL, err := url.Parse(entry.Hostname)
		if err == nil {
			host = parsedURL.Hostname()
		}

		// Convert technologies
		technologies := []map[string]any{}
		for _, app := range entry.Apps {
			technologies = append(technologies, map[string]any{
				"name":       app.Name,
				"version":    app.Version,
				"categories": app.Categories,
				"confidence": app.Confidence,
			})
		}

		result := map[string]any{
			"url":          entry.Hostname,
			"host":         host,
			"technologies": technologies,
		}

		results = append(results, result)
	}

	return map[string]any{
		"results":       results,
		"total_scanned": len(results),
	}, nil
}
