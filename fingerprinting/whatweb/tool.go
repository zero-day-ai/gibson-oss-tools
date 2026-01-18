package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
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
	ToolName        = "whatweb"
	ToolVersion     = "1.0.0"
	ToolDescription = "Web technology detection tool for identifying CMS, frameworks, JavaScript libraries, and server technologies"
	BinaryName      = "whatweb"
)

// ToolImpl implements the whatweb tool
type ToolImpl struct{}

// NewTool creates a new whatweb tool instance
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

// Execute runs the whatweb tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract input parameters
	targets := sdkinput.GetStringSlice(input, "targets")
	if len(targets) == 0 {
		return nil, fmt.Errorf("targets is required")
	}

	timeout := sdkinput.GetTimeout(input, "timeout", sdkinput.DefaultTimeout())
	aggression := sdkinput.GetInt(input, "aggression", 1)

	// Build whatweb command arguments
	args := []string{
		"--log-json=-", // Output JSON to stdout
		fmt.Sprintf("-a%d", aggression),
		"--color=never",
		"--no-errors",
	}

	// Add all targets
	args = append(args, targets...)

	// Execute whatweb command
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: timeout,
	})

	if err != nil {
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeExecutionFailed, err.Error()).WithCause(err)
	}

	// Parse whatweb JSON output
	output, err := parseOutput(result.Stdout)
	if err != nil {
		return nil, toolerr.New(ToolName, "parse", toolerr.ErrCodeParseError, err.Error()).WithCause(err)
	}

	// Add scan time
	output["scan_time_ms"] = int(time.Since(startTime).Milliseconds())

	return output, nil
}

// Health checks if the whatweb binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// WhatWebPlugin represents a detected plugin/technology from whatweb
type WhatWebPlugin struct {
	Name       string              `json:"name"`
	Version    []string            `json:"version,omitempty"`
	Categories []string            `json:"category,omitempty"`
	String     []string            `json:"string,omitempty"`
	Match      map[string][]string `json:"match,omitempty"`
}

// WhatWebOutput represents the JSON output from whatweb
type WhatWebOutput struct {
	Target     string          `json:"target"`
	HTTPStatus int             `json:"http_status"`
	RequestURL string          `json:"request_config,omitempty"`
	Plugins    []WhatWebPlugin `json:"plugins"`
}

// parseOutput parses the JSON output from whatweb
func parseOutput(data []byte) (map[string]any, error) {
	lines := strings.Split(string(data), "\n")
	results := []map[string]any{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var entry WhatWebOutput
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		// Extract host and IP from target URL
		host := ""
		ip := ""
		parsedURL, err := url.Parse(entry.Target)
		if err == nil {
			host = parsedURL.Hostname()
			// whatweb sometimes includes IP in brackets after hostname
			// but we'll use the hostname for now
		}

		// Convert plugins to technology format
		plugins := []map[string]any{}
		for _, plugin := range entry.Plugins {
			pluginData := map[string]any{
				"name":       plugin.Name,
				"version":    plugin.Version,
				"categories": plugin.Categories,
				"string":     plugin.String,
			}
			plugins = append(plugins, pluginData)
		}

		result := map[string]any{
			"target":      entry.Target,
			"http_status": entry.HTTPStatus,
			"request_url": entry.RequestURL,
			"plugins":     plugins,
			"ip":          ip,
			"host":        host,
		}

		results = append(results, result)
	}

	return map[string]any{
		"results":       results,
		"total_scanned": len(results),
	}, nil
}
