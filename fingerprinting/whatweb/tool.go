package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/zero-day-ai/sdk/api/gen/graphragpb"
	"github.com/zero-day-ai/sdk/api/gen/toolspb"
	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/health"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/toolerr"
	"github.com/zero-day-ai/sdk/types"
	"google.golang.org/protobuf/proto"
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
	impl := &ToolImpl{}
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
		SetInputMessageType(impl.InputMessageType()).
		SetOutputMessageType(impl.OutputMessageType()).
		SetExecuteProtoFunc(impl.ExecuteProto)

	t, _ := tool.New(cfg)
	return &toolWithHealth{Tool: t, impl: impl}
}

// toolWithHealth wraps the tool to add custom health checks
type toolWithHealth struct {
	tool.Tool
	impl *ToolImpl
}

func (t *toolWithHealth) Health(ctx context.Context) types.HealthStatus {
	return t.impl.Health(ctx)
}

// InputMessageType returns the proto message type for input
func (t *ToolImpl) InputMessageType() string {
	return "gibson.tools.WhatwebRequest"
}

// OutputMessageType returns the proto message type for output
func (t *ToolImpl) OutputMessageType() string {
	return "gibson.tools.WhatwebResponse"
}

// ExecuteProto runs the whatweb tool with proto message input
func (t *ToolImpl) ExecuteProto(ctx context.Context, input proto.Message) (proto.Message, error) {
	startTime := time.Now()

	// Type assert input to WhatwebRequest
	req, ok := input.(*toolspb.WhatwebRequest)
	if !ok {
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeInvalidInput,
			fmt.Sprintf("expected *toolspb.WhatwebRequest, got %T", input))
	}

	// Validate required fields
	if len(req.Targets) == 0 {
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeInvalidInput, "targets is required")
	}

	// Set default aggression level if not specified
	aggression := req.Aggression
	if aggression == 0 {
		aggression = 1
	}

	// Build whatweb command arguments
	args := []string{
		"--log-json=-", // Output JSON to stdout
		fmt.Sprintf("-a%d", aggression),
		"--color=never",
	}

	// Add no-errors flag if requested
	if req.NoErrors {
		args = append(args, "--no-errors")
	}

	// Add all targets
	args = append(args, req.Targets...)

	// Calculate timeout (default to 120 seconds if not specified)
	timeout := time.Duration(req.Timeout) * time.Second
	if timeout == 0 {
		timeout = 120 * time.Second
	}

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
	response, err := parseOutputProto(result.Stdout)
	if err != nil {
		return nil, toolerr.New(ToolName, "parse", toolerr.ErrCodeParseError, err.Error()).WithCause(err)
	}

	// Set duration
	response.Duration = time.Since(startTime).Seconds()

	return response, nil
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

// parseOutputProto parses the JSON output from whatweb and returns proto response
func parseOutputProto(data []byte) (*toolspb.WhatwebResponse, error) {
	lines := strings.Split(string(data), "\n")
	results := []*toolspb.WhatwebResult{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var entry WhatWebOutput
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		// Extract IP from target URL
		ip := ""
		parsedURL, err := url.Parse(entry.Target)
		if err == nil {
			// whatweb sometimes includes IP in brackets after hostname
			// but we'll use the hostname for now
			ip = parsedURL.Hostname()
		}

		// Convert plugins to proto format
		plugins := []*toolspb.WhatwebPlugin{}
		for _, plugin := range entry.Plugins {
			protoPlugin := &toolspb.WhatwebPlugin{
				Name:       plugin.Name,
				Version:    plugin.Version,
				String_:    plugin.String,
				Categories: plugin.Categories,
			}
			plugins = append(plugins, protoPlugin)
		}

		result := &toolspb.WhatwebResult{
			Target:     entry.Target,
			StatusCode: int32(entry.HTTPStatus),
			Ip:         ip,
			Plugins:    plugins,
		}

		results = append(results, result)
	}

	response := &toolspb.WhatwebResponse{
		Results:      results,
		TotalTargets: int32(len(results)),
	}

	// Populate discovery field for automatic graph storage
	response.Discovery = convertToDiscoveryResult(response)

	return response, nil
}

// convertToDiscoveryResult converts whatweb results to GraphRAG discovery result proto
func convertToDiscoveryResult(response *toolspb.WhatwebResponse) *graphragpb.DiscoveryResult {
	result := &graphragpb.DiscoveryResult{
		Technologies: []*graphragpb.Technology{},
	}

	// Track unique technologies to avoid duplicates
	techMap := make(map[string]*graphragpb.Technology)

	for _, r := range response.Results {
		for _, plugin := range r.Plugins {
			// Extract version (use first if multiple)
			version := ""
			if len(plugin.Version) > 0 {
				version = plugin.Version[0]
			}

			// Use name+version as key to avoid duplicates
			key := plugin.Name
			if version != "" {
				key = fmt.Sprintf("%s:%s", plugin.Name, version)
			}

			if _, exists := techMap[key]; !exists {
				// Get category (use first if multiple)
				category := ""
				if len(plugin.Categories) > 0 {
					category = plugin.Categories[0]
				}

				techProto := &graphragpb.Technology{
					Name: plugin.Name,
				}
				if version != "" {
					techProto.Version = &version
				}
				if category != "" {
					techProto.Category = &category
				}
				techMap[key] = techProto
			}
		}
	}

	// Add unique technologies
	for _, tech := range techMap {
		result.Technologies = append(result.Technologies, tech)
	}

	return result
}
