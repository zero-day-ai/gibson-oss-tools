package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson-tools-official/pkg/common"
	"github.com/zero-day-ai/gibson-tools-official/pkg/executor"
	"github.com/zero-day-ai/gibson-tools-official/pkg/health"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "nuclei"
	ToolVersion     = "1.0.0"
	ToolDescription = "Fast vulnerability scanner using customizable templates for security testing"
	BinaryName      = "nuclei"
)

// ToolImpl implements the nuclei tool
type ToolImpl struct{}

// NewTool creates a new nuclei tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"reconnaissance",
			"vulnerability",
			"scanner",
			"T1595", // Active Scanning
			"T1190", // Exploit Public-Facing Application
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

// Execute runs the nuclei tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract input parameters
	target := common.GetString(input, "target", "")
	if target == "" {
		return nil, fmt.Errorf("target is required")
	}

	templates := common.GetStringSlice(input, "templates")
	severity := common.GetStringSlice(input, "severity")
	tags := common.GetStringSlice(input, "tags")
	timeout := common.GetTimeout(input, "timeout", common.DefaultTimeout())
	rateLimit := common.GetInt(input, "rate_limit", 150)

	// Build nuclei command arguments
	args := buildArgs(target, templates, severity, tags, rateLimit)

	// Execute nuclei command
	result, err := executor.Execute(ctx, executor.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: timeout,
	})

	if err != nil {
		return nil, common.NewToolError(ToolName, "execute", common.ErrCodeExecutionFailed, err.Error()).WithCause(err)
	}

	// Parse nuclei JSON output
	output, err := parseOutput(result.Stdout, target)
	if err != nil {
		return nil, common.NewToolError(ToolName, "parse", common.ErrCodeParseError, err.Error()).WithCause(err)
	}

	// Add scan time
	output["scan_time_ms"] = int(time.Since(startTime).Milliseconds())

	return output, nil
}

// Health checks if the nuclei binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// buildArgs constructs the command-line arguments for nuclei
func buildArgs(target string, templates, severity, tags []string, rateLimit int) []string {
	args := []string{"-u", target, "-json", "-silent"}

	if len(templates) > 0 {
		args = append(args, "-t", strings.Join(templates, ","))
	}

	if len(severity) > 0 {
		args = append(args, "-severity", strings.Join(severity, ","))
	}

	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}

	if rateLimit > 0 {
		args = append(args, "-rate-limit", fmt.Sprintf("%d", rateLimit))
	}

	return args
}

// NucleiOutput represents a single JSON line from nuclei output
type NucleiOutput struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
	Type      string   `json:"type"`
	MatchedAt string   `json:"matched-at"`
	Extracted []string `json:"extracted-results,omitempty"`
}

// parseOutput parses the JSON output from nuclei
func parseOutput(data []byte, target string) (map[string]any, error) {
	lines := strings.Split(string(data), "\n")

	findings := []map[string]any{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var entry NucleiOutput
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		findings = append(findings, map[string]any{
			"template_id":   entry.TemplateID,
			"template_name": entry.Info.Name,
			"severity":      entry.Info.Severity,
			"type":          entry.Type,
			"matched_at":    entry.MatchedAt,
			"extracted":     entry.Extracted,
		})
	}

	return map[string]any{
		"target":         target,
		"findings":       findings,
		"total_findings": len(findings),
	}, nil
}
