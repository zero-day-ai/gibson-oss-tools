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
	ToolName        = "naabu"
	ToolVersion     = "1.0.0"
	ToolDescription = "Fast port scanner written in Go with focus on reliability and simplicity"
	BinaryName      = "naabu"
)

// ToolImpl implements the naabu tool logic
type ToolImpl struct{}

// NewTool creates a new naabu tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"reconnaissance",
			"network-scanning",
			"port-scanning",
			"T1046", // Network Service Scanning
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

// Execute runs the naabu tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract input parameters
	hosts := sdkinput.GetString(input, "hosts", "")
	if hosts == "" {
		return nil, fmt.Errorf("hosts is required")
	}

	ports := sdkinput.GetString(input, "ports", "")
	rate := sdkinput.GetInt(input, "rate", 1000)
	timeout := sdkinput.GetTimeout(input, "timeout", sdkinput.DefaultTimeout())
	excludePorts := sdkinput.GetString(input, "exclude_ports", "")
	topPorts := sdkinput.GetString(input, "top_ports", "")

	// Build naabu command arguments
	args := buildNaabuArgs(hosts, ports, rate, excludePorts, topPorts)

	// Execute naabu command
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: timeout,
	})

	if err != nil {
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeExecutionFailed, err.Error()).WithCause(err)
	}

	// Parse naabu output
	output, err := parseNaabuOutput(result.Stdout, hosts)
	if err != nil {
		return nil, toolerr.New(ToolName, "parse", toolerr.ErrCodeParseError, err.Error()).WithCause(err)
	}

	// Add scan metadata
	output["scan_rate"] = rate
	output["scan_time_ms"] = int(time.Since(startTime).Milliseconds())

	return output, nil
}

// Health checks if the naabu binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// buildNaabuArgs constructs the command line arguments for naabu
func buildNaabuArgs(hosts, ports string, rate int, excludePorts, topPorts string) []string {
	args := []string{
		"-host", hosts,
		"-rate", fmt.Sprintf("%d", rate),
		"-json", // Output in JSON format
		"-silent", // Silent mode
	}

	// Add port specification
	if topPorts != "" {
		args = append(args, "-top-ports", topPorts)
	} else if ports != "" {
		args = append(args, "-p", ports)
	}

	// Add exclude ports if specified
	if excludePorts != "" {
		args = append(args, "-exclude-ports", excludePorts)
	}

	return args
}

// NaabuResult represents a single naabu scan result
type NaabuResult struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// parseNaabuOutput parses the JSON output from naabu
func parseNaabuOutput(output []byte, hosts string) (map[string]any, error) {
	lines := strings.Split(string(output), "\n")

	// Group ports by host
	hostMap := make(map[string][]map[string]any)
	totalPorts := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var result NaabuResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			// Skip lines that can't be parsed
			continue
		}

		// Determine the host identifier (prefer hostname, fallback to IP)
		hostKey := result.Host
		if hostKey == "" {
			hostKey = result.IP
		}

		portInfo := map[string]any{
			"port":     result.Port,
			"protocol": "tcp",
			"state":    "open",
		}

		// Add IP if hostname was provided
		if result.Host != "" && result.IP != "" {
			portInfo["ip"] = result.IP
		}

		hostMap[hostKey] = append(hostMap[hostKey], portInfo)
		totalPorts++
	}

	// Convert map to slice
	hostsOutput := make([]map[string]any, 0, len(hostMap))
	for host, ports := range hostMap {
		hostsOutput = append(hostsOutput, map[string]any{
			"host":  host,
			"ports": ports,
		})
	}

	return map[string]any{
		"hosts":       hostsOutput,
		"total_hosts": len(hostsOutput),
		"total_ports": totalPorts,
	}, nil
}
