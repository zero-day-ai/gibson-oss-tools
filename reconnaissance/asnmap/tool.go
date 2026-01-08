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
	ToolName        = "asnmap"
	ToolVersion     = "1.0.0"
	ToolDescription = "ASN to IP/CIDR mapping tool for network reconnaissance"
	BinaryName      = "asnmap"
)

// ASNInfo represents ASN information from asnmap output
type ASNInfo struct {
	Timestamp string   `json:"timestamp"`
	Input     string   `json:"input"`
	ASN       string   `json:"asn"`
	Country   string   `json:"country,omitempty"`
	Name      string   `json:"name,omitempty"`
	Domain    string   `json:"domain,omitempty"`
	IP        string   `json:"ip,omitempty"`
	CIDR      []string `json:"cidr,omitempty"`
	Org       string   `json:"org,omitempty"`
	Registry  string   `json:"registry,omitempty"`
	Ports     []int    `json:"ports,omitempty"`
}

// ToolImpl implements the asnmap tool
type ToolImpl struct{}

// NewTool creates a new asnmap tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"reconnaissance",
			"asn",
			"network",
			"cidr",
			"T1590", // Gather Victim Network Information
			"T1596", // Search Open Technical Databases
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

// Execute runs the asnmap tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract input parameters
	targets, err := extractTargets(input)
	if err != nil {
		return nil, toolerr.New(ToolName, "input", toolerr.ErrCodeInvalidInput, err.Error()).WithCause(err)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("at least one target is required (domain, ip, asn, or org)")
	}

	timeout := sdkinput.GetTimeout(input, "timeout", sdkinput.DefaultTimeout())
	includeCIDR := sdkinput.GetBool(input, "include_cidr", true)
	includeIPv6 := sdkinput.GetBool(input, "include_ipv6", false)

	// Build asnmap command arguments
	args := buildArgs(targets, includeCIDR, includeIPv6)

	// Execute asnmap command
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: timeout,
	})

	if err != nil {
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeExecutionFailed, err.Error()).WithCause(err)
	}

	// Parse asnmap output
	output, err := parseOutput(result.Stdout)
	if err != nil {
		return nil, toolerr.New(ToolName, "parse", toolerr.ErrCodeParseError, err.Error()).WithCause(err)
	}

	// Add metadata
	output["targets"] = targets
	output["scan_time_ms"] = int(time.Since(startTime).Milliseconds())

	return output, nil
}

// Health checks if the asnmap binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// extractTargets extracts targets from input
func extractTargets(input map[string]any) ([]string, error) {
	var targets []string

	// Try domain
	if domain := sdkinput.GetString(input, "domain", ""); domain != "" {
		targets = append(targets, "-d", domain)
	}

	// Try IP
	if ip := sdkinput.GetString(input, "ip", ""); ip != "" {
		targets = append(targets, "-i", ip)
	}

	// Try ASN
	if asn := sdkinput.GetString(input, "asn", ""); asn != "" {
		targets = append(targets, "-a", asn)
	}

	// Try organization
	if org := sdkinput.GetString(input, "org", ""); org != "" {
		targets = append(targets, "-o", org)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("at least one of domain, ip, asn, or org must be provided")
	}

	return targets, nil
}

// buildArgs constructs the command-line arguments for asnmap
func buildArgs(targets []string, includeCIDR, includeIPv6 bool) []string {
	args := []string{"-json", "-silent"}

	// Add targets
	args = append(args, targets...)

	// Add CIDR flag
	if includeCIDR {
		args = append(args, "-c")
	}

	// Add IPv6 flag
	if includeIPv6 {
		args = append(args, "-6")
	}

	return args
}

// parseOutput parses the JSON output from asnmap
func parseOutput(data []byte) (map[string]any, error) {
	lines := strings.Split(string(data), "\n")

	var asnRecords []ASNInfo
	asnMap := make(map[string]bool)
	var allCIDRs []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var record ASNInfo
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			// Skip malformed lines but continue processing
			continue
		}

		asnRecords = append(asnRecords, record)

		// Track unique ASNs
		if record.ASN != "" {
			asnMap[record.ASN] = true
		}

		// Collect CIDRs
		allCIDRs = append(allCIDRs, record.CIDR...)
	}

	// Get unique ASNs
	uniqueASNs := make([]string, 0, len(asnMap))
	for asn := range asnMap {
		uniqueASNs = append(uniqueASNs, asn)
	}

	// Deduplicate CIDRs
	cidrMap := make(map[string]bool)
	for _, cidr := range allCIDRs {
		if cidr != "" {
			cidrMap[cidr] = true
		}
	}
	uniqueCIDRs := make([]string, 0, len(cidrMap))
	for cidr := range cidrMap {
		uniqueCIDRs = append(uniqueCIDRs, cidr)
	}

	return map[string]any{
		"asn_info":    asnRecords,
		"total_asns":  len(uniqueASNs),
		"asns":        uniqueASNs,
		"cidrs":       uniqueCIDRs,
		"total_cidrs": len(uniqueCIDRs),
	}, nil
}
