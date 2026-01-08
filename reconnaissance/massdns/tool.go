package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
	ToolName        = "massdns"
	ToolVersion     = "1.0.0"
	ToolDescription = "High-performance DNS stub resolver for bulk lookups and reconnaissance"
	BinaryName      = "massdns"
)

// MassDNSRecord represents a resolved DNS record from massdns output
type MassDNSRecord struct {
	Domain string `json:"domain"`
	Type   string `json:"type"`
	Value  string `json:"value"`
}

// ToolImpl implements the massdns tool
type ToolImpl struct{}

// NewTool creates a new massdns tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"reconnaissance",
			"dns",
			"bulk-resolution",
			"T1595", // Active Scanning
			"T1590", // Gather Victim Network Information
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

// Execute runs the massdns tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract input parameters
	domains, err := extractDomains(input)
	if err != nil {
		return nil, toolerr.New(ToolName, "input", toolerr.ErrCodeInvalidInput, err.Error()).WithCause(err)
	}

	if len(domains) == 0 {
		return nil, fmt.Errorf("at least one domain is required")
	}

	timeout := sdkinput.GetTimeout(input, "timeout", 300*time.Second)
	recordType := sdkinput.GetString(input, "record_type", "A")
	resolvers := sdkinput.GetString(input, "resolvers", "")
	threads := sdkinput.GetInt(input, "threads", 1000)
	rateLimit := sdkinput.GetInt(input, "rate_limit", 0)

	// Create temporary file for domains
	domainsFile, err := createTempFile(domains, recordType)
	if err != nil {
		return nil, toolerr.New(ToolName, "tempfile", toolerr.ErrCodeExecutionFailed, err.Error()).WithCause(err)
	}
	defer os.Remove(domainsFile)

	// Build massdns command arguments
	args := buildArgs(domainsFile, resolvers, threads, rateLimit)

	// Execute massdns command
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: timeout,
	})

	if err != nil {
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeExecutionFailed, err.Error()).WithCause(err)
	}

	// Parse massdns output
	output, err := parseOutput(result.Stdout, domains)
	if err != nil {
		return nil, toolerr.New(ToolName, "parse", toolerr.ErrCodeParseError, err.Error()).WithCause(err)
	}

	// Add scan time
	output["scan_time_ms"] = int(time.Since(startTime).Milliseconds())

	return output, nil
}

// Health checks if the massdns binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// extractDomains extracts domains from input (either single domain or list)
func extractDomains(input map[string]any) ([]string, error) {
	// Try single domain first
	if domain := sdkinput.GetString(input, "domain", ""); domain != "" {
		return []string{domain}, nil
	}

	// Try domains list
	domains := sdkinput.GetStringSlice(input, "domains")
	if len(domains) > 0 {
		return domains, nil
	}

	return nil, fmt.Errorf("either 'domain' or 'domains' must be provided")
}

// createTempFile creates a temporary file with domains in massdns format
func createTempFile(domains []string, recordType string) (string, error) {
	tmpDir := os.TempDir()
	tmpFile := filepath.Join(tmpDir, fmt.Sprintf("massdns-domains-%d.txt", time.Now().UnixNano()))

	var lines []string
	for _, domain := range domains {
		// MassDNS expects format: domain.com. A
		lines = append(lines, fmt.Sprintf("%s. %s", strings.TrimSuffix(domain, "."), recordType))
	}

	content := strings.Join(lines, "\n")
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		return "", err
	}

	return tmpFile, nil
}

// buildArgs constructs the command-line arguments for massdns
func buildArgs(domainsFile, resolvers string, threads, rateLimit int) []string {
	args := []string{
		"-o", "S", // Simple output format
		"-q",      // Quiet mode
	}

	// Add resolver file if provided
	if resolvers != "" {
		args = append(args, "-r", resolvers)
	}

	// Add threads
	args = append(args, "-s", fmt.Sprintf("%d", threads))

	// Add rate limit if specified
	if rateLimit > 0 {
		args = append(args, "-l", fmt.Sprintf("%d", rateLimit))
	}

	// Add domains file
	args = append(args, domainsFile)

	return args
}

// parseOutput parses the simple output format from massdns
func parseOutput(data []byte, domains []string) (map[string]any, error) {
	lines := strings.Split(string(data), "\n")

	records := []MassDNSRecord{}
	resolvedDomains := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse simple format: domain. type value
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		domain := strings.TrimSuffix(parts[0], ".")
		recordType := parts[1]
		value := strings.Join(parts[2:], " ")

		record := MassDNSRecord{
			Domain: domain,
			Type:   recordType,
			Value:  value,
		}

		records = append(records, record)
		resolvedDomains[domain] = true
	}

	return map[string]any{
		"domains":  domains,
		"records":  records,
		"total":    len(domains),
		"resolved": len(resolvedDomains),
		"failed":   len(domains) - len(resolvedDomains),
	}, nil
}
