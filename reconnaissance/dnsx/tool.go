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
	ToolName        = "dnsx"
	ToolVersion     = "1.0.0"
	ToolDescription = "Fast DNS resolution and probing tool with support for multiple query types"
	BinaryName      = "dnsx"
)

// DNSRecord represents a resolved DNS record
type DNSRecord struct {
	Host      string   `json:"host"`
	A         []string `json:"a,omitempty"`
	AAAA      []string `json:"aaaa,omitempty"`
	CNAME     []string `json:"cname,omitempty"`
	MX        []string `json:"mx,omitempty"`
	NS        []string `json:"ns,omitempty"`
	TXT       []string `json:"txt,omitempty"`
	SOA       []string `json:"soa,omitempty"`
	PTR       []string `json:"ptr,omitempty"`
	SRV       []string `json:"srv,omitempty"`
	StatusCode string  `json:"status_code,omitempty"`
}

// ToolImpl implements the dnsx tool
type ToolImpl struct{}

// NewTool creates a new dnsx tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"reconnaissance",
			"dns",
			"resolution",
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

// Execute runs the dnsx tool with the provided input
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

	timeout := sdkinput.GetTimeout(input, "timeout", sdkinput.DefaultTimeout())
	queryTypes := sdkinput.GetStringSlice(input, "query_types")
	if len(queryTypes) == 0 {
		queryTypes = []string{"A"}
	}
	retries := sdkinput.GetInt(input, "retries", 2)
	threads := sdkinput.GetInt(input, "threads", 100)
	wildcardCheck := sdkinput.GetBool(input, "wildcard_check", true)

	// Build dnsx command arguments
	args := buildArgs(queryTypes, retries, threads, wildcardCheck)

	// Execute dnsx command with domains as stdin
	domainsInput := strings.Join(domains, "\n")
	result, err := exec.Run(ctx, exec.Config{
		Command:   BinaryName,
		Args:      args,
		StdinData: []byte(domainsInput),
		Timeout:   timeout,
	})

	if err != nil {
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeExecutionFailed, err.Error()).WithCause(err)
	}

	// Parse dnsx output
	output, err := parseOutput(result.Stdout, domains)
	if err != nil {
		return nil, toolerr.New(ToolName, "parse", toolerr.ErrCodeParseError, err.Error()).WithCause(err)
	}

	// Add scan time
	output["scan_time_ms"] = int(time.Since(startTime).Milliseconds())

	return output, nil
}

// Health checks if the dnsx binary is available
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

// buildArgs constructs the command-line arguments for dnsx
func buildArgs(queryTypes []string, retries, threads int, wildcardCheck bool) []string {
	args := []string{"-json", "-silent"}

	// Add query type flags
	for _, qtype := range queryTypes {
		switch strings.ToUpper(qtype) {
		case "A":
			args = append(args, "-a")
		case "AAAA":
			args = append(args, "-aaaa")
		case "CNAME":
			args = append(args, "-cname")
		case "MX":
			args = append(args, "-mx")
		case "NS":
			args = append(args, "-ns")
		case "TXT":
			args = append(args, "-txt")
		case "SOA":
			args = append(args, "-soa")
		case "PTR":
			args = append(args, "-ptr")
		case "SRV":
			args = append(args, "-srv")
		}
	}

	// Add optional flags
	args = append(args, "-retry", fmt.Sprintf("%d", retries))
	args = append(args, "-t", fmt.Sprintf("%d", threads))

	if wildcardCheck {
		args = append(args, "-wd")
	}

	return args
}

// parseOutput parses the JSON output from dnsx
func parseOutput(data []byte, domains []string) (map[string]any, error) {
	lines := strings.Split(string(data), "\n")

	records := []DNSRecord{}
	resolved := 0
	failed := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var record DNSRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			// Skip malformed lines but continue processing
			continue
		}

		records = append(records, record)
		if hasResolution(&record) {
			resolved++
		} else {
			failed++
		}
	}

	return map[string]any{
		"domains":  domains,
		"records":  records,
		"total":    len(domains),
		"resolved": resolved,
		"failed":   failed,
	}, nil
}

// hasResolution checks if a DNS record has at least one resolved value
func hasResolution(record *DNSRecord) bool {
	return len(record.A) > 0 ||
		len(record.AAAA) > 0 ||
		len(record.CNAME) > 0 ||
		len(record.MX) > 0 ||
		len(record.NS) > 0 ||
		len(record.TXT) > 0 ||
		len(record.SOA) > 0 ||
		len(record.PTR) > 0 ||
		len(record.SRV) > 0
}
