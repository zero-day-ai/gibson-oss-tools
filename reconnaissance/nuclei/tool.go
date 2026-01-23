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
		})

	t, _ := tool.New(cfg)
	return &toolWithHealth{Tool: t, impl: &ToolImpl{}}
}

// toolWithHealth wraps the tool to add custom health checks and proto execution
type toolWithHealth struct {
	tool.Tool
	impl *ToolImpl
}

func (t *toolWithHealth) Health(ctx context.Context) types.HealthStatus {
	return t.impl.Health(ctx)
}

func (t *toolWithHealth) InputMessageType() string {
	return "gibson.tools.NucleiRequest"
}

func (t *toolWithHealth) OutputMessageType() string {
	return "gibson.tools.NucleiResponse"
}

func (t *toolWithHealth) ExecuteProto(ctx context.Context, input proto.Message) (proto.Message, error) {
	return t.impl.ExecuteProto(ctx, input)
}

// ExecuteProto runs the nuclei tool with the provided proto input
func (t *ToolImpl) ExecuteProto(ctx context.Context, input proto.Message) (proto.Message, error) {
	startTime := time.Now()

	// Type assert input to NucleiRequest
	req, ok := input.(*toolspb.NucleiRequest)
	if !ok {
		return nil, fmt.Errorf("expected *toolspb.NucleiRequest, got %T", input)
	}

	// Validate input - need at least one target
	if len(req.Targets) == 0 {
		return nil, fmt.Errorf("targets is required")
	}

	// For now, use the first target (matching old Execute behavior with single target)
	target := req.Targets[0]

	// Extract parameters from proto
	templates := req.Templates
	severity := req.Severity
	tags := req.Tags
	rateLimit := int(req.RateLimit)
	if rateLimit == 0 {
		rateLimit = 150 // Default rate limit
	}

	// Calculate timeout
	timeout := time.Duration(req.Timeout) * time.Second
	if timeout == 0 {
		timeout = 5 * time.Minute // Default timeout
	}

	// Build nuclei command arguments
	args := buildArgs(target, templates, severity, tags, rateLimit)

	// Execute nuclei command
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: timeout,
	})

	if err != nil {
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeExecutionFailed, err.Error()).WithCause(err)
	}

	// Parse nuclei JSON output to proto response
	response, err := parseOutputProto(result.Stdout, target)
	if err != nil {
		return nil, toolerr.New(ToolName, "parse", toolerr.ErrCodeParseError, err.Error()).WithCause(err)
	}

	// Add scan duration
	response.Duration = time.Since(startTime).Seconds()

	// Populate discovery field for automatic graph storage
	response.Discovery = convertToDiscoveryResult(response)

	return response, nil
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
	TemplateID  string   `json:"template-id"`
	Info        Info     `json:"info"`
	Type        string   `json:"type"`
	MatchedAt   string   `json:"matched-at"`
	Extracted   []string `json:"extracted-results,omitempty"`
	MatcherName string   `json:"matcher-name,omitempty"`
}

// Info contains metadata about the nuclei template
type Info struct {
	Name           string         `json:"name"`
	Severity       string         `json:"severity"`
	Description    string         `json:"description,omitempty"`
	Remediation    string         `json:"remediation,omitempty"`
	Reference      []string       `json:"reference,omitempty"`
	Classification Classification `json:"classification,omitempty"`
}

// Classification contains vulnerability classification data
type Classification struct {
	CVEID       []string `json:"cve-id,omitempty"`
	CWEID       []string `json:"cwe-id,omitempty"`
	CVSSScore   float64  `json:"cvss-score,omitempty"`
	CVSSMetrics string   `json:"cvss-metrics,omitempty"`
}

// parseOutputProto parses the JSON output from nuclei into proto response
func parseOutputProto(data []byte, target string) (*toolspb.NucleiResponse, error) {
	lines := strings.Split(string(data), "\n")

	results := []*toolspb.TemplateMatch{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var entry NucleiOutput
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		// Parse matched_at URL to extract host
		parsedURL, _ := url.Parse(entry.MatchedAt)
		host := ""
		if parsedURL != nil {
			host = parsedURL.Hostname()
		}

		// Build template info
		templateInfo := &toolspb.TemplateInfo{
			Name:        entry.Info.Name,
			Severity:    entry.Info.Severity,
			Description: entry.Info.Description,
			Remediation: entry.Info.Remediation,
			Reference:   entry.Info.Reference,
			Tags:        []string{}, // Tags not in nuclei JSON output
		}

		// Add classification if present
		if len(entry.Info.Classification.CVEID) > 0 || len(entry.Info.Classification.CWEID) > 0 ||
			entry.Info.Classification.CVSSScore > 0 {
			templateInfo.Classification = &toolspb.TemplateClassification{
				CveId:       entry.Info.Classification.CVEID,
				CweId:       entry.Info.Classification.CWEID,
				CvssScore:   entry.Info.Classification.CVSSScore,
				CvssMetrics: entry.Info.Classification.CVSSMetrics,
			}
		}

		// Build template match
		match := &toolspb.TemplateMatch{
			TemplateId:       entry.TemplateID,
			TemplateName:     entry.Info.Name,
			TemplatePath:     "", // Not available in nuclei JSON output
			Info:             templateInfo,
			MatcherName:      entry.MatcherName,
			Type:             entry.Type,
			Host:             host,
			Url:              entry.MatchedAt, // Use matched_at as URL
			MatchedAt:        entry.MatchedAt,
			ExtractedResults: entry.Extracted,
			Timestamp:        time.Now().Unix(),
			Metadata:         map[string]string{},
		}

		results = append(results, match)
	}

	return &toolspb.NucleiResponse{
		Results:      results,
		TotalMatches: int32(len(results)),
	}, nil
}

// ptrStr returns a pointer to the given string
func ptrStr(s string) *string {
	return &s
}

// ptrFloat returns a pointer to the given float64
func ptrFloat(f float64) *float64 {
	return &f
}

// convertToDiscoveryResult converts nuclei results to GraphRAG discovery result proto
func convertToDiscoveryResult(response *toolspb.NucleiResponse) *graphragpb.DiscoveryResult {
	result := &graphragpb.DiscoveryResult{
		Findings: []*graphragpb.Finding{},
	}

	// Track unique findings (by CVE or template ID)
	findingMap := make(map[string]*graphragpb.Finding)

	for _, match := range response.Results {
		// Build finding ID
		findingID := match.TemplateId

		// If we have CVE IDs, use the first one as the ID
		if match.Info != nil && match.Info.Classification != nil && len(match.Info.Classification.CveId) > 0 {
			findingID = match.Info.Classification.CveId[0]
		}

		// Skip if we've already added this finding
		if _, exists := findingMap[findingID]; exists {
			continue
		}

		// Create finding
		finding := &graphragpb.Finding{
			Title:    match.TemplateName,
			Severity: strings.ToLower(match.Info.Severity),
		}

		if match.Info != nil {
			if match.Info.Description != "" {
				finding.Description = ptrStr(match.Info.Description)
			}
			if match.Info.Remediation != "" {
				finding.Remediation = ptrStr(match.Info.Remediation)
			}

			// Add classification data
			if match.Info.Classification != nil {
				if len(match.Info.Classification.CveId) > 0 {
					finding.CveIds = ptrStr(strings.Join(match.Info.Classification.CveId, ", "))
				}
				if match.Info.Classification.CvssScore > 0 {
					finding.CvssScore = ptrFloat(match.Info.Classification.CvssScore)
				}
			}
		}

		findingMap[findingID] = finding
	}

	// Add unique findings
	for _, finding := range findingMap {
		result.Findings = append(result.Findings, finding)
	}

	return result
}
