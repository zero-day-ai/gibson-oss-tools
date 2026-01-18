package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	sdkinput "github.com/zero-day-ai/sdk/input"
	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/health"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "testssl"
	ToolVersion     = "1.0.0"
	ToolDescription = "SSL/TLS security testing tool for analyzing protocols, ciphers, vulnerabilities, and certificate information"
	BinaryName      = "testssl.sh"
)

// ToolImpl implements the testssl tool
type ToolImpl struct{}

// NewTool creates a new testssl tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"fingerprinting",
			"ssl-tls",
			"security-testing",
			"vulnerability-detection",
			"T1595", // Active Scanning
			"T1071", // Application Layer Protocol
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

// Execute runs the testssl tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract input parameters
	targets := sdkinput.GetStringSlice(input, "targets")
	if len(targets) == 0 {
		return nil, fmt.Errorf("targets is required")
	}

	timeout := sdkinput.GetTimeout(input, "timeout", 5*time.Minute)
	severity := sdkinput.GetString(input, "severity", "LOW")

	// Process each target
	allResults := []map[string]any{}
	for _, target := range targets {
		// Build testssl command arguments
		args := []string{
			"--jsonfile=-", // Output JSON to stdout
			"--quiet",
			"--fast", // Faster scan mode
			"--severity", severity,
			target,
		}

		// Execute testssl command
		result, err := exec.Run(ctx, exec.Config{
			Command: BinaryName,
			Args:    args,
			Timeout: timeout,
		})

		if err != nil {
			// Continue with other targets if one fails
			continue
		}

		// Parse testssl JSON output
		targetResult, err := parseOutput(target, result.Stdout)
		if err != nil {
			continue
		}

		allResults = append(allResults, targetResult)
	}

	return map[string]any{
		"results":       allResults,
		"total_scanned": len(allResults),
		"scan_time_ms":  int(time.Since(startTime).Milliseconds()),
	}, nil
}

// Health checks if the testssl.sh binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// TestSSLEntry represents a single JSON entry from testssl output
type TestSSLEntry struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Finding     string `json:"finding"`
	CVE         string `json:"cve,omitempty"`
	Description string `json:"description,omitempty"`
	IP          string `json:"ip,omitempty"`
}

// parseOutput parses the JSON output from testssl
func parseOutput(target string, data []byte) (map[string]any, error) {
	lines := strings.Split(string(data), "\n")

	protocols := []map[string]any{}
	ciphers := []map[string]any{}
	vulnerabilities := []map[string]any{}
	var certificate map[string]any
	ip := ""
	port := 443 // Default HTTPS port

	// Extract port from target if present
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		if len(parts) == 2 {
			fmt.Sscanf(parts[1], "%d", &port)
		}
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var entry TestSSLEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		// Extract IP if available
		if entry.IP != "" {
			ip = entry.IP
		}

		// Categorize findings
		switch {
		case strings.Contains(entry.ID, "protocol_"):
			protocols = append(protocols, map[string]any{
				"name":     entry.Finding,
				"severity": entry.Severity,
				"finding":  entry.Finding,
			})
		case strings.Contains(entry.ID, "cipher_"):
			ciphers = append(ciphers, map[string]any{
				"name":     entry.Finding,
				"severity": entry.Severity,
				"finding":  entry.Finding,
			})
		case strings.Contains(entry.ID, "cert_"):
			// Parse certificate info
			if certificate == nil {
				certificate = parseCertificate(entry)
			}
		case entry.CVE != "" || strings.Contains(entry.ID, "vuln_"):
			vulnerabilities = append(vulnerabilities, map[string]any{
				"id":          entry.ID,
				"severity":    entry.Severity,
				"finding":     entry.Finding,
				"cve":         entry.CVE,
				"description": entry.Description,
			})
		}
	}

	// Ensure certificate exists even if empty
	if certificate == nil {
		certificate = map[string]any{
			"subject":    "",
			"issuer":     "",
			"not_before": "",
			"not_after":  "",
			"sans":       []string{},
			"expired":    false,
		}
	}

	return map[string]any{
		"target":          target,
		"ip":              ip,
		"port":            port,
		"protocols":       protocols,
		"ciphers":         ciphers,
		"certificate":     certificate,
		"vulnerabilities": vulnerabilities,
	}, nil
}

// parseCertificate extracts certificate information from testssl entry
func parseCertificate(entry TestSSLEntry) map[string]any {
	cert := map[string]any{
		"subject":    "",
		"issuer":     "",
		"not_before": "",
		"not_after":  "",
		"sans":       []string{},
		"expired":    false,
	}

	// Parse finding for certificate details
	if strings.Contains(entry.ID, "cert_subject") {
		cert["subject"] = entry.Finding
	} else if strings.Contains(entry.ID, "cert_issuer") {
		cert["issuer"] = entry.Finding
	} else if strings.Contains(entry.ID, "cert_notBefore") {
		cert["not_before"] = entry.Finding
	} else if strings.Contains(entry.ID, "cert_notAfter") {
		cert["not_after"] = entry.Finding
	} else if strings.Contains(entry.ID, "cert_expirationStatus") {
		cert["expired"] = strings.Contains(strings.ToLower(entry.Finding), "expired")
	}

	return cert
}
