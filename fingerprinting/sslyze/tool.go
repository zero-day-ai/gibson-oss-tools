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
	ToolName        = "sslyze"
	ToolVersion     = "1.0.0"
	ToolDescription = "Fast and powerful SSL/TLS scanning library for analyzing security configurations"
	BinaryName      = "sslyze"
)

// ToolImpl implements the sslyze tool
type ToolImpl struct{}

// NewTool creates a new sslyze tool instance
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

// Execute runs the sslyze tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract input parameters
	targets := sdkinput.GetStringSlice(input, "targets")
	if len(targets) == 0 {
		return nil, fmt.Errorf("targets is required")
	}

	timeout := sdkinput.GetTimeout(input, "timeout", 5*time.Minute)

	// Build sslyze command arguments
	args := []string{
		"--json_out=-", // Output JSON to stdout
		"--quiet",
	}

	// Add all targets
	args = append(args, targets...)

	// Execute sslyze command
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: timeout,
	})

	if err != nil {
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeExecutionFailed, err.Error()).WithCause(err)
	}

	// Parse sslyze JSON output
	output, err := parseOutput(result.Stdout)
	if err != nil {
		return nil, toolerr.New(ToolName, "parse", toolerr.ErrCodeParseError, err.Error()).WithCause(err)
	}

	// Add scan time
	output["scan_time_ms"] = int(time.Since(startTime).Milliseconds())

	return output, nil
}

// Health checks if the sslyze binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// SSLyzeServerLocation represents the server connection info
type SSLyzeServerLocation struct {
	Hostname  string `json:"hostname"`
	IPAddress string `json:"ip_address"`
	Port      int    `json:"port"`
}

// SSLyzeCertificate represents certificate info
type SSLyzeCertificate struct {
	Subject    map[string]string `json:"subject"`
	Issuer     map[string]string `json:"issuer"`
	NotBefore  string            `json:"notBefore"`
	NotAfter   string            `json:"notAfter"`
	SubjectAlt []string          `json:"subjectAltName,omitempty"`
}

// SSLyzeScanResult represents scan results for a single server
type SSLyzeScanResult struct {
	ServerLocation SSLyzeServerLocation `json:"server_location"`
	ScanCommands   map[string]any       `json:"scan_commands"`
}

// SSLyzeOutput represents the complete JSON output from sslyze
type SSLyzeOutput struct {
	ServerScanResults []SSLyzeScanResult `json:"server_scan_results"`
}

// parseOutput parses the JSON output from sslyze
func parseOutput(data []byte) (map[string]any, error) {
	var output SSLyzeOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("failed to parse sslyze output: %w", err)
	}

	results := []map[string]any{}

	for _, scanResult := range output.ServerScanResults {
		target := fmt.Sprintf("%s:%d", scanResult.ServerLocation.Hostname, scanResult.ServerLocation.Port)

		protocols := []map[string]any{}
		ciphers := []map[string]any{}
		vulnerabilities := []map[string]any{}
		var certificate map[string]any

		// Parse scan commands for protocol and cipher info
		for cmdName, cmdResult := range scanResult.ScanCommands {
			cmdData, ok := cmdResult.(map[string]any)
			if !ok {
				continue
			}

			switch {
			case strings.Contains(cmdName, "ssl_") || strings.Contains(cmdName, "tls_"):
				// Protocol check
				if accepted, ok := cmdData["accepted_cipher_suites"].([]any); ok && len(accepted) > 0 {
					protocols = append(protocols, map[string]any{
						"name":     strings.ToUpper(strings.Replace(cmdName, "_", " ", -1)),
						"severity": "INFO",
						"finding":  "supported",
					})

					// Extract cipher suites
					for _, cipher := range accepted {
						if cipherMap, ok := cipher.(map[string]any); ok {
							if cipherSuite, ok := cipherMap["cipher_suite"].(map[string]any); ok {
								if name, ok := cipherSuite["name"].(string); ok {
									ciphers = append(ciphers, map[string]any{
										"name":     name,
										"severity": "INFO",
										"finding":  "supported",
									})
								}
							}
						}
					}
				}
			case cmdName == "certificate_info":
				// Parse certificate information
				if certDeployments, ok := cmdData["certificate_deployments"].([]any); ok && len(certDeployments) > 0 {
					if firstDeploy, ok := certDeployments[0].(map[string]any); ok {
						if receivedCertChain, ok := firstDeploy["received_certificate_chain"].([]any); ok && len(receivedCertChain) > 0 {
							if cert, ok := receivedCertChain[0].(map[string]any); ok {
								certificate = parseCertificateInfo(cert)
							}
						}
					}
				}
			case strings.Contains(cmdName, "heartbleed") || strings.Contains(cmdName, "robot") || strings.Contains(cmdName, "openssl"):
				// Vulnerability checks
				if vulnerable, ok := cmdData["is_vulnerable_to_"+cmdName].(bool); ok && vulnerable {
					vulnerabilities = append(vulnerabilities, map[string]any{
						"id":          cmdName,
						"severity":    "HIGH",
						"finding":     "vulnerable",
						"cve":         "",
						"description": fmt.Sprintf("Vulnerable to %s", cmdName),
					})
				}
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

		result := map[string]any{
			"target":          target,
			"ip":              scanResult.ServerLocation.IPAddress,
			"port":            scanResult.ServerLocation.Port,
			"protocols":       protocols,
			"ciphers":         ciphers,
			"certificate":     certificate,
			"vulnerabilities": vulnerabilities,
		}

		results = append(results, result)
	}

	return map[string]any{
		"results":       results,
		"total_scanned": len(results),
	}, nil
}

// parseCertificateInfo extracts certificate details
func parseCertificateInfo(cert map[string]any) map[string]any {
	certificate := map[string]any{
		"subject":    "",
		"issuer":     "",
		"not_before": "",
		"not_after":  "",
		"sans":       []string{},
		"expired":    false,
	}

	// Extract subject
	if subject, ok := cert["subject"].(map[string]any); ok {
		if cn, ok := subject["commonName"].(string); ok {
			certificate["subject"] = cn
		}
	}

	// Extract issuer
	if issuer, ok := cert["issuer"].(map[string]any); ok {
		if cn, ok := issuer["commonName"].(string); ok {
			certificate["issuer"] = cn
		}
	}

	// Extract validity dates
	if notBefore, ok := cert["notBefore"].(string); ok {
		certificate["not_before"] = notBefore
	}
	if notAfter, ok := cert["notAfter"].(string); ok {
		certificate["not_after"] = notAfter

		// Check if expired
		notAfterTime, err := time.Parse(time.RFC3339, notAfter)
		if err == nil {
			certificate["expired"] = time.Now().After(notAfterTime)
		}
	}

	// Extract SANs
	if sans, ok := cert["subjectAltName"].([]any); ok {
		sansList := []string{}
		for _, san := range sans {
			if sanStr, ok := san.(string); ok {
				sansList = append(sansList, sanStr)
			}
		}
		certificate["sans"] = sansList
	}

	return certificate
}
