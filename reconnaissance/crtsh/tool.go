package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	sdkinput "github.com/zero-day-ai/sdk/input"
	"github.com/zero-day-ai/sdk/toolerr"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "crtsh"
	ToolVersion     = "1.0.0"
	ToolDescription = "Certificate Transparency log search for passive subdomain enumeration via crt.sh"
	CrtshAPIURL     = "https://crt.sh/"
)

// Certificate represents a certificate entry from crt.sh
type Certificate struct {
	ID           int64  `json:"id"`
	LoggedAt     string `json:"logged_at"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	CommonName   string `json:"common_name"`
	NameValue    string `json:"name_value"`
	IssuerName   string `json:"issuer_name"`
	SerialNumber string `json:"serial_number"`
}

// ToolImpl implements the crtsh tool
type ToolImpl struct {
	httpClient *http.Client
}

// NewTool creates a new crtsh tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"reconnaissance",
			"certificate-transparency",
			"passive",
			"subdomain",
			"T1595", // Active Scanning (passive)
			"T1592", // Gather Victim Host Information
		}).
		SetInputSchema(InputSchema()).
		SetOutputSchema(OutputSchema()).
		SetExecuteFunc((&ToolImpl{
			httpClient: &http.Client{
				Timeout: 30 * time.Second,
			},
		}).Execute)

	t, _ := tool.New(cfg)
	return &toolWithHealth{
		Tool: t,
		impl: &ToolImpl{
			httpClient: &http.Client{
				Timeout: 30 * time.Second,
			},
		},
	}
}

// toolWithHealth wraps the tool to add custom health checks
type toolWithHealth struct {
	tool.Tool
	impl *ToolImpl
}

func (t *toolWithHealth) Health(ctx context.Context) types.HealthStatus {
	return t.impl.Health(ctx)
}

// Execute runs the crtsh tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract input parameters
	domain := sdkinput.GetString(input, "domain", "")
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	timeout := sdkinput.GetTimeout(input, "timeout", 30*time.Second)
	includeExpired := sdkinput.GetBool(input, "include_expired", true)
	wildcardSearch := sdkinput.GetBool(input, "wildcard_search", true)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Query crt.sh API
	certificates, err := t.queryCrtsh(ctx, domain, wildcardSearch)
	if err != nil {
		return nil, toolerr.New(ToolName, "query", toolerr.ErrCodeExecutionFailed, err.Error()).WithCause(err)
	}

	// Extract subdomains from certificates
	output := parseOutput(certificates, domain, includeExpired)

	// Add scan time
	output["scan_time_ms"] = int(time.Since(startTime).Milliseconds())

	return output, nil
}

// Health checks if the crt.sh API is accessible
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	req, err := http.NewRequestWithContext(ctx, "GET", CrtshAPIURL, nil)
	if err != nil {
		return types.HealthStatus{
			Status:  types.StatusUnhealthy,
			Message: fmt.Sprintf("Failed to create health check request: %v", err),
		}
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return types.HealthStatus{
			Status:  types.StatusUnhealthy,
			Message: fmt.Sprintf("crt.sh API unreachable: %v", err),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return types.HealthStatus{
			Status:  types.StatusHealthy,
			Message: "crt.sh API is accessible",
		}
	}

	return types.HealthStatus{
		Status:  types.StatusUnhealthy,
		Message: fmt.Sprintf("crt.sh API returned status %d", resp.StatusCode),
	}
}

// queryCrtsh queries the crt.sh API for certificates
func (t *ToolImpl) queryCrtsh(ctx context.Context, domain string, wildcardSearch bool) ([]Certificate, error) {
	searchQuery := domain
	if wildcardSearch {
		searchQuery = "%" + domain
	}

	// Build API URL
	apiURL := fmt.Sprintf("%s?q=%s&output=json", CrtshAPIURL, url.QueryEscape(searchQuery))

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "Gibson-Framework/"+ToolVersion)

	// Execute request
	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query crt.sh: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse JSON response
	var certificates []Certificate
	if err := json.Unmarshal(body, &certificates); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	return certificates, nil
}

// parseOutput extracts subdomains from certificate data
func parseOutput(certificates []Certificate, domain string, includeExpired bool) map[string]any {
	subdomainMap := make(map[string]bool)
	var certList []map[string]any
	now := time.Now()

	for _, cert := range certificates {
		// Check if certificate is expired
		if !includeExpired {
			notAfter, err := time.Parse("2006-01-02T15:04:05", cert.NotAfter)
			if err == nil && notAfter.Before(now) {
				continue
			}
		}

		// Extract subdomains from name_value (can contain multiple domains separated by newlines)
		names := strings.Split(cert.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			name = strings.ToLower(name)

			// Remove wildcard prefix
			name = strings.TrimPrefix(name, "*.")

			// Only include subdomains of the target domain
			if strings.HasSuffix(name, domain) || name == domain {
				subdomainMap[name] = true
			}
		}

		// Add certificate info
		certList = append(certList, map[string]any{
			"id":            cert.ID,
			"logged_at":     cert.LoggedAt,
			"not_before":    cert.NotBefore,
			"not_after":     cert.NotAfter,
			"common_name":   cert.CommonName,
			"issuer_name":   cert.IssuerName,
			"serial_number": cert.SerialNumber,
		})
	}

	// Convert map to slice
	subdomains := make([]string, 0, len(subdomainMap))
	for subdomain := range subdomainMap {
		subdomains = append(subdomains, subdomain)
	}

	return map[string]any{
		"domain":       domain,
		"subdomains":   subdomains,
		"count":        len(subdomains),
		"certificates": certList,
		"total_certs":  len(certList),
	}
}
