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
	ToolName        = "feroxbuster"
	ToolVersion     = "1.0.0"
	ToolDescription = "Fast, simple, recursive content discovery tool written in Rust"
	BinaryName      = "feroxbuster"
)

// ToolImpl implements the feroxbuster tool logic
type ToolImpl struct{}

// NewTool creates a new feroxbuster tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"reconnaissance",
			"web-fuzzing",
			"directory-enumeration",
			"T1595", // Active Scanning
			"T1083", // File and Directory Discovery
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

// Execute runs the feroxbuster tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract input parameters
	url := sdkinput.GetString(input, "url", "")
	if url == "" {
		return nil, fmt.Errorf("url is required")
	}

	wordlist := sdkinput.GetString(input, "wordlist", "")
	if wordlist == "" {
		return nil, fmt.Errorf("wordlist is required")
	}

	extensions := sdkinput.GetString(input, "extensions", "")
	threads := sdkinput.GetInt(input, "threads", 50)
	depth := sdkinput.GetInt(input, "depth", 4)
	timeout := sdkinput.GetTimeout(input, "timeout", sdkinput.DefaultTimeout())
	statusCodes := sdkinput.GetString(input, "status_codes", "200,204,301,302,307,308,401,403,405")
	filterSize := sdkinput.GetString(input, "filter_size", "")

	// Build feroxbuster command arguments
	args := buildFeroxbusterArgs(url, wordlist, extensions, threads, depth, statusCodes, filterSize)

	// Execute feroxbuster command
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: timeout,
	})

	if err != nil {
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeExecutionFailed, err.Error()).WithCause(err)
	}

	// Parse feroxbuster output
	output, err := parseFeroxbusterOutput(result.Stdout, url)
	if err != nil {
		return nil, toolerr.New(ToolName, "parse", toolerr.ErrCodeParseError, err.Error()).WithCause(err)
	}

	// Add scan metadata
	output["scan_time_ms"] = int(time.Since(startTime).Milliseconds())
	output["threads"] = threads
	output["depth"] = depth

	return output, nil
}

// Health checks if the feroxbuster binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// buildFeroxbusterArgs constructs the command line arguments for feroxbuster
func buildFeroxbusterArgs(url, wordlist, extensions string, threads, depth int, statusCodes, filterSize string) []string {
	args := []string{
		"-u", url,
		"-w", wordlist,
		"-t", fmt.Sprintf("%d", threads),
		"-d", fmt.Sprintf("%d", depth),
		"--json", // Output in JSON format
		"--silent", // Silent mode
		"--auto-bail", // Auto-cancel on errors
		"--no-state", // Disable state output
	}

	// Add extensions if specified
	if extensions != "" {
		args = append(args, "-x", extensions)
	}

	// Add status codes filter if specified
	if statusCodes != "" {
		args = append(args, "-s", statusCodes)
	}

	// Add size filter if specified
	if filterSize != "" {
		args = append(args, "-S", filterSize)
	}

	return args
}

// FeroxbusterResult represents a single feroxbuster result
type FeroxbusterResult struct {
	Type       string `json:"type"`
	URL        string `json:"url"`
	Path       string `json:"path"`
	Status     int    `json:"status"`
	Method     string `json:"method"`
	ContentLength int `json:"content_length"`
	LineCount  int    `json:"line_count"`
	WordCount  int    `json:"word_count"`
	Headers    map[string]string `json:"headers,omitempty"`
}

// parseFeroxbusterOutput parses the JSON output from feroxbuster
func parseFeroxbusterOutput(output []byte, url string) (map[string]any, error) {
	lines := strings.Split(string(output), "\n")

	paths := []map[string]any{}
	statusCodes := make(map[int]int)
	directories := []string{}
	files := []string{}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var result FeroxbusterResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			// Skip lines that can't be parsed
			continue
		}

		// Only process response types
		if result.Type != "response" {
			continue
		}

		pathInfo := map[string]any{
			"path":           result.Path,
			"url":            result.URL,
			"status_code":    result.Status,
			"method":         result.Method,
			"content_length": result.ContentLength,
			"line_count":     result.LineCount,
			"word_count":     result.WordCount,
		}

		paths = append(paths, pathInfo)

		// Track status codes
		statusCodes[result.Status]++

		// Categorize as directory or file
		if strings.HasSuffix(result.Path, "/") {
			directories = append(directories, result.Path)
		} else {
			files = append(files, result.Path)
		}
	}

	return map[string]any{
		"paths":        paths,
		"total_paths":  len(paths),
		"directories":  directories,
		"files":        files,
		"status_codes": statusCodes,
	}, nil
}
