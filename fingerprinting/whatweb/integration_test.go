//go:build integration

package main

import (
	"context"
	"testing"
	"time"

	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/types"
)

func TestWhatWebIntegration(t *testing.T) {
	// Skip if whatweb binary is not available
	if !exec.BinaryExists(BinaryName) {
		t.Skipf("skipping integration test: %s binary not found", BinaryName)
	}

	tool := NewTool()

	// Verify health check passes
	t.Run("HealthCheck", func(t *testing.T) {
		ctx := context.Background()
		health := tool.Health(ctx)

		if health.Status != types.StatusHealthy {
			t.Errorf("expected health status %s, got %s: %s",
				types.StatusHealthy, health.Status, health.Message)
		}
	})

	// Test basic technology detection
	t.Run("BasicDetection", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping test in short mode")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		input := map[string]any{
			"targets": []any{"https://example.com"},
		}

		output, err := tool.Execute(ctx, input)
		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}

		// Validate output structure
		if results, ok := output["results"].([]any); !ok {
			t.Errorf("expected results to be []any, got %T", output["results"])
		} else {
			t.Logf("found %d results", len(results))
			if len(results) > 0 {
				t.Logf("first result: %+v", results[0])
			}
		}

		if count, ok := output["total_scanned"].(int); !ok || count < 0 {
			t.Errorf("expected valid total_scanned, got %v", output["total_scanned"])
		}
	})

	// Test with aggression level
	t.Run("AggressionLevel", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping test in short mode")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		input := map[string]any{
			"targets":    []any{"https://example.com"},
			"aggression": 3,
		}

		output, err := tool.Execute(ctx, input)
		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}

		// Validate output
		if _, ok := output["results"].([]any); !ok {
			t.Errorf("expected results to be []any, got %T", output["results"])
		}
	})

	// Test multiple targets
	t.Run("MultipleTargets", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping test in short mode")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		input := map[string]any{
			"targets": []any{
				"https://example.com",
				"https://www.google.com",
			},
		}

		output, err := tool.Execute(ctx, input)
		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}

		// Validate output
		if results, ok := output["results"].([]any); !ok {
			t.Errorf("expected results to be []any, got %T", output["results"])
		} else if len(results) != 2 {
			t.Errorf("expected 2 results, got %d", len(results))
		}
	})
}
