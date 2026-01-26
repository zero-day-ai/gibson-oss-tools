//go:build integration

package main

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/sdk/api/gen/toolspb"
	"github.com/zero-day-ai/sdk/types"
)

func TestNmapIntegration(t *testing.T) {
	// Skip if nmap binary is not available
	if _, err := exec.LookPath(BinaryName); err != nil {
		t.Skipf("skipping integration test: %s binary not found", BinaryName)
	}

	tool := NewTool()

	// Verify health check
	t.Run("HealthCheck", func(t *testing.T) {
		ctx := context.Background()
		health := tool.Health(ctx)

		// Health should be at least degraded (healthy or degraded, not unhealthy)
		if health.Status == types.StatusUnhealthy {
			t.Logf("nmap health check unhealthy: %s", health.Message)
		} else {
			t.Logf("nmap health check: %s - %s", health.Status, health.Message)
		}
	})

	// Test ping scan (Requirement 1.1: -sn flag support)
	t.Run("PingScan", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()

		// Request: targets=["127.0.0.1"], args=["-sn"]
		req := &toolspb.NmapRequest{
			Targets: []string{"127.0.0.1"},
			Args:    []string{"-sn"},
		}

		resp, err := tool.ExecuteProto(ctx, req)
		require.NoError(t, err, "ping scan should not error")
		require.NotNil(t, resp, "response should not be nil")

		nmapResp, ok := resp.(*toolspb.NmapResponse)
		require.True(t, ok, "response should be NmapResponse")

		// Verify: Response contains at least one host, host is up
		assert.Greater(t, nmapResp.TotalHosts, int32(0), "should find at least one host")
		assert.Greater(t, nmapResp.HostsUp, int32(0), "at least one host should be up")
		assert.NotEmpty(t, nmapResp.Hosts, "hosts list should not be empty")

		// Verify localhost is detected as up
		foundLocalhost := false
		for _, host := range nmapResp.Hosts {
			if host.Ip == "127.0.0.1" {
				foundLocalhost = true
				assert.Equal(t, "up", host.State, "localhost should be up")
			}
		}
		assert.True(t, foundLocalhost, "should find 127.0.0.1 in results")

		t.Logf("Ping scan results: %d hosts total, %d up", nmapResp.TotalHosts, nmapResp.HostsUp)
	})

	// Test port scan against localhost (Requirement 1.3: Port scanning)
	t.Run("PortScan", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		// Request: targets=["127.0.0.1"], args=["-p", "22,80,443", "-sT"]
		req := &toolspb.NmapRequest{
			Targets: []string{"127.0.0.1"},
			Args:    []string{"-p", "22,80,443", "-sT"},
		}

		resp, err := tool.ExecuteProto(ctx, req)
		require.NoError(t, err, "port scan should not error")
		require.NotNil(t, resp, "response should not be nil")

		nmapResp, ok := resp.(*toolspb.NmapResponse)
		require.True(t, ok, "response should be NmapResponse")

		// Verify: Response contains port scan results, output parsing works
		assert.Greater(t, nmapResp.TotalHosts, int32(0), "should find at least one host")
		assert.NotEmpty(t, nmapResp.Hosts, "hosts list should not be empty")

		// Find localhost and verify port information
		var localhostHost *toolspb.NmapHost
		for _, host := range nmapResp.Hosts {
			if host.Ip == "127.0.0.1" {
				localhostHost = host
				break
			}
		}
		require.NotNil(t, localhostHost, "should find 127.0.0.1 in results")

		// Verify port data is populated (at least some ports should be scanned)
		// Note: Not all ports may be open, but the structure should be valid
		t.Logf("Port scan found %d ports on 127.0.0.1", len(localhostHost.Ports))

		// If any ports are present, verify structure
		if len(localhostHost.Ports) > 0 {
			port := localhostHost.Ports[0]
			assert.NotEmpty(t, port.Protocol, "port should have protocol")
			assert.NotEmpty(t, port.State, "port should have state")
			assert.Greater(t, port.Number, int32(0), "port number should be positive")
		}
	})

	// Test with raw nmap arguments
	t.Run("RawArguments", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		// Request: targets=["127.0.0.1"], args=["-T4", "-sV", "-p", "22"]
		req := &toolspb.NmapRequest{
			Targets: []string{"127.0.0.1"},
			Args:    []string{"-T4", "-sV", "-p", "22"},
		}

		resp, err := tool.ExecuteProto(ctx, req)
		require.NoError(t, err, "service version scan should not error")
		require.NotNil(t, resp, "response should not be nil")

		nmapResp, ok := resp.(*toolspb.NmapResponse)
		require.True(t, ok, "response should be NmapResponse")

		// Verify: Args are passed correctly to nmap
		assert.Greater(t, nmapResp.TotalHosts, int32(0), "should find at least one host")

		// Find localhost
		var localhostHost *toolspb.NmapHost
		for _, host := range nmapResp.Hosts {
			if host.Ip == "127.0.0.1" {
				localhostHost = host
				break
			}
		}
		require.NotNil(t, localhostHost, "should find 127.0.0.1 in results")

		// If port 22 is present, verify service version was attempted
		for _, port := range localhostHost.Ports {
			if port.Number == 22 {
				t.Logf("Port 22 found - State: %s, Service: %+v", port.State, port.Service)
				// If the port is open, service detection should provide info
				if port.State == "open" && port.Service != nil {
					assert.NotEmpty(t, port.Service.Name, "open port 22 should have service name")
				}
			}
		}

		t.Logf("Service version scan completed: %d hosts, %d hosts up", nmapResp.TotalHosts, nmapResp.HostsUp)
	})

	// Test multiple targets
	t.Run("MultipleTargets", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping test in short mode")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		// Test with both 127.0.0.1 and localhost
		req := &toolspb.NmapRequest{
			Targets: []string{"127.0.0.1", "localhost"},
			Args:    []string{"-sn"},
		}

		resp, err := tool.ExecuteProto(ctx, req)
		require.NoError(t, err, "multi-target scan should not error")
		require.NotNil(t, resp, "response should not be nil")

		nmapResp, ok := resp.(*toolspb.NmapResponse)
		require.True(t, ok, "response should be NmapResponse")

		// Should find at least one host (both targets resolve to localhost)
		assert.Greater(t, nmapResp.TotalHosts, int32(0), "should find at least one host")
		t.Logf("Multi-target scan found %d hosts", nmapResp.TotalHosts)
	})

	// Test error handling - no targets
	t.Run("ErrorNoTargets", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		req := &toolspb.NmapRequest{
			Targets: []string{},
			Args:    []string{"-sn"},
		}

		_, err := tool.ExecuteProto(ctx, req)
		require.Error(t, err, "should error with no targets")
		assert.Contains(t, err.Error(), "at least one target is required")
	})

	// Test error handling - no args
	t.Run("ErrorNoArgs", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		req := &toolspb.NmapRequest{
			Targets: []string{"127.0.0.1"},
			Args:    []string{},
		}

		_, err := tool.ExecuteProto(ctx, req)
		require.Error(t, err, "should error with no args")
		assert.Contains(t, err.Error(), "at least one argument is required")
	})
}
