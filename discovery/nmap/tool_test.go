package main

import (
	"errors"
	"testing"

	"github.com/zero-day-ai/sdk/toolerr"
)

func TestClassifyExecutionError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected toolerr.ErrorClass
	}{
		{
			name:     "binary not found",
			err:      errors.New("exec: \"nmap\": executable file not found in $PATH"),
			expected: toolerr.ErrorClassInfrastructure,
		},
		{
			name:     "binary not found alternative",
			err:      errors.New("nmap not found"),
			expected: toolerr.ErrorClassInfrastructure,
		},
		{
			name:     "timeout error",
			err:      errors.New("command timed out after 30s"),
			expected: toolerr.ErrorClassTransient,
		},
		{
			name:     "deadline exceeded",
			err:      errors.New("context deadline exceeded"),
			expected: toolerr.ErrorClassTransient,
		},
		{
			name:     "permission denied",
			err:      errors.New("permission denied: requires root"),
			expected: toolerr.ErrorClassInfrastructure,
		},
		{
			name:     "access denied",
			err:      errors.New("access denied"),
			expected: toolerr.ErrorClassInfrastructure,
		},
		{
			name:     "network error",
			err:      errors.New("network unreachable"),
			expected: toolerr.ErrorClassTransient,
		},
		{
			name:     "connection error",
			err:      errors.New("connection refused"),
			expected: toolerr.ErrorClassTransient,
		},
		{
			name:     "host unreachable",
			err:      errors.New("host unreachable"),
			expected: toolerr.ErrorClassTransient,
		},
		{
			name:     "no route to host",
			err:      errors.New("no route to host"),
			expected: toolerr.ErrorClassTransient,
		},
		{
			name:     "cancelled",
			err:      errors.New("command cancelled"),
			expected: toolerr.ErrorClassTransient,
		},
		{
			name:     "canceled",
			err:      errors.New("context canceled"),
			expected: toolerr.ErrorClassTransient,
		},
		{
			name:     "unknown error",
			err:      errors.New("some unknown error occurred"),
			expected: toolerr.ErrorClassTransient,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: toolerr.ErrorClassTransient,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyExecutionError(tt.err)
			if got != tt.expected {
				t.Errorf("classifyExecutionError() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestParseOutput(t *testing.T) {
	t.Run("parse error should have semantic class", func(t *testing.T) {
		// Test with invalid XML
		invalidXML := []byte("this is not valid XML")
		_, err := parseOutput(invalidXML)

		if err == nil {
			t.Fatal("expected error from invalid XML, got nil")
		}

		// The error from parseOutput is just a regular error
		// But when wrapped in the Execute function, it should get ErrorClassSemantic
		// This test validates that parseOutput returns an error for invalid input
	})

	t.Run("valid XML should parse successfully", func(t *testing.T) {
		validXML := []byte(`<?xml version="1.0"?>
<nmaprun>
	<host>
		<status state="up"/>
		<address addr="192.168.1.1" addrtype="ipv4"/>
		<hostnames>
			<hostname name="test.local" type="user"/>
		</hostnames>
		<ports>
			<port protocol="tcp" portid="80">
				<state state="open"/>
				<service name="http" product="nginx" version="1.20.0"/>
			</port>
		</ports>
		<os>
			<osmatch name="Linux 5.4" accuracy="95"/>
		</os>
	</host>
</nmaprun>`)

		result, err := parseOutput(validXML)
		if err != nil {
			t.Fatalf("unexpected error parsing valid XML: %v", err)
		}

		// Validate host
		if len(result.Hosts) != 1 {
			t.Fatalf("expected 1 host, got %d", len(result.Hosts))
		}

		host := result.Hosts[0]
		if host.IP != "192.168.1.1" {
			t.Errorf("expected ip=192.168.1.1, got %v", host.IP)
		}

		if host.Hostname != "test.local" {
			t.Errorf("expected hostname=test.local, got %v", host.Hostname)
		}

		if host.State != "up" {
			t.Errorf("expected state=up, got %v", host.State)
		}

		if host.OS != "Linux 5.4" {
			t.Errorf("expected os='Linux 5.4', got %v", host.OS)
		}

		// Validate port
		if len(result.Ports) != 1 {
			t.Fatalf("expected 1 port, got %d", len(result.Ports))
		}

		port := result.Ports[0]
		if port.HostID != "192.168.1.1" {
			t.Errorf("expected hostID=192.168.1.1, got %v", port.HostID)
		}

		if port.Number != 80 {
			t.Errorf("expected port=80, got %v", port.Number)
		}

		if port.Protocol != "tcp" {
			t.Errorf("expected protocol=tcp, got %v", port.Protocol)
		}

		if port.State != "open" {
			t.Errorf("expected state=open, got %v", port.State)
		}

		// Validate service
		if len(result.Services) != 1 {
			t.Fatalf("expected 1 service, got %d", len(result.Services))
		}

		service := result.Services[0]
		if service.PortID != "192.168.1.1:80:tcp" {
			t.Errorf("expected portID=192.168.1.1:80:tcp, got %v", service.PortID)
		}

		if service.Name != "http" {
			t.Errorf("expected service name=http, got %v", service.Name)
		}

		if service.Version != "nginx 1.20.0" {
			t.Errorf("expected version='nginx 1.20.0', got %v", service.Version)
		}
	})

	t.Run("service should not be created when service name is empty", func(t *testing.T) {
		xmlWithNoService := []byte(`<?xml version="1.0"?>
<nmaprun>
	<host>
		<status state="up"/>
		<address addr="192.168.1.1" addrtype="ipv4"/>
		<ports>
			<port protocol="tcp" portid="80">
				<state state="open"/>
				<service name=""/>
			</port>
		</ports>
	</host>
</nmaprun>`)

		result, err := parseOutput(xmlWithNoService)
		if err != nil {
			t.Fatalf("unexpected error parsing XML: %v", err)
		}

		// Port should exist but service should not
		if len(result.Ports) != 1 {
			t.Fatalf("expected 1 port, got %d", len(result.Ports))
		}

		if len(result.Services) != 0 {
			t.Errorf("expected 0 services when service name is empty, got %d", len(result.Services))
		}
	})

	t.Run("multiple ports with services", func(t *testing.T) {
		xmlWithMultiplePorts := []byte(`<?xml version="1.0"?>
<nmaprun>
	<host>
		<status state="up"/>
		<address addr="192.168.1.1" addrtype="ipv4"/>
		<ports>
			<port protocol="tcp" portid="22">
				<state state="open"/>
				<service name="ssh" product="OpenSSH" version="8.2p1"/>
			</port>
			<port protocol="tcp" portid="80">
				<state state="open"/>
				<service name="http" product="nginx" version="1.20.0"/>
			</port>
		</ports>
	</host>
</nmaprun>`)

		result, err := parseOutput(xmlWithMultiplePorts)
		if err != nil {
			t.Fatalf("unexpected error parsing XML: %v", err)
		}

		if len(result.Ports) != 2 {
			t.Fatalf("expected 2 ports, got %d", len(result.Ports))
		}

		if len(result.Services) != 2 {
			t.Fatalf("expected 2 services, got %d", len(result.Services))
		}

		// Check first service (SSH)
		sshService := result.Services[0]
		if sshService.Name != "ssh" {
			t.Errorf("expected first service name=ssh, got %v", sshService.Name)
		}

		if sshService.PortID != "192.168.1.1:22:tcp" {
			t.Errorf("expected SSH portID=192.168.1.1:22:tcp, got %v", sshService.PortID)
		}

		// Check second service (HTTP)
		httpService := result.Services[1]
		if httpService.Name != "http" {
			t.Errorf("expected second service name=http, got %v", httpService.Name)
		}

		if httpService.PortID != "192.168.1.1:80:tcp" {
			t.Errorf("expected HTTP portID=192.168.1.1:80:tcp, got %v", httpService.PortID)
		}
	})
}

func TestBuildArgs(t *testing.T) {
	tests := []struct {
		name              string
		target            string
		ports             string
		scanType          string
		serviceDetection  bool
		osDetection       bool
		scripts           []string
		timing            int
		expectedContains  []string
		expectedNotContains []string
	}{
		{
			name:             "ping scan",
			target:           "192.168.1.1",
			ports:            "80",
			scanType:         "ping",
			serviceDetection: false,
			osDetection:      false,
			scripts:          nil,
			timing:           3,
			expectedContains: []string{"-sn", "-T3", "192.168.1.1"},
			expectedNotContains: []string{"-p", "80"},
		},
		{
			name:             "connect scan with service detection",
			target:           "192.168.1.1",
			ports:            "22,80,443",
			scanType:         "connect",
			serviceDetection: true,
			osDetection:      false,
			scripts:          nil,
			timing:           4,
			expectedContains: []string{"-sT", "-sV", "-p", "22,80,443", "-T4", "192.168.1.1"},
		},
		{
			name:             "syn scan with os detection",
			target:           "192.168.1.1",
			ports:            "1-1000",
			scanType:         "syn",
			serviceDetection: false,
			osDetection:      true,
			scripts:          nil,
			timing:           3,
			expectedContains: []string{"-sS", "-O", "-p", "1-1000", "-T3", "192.168.1.1"},
		},
		{
			name:             "scan with scripts",
			target:           "192.168.1.1",
			ports:            "80",
			scanType:         "connect",
			serviceDetection: false,
			osDetection:      false,
			scripts:          []string{"http-enum", "http-headers"},
			timing:           3,
			expectedContains: []string{"-sT", "--script", "http-enum,http-headers", "192.168.1.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := buildArgs(tt.target, tt.ports, tt.scanType, tt.serviceDetection, tt.osDetection, tt.scripts, tt.timing)

			// Check that expected arguments are present
			for _, expected := range tt.expectedContains {
				found := false
				for _, arg := range args {
					if arg == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected argument %q not found in args: %v", expected, args)
				}
			}

			// Check that unexpected arguments are not present
			for _, unexpected := range tt.expectedNotContains {
				for _, arg := range args {
					if arg == unexpected {
						t.Errorf("unexpected argument %q found in args: %v", unexpected, args)
					}
				}
			}
		})
	}
}
