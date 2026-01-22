# Makefile for Gibson Tools Ecosystem
# Build, test, and manage all security tools with embedded GraphRAG taxonomy

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOWORK=$(GOCMD) work

# Build parameters
BIN_DIR=bin
BUILD_FLAGS=
VERBOSE_FLAG=

# Tool directories - only tools with embedded GraphRAG taxonomy
# Reconnaissance Tools (TA0043)
RECON_TOOLS := \
	reconnaissance/httpx \
	reconnaissance/nuclei

# Discovery Tools (TA0007)
DISCOVERY_TOOLS := \
	discovery/nmap

# Fingerprinting Tools (TA0015)
FINGERPRINTING_TOOLS := \
	fingerprinting/wappalyzer \
	fingerprinting/whatweb \
	fingerprinting/testssl \
	fingerprinting/sslyze

# All tools combined
ALL_TOOLS := \
	$(RECON_TOOLS) \
	$(DISCOVERY_TOOLS) \
	$(FINGERPRINTING_TOOLS)

# Binary names (extract basename from paths)
BINARIES := $(foreach tool,$(ALL_TOOLS),$(BIN_DIR)/$(notdir $(tool)))

# Default target
.DEFAULT_GOAL := all

# Phony targets
.PHONY: all bin build test integration-test clean help \
	build-recon build-discovery build-fingerprinting \
	verify deps tidy fmt vet lint

# Help target - display available targets
help:
	@echo "Gibson Tools Ecosystem - Build System"
	@echo "======================================"
	@echo ""
	@echo "All tools include embedded GraphRAG taxonomy for knowledge graph integration."
	@echo ""
	@echo "Available targets:"
	@echo "  all              - Build and test all tools (default)"
	@echo "  bin              - Alias for build (consistency with other components)"
	@echo "  build            - Build all tools to bin/ directory"
	@echo "  test             - Run all unit tests"
	@echo "  integration-test - Run integration tests (requires binaries installed)"
	@echo "  clean            - Remove all build artifacts"
	@echo "  verify           - Verify dependencies and run tests"
	@echo "  deps             - Download and verify dependencies"
	@echo "  tidy             - Tidy go modules"
	@echo "  fmt              - Format all Go code"
	@echo "  vet              - Run go vet on all packages"
	@echo "  lint             - Run golangci-lint (if available)"
	@echo ""
	@echo "Phase-specific build targets:"
	@echo "  build-recon        - Build reconnaissance tools (httpx, nuclei)"
	@echo "  build-discovery    - Build discovery tools (nmap)"
	@echo "  build-fingerprinting - Build fingerprinting tools (wappalyzer, whatweb, testssl, sslyze)"
	@echo ""
	@echo "Examples:"
	@echo "  make              # Build and test all tools"
	@echo "  make build        # Build all tools"
	@echo "  make test         # Run unit tests"
	@echo "  make clean        # Clean build artifacts"
	@echo "  make build-recon  # Build only reconnaissance tools"

# All target - build and test
all: build test

# Alias for build (consistency with other components)
bin: build

# Build all tools (tidy first to ensure deps are current)
build: tidy build-dir
	@echo "Building all Gibson Tools..."
	@$(MAKE) --no-print-directory $(BINARIES)
	@echo "Build complete! Binaries are in $(BIN_DIR)/"

# Create bin directory (separate target to avoid conflict with 'bin' alias)
.PHONY: build-dir
build-dir:
	@mkdir -p $(BIN_DIR)

# Generic build rule for individual tools
$(BIN_DIR)/%: */%
	@mkdir -p $(BIN_DIR)
	@tool_path=$$(find . -type d -name "$*" | head -1); \
	if [ -z "$$tool_path" ]; then \
		echo "Error: Could not find tool $*"; \
		exit 1; \
	fi; \
	if [ ! -f "$$tool_path/main.go" ]; then \
		echo "Warning: No main.go found in $$tool_path, skipping"; \
		exit 0; \
	fi; \
	echo "Building $*..."; \
	cd $$tool_path && $(GOBUILD) $(BUILD_FLAGS) -o ../../$(BIN_DIR)/$* . && \
	echo "  ✓ Built $* ($$(du -h ../../$(BIN_DIR)/$* | cut -f1))"

# Phase-specific build targets
build-recon: build-dir
	@echo "Building Reconnaissance tools..."
	@$(foreach tool,$(RECON_TOOLS),$(MAKE) --no-print-directory $(BIN_DIR)/$(notdir $(tool));)

build-discovery: build-dir
	@echo "Building Discovery tools..."
	@$(foreach tool,$(DISCOVERY_TOOLS),$(MAKE) --no-print-directory $(BIN_DIR)/$(notdir $(tool));)

build-fingerprinting: build-dir
	@echo "Building Fingerprinting tools..."
	@$(foreach tool,$(FINGERPRINTING_TOOLS),$(MAKE) --no-print-directory $(BIN_DIR)/$(notdir $(tool));)

# Run all unit tests
test:
	@echo "Running unit tests..."
	@for dir in $(ALL_TOOLS); do \
		if [ -d "$$dir" ] && [ -f "$$dir/go.mod" ]; then \
			echo "Testing $$dir..."; \
			cd $$dir && $(GOTEST) -v . && cd - > /dev/null || exit 1; \
		fi; \
	done
	@echo "All tests passed!"

# Run integration tests (requires actual binaries installed)
integration-test:
	@echo "Running integration tests..."
	@echo "Note: Integration tests require actual security tools to be installed"
	@for dir in $(ALL_TOOLS); do \
		if [ -d "$$dir" ] && [ -f "$$dir/go.mod" ]; then \
			echo "Integration testing $$dir..."; \
			cd $$dir && $(GOTEST) -v -tags=integration . && cd - > /dev/null || exit 1; \
		fi; \
	done
	@echo "All integration tests passed!"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BIN_DIR)
	@$(GOCLEAN) -cache
	@echo "Clean complete!"

# Verify dependencies and run tests
verify: deps test
	@echo "Verification complete!"

# Download and verify dependencies
deps:
	@echo "Downloading dependencies..."
	@$(GOWORK) sync
	@echo "Dependencies downloaded!"

# Tidy go modules
tidy:
	@echo "Tidying modules..."
	@for dir in $(ALL_TOOLS); do \
		if [ -f "$$dir/go.mod" ]; then \
			echo "  Tidying $$dir..."; \
			cd $$dir && $(GOMOD) tidy -v 2>&1 | sed 's/^/    /' && cd - > /dev/null; \
		fi; \
	done
	@echo "Modules tidied!"

# Format all Go code
fmt:
	@echo "Formatting Go code..."
	@gofmt -w -s .
	@echo "Code formatted!"

# Run go vet on all packages
vet:
	@echo "Running go vet..."
	@$(GOCMD) vet ./...
	@echo "Vet complete!"

# Run golangci-lint (if available)
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed, skipping..."; \
		echo "Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# Show build statistics
stats: build
	@echo ""
	@echo "Build Statistics"
	@echo "================"
	@echo "Total tools: $$(ls -1 $(BIN_DIR) | wc -l)"
	@echo "Total size: $$(du -sh $(BIN_DIR) | cut -f1)"
	@echo ""
	@echo "By phase:"
	@echo "  Reconnaissance: $(words $(RECON_TOOLS))"
	@echo "  Discovery: $(words $(DISCOVERY_TOOLS))"
	@echo ""
	@echo "Binaries:"
	@ls -lh $(BIN_DIR) | tail -n +2
