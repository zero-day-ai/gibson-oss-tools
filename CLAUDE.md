# Gibson Tools Development Guide

Open source tool wrappers with embedded GraphRAG taxonomy for knowledge graph integration.

## Purpose

This repository provides Gibson-compatible tool wrappers that:
- Wrap common security tools (nmap, subfinder, httpx, etc.)
- Output structured JSON with GraphRAG taxonomy mappings
- Enable automatic knowledge graph population

## Architecture

```
tools/
├── reconnaissance/      # Reconnaissance tools (TA0043)
│   ├── subfinder/       # Subdomain enumeration
│   ├── httpx/           # HTTP probing
│   ├── amass/           # Attack surface mapping
│   └── nuclei/          # Vulnerability scanning
├── discovery/           # Discovery tools (TA0007)
│   ├── nmap/            # Port scanning
│   └── masscan/         # Fast TCP scanning
├── bin/                 # Built binaries
└── Makefile
```

## Tool Requirements

Each tool wrapper:
1. Wraps an underlying binary (must be installed on host)
2. Accepts JSON input via stdin or `--input` flag
3. Outputs structured JSON with taxonomy mappings
4. Supports `--schema` flag to output JSON schema

## GraphRAG Taxonomy Integration

Tools embed taxonomy mappings in their schema:

```json
{
  "taxonomy": {
    "node_type": "host",
    "identifying_properties": {
      "ip": "$.ip"
    },
    "properties": [
      {"source": "ip", "target": "ip"}
    ],
    "relationships": [
      {
        "type": "DISCOVERED",
        "from": {
          "type": "agent_run",
          "properties": {
            "agent_run_id": "$._context.agent_run_id"
          }
        },
        "to": {
          "type": "self"
        }
      }
    ]
  }
}
```

This allows Gibson to automatically:
- Create graph nodes from tool output
- Establish relationships between discovered entities
- Link discoveries to agent runs

## Development

### Adding a New Tool

1. Create directory under appropriate category
2. Implement tool wrapper with schema
3. Include taxonomy mappings for output types
4. Add to Makefile

```go
// Example tool schema using SDK schema package
import "github.com/zero-day-ai/sdk/schema"

func OutputSchema() schema.JSON {
    // Host schema with taxonomy mapping
    hostSchema := schema.Object(map[string]schema.JSON{
        "ip":       schema.String(),
        "hostname": schema.String(),
        "state":    schema.String(),
    }).WithTaxonomy(schema.TaxonomyMapping{
        NodeType: "host",
        // IdentifyingProperties define what makes this node unique
        IdentifyingProperties: map[string]string{
            "ip": "ip",  // property name -> JSONPath in output
        },
        // Regular properties to copy to the node
        Properties: []schema.PropertyMapping{
            schema.PropMap("ip", "ip"),
            schema.PropMap("hostname", "hostname"),
        },
        // Relationships use NodeReference objects
        Relationships: []schema.RelationshipMapping{
            schema.Rel("DISCOVERED",
                schema.Node("agent_run", map[string]string{
                    "agent_run_id": "_context.agent_run_id",
                }),
                schema.SelfNode(),  // Current node being mapped
            ),
        },
    })

    return schema.Object(map[string]schema.JSON{
        "hosts": schema.Array(hostSchema),
    })
}
```

### Taxonomy API Reference

**Key structs:**
- `schema.TaxonomyMapping` - Defines how output maps to graph nodes
- `schema.NodeReference` - References a node by type and identifying properties
- `schema.PropertyMapping` - Maps source field to target property

**Helper functions:**
- `schema.PropMap(source, target)` - Create property mapping
- `schema.Node(type, props)` - Create NodeReference to another node
- `schema.SelfNode()` - Reference the current node being mapped
- `schema.Rel(type, from, to)` - Create relationship between NodeReferences

### Building

**IMPORTANT: AI agents must use make commands, not raw go commands.**

```bash
# Build all tools
make build

# Build specific category
make build-recon
make build-discovery
make build-fingerprinting

# Test
make test
make integration-test

# Code quality
make lint
make fmt
make vet

# Clean
make clean

# See all available targets
make help
```

### DON'T: Use Raw Go Commands

```bash
# NEVER do these - they bypass Makefile configuration
go build ./...               # Use: make build
go test ./...                # Use: make test
```

### Running Tools

```bash
# View schema with taxonomy
./bin/nmap --schema

# Run with JSON input
echo '{"targets": "192.168.1.0/24"}' | ./bin/nmap

# Direct input
./bin/subfinder --input '{"domain": "example.com"}'
```

## Required Host Tools

Underlying tools must be installed:
- `nmap` - Network scanning
- `masscan` - Fast port scanning
- `subfinder` - Subdomain enumeration
- `httpx` - HTTP probing
- `amass` - Attack surface mapping
- `nuclei` - Vulnerability scanning

## Spec Workflow

**IMPORTANT**: The spec-workflow directory ALWAYS lives at `~/Code/zero-day.ai/.spec-workflow`

All specifications, requirements, design documents, and task breakdowns are managed through the spec-workflow MCP tools and stored in this central location, regardless of which subdirectory you're working in.

## See Also

- `../sdk/CLAUDE.md` - SDK tool development guide
- `../sdk/tool/` - Tool interface definitions
- `../gibson/internal/registry/` - Tool registration in Gibson
