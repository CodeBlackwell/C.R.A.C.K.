# BloodTrail - BloodHound Attack Path Enhancement

Edge enhancement and Cypher query analysis for BloodHound/Neo4j.

## Features

- **Edge Enhancement**: Import missing edges (AdminTo, GenericAll, MemberOf, etc.) from SharpHound JSON exports
- **Query Library**: 63+ pre-built Cypher queries for attack path discovery
- **ZIP Support**: Process SharpHound ZIP output directly (no extraction needed)
- **Command Suggestions**: Auto-suggest exploitation commands based on discovered paths

## Quick Start

```bash
# Enhance edges from SharpHound ZIP
crack bloodtrail /path/to/sharphound_output.zip --preset attack-paths

# Enhance edges from directory
crack bloodtrail /path/to/bh/json/ --preset attack-paths

# List available queries
crack bloodtrail --list-queries

# Run a specific query
crack bloodtrail --run-query lateral-adminto-nonpriv

# Search queries
crack bloodtrail --search-query DCSync
```

## Presets

- `attack-paths`: High-value attack path edges (AdminTo, DCSync, GenericAll)
- `all`: All available edge types
- `minimal`: Essential edges only

## Neo4j Connection

Default connection: `bolt://localhost:7687`

Configure via environment or `~/.crack/config.json`:
```json
{
  "bloodtrail": {
    "neo4j_uri": "bolt://localhost:7687",
    "neo4j_user": "neo4j",
    "neo4j_password": "your_password"
  }
}
```

## Architecture

```
bloodtrail/
├── cli.py              # CLI interface
├── main.py             # BHEnhancer core logic
├── extractors.py       # Edge extraction from JSON
├── query_runner.py     # Cypher query execution
├── command_suggester.py # Attack path → command mapping
├── cypher_queries/     # Pre-built query library
└── display/            # Output formatting
```
