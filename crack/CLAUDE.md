# CRACK - Claude Code Reference

## Project Overview

**C.R.A.C.K.** = Comprehensive Recon & Attack Creation Kit
Professional pentesting toolkit for OSCP preparation.

**Architecture Doc**: See `ARCHITECTURE.md` for full inventory of tools, data persistence, and Neo4j unification plan.

## Quick Stats

| Metric | Count |
|--------|-------|
| Python files | 290+ |
| CLI commands | 20 |
| Command definitions | 163+ |
| Attack chains | 50+ |
| Modules | 4 (core, tools, reference, db) |

## Directory Structure

```
crack/
├── cli.py              # Main entry point
├── core/               # Config, themes, utilities
├── tools/
│   ├── recon/          # Network, web, SQLi scanning
│   ├── post/           # BloodTrail, PRISM, Sessions
│   └── engagement/     # Client/engagement/target tracking
├── reference/          # Command reference system
├── crackpedia/         # GUI command encyclopedia (Electron)
└── db/                 # Data storage, Neo4j migration
    └── data/           # JSON knowledge base
```

## Module References

| Module | CLAUDE.md | Purpose |
|--------|-----------|---------|
| db | `db/CLAUDE.md` | Command schema, validation, enrichment |
| reference | `reference/CLAUDE.md` | Registry, backends, CLI usage |
| crackpedia | `crackpedia/CLAUDE.md` | GUI development, Electron/React |

## Data Persistence Summary

| Component | Storage | Location |
|-----------|---------|----------|
| Commands, chains | JSON | `db/data/` |
| User config | JSON | `~/.crack/config.json` |
| Chain sessions | JSON | `~/.crack/chain_sessions/` |
| Listeners | JSON | `~/.crack/sessions/` |
| Active engagement | JSON | `~/.crack/engagement.json` |
| Graph queries | Neo4j | `bolt://localhost:7687` |
| Engagement data | Neo4j | Client, Engagement, Target, Finding, Service nodes |
| BloodHound data | Neo4j | Separate database |

## Engagement Tracking (NEW)

Unified client/engagement/target tracking with Neo4j persistence.

### Graph Model
```
(:Client)─[:HAS_ENGAGEMENT]→(:Engagement)─[:TARGETS]→(:Target)─[:HAS_SERVICE]→(:Service)
                                    └─[:HAS_FINDING]→(:Finding)─[:AFFECTS]→(:Target)
                                                           └─[:EXPLOITS]→(:CVE)
```

### CLI Commands
```bash
# Client Management
crack engagement client create "ACME Corp"
crack engagement client list

# Engagement Management
crack engagement create "Q4 Pentest" --client <id>
crack engagement list
crack engagement activate <id>
crack engagement status

# Target Management
crack target add <ip> --hostname <name>
crack target list
crack target services <id>
crack target service-add <id> <port>

# Finding Management
crack finding add "SQL Injection" --severity critical
crack finding list
crack finding link <finding_id> --target <target_id>
```

### Tool Integration
When an engagement is active, tools auto-log data:
- **port_scanner.py** - Logs discovered services
- **PRISM adapter** - Links credentials to targets
- **SessionManager** - Logs shells as critical findings

### Integration API
```python
from crack.tools.engagement import EngagementIntegration

if EngagementIntegration.is_active():
    target_id = EngagementIntegration.ensure_target("192.168.1.100")
    EngagementIntegration.add_service(target_id, 80, service_name="http")
    EngagementIntegration.add_finding("SQLi", severity="critical", target_id=target_id)
```

## CLI Commands

```bash
# Recon
crack port-scan <target>      # Two-stage port scanning
crack enum-scan <target>      # Fast enum + CVE lookup
crack html-enum <url>         # HTML/DOM extraction
crack sqli-scan <url>         # SQLi detection

# Post-exploitation
crack bloodtrail              # BloodHound analysis (Neo4j)
crack prism <file>            # Parse mimikatz/nmap output
crack session                 # Reverse shell management

# Engagement Tracking
crack engagement status       # Show active engagement
crack target list             # List engagement targets
crack finding list            # List findings

# Reference
crack reference <query>       # Command lookup
crack cheatsheets             # Educational collections
crack config set <var> <val>  # Variable management

# GUI
crackpedia                    # Launch visual command encyclopedia
```

## Crackpedia (GUI)

Electron-based visual command encyclopedia. Launch with:

```bash
crackpedia              # Normal mode
crackpedia debug        # Debug mode
crackpedia verbose      # Maximum verbosity
```

Features:
- **Command Search** - Full-text search across 734+ commands
- **Graph Visualization** - Interactive relationship explorer
- **Attack Chains** - Multi-step workflow visualization
- **Cheatsheets** - Educational reference sheets
- **Writeups** - Machine walkthrough viewer

See `crackpedia/CLAUDE.md` for development guide.

## Development Guidelines

### Adding Commands
```bash
# 1. Add to db/data/commands/{category}/{subcategory}.json
# 2. No reinstall needed - registry loads JSON dynamically
# 3. Validate: crack reference --validate
```

### Schema Rules
- Command IDs: `kebab-case`, globally unique
- Variables: `<UPPERCASE_ANGLE_BRACKETS>`
- Links: Use command IDs only (not text)
- Required tag: `OSCP:HIGH|MEDIUM|LOW`

### Backend Selection
CLI auto-detects in order:
1. Neo4j (if configured)
2. SQL (`~/.crack/crack.db`)
3. JSON (fallback)

## Key Files

| Purpose | Path |
|---------|------|
| Main CLI | `cli.py` |
| Neo4j config | `db/config.py` |
| Neo4j adapter | `reference/core/neo4j_adapter.py` |
| Config manager | `core/config/manager.py` |
| Command schema | `db/schemas/command.schema.json` |
| Migration pipeline | `db/neo4j-migration/` |
| Engagement adapter | `tools/engagement/adapter.py` |
| Engagement CLI | `tools/engagement/cli.py` |
| Engagement integration | `tools/engagement/integration.py` |
| Engagement models | `tools/engagement/models.py` |

## Testing

```bash
# Validation
crack reference --validate
crack reference --stats

# Database
python3 db/neo4j-migration/scripts/import_to_neo4j.py
python3 db/verify_neo4j_import.py

# Engagement
crack engagement status
crack target list
```

## Environment

```bash
# Neo4j (required for engagement tracking)
export NEO4J_URI='bolt://localhost:7687'
export NEO4J_PASSWORD='your_password'

# Config auto-detection
crack config auto  # Detects LHOST, INTERFACE
```

## What Needs Building

Priority items remaining:

1. **Session Migration** - Move chain sessions to Neo4j
2. **Progress Dashboard** - Engagement progress visualization
3. **Report Generation** - Export engagement findings to markdown/PDF
4. **Attack Timeline** - Reconstruct attack sequence from engagement data

## Philosophy

```
"Failed attempts documented well teach more than lucky successes explained poorly."
```

Focus on:
- Manual methodology over tool memorization
- Documentation of failures (critical for OSCP)
- Time tracking for exam planning
- Tool-independent exploitation skills
