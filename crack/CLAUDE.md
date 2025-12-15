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
│   └── engagement/     # Engagement/target tracking (Python CLI)
├── reference/          # Command reference system
├── crackpedia/         # GUI command encyclopedia (Electron)
├── breach/             # GUI pentesting workspace (Electron)
├── shared/             # Shared TypeScript types for Electron apps
└── db/                 # Data storage, Neo4j migration
    └── data/           # JSON knowledge base
```

## Module References

| Module | CLAUDE.md | Purpose |
|--------|-----------|---------|
| db | `db/CLAUDE.md` | Command schema, validation, enrichment |
| reference | `reference/CLAUDE.md` | Registry, backends, CLI usage |
| crackpedia | `crackpedia/CLAUDE.md` | GUI command encyclopedia |
| breach | `breach/CLAUDE.md` | GUI pentesting workspace |

## Data Persistence Summary

| Component | Storage | Location |
|-----------|---------|----------|
| Commands, chains | JSON | `db/data/` |
| User config | JSON | `~/.crack/config.json` |
| Chain sessions | JSON | `~/.crack/chain_sessions/` |
| Listeners | JSON | `~/.crack/sessions/` |
| Active engagement | JSON | `~/.crack/engagement.json` |
| Graph queries | Neo4j | `bolt://localhost:7687` |
| Engagement data | Neo4j | Engagement, Target, Service, Credential, Loot nodes |
| BloodHound data | Neo4j | Separate database |

## Engagement Tracking

Simplified engagement/target tracking with Neo4j persistence. No client/organization layer - each engagement is a standalone workspace.

### Graph Model
```
(:Engagement)─[:TARGETS]→(:Target)─[:HAS_SERVICE]→(:Service)
      │
      ├─[:HAS_CREDENTIAL]→(:Credential)─[:GRANTS_ACCESS]→(:Service)
      │
      ├─[:HAS_FINDING]→(:Finding)─[:AFFECTS]→(:Target)
      │
      └─[:HAS_LOOT]→(:Loot)
```

### CLI Commands (Python)
```bash
# Engagement Management
crack engagement create "OSCP Lab"
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

### GUI (B.R.E.A.C.H.)
```bash
cd breach && ./start.sh   # Launch workspace GUI
```
- Terminal multiplexer with PTY sessions
- Engagement selector dropdown
- Credential vault and loot tracking
- Target sidebar with status indicators

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

## GUI Applications

### Crackpedia (Command Encyclopedia)
```bash
crackpedia              # Normal mode
crackpedia debug        # Debug mode
```
- Command search across 734+ commands
- Graph visualization of command relationships
- Attack chain workflows
- Cheatsheets and writeups

See `crackpedia/CLAUDE.md` for development guide.

### B.R.E.A.C.H. (Pentesting Workspace)
```bash
cd breach && ./start.sh   # Launch workspace
```
- Terminal multiplexer with xterm.js + node-pty
- Engagement navigation (switch between workspaces)
- Credential vault (discovered creds with "Use" action)
- Loot tracking (flags, SSH keys, configs)
- Target sidebar (machines by status)

See `breach/CLAUDE.md` for development guide.

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

1. **B.R.E.A.C.H. Topology View** - Cytoscape graph showing session relationships
2. **Finding Tracker** - Vulnerability management with severity levels
3. **PRISM Integration** - Auto-parse credentials from terminal output
4. **Report Generation** - Export engagement findings to markdown/PDF
5. **Attack Timeline** - Reconstruct attack sequence from session history

## Philosophy

```
"Failed attempts documented well teach more than lucky successes explained poorly."
```

Focus on:
- Manual methodology over tool memorization
- Documentation of failures (critical for OSCP)
- Time tracking for exam planning
- Tool-independent exploitation skills
