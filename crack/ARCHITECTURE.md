# CRACK Architecture

## Overview

CRACK (Comprehensive Recon & Attack Creation Kit) is a modular pentesting toolkit designed for OSCP preparation. The architecture follows a layered approach with clear separation between core utilities, specialized tools, and data persistence.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLI Entry Point                          │
│                          crack.cli                              │
└─────────────────────────────┬───────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐   ┌─────────────────┐   ┌─────────────────┐
│     Tools     │   │    Reference    │   │       DB        │
│  (Execution)  │   │  (Knowledge)    │   │  (Persistence)  │
└───────┬───────┘   └────────┬────────┘   └────────┬────────┘
        │                    │                     │
        ▼                    ▼                     ▼
┌───────────────────────────────────────────────────────────────┐
│                          Core                                  │
│              (Config, Themes, Utilities)                       │
└───────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
crack/
├── cli.py                 # Main entry point
├── core/                  # Foundation layer
│   ├── config/           # Configuration management
│   ├── themes/           # Terminal theming
│   └── utils/            # Shared utilities
├── tools/                 # Execution layer
│   ├── recon/            # Reconnaissance tools
│   │   ├── network/      # Port scanning, service enum
│   │   ├── web/          # HTML parsing, spider
│   │   └── sqli/         # SQL injection detection
│   ├── post/             # Post-exploitation
│   │   ├── bloodtrail/   # AD attack path analysis
│   │   ├── prism/        # Credential parsing
│   │   └── sessions/     # Shell management
│   └── engagement/       # Target tracking
├── reference/             # Knowledge layer
│   ├── core/             # Backend adapters
│   ├── chains/           # Attack chain execution
│   └── cli/              # Interactive mode
├── db/                    # Data layer
│   └── data/             # JSON knowledge base
│       ├── commands/     # 163+ command definitions
│       ├── chains/       # 50+ attack chains
│       └── cheatsheets/  # Educational collections
├── crackpedia/           # GUI: Command encyclopedia (Electron)
├── breach/               # GUI: Pentesting workspace (Electron)
└── shared/               # Shared TypeScript types
```

## Component Details

### Core Layer (`core/`)

Foundation utilities used across all modules:

| Component | Purpose |
|-----------|---------|
| `config/manager.py` | Configuration loading and env vars |
| `themes/` | Rich terminal color schemes |
| `utils/` | Common helpers (logging, paths) |

### Tools Layer (`tools/`)

Active execution tools for penetration testing:

#### Reconnaissance (`tools/recon/`)
- **network/** - Two-stage port scanning, service enumeration
- **web/** - HTML DOM extraction, endpoint discovery
- **sqli/** - SQL injection detection and exploitation

#### Post-Exploitation (`tools/post/`)
- **bloodtrail/** - BloodHound data analysis, AD attack paths
- **prism/** - Parse mimikatz, SAM dumps, LDAP output
- **sessions/** - Reverse shell management, listeners

#### Engagement (`tools/engagement/`)
- Target and finding tracking with Neo4j persistence

### Reference Layer (`reference/`)

Command knowledge base and execution:

| Component | Purpose |
|-----------|---------|
| `core/registry.py` | Command lookup across backends |
| `core/neo4j_adapter.py` | Graph database queries |
| `chains/` | Attack chain parsing and execution |
| `cli/interactive.py` | Menu-driven interface |

### Data Layer (`db/`)

Persistent storage for knowledge and configuration:

```
db/data/
├── commands/           # Atomic command definitions
│   ├── enumeration/   # 198 recon commands
│   ├── web/           # 245 web exploitation
│   ├── exploitation/  # 156 exploitation
│   └── post-exploit/  # 102 post-exploitation
├── chains/             # Attack sequences
└── cheatsheets/        # Educational collections
```

## Data Flow

### Command Lookup

```
User Query → Registry → Backend Selection → Response
                           │
            ┌──────────────┼──────────────┐
            │              │              │
        Neo4j           SQLite         JSON
     (graph ops)    (relational)    (fallback)
```

### Attack Chain Execution

```
Chain Definition → Variable Resolution → Step Execution → State Tracking
       │                   │                   │               │
   JSON file        User prompts        Tool dispatch    Session save
```

## GUI Applications

### Crackpedia (Electron)

Visual command encyclopedia:
- Search across 734+ commands
- Graph visualization of relationships
- Attack chain workflows

### B.R.E.A.C.H. (Electron)

Pentesting workspace:
- Terminal multiplexer (xterm.js + node-pty)
- Credential vault
- Target sidebar with status

## Neo4j Graph Model

```
(:Command)─[:PREREQUISITE]→(:Command)
     │
     ├─[:TAGGED]→(:Tag)
     │
     ├─[:HAS_VARIABLE]→(:Variable)
     │
     └─[:PART_OF]→(:Chain)

(:Engagement)─[:TARGETS]→(:Target)
      │
      ├─[:HAS_CREDENTIAL]→(:Credential)
      │
      └─[:HAS_FINDING]→(:Finding)
```

## Key Design Decisions

### 1. Multi-Backend Storage
- **Why**: Flexibility for different deployment scenarios
- **Implementation**: Auto-detection with fallback (Neo4j → SQLite → JSON)

### 2. JSON-First Knowledge Base
- **Why**: Human-readable, git-friendly, no database required
- **Location**: `db/data/` with schema validation

### 3. Modular Tool Architecture
- **Why**: Each tool operates independently
- **Pattern**: Tools consume from reference layer, persist to db layer

### 4. Electron GUIs Sharing Types
- **Why**: Type safety across multiple apps
- **Location**: `shared/` directory with TypeScript interfaces

## Extension Points

### Adding a New Command
1. Add to `db/data/commands/{category}/{subcategory}.json`
2. No code changes needed - registry loads dynamically

### Adding a New Tool
1. Create module in `tools/{category}/`
2. Register CLI command in `cli.py`
3. Add optional integration with engagement tracking

### Adding a Backend
1. Implement adapter interface in `reference/core/`
2. Register in backend selection logic
3. Implement query translation

## Configuration

Environment variables:
```bash
NEO4J_URI=bolt://localhost:7687
NEO4J_PASSWORD=your_password
CRACK_CONFIG_DIR=~/.crack
```

Configuration files:
- `~/.crack/config.json` - User preferences
- `~/.crack/sessions/` - Listener states
- `~/.crack/engagement.json` - Active engagement
