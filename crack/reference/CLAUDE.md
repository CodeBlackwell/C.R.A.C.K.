# CRACK Reference System - LLM Reference

## Architecture

```
reference/
├── core/
│   ├── registry.py         # HybridCommandRegistry, Command dataclass
│   ├── sql_adapter.py      # SQLCommandRegistryAdapter (SQL backend) ✨ NEW
│   ├── placeholder.py      # PlaceholderEngine, variable substitution
│   ├── config.py           # ConfigManager, ~/.crack/config.json
│   ├── colors.py           # ReferenceTheme, ANSI escape codes
│   ├── validator.py        # CommandValidator, schema validation
│   └── parser.py           # MarkdownCommandParser (TODO)
├── data/commands/          # JSON command definitions (fallback)
│   ├── *.json              # Flat structure (legacy)
│   └── category/           # Subdirectory structure
│       └── subcategory.json
├── cli/
│   └── main.py             # ReferenceCLI with auto-detect fallback ✨ UPDATED
└── ~/.crack/crack.db       # SQL database (preferred backend) ✨ NEW
```

## Backend Architecture ✨ UPDATED (Phase 5: Neo4j Graph Database)

**Triple Backend Support:**
- **`Neo4jCommandRegistryAdapter`**: Graph-based (NEW - advanced queries, relationship traversal) ✨
- **`SQLCommandRegistryAdapter`**: SQL-based (recommended for simple queries, 10-20x faster)
- **`HybridCommandRegistry`**: JSON-based (fallback, human-editable)

**CLI Auto-Detection** (`reference/cli/main.py:52-114`):
1. Tries Neo4j first (if available and configured for graph queries)
2. Tries SQL (`~/.crack/crack.db` exists + valid)
3. Falls back to JSON if SQL missing/corrupted/empty
4. User sees status message for transparency

**Router Intelligence**: Auto-selects backend based on query complexity
- Graph queries (multi-hop, relationships) → Neo4j
- Simple lookups, text search → SQL
- Fallback → JSON

**Import Pattern:**
```python
from crack.reference.core import (
    Neo4jCommandRegistryAdapter,
    SQLCommandRegistryAdapter,
    HybridCommandRegistry
)

# Auto-detect (CLI does this internally)
registry = cli._initialize_registry()  # Returns Neo4j/SQL/JSON

# Explicit Neo4j (for graph queries)
registry = Neo4jCommandRegistryAdapter(
    config_manager=config,
    theme=theme,
    neo4j_config=None  # Uses environment vars or defaults
)

# Explicit SQL (for simple queries)
registry = SQLCommandRegistryAdapter(
    db_path='~/.crack/crack.db',
    config_manager=config,
    theme=theme
)

# Explicit JSON (fallback)
registry = HybridCommandRegistry(
    config_manager=config,
    theme=theme
)
```

**API Parity:**
All backends expose identical core methods:
- `get_command(id)`, `search(query)`, `filter_by_category()`, `filter_by_tags()`
- `get_quick_wins()`, `get_oscp_high()`, `get_stats()`, `interactive_fill()`

**Neo4j-Exclusive Methods** (graph primitives):
- `traverse_graph()`: Variable-length path traversal
- `aggregate_by_pattern()`: Template-based aggregation
- `find_by_pattern()`: Generic Cypher pattern matching
- Enhanced: `find_alternatives(return_metadata=True)`
- Enhanced: `find_prerequisites(execution_order=True)`
- Enhanced: `filter_by_tags(include_hierarchy=True)`

**Pattern Library** (`reference/patterns/advanced_queries.py`):
- 10 pre-built advanced query patterns
- High-level OSCP-focused API
- Usage: `patterns = create_pattern_helper(adapter)`

**Limitations:**
- **SQL/JSON**: No graph traversal (use Neo4j for multi-hop, alternatives)
- **SQL**: `add_command()` not implemented (use migration script)
- **Neo4j**: Requires database setup (PostgreSQL fallback available)

## Core Classes

### Command (dataclass)
```python
Command:
  id: str                              # Unique identifier
  name: str
  category: str                        # recon|web|exploitation|post-exploit|file-transfer|pivoting|custom
  command: str                         # Template with <PLACEHOLDERS>
  description: str
  subcategory: str = ""
  tags: List[str] = []
  variables: List[CommandVariable] = []
  flag_explanations: Dict[str, str] = {}
  success_indicators: List[str] = []
  failure_indicators: List[str] = []
  next_steps: List[str] = []
  alternatives: List[str] = []         # Command IDs (link by ID, not text)
  prerequisites: List[str] = []        # Commands to run first
  troubleshooting: Dict[str, str] = {}
  notes: str = ""
  oscp_relevance: str = "medium"       # low|medium|high
```

### CommandVariable (dataclass)
```python
CommandVariable:
  name: str           # <PLACEHOLDER_NAME>
  description: str
  example: str = ""   # Used as DEFAULT if user presses Enter
  required: bool = True
```

### Key Methods
```python
Command.fill_placeholders(values: Dict[str, str]) -> str
  # Replace placeholders with values
  # Falls back to var.example if placeholder not in values dict

HybridCommandRegistry.interactive_fill(command: Command) -> str
  # Prompt user for each placeholder
  # Auto-fill from config (TARGET, LHOST, LPORT)
  # Use var.example as default for optional fields
  # Return fully-populated command string
```

## JSON Schema

```json
{
  "category": "file-transfer",
  "commands": [{
    "id": "rdesktop-disk-share",
    "name": "RDesktop Disk Sharing",
    "category": "file-transfer",
    "command": "rdesktop -u <USERNAME> -p <PASSWORD> -r disk:share=<LOCAL_PATH> <TARGET>:<PORT>",
    "description": "Mount local directory in Windows RDP session",
    "tags": ["FILE_TRANSFER", "RDP", "OSCP:HIGH"],
    "variables": [
      {
        "name": "<USERNAME>",
        "description": "RDP username",
        "example": "administrator",
        "required": true
      },
      {
        "name": "<PORT>",
        "description": "RDP port (default 3389)",
        "example": "3389",
        "required": false
      }
    ],
    "flag_explanations": {
      "-r disk:share=<PATH>": "Mount local directory as \\\\tsclient\\share in RDP session",
      "-u": "Username for authentication",
      "-p": "Password for authentication"
    },
    "prerequisites": [
      "mkdir -p <LOCAL_PATH>",
      "sudo nmap -p <PORT> -Pn -v <TARGET>"
    ],
    "troubleshooting": {
      "Connection refused": "Verify port: sudo nmap -p <PORT> -Pn -v <TARGET>",
      "Access denied to \\\\tsclient\\share": "Drive redirection blocked. Use alternative: smb-server"
    },
    "alternatives": ["smb-server", "scp-transfer"],
    "success_indicators": ["Connected to", "Mounted"],
    "failure_indicators": ["Connection refused", "Authentication failed"],
    "next_steps": ["Access shared folder via \\\\tsclient\\share", "Copy files"],
    "oscp_relevance": "high"
  }]
}
```

## Rules

**NEVER hardcode values:**
- ✗ `nmap -p 3389 <TARGET>`
- ✓ `nmap -p <PORT> <TARGET>` + variable with example: "3389"

**Link by ID, not text:**
- ✗ `"alternatives": ["Use impacket-smbserver"]`
- ✓ `"alternatives": ["smb-server"]` (command ID)

**Required setup = prerequisites:**
- Listener needed? → `prerequisites: ["nc -lvnp <LPORT>"]`
- Directory needed? → `prerequisites: ["mkdir -p <OUTPUT_DIR>"]`

**All nmap commands:**
- Must use `sudo`
- Must use `-v` (verbose)
- Must use `-Pn` (skip ping) for port checks

## Theme System (ANSI)

**Do NOT use Rich markup** - Use ANSI escape codes directly

```python
from crack.reference.core import ReferenceTheme

theme = ReferenceTheme()
theme.primary(text)      # Cyan - placeholders, values
theme.prompt(text)       # Yellow - prompts
theme.success(text)      # Green - success messages
theme.error(text)        # Red - errors
theme.hint(text)         # Dim - examples, descriptions
theme.command_name(text) # Bold white - command names
theme.bold_white(text)   # Bold bright white
```

**Color codes:**
```python
Colors.CYAN = '\033[36m'
Colors.YELLOW = '\033[33m'
Colors.GREEN = '\033[32m'
Colors.RED = '\033[31m'
Colors.DIM = '\033[2m'
Colors.BOLD = '\033[1m'
Colors.BRIGHT_WHITE = '\033[97m'
Colors.RESET = '\033[0m'
```

## CLI Usage

```bash
# Search
crack reference rdp                              # Search "rdp"
crack reference --category file-transfer         # List category
crack reference --tag QUICK_WIN                  # Filter by tag

# Numbered selection (auto-fill)
crack reference rdp 1                            # Search + select first result
crack reference file-transfer 2                  # Category + select second

# Interactive fill (prompts for placeholders)
crack reference --fill rdesktop-disk-share       # By ID
crack reference rdp 1                            # Search → select → fill

# Config management
crack reference --config auto                    # Auto-detect LHOST, INTERFACE
crack reference --set LHOST 10.10.14.5          # Set variable
crack reference --set TARGET 192.168.45.100
crack reference --get LHOST                      # Get variable
crack reference --config list                    # List all config

# Verbose display (shows all fields)
crack reference rdp --verbose                    # Detailed view
```

## Config Priority

1. User input (interactive prompt)
2. Config file (`~/.crack/config.json`)
3. Variable example (default)
4. Empty string

**Example flow:**
```
User sees: "Enter <PORT> [e.g., 3389] [config: 3389] (optional): "
User presses Enter → Uses config value: 3389
No config value → Uses example: 3389
```

## Development Patterns

### Adding Commands

**1. Create JSON** (`data/commands/category/subcategory.json`)
```json
{
  "category": "exploitation",
  "commands": [{
    "id": "new-command",
    "name": "New Command",
    "command": "tool --flag <VALUE>",
    "description": "Brief description",
    "category": "exploitation",
    "variables": [{"name": "<VALUE>", "description": "...", "example": "default"}],
    "oscp_relevance": "high"
  }]
}
```

**2. Reload** - No reinstall needed, registry loads JSON dynamically

**3. Validate**
```bash
crack reference --validate
```

### Adding Placeholders

Edit `reference/core/placeholder.py` → `_load_standard_placeholders()`

```python
'<NEW_VAR>': PlaceholderDefinition(
    name='<NEW_VAR>',
    description='Description',
    example='default_value',
    validation_regex=r'^pattern$',  # Optional
    source='ENV_VAR_NAME'           # Optional (loads from env)
)
```

### Validation Rules

```python
# Checked by CommandValidator
- Command ID unique
- Command text present
- All placeholders defined in variables array
- All variable placeholders exist in command text
```

## Integration Points

### With Track Module
```python
# Track can use reference commands for alternatives
from crack.reference.core import HybridCommandRegistry

registry = HybridCommandRegistry()
cmd = registry.get_command('bash-reverse-shell')
filled = registry.interactive_fill(cmd)
```

### With Config System
```python
# Shared config location
config_path = "~/.crack/config.json"

# Config structure
{
  "placeholders": {
    "<TARGET>": "192.168.45.100",
    "<LHOST>": "10.10.14.5",
    "<LPORT>": "4444"
  }
}
```

## Quick Reference

**File locations:**
- Commands: `reference/data/commands/`
- Config: `~/.crack/config.json`
- Registry: `reference/core/registry.py:83-411`
- Theme: `reference/core/colors.py:1-113`
- CLI: `reference/cli.py:23-778`

**Key concepts:**
- Commands = JSON definitions with placeholders
- Placeholders = `<UPPERCASE_NAME>` in command strings
- Variables = Metadata about placeholders (description, example, required)
- Theme = ANSI colors (not Rich markup)
- Config = Auto-fill values for common placeholders
- Prerequisites = Setup commands (must run before main command)
- Alternatives = Other command IDs (link by ID)

**Testing:**
```bash
crack reference --validate           # Schema validation
crack reference --stats              # Registry statistics
crack reference --fill test-command  # Test interactive fill
```

**No reinstall needed for:**
- JSON changes (`data/commands/`)
- New commands
- Placeholder defaults
- Theme color changes

**Reinstall required for:**
- CLI argument changes
- Core class changes (registry, placeholder engine)
- New imports in `__init__.py`

---

## 🔄 Neo4j Graph Database (Phase 5) - Quick Reference

**For full documentation, see**: `reference/NEO4J_ARCHITECTURE.md`

### Minimalist Architecture
- **3 flexible primitives** replace 10 hardcoded methods (76% code reduction)
- **10 pre-built patterns** via `reference/patterns/advanced_queries.py`
- **Zero breaking changes** (100% backward compatible)

### Quick Usage
```python
from crack.reference.patterns.advanced_queries import create_pattern_helper
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter

adapter = Neo4jCommandRegistryAdapter(config, theme)
patterns = create_pattern_helper(adapter)

# Find alternatives when tools fail
alts = patterns.multi_hop_alternatives('gobuster-dir', depth=3)

# Get prerequisites with execution order
prereqs = patterns.prerequisite_closure('wordpress-sqli', with_execution_order=True)

# Service recommendations for detected ports
recs = patterns.service_recommendations([80, 445, 22])
```

### Configuration
```bash
export NEO4J_PASSWORD='your_password'  # Required for production
export NEO4J_URI='bolt://localhost:7687'  # Default
```

### Testing
```bash
python3 tests/scripts/validate_all_patterns.py  # Validate all 10 patterns
python3 -m pytest tests/reference/test_neo4j_adapter_primitives.py  # 28 tests
```

### Status
- ✅ **28/28 primitive tests passing**
- ✅ **4/4 integration tests passing**
- ✅ **10/10 patterns validated**
- ✅ **All queries <500ms**
- ✅ **Production ready**

**See `TESTING_GUIDE.md` for 60+ test examples**

