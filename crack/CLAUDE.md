# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**C.R.A.C.K.** (Comprehensive Recon & Attack Creation Kit) is a modular penetration testing toolkit for OSCP preparation. It consists of multiple standalone tools unified under a single CLI interface.

## Installation & Development Workflow

### Installing/Reinstalling the Library
```bash
# Quick reinstall (recommended during development)
./reinstall.sh

# Manual install (editable mode for development)
pip install -e . --break-system-packages

# Normal install
pip install . --break-system-packages
```

**IMPORTANT**: After ANY changes to:
- Module structure (`__init__.py`)
- CLI command registration (`cli.py`)
- Entry points (`pyproject.toml`)

You MUST run `./reinstall.sh` to apply changes to the `crack` command.

### Testing
```bash
# Run all tests with coverage
./run_tests.sh all

# Run specific test categories
./run_tests.sh unit           # Unit tests only
./run_tests.sh integration    # CLI integration tests
./run_tests.sh fast           # Quick tests only

# Run tests for specific module
./run_tests.sh module network
./run_tests.sh module sqli

# Single test file
pytest tests/unit/test_network_scanner.py -v

# Clean test artifacts
./run_tests.sh clean
```

**Coverage Target**: 70%+ for core functionality

## Architecture

### Module Organization
The toolkit uses a **modular category-based structure**:

```
crack/
├── network/        # Port scanning, service enumeration, CVE lookup
├── web/            # HTML enumeration, parameter discovery
├── sqli/           # SQL injection detection and exploitation
├── exploit/        # CVE research and exploit lookup
└── utils/          # Shared utilities (colors, parsers)
```

### CLI Architecture Pattern

**Adding a New Tool** requires updates to THREE locations:

1. **Create the tool module** (e.g., `network/port_scanner.py`)
   - Must have a `main()` function that accepts `sys.argv`
   - Should use `argparse` for argument parsing
   - Can run standalone: `python3 -m crack.network.port_scanner`

2. **Update category `__init__.py`** (e.g., `network/__init__.py`)
   ```python
   from .port_scanner import PortScanner

   __all__ = ['PortScanner', 'port_scanner', ...]
   ```

3. **Register in CLI** (`cli.py`)
   - Add command function that passes args to tool's `main()`
   - Add subparser registration
   - Update help text examples

4. **Run reinstall**: `./reinstall.sh`

### Example: Adding a New Network Tool

```python
# 1. Create crack/network/new_tool.py
def main():
    import argparse
    parser = argparse.ArgumentParser(description='New Tool')
    parser.add_argument('target', help='Target IP')
    args = parser.parse_args()
    # ... tool logic ...

if __name__ == '__main__':
    main()

# 2. Update crack/network/__init__.py
from .new_tool import NewTool
__all__ = ['NewTool', 'port_scanner', 'new_tool', ...]

# 3. Add to crack/cli.py
def new_tool_command(args):
    from crack.network import new_tool
    sys.argv = ['new_tool'] + args
    new_tool.main()

# In main(), add subparser:
new_tool_parser = subparsers.add_parser('new-tool',
                                        help='Description',
                                        add_help=False)
new_tool_parser.set_defaults(func=new_tool_command)

# 4. Run reinstall
# ./reinstall.sh
```

## Key Design Patterns

### 1. Standalone + Integrated Design
Every tool can run both:
- **Standalone**: `python3 crack/network/port_scanner.py 192.168.1.1`
- **Via CLI**: `crack port-scan 192.168.1.1`

This is achieved by:
- Each tool has its own `main()` function with full argparse
- CLI command functions pass through args using `sys.argv` reassignment
- Subparsers use `add_help=False` to delegate help to the tool

### 2. Shared Utilities
Common functionality lives in `utils/`:
- **colors.py**: Terminal color codes (Colors class)
- **curl_parser.py**: Parse Burp Suite curl exports

Import pattern:
```python
try:
    from crack.utils.colors import Colors
except ImportError:
    # Fallback for standalone usage
    class Colors:
        HEADER = '\033[95m'
        # ...
```

### 3. Educational Output Philosophy
All tools follow OSCP exam preparation principles:
- Include manual testing alternatives (for exam scenarios where tools fail)
- Explain flag meanings and methodology
- Provide time estimates
- Show alternative approaches
- Educational mode with detailed explanations

## SQLi Module Architecture

The SQLi scanner is the most complex module with sub-modules:

```
sqli/
├── scanner.py      # Main orchestration (SQLiScanner class)
├── techniques.py   # Detection techniques (error, boolean, time, union)
├── databases.py    # DB-specific enumeration (MySQL, PostgreSQL, MSSQL, Oracle)
├── reporter.py     # Output formatting and reporting
└── reference.py    # Post-exploitation reference (sqli-fu command)
```

**Key insight**: The `sqli_scanner.py` in `sqli/` is the main entry point that imports from sub-modules. When modifying SQLi functionality, update the appropriate sub-module.

## Reference System Architecture

The reference system (`crack/reference/`) is a hybrid command lookup system combining JSON command definitions with a CLI interface for OSCP exam preparation.

### Directory Structure

```
reference/
├── core/                    # Core functionality
│   ├── registry.py         # Command registry with subcategory support
│   ├── config.py           # Config management (~/.crack/config.json)
│   ├── placeholder.py      # Variable substitution engine
│   └── validator.py        # JSON schema validation
├── data/
│   └── commands/           # Command definitions (JSON)
│       ├── recon.json      # Flat structure (legacy)
│       ├── web.json
│       ├── exploitation.json
│       └── post-exploit/   # Subdirectory structure (new)
│           ├── linux.json
│           ├── windows.json
│           └── file-transfer.json
├── docs/                   # Markdown documentation
│   ├── config.md           # Config system guide
│   ├── placeholders.md     # Variable reference
│   └── tags.md             # Tag explanations
└── cli.py                  # CLI interface

Config storage: ~/.crack/config.json
```

### Command Structure (JSON)

Commands are defined in JSON with rich metadata for OSCP preparation:

```json
{
  "category": "post-exploit",
  "subcategory": "linux",
  "commands": [
    {
      "id": "linux-suid-find",
      "name": "Find SUID Binaries",
      "category": "post-exploit",
      "subcategory": "linux",
      "command": "find / -perm -u=s -type f 2>/dev/null",
      "description": "Manually find all SUID binaries (may lead to privilege escalation)",
      "variables": [],
      "flag_explanations": {
        "-perm -u=s": "Find files with SUID bit set",
        "-type f": "Only search for files (not directories)",
        "2>/dev/null": "Suppress permission denied errors"
      },
      "tags": ["MANUAL", "OSCP:HIGH", "QUICK_WIN"],
      "oscp_relevance": "high",
      "success_indicators": [
        "List of SUID binaries returned",
        "Unusual binaries found (not system defaults)"
      ],
      "failure_indicators": [
        "Empty output",
        "Permission denied on all paths"
      ],
      "next_steps": [
        "Check each binary against GTFOBins",
        "Test unusual SUID binaries for exploits"
      ],
      "alternatives": [
        "find / -perm -4000 2>/dev/null",
        "find / -user root -perm -4000 -exec ls -ldb {} \\;"
      ],
      "notes": "Cross-reference findings with https://gtfobins.github.io/"
    }
  ]
}
```

### Key Fields Explained

**Required:**
- `id`: Unique identifier (kebab-case)
- `name`: Human-readable name
- `category`: Top-level category
- `command`: Actual command string with placeholders
- `description`: What the command does

**Optional but Recommended:**
- `subcategory`: Second-level organization (enables `crack reference category subcategory`)
- `variables`: List of `<PLACEHOLDER>` definitions with descriptions/examples
- `flag_explanations`: Dictionary mapping flags to explanations (OSCP learning focus)
- `tags`: Array of tags (OSCP:HIGH, QUICK_WIN, MANUAL, LINUX, WINDOWS, etc.)
- `oscp_relevance`: "high", "medium", "low"
- `success_indicators`: What to look for when command succeeds
- `failure_indicators`: Common failure modes
- `next_steps`: What to do after running command
- `alternatives`: Other ways to achieve same goal
- `notes`: Additional context, tool download links, etc.

### Subcategory System

The registry supports two organizational patterns:

**Flat Structure (backward compatible):**
```
data/commands/
├── recon.json          # All recon commands
├── web.json            # All web commands
└── exploitation.json   # All exploitation commands
```

**Hierarchical Structure (new):**
```
data/commands/
└── post-exploit/       # Category directory
    ├── linux.json      # Subcategory
    ├── windows.json    # Subcategory
    └── file-transfer.json
```

**CLI Navigation:**
```bash
crack reference post-exploit              # Shows all + lists subcategories
crack reference post-exploit linux        # Shows only linux commands
crack reference post-exploit file-transfer
```

**Implementation Notes:**
- Registry automatically detects subdirectories in `data/commands/`
- Subcategories are extracted from directory structure
- Commands in subdirectories auto-populate `subcategory` field
- Flat and hierarchical structures can coexist

### Configuration System Integration

The reference system integrates with central config (`~/.crack/config.json`):

**Config Variables:**
```json
{
  "variables": {
    "LHOST": {
      "value": "192.168.1.113",
      "source": "auto-detected",
      "description": "Local/attacker IP"
    },
    "TARGET": {
      "value": "192.168.45.100",
      "source": "manual",
      "description": "Target IP"
    },
    "LPORT": {
      "value": "4444",
      "source": "default"
    }
  }
}
```

**Auto-fill Behavior:**
1. User runs: `crack reference --fill bash-reverse-shell`
2. PlaceholderEngine checks config for `<LHOST>` and `<LPORT>`
3. Displays: `Enter value for <LHOST> [config: 192.168.1.113]:`
4. User presses Enter → uses config value
5. User types value → overrides config for this command only

**Config Commands:**
```bash
# Auto-detect network settings
crack reference --config auto

# Set variables
crack reference --set TARGET 192.168.45.100
crack reference --set LHOST auto  # Auto-detect

# View config
crack reference --config list
crack reference --get LHOST

# Edit config file
crack reference --config edit
```

### Adding New Commands

**Step 1: Choose Organization**

Flat file:
```bash
# Add to existing category
vim reference/data/commands/recon.json
```

Subcategory:
```bash
# Create new subcategory
mkdir -p reference/data/commands/enumeration
vim reference/data/commands/enumeration/services.json
```

**Step 2: Define Command**

```json
{
  "id": "enum-smb-shares",
  "name": "Enumerate SMB Shares",
  "category": "enumeration",
  "subcategory": "services",
  "command": "smbclient -L //<TARGET> -N",
  "description": "List SMB shares without authentication",
  "variables": [
    {
      "name": "<TARGET>",
      "description": "Target IP address",
      "example": "192.168.45.100",
      "required": true
    }
  ],
  "flag_explanations": {
    "-L": "List shares on target",
    "-N": "No password (null session)"
  },
  "tags": ["OSCP:HIGH", "ENUM", "QUICK_WIN"],
  "oscp_relevance": "high",
  "success_indicators": [
    "Share list displayed",
    "No authentication error"
  ],
  "failure_indicators": [
    "NT_STATUS_ACCESS_DENIED",
    "Connection refused"
  ],
  "next_steps": [
    "Connect to discovered shares: smbclient //<TARGET>/<SHARE> -N",
    "Download files with: get, mget",
    "Check for writable shares"
  ],
  "alternatives": [
    "enum4linux -S <TARGET>",
    "nmap --script smb-enum-shares <TARGET>",
    "crackmapexec smb <TARGET> --shares"
  ],
  "notes": "Null sessions often disabled on modern Windows"
}
```

**Step 3: Test**

```bash
# No reinstall needed for reference system changes
crack reference --stats              # Verify command loaded
crack reference enum-smb-shares      # Search for command
crack reference enumeration services # Browse by subcategory
crack reference --fill enum-smb-shares  # Test variable substitution
```

### Standard Tags

Use consistent tags for filtering:

- **OSCP Relevance:** `OSCP:HIGH`, `OSCP:MEDIUM`, `OSCP:LOW`
- **Success Rate:** `QUICK_WIN`, `RELIABLE`
- **Method:** `MANUAL`, `AUTOMATED`, `STEALTH`, `NOISY`
- **OS:** `LINUX`, `WINDOWS`, `BOTH_OS`
- **Phase:** `RECON`, `ENUM`, `EXPLOIT`, `PRIVESC`, `TRANSFER`
- **Tool Type:** `REQUIRES_AUTH`, `NO_TOOLS_NEEDED`

### Placeholder Naming Convention

Placeholders use UPPER_CASE with angle brackets:

Common placeholders (auto-filled from config):
- `<TARGET>` - Target IP address
- `<LHOST>` - Local/attacker IP
- `<LPORT>` - Local port for listener
- `<URL>` - Full URL
- `<FILE>` - Filename
- `<WORDLIST>` - Path to wordlist
- `<USERNAME>` - Username
- `<PASSWORD>` - Password
- `<DOMAIN>` - Domain name
- `<OUTPUT>` - Output file path

### Testing Reference Commands

```bash
# Validate JSON structure
crack reference --validate

# View statistics
crack reference --stats

# List all tags
crack reference --list-tags

# Search functionality
crack reference nmap
crack reference "sql injection"
crack reference --tag QUICK_WIN

# Category/subcategory browsing
crack reference post-exploit
crack reference post-exploit linux
crack reference -c enumeration -s services

# Interactive mode
crack reference --interactive

# Export commands
crack reference --category recon --format json
crack reference --category web --format markdown
```

### Integration with Main CLI

The reference system is integrated as a subcommand in `cli.py`:

```python
def reference_command(args):
    from crack.reference import cli as ref_cli
    sys.argv = ['crack-reference'] + args
    ref_cli.main()

# In create_parser():
ref_parser = subparsers.add_parser(
    'reference',
    help='Command reference lookup',
    add_help=False
)
ref_parser.set_defaults(func=reference_command)
```

**Important**: Reference system has its own CLI (`reference/cli.py`) that handles all argument parsing. The main CLI just delegates with `add_help=False`.

### Development Workflow

**Adding new category:**
1. Create directory: `mkdir reference/data/commands/new-category`
2. Add JSON file: `vim reference/data/commands/new-category/subcategory.json`
3. Update `registry.py` categories dict if needed (optional - auto-detected)
4. Test: `crack reference new-category`

**Adding to existing category:**
1. Edit JSON file: `vim reference/data/commands/category/subcategory.json`
2. Add command object to `commands` array
3. Test: `crack reference --fill command-id`

**No reinstall needed** - Reference JSON changes load dynamically

**Modifying core logic:**
1. Edit `reference/core/*.py`
2. Run `./reinstall.sh` (registry, config, placeholder changes)
3. Test with `crack reference --stats`

### Educational Philosophy

Every command should teach OSCP methodology:

1. **Flag Explanations**: Always explain what flags do and why
2. **Success/Failure Indicators**: Help user verify results
3. **Next Steps**: Guide the attack chain progression
4. **Alternatives**: Manual methods for when tools fail/unavailable
5. **Notes**: Context, tool sources, exam tips

**Example from real command:**
```json
{
  "flag_explanations": {
    "-sV": "Service version detection (critical for CVE matching)",
    "-sC": "Default NSE scripts (finds low-hanging fruit)",
    "-p-": "All 65535 ports (thorough, finds hidden services)"
  },
  "success_indicators": [
    "Open ports with service versions",
    "Service banners visible"
  ],
  "failure_indicators": [
    "Scan too slow (add --min-rate 1000)",
    "Firewall blocking (try -Pn)"
  ],
  "next_steps": [
    "Research versions on searchsploit",
    "Run targeted NSE scripts on findings"
  ],
  "alternatives": [
    "nc -zv <TARGET> 1-65535 2>&1 | grep succeeded"
  ],
  "notes": "For exam: always use -oA to save all formats"
}
```

## Common Development Tasks

### Adding a New CLI Command
See "CLI Architecture Pattern" above. Always run `./reinstall.sh` after changes.

### Modifying Existing Tools
If you change tool logic but NOT the CLI structure:
- No reinstall needed for Python library usage
- Reinstall IS needed if imported as `crack` command

### Adding Dependencies
1. Update `pyproject.toml` dependencies section
2. Run `./reinstall.sh`

### Module Imports
When a module needs to import another crack module:
```python
# ✓ Correct - relative import for same package
from .utils.colors import Colors

# ✓ Correct - absolute import
from crack.utils.colors import Colors

# ✗ Wrong - circular imports
from crack.network import port_scanner  # in network/__init__.py
```

## Testing Philosophy

- **Unit tests**: Test individual functions/classes in isolation (70%+ coverage target)
- **Integration tests**: Test CLI routing and module interactions
- **Functional tests**: Test complete workflows

**Mock Strategy**:
- Mock external commands (nmap, searchsploit, nikto) via `subprocess.run`
- Mock HTTP requests via `requests.Session`
- Use real parsing logic with mock data

**Common test patterns** are in `tests/conftest.py`:
- `temp_output_dir`: Temporary directory for test outputs
- `mock_subprocess_run`: Mock external tools
- `mock_requests_session`: Mock HTTP calls

## Important Files

- **pyproject.toml**: Package metadata, dependencies, entry points
- **cli.py**: Main CLI router (all subcommands registered here)
- **reinstall.sh**: Development reinstall script
- **run_tests.sh**: Test runner with multiple modes
- **tests/conftest.py**: Shared test fixtures

## Package Distribution

The package is named `crack-toolkit` on PyPI but imports as `crack`:
```python
# Package name: crack-toolkit
# pip install crack-toolkit

# Import name: crack
from crack.network import PortScanner
```

Entry point: `crack` command → `crack.cli:main`

## Running Tools

```bash
# Via crack CLI (requires installation)
crack port-scan 192.168.45.100
crack scan-analyze scan.nmap
crack html-enum http://target.com
crack sqli-scan http://target.com/page.php?id=1

# Standalone (no installation required)
python3 -m crack.network.port_scanner 192.168.45.100
python3 -m crack.sqli.scanner http://target.com/page.php?id=1
```

## Environment

- **Platform**: Kali Linux (OSCP preparation environment)
- **Python**: 3.8+
- **Dependencies**: requests, beautifulsoup4, urllib3
- **External tools**: nmap, searchsploit, nikto (called via subprocess)
