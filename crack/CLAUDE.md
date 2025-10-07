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
├── track/          # CRACK Track - Enumeration tracking & task management
├── reference/      # Command reference system with 70+ OSCP commands
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

## CRACK Track Architecture

**CRACK Track** (`crack/track/`) is the enumeration tracking and task management system for OSCP preparation.

### Overview

CRACK Track automatically generates actionable task lists from scan results, tracks progress, and exports comprehensive OSCP writeups.

**Primary command**: `crack track` (user-facing brand name)
**Backward compatibility**: `crack checklist` (legacy alias)

### Directory Structure

```
track/
├── core/                    # Core functionality
│   ├── state.py            # TargetProfile - complete enumeration state
│   ├── storage.py          # JSON persistence (~/.crack/targets/)
│   ├── task_tree.py        # Hierarchical task management
│   └── events.py           # EventBus for plugin communication
├── parsers/                 # Scan result parsers
│   ├── nmap_xml.py         # Nmap XML parser
│   ├── nmap_gnmap.py       # Nmap greppable format parser
│   └── registry.py         # Auto-detect parser by file type
├── services/                # Service-specific plugins
│   ├── http.py             # HTTP/HTTPS enumeration
│   ├── smb.py              # SMB enumeration
│   ├── ssh.py              # SSH enumeration
│   ├── ftp.py              # FTP enumeration
│   ├── sql.py              # SQL database enumeration
│   ├── post_exploit.py     # Post-exploitation tasks
│   └── registry.py         # Service plugin auto-discovery
├── phases/                  # Enumeration phase management
│   ├── definitions.py      # Phase task definitions
│   └── registry.py         # Phase progression logic
├── recommendations/         # Task recommendation engine
│   └── engine.py           # Context-aware next-step suggestions
├── formatters/              # Output formatters
│   ├── console.py          # Terminal-friendly display
│   └── markdown.py         # OSCP writeup export
└── cli.py                  # CLI interface

Storage: ~/.crack/targets/<TARGET>.json
```

### Key Components

**TargetProfile** (`core/state.py`):
- Complete enumeration state for a single target
- Ports, services, findings, credentials, notes
- Hierarchical task tree with progress tracking
- Timestamped events for timeline reconstruction

**EventBus** (`core/events.py`):
- Decouples parsers from service plugins
- Events: `port_discovered`, `service_detected`, `version_detected`
- Plugins subscribe to events and generate tasks automatically

**Service Plugins** (`services/`):
- Auto-generate tasks when services are detected
- HTTP: whatweb, gobuster, nikto, manual checks
- SMB: enum4linux, smbclient, share enumeration
- Each plugin includes manual alternatives for OSCP exam

**TaskNode** (`core/task_tree.py`):
- Hierarchical task organization (parent/child relationships)
- Status tracking: pending, in-progress, completed, skipped
- Rich metadata: commands, flag explanations, success indicators
- Educational focus: next steps, alternatives, failure indicators

**RecommendationEngine** (`recommendations/engine.py`):
- Context-aware next-step suggestions
- Prioritizes "quick wins" (fast, high-value tasks)
- Limits to 5 recommendations to avoid overwhelming users
- Identifies parallelizable tasks for efficiency

### Usage Examples

```bash
# Create new target profile
crack track new 192.168.45.100

# Import nmap scan (auto-generates service tasks)
crack track import 192.168.45.100 service_scan.xml

# View recommendations
crack track show 192.168.45.100
crack track recommend 192.168.45.100

# Mark tasks complete
crack track done 192.168.45.100 whatweb-80

# Document findings (source required!)
crack track finding 192.168.45.100 \
  --type vulnerability \
  --description "SQL injection in id parameter" \
  --source "Manual testing with sqlmap"

# Add credentials
crack track creds 192.168.45.100 \
  --username admin \
  --password password123 \
  --service http \
  --port 80 \
  --source "Found in config.php"

# Export OSCP writeup
crack track export 192.168.45.100 > writeup.md
crack track timeline 192.168.45.100

# List all tracked targets
crack track list
```

### Event-Driven Task Generation

```
Nmap Parser → parse_file()
    ↓
Emits: service_detected(port=80, service='http', version='Apache 2.4.41')
    ↓
ServiceRegistry → Matches HTTP plugin
    ↓
HTTP Plugin → detect() returns True
    ↓
HTTP Plugin → get_task_tree() generates:
    ├── Technology Fingerprinting (whatweb)
    ├── Directory Brute-force (gobuster)
    ├── Vulnerability Scan (nikto)
    ├── Manual Checks
    │   ├── robots.txt
    │   ├── sitemap.xml
    │   └── Source review
    └── Exploit Research: Apache 2.4.41
        ├── searchsploit
        └── CVE lookup
    ↓
Emits: plugin_tasks_generated(task_tree={...})
    ↓
TargetProfile → add_task() integrates into tree
```

### Testing CRACK Track

```bash
# Run all CRACK Track tests (51 tests, 100% passing)
pytest tests/track/ -v

# Run specific test categories
pytest tests/track/test_user_stories.py -v       # Real OSCP workflows
pytest tests/track/test_guidance_quality.py -v   # Recommendation quality
pytest tests/track/test_edge_cases.py -v         # Robustness testing
pytest tests/track/test_documentation.py -v      # OSCP report requirements

# With coverage
pytest tests/track/ --cov=crack.track --cov-report=term-missing

# Use test runner script
./tests/track/run_track_tests.sh all
./tests/track/run_track_tests.sh user-stories
./tests/track/run_track_tests.sh coverage
```

**Test Philosophy:**
- **User-story driven**: Tests validate real OSCP workflows
- **BDD format**: "As a pentester... I want... So that..."
- **Realistic scenarios**: Nmap XML from actual OSCP-style boxes
- **Value validation**: Tests prove the tool helps, not just that it runs

### Adding New Service Plugins

```python
# 1. Create track/services/new_service.py
from .base import ServicePlugin

@ServiceRegistry.register
class NewServicePlugin(ServicePlugin):
    @property
    def name(self) -> str:
        return "new-service"

    def detect(self, port_info: Dict[str, Any]) -> bool:
        """Return True if this plugin handles this port"""
        service = port_info.get('service', '').lower()
        return service in ['new-service', 'new-svc']

    def get_task_tree(self, target: str, port: int, service_info: Dict) -> Dict:
        """Generate task tree for this service"""
        return {
            'id': f'new-service-{port}',
            'name': f'NewService Enumeration (Port {port})',
            'type': 'parent',
            'children': [
                {
                    'id': f'enum-{port}',
                    'name': 'Basic Enumeration',
                    'type': 'command',
                    'metadata': {
                        'command': f'tool -target {target} -port {port}',
                        'description': 'Enumerate new service',
                        'tags': ['OSCP:HIGH', 'QUICK_WIN'],
                        'flag_explanations': {
                            '-target': 'Target hostname/IP',
                            '-port': 'Service port'
                        },
                        'success_indicators': ['Data enumerated'],
                        'alternatives': ['Manual: nc {target} {port}']
                    }
                }
            ]
        }

# 2. Import in track/services/registry.py
# (Auto-discovered via @ServiceRegistry.register decorator)

# 3. Test
# No reinstall needed - plugins auto-discovered on import
```

### Storage Format

Profiles stored as JSON in `~/.crack/targets/`:

```json
{
  "target": "192.168.45.100",
  "created": "2025-10-07T12:00:00",
  "updated": "2025-10-07T15:30:00",
  "phase": "service-specific",
  "status": "in-progress",
  "ports": {
    "80": {
      "state": "open",
      "service": "http",
      "version": "Apache httpd 2.4.41",
      "product": "Apache httpd",
      "source": "nmap service scan"
    }
  },
  "findings": [
    {
      "timestamp": "2025-10-07T13:45:00",
      "type": "vulnerability",
      "description": "Directory traversal in /download.php",
      "source": "Manual testing: /download.php?file=../../../etc/passwd"
    }
  ],
  "credentials": [
    {
      "timestamp": "2025-10-07T14:00:00",
      "username": "admin",
      "password": "password123",
      "service": "http",
      "port": 80,
      "source": "Found in config.php"
    }
  ],
  "task_tree": {
    "id": "root",
    "name": "Enumeration: 192.168.45.100",
    "type": "parent",
    "status": "pending",
    "children": [...]
  }
}
```

### OSCP Exam Features

**1. Source Tracking (Required!):**
```python
# All findings MUST have sources
profile.add_finding(
    finding_type="vulnerability",
    description="SQLi in id parameter",
    source="Manual testing: sqlmap -u 'http://target/page.php?id=1'"
)
```

**2. Manual Alternatives:**
Every automated task includes manual alternatives for when tools fail:
```python
'alternatives': [
    'Manual: curl http://target/admin',
    'Manual: curl http://target/upload',
    'Browser: View page source for hidden directories'
]
```

**3. Flag Explanations:**
Educational focus - every flag is explained:
```python
'flag_explanations': {
    'dir': 'Directory/file brute-forcing mode',
    '-u': 'Target URL',
    '-w': 'Wordlist path (common.txt for speed)',
    '-o': 'Output file (required for OSCP documentation)'
}
```

**4. Timeline Export:**
Complete event timeline for report submission:
```bash
crack track timeline 192.168.45.100

# Output:
# 2025-10-07 12:00:00 - Completed: Full port scan
# 2025-10-07 12:30:00 - Finding: Directory traversal
# 2025-10-07 13:00:00 - Credential: admin discovered
```

### Documentation

**Comprehensive README**: `track/README.md`
- Full usage guide with examples
- Architecture deep dive
- OSCP exam preparation features
- Service plugin development guide

**Test README**: `tests/track/README.md`
- Test philosophy and structure
- Running tests
- User story descriptions

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
crack track new 192.168.45.100
crack reference --fill bash-reverse-shell

# Standalone (no installation required)
python3 -m crack.network.port_scanner 192.168.45.100
python3 -m crack.sqli.scanner http://target.com/page.php?id=1
python3 -m crack.track.cli 192.168.45.100
```

## Environment

- **Platform**: Kali Linux (OSCP preparation environment)
- **Python**: 3.8+
- **Dependencies**: requests, beautifulsoup4, urllib3
- **External tools**: nmap, searchsploit, nikto (called via subprocess)
