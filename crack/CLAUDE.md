# CLAUDE.md

## Project Overview

**C.R.A.C.K.** - **C**omprehensive **R**econ & **A**ttack **C**reation **K**it

A modular penetration testing toolkit for OSCP preparation. Multiple standalone tools unified under a single CLI interface.

## Installation & Development

### Quick Commands
```bash
./reinstall.sh                    # After ANY changes to __init__.py, cli.py, or pyproject.toml
./run_tests.sh all                # Run all tests with coverage
./run_tests.sh module <name>      # Test specific module
```

**Coverage Target**: 70%+ for core functionality

## Architecture

### Module Organization
```
crack/
├── network/        # Port scanning, service enumeration, CVE lookup
├── web/            # HTML enumeration, parameter discovery
├── sqli/           # SQL injection detection and exploitation
├── exploit/        # CVE research and exploit lookup
├── track/          # Enumeration tracking & task management (235+ service plugins)
├── reference/      # Command reference system (70+ OSCP commands)
└── utils/          # Shared utilities (colors, parsers)
```

### CLI Architecture Pattern

**Adding a New Tool** requires THREE steps:

1. **Create tool module** with `main()` function using `argparse`
2. **Update category `__init__.py`** to export it
3. **Register in `cli.py`** with subparser + command function
4. **Run `./reinstall.sh`**

Example:
```python
# 1. Create crack/network/new_tool.py
def main():
    parser = argparse.ArgumentParser(description='New Tool')
    parser.add_argument('target', help='Target IP')
    args = parser.parse_args()
    # ... tool logic ...

# 2. Update crack/network/__init__.py
from .new_tool import NewTool
__all__ = ['NewTool', 'new_tool', ...]

# 3. Add to crack/cli.py
def new_tool_command(args):
    from crack.network import new_tool
    sys.argv = ['new_tool'] + args
    new_tool.main()

new_tool_parser = subparsers.add_parser('new-tool', help='Description', add_help=False)
new_tool_parser.set_defaults(func=new_tool_command)

# 4. Run reinstall
./reinstall.sh
```

### Key Design Patterns

1. **Standalone + Integrated Design**
   - Standalone: `python3 crack/network/port_scanner.py 192.168.1.1`
   - Via CLI: `crack port-scan 192.168.1.1`
   - Achieved via `sys.argv` reassignment and `add_help=False`

2. **Shared Utilities** (`utils/`)
   - `colors.py`: Terminal color codes
   - `curl_parser.py`: Parse Burp Suite curl exports

3. **Educational Output Philosophy**
   - Manual testing alternatives (for OSCP exam scenarios)
   - Flag explanations and methodology
   - Time estimates and alternative approaches

## CRACK Track Architecture

**Primary Command**: `crack track` (enumeration tracking and task management)

### Core Components

**Directory Structure:**
```
track/
├── core/              # TargetProfile, TaskNode, EventBus, Storage
├── parsers/           # Nmap XML/greppable parsers
├── services/          # 235+ service plugins (auto-generate tasks)
├── alternatives/      # Alternative Commands system (45+ manual alternatives)
├── phases/            # Enumeration phase management
├── recommendations/   # Context-aware next-step suggestions
├── formatters/        # Console + Markdown exporters
├── interactive/       # Interactive mode (state machine, menus, shortcuts)
└── visualizer/        # Task tree visualization

Storage: ~/.crack/targets/<TARGET>.json
Config: ~/.crack/config.json
```

**Key Classes:**
- **TargetProfile** (`core/state.py`): Complete enumeration state for a target
- **EventBus** (`core/events.py`): Decouples parsers from service plugins
- **TaskNode** (`core/task_tree.py`): Hierarchical task organization with status tracking
- **ServicePlugin** (`services/base.py`): Base class for service-specific enumeration

### Event-Driven Task Generation Flow

```
Nmap Parser → parse_file()
    ↓
Emits: service_detected(port=80, service='http', version='Apache 2.4.41')
    ↓
ServiceRegistry → Matches HTTP plugin
    ↓
HTTP Plugin → detect() returns True → get_task_tree() generates tasks
    ↓
TargetProfile → add_task() integrates into tree
```

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
        service = port_info.get('service', '').lower()
        return service in ['new-service', 'new-svc']

    def get_task_tree(self, target: str, port: int, service_info: Dict) -> Dict:
        return {
            'id': f'new-service-{port}',
            'name': f'NewService Enumeration (Port {port})',
            'type': 'parent',
            'children': [...]
        }

# 2. No reinstall needed - plugins auto-discovered via decorator
```

### OSCP Exam Features

1. **Source Tracking** - All findings require `source` field
2. **Manual Alternatives** - Every task includes manual methods
3. **Flag Explanations** - Educational focus on understanding commands
4. **Timeline Export** - Complete event timeline for report submission

**Documentation:** See `track/README.md` for comprehensive usage guide

## Interactive Mode (`track/interactive/`)

**Flow:** Display Context → Build Menu → Get Input → Process Choice → Execute Action → Save Checkpoint → Repeat

**Architecture:**
```
track/interactive/
├── session.py          # State machine loop
├── prompts.py          # Context-aware menu generation
├── display.py          # Terminal UI formatting
├── shortcuts.py        # Keyboard shortcuts ('s', 't', 'r', 'n', 'alt', 'q')
└── decision_trees.py   # Navigation system
```

**Session Persistence:** Auto-saves to `~/.crack/sessions/TARGET.json` after every action

**No Reinstall Needed** - Changes to `track/interactive/` load immediately (exception: `track/cli.py`)

**Documentation:** See `track/README.md` Interactive Mode section for extension patterns

## Alternative Commands (`track/alternatives/`)

**Purpose:** Context-aware manual command alternatives when automated tools fail (OSCP exam requirement)

**Status:** Production Ready (Phases 1-6 Complete, 83/83 tests passing)

**Architecture:**
```
track/alternatives/
├── models.py       # AlternativeCommand, Variable, ExecutionResult
├── context.py      # ContextResolver (Task → Profile → Config → User)
├── executor.py     # Template substitution + execution
├── registry.py     # Pattern matching (task ID, service, tags)
└── commands/       # 45+ alternative definitions
```

**Usage Flow:**
1. User presses `alt` in interactive mode
2. ContextResolver auto-fills variables from task metadata, profile state, config
3. User prompted for missing variables
4. AlternativeExecutor substitutes template and executes
5. Result logged to profile with timestamp

**Variable Resolution Priority:**
1. Task Metadata (e.g., `<PORT>` from `gobuster-80`)
2. Profile State (e.g., `<TARGET>` from profile)
3. Config Variables (e.g., `<LHOST>` from `~/.crack/config.json`)
4. User Prompt (e.g., `<DIRECTORY>` from user input)

**Pattern Matching:** Auto-links alternatives to tasks via glob patterns (`gobuster-*`), service type (`http`), or tags (`OSCP:HIGH`)

**Performance:** <1ms per task, all benchmarks exceeded

**Documentation:** See `track/alternatives/README.md` for developer guide

## Reference System (`crack/reference/`)

**Purpose:** Hybrid command lookup system with JSON definitions and CLI interface

**Architecture:**
```
reference/
├── core/
│   ├── registry.py      # Command registry with subcategory support
│   ├── config.py        # Config management (~/.crack/config.json)
│   ├── placeholder.py   # Variable substitution engine
│   └── validator.py     # JSON schema validation
├── data/commands/       # JSON command definitions (70+ commands)
│   ├── recon.json       # Flat structure
│   └── post-exploit/    # Hierarchical structure
│       ├── linux.json
│       └── windows.json
└── cli.py               # CLI interface
```

**Command Structure:** JSON with rich metadata (flag_explanations, success_indicators, failure_indicators, next_steps, alternatives)

**Config Integration:** Auto-fills `<LHOST>`, `<LPORT>`, `<TARGET>`, `<WORDLIST>` from `~/.crack/config.json`

**Usage:**
```bash
crack reference --fill bash-reverse-shell    # Auto-fill with config
crack reference --config auto                # Auto-detect network settings
crack reference post-exploit linux           # Browse by subcategory
crack reference --tag QUICK_WIN              # Filter by tag
```

**No Reinstall Needed** - JSON changes load dynamically (exception: `reference/core/*.py`)

**Documentation:** See `reference/docs/` for config guide, placeholder reference, tag explanations

## SQLi Module (`crack/sqli/`)

**Most complex module with sub-modules:**
```
sqli/
├── scanner.py      # Main orchestration (SQLiScanner class)
├── techniques.py   # Detection techniques (error, boolean, time, union)
├── databases.py    # DB-specific enumeration (MySQL, PostgreSQL, MSSQL, Oracle)
├── reporter.py     # Output formatting and reporting
└── reference.py    # Post-exploitation reference (sqli-fu command)
```

**Key Insight:** `sqli_scanner.py` is main entry point. Modify appropriate sub-module for functionality changes.

## Common Development Tasks

### Adding New CLI Command
Follow "CLI Architecture Pattern" above. Always run `./reinstall.sh`.

### Modifying Existing Tools
- **No reinstall needed**: Changes to tool logic (if used as library)
- **Reinstall needed**: Changes to CLI structure or `crack` command integration

### Adding Dependencies
1. Update `pyproject.toml` dependencies
2. Run `./reinstall.sh`

### Module Imports
```python
# ✓ Correct
from .utils.colors import Colors              # Relative import
from crack.utils.colors import Colors         # Absolute import

# ✗ Wrong
from crack.network import port_scanner        # Circular import in __init__.py
```

## Testing Philosophy

- **Unit tests**: Individual functions/classes (70%+ coverage target)
- **Integration tests**: CLI routing and module interactions
- **Functional tests**: Complete workflows
- **User-story driven**: Tests validate real OSCP workflows (BDD format)

**Mock Strategy:**
- Mock external commands (`subprocess.run`)
- Mock HTTP requests (`requests.Session`)
- Use real parsing logic with mock data

**Common fixtures** in `tests/conftest.py`:
- `temp_output_dir`, `mock_subprocess_run`, `mock_requests_session`

## Important Files

- `pyproject.toml`: Package metadata, dependencies, entry points
- `cli.py`: Main CLI router (all subcommands registered here)
- `reinstall.sh`: Development reinstall script
- `run_tests.sh`: Test runner with multiple modes
- `tests/conftest.py`: Shared test fixtures

## Package Info

- **PyPI Name**: `crack-toolkit`
- **Import Name**: `crack`
- **Entry Point**: `crack` command → `crack.cli:main`
- **Platform**: Kali Linux (OSCP preparation)
- **Python**: 3.8+
- **Dependencies**: requests, beautifulsoup4, urllib3
- **External Tools**: nmap, searchsploit, nikto (subprocess calls)

## Running Tools

```bash
# Via CLI (requires installation)
crack port-scan 192.168.45.100
crack track new 192.168.45.100
crack reference --fill bash-reverse-shell

# Standalone (no installation)
python3 -m crack.network.port_scanner 192.168.45.100
python3 -m crack.track.cli 192.168.45.100
```

## Educational Philosophy (OSCP Focus)

Every tool follows these principles:
1. **Manual alternatives** - For exam scenarios where tools fail
2. **Flag explanations** - Teach methodology, not just commands
3. **Time estimates** - Help with exam time management
4. **Success/failure indicators** - Verify results
5. **Next steps** - Guide attack chain progression
6. **Source tracking** - Required for OSCP report submission

## Quick Reference: When to Reinstall

**Reinstall Required:**
- Changes to `__init__.py` (module structure)
- Changes to `cli.py` (CLI command registration)
- Changes to `pyproject.toml` (entry points, dependencies)
- Changes to `track/cli.py` (Track CLI routing)
- Changes to `reference/core/*.py` (Reference core logic)

**No Reinstall Needed:**
- Changes to tool logic (if used as library)
- Changes to `track/interactive/` modules
- Changes to `track/services/` plugins
- Changes to `track/alternatives/commands/`
- Changes to `reference/data/commands/` JSON files
- Test file changes

## Documentation Deep Dives

For detailed implementation guides, see:
- **Track Module**: `track/README.md` (comprehensive usage + architecture)
- **Interactive Mode**: `track/README.md` (extension patterns, best practices)
- **Alternative Commands**: `track/alternatives/README.md` (developer guide)
- **Reference System**: `reference/docs/` (config, placeholders, tags)
- **SQLi Module**: Module-level docstrings in `sqli/*.py`
- **Test Philosophy**: `tests/track/README.md` (user stories, value validation)
