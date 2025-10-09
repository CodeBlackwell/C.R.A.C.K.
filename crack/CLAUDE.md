# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**C.R.A.C.K.** - **C**omprehensive **R**econ & **A**ttack **C**reation **K**it

A modular penetration testing toolkit for OSCP preparation. It consists of multiple standalone tools unified under a single CLI interface.

### CRACK Track Module

**C.R.A.C.K. T.R.A.C.K.** - The enumeration tracking and task management system:
- **C**omprehensive **R**econ & **A**ttack **C**reation **K**it
- **T**argeted **R**econnaissance **A**nd **C**ommand **K**onsole

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
├── services/                # Service-specific plugins (235+ plugins)
│   ├── http.py             # HTTP/HTTPS enumeration
│   ├── smb.py              # SMB enumeration
│   ├── ssh.py              # SSH enumeration
│   ├── ftp.py              # FTP enumeration
│   ├── sql.py              # SQL database enumeration
│   ├── post_exploit.py     # Post-exploitation tasks
│   └── registry.py         # Service plugin auto-discovery
├── alternatives/            # Alternative Commands system (NEW)
│   ├── models.py           # Data models (AlternativeCommand, Variable)
│   ├── context.py          # Context-aware variable resolution
│   ├── executor.py         # Dynamic command execution
│   ├── registry.py         # Command registry with pattern matching
│   └── commands/           # Command definitions (45+ alternatives)
│       ├── web_enumeration.py
│       ├── privilege_escalation.py
│       ├── file_transfer.py
│       ├── anti_forensics.py
│       ├── database_enum.py
│       └── network_recon.py
├── phases/                  # Enumeration phase management
│   ├── definitions.py      # Phase task definitions
│   └── registry.py         # Phase progression logic
├── recommendations/         # Task recommendation engine
│   └── engine.py           # Context-aware next-step suggestions
├── formatters/              # Output formatters
│   ├── console.py          # Terminal-friendly display
│   └── markdown.py         # OSCP writeup export
├── interactive/             # Interactive mode
│   ├── session.py          # State machine loop
│   ├── prompts.py          # Context-aware menus
│   ├── shortcuts.py        # Keyboard shortcuts ('alt' key)
│   └── display.py          # Terminal UI
└── cli.py                  # CLI interface

Storage: ~/.crack/targets/<TARGET>.json
Config: ~/.crack/config.json
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

## Interactive Mode Development

**CRACK Track Interactive Mode** (`track/interactive/`) provides a progressive prompting system for OSCP workflows. This section covers how to extend and customize the interactive experience.

### Overview

Interactive mode uses a state machine architecture with the following flow:

```
Loop: Display Context → Build Menu → Get Input → Process Choice → Execute Action → Save Checkpoint → Repeat
```

**Key Design Principles:**
- **Zero dependencies** - Uses only Python stdlib + existing CRACK infrastructure
- **Session persistence** - Auto-saves after every action to `~/.crack/sessions/`
- **Context-aware** - Menus adapt based on target state (phase, ports, findings)
- **Keyboard shortcuts** - Single-key commands for expert efficiency
- **Educational focus** - OSCP preparation with source tracking and flag explanations

### Architecture Components

```
track/interactive/
├── session.py          # Main state machine loop (600 lines)
├── prompts.py          # Context-aware menu generation (350 lines)
├── input_handler.py    # Input parsing & validation (300 lines)
├── display.py          # Terminal formatting & UI (270 lines)
├── decision_trees.py   # Navigation system (400 lines)
├── shortcuts.py        # Keyboard shortcut handlers (150 lines)
└── __init__.py         # Module exports
```

**Session State:**
```python
class InteractiveSession:
    profile: TargetProfile          # Target state
    last_action: str                # Last action performed
    start_time: int                 # Session start timestamp
    target: str                     # Target IP/hostname
```

**Checkpoint Format** (`~/.crack/sessions/TARGET.json`):
```json
{
  "target": "192.168.45.100",
  "phase": "service-specific",
  "last_action": "Imported nmap scan",
  "start_time": 1699564800,
  "timestamp": 1699564900
}
```

### Adding New Menu Options

**Step 1: Define Choice in PromptBuilder**

Edit `track/interactive/prompts.py`:

```python
@classmethod
def _get_enumeration_choices(cls, profile) -> List[Dict[str, Any]]:
    """Get enumeration phase specific choices"""
    choices = []

    # Your new choice
    choices.append({
        'id': 'auto-exploit',           # Unique ID
        'label': 'Auto-exploit found vulnerabilities',
        'description': 'Run Metasploit against known vulns'
    })

    # Conditional choice (only show if conditions met)
    if len(profile.findings) > 0:
        choices.append({
            'id': 'exploit-findings',
            'label': 'Exploit documented findings',
            'description': f'Attempt exploitation on {len(profile.findings)} finding(s)'
        })

    return choices
```

**Step 2: Add Handler in InteractiveSession**

Edit `track/interactive/session.py`:

```python
def process_input(self, user_input: str, choices: List[Dict], recommendations: Dict) -> bool:
    """Process user input and execute action"""

    # ... existing code ...

    # Handle your new choice
    if choice['id'] == 'auto-exploit':
        self.handle_auto_exploit()
        self.last_action = "Auto-exploit attempted"
        return True

    elif choice['id'] == 'exploit-findings':
        self.handle_exploit_findings()
        self.last_action = "Findings exploitation attempted"
        return True


def handle_auto_exploit(self):
    """Handle auto-exploitation action"""
    print(DisplayManager.format_info("Searching for exploits..."))

    # Your logic here
    vulnerabilities = [f for f in self.profile.findings if f['type'] == 'vulnerability']

    if not vulnerabilities:
        print(DisplayManager.format_warning("No vulnerabilities documented yet"))
        return

    # Show vulnerabilities
    for i, vuln in enumerate(vulnerabilities, 1):
        print(f"{i}. {vuln['description']}")

    # Confirmation
    confirm = input(DisplayManager.format_confirmation("Proceed with exploitation?", default='N'))
    if not InputProcessor.parse_confirmation(confirm, default='N'):
        print("Cancelled")
        return

    # Execute
    # ... your exploitation logic ...

    # Save result
    self.profile.add_note(
        note="Attempted auto-exploitation",
        source="interactive mode"
    )
    self.profile.save()
```

**Step 3: Test**

```bash
# No reinstall needed for interactive changes
pytest tests/track/test_interactive.py::TestPromptBuilder -v

# Manual testing
crack track -i 192.168.45.100
```

### Adding Keyboard Shortcuts

**Step 1: Register Shortcut in ShortcutHandler**

Edit `track/interactive/shortcuts.py`:

```python
def __init__(self, session):
    self.session = session

    # Add your shortcut
    self.shortcuts: Dict[str, Tuple[str, str]] = {
        's': ('Show full status', 'show_status'),
        't': ('Show task tree', 'show_tree'),
        'r': ('Show recommendations', 'show_recommendations'),
        'n': ('Execute next recommended task', 'do_next'),
        'e': ('Auto-exploit findings', 'auto_exploit'),  # NEW
        'b': ('Go back', 'go_back'),
        'h': ('Show help', 'show_help'),
        'q': ('Quit and save', 'quit')
    }


def auto_exploit(self):
    """Execute auto-exploitation (shortcut: e)"""
    from ..formatters.console import ConsoleFormatter

    print(DisplayManager.format_info("Auto-exploit mode"))

    # Call session handler
    self.session.handle_auto_exploit()
```

**Step 2: Update Help Text**

Edit `track/interactive/prompts.py`:

```python
@classmethod
def build_help_text(cls) -> str:
    """Build help text for interactive mode"""
    help_text = f"""
Interactive Mode Help
{'=' * 50}

KEYBOARD SHORTCUTS:
  s - Show full status and task tree
  t - Show task tree only
  r - Show recommendations
  n - Execute next recommended task
  e - Auto-exploit documented findings  # NEW
  b - Go back to previous menu
  h - Show this help
  q - Quit and save

...
"""
    return help_text
```

**Step 3: Test**

```python
# tests/track/test_interactive.py

def test_auto_exploit_shortcut(temp_crack_home, mock_profile_with_findings):
    """PROVES: 'e' shortcut triggers auto-exploit"""
    session = InteractiveSession(mock_profile_with_findings.target)
    handler = ShortcutHandler(session)

    # Verify shortcut exists
    assert 'e' in handler.shortcuts

    # Verify handler callable
    assert hasattr(handler, 'auto_exploit')
```

### Extending Decision Trees

**Step 1: Add New Node to Existing Tree**

Edit `track/interactive/decision_trees.py`:

```python
@staticmethod
def create_exploitation_tree() -> DecisionTree:
    """Create exploitation phase decision tree"""

    # Existing root
    root_choices = [
        Choice(
            id='research',
            label='Research exploits',
            description='Search exploitdb, GitHub, Metasploit',
            action='research_exploits'
        ),
        # NEW CHOICE
        Choice(
            id='auto-exploit',
            label='Automated exploitation',
            description='Auto-exploit with Metasploit',
            next_node='auto-exploit-menu',  # Navigate to new node
            requires={'has_vulnerabilities': True}  # Conditional
        )
    ]

    root = DecisionNode(
        node_id='exploit-root',
        question='Vulnerabilities found. Next steps:',
        choices=root_choices
    )

    # NEW NODE
    auto_exploit_choices = [
        Choice(
            id='msf-auto',
            label='Metasploit auto-exploit',
            action='run_metasploit_auto'
        ),
        Choice(
            id='manual-exploit',
            label='Manual exploitation',
            action='manual_exploit_guide'
        ),
        Choice(
            id='back',
            label='Back to exploitation menu',
            next_node='exploit-root'
        )
    ]

    auto_exploit_node = DecisionNode(
        node_id='auto-exploit-menu',
        question='Select exploitation method:',
        choices=auto_exploit_choices
    )

    # Build tree
    tree = DecisionTree('exploitation', root)
    tree.add_node(auto_exploit_node)  # Register new node

    return tree
```

**Step 2: Implement Choice Actions**

In `session.py`, add handlers for new actions:

```python
def run_metasploit_auto(self):
    """Execute Metasploit auto-exploitation"""
    print(DisplayManager.format_info("Launching Metasploit..."))
    # Implementation
    pass


def manual_exploit_guide(self):
    """Show manual exploitation guide"""
    print(DisplayManager.format_info("Manual Exploitation Guide"))
    # Show step-by-step instructions
    pass
```

**Step 3: Connect to Session Loop**

```python
def process_input(self, user_input: str, choices: List[Dict], recommendations: Dict) -> bool:
    """Process user input and execute action"""

    # ... existing code ...

    # Execute action from choice
    if choice.get('action'):
        action_name = choice['action']

        # Map actions to handlers
        action_map = {
            'research_exploits': self.research_exploits,
            'run_metasploit_auto': self.run_metasploit_auto,      # NEW
            'manual_exploit_guide': self.manual_exploit_guide,    # NEW
        }

        handler = action_map.get(action_name)
        if handler:
            handler()
            return True
```

**Step 4: Test Decision Tree Navigation**

```python
# tests/track/test_interactive.py

def test_auto_exploit_node_navigation():
    """PROVES: Auto-exploit node navigates correctly"""
    tree = DecisionTreeFactory.create_exploitation_tree()

    # Verify node exists
    auto_node = tree.get_node('auto-exploit-menu')
    assert auto_node is not None

    # Navigate to it
    context = {'has_vulnerabilities': True}
    result = tree.navigate_to('auto-exploit-menu', context)
    assert result is not None
    assert tree.current_node.id == 'auto-exploit-menu'

    # Navigate back
    tree.navigate_back()
    assert tree.current_node.id == 'exploit-root'
```

### Creating a New Phase Tree

**Step 1: Define Tree Structure**

```python
@staticmethod
def create_custom_phase_tree() -> DecisionTree:
    """Create custom phase decision tree"""

    root_choices = [
        Choice(
            id='option-1',
            label='First option',
            description='Description',
            action='handle_option_1'
        ),
        Choice(
            id='option-2',
            label='Second option',
            next_node='submenu-1'
        )
    ]

    root = DecisionNode(
        node_id='custom-root',
        question='What would you like to do?',
        choices=root_choices
    )

    # Submenu node
    submenu_choices = [
        Choice(id='sub-1', label='Sub option 1', action='handle_sub_1'),
        Choice(id='back', label='Back', next_node='custom-root')
    ]

    submenu = DecisionNode(
        node_id='submenu-1',
        question='Submenu:',
        choices=submenu_choices
    )

    tree = DecisionTree('custom-phase', root)
    tree.add_node(submenu)

    return tree
```

**Step 2: Register in Factory**

```python
@staticmethod
def create_phase_tree(phase: str) -> Optional[DecisionTree]:
    """Create decision tree for specific phase"""
    if phase == 'discovery':
        return DecisionTreeFactory.create_discovery_tree()
    elif phase in ['service-detection', 'service-specific']:
        return DecisionTreeFactory.create_enumeration_tree()
    elif phase == 'exploitation':
        return DecisionTreeFactory.create_exploitation_tree()
    elif phase == 'post-exploit':
        return DecisionTreeFactory.create_post_exploit_tree()
    elif phase == 'custom-phase':                                    # NEW
        return DecisionTreeFactory.create_custom_phase_tree()        # NEW

    return None
```

### Adding Guided Forms

**Step 1: Define Form Fields in PromptBuilder**

```python
@classmethod
def build_exploit_form(cls) -> List[Dict[str, Any]]:
    """Build guided form for exploit documentation"""
    return [
        {
            'name': 'exploit_name',
            'type': str,
            'required': True,
            'prompt': 'Exploit name/CVE',
            'example': 'CVE-2021-41773 or EternalBlue'
        },
        {
            'name': 'target_service',
            'type': str,
            'required': True,
            'prompt': 'Target service',
            'example': 'Apache 2.4.41, SMBv1'
        },
        {
            'name': 'exploit_path',
            'type': str,
            'required': False,
            'prompt': 'Path to exploit script',
            'example': '/usr/share/exploitdb/exploits/linux/remote/50383.py'
        },
        {
            'name': 'payload',
            'type': str,
            'required': False,
            'prompt': 'Payload used',
            'example': 'linux/x64/shell_reverse_tcp'
        },
        {
            'name': 'success',
            'type': bool,
            'required': True,
            'prompt': 'Exploitation successful? (y/n)',
            'example': 'y'
        }
    ]
```

**Step 2: Implement Form Handler**

```python
def handle_exploit_documentation(self):
    """Guide user through exploit documentation form"""

    print(DisplayManager.format_info("Exploit Documentation Form"))
    print("=" * 50)

    # Get form definition
    form = PromptBuilder.build_exploit_form()

    # Collect values
    values = {}
    for field in form:
        while True:
            # Show prompt with example
            prompt = f"\n{field['prompt']}"
            if field.get('example'):
                prompt += f" (e.g., {field['example']})"
            if not field['required']:
                prompt += " [optional]"
            prompt += ": "

            # Get input
            user_input = input(prompt)

            # Validate
            if field['required'] and not user_input:
                print(DisplayManager.format_error("This field is required"))
                continue

            # Parse by type
            if field['type'] == bool:
                values[field['name']] = InputProcessor.parse_confirmation(user_input)
            else:
                values[field['name']] = user_input

            break

    # Save to profile
    exploit_note = f"""
Exploit Documentation:
- Name: {values['exploit_name']}
- Service: {values['target_service']}
- Script: {values.get('exploit_path', 'N/A')}
- Payload: {values.get('payload', 'N/A')}
- Success: {values['success']}
"""

    self.profile.add_finding(
        finding_type='exploit_attempt',
        description=values['exploit_name'],
        source=f"Exploit: {values.get('exploit_path', 'manual')}"
    )

    self.profile.add_note(exploit_note, source='interactive mode')
    self.profile.save()

    print(DisplayManager.format_success("Exploit documented!"))
```

### Session Persistence Patterns

**Checkpoint Best Practices:**

```python
def save_checkpoint(self):
    """Save session checkpoint"""
    checkpoint_file = self.sessions_dir / f"{self.target}.json"

    checkpoint_data = {
        'target': self.target,
        'phase': self.profile.phase,
        'last_action': self.last_action,
        'start_time': self.start_time,
        'timestamp': int(datetime.now().timestamp()),
        # Add custom state
        'custom_state': {
            'current_menu': self.current_menu_id,
            'navigation_history': self.nav_history,
            'user_preferences': self.preferences
        }
    }

    checkpoint_file.write_text(json.dumps(checkpoint_data, indent=2))


def load_checkpoint(self) -> Dict[str, Any]:
    """Load session checkpoint"""
    checkpoint_file = self.sessions_dir / f"{self.target}.json"

    if not checkpoint_file.exists():
        return {}

    try:
        data = json.loads(checkpoint_file.read_text())

        # Restore custom state
        if 'custom_state' in data:
            self.current_menu_id = data['custom_state'].get('current_menu')
            self.nav_history = data['custom_state'].get('navigation_history', [])
            self.preferences = data['custom_state'].get('user_preferences', {})

        return data

    except json.JSONDecodeError:
        print(DisplayManager.format_warning("Checkpoint corrupted, starting fresh"))
        return {}
```

**Always save after modifications:**

```python
def execute_task(self, task):
    """Execute a task and save state"""
    # Execute
    result = self._run_task_command(task)

    # Update state
    self.profile.mark_task_done(task.id)
    self.last_action = f"Completed: {task.name}"

    # Save both profile and checkpoint
    self.profile.save()          # ← Profile to ~/.crack/targets/
    self.save_checkpoint()       # ← Session to ~/.crack/sessions/
```

### Testing Interactive Features

**Value-Focused Testing Pattern:**

```python
# tests/track/test_interactive.py

class TestNewFeature:
    """Prove new feature works for OSCP workflows"""

    def test_complete_workflow(self, temp_crack_home, mock_profile, simulated_input):
        """
        PROVES: User can complete [feature] workflow

        Workflow:
        1. User selects new option
        2. System displays form/menu
        3. User enters data
        4. System saves to profile
        5. Data persists across sessions
        """
        # Setup
        session = InteractiveSession(mock_profile.target)

        # Simulate user input
        simulated_input(['new-option', 'data1', 'data2', 'yes'])

        # Execute
        # ... trigger your feature ...

        # Verify outcome
        assert len(session.profile.findings) > 0

        # Verify persistence
        session.profile.save()
        loaded = TargetProfile.load(mock_profile.target)
        assert loaded.findings == session.profile.findings


    def test_error_handling(self, temp_crack_home):
        """PROVES: Feature degrades gracefully on error"""
        # Test invalid input, missing data, etc.
        pass
```

**Test Real Objects, Not Mocks:**

```python
# ✓ Good - Tests real behavior
def test_menu_generation(mock_profile_with_services):
    """Test menu adapts to profile state"""
    prompt, choices = PromptBuilder.build_main_menu(
        mock_profile_with_services,
        {}
    )

    # Verify menu contains expected options
    choice_ids = [c['id'] for c in choices]
    assert 'import' in choice_ids
    assert 'exit' in choice_ids


# ✗ Avoid - Tests mock, not real code
def test_menu_generation_mocked(mocker):
    """Don't do this"""
    mock_builder = mocker.patch('PromptBuilder.build_main_menu')
    mock_builder.return_value = ("prompt", [])
    # This tests the mock, not the real PromptBuilder
```

### Common Patterns

**Pattern 1: Conditional Menu Options**

```python
# Only show option if condition met
if profile.phase == 'exploitation' and len(profile.findings) > 0:
    choices.append({
        'id': 'exploit',
        'label': 'Exploit vulnerabilities',
        'description': f'{len(profile.findings)} vuln(s) found'
    })
```

**Pattern 2: Multi-Step Workflows**

```python
def multi_step_workflow(self):
    """Example multi-step workflow"""
    # Step 1: Selection
    print("Step 1: Select target service")
    services = list(self.profile.ports.keys())
    for i, port in enumerate(services, 1):
        print(f"{i}. Port {port}")

    choice = input("Select port: ")
    selected_port = services[int(choice) - 1]

    # Step 2: Configuration
    print(f"\nStep 2: Configure scan for port {selected_port}")
    wordlist = input("Wordlist [/usr/share/wordlists/common.txt]: ") or "/usr/share/wordlists/common.txt"

    # Step 3: Confirmation
    print(f"\nReady to scan port {selected_port} with {wordlist}")
    if not InputProcessor.parse_confirmation(input("Proceed? [Y/n]: "), default='Y'):
        return

    # Step 4: Execute
    # ... execute scan ...

    # Step 5: Save
    self.profile.save()
    self.save_checkpoint()
```

**Pattern 3: Context-Aware Recommendations**

```python
def get_context_aware_menu(profile: TargetProfile) -> tuple:
    """Build menu based on current context"""

    # Check what's been done
    has_ports = len(profile.ports) > 0
    has_http = any(p.get('service') == 'http' for p in profile.ports.values())
    has_findings = len(profile.findings) > 0
    has_creds = len(profile.credentials) > 0

    # Adapt recommendations
    if not has_ports:
        return "No ports found. Scan now?", [
            {'id': 'quick-scan', 'label': 'Quick scan'},
            {'id': 'full-scan', 'label': 'Full scan'}
        ]

    elif has_http and not any('gobuster' in t.id for t in profile.task_tree.get_all_pending()):
        return "HTTP found. Enumerate web?", [
            {'id': 'run-gobuster', 'label': 'Directory brute-force'},
            {'id': 'run-nikto', 'label': 'Vulnerability scan'}
        ]

    elif has_findings and not has_creds:
        return "Vulnerabilities found. Need creds?", [
            {'id': 'brute-force', 'label': 'Credential brute-force'},
            {'id': 'exploit', 'label': 'Try exploits'}
        ]

    else:
        return "What next?", [
            {'id': 'status', 'label': 'Show status'},
            {'id': 'export', 'label': 'Export report'}
        ]
```

### No Reinstall Needed

Unlike other CRACK modules, **interactive mode changes don't require reinstall**:

```bash
# Edit interactive code
vim track/interactive/session.py
vim track/interactive/prompts.py

# Test immediately - no reinstall needed!
crack track -i 192.168.45.100

# Run tests
pytest tests/track/test_interactive.py -v
```

**Exception**: Changes to `track/cli.py` or CLI routing DO require reinstall:

```bash
# If you modify CLI integration
vim track/cli.py

# Then reinstall
./reinstall.sh
```

### Best Practices

1. **Always provide context** - Menus should adapt to profile state
2. **Confirm destructive actions** - Use `InputProcessor.parse_confirmation()`
3. **Save frequently** - Call `profile.save()` and `save_checkpoint()` after changes
4. **Handle Ctrl+C gracefully** - Wrap in try/except KeyboardInterrupt
5. **Provide alternatives** - Multiple paths to accomplish same goal
6. **Test with real profiles** - Use fixtures like `mock_profile_with_services`
7. **Keep it educational** - Show commands, explain flags, track sources
8. **Limit choices** - 3-7 options per menu for cognitive load
9. **Use shortcuts** - Single-key for common actions
10. **Support resume** - Session state should survive interruption

### Development Workflow

```bash
# 1. Modify interactive module
vim track/interactive/prompts.py

# 2. Add test
vim tests/track/test_interactive.py

# 3. Run test
pytest tests/track/test_interactive.py::TestNewFeature -v

# 4. Manual test
crack track -i 192.168.45.100

# 5. Commit (no reinstall needed!)
git add track/interactive/ tests/track/
git commit -m "Add new interactive feature"
```

## Alternative Commands Architecture

The Alternative Commands system (`crack/track/alternatives/`) provides context-aware manual command alternatives for when automated tools fail during OSCP exams. Press `alt` in interactive mode to execute manual methods with auto-filled variables.

### Overview

**Status**: Production Ready (Phases 1-6 Complete)
**Tests**: 83/83 passing (100%)
**Implementation Date**: 2025-10-09

Alternative Commands solve the OSCP exam problem: automated tools fail, but manual methods always work.

### Directory Structure

```
track/alternatives/
├── models.py               # Data models (129 lines)
│   ├── AlternativeCommand  # Command definition with metadata
│   ├── Variable            # Variable with auto-resolution config
│   └── ExecutionResult     # Command execution results
├── context.py              # Context resolution (166 lines)
│   ├── ContextResolver     # Variable resolution engine
│   ├── WORDLIST_CONTEXTS   # Context-aware wordlist mapping
│   └── resolution priority # Task → Profile → Config → User
├── executor.py             # Dynamic execution (220 lines)
│   ├── AlternativeExecutor # Command execution with auto-fill
│   ├── _resolve_all        # Auto-resolve all variables
│   ├── _prompt_user        # Interactive prompting
│   └── execute             # Template substitution + execution
├── registry.py             # Command registry (198 lines)
│   ├── AlternativeCommandRegistry # Central command store
│   ├── auto_link_to_task   # Pattern matching for task linkage
│   ├── _by_task_pattern    # Index by task ID patterns
│   ├── _by_service         # Index by service type
│   └── _by_tag             # Index by OSCP tags
└── commands/               # Command definitions (45+ alternatives)
    ├── README.md           # Developer guide
    ├── TEMPLATE.py         # Copy-paste examples
    ├── web_enumeration.py  # 10+ web alternatives
    ├── privilege_escalation.py  # 10+ privesc alternatives
    ├── file_transfer.py    # 10+ transfer alternatives
    ├── anti_forensics.py   # 10+ cleanup alternatives
    ├── database_enum.py    # 10+ database alternatives
    └── network_recon.py    # 10+ recon alternatives

Tests: tests/track/alternatives/
Config: ~/.crack/config.json (shared with reference system)
```

### Key Architecture Decisions

**1. Config System Reuse**
- Reuses existing `crack/reference/core/config.py`
- Single source of truth for LHOST, LPORT, WORDLIST
- User-familiar interface: `crack reference --config auto`

**2. Metadata Field Design**
- Added `alternative_ids` alongside existing `alternatives` field
- Zero breaking changes (backward compatible)
- Clear separation: `alternatives` = text, `alternative_ids` = executable

**3. Pattern Matching Approach**
- Pattern matching on task IDs (`gobuster-*` → http alternatives)
- Service-based matching (`http` → web alternatives)
- Tag-based matching (`OSCP:HIGH` → prioritized alternatives)
- Performance: <1ms per task

**4. Context Resolution Priority**
```python
# Variable resolution order (most specific wins)
1. Task Metadata    → <PORT>: 80 (from gobuster-80)
2. Profile State    → <TARGET>: 192.168.45.100 (from profile)
3. Config Variables → <LHOST>: 192.168.1.113 (from config)
4. User Prompt      → <DIRECTORY>: admin (user enters)
```

**5. Wordlist Context Design**
```python
# Purpose-based with service refinement
WORDLIST_CONTEXTS = {
    'web-enumeration': '/usr/share/wordlists/dirb/common.txt',
    'password-cracking': '/usr/share/wordlists/rockyou.txt',
    'ssh-specific': '/usr/share/seclists/.../ssh-passwords.txt',
    'parameter-fuzzing': '/usr/share/seclists/.../burp-parameter-names.txt'
}

# Automatic purpose inference from task
if 'gobuster' in task.id or 'dirb' in task.id:
    purpose = 'web-enumeration'
elif 'hydra' in task.id or 'medusa' in task.id:
    purpose = 'password-cracking'
```

### Phase Implementation Summary

**Phase 1-4: Core Infrastructure** (Completed 2025-10-09)
- Data models (AlternativeCommand, Variable, ExecutionResult)
- Dynamic executor with template substitution
- Command registry with search and filtering
- Interactive mode integration ('alt' shortcut)

**Phase 5: Config Integration** (Completed 2025-10-09)
- Config-aware variable resolution (LHOST, LPORT, WORDLIST)
- Context-aware wordlist selection
- Priority-based resolution with source tracking
- Auto-detection from network interfaces

**Phase 6: Task Tree Linkage** (Completed 2025-10-09)
- TaskNode metadata enhancement (alternative_ids, alternative_context)
- Service plugin integration (HTTP plugin as reference)
- Registry pattern matching (glob patterns, service, tags)
- Display integration (badges, details)
- Interactive mode enhancements (context-aware menu)

### Usage Flow

```
User in interactive mode
    ↓ Press 'alt'
Context-aware alternative menu
    ↓ User selects alternative
ContextResolver.resolve_all()
    ↓
Task Metadata check → PORT: 80 ✓
Profile State check → TARGET: 192.168.45.100 ✓
Config check → LHOST: 192.168.1.113 ✓
    ↓ Missing: DIRECTORY
User prompt → DIRECTORY: admin
    ↓
AlternativeExecutor.execute()
    ↓
Template substitution: curl http://192.168.45.100:80/admin
    ↓ User confirms
Command execution
    ↓
Log to profile with timestamp
    ↓
Continue interactive session
```

### Pattern Matching Algorithm

```python
def auto_link_to_task(task: TaskNode) -> List[str]:
    """Auto-discover alternatives for a task"""
    matches = []

    # 1. Pattern match task ID (fnmatch)
    for pattern, alt_ids in registry._by_task_pattern.items():
        if fnmatch.fnmatch(task.id, pattern):
            matches.extend(alt_ids)
            # Example: 'gobuster-80' matches 'gobuster-*'

    # 2. Match by service from metadata
    if task.metadata.get('service'):
        service_alts = registry._by_service.get(task.metadata['service'], [])
        matches.extend(service_alts)
        # Example: service='http' → http alternatives

    # 3. Match by tags
    for tag in task.metadata.get('tags', []):
        tag_alts = registry._by_tag.get(tag, [])
        matches.extend(tag_alts)
        # Example: 'OSCP:HIGH' → high-priority alternatives

    return list(set(matches))  # Deduplicate

# Performance: <1ms per task, even with 100+ alternatives
```

### Integration with Existing Systems

**Zero Breaking Changes**:
- All 235+ service plugins work unchanged
- Event-driven architecture intact
- Storage format backward compatible
- Task tree structure unchanged
- Old profiles load automatically

**Reused Components**:
- ConfigManager from reference module (LHOST, LPORT)
- DisplayManager from interactive module (formatting)
- InputProcessor from interactive module (user input)
- Existing task metadata structure

**Service Plugin Integration** (Optional Enhancement):
```python
# Example: HTTP plugin auto-links alternatives
def get_task_tree(self, target: str, port: int, service_info: Dict) -> Dict:
    return {
        'id': f'gobuster-{port}',
        'name': f'Directory Brute-force (Port {port})',
        'metadata': {
            'command': f'gobuster dir -u http://{target}:{port} -w common.txt',
            'alternative_ids': [              # AUTO-LINKED
                'alt-manual-dir-check',
                'alt-robots-check'
            ],
            'alternative_context': {          # CONTEXT FOR RESOLUTION
                'service': 'http',
                'port': port,
                'purpose': 'web-enumeration'
            }
        }
    }
```

### Testing Strategy

**Test Philosophy**: Prove value to OSCP students with real scenarios

**83 Tests Total**:
- 25 tests: Config integration (test_config_integration.py)
- 21 tests: Registry pattern matching (test_registry_auto_linking.py)
- 18 tests: Task tree linkage (test_phase6_linkage.py)
- 11 tests: Display integration (test_phase6_display.py)
- 20 tests: End-to-end workflows (test_integration_workflows.py)

**Test Categories**:
1. **Unit Tests**: Test functions in isolation
2. **Integration Tests**: Test with real objects (no mocks)
3. **Workflow Tests**: Test complete OSCP scenarios
4. **Performance Tests**: Verify <100ms targets

**Example Test**:
```python
def test_web_enum_wordlist_selects_web_wordlist(mock_profile):
    """
    PROVES: Web enumeration task gets dirb/common.txt, NOT rockyou.txt

    Real OSCP scenario: Student runs gobuster and needs correct wordlist.
    Wrong wordlist wastes precious exam time.
    """
    # Create gobuster task
    task = TaskNode(
        id='gobuster-80',
        name='Directory Brute-force',
        metadata={'service': 'http', 'port': 80}
    )

    # Resolve wordlist with web-enumeration context
    resolver = ContextResolver(profile=mock_profile, task=task)
    wordlist = resolver.resolve('WORDLIST', context_hints={'purpose': 'web-enumeration'})

    # Assert correct wordlist selected
    assert 'dirb/common.txt' in wordlist
    assert 'rockyou.txt' not in wordlist  # Wrong wordlist!

    # Assert resolution source tracked
    assert resolver.get_resolution_source('WORDLIST') == 'context'
```

### Performance Benchmarks

All targets exceeded:

| Operation | Target | Actual | Status |
|-----------|--------|--------|--------|
| Registry Load | <100ms | ~50ms | ✅ EXCEEDED |
| Pattern Matching | <100ms | <1ms | ✅ EXCEEDED |
| Config Loading | <100ms | ~10ms | ✅ EXCEEDED |
| Full Test Suite | <10s | 4.27s | ✅ EXCEEDED |

### Adding New Alternative Commands

**Quick Example**:
```python
# File: crack/track/alternatives/commands/web_enumeration.py

from ..models import AlternativeCommand, Variable

ALTERNATIVES = [
    AlternativeCommand(
        id='alt-manual-dir-check',
        name='Manual Directory Check',
        command_template='curl http://<TARGET>:<PORT>/<DIRECTORY>',
        description='Use curl to manually test common directories',
        category='web-enumeration',
        variables=[
            Variable(name='TARGET', auto_resolve=True, required=True),
            Variable(name='PORT', auto_resolve=True, required=True),
            Variable(name='DIRECTORY', auto_resolve=False, required=True,
                    description='Directory to test', example='admin')
        ],
        tags=['MANUAL', 'OSCP:HIGH', 'QUICK_WIN'],
        parent_task_pattern='gobuster-*',  # Auto-links to gobuster tasks
        oscp_relevance='high',
        notes='Test common directories when gobuster fails'
    )
]
```

**No reinstall needed** - Commands load dynamically from JSON-like Python modules.

### Development Workflow

```bash
# 1. Modify alternative command
vim track/alternatives/commands/web_enumeration.py

# 2. Test immediately (no reinstall needed!)
crack track -i 192.168.45.100
# Press 'alt' → Your command appears

# 3. Run tests
pytest tests/track/alternatives/ -v

# 4. Commit
git add track/alternatives/
git commit -m "Add new alternative command"
```

### Documentation

**For Users**:
- User guide: `track/alternatives/README.md` (comprehensive)
- Main README: `track/README.md` (Alternative Commands section)

**For Developers**:
- Developer guide: `alternatives/commands/README.md`
- Template: `alternatives/commands/TEMPLATE.py`
- Tests: `tests/track/alternatives/` (reference examples)

**For Architecture**:
- Integration plan: `docs/ALTERNATIVE_COMMANDS_INTEGRATION_PLAN.md`
- Implementation summary: `docs/ALTERNATIVE_COMMANDS_IMPLEMENTATION_SUMMARY.md`
- Completion report: `docs/PHASE_5_6_COMPLETION_REPORT.md`
- Execution checklist: `docs/PHASE_5_6_EXECUTION_CHECKLIST.md`

### Future Enhancements

**Next priorities** (out of scope for current implementation):
1. Expand service plugin integration (SMB, SSH, FTP, SQL)
2. Grow command library to 350+ alternatives
3. Agent mining (CrackPot mines alternatives from HackTricks)
4. Success tracking (mark alternatives as working/not working)
5. Workflow chaining (sequence of alternatives)

**Production Status**: ✅ READY FOR DEPLOYMENT

---

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
