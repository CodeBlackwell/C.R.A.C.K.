# CRACK Track Plugin Contribution Guide

**Welcome!** This guide explains how to contribute service plugins to CRACK Track. Service plugins automatically generate enumeration tasks when specific services are detected during port scanning.

---

## Table of Contents

- [Overview](#overview)
- [Plugin Architecture](#plugin-architecture)
- [Required Components](#required-components)
- [Schema Specifications](#schema-specifications)
- [Development Workflow](#development-workflow)
- [Testing Requirements](#testing-requirements)
- [OSCP Best Practices](#oscp-best-practices)
- [Code Style](#code-style)
- [Submission Checklist](#submission-checklist)
- [Examples](#examples)

---

## Overview

### What is a Service Plugin?

A service plugin is a Python class that:

1. **Detects** when a specific service is found (e.g., FTP on port 21)
2. **Generates** a hierarchical task tree for enumerating that service
3. **Provides** educational metadata for OSCP exam preparation

### Plugin Lifecycle

```
User imports nmap scan
    ↓
Parser emits service_detected event
    ↓
ServiceRegistry calls your plugin's detect() method
    ↓
If detect() returns True:
    ↓
Registry calls your plugin's get_task_tree() method
    ↓
Tasks added to TargetProfile
    ↓
Tasks appear in CLI (standard and interactive)
```

### Auto-Discovery

Plugins are automatically discovered using the `@ServiceRegistry.register` decorator. No manual registration required!

```python
from .base import ServicePlugin
from .registry import ServiceRegistry

@ServiceRegistry.register  # ← Automatic registration
class YourPlugin(ServicePlugin):
    # Your implementation
```

---

## Plugin Architecture

### File Location

Create your plugin in: `track/services/your_service.py`

### Required Imports

```python
from typing import Dict, Any, List
from .base import ServicePlugin
from .registry import ServiceRegistry
```

### Class Structure

```python
@ServiceRegistry.register
class YourServicePlugin(ServicePlugin):
    """Brief description of what this plugin handles"""

    @property
    def name(self) -> str:
        """Unique identifier for this plugin"""
        pass

    def detect(self, port_info: Dict[str, Any]) -> bool:
        """Return True if this plugin handles this service"""
        pass

    def get_task_tree(self, target: str, port: int, service_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate task tree for this service"""
        pass
```

---

## Required Components

### 1. Plugin Name (Property)

**Purpose:** Unique identifier for logging and debugging

**Type:** `str`

**Rules:**
- Lowercase
- No spaces (use hyphens if needed)
- Descriptive (e.g., "http", "smb", "ftp")

**Example:**

```python
@property
def name(self) -> str:
    return "mysql"
```

---

### 2. Detection Method

**Signature:** `def detect(self, port_info: Dict[str, Any]) -> bool`

**Purpose:** Determine if this plugin should handle a discovered port/service

**Input Schema:**

```python
port_info = {
    'port': int,              # Port number (e.g., 80)
    'state': str,             # Port state: 'open', 'closed', 'filtered'
    'service': str,           # Service name from nmap (e.g., 'http', 'mysql')
    'product': str,           # Product name (e.g., 'Apache httpd')
    'version': str,           # Version string (e.g., '2.4.41')
    'extrainfo': str,         # Additional info (e.g., '(Ubuntu)')
    'ostype': str,            # Detected OS (optional)
    'source': str             # Data source (e.g., 'nmap service scan')
}
```

**Return Value:** `bool`
- `True` = This plugin handles this service
- `False` = Skip this plugin for this port

**Best Practices:**

✅ **DO:**
```python
def detect(self, port_info: Dict[str, Any]) -> bool:
    service = port_info.get('service', '').lower()
    port = port_info.get('port')

    # Check service name (primary)
    if service in ['mysql', 'mysql-proxy']:
        return True

    # Check port number (fallback)
    if port == 3306:
        return True

    return False
```

❌ **DON'T:**
```python
def detect(self, port_info: Dict[str, Any]) -> bool:
    # Don't crash on missing keys
    return port_info['service'] == 'mysql'  # ← Will crash if 'service' missing

    # Don't be too restrictive
    return port_info.get('service') == 'MySQL'  # ← Case-sensitive, will miss 'mysql'
```

**Defensive Coding:**

```python
def detect(self, port_info: Dict[str, Any]) -> bool:
    # Always use .get() with defaults
    service = port_info.get('service', '').lower()
    product = port_info.get('product', '').lower()
    port = port_info.get('port', 0)

    # Check multiple indicators
    return (
        'mysql' in service or
        'mysql' in product or
        port == 3306
    )
```

---

### 3. Task Tree Generator

**Signature:** `def get_task_tree(self, target: str, port: int, service_info: Dict[str, Any]) -> Dict[str, Any]`

**Purpose:** Generate hierarchical task tree for enumeration

**Input Parameters:**

```python
target: str          # Target IP or hostname (e.g., "192.168.45.100")
port: int            # Port number (e.g., 3306)
service_info: Dict   # Full service information (same schema as detect())
```

**Return Value:** Task tree dictionary (see [Schema Specifications](#task-tree-schema))

**Example:**

```python
def get_task_tree(self, target: str, port: int, service_info: Dict[str, Any]) -> Dict[str, Any]:
    version = service_info.get('version', 'unknown')
    product = service_info.get('product', 'MySQL')

    return {
        'id': f'mysql-enum-{port}',
        'name': f'MySQL Enumeration (Port {port})',
        'type': 'parent',
        'children': [
            # Task definitions here...
        ]
    }
```

---

## Schema Specifications

### Task Tree Schema

#### Root Task (Parent Container)

```python
{
    'id': str,              # REQUIRED: Unique ID (include port: 'http-enum-80')
    'name': str,            # REQUIRED: Human-readable name
    'type': 'parent',       # REQUIRED: Must be 'parent' for root
    'children': List[Dict]  # REQUIRED: Array of child tasks
}
```

#### Child Task (Command/Action)

```python
{
    'id': str,              # REQUIRED: Unique ID (e.g., 'mysql-version-3306')
    'name': str,            # REQUIRED: Task name (e.g., 'Check MySQL Version')
    'type': str,            # REQUIRED: 'command', 'parent', 'manual', 'research'
    'metadata': Dict        # RECOMMENDED: Task metadata (see below)
}
```

#### Metadata Schema (OSCP Focus)

```python
'metadata': {
    # === COMMAND (Required for type='command') ===
    'command': str,                    # Exact command to execute

    # === DESCRIPTION ===
    'description': str,                # What this accomplishes

    # === EDUCATIONAL (Required for OSCP) ===
    'flag_explanations': {             # Explain every flag
        '-flag': 'What it does and why',
        'argument': 'Purpose of this argument'
    },

    # === GUIDANCE ===
    'success_indicators': List[str],   # How to verify success
    'failure_indicators': List[str],   # Common failure modes
    'next_steps': List[str],           # What to do after completion

    # === ALTERNATIVES (Required for OSCP) ===
    'alternatives': List[str],         # Manual alternatives when tools fail

    # === CLASSIFICATION ===
    'tags': List[str],                 # Tags (see Tag Standards)

    # === OPTIONAL ===
    'estimated_time': str,             # Time estimate (e.g., '2-3 minutes')
    'notes': str                       # Additional context, tips, warnings
}
```

---

### Task Types

| Type | Purpose | Has Command | Has Children |
|------|---------|-------------|--------------|
| `command` | Executable task | ✅ Yes | ❌ No |
| `parent` | Container for subtasks | ❌ No | ✅ Yes |
| `manual` | Manual action required | ❌ Optional | ❌ No |
| `research` | Information gathering | ❌ Optional | ❌ No |

**Examples:**

```python
# TYPE: command
{
    'id': 'mysql-version-3306',
    'name': 'Check MySQL Version',
    'type': 'command',
    'metadata': {
        'command': 'mysql -h 192.168.45.100 -P 3306 -u root --version',
        'description': 'Identify MySQL version for exploit research'
    }
}

# TYPE: parent (container)
{
    'id': 'mysql-brute-3306',
    'name': 'MySQL Brute-force',
    'type': 'parent',
    'children': [
        # Child tasks here...
    ]
}

# TYPE: manual
{
    'id': 'mysql-manual-enum-3306',
    'name': 'Manual MySQL Enumeration',
    'type': 'manual',
    'metadata': {
        'description': 'Review MySQL configuration files',
        'alternatives': [
            'Check /etc/mysql/my.cnf',
            'Check ~/.my.cnf'
        ]
    }
}

# TYPE: research
{
    'id': 'mysql-cve-3306',
    'name': 'CVE Research: MySQL 5.7.40',
    'type': 'research',
    'metadata': {
        'command': 'searchsploit MySQL 5.7.40',
        'description': 'Search for known vulnerabilities'
    }
}
```

---

### Tag Standards

Use consistent tags for filtering and prioritization:

#### Priority Tags
- `OSCP:HIGH` - Critical for OSCP exam
- `OSCP:MEDIUM` - Recommended for OSCP
- `OSCP:LOW` - Optional/advanced
- `QUICK_WIN` - Fast, high-value tasks (< 5 minutes)

#### Method Tags
- `MANUAL` - Manual action required
- `AUTOMATED` - Fully automated
- `NOISY` - Generates significant traffic
- `STEALTH` - Low-profile enumeration

#### Phase Tags
- `RECON` - Initial reconnaissance
- `ENUM` - Service enumeration
- `EXPLOIT` - Exploitation phase
- `PRIVESC` - Privilege escalation
- `POST_EXPLOIT` - Post-exploitation

#### Type Tags
- `RESEARCH` - Information gathering
- `BRUTE_FORCE` - Credential brute-forcing
- `VULN_SCAN` - Vulnerability scanning

**Example:**
```python
'tags': ['QUICK_WIN', 'OSCP:HIGH', 'ENUM', 'MANUAL']
```

---

## Development Workflow

### Step 1: Create Plugin File

```bash
# Create plugin file
vim track/services/your_service.py
```

### Step 2: Implement Required Methods

```python
from typing import Dict, Any
from .base import ServicePlugin
from .registry import ServiceRegistry


@ServiceRegistry.register
class YourServicePlugin(ServicePlugin):
    """Description of your plugin"""

    @property
    def name(self) -> str:
        return "your-service"

    def detect(self, port_info: Dict[str, Any]) -> bool:
        service = port_info.get('service', '').lower()
        return 'your-service' in service

    def get_task_tree(self, target: str, port: int, service_info: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'id': f'your-service-enum-{port}',
            'name': f'Your Service Enumeration (Port {port})',
            'type': 'parent',
            'children': [
                # Your tasks here
            ]
        }
```

### Step 3: Test Plugin

```bash
# No reinstall needed for plugins!
# Create test target
crack track new 192.168.45.100

# Import scan with your service
crack track import 192.168.45.100 test_scan.xml

# Verify tasks generated
crack track show 192.168.45.100

# Test in interactive mode
crack track -i 192.168.45.100
```

### Step 4: Write Tests

Create test file: `tests/track/services/test_your_service.py`

```python
import pytest
from crack.track.services.your_service import YourServicePlugin


def test_plugin_detection():
    """PROVES: Plugin detects your service"""
    plugin = YourServicePlugin()

    port_info = {
        'port': 1234,
        'service': 'your-service'
    }

    assert plugin.detect(port_info) == True


def test_task_generation():
    """PROVES: Plugin generates valid task tree"""
    plugin = YourServicePlugin()

    service_info = {
        'port': 1234,
        'service': 'your-service',
        'version': '1.0.0'
    }

    tree = plugin.get_task_tree('192.168.45.100', 1234, service_info)

    # Verify structure
    assert tree['id'] == 'your-service-enum-1234'
    assert tree['type'] == 'parent'
    assert 'children' in tree
    assert len(tree['children']) > 0

    # Verify metadata
    first_task = tree['children'][0]
    assert 'metadata' in first_task
    assert 'command' in first_task['metadata']
    assert 'flag_explanations' in first_task['metadata']
```

### Step 5: Submit Pull Request

1. Ensure all tests pass: `pytest tests/track/services/test_your_service.py -v`
2. Verify plugin appears in registry: `crack track list`
3. Create pull request with:
   - Plugin file (`track/services/your_service.py`)
   - Test file (`tests/track/services/test_your_service.py`)
   - Documentation updates (if needed)

---

## Testing Requirements

### Minimum Test Coverage

Your plugin must include tests for:

1. **Detection logic** - Verify `detect()` correctly identifies services
2. **Task generation** - Verify `get_task_tree()` returns valid structure
3. **Metadata completeness** - Verify OSCP-required fields present

### Test Template

```python
import pytest
from crack.track.services.your_service import YourServicePlugin


class TestYourServicePlugin:
    """Test suite for YourService plugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return YourServicePlugin()

    def test_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "your-service"

    def test_detect_by_service_name(self, plugin):
        """PROVES: Plugin detects service by name"""
        port_info = {'service': 'your-service', 'port': 1234}
        assert plugin.detect(port_info) == True

    def test_detect_by_port(self, plugin):
        """PROVES: Plugin detects service by port"""
        port_info = {'service': 'unknown', 'port': 1234}
        assert plugin.detect(port_info) == True

    def test_detect_negative(self, plugin):
        """PROVES: Plugin rejects unrelated services"""
        port_info = {'service': 'http', 'port': 80}
        assert plugin.detect(port_info) == False

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid structure"""
        tree = plugin.get_task_tree('192.168.45.100', 1234, {'service': 'your-service'})

        # Root structure
        assert 'id' in tree
        assert 'name' in tree
        assert 'type' in tree
        assert tree['type'] == 'parent'
        assert 'children' in tree

        # Has tasks
        assert len(tree['children']) > 0

    def test_oscp_metadata(self, plugin):
        """PROVES: Tasks include OSCP-required metadata"""
        tree = plugin.get_task_tree('192.168.45.100', 1234, {'service': 'your-service'})

        # Check first command task
        command_tasks = [t for t in tree['children'] if t['type'] == 'command']
        assert len(command_tasks) > 0

        task = command_tasks[0]
        metadata = task.get('metadata', {})

        # Required fields
        assert 'command' in metadata, "Command tasks must have 'command' field"
        assert 'description' in metadata, "Tasks must have description"
        assert 'flag_explanations' in metadata, "Must explain all flags"
        assert 'alternatives' in metadata, "Must provide manual alternatives"

        # At least one tag
        assert 'tags' in metadata
        assert len(metadata['tags']) > 0
```

---

## OSCP Best Practices

### 1. Always Explain Flags

❌ **Bad:**
```python
'command': 'nmap -sV -sC -p- target'
```

✅ **Good:**
```python
'command': 'nmap -sV -sC -p- target',
'flag_explanations': {
    '-sV': 'Service version detection (matches CVEs)',
    '-sC': 'Default NSE scripts (finds vulnerabilities)',
    '-p-': 'Scan all 65535 ports (thorough enumeration)'
}
```

### 2. Provide Manual Alternatives

Every automated task must include manual alternatives for OSCP exam scenarios where tools fail or are unavailable.

❌ **Bad:**
```python
{
    'command': 'gobuster dir -u http://target -w wordlist.txt'
    # No alternatives provided
}
```

✅ **Good:**
```python
{
    'command': 'gobuster dir -u http://target -w wordlist.txt',
    'alternatives': [
        'Manual: curl http://target/admin',
        'Manual: curl http://target/upload',
        'Manual: curl http://target/backup',
        'Browser: View page source for hidden directories',
        'ffuf -u http://target/FUZZ -w wordlist.txt'
    ]
}
```

### 3. Guide the Attack Chain

Use `next_steps` to guide users through the enumeration process:

```python
'next_steps': [
    'Review discovered directories for sensitive files',
    'Check for upload functionality',
    'Look for admin panels',
    'Test for directory traversal',
    'Research identified technologies for CVEs'
]
```

### 4. Include Success/Failure Indicators

Help users verify results and diagnose issues:

```python
'success_indicators': [
    'Directories found (Status: 200, 301, 302)',
    'Admin panels discovered',
    'Upload forms located'
],
'failure_indicators': [
    'Connection timeout (host may be down)',
    'All requests return 404 (wrong wordlist)',
    '403 Forbidden (firewall blocking)',
    'Rate limited (too many requests)'
]
```

### 5. Provide Time Estimates

Help users plan their exam time:

```python
'estimated_time': '2-3 minutes',  # Quick checks
'estimated_time': '10-15 minutes',  # Standard scans
'estimated_time': '30+ minutes'  # Brute-force, exhaustive scans
```

### 6. Tag for Priority

Use tags to help users identify critical tasks:

```python
'tags': ['QUICK_WIN', 'OSCP:HIGH']  # Do this first!
'tags': ['OSCP:MEDIUM', 'ENUM']     # Standard enumeration
'tags': ['OSCP:LOW', 'ADVANCED']    # Optional/advanced
```

---

## Code Style

### Python Standards

- **PEP 8** compliance
- **Type hints** for all parameters and return values
- **Docstrings** for all classes and methods
- **Descriptive variable names** (avoid single letters except loop counters)

### Naming Conventions

- **Class names**: `PascalCase` (e.g., `MySQLPlugin`)
- **Method names**: `snake_case` (e.g., `get_task_tree`)
- **Task IDs**: `kebab-case` with port (e.g., `mysql-version-3306`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `DEFAULT_TIMEOUT`)

### Documentation

Every plugin must include:

```python
"""
Brief description of what this plugin handles

Longer description explaining:
- What services are detected
- What enumeration tasks are generated
- Any special considerations

Example:
    This plugin handles MySQL/MariaDB database servers.
    Generates tasks for version checking, user enumeration,
    and credential brute-forcing.
"""
```

### Error Handling

Plugins should be defensive and never crash:

```python
def detect(self, port_info: Dict[str, Any]) -> bool:
    try:
        service = port_info.get('service', '').lower()
        return 'mysql' in service
    except Exception:
        # Log error but don't crash
        return False

def get_task_tree(self, target: str, port: int, service_info: Dict[str, Any]) -> Dict[str, Any]:
    # Always provide fallback values
    version = service_info.get('version', 'unknown')
    product = service_info.get('product', 'MySQL')

    # Defensive checks
    if not target:
        target = 'TARGET'

    # Return valid structure even on error
    return {
        'id': f'mysql-enum-{port}',
        'name': f'MySQL Enumeration (Port {port})',
        'type': 'parent',
        'children': []  # At minimum, return empty children
    }
```

---

## Submission Checklist

Before submitting your plugin:

### Code Quality
- [ ] Plugin inherits from `ServicePlugin`
- [ ] Decorated with `@ServiceRegistry.register`
- [ ] All 3 required methods implemented
- [ ] Type hints on all methods
- [ ] Docstrings present
- [ ] No syntax errors
- [ ] PEP 8 compliant

### Detection
- [ ] `detect()` handles service name variations
- [ ] `detect()` checks port numbers as fallback
- [ ] `detect()` uses `.get()` with defaults (defensive)
- [ ] `detect()` never crashes on missing fields

### Task Generation
- [ ] Root task has unique ID with port number
- [ ] Root task type is `parent`
- [ ] At least 3-5 child tasks
- [ ] Each task has proper `type`
- [ ] Task IDs are unique and descriptive

### Metadata (OSCP)
- [ ] All command tasks have `metadata.command`
- [ ] All flags explained in `flag_explanations`
- [ ] `success_indicators` included
- [ ] `failure_indicators` included
- [ ] `next_steps` guide attack progression
- [ ] `alternatives` provide manual options
- [ ] Appropriate `tags` added
- [ ] Time estimates included (optional but recommended)

### Testing
- [ ] Unit tests for `detect()` method (positive and negative cases)
- [ ] Unit tests for task tree structure
- [ ] Unit tests for metadata completeness
- [ ] All tests pass: `pytest tests/track/services/test_your_service.py -v`
- [ ] Manual testing with real nmap scan
- [ ] Verified tasks appear in interactive mode

### Documentation
- [ ] Plugin docstring explains purpose
- [ ] Complex logic has inline comments
- [ ] Examples provided for usage
- [ ] README updated (if adding new capability)

---

## Examples

### Example 1: Simple Plugin (FTP)

```python
from typing import Dict, Any
from .base import ServicePlugin
from .registry import ServiceRegistry


@ServiceRegistry.register
class FTPPlugin(ServicePlugin):
    """FTP service enumeration plugin"""

    @property
    def name(self) -> str:
        return "ftp"

    def detect(self, port_info: Dict[str, Any]) -> bool:
        service = port_info.get('service', '').lower()
        port = port_info.get('port')

        return 'ftp' in service or port == 21

    def get_task_tree(self, target: str, port: int, service_info: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'id': f'ftp-enum-{port}',
            'name': f'FTP Enumeration (Port {port})',
            'type': 'parent',
            'children': [
                {
                    'id': f'ftp-anon-{port}',
                    'name': 'Check Anonymous Login',
                    'type': 'command',
                    'metadata': {
                        'command': f'ftp {target} {port}',
                        'description': 'Test anonymous FTP access',
                        'flag_explanations': {
                            'ftp': 'FTP client command',
                            target: 'Target IP/hostname',
                            str(port): 'FTP port'
                        },
                        'success_indicators': [
                            'Login successful with username "anonymous"',
                            'File listing appears'
                        ],
                        'failure_indicators': [
                            'Login incorrect',
                            'Anonymous login disabled'
                        ],
                        'next_steps': [
                            'List files: ls -la',
                            'Download files: get filename',
                            'Test write access: put test.txt'
                        ],
                        'alternatives': [
                            f'nc {target} {port} (manual FTP)',
                            f'nmap --script ftp-anon -p {port} {target}'
                        ],
                        'tags': ['QUICK_WIN', 'OSCP:HIGH', 'MANUAL'],
                        'estimated_time': '2-3 minutes'
                    }
                }
            ]
        }
```

### Example 2: Complex Plugin with Conditional Tasks

```python
from typing import Dict, Any
from .base import ServicePlugin
from .registry import ServiceRegistry


@ServiceRegistry.register
class MySQLPlugin(ServicePlugin):
    """MySQL/MariaDB enumeration plugin"""

    @property
    def name(self) -> str:
        return "mysql"

    def detect(self, port_info: Dict[str, Any]) -> bool:
        service = port_info.get('service', '').lower()
        product = port_info.get('product', '').lower()
        port = port_info.get('port')

        return (
            'mysql' in service or
            'mariadb' in service or
            'mysql' in product or
            port == 3306
        )

    def get_task_tree(self, target: str, port: int, service_info: Dict[str, Any]) -> Dict[str, Any]:
        version = service_info.get('version', 'unknown')
        product = service_info.get('product', 'MySQL')

        tasks = {
            'id': f'mysql-enum-{port}',
            'name': f'MySQL Enumeration (Port {port})',
            'type': 'parent',
            'children': []
        }

        # Always include version check
        tasks['children'].append({
            'id': f'mysql-version-{port}',
            'name': 'Check MySQL Version',
            'type': 'command',
            'metadata': {
                'command': f'mysql -h {target} -P {port} -u root --version',
                'description': 'Identify MySQL version for exploit research',
                'tags': ['QUICK_WIN', 'OSCP:HIGH']
            }
        })

        # Add brute-force task
        tasks['children'].append({
            'id': f'mysql-brute-{port}',
            'name': 'MySQL Brute-force',
            'type': 'command',
            'metadata': {
                'command': f'hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/common_passwords.txt {target} mysql -s {port}',
                'description': 'Brute-force MySQL credentials',
                'tags': ['OSCP:MEDIUM', 'BRUTE_FORCE', 'NOISY'],
                'estimated_time': '10-30 minutes'
            }
        })

        # Conditional: Add exploit research if version known
        if version and version != 'unknown':
            tasks['children'].append(
                self._create_exploit_research(product, version, port)
            )

        return tasks

    def _create_exploit_research(self, product: str, version: str, port: int) -> Dict[str, Any]:
        """Create exploit research task"""
        search_term = f"{product} {version}"

        return {
            'id': f'mysql-exploit-{port}',
            'name': f'Exploit Research: {search_term}',
            'type': 'parent',
            'children': [
                {
                    'id': f'mysql-searchsploit-{port}',
                    'name': 'SearchSploit Lookup',
                    'type': 'command',
                    'metadata': {
                        'command': f'searchsploit "{search_term}"',
                        'description': f'Search exploit-db for {search_term}',
                        'tags': ['OSCP:HIGH', 'RESEARCH']
                    }
                }
            ]
        }
```

---

## Getting Help

### Resources

- **Documentation**: `/home/kali/OSCP/crack/track/README.md`
- **Examples**: See existing plugins in `track/services/`
- **Tests**: See `tests/track/services/` for test examples

### Questions?

- Check existing plugins for patterns
- Review test suite for examples
- Create GitHub issue for support

---

## License

By contributing, you agree that your contributions will be licensed under the same license as the CRACK Track project.

---

**Thank you for contributing to CRACK Track!** Your plugin will help OSCP students enumerate services more effectively. 🎯
