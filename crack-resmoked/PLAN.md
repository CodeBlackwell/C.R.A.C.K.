# CRACK-RESMOKED: MVP Rebuild Plan

## Executive Summary

### The Problem

The original CRACK toolkit has become over-engineered:
- **16,000+ lines** of TUI code
- **126 service plugins** built without proper testing
- **Complex event-driven architecture** with EventBus, ServiceRegistry, FindingsProcessor
- **Intelligence systems** (pattern learning, telemetry, correlation engines) that aren't fully functional
- **Multiple abstraction layers** that make debugging difficult
- **Feature creep** - too much built at once without validation

**Result**: Good ideas, buggy implementation, difficult to maintain or extend.

### The Solution

**CRACK-RESMOKED** - A minimal viable product that:
- Preserves the **core philosophy** (TUI as pentesting command center)
- Maintains the **intelligent flow** (service discovery → enumeration triggers)
- Simplifies the **architecture** (direct calls, no events)
- Focuses on **3 core services** first (HTTP, SMB, SSH)
- Builds **incrementally** with full testing at each step

### Core Value Proposition

**"The TUI guides you through pentesting methodology naturally"**

- Host discovery → Port scanning → Service detection → Enumeration → Exploitation
- Service found triggers appropriate enumeration
- Findings generate new recommendations
- Everything tracked for OSCP reporting

### Success Metrics

- **< 1,500 lines** total codebase
- **3 working plugins** (HTTP, SMB, SSH)
- **80%+ test coverage**
- **< 100ms TUI load time**
- **Zero external dependencies** (stdlib + subprocess only)
- **Can go from nmap → task list in 3 clicks**

---

## Core Philosophy

### 1. The TUI is the Pentester's Command Center

Not just a menu system - an intelligent hub that:
- **Tracks** where you are in methodology
- **Suggests** what to do next based on findings
- **Records** everything for reporting
- **Flows** naturally from recon → enum → exploit
- **Adapts** recommendations based on discovered services

### 2. Natural Pentesting Flow

```
1. HOST DISCOVERY
   └─> Is target alive?

2. PORT SCANNING
   └─> What ports are open?

3. SERVICE DETECTION
   └─> What services are running?

4. SERVICE ENUMERATION ←─────┐
   └─> HTTP? → Web crawling   │
   └─> SMB? → Share enum      │ LOOP: Findings
   └─> SSH? → Version check   │ trigger new
                               │ enumeration
5. FINDING ANALYSIS            │
   └─> /admin found?           │
   └─> Anonymous SMB?          │
   └─> Old SSH version?        │
                               │
6. VULNERABILITY RESEARCH      │
   └─> searchsploit            │
   └─> CVE lookup              │
                               │
7. EXPLOITATION ATTEMPTS ──────┘
   └─> Test exploit
   └─> Get shell?

8. POST-EXPLOITATION
   └─> Privilege escalation
   └─> Lateral movement
```

### 3. Context-Aware Intelligence

The TUI understands context:
- **Phase awareness** - Discovery vs enumeration vs exploitation
- **Service awareness** - HTTP gets gobuster, SMB gets enum4linux
- **Finding awareness** - /admin found → check for auth bypass
- **Priority awareness** - Quick wins vs deep enumeration

### 4. Simplicity Over Cleverness

- **Direct method calls** (no event bus)
- **Simple if/then logic** (no pattern learning)
- **Flat data structures** (no hierarchical trees)
- **Readable code** (boring is good)

---

## Pentesting Methodology Flow

### Phase Definitions

```
PHASE 1: HOST DISCOVERY
  Goal: Determine if target is alive
  Tools: ping, nmap -sn
  Next: Port scanning

PHASE 2: PORT SCANNING
  Goal: Find open ports
  Tools: nmap -p-, masscan
  Next: Service detection

PHASE 3: SERVICE DETECTION
  Goal: Identify services and versions
  Tools: nmap -sV -sC
  Next: Service enumeration

PHASE 4: SERVICE ENUMERATION
  Goal: Deep enumeration of each service
  Tools: gobuster, enum4linux, nikto
  Next: Vulnerability research
  Loop: New findings trigger more enumeration

PHASE 5: VULNERABILITY RESEARCH
  Goal: Find exploits for versions/misconfigs
  Tools: searchsploit, CVE databases
  Next: Exploitation

PHASE 6: EXPLOITATION
  Goal: Gain initial access
  Tools: Exploit code, Metasploit
  Next: Post-exploitation

PHASE 7: POST-EXPLOITATION
  Goal: Privilege escalation, persistence
  Tools: linpeas, winPEAS, kernel exploits
  Next: Complete compromise
```

### State Transitions

```
┌─────────────────┐
│ Host Discovery  │
└────────┬────────┘
         │ (host alive)
         ▼
┌─────────────────┐
│  Port Scanning  │
└────────┬────────┘
         │ (ports found)
         ▼
┌─────────────────┐
│Service Detection│
└────────┬────────┘
         │ (services identified)
         ▼
┌─────────────────────────┐
│ Service Enumeration     │◄─────┐
│                         │      │
│ For each service:       │      │
│  - HTTP → Web enum      │      │
│  - SMB  → Share enum    │      │
│  - SSH  → Version check │      │
└────────┬────────────────┘      │
         │ (findings discovered) │
         │                       │
         │ ┌──────────────────┐  │
         └►│ Finding Analysis │──┘
           │                  │   (Loop: New findings
           │ - Directory?     │    trigger more enum)
           │ - Credential?    │
           │ - Version?       │
           └────────┬─────────┘
                    │ (vulnerabilities identified)
                    ▼
           ┌─────────────────┐
           │ Vulnerability   │
           │    Research     │
           └────────┬────────┘
                    │ (exploits found)
                    ▼
           ┌─────────────────┐
           │  Exploitation   │
           └────────┬────────┘
                    │ (shell obtained)
                    ▼
           ┌─────────────────┐
           │Post-Exploitation│
           └─────────────────┘
```

### Phase Detection Logic

The system auto-detects current phase based on profile state:

```
IF no host_alive flag
  → PHASE: Host Discovery
  → RECOMMENDATION: "Ping target to verify it's alive"

ELSE IF no ports in profile
  → PHASE: Port Scanning
  → RECOMMENDATION: "Run full port scan (nmap -p-)"

ELSE IF ports exist BUT no service versions
  → PHASE: Service Detection
  → RECOMMENDATION: "Run service scan (nmap -sV -sC)"

ELSE IF services identified AND no shell access
  → PHASE: Service Enumeration
  → RECOMMENDATIONS: Service-specific (HTTP→gobuster, SMB→enum4linux)

ELSE IF shell access obtained
  → PHASE: Post-Exploitation
  → RECOMMENDATION: "Run privilege escalation enumeration"
```

---

## Architecture Overview

### Component Map

```
crack-resmoked/
│
├── core/                    # Core data structures and logic
│   ├── profile.py          # Target state management
│   ├── storage.py          # JSON persistence
│   ├── flow.py             # Phase detection & transitions
│   └── recommendations.py  # Task recommendation engine
│
├── parsers/                 # Output parsers
│   ├── nmap.py             # Extract ports/services from XML
│   └── gobuster.py         # Extract directories from output
│
├── plugins/                 # Service-specific enumeration
│   ├── base.py             # Plugin interface
│   ├── http.py             # HTTP/HTTPS enumeration
│   ├── smb.py              # SMB enumeration
│   └── ssh.py              # SSH enumeration
│
├── tui/                     # Terminal User Interface
│   ├── hub.py              # Main command center
│   ├── display.py          # Formatting helpers
│   └── executor.py         # Command execution wrapper
│
└── tests/                   # Test suite
    ├── test_profile.py
    ├── test_flow.py
    ├── test_recommendations.py
    └── test_tui.py
```

### Data Flow

```
1. USER ACTION (TUI)
   └─> Execute nmap scan

2. IMPORT RESULTS
   └─> parsers/nmap.py extracts ports/services

3. UPDATE PROFILE
   └─> core/profile.py stores discoveries

4. DETECT PHASE
   └─> core/flow.py determines current phase

5. GENERATE RECOMMENDATIONS
   └─> core/recommendations.py queries plugins
   └─> plugins/http.py suggests gobuster
   └─> plugins/smb.py suggests enum4linux

6. DISPLAY IN TUI
   └─> tui/hub.py shows recommendations
   └─> User selects task

7. EXECUTE TASK
   └─> tui/executor.py runs command
   └─> Captures output

8. PARSE OUTPUT
   └─> parsers/gobuster.py extracts findings

9. ADD FINDINGS TO PROFILE
   └─> core/profile.py.add_finding()

10. LOOP: New findings trigger new recommendations
    └─> Back to step 5
```

### Responsibility Matrix

| Component | Responsibility | Lines | Dependencies |
|-----------|---------------|-------|--------------|
| `core/profile.py` | Target state, findings, tasks | ~100 | storage.py |
| `core/storage.py` | JSON save/load | ~50 | stdlib json |
| `core/flow.py` | Phase detection, transitions | ~150 | profile.py, plugins/ |
| `core/recommendations.py` | Task generation logic | ~100 | profile.py, plugins/ |
| `parsers/nmap.py` | Extract ports/services | ~80 | stdlib xml |
| `parsers/gobuster.py` | Extract directories | ~60 | stdlib re |
| `plugins/base.py` | Plugin interface | ~30 | None |
| `plugins/http.py` | HTTP enumeration tasks | ~100 | base.py |
| `plugins/smb.py` | SMB enumeration tasks | ~100 | base.py |
| `plugins/ssh.py` | SSH enumeration tasks | ~80 | base.py |
| `tui/hub.py` | Main TUI loop | ~300 | flow.py, recommendations.py |
| `tui/display.py` | Text formatting | ~100 | None |
| `tui/executor.py` | Command execution | ~80 | subprocess |
| **TOTAL** | | **~1,330** | **stdlib only** |

---

## Data Models

### TargetProfile

The core data structure representing all knowledge about a target.

```python
{
  "target": "192.168.1.1",
  "created": "2025-10-12T10:00:00",
  "updated": "2025-10-12T14:30:00",

  # Host state
  "host_alive": true,
  "shell_access": false,

  # Discovered ports
  "ports": {
    "22": {
      "service": "ssh",
      "version": "OpenSSH 7.4",
      "state": "open"
    },
    "80": {
      "service": "http",
      "version": "Apache 2.4.41",
      "state": "open"
    },
    "445": {
      "service": "microsoft-ds",
      "version": "Samba 4.9.5",
      "state": "open"
    }
  },

  # Enumeration findings
  "findings": [
    {
      "id": "f1",
      "timestamp": "2025-10-12T12:00:00",
      "type": "directory",
      "service": "http",
      "port": 80,
      "value": "/admin",
      "source": "gobuster",
      "command": "gobuster dir -u http://192.168.1.1"
    },
    {
      "id": "f2",
      "timestamp": "2025-10-12T12:15:00",
      "type": "smb_share",
      "service": "smb",
      "port": 445,
      "value": "\\\\192.168.1.1\\backup",
      "access": "anonymous",
      "source": "enum4linux"
    }
  ],

  # Tasks to perform
  "tasks": [
    {
      "id": "t1",
      "name": "Check robots.txt",
      "command": "curl http://192.168.1.1/robots.txt",
      "service": "http",
      "port": 80,
      "priority": "HIGH",
      "quick_win": true,
      "done": true,
      "completed": "2025-10-12T11:45:00"
    },
    {
      "id": "t2",
      "name": "Enumerate /admin directory",
      "command": "gobuster dir -u http://192.168.1.1/admin",
      "service": "http",
      "port": 80,
      "priority": "HIGH",
      "quick_win": false,
      "done": false,
      "triggered_by": "f1"  # Finding that triggered this task
    }
  ]
}
```

### Finding Types

```python
FINDING_TYPES = [
  "directory",      # Web directory found
  "file",           # Interesting file found
  "subdomain",      # Subdomain discovered
  "smb_share",      # SMB share enumerated
  "credential",     # Username/password found
  "version",        # Service version identified
  "vulnerability",  # Potential vuln discovered
  "misconfiguration", # Config issue found
  "user",           # Username enumerated
  "hash"            # Password hash found
]
```

### Task Structure

```python
{
  "id": "t123",
  "name": "Human-readable task name",
  "command": "Exact command to execute",
  "service": "http",  # Which service this targets
  "port": 80,
  "priority": "HIGH",  # HIGH, MEDIUM, LOW
  "quick_win": true,   # Quick tasks (< 1 minute)
  "done": false,
  "triggered_by": "f456",  # Finding ID that triggered this
  "created": "2025-10-12T12:00:00",
  "completed": null
}
```

### Recommendation Format

```python
{
  "task": {
    # Task object as above
  },
  "reason": "HTTP service found on port 80",
  "context": "service_enumeration",
  "priority": "HIGH",
  "estimated_time": "30 seconds"
}
```

---

## Component Specifications

### core/profile.py (~100 lines)

**Purpose**: Central data structure for target state

**Key Methods**:
```python
class TargetProfile:
    def __init__(self, target: str)
    def add_port(self, port: int, service: str, version: str)
    def add_finding(self, finding_type: str, value: str, ...)
    def add_task(self, name: str, command: str, ...)
    def complete_task(self, task_id: str)
    def get_tasks(self, done: bool = None, service: str = None)
    def get_findings(self, finding_type: str = None)
    def to_dict(self) -> dict
    def from_dict(cls, data: dict) -> TargetProfile
```

**Responsibilities**:
- Store all target information
- Provide query methods
- Serialize/deserialize to dict

**Does NOT**:
- Handle storage (that's storage.py)
- Generate recommendations (that's recommendations.py)
- Emit events (no event system)

---

### core/storage.py (~50 lines)

**Purpose**: JSON persistence layer

**Key Functions**:
```python
def save(profile: TargetProfile) -> None:
    """Save profile to ~/.crack-resmoked/targets/{target}.json"""

def load(target: str) -> TargetProfile:
    """Load profile from disk"""

def exists(target: str) -> bool:
    """Check if profile exists"""

def list_targets() -> List[str]:
    """List all saved targets"""

def delete(target: str) -> None:
    """Delete a profile"""
```

**Storage Location**: `~/.crack-resmoked/targets/`

**File Format**: `{target}.json` (e.g., `192.168.1.1.json`)

---

### core/flow.py (~150 lines)

**Purpose**: Pentesting methodology state machine

**Key Class**:
```python
class PentestFlow:
    PHASES = [
        'host_discovery',
        'port_scanning',
        'service_detection',
        'service_enumeration',
        'vulnerability_research',
        'exploitation',
        'post_exploitation'
    ]

    def __init__(self, profile: TargetProfile)
    def get_current_phase(self) -> str
    def get_phase_description(self) -> str
    def get_next_phase(self) -> str
    def advance_phase(self) -> None
    def can_advance(self) -> bool
```

**Phase Detection Logic**:
```python
def _detect_phase(self) -> str:
    """Auto-detect current phase based on profile state"""

    if not self.profile.host_alive:
        return 'host_discovery'

    if not self.profile.ports:
        return 'port_scanning'

    if not self._has_service_versions():
        return 'service_detection'

    if self.profile.shell_access:
        return 'post_exploitation'

    # Default to service enumeration
    return 'service_enumeration'
```

---

### core/recommendations.py (~100 lines)

**Purpose**: Generate task recommendations based on current state

**Key Class**:
```python
class Recommender:
    def __init__(self, profile: TargetProfile, flow: PentestFlow)

    def get_recommendations(self, limit: int = 5) -> List[dict]:
        """Get top N recommendations for current phase"""

    def process_finding(self, finding: dict) -> List[dict]:
        """Convert a finding into actionable tasks"""

    def _prioritize(self, tasks: List[dict]) -> List[dict]:
        """Sort tasks by priority and quick wins"""
```

**Recommendation Logic**:
```python
def get_recommendations(self, limit=5):
    recommendations = []
    phase = self.flow.get_current_phase()

    if phase == 'host_discovery':
        recommendations.append(self._create_ping_task())

    elif phase == 'port_scanning':
        recommendations.append(self._create_nmap_task())

    elif phase == 'service_detection':
        recommendations.append(self._create_service_scan_task())

    elif phase == 'service_enumeration':
        # Query each plugin for tasks
        for port, info in self.profile.ports.items():
            plugin = get_plugin_for_service(info['service'])
            if plugin:
                tasks = plugin.get_tasks(self.profile, port)
                recommendations.extend(tasks)

    return self._prioritize(recommendations)[:limit]
```

---

### parsers/nmap.py (~80 lines)

**Purpose**: Extract ports and services from nmap XML output

**Key Function**:
```python
def parse_nmap_xml(xml_file: str) -> dict:
    """
    Returns:
    {
        'ports': [
            {'port': 80, 'service': 'http', 'version': 'Apache 2.4.41'},
            {'port': 445, 'service': 'microsoft-ds', 'version': 'Samba 4.9.5'}
        ]
    }
    """
```

**XML Structure to Parse**:
```xml
<nmaprun>
  <host>
    <address addr="192.168.1.1"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.41"/>
      </port>
    </ports>
  </host>
</nmaprun>
```

---

### parsers/gobuster.py (~60 lines)

**Purpose**: Extract directories from gobuster output

**Key Function**:
```python
def parse_gobuster_output(output: str) -> List[dict]:
    """
    Returns:
    [
        {'path': '/admin', 'status': 200},
        {'path': '/backup', 'status': 301}
    ]
    """
```

**Gobuster Output Format**:
```
/admin                (Status: 200) [Size: 1234]
/backup               (Status: 301) [Size: 312]
/uploads              (Status: 403) [Size: 278]
```

**Parsing Strategy**: Regex matching for path and status code

---

### plugins/base.py (~30 lines)

**Purpose**: Plugin interface

**Base Class**:
```python
class ServicePlugin:
    """Base class for service enumeration plugins"""

    def detect(self, service: str, port: int, version: str) -> bool:
        """Return True if this plugin handles this service"""
        raise NotImplementedError

    def get_initial_tasks(self, profile: TargetProfile, port: int) -> List[dict]:
        """Get first tasks to run for this service"""
        raise NotImplementedError

    def get_followup_tasks(self, profile: TargetProfile, port: int, findings: List[dict]) -> List[dict]:
        """Get tasks based on findings"""
        raise NotImplementedError
```

**Plugin Registry**:
```python
PLUGINS = []

def register_plugin(plugin_class):
    PLUGINS.append(plugin_class())

def get_plugin_for_service(service: str, port: int) -> ServicePlugin:
    for plugin in PLUGINS:
        if plugin.detect(service, port, None):
            return plugin
    return None
```

---

### plugins/http.py (~100 lines)

**Purpose**: HTTP/HTTPS enumeration logic

**Service Detection**:
```python
def detect(self, service, port, version):
    return service in ['http', 'https'] or port in [80, 443, 8080, 8443]
```

**Initial Tasks**:
```python
def get_initial_tasks(self, profile, port):
    base_url = f"http://{profile.target}:{port}"

    return [
        {
            'name': 'Check robots.txt',
            'command': f'curl {base_url}/robots.txt',
            'priority': 'HIGH',
            'quick_win': True
        },
        {
            'name': 'Technology fingerprinting',
            'command': f'whatweb {base_url}',
            'priority': 'HIGH',
            'quick_win': True
        },
        {
            'name': 'Directory bruteforce',
            'command': f'gobuster dir -u {base_url} -w /usr/share/wordlists/dirb/common.txt',
            'priority': 'MEDIUM',
            'quick_win': False
        }
    ]
```

**Followup Tasks** (based on findings):
```python
def get_followup_tasks(self, profile, port, findings):
    tasks = []

    for finding in findings:
        if finding['type'] == 'directory':
            path = finding['value']

            # /admin found → Check for auth bypass
            if 'admin' in path.lower():
                tasks.append({
                    'name': f'Test authentication bypass on {path}',
                    'command': f'curl -I {base_url}{path}',
                    'priority': 'HIGH'
                })

            # /backup found → Look for backup files
            if 'backup' in path.lower():
                tasks.append({
                    'name': f'Search for backup files in {path}',
                    'command': f'gobuster dir -u {base_url}{path} -x bak,old,zip',
                    'priority': 'HIGH'
                })

    return tasks
```

---

### plugins/smb.py (~100 lines)

**Purpose**: SMB enumeration logic

**Service Detection**:
```python
def detect(self, service, port, version):
    return service in ['microsoft-ds', 'netbios-ssn', 'smb'] or port in [139, 445]
```

**Initial Tasks**:
```python
def get_initial_tasks(self, profile, port):
    return [
        {
            'name': 'Enumerate SMB shares',
            'command': f'smbclient -L //{profile.target} -N',
            'priority': 'HIGH',
            'quick_win': True
        },
        {
            'name': 'Run enum4linux',
            'command': f'enum4linux -a {profile.target}',
            'priority': 'MEDIUM',
            'quick_win': False
        }
    ]
```

**Followup Tasks**:
```python
def get_followup_tasks(self, profile, port, findings):
    tasks = []

    for finding in findings:
        if finding['type'] == 'smb_share':
            share = finding['value']

            # Anonymous share found → Try to mount
            if finding.get('access') == 'anonymous':
                tasks.append({
                    'name': f'Mount and browse {share}',
                    'command': f'smbclient {share} -N',
                    'priority': 'HIGH'
                })

    return tasks
```

---

### plugins/ssh.py (~80 lines)

**Purpose**: SSH enumeration logic

**Service Detection**:
```python
def detect(self, service, port, version):
    return service == 'ssh' or port == 22
```

**Initial Tasks**:
```python
def get_initial_tasks(self, profile, port):
    version = profile.ports[port].get('version', '')

    tasks = [
        {
            'name': 'SSH banner grab',
            'command': f'nc {profile.target} {port}',
            'priority': 'HIGH',
            'quick_win': True
        }
    ]

    # If version detected, search for exploits
    if version:
        tasks.append({
            'name': f'Search exploits for {version}',
            'command': f'searchsploit {version}',
            'priority': 'MEDIUM',
            'quick_win': True
        })

    return tasks
```

---

### tui/hub.py (~300 lines)

**Purpose**: Main TUI command center

**Key Class**:
```python
class PentestHub:
    def __init__(self):
        self.profile = None
        self.flow = None
        self.recommender = None

    def run(self):
        """Main TUI loop"""
        while True:
            self.clear_screen()
            self.display_header()
            self.display_context()
            self.display_recommendations()
            self.display_menu()

            choice = input("\nChoice: ").strip()
            self.handle_choice(choice)

    def display_context(self):
        """Show current state and discoveries"""

    def display_recommendations(self):
        """Show intelligent next steps"""

    def handle_choice(self, choice: str):
        """Process user input"""
```

**Display Example**:
```
========================================
CRACK-RESMOKED | Target: 192.168.1.1
Phase: Service Enumeration
========================================

DISCOVERED:
  ✓ Host alive
  ✓ 3 ports open (22, 80, 445)
  ✓ HTTP - Apache 2.4.41
  ✓ SMB - Samba 4.9.5
  ✓ SSH - OpenSSH 7.4

FINDINGS (2):
  [WEB] /admin (200)
  [SMB] \\backup (anonymous access)

RECOMMENDATIONS:
  [1] Check /admin authentication    (HIGH, <1min)
  [2] Mount SMB backup share         (HIGH, <1min)
  [3] Directory scan on /admin       (MED, ~5min)
  [4] Search OpenSSH 7.4 exploits    (MED, <1min)
  [5] Full directory bruteforce      (LOW, ~10min)

QUICK ACTIONS:
  [n] Execute next (recommendation #1)
  [1-5] Execute specific recommendation
  [a] Add custom task
  [f] Record finding
  [i] Import nmap scan
  [v] View all tasks
  [s] Show full status

Choice: _
```

---

### tui/display.py (~100 lines)

**Purpose**: Text formatting helpers

**Key Functions**:
```python
def format_header(target: str, phase: str) -> str:
    """Format TUI header"""

def format_port(port: int, service: str, version: str) -> str:
    """Format single port display"""

def format_finding(finding: dict) -> str:
    """Format finding for display"""

def format_task(task: dict, index: int) -> str:
    """Format task recommendation"""

def format_priority(priority: str) -> str:
    """Colorize priority (HIGH=red, MED=yellow, LOW=green)"""
```

**Display Helpers**:
```python
def truncate(text: str, max_len: int) -> str:
    """Truncate long text with ..."""

def wrap_text(text: str, width: int) -> List[str]:
    """Word wrap text to width"""
```

---

### tui/executor.py (~80 lines)

**Purpose**: Execute commands and capture output

**Key Class**:
```python
class CommandExecutor:
    def execute(self, command: str) -> dict:
        """
        Execute command and return results

        Returns:
        {
            'success': True,
            'stdout': 'command output',
            'stderr': '',
            'returncode': 0
        }
        """

    def execute_with_progress(self, command: str, callback=None):
        """Execute and stream output to callback"""
```

**Security Considerations**:
- No shell=True (use list format)
- Sanitize command strings
- Timeout for long-running commands

---

## Service-Specific Logic

### HTTP/HTTPS Plugin Behavior

**Service Detected** → Initial Tasks:
1. Check robots.txt (QUICK WIN)
2. Check sitemap.xml (QUICK WIN)
3. Technology fingerprinting with whatweb (QUICK WIN)
4. Directory bruteforce with gobuster (MEDIUM)

**Finding: /admin directory** → Followup Tasks:
1. Check authentication (curl -I)
2. Try default credentials
3. Enumerate /admin subdirectories

**Finding: /backup directory** → Followup Tasks:
1. Look for backup files (.bak, .old, .zip)
2. Try to download files
3. Check directory listing

**Finding: WordPress detected** → Followup Tasks:
1. Run wpscan
2. Enumerate users
3. Check for vulnerable plugins

**Finding: File upload form** → Followup Tasks:
1. Test file upload restrictions
2. Try various file types
3. Check for path traversal

---

### SMB Plugin Behavior

**Service Detected** → Initial Tasks:
1. Anonymous access test (smbclient -N) (QUICK WIN)
2. Run enum4linux (MEDIUM)
3. Test null session (MEDIUM)

**Finding: Anonymous share** → Followup Tasks:
1. Mount and browse share
2. Look for interesting files
3. Check for writable directories

**Finding: User list** → Followup Tasks:
1. Password spray common passwords
2. Check for password policy
3. Kerberoasting (if AD)

---

### SSH Plugin Behavior

**Service Detected** → Initial Tasks:
1. Banner grab (QUICK WIN)
2. Search for version exploits (QUICK WIN)
3. Test common credentials (MEDIUM)

**Finding: Old OpenSSH version** → Followup Tasks:
1. Search for specific CVEs
2. Check for user enumeration vuln
3. Attempt exploit

**Finding: Valid credentials** → Followup Tasks:
1. Login and enumerate
2. Check sudo permissions
3. Look for privilege escalation

---

## Implementation Roadmap

### Phase 1: Foundation (Week 1)

**Goal**: Basic working system with data persistence

**Day 1-2: Core Data Structures**
- [ ] Create project structure
- [ ] Implement `core/profile.py`
  - TargetProfile class
  - add_port, add_finding, add_task methods
  - to_dict / from_dict serialization
- [ ] Implement `core/storage.py`
  - save/load/exists functions
  - JSON file handling
- [ ] Write tests for profile and storage
  - Test serialization
  - Test file operations
  - Test data integrity

**Day 3-4: Nmap Integration**
- [ ] Implement `parsers/nmap.py`
  - Parse XML format
  - Extract ports, services, versions
- [ ] Create simple import script
  - `python3 -m core.profile import <target> <nmap.xml>`
- [ ] Write tests for parser
  - Test with real nmap output
  - Handle malformed XML

**Day 5-7: Basic TUI**
- [ ] Implement `tui/hub.py` skeleton
  - Main loop
  - Basic menu system
  - Profile selection
- [ ] Implement `tui/display.py`
  - Header formatting
  - Port display
  - Basic text helpers
- [ ] Manual testing of TUI flow
  - Create profile
  - Import nmap
  - View results

**Deliverable**: Can create profile, import nmap, view ports in TUI

---

### Phase 2: Intelligence Layer (Week 2)

**Goal**: Smart task recommendations

**Day 8-9: Flow State Machine**
- [ ] Implement `core/flow.py`
  - Phase detection logic
  - State transitions
  - Phase descriptions
- [ ] Write tests for flow
  - Test phase detection
  - Test state transitions

**Day 10-11: Recommendation Engine**
- [ ] Implement `core/recommendations.py`
  - Basic recommendation logic
  - Priority sorting
  - Quick win detection
- [ ] Write tests for recommendations
  - Test prioritization
  - Test context-awareness

**Day 12-13: Plugin System**
- [ ] Implement `plugins/base.py`
  - Plugin interface
  - Plugin registry
- [ ] Implement `plugins/http.py`
  - Service detection
  - Initial tasks
  - Followup logic
- [ ] Implement `plugins/smb.py`
  - Service detection
  - Initial tasks
- [ ] Implement `plugins/ssh.py`
  - Service detection
  - Initial tasks
- [ ] Write tests for plugins
  - Test detection logic
  - Test task generation

**Day 14: Integration**
- [ ] Connect TUI to recommendations
  - Display recommendations
  - Execute tasks
- [ ] End-to-end testing
  - Full workflow test
  - Multiple services test

**Deliverable**: TUI suggests relevant tasks based on discovered services

---

### Phase 3: Finding Loop (Week 3)

**Goal**: Findings generate new recommendations

**Day 15-16: Output Parsing**
- [ ] Implement `parsers/gobuster.py`
  - Parse directory output
  - Extract paths and status codes
- [ ] Extend `tui/executor.py`
  - Execute commands
  - Capture output
  - Parse based on tool
- [ ] Write tests for output parsing
  - Test gobuster parser
  - Test error handling

**Day 17-18: Finding Processing**
- [ ] Enhance `plugins/http.py`
  - Implement get_followup_tasks()
  - Handle directory findings
  - Handle file findings
- [ ] Enhance `plugins/smb.py`
  - Handle share findings
  - Handle user findings
- [ ] Write tests for followup logic
  - Test finding → task conversion
  - Test multiple findings

**Day 19: Complete the Loop**
- [ ] Connect execution → parsing → findings → new tasks
  - Execute task
  - Parse output
  - Add findings to profile
  - Generate new recommendations
- [ ] End-to-end testing
  - Test full loop
  - Test multiple iterations

**Day 20-21: Polish**
- [ ] Improve TUI display
  - Better formatting
  - Color coding
  - Progress indicators
- [ ] Add error handling
  - Command failures
  - Network errors
  - File not found
- [ ] Performance optimization
  - Fast TUI refresh
  - Efficient parsing
- [ ] Documentation
  - Usage examples
  - Plugin development guide

**Deliverable**: Complete working MVP with finding loop

---

### Phase 4: Future Enhancements (Post-MVP)

**Only after MVP is stable and tested**

Priority order:
1. **Task search/filter** - Find tasks by name/port/service
2. **Basic export** - Generate markdown report
3. **Session resume** - Pick up where you left off
4. **More plugins** - Add one at a time with full testing
5. **Finding tracking** - Better visualization of findings
6. **Credential management** - Track creds separately
7. **Timeline view** - See chronological actions
8. **Quick wins panel** - Dedicated quick win view

**Rule**: Each enhancement must be fully tested before next one

---

## Testing Strategy

### Test-First Development

**Principle**: Write test before implementation

**Example Workflow**:
```python
# 1. Write test
def test_profile_adds_port():
    profile = TargetProfile("192.168.1.1")
    profile.add_port(80, "http", "Apache 2.4")

    assert 80 in profile.ports
    assert profile.ports[80]["service"] == "http"

# 2. Run test (fails)
# 3. Implement feature
# 4. Run test (passes)
# 5. Refactor if needed
# 6. Run test again (still passes)
```

### Coverage Goals

- **Phase 1**: 90% coverage on core components
- **Phase 2**: 85% coverage including plugins
- **Phase 3**: 80% coverage overall
- **Maintain**: Never drop below 80%

### Test Categories

**Unit Tests** (Fast, isolated):
```python
test_profile.py
  - test_create_profile
  - test_add_port
  - test_add_finding
  - test_add_task
  - test_serialization

test_storage.py
  - test_save_profile
  - test_load_profile
  - test_profile_exists
  - test_missing_profile

test_flow.py
  - test_phase_detection
  - test_state_transitions
  - test_phase_descriptions

test_recommendations.py
  - test_prioritization
  - test_quick_win_detection
  - test_context_awareness
```

**Integration Tests** (Slower, full components):
```python
test_nmap_import.py
  - test_import_real_nmap_xml
  - test_import_with_multiple_hosts
  - test_import_malformed_xml

test_plugin_integration.py
  - test_http_plugin_generates_tasks
  - test_smb_plugin_generates_tasks
  - test_multiple_plugins

test_finding_loop.py
  - test_execute_task_creates_findings
  - test_findings_trigger_new_tasks
  - test_multiple_iterations
```

**TUI Tests** (Manual + Smoke):
- Smoke test: TUI loads without errors
- Manual test checklist for full workflow
- No complex TUI automation (too fragile)

### Test Data

**fixtures/nmap_samples/**:
- `simple.xml` - 3 ports (22, 80, 445)
- `http_only.xml` - Single HTTP service
- `complex.xml` - Many services
- `malformed.xml` - Invalid XML

**fixtures/gobuster_samples/**:
- `simple.txt` - 3 directories
- `with_codes.txt` - Various status codes
- `empty.txt` - No results

### Running Tests

```bash
# All tests
pytest tests/ -v

# Specific module
pytest tests/test_profile.py -v

# With coverage
pytest tests/ --cov=core --cov=plugins --cov-report=term-missing

# Fast tests only (no integration)
pytest tests/ -v -m "not integration"
```

### Test Quality Standards

**Good Tests**:
- Test behavior, not implementation
- Use real data, not excessive mocks
- Clear test names that describe scenario
- Single assertion per test (when possible)
- Fast (<100ms per test)

**Bad Tests**:
- Test private methods
- Mock everything (tests the mocks, not code)
- Cryptic names like `test_1`, `test_foo`
- Multiple unrelated assertions
- Slow (>1s per test)

---

## Success Metrics

### Quantitative Metrics

**Code Size**:
- [ ] Total codebase < 1,500 lines
- [ ] Largest file < 350 lines
- [ ] Average function < 20 lines

**Performance**:
- [ ] TUI loads in < 100ms
- [ ] Profile load/save < 50ms
- [ ] Recommendation generation < 100ms
- [ ] Full test suite < 5 seconds

**Quality**:
- [ ] Test coverage > 80%
- [ ] Zero pylint errors
- [ ] Zero runtime warnings
- [ ] All type hints present

**Dependencies**:
- [ ] Zero external Python dependencies
- [ ] Only stdlib + subprocess
- [ ] Works on fresh Kali install

### Qualitative Metrics

**User Experience**:
- [ ] Can go from nmap → task list in 3 clicks
- [ ] Recommendations feel intelligent
- [ ] TUI is responsive and clear
- [ ] Error messages are helpful

**Code Quality**:
- [ ] New developer understands in 10 minutes
- [ ] Any component can be modified in isolation
- [ ] No "clever" code - everything is obvious
- [ ] Comments explain WHY, not WHAT

**Maintainability**:
- [ ] Adding a new plugin takes < 1 hour
- [ ] Bug fixes don't break other features
- [ ] Tests prevent regression
- [ ] Documentation matches implementation

### Definition of Done

**MVP is complete when**:
1. All Phase 1-3 tasks checked off
2. All success metrics achieved
3. Full workflow tested end-to-end
4. Documentation written
5. No known critical bugs
6. Passing all tests with >80% coverage

---

## Anti-Patterns to Avoid

### Lessons from Original CRACK

**Don't**:
- ❌ Build all 120 plugins at once (build 3, prove they work)
- ❌ Create complex event systems (direct method calls are fine)
- ❌ Over-abstract everything (concrete implementations first)
- ❌ Add intelligence without testing (simple if/then logic is enough)
- ❌ Write code before tests (test-first development)
- ❌ Optimize prematurely (make it work, then fast)
- ❌ Add features before core is stable (MVP first, features later)

**Do**:
- ✅ Start with smallest possible working system
- ✅ Test every component before moving on
- ✅ Keep it simple and boring
- ✅ Make it work before making it clever
- ✅ Build incrementally with validation

### Code Quality Guidelines

**Keep functions small**:
```python
# Good - Single responsibility
def parse_port(port_element):
    port_id = int(port_element.get('portid'))
    service = port_element.find('service')
    return {
        'port': port_id,
        'service': service.get('name') if service else 'unknown'
    }

# Bad - Too many responsibilities
def parse_nmap_and_update_profile_and_generate_tasks(xml_file, profile):
    # 200 lines of mixed concerns
    ...
```

**Use clear names**:
```python
# Good
def get_high_priority_quick_win_tasks(profile):
    return [t for t in profile.tasks if t['priority'] == 'HIGH' and t['quick_win']]

# Bad
def get_hpqw(p):
    return [t for t in p.ts if t['p'] == 'H' and t['qw']]
```

**Avoid clever code**:
```python
# Good - Obvious
def is_http_service(service):
    return service in ['http', 'https']

# Bad - Too clever
def is_http_service(service):
    return bool(re.match(r'https?', service))
```

---

## Appendix: Example Workflows

### Workflow 1: Basic Enumeration

```
1. USER: Start TUI
   └─> python3 -m tui.hub

2. TUI: Select or create target
   └─> Enter target: 192.168.1.1

3. TUI: No data yet, show import menu
   └─> [i] Import nmap scan

4. USER: Imports scan
   └─> Enter path: /tmp/scan.xml

5. SYSTEM: Parse nmap XML
   └─> Found ports: 22, 80, 445
   └─> Services: ssh, http, smb

6. TUI: Display discoveries and recommendations
   └─> RECOMMENDATIONS:
       [1] Check robots.txt (HTTP, QUICK WIN)
       [2] Anonymous SMB test (SMB, QUICK WIN)
       [3] SSH version check (SSH, QUICK WIN)

7. USER: Execute recommendation #1
   └─> Choice: 1

8. SYSTEM: Execute curl http://192.168.1.1/robots.txt
   └─> Output: Disallow: /admin

9. SYSTEM: Parse output, extract finding
   └─> Finding: directory "/admin"
   └─> Add to profile

10. SYSTEM: Generate followup tasks
    └─> New task: "Check /admin authentication"

11. TUI: Update display with new finding and task
    └─> FINDINGS (1):
        [WEB] /admin
    └─> RECOMMENDATIONS:
        [1] Check /admin authentication (NEW!)
        [2] Anonymous SMB test
        [3] SSH version check

12. Loop continues...
```

### Workflow 2: Finding Loop

```
Initial State:
  - HTTP service on port 80 detected
  - No findings yet

Iteration 1:
  1. Execute: gobuster dir -u http://192.168.1.1
  2. Finding: /admin directory
  3. New task: Check /admin for auth bypass
  4. New task: Enumerate /admin subdirectories

Iteration 2:
  1. Execute: curl -I http://192.168.1.1/admin
  2. Finding: 401 Unauthorized (auth required)
  3. New task: Try default admin credentials
  4. New task: Search for admin bypass techniques

Iteration 3:
  1. Execute: gobuster dir -u http://192.168.1.1/admin
  2. Finding: /admin/backup directory
  3. New task: Check /admin/backup for files

Iteration 4:
  1. Execute: gobuster dir -u http://192.168.1.1/admin/backup -x bak,old
  2. Finding: /admin/backup/config.php.bak
  3. New task: Download config.php.bak

Iteration 5:
  1. Execute: curl http://192.168.1.1/admin/backup/config.php.bak
  2. Finding: credentials found (admin:P@ssw0rd)
  3. New task: Test credentials on /admin login

Result: Natural progression from discovery to credentials
```

---

## Appendix: TUI State Diagrams

### Main Menu State

```
         ┌──────────────┐
         │  MAIN MENU   │
         └──────┬───────┘
                │
    ┌───────────┼───────────┐
    │           │           │
    ▼           ▼           ▼
┌────────┐  ┌───────┐  ┌────────┐
│ Import │  │Execute│  │ Manual │
│  Scan  │  │  Task │  │ Action │
└────┬───┘  └───┬───┘  └───┬────┘
     │          │          │
     └──────────┴──────────┘
                │
                ▼
         ┌──────────────┐
         │ Update State │
         └──────┬───────┘
                │
                ▼
         ┌──────────────┐
         │ Regenerate   │
         │Recommendations│
         └──────┬───────┘
                │
                ▼
         (Loop back to main menu)
```

### Task Execution Flow

```
┌───────────────┐
│ User Selects  │
│     Task      │
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ Confirm       │
│ Execution?    │
└───────┬───────┘
        │
        ├─[No]──> Return to menu
        │
        ▼[Yes]
┌───────────────┐
│ Execute       │
│ Command       │
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ Capture       │
│ Output        │
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ Parse         │
│ Output        │
└───────┬───────┘
        │
        ├─[Findings Found]
        │       │
        │       ▼
        │  ┌──────────────┐
        │  │ Add Findings │
        │  │ to Profile   │
        │  └──────┬───────┘
        │         │
        │         ▼
        │  ┌──────────────┐
        │  │ Generate New │
        │  │    Tasks     │
        │  └──────┬───────┘
        │         │
        └─────────┘
                  │
                  ▼
          ┌──────────────┐
          │ Mark Task    │
          │  Complete    │
          └──────┬───────┘
                 │
                 ▼
          ┌──────────────┐
          │ Show Results │
          └──────┬───────┘
                 │
                 ▼
          (Return to main menu)
```

---

## Getting Started

Once implementation begins:

```bash
# 1. Clone/create project
mkdir crack-resmoked
cd crack-resmoked

# 2. Create virtual environment (optional)
python3 -m venv venv
source venv/bin/activate

# 3. Create directory structure
mkdir -p core parsers plugins tui tests/fixtures

# 4. Start with core/profile.py
# Write test first, then implementation
nano tests/test_profile.py
nano core/profile.py

# 5. Run tests continuously
pytest tests/ -v --watch

# 6. Follow implementation roadmap phase by phase
```

---

## Summary

**CRACK-RESMOKED** is a from-scratch rebuild that:

✅ **Preserves** the core philosophy (TUI as pentesting hub)
✅ **Maintains** the intelligent flow (recon → enum → exploit)
✅ **Simplifies** the architecture (no events, no complexity)
✅ **Focuses** on 3 core services to start
✅ **Builds** incrementally with full testing
✅ **Delivers** a stable, maintainable foundation

The goal is not feature parity with the original CRACK - it's to create a rock-solid foundation that actually works and can be extended safely.

**Start small. Test thoroughly. Build incrementally.**
