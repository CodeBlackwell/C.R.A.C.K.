# ServicePlugin Requirements

## Complete Checklist

For a plugin to be used in the CRACK Track application, it must satisfy the following requirements:

---

## ✅ 1. Inherit from ServicePlugin Base Class

```python
from .base import ServicePlugin

class MyPlugin(ServicePlugin):
    ...
```

**Why:** ServicePlugin provides the interface contract and abstract methods.

---

## ✅ 2. Implement Required Abstract Methods/Properties

### **Required: `name` Property**
```python
@property
def name(self) -> str:
    """Unique service identifier"""
    return "my-service"
```
- **Purpose:** Unique identifier for the plugin
- **Format:** lowercase, alphanumeric with hyphens
- **Examples:** `"http"`, `"smb"`, `"mysql"`, `"ad-attacks"`

### **Required: `detect()` Method**
```python
def detect(self, port_info: Dict[str, Any]) -> float:
    """Determine if this plugin can handle this port/service

    Args:
        port_info: {'port': 80, 'service': 'http', 'version': 'Apache/2.4.41', 'state': 'open'}

    Returns:
        Confidence score (0-100):
        - 0: Cannot handle
        - 1-30: Low confidence
        - 31-70: Medium confidence
        - 71-90: High confidence
        - 91-100: Perfect match
    """
    service = port_info.get('service', '').lower()
    port = port_info.get('port')

    # Perfect match
    if service == 'my-service' and port in self.default_ports:
        return 100

    # High confidence
    if service == 'my-service':
        return 80

    # Medium confidence
    if port in self.default_ports:
        return 50

    return 0  # Cannot handle
```

**Why:** ServiceRegistry uses confidence scores for conflict resolution when multiple plugins claim the same port.

**Backward Compatibility:** Can still return `bool` (`True` = 100, `False` = 0)

### **Required: `get_task_tree()` Method**
```python
def get_task_tree(self, target: str, port: int, service_info: Dict[str, Any]) -> Dict[str, Any]:
    """Generate initial enumeration tasks for this service

    Args:
        target: '192.168.45.100'
        port: 80
        service_info: {'port': 80, 'service': 'http', 'version': 'Apache/2.4.41'}

    Returns:
        Task tree dict with structure:
        {
            'id': 'my-service-enum-80',
            'name': 'MyService Enumeration (Port 80)',
            'type': 'parent',
            'children': [
                {
                    'id': 'version-check-80',
                    'name': 'Check Version',
                    'type': 'command',
                    'metadata': {
                        'command': 'myservice-scan 192.168.45.100',
                        'description': 'Scan for version info',
                        'tags': ['OSCP:HIGH']
                    }
                }
            ]
        }
    """
    return {
        'id': f'my-service-enum-{port}',
        'name': f'MyService Enumeration (Port {port})',
        'type': 'parent',
        'children': [...]
    }
```

**Why:** This generates the **initial tasks** when the service is first detected.

---

## ✅ 3. Optional But Recommended Methods/Properties

### **Optional: `default_ports` Property**
```python
@property
def default_ports(self) -> List[int]:
    """Common ports for this service"""
    return [80, 443, 8080, 8443]
```
- **Default:** `[]` (empty list)
- **Purpose:** Used for detection and fuzzy task matching
- **Leave empty for:** Manual-trigger plugins (post-exploitation, etc.)

### **Optional: `service_names` Property**
```python
@property
def service_names(self) -> List[str]:
    """Service name variations this plugin handles"""
    return ['http', 'https', 'http-proxy', 'ssl/http']
```
- **Default:** `[self.name]`
- **Purpose:** Helps detect() match service name variations
- **Leave empty for:** Manual-trigger plugins

### **Recommended: `detect_from_finding()` Method**
```python
def detect_from_finding(self, finding: Dict[str, Any], profile: Optional['TargetProfile'] = None) -> float:
    """Determine if this plugin should activate based on a finding

    Args:
        finding: Finding dict with keys: type, description, source, timestamp
        profile: Optional TargetProfile for additional context

    Returns:
        Confidence score (0-100) that this plugin should handle this finding:
        - 0: Cannot handle this finding
        - 1-30: Low confidence
        - 31-70: Medium confidence
        - 71-90: High confidence
        - 91-100: Perfect match

    Default implementation returns 0 (plugins opt-in to finding-based activation)
    """
    from ..core.constants import FindingTypes

    finding_type = finding.get('type', '').lower()
    description = finding.get('description', '').lower()

    # Example: Post-exploit plugin activates on shell obtained
    if finding_type == FindingTypes.SHELL_OBTAINED:
        return 100

    # Example: WordPress plugin activates on CMS detection
    if finding_type == FindingTypes.CMS_WORDPRESS:
        return 100

    return 0
```

- **Default:** Base class returns `0` (no activation)
- **Purpose:** Enable context-aware plugin activation beyond port-based detection
- **When to implement:** **MOST PLUGINS SHOULD IMPLEMENT THIS**
  - ✅ Post-exploit plugins (shell obtained)
  - ✅ OS-specific plugins (OS detected)
  - ✅ CMS/framework plugins (technology detected)
  - ✅ Privilege escalation plugins (low-priv shell)
  - ✅ AD plugins (domain membership detected)
  - ✅ Container escape plugins (container detected)
  - ❌ Pure network services (SSH, FTP, SMTP) - port-based is sufficient

**Finding Types Available:**
```python
from crack.track.core.constants import FindingTypes

# Access/Shell
FindingTypes.SHELL_OBTAINED
FindingTypes.LOW_PRIVILEGE_SHELL
FindingTypes.ROOT_SHELL

# OS Detection
FindingTypes.OS_DETECTED
FindingTypes.OS_LINUX
FindingTypes.OS_WINDOWS

# CMS/Frameworks
FindingTypes.CMS_DETECTED
FindingTypes.CMS_WORDPRESS
FindingTypes.FRAMEWORK_DETECTED

# Credentials
FindingTypes.CREDENTIAL_FOUND

# Vulnerabilities
FindingTypes.VULNERABILITY_FOUND
FindingTypes.CVE_FOUND

# Environment
FindingTypes.CONTAINER_DETECTED
FindingTypes.DOMAIN_JOINED
```

**Examples:**
```python
# Post-Exploit Plugin
def detect_from_finding(self, finding, profile=None):
    finding_type = finding.get('type', '').lower()
    if finding_type in ['shell_obtained', 'low_privilege_shell']:
        return 100  # Activate immediately
    return 0

# WordPress Plugin
def detect_from_finding(self, finding, profile=None):
    finding_type = finding.get('type', '').lower()
    description = finding.get('description', '').lower()

    if finding_type == 'cms_wordpress':
        return 100
    if 'wordpress' in description or 'wp-content' in description:
        return 85
    return 0

# Windows PrivEsc Plugin
def detect_from_finding(self, finding, profile=None):
    finding_type = finding.get('type', '').lower()
    description = finding.get('description', '').lower()

    # Perfect match - Windows shell
    if finding_type == 'shell_obtained' and 'windows' in description:
        return 100
    # High confidence - Windows OS detected
    if finding_type == 'os_windows':
        return 95
    return 0
```

**Why This Matters:**
- **Manual-only plugins are an anti-pattern** - they require user intervention
- Finding-based activation enables **intelligent, context-aware** plugin triggering
- Users get the right tasks at the right time automatically
- Goal: <5% of plugins should be manual-only (network services only)

---

### **Optional: `on_task_complete()` Method**
```python
def on_task_complete(self, task_id: str, result: str, target: str) -> List[Dict[str, Any]]:
    """Generate follow-up tasks based on results

    Args:
        task_id: 'gobuster-80'
        result: 'Command output as string...'
        target: '192.168.45.100'

    Returns:
        List of new task definitions
    """
    new_tasks = []

    # If gobuster found /admin, add login test
    if 'gobuster' in task_id and '/admin' in result.lower():
        new_tasks.append({
            'id': 'admin-login-test-80',
            'name': 'Test Admin Panel Authentication',
            'type': 'manual',
            'metadata': {
                'description': 'Try default credentials',
                'tags': ['OSCP:HIGH']
            }
        })

    return new_tasks
```
- **Default:** Returns `[]` (no follow-up tasks)
- **Purpose:** Service-specific intelligence for follow-up tasks
- **When to implement:** If your service has common patterns that trigger specific next steps

**Examples of Good Use Cases:**
- HTTP: WordPress detected → Generate WPScan task
- SMB: Share found → Generate mount task
- SSH: Old version → Generate exploit research task

### **Optional: `get_manual_alternatives()` Method**
```python
def get_manual_alternatives(self, task_id: str) -> List[str]:
    """Get manual alternatives for OSCP exam scenarios

    Args:
        task_id: Task ID to get alternatives for

    Returns:
        List of manual command alternatives
    """
    alternatives = {
        'version-check': [
            'nc -nv <target> <port>',
            'telnet <target> <port>',
            'curl -I <target>'
        ]
    }

    for key, cmds in alternatives.items():
        if key in task_id:
            return cmds

    return []
```
- **Default:** Returns `[]`
- **Purpose:** OSCP exam preparation (manual techniques when tools fail)
- **When to implement:** If you have good manual alternatives

---

## ✅ 4. Register Plugin with @ServiceRegistry.register

```python
from .registry import ServiceRegistry

@ServiceRegistry.register
class MyPlugin(ServicePlugin):
    ...
```

**Why:** This decorator:
1. Instantiates the plugin
2. Adds it to the registry
3. Auto-wires event handlers (`service_detected`, `task_completed`)
4. Makes the plugin discoverable

**Note:** Registration happens automatically when the module is imported.

---

## ✅ 5. Add Plugin to Registry Import List

In `track/services/registry.py`, line 122:

```python
def initialize_plugins(cls):
    # Import all plugin modules to trigger @register decorators
    from . import http, smb, ssh, ..., my_plugin  # ADD YOUR PLUGIN HERE
```

**Why:** Plugins must be imported for the `@ServiceRegistry.register` decorator to execute.

**Alternative:** If you want auto-discovery without editing registry.py, use dynamic imports (not currently implemented).

---

## ✅ 6. No Reinstall Needed!

Once your plugin file is created and added to the import list, **no `./reinstall.sh` is needed**. The plugin is auto-discovered at runtime.

---

## Plugin Lifecycle

### Phase 1: Registration (Startup)
```
1. ServiceRegistry.initialize_plugins() called
2. Plugin module imported
3. @ServiceRegistry.register decorator executes
4. Plugin instantiated and added to _plugins dict
5. Event handlers auto-wired:
   - service_detected → _handle_service_detected
   - task_completed → _handle_task_completed
```

### Phase 2: Service Detection (Nmap Port-Based)
```
1. Nmap parser detects service on port
2. Emits service_detected event
3. ALL plugins receive event
4. Each plugin's detect() called with port_info
5. Plugins return confidence scores
6. Conflict resolution (highest confidence wins)
7. Winner's get_task_tree() called
8. Tasks added to profile
```

### Phase 3: Finding Detection (Context-Based) **NEW!**
```
1. Finding added to profile (shell, OS, CMS, credential, etc.)
2. Emits finding_added event
3. ALL plugins receive event
4. Each plugin's detect_from_finding() called with finding
5. Plugins return confidence scores
6. Conflict resolution (highest confidence wins)
7. Winner's get_task_tree() called with finding context
8. Tasks added to profile
```

### Phase 4: Task Completion (When Task Executes)
```
1. User executes task
2. TUI emits task_completed event
3. ALL plugins receive event
4. Fuzzy matching identifies which plugin owns task
5. Matching plugin's on_task_complete() called
6. Plugin returns follow-up tasks
7. Tasks added to profile
```

---

## Conflict Resolution (Multiple Plugins for Same Port)

**Scenario:** Both HTTPPlugin and GenericPlugin claim port 80.

**Resolution:**
1. HTTPPlugin.detect() returns 100 (perfect match)
2. GenericPlugin.detect() returns 30 (low confidence)
3. ServiceRegistry sorts by confidence (highest first)
4. HTTPPlugin wins → Its get_task_tree() is called
5. GenericPlugin's tasks are NOT generated

**Tip:** Use confidence scores strategically:
- 91-100: You're certain (exact service + port match)
- 71-90: High confidence (service name match)
- 31-70: Medium (port match, but unsure)
- 1-30: Low (maybe, if no better plugin)
- 0: Cannot handle

---

## Fuzzy Task Matching (for on_task_complete)

**How ServiceRegistry Determines Which Plugin Owns a Task:**

### 1. Direct Name Match
`task_id: 'http-enum-80'` → HTTPPlugin (contains "http")

### 2. Alias Match
`task_id: 'gobuster-80'` → HTTPPlugin (alias: "gobuster")

### 3. Port Match
`task_id: 'custom-scan-80'` → HTTPPlugin (default port: 80)

### 4. Metadata Match
`task.metadata: {'service': 'http'}` → HTTPPlugin

**Tip:** To ensure your plugin's on_task_complete is called:
1. Include plugin name in task IDs (e.g., `my-service-enum-80`)
2. Add common tool names to service_aliases in registry.py
3. Set metadata in your tasks: `{'service': 'my-service'}`

---

## Example: Minimal Plugin

```python
"""
MyService Plugin - Minimal Example
"""

from typing import Dict, Any, List
from .base import ServicePlugin
from .registry import ServiceRegistry


@ServiceRegistry.register
class MyServicePlugin(ServicePlugin):
    """MyService enumeration plugin"""

    @property
    def name(self) -> str:
        return "my-service"

    @property
    def default_ports(self) -> List[int]:
        return [9999]

    @property
    def service_names(self) -> List[str]:
        return ['my-service', 'myservice', 'ms']

    def detect(self, port_info: Dict[str, Any]) -> float:
        """Detect MyService"""
        service = port_info.get('service', '').lower()
        port = port_info.get('port')

        # Perfect match
        if service in self.service_names and port in self.default_ports:
            return 100

        # High confidence
        if service in self.service_names:
            return 80

        # Medium confidence
        if port in self.default_ports:
            return 50

        return 0

    def get_task_tree(self, target: str, port: int, service_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate initial tasks"""
        return {
            'id': f'my-service-enum-{port}',
            'name': f'MyService Enumeration (Port {port})',
            'type': 'parent',
            'children': [
                {
                    'id': f'my-service-version-{port}',
                    'name': 'Check MyService Version',
                    'type': 'command',
                    'metadata': {
                        'command': f'myservice-scan {target}:{port}',
                        'description': 'Enumerate MyService version',
                        'tags': ['OSCP:HIGH']
                    }
                }
            ]
        }

    def on_task_complete(self, task_id: str, result: str, target: str) -> List[Dict[str, Any]]:
        """Generate follow-up tasks"""
        new_tasks = []

        # If version scan found vulnerability, add exploit task
        if 'version' in task_id and 'CVE-2024-1234' in result:
            new_tasks.append({
                'id': 'my-service-exploit-9999',
                'name': 'Exploit CVE-2024-1234',
                'type': 'command',
                'metadata': {
                    'command': f'exploit-tool {target}',
                    'description': 'Exploit known vulnerability',
                    'tags': ['OSCP:HIGH', 'EXPLOIT']
                }
            })

        return new_tasks
```

---

## Testing Your Plugin

### 1. Unit Tests
```python
# tests/track/test_my_service_plugin.py
from crack.track.services.registry import ServiceRegistry

def test_my_service_plugin_registered():
    """Plugin is registered"""
    ServiceRegistry.initialize_plugins()
    plugin = ServiceRegistry.get_plugin_by_name('my-service')
    assert plugin is not None
    assert plugin.name == 'my-service'

def test_my_service_plugin_detects_service():
    """Plugin detects MyService"""
    plugin = ServiceRegistry.get_plugin_by_name('my-service')

    port_info = {'port': 9999, 'service': 'my-service', 'state': 'open'}
    confidence = plugin.detect(port_info)

    assert confidence == 100  # Perfect match

def test_my_service_plugin_generates_tasks():
    """Plugin generates tasks"""
    plugin = ServiceRegistry.get_plugin_by_name('my-service')

    task_tree = plugin.get_task_tree('192.168.45.100', 9999, {})

    assert task_tree['id'] == 'my-service-enum-9999'
    assert len(task_tree['children']) > 0
```

### 2. Integration Test
```python
from crack.track.core.events import EventBus

def test_my_service_plugin_activates_on_detection():
    """Plugin activates when service detected"""
    ServiceRegistry.initialize_plugins()

    emitted_tasks = []
    def capture(data):
        emitted_tasks.append(data)

    EventBus.on('plugin_tasks_generated', capture)

    # Simulate Nmap detecting MyService
    EventBus.emit('service_detected', {
        'target': '192.168.45.100',
        'port': 9999,
        'service': 'my-service',
        'version': '1.0'
    })

    assert len(emitted_tasks) > 0
    assert emitted_tasks[0]['plugin'] == 'my-service'
```

### 3. Manual Test
```bash
# Create target profile
crack track new 192.168.45.100

# Simulate Nmap detection by manually adding port
crack track --target 192.168.45.100 --tui

# In TUI: Import scan results with MyService on port 9999
# Verify tasks are generated automatically
```

---

## Checklist Summary

### Required
- [ ] **Inherit from ServicePlugin**
- [ ] **Implement `name` property**
- [ ] **Implement `detect()` method** (return confidence 0-100)
- [ ] **Implement `get_task_tree()` method** (return task dict)
- [ ] **Add `@ServiceRegistry.register` decorator**
- [ ] **Add plugin to registry.py import list**

### Recommended (Implement for Most Plugins)
- [ ] **Implement `detect_from_finding()`** (finding-based activation)
- [ ] **Set `default_ports`** (for detection & fuzzy matching)
- [ ] **Set `service_names`** (for detection)

### Optional (Implement If Applicable)
- [ ] **Implement `on_task_complete()`** (for follow-up tasks)
- [ ] **Implement `get_manual_alternatives()`** (for OSCP)

### Testing
- [ ] **Test port-based detection logic**
- [ ] **Test finding-based detection logic** (if implemented)
- [ ] **Test task generation**
- [ ] **Test integration with EventBus**

---

## Common Pitfalls

### ❌ Forgetting @ServiceRegistry.register
```python
class MyPlugin(ServicePlugin):  # Will NOT be registered!
    ...
```

### ❌ Not Adding to Import List
Plugin won't be discovered if not imported in `registry.py:122`.

### ❌ Returning Wrong Type from detect()
```python
def detect(self, port_info):
    return "yes"  # ❌ Wrong! Must return float or bool
```

### ❌ Not Handling Confidence Conflicts
If two plugins return same confidence, first one wins. Be strategic with scores.

### ❌ Assuming on_task_complete is Always Called
Fuzzy matching must succeed for your plugin to receive task_completed events. Ensure:
- Task IDs contain plugin name, OR
- Plugin name is in service_aliases, OR
- Task metadata includes service hint

---

## Questions?

Check existing plugins for examples:
- `track/services/http.py` - Complex plugin with on_task_complete
- `track/services/ssh.py` - Simple plugin
- `track/services/post_exploit.py` - Manual-trigger plugin (no ports)
- `tests/track/test_service_plugins.py` - Test patterns
