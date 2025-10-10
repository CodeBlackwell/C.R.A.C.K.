# Plugin Activation Renovation Plan

## Executive Summary

The CRACK Track plugin system currently suffers from a critical architectural limitation: 98% of plugins (120/122) can ONLY activate via nmap port detection. This creates massive blind spots where plugins that SHOULD activate based on context (shell obtained, OS detected, CMS identified) remain dormant. This renovation adds finding-based activation alongside port-based activation, enabling intelligent plugin activation based on any discovery event.

**Goal**: Reduce manual-only plugins from 2% to <5% while maintaining 100% backward compatibility.

## Architecture Design

### Current Flow (Port-Only)
```
Nmap Scan → Port Detected → ServiceRegistry → detect(port_info) → Plugin Activates
                                                      ↓
                                                 Returns False (2 plugins)
                                                      ↓
                                                 Manual Activation Required
```

### New Flow (Dual Activation)
```
┌─ Nmap Scan → Port Detected ──────────────┐
│                                           ↓
│                                    ServiceRegistry
│                                           ↓
│                                    detect(port_info) → Plugin Activates
│
└─ Finding Added → finding_added Event ─────┘
                           ↓
                   detect_from_finding(finding, profile) → Plugin Activates
```

### Event Flow Diagram
```
[Finding Added to Profile]
         ↓
[EventBus.emit('finding_added')]
         ↓
[ServiceRegistry._handle_finding_added()]
         ↓
[For Each Plugin: detect_from_finding()]
         ↓
[Collect Confidence Scores]
         ↓
[Conflict Resolution (Highest Wins)]
         ↓
[Winner.get_task_tree()]
         ↓
[EventBus.emit('plugin_tasks_generated')]
         ↓
[Tasks Added to Profile]
```

### Finding Types for Plugin Activation

| Finding Type | Description | Activates Plugins |
|--------------|-------------|-------------------|
| `shell_obtained` | Shell access gained | post_exploit, linux_privesc, windows_privesc |
| `os_detected` | Operating system identified | OS-specific privesc plugins |
| `cms_detected` | CMS platform identified | wordpress, joomla, drupal plugins |
| `credential_found` | Valid credentials discovered | credential_testing plugins |
| `vulnerability` | CVE or vuln identified | exploit research plugins |
| `service_version` | Service version discovered | version-specific plugins |
| `low_privilege` | Low-priv shell obtained | privilege escalation plugins |
| `domain_joined` | AD domain membership | AD enumeration plugins |
| `container_detected` | Container environment | container escape plugins |
| `database_access` | Database credentials | database enumeration plugins |

## Implementation Checklist

### Phase 1: Core Infrastructure (4-6 hours)

#### 1.1 Enhance ServicePlugin Base Class
**File**: `/home/kali/OSCP/crack/track/services/base.py`
**Line**: After line 91 (after on_task_complete)

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
    return 0
```

**Tests**: `tests/track/test_service_base.py`
- [ ] Test default implementation returns 0
- [ ] Test method signature compatibility
- [ ] Test with/without profile parameter

#### 1.2 Add Finding Type Constants
**File**: `/home/kali/OSCP/crack/track/core/constants.py` (NEW FILE)

```python
"""Finding type constants for standardization"""

class FindingTypes:
    # Access/Shell Types
    SHELL_OBTAINED = 'shell_obtained'
    LOW_PRIVILEGE_SHELL = 'low_privilege_shell'
    HIGH_PRIVILEGE_SHELL = 'high_privilege_shell'
    ROOT_SHELL = 'root_shell'
    SYSTEM_SHELL = 'system_shell'

    # OS Detection
    OS_DETECTED = 'os_detected'
    OS_LINUX = 'os_linux'
    OS_WINDOWS = 'os_windows'
    OS_MACOS = 'os_macos'
    OS_BSD = 'os_bsd'

    # CMS/Framework Detection
    CMS_DETECTED = 'cms_detected'
    CMS_WORDPRESS = 'cms_wordpress'
    CMS_JOOMLA = 'cms_joomla'
    CMS_DRUPAL = 'cms_drupal'
    FRAMEWORK_DETECTED = 'framework_detected'

    # Credentials
    CREDENTIAL_FOUND = 'credential_found'
    SSH_CREDENTIAL = 'ssh_credential'
    DATABASE_CREDENTIAL = 'database_credential'
    WEB_CREDENTIAL = 'web_credential'

    # Vulnerabilities
    VULNERABILITY_FOUND = 'vulnerability'
    CVE_FOUND = 'cve_found'
    MISCONFIGURATION = 'misconfiguration'

    # Environment
    CONTAINER_DETECTED = 'container_detected'
    DOMAIN_JOINED = 'domain_joined'
    CLOUD_DETECTED = 'cloud_detected'

    # Services
    SERVICE_VERSION = 'service_version'
    DATABASE_ACCESS = 'database_access'
    API_ACCESS = 'api_access'
```

#### 1.3 Update ServiceRegistry for Finding-Based Activation
**File**: `/home/kali/OSCP/crack/track/services/registry.py`
**Line**: After line 60 (after _setup_event_handlers)

```python
# Add to _setup_event_handlers method (line 56):
# Listen for finding_added events for finding-based plugin activation
EventBus.on('finding_added', lambda data: cls._handle_finding_added(plugin, data))

# Add new method after _handle_task_completed (line 222):
@classmethod
def _handle_finding_added(cls, plugin: ServicePlugin, data: Dict[str, Any]):
    """Handle finding_added event with finding-based activation

    Args:
        plugin: Service plugin instance
        data: Event data containing finding and profile
    """
    finding = data.get('finding')
    profile = data.get('profile')  # Optional profile for context

    if not finding:
        return

    # Check if plugin can handle this finding
    confidence = plugin.detect_from_finding(finding, profile)

    if confidence <= 0:
        return

    # Create unique key for this finding-plugin combination
    finding_key = f"{finding.get('type')}:{finding.get('description', '')}"

    # Check deduplication
    if not hasattr(cls, '_activated_findings'):
        cls._activated_findings = set()

    activation_key = f"{plugin.name}:{finding_key}"
    if activation_key in cls._activated_findings:
        return  # Already activated this plugin for this finding

    # Track plugin confidence for this finding
    if not hasattr(cls, '_finding_claims'):
        cls._finding_claims = {}

    if finding_key not in cls._finding_claims:
        cls._finding_claims[finding_key] = []

    cls._finding_claims[finding_key].append({
        'plugin': plugin,
        'confidence': confidence,
        'data': data
    })

    # Schedule resolution (immediate for now, could be async)
    cls._resolve_finding_conflicts(finding_key)

@classmethod
def _resolve_finding_conflicts(cls, finding_key: str):
    """Resolve plugin conflicts for finding-based activation

    Args:
        finding_key: Unique finding identifier
    """
    if finding_key not in cls._finding_claims:
        return

    claims = cls._finding_claims[finding_key]
    if not claims:
        return

    # Sort by confidence (highest first)
    claims.sort(key=lambda x: x['confidence'], reverse=True)

    # Winner takes all
    winner = claims[0]
    plugin = winner['plugin']
    data = winner['data']

    # Mark as activated
    activation_key = f"{plugin.name}:{finding_key}"
    cls._activated_findings.add(activation_key)

    logger.info(f"Plugin '{plugin.name}' activated via finding with confidence {winner['confidence']}")

    # Generate tasks (reuse existing task generation pattern)
    try:
        # For finding-based activation, port is not relevant
        # Pass finding context in service_info
        finding = data.get('finding')
        target = data.get('target', 'unknown')

        service_info = {
            'activation_source': 'finding',
            'finding': finding,
            'finding_type': finding.get('type'),
            'finding_description': finding.get('description')
        }

        task_tree = plugin.get_task_tree(
            target=target,
            port=0,  # No port for finding-based activation
            service_info=service_info
        )

        # Emit tasks
        EventBus.emit('plugin_tasks_generated', {
            'plugin': plugin.name,
            'task_tree': task_tree,
            'target': target,
            'source': 'finding_activation'
        })

    except Exception as e:
        logger.error(f"Error generating tasks for {plugin.name} from finding: {e}")

    # Clear claims
    del cls._finding_claims[finding_key]
```

#### 1.4 Update clear() Method for Testing
**File**: `/home/kali/OSCP/crack/track/services/registry.py`
**Line**: 390 (in clear method)

```python
# Add to clear() method:
if hasattr(cls, '_finding_claims'):
    cls._finding_claims.clear()
    delattr(cls, '_finding_claims')
if hasattr(cls, '_activated_findings'):
    cls._activated_findings.clear()
    delattr(cls, '_activated_findings')
```

### Phase 2: Plugin Migration - Tier 1 (2-3 hours)

#### 2.1 Migrate post_exploit Plugin
**File**: `/home/kali/OSCP/crack/track/services/post_exploit.py`
**Line**: After line 23 (after detect method)

```python
def detect_from_finding(self, finding: Dict[str, Any], profile: Optional['TargetProfile'] = None) -> float:
    """Activate on shell obtained findings"""
    from ..core.constants import FindingTypes

    finding_type = finding.get('type', '').lower()
    description = finding.get('description', '').lower()

    # Perfect match - explicit shell obtained
    if finding_type in [FindingTypes.SHELL_OBTAINED, FindingTypes.LOW_PRIVILEGE_SHELL]:
        return 100

    # High confidence - shell indicators in description
    shell_indicators = ['shell obtained', 'got shell', 'shell access', 'rce achieved',
                       'remote code execution', 'command execution', 'reverse shell']
    if any(indicator in description for indicator in shell_indicators):
        return 85

    # Medium confidence - exploitation success
    if finding_type == FindingTypes.VULNERABILITY_FOUND and 'exploited' in description:
        return 60

    return 0

# Update get_task_tree to handle finding context (line 25):
def get_task_tree(self, target: str, port: int, service_info: Dict[str, Any]) -> Dict[str, Any]:
    """Generate post-exploitation enumeration tasks

    service_info may contain:
    - For port activation: os_type from port scan
    - For finding activation: finding with OS details
    """
    # Extract OS type from finding if available
    if service_info.get('activation_source') == 'finding':
        finding = service_info.get('finding', {})
        description = finding.get('description', '').lower()

        # Detect OS from finding description
        if 'windows' in description or 'powershell' in description:
            os_type = 'windows'
        elif 'linux' in description or 'bash' in description:
            os_type = 'linux'
        else:
            os_type = 'unknown'
    else:
        # Original port-based logic
        os_type = service_info.get('os_type', 'linux').lower()

    # Rest of method unchanged...
```

#### 2.2 Migrate windows_privesc Plugin
**File**: `/home/kali/OSCP/crack/track/services/windows_privesc.py`
**Line**: After detect method (around line 100)

```python
def detect_from_finding(self, finding: Dict[str, Any], profile: Optional['TargetProfile'] = None) -> float:
    """Activate on Windows shell or OS detection"""
    from ..core.constants import FindingTypes

    finding_type = finding.get('type', '').lower()
    description = finding.get('description', '').lower()

    # Perfect match - Windows shell explicitly obtained
    windows_indicators = ['windows shell', 'powershell', 'cmd.exe', 'windows command',
                         'nt authority\\', 'windows\\system32']
    if finding_type == FindingTypes.SHELL_OBTAINED and any(ind in description for ind in windows_indicators):
        return 100

    # High confidence - Windows OS detected
    if finding_type == FindingTypes.OS_DETECTED and 'windows' in description:
        return 90

    # High confidence - Windows-specific findings
    if finding_type == FindingTypes.OS_WINDOWS:
        return 95

    # Medium confidence - Windows service/version
    if 'windows' in description or 'microsoft' in description:
        return 50

    return 0
```

#### 2.3 Migrate linux_privesc Plugin
**File**: `/home/kali/OSCP/crack/track/services/linux_privesc.py`
**Line**: After detect method (around line 41)

```python
def detect_from_finding(self, finding: Dict[str, Any], profile: Optional['TargetProfile'] = None) -> float:
    """Activate on Linux shell or OS detection"""
    from ..core.constants import FindingTypes

    finding_type = finding.get('type', '').lower()
    description = finding.get('description', '').lower()

    # Perfect match - Linux shell explicitly obtained
    linux_indicators = ['linux shell', 'bash', 'sh shell', '/bin/sh', '/bin/bash',
                       'www-data', 'apache', 'nobody']
    if finding_type == FindingTypes.SHELL_OBTAINED and any(ind in description for ind in linux_indicators):
        return 100

    # High confidence - Linux OS detected
    if finding_type == FindingTypes.OS_DETECTED and 'linux' in description:
        return 90

    # High confidence - Linux-specific finding
    if finding_type == FindingTypes.OS_LINUX:
        return 95

    # Medium confidence - Linux indicators
    if 'linux' in description or 'ubuntu' in description or 'debian' in description:
        return 50

    return 0
```

#### 2.4 Migrate wordpress Plugin
**File**: `/home/kali/OSCP/crack/track/services/wordpress.py`
**Line**: After detect method (around line 68)

```python
def detect_from_finding(self, finding: Dict[str, Any], profile: Optional['TargetProfile'] = None) -> float:
    """Activate when WordPress is detected"""
    from ..core.constants import FindingTypes

    finding_type = finding.get('type', '').lower()
    description = finding.get('description', '').lower()

    # Perfect match - WordPress explicitly detected
    if finding_type == FindingTypes.CMS_WORDPRESS:
        return 100

    # High confidence - WordPress CMS finding
    if finding_type == FindingTypes.CMS_DETECTED and 'wordpress' in description:
        return 95

    # High confidence - WordPress indicators
    wordpress_indicators = ['wordpress', 'wp-content', 'wp-admin', 'wp-login',
                           'wp-includes', 'wp-json']
    if any(ind in description for ind in wordpress_indicators):
        return 85

    # Medium confidence - PHP CMS that might be WordPress
    if 'cms' in description and 'php' in description:
        return 30

    return 0
```

### Phase 3: Testing Infrastructure (2 hours)

#### 3.1 Unit Tests for Base Class
**File**: `tests/track/test_service_plugin_finding_activation.py` (NEW)

```python
"""Test finding-based plugin activation"""

import pytest
from unittest.mock import Mock, patch
from crack.track.services.base import ServicePlugin
from crack.track.services.registry import ServiceRegistry
from crack.track.core.events import EventBus
from crack.track.core.constants import FindingTypes


class TestFindingBasedActivation:

    def test_default_detect_from_finding_returns_zero(self):
        """Base class default returns 0 (opt-in behavior)"""

        class MinimalPlugin(ServicePlugin):
            @property
            def name(self): return "test"
            def detect(self, port_info): return False
            def get_task_tree(self, target, port, service_info): return {}

        plugin = MinimalPlugin()
        finding = {'type': 'shell_obtained', 'description': 'Got shell'}

        confidence = plugin.detect_from_finding(finding)
        assert confidence == 0

    def test_plugin_activates_on_finding(self):
        """Plugin with detect_from_finding activates correctly"""

        @ServiceRegistry.register
        class TestPlugin(ServicePlugin):
            @property
            def name(self): return "test-finding"
            def detect(self, port_info): return False

            def detect_from_finding(self, finding, profile=None):
                if finding.get('type') == 'test_finding':
                    return 100
                return 0

            def get_task_tree(self, target, port, service_info):
                return {
                    'id': 'test-task',
                    'name': 'Test Task',
                    'type': 'manual'
                }

        # Setup event capture
        generated_tasks = []
        EventBus.on('plugin_tasks_generated', lambda d: generated_tasks.append(d))

        # Emit finding
        EventBus.emit('finding_added', {
            'finding': {'type': 'test_finding', 'description': 'Test'},
            'target': '192.168.1.1'
        })

        # Verify task generated
        assert len(generated_tasks) > 0
        assert generated_tasks[0]['plugin'] == 'test-finding'

    def test_conflict_resolution_highest_confidence_wins(self):
        """Multiple plugins claiming same finding - highest confidence wins"""

        @ServiceRegistry.register
        class LowConfPlugin(ServicePlugin):
            @property
            def name(self): return "low-conf"
            def detect(self, port_info): return False
            def detect_from_finding(self, finding, profile=None): return 30
            def get_task_tree(self, target, port, service_info): return {'id': 'low'}

        @ServiceRegistry.register
        class HighConfPlugin(ServicePlugin):
            @property
            def name(self): return "high-conf"
            def detect(self, port_info): return False
            def detect_from_finding(self, finding, profile=None): return 90
            def get_task_tree(self, target, port, service_info): return {'id': 'high'}

        generated_tasks = []
        EventBus.on('plugin_tasks_generated', lambda d: generated_tasks.append(d))

        EventBus.emit('finding_added', {
            'finding': {'type': 'test', 'description': 'Test'},
            'target': '192.168.1.1'
        })

        # Only high confidence plugin should generate tasks
        assert len(generated_tasks) == 1
        assert generated_tasks[0]['plugin'] == 'high-conf'

    def test_deduplication_prevents_double_activation(self):
        """Same finding doesn't activate plugin twice"""

        @ServiceRegistry.register
        class DedupePlugin(ServicePlugin):
            activation_count = 0

            @property
            def name(self): return "dedupe-test"
            def detect(self, port_info): return False

            def detect_from_finding(self, finding, profile=None):
                return 100 if finding.get('type') == 'dedupe' else 0

            def get_task_tree(self, target, port, service_info):
                DedupePlugin.activation_count += 1
                return {'id': f'task-{self.activation_count}'}

        # Emit same finding twice
        finding = {'type': 'dedupe', 'description': 'Test'}
        EventBus.emit('finding_added', {'finding': finding, 'target': '192.168.1.1'})
        EventBus.emit('finding_added', {'finding': finding, 'target': '192.168.1.1'})

        # Should only activate once
        assert DedupePlugin.activation_count == 1
```

#### 3.2 Integration Tests
**File**: `tests/track/test_finding_to_plugin_flow.py` (NEW)

```python
"""Integration tests for finding → plugin → task flow"""

def test_shell_obtained_activates_post_exploit():
    """Shell obtained finding activates post-exploit plugin"""
    from crack.track.services.registry import ServiceRegistry
    from crack.track.core.events import EventBus

    ServiceRegistry.initialize_plugins()

    generated_tasks = []
    EventBus.on('plugin_tasks_generated', lambda d: generated_tasks.append(d))

    # Emit shell obtained finding
    EventBus.emit('finding_added', {
        'finding': {
            'type': 'shell_obtained',
            'description': 'Got reverse shell as www-data',
            'source': 'manual'
        },
        'target': '192.168.45.100'
    })

    # Verify post-exploit plugin activated
    assert any(t['plugin'] == 'post-exploit' for t in generated_tasks)

def test_wordpress_detection_activates_wordpress_plugin():
    """WordPress CMS detection activates WordPress plugin"""
    from crack.track.services.registry import ServiceRegistry
    from crack.track.core.events import EventBus

    ServiceRegistry.initialize_plugins()

    generated_tasks = []
    EventBus.on('plugin_tasks_generated', lambda d: generated_tasks.append(d))

    # Emit WordPress detection finding
    EventBus.emit('finding_added', {
        'finding': {
            'type': 'cms_detected',
            'description': 'WordPress 5.8.1 detected at /wordpress',
            'source': 'http-enum'
        },
        'target': '192.168.45.100'
    })

    # Verify WordPress plugin activated
    assert any(t['plugin'] == 'wordpress' for t in generated_tasks)
```

### Phase 4: Plugin Migration - Tier 2 (4 hours)

Additional plugins to migrate based on audit:

| Plugin | Current | Target | Finding Trigger |
|--------|---------|--------|-----------------|
| injection_attacks.py | finding-triggered | Enhance | sql_injection_found |
| cms.py | nmap-triggered | Dual | cms_detected |
| linux_enumeration.py | nmap-triggered | Dual | os_linux |
| linux_persistence.py | nmap-triggered | Dual | root_shell |
| linux_container_escape.py | nmap-triggered | Dual | container_detected |
| ad_enumeration.py | nmap-triggered | Dual | domain_joined |
| credential_theft.py | nmap-triggered | Dual | credential_found |

### Phase 5: Documentation Updates (1 hour)

#### 5.1 Update PLUGIN_REQUIREMENTS.md
**Line**: After line 91 (after on_task_complete section)

Add new section:
```markdown
### **Optional: `detect_from_finding()` Method**
```

#### 5.2 Update CLAUDE.md Architecture Section
Document the dual activation pathways and finding types.

#### 5.3 Create FINDING_TYPES.md
Document all standardized finding types and which plugins they activate.

## Rollout Plan

### Phase Breakdown
1. **Week 1**: Core infrastructure + Tier 1 plugins (4 critical)
2. **Week 2**: Tier 2 plugins (7 high-value)
3. **Week 3**: Tier 3 plugins (remaining candidates)
4. **Week 4**: Testing, documentation, cleanup

### Validation Gates

#### After Phase 1:
- [ ] All existing plugins still work (regression test)
- [ ] Post-exploit plugin activates via finding
- [ ] Windows/Linux privesc activate via OS detection
- [ ] WordPress activates via CMS detection
- [ ] No performance degradation

#### After Phase 2:
- [ ] 15+ plugins support finding-based activation
- [ ] <10% manual-only plugins remain
- [ ] Integration tests pass
- [ ] TUI properly displays finding-triggered tasks

#### After Phase 3:
- [ ] <5% manual-only plugins (goal achieved)
- [ ] Documentation complete
- [ ] All tests passing
- [ ] User acceptance testing

### Rollback Strategy
1. **Feature Flag**: Add `ENABLE_FINDING_ACTIVATION` config flag
2. **Gradual Rollout**: Enable per-plugin via config
3. **Safe Fallback**: detect_from_finding defaults to 0 (no activation)
4. **Version Control**: Tag releases before/after changes

## Success Metrics
- **Reduction in Manual Plugins**: From 2% to <5% manual-only
- **Increased Automation**: 50%+ reduction in manual plugin triggers
- **No Performance Impact**: <100ms overhead for finding processing
- **Backward Compatibility**: 100% of existing plugins still work
- **Test Coverage**: 90%+ coverage of new code paths