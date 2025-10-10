# Plugin Activation Renovation - Code Snippets

## 1. Base Class Enhancement

### ServicePlugin Base Class Addition
```python
# File: track/services/base.py
# Location: After line 91 (after on_task_complete method)

def detect_from_finding(self, finding: Dict[str, Any], profile: Optional['TargetProfile'] = None) -> float:
    """Determine if this plugin should activate based on a finding

    Args:
        finding: Finding dict with keys:
            - type: Finding type (shell_obtained, cms_detected, etc.)
            - description: Human-readable description
            - source: Where finding came from (nmap, gobuster, manual)
            - timestamp: When finding was discovered
        profile: Optional TargetProfile for additional context (OS info, services, etc.)

    Returns:
        Confidence score (0-100) that this plugin should handle this finding:
        - 0: Cannot handle this finding (default)
        - 1-30: Low confidence (maybe handle if no better match)
        - 31-70: Medium confidence (likely match)
        - 71-90: High confidence (strong match)
        - 91-100: Perfect match (exact finding type match)

    Example:
        >>> finding = {'type': 'shell_obtained', 'description': 'Got reverse shell as www-data'}
        >>> plugin.detect_from_finding(finding)
        100  # Post-exploit plugin returns high confidence

    Note:
        Default implementation returns 0, making this opt-in.
        Plugins that want finding-based activation must override this method.
    """
    return 0
```

## 2. ServiceRegistry Enhancement

### New Event Handler Setup
```python
# File: track/services/registry.py
# Location: Line 56 in _setup_event_handlers method

@classmethod
def _setup_event_handlers(cls, plugin: ServicePlugin):
    """Setup event handlers for plugin

    Args:
        plugin: Service plugin instance
    """
    # Existing handlers
    EventBus.on('service_detected', lambda data: cls._handle_service_detected(plugin, data))
    EventBus.on('task_completed', lambda data: cls._handle_task_completed(plugin, data))

    # NEW: Finding-based activation handler
    EventBus.on('finding_added', lambda data: cls._handle_finding_added(plugin, data))
```

### Finding Handler Implementation
```python
# File: track/services/registry.py
# Location: After _handle_task_completed method (line 222)

@classmethod
def _handle_finding_added(cls, plugin: ServicePlugin, data: Dict[str, Any]):
    """Handle finding_added event with finding-based plugin activation

    This enables plugins to activate based on discoveries, not just port scans.
    Examples:
    - Shell obtained → Activate post-exploit plugin
    - WordPress detected → Activate WordPress plugin
    - Windows OS identified → Activate Windows privesc plugin

    Args:
        plugin: Service plugin instance
        data: Event data containing:
            - finding: Dict with type, description, source
            - profile: Optional TargetProfile
            - target: Target IP/hostname
    """
    finding = data.get('finding')
    if not finding:
        return

    profile = data.get('profile')  # Optional, for additional context
    target = data.get('target', 'unknown')

    # Check if this plugin can handle this finding
    try:
        confidence = plugin.detect_from_finding(finding, profile)
    except Exception as e:
        logger.debug(f"Plugin {plugin.name} detect_from_finding failed: {e}")
        confidence = 0

    # Backward compatibility: handle boolean returns
    if isinstance(confidence, bool):
        confidence = 100 if confidence else 0

    if confidence <= 0:
        return

    # Create unique fingerprint for deduplication
    finding_key = f"{finding.get('type', 'unknown')}:{finding.get('description', '')[:100]}"

    # Initialize tracking structures if needed
    if not hasattr(cls, '_activated_findings'):
        cls._activated_findings = set()
    if not hasattr(cls, '_finding_claims'):
        cls._finding_claims = {}

    # Check if already activated this plugin for this finding
    activation_key = f"{plugin.name}:{finding_key}"
    if activation_key in cls._activated_findings:
        logger.debug(f"Plugin {plugin.name} already activated for finding {finding_key[:50]}")
        return

    # Register this plugin's claim on the finding
    if finding_key not in cls._finding_claims:
        cls._finding_claims[finding_key] = []

    cls._finding_claims[finding_key].append({
        'plugin': plugin,
        'confidence': confidence,
        'data': data,
        'target': target
    })

    # Resolve conflicts (immediate for now, could be async with timer)
    cls._resolve_finding_conflicts(finding_key)

@classmethod
def _resolve_finding_conflicts(cls, finding_key: str):
    """Resolve competing plugin claims for a finding

    When multiple plugins want to handle the same finding,
    the one with highest confidence wins (same as port conflicts).

    Args:
        finding_key: Unique finding identifier
    """
    if finding_key not in cls._finding_claims:
        return

    claims = cls._finding_claims.get(finding_key, [])
    if not claims:
        return

    # Sort by confidence (highest first)
    claims.sort(key=lambda x: x['confidence'], reverse=True)

    # Winner takes all - highest confidence generates tasks
    winner = claims[0]
    plugin = winner['plugin']
    data = winner['data']
    target = winner['target']

    # Mark this plugin-finding combo as activated (prevent re-activation)
    activation_key = f"{plugin.name}:{finding_key}"
    cls._activated_findings.add(activation_key)

    logger.info(f"Plugin '{plugin.name}' activated by finding (confidence: {winner['confidence']})")

    # Generate task tree with finding context
    try:
        finding = data.get('finding', {})

        # Build service_info with finding context
        service_info = {
            'activation_source': 'finding',  # Mark as finding-triggered
            'finding': finding,
            'finding_type': finding.get('type'),
            'finding_description': finding.get('description'),
            'finding_source': finding.get('source', 'unknown')
        }

        # Add profile data if available
        if data.get('profile'):
            service_info['profile'] = data['profile']

        # Generate tasks (port=0 for finding-based activation)
        task_tree = plugin.get_task_tree(
            target=target,
            port=0,  # No port for finding-based activation
            service_info=service_info
        )

        # Emit task generation event
        if task_tree:
            EventBus.emit('plugin_tasks_generated', {
                'plugin': plugin.name,
                'task_tree': task_tree,
                'target': target,
                'source': 'finding_activation',
                'finding_type': finding.get('type')
            })
            logger.debug(f"Plugin {plugin.name} generated tasks from finding")

    except Exception as e:
        logger.error(f"Error generating tasks for {plugin.name} from finding: {e}")

    # Clear claims after resolution
    del cls._finding_claims[finding_key]
```

### Update Clear Method for Testing
```python
# File: track/services/registry.py
# Location: Line 390 in clear() method

@classmethod
def clear(cls):
    """Clear resolution state but preserve registered plugins (for testing isolation)"""
    cls._initialized = False

    # Clear port-based tracking
    if hasattr(cls, '_plugin_claims'):
        cls._plugin_claims.clear()
        delattr(cls, '_plugin_claims')
    if hasattr(cls, '_resolved_ports'):
        cls._resolved_ports.clear()
        delattr(cls, '_resolved_ports')

    # NEW: Clear finding-based tracking
    if hasattr(cls, '_finding_claims'):
        cls._finding_claims.clear()
        delattr(cls, '_finding_claims')
    if hasattr(cls, '_activated_findings'):
        cls._activated_findings.clear()
        delattr(cls, '_activated_findings')
```

## 3. Finding Type Constants

### New Constants File
```python
# File: track/core/constants.py (NEW FILE)
"""Standardized finding types for plugin activation"""

class FindingTypes:
    """Standard finding type constants

    These enable consistent finding categorization across the system.
    Plugins use these to determine activation triggers.
    """

    # Shell/Access Types
    SHELL_OBTAINED = 'shell_obtained'  # Any shell access
    LOW_PRIVILEGE_SHELL = 'low_privilege_shell'  # www-data, apache, etc.
    HIGH_PRIVILEGE_SHELL = 'high_privilege_shell'  # root, administrator
    ROOT_SHELL = 'root_shell'  # Unix root
    SYSTEM_SHELL = 'system_shell'  # Windows SYSTEM
    ADMIN_SHELL = 'admin_shell'  # Windows Administrator

    # Operating System Detection
    OS_DETECTED = 'os_detected'  # Generic OS identification
    OS_LINUX = 'os_linux'
    OS_WINDOWS = 'os_windows'
    OS_MACOS = 'os_macos'
    OS_BSD = 'os_bsd'
    OS_SOLARIS = 'os_solaris'
    OS_AIX = 'os_aix'

    # CMS/Framework Detection
    CMS_DETECTED = 'cms_detected'  # Generic CMS found
    CMS_WORDPRESS = 'cms_wordpress'
    CMS_JOOMLA = 'cms_joomla'
    CMS_DRUPAL = 'cms_drupal'
    CMS_MAGENTO = 'cms_magento'
    CMS_SHOPIFY = 'cms_shopify'
    FRAMEWORK_DETECTED = 'framework_detected'
    FRAMEWORK_DJANGO = 'framework_django'
    FRAMEWORK_RAILS = 'framework_rails'
    FRAMEWORK_LARAVEL = 'framework_laravel'
    FRAMEWORK_SPRING = 'framework_spring'

    # Credentials
    CREDENTIAL_FOUND = 'credential_found'  # Generic credential
    SSH_CREDENTIAL = 'ssh_credential'
    RDP_CREDENTIAL = 'rdp_credential'
    DATABASE_CREDENTIAL = 'database_credential'
    WEB_CREDENTIAL = 'web_credential'
    API_KEY_FOUND = 'api_key_found'
    HASH_FOUND = 'hash_found'

    # Vulnerabilities
    VULNERABILITY_FOUND = 'vulnerability'
    CVE_FOUND = 'cve_found'
    MISCONFIGURATION = 'misconfiguration'
    SQL_INJECTION = 'sql_injection'
    XSS_FOUND = 'xss_found'
    LFI_FOUND = 'lfi_found'
    RFI_FOUND = 'rfi_found'
    XXE_FOUND = 'xxe_found'
    SSRF_FOUND = 'ssrf_found'
    RCE_FOUND = 'rce_found'

    # Environment Detection
    CONTAINER_DETECTED = 'container_detected'  # Docker, LXC, etc.
    KUBERNETES_DETECTED = 'kubernetes_detected'
    DOMAIN_JOINED = 'domain_joined'  # Active Directory
    CLOUD_DETECTED = 'cloud_detected'  # AWS, Azure, GCP
    VIRTUAL_MACHINE = 'virtual_machine'  # VMware, VirtualBox, etc.

    # Service/Access Types
    SERVICE_VERSION = 'service_version'  # Specific version identified
    DATABASE_ACCESS = 'database_access'  # Got DB access
    API_ACCESS = 'api_access'  # API endpoint discovered
    ADMIN_PANEL_FOUND = 'admin_panel_found'
    CONFIG_FILE_FOUND = 'config_file_found'
    BACKUP_FILE_FOUND = 'backup_file_found'
    SOURCE_CODE_FOUND = 'source_code_found'

    @classmethod
    def is_shell_type(cls, finding_type: str) -> bool:
        """Check if finding type represents shell access"""
        shell_types = {
            cls.SHELL_OBTAINED,
            cls.LOW_PRIVILEGE_SHELL,
            cls.HIGH_PRIVILEGE_SHELL,
            cls.ROOT_SHELL,
            cls.SYSTEM_SHELL,
            cls.ADMIN_SHELL
        }
        return finding_type in shell_types

    @classmethod
    def is_os_type(cls, finding_type: str) -> bool:
        """Check if finding type represents OS detection"""
        os_types = {
            cls.OS_DETECTED,
            cls.OS_LINUX,
            cls.OS_WINDOWS,
            cls.OS_MACOS,
            cls.OS_BSD,
            cls.OS_SOLARIS,
            cls.OS_AIX
        }
        return finding_type in os_types

    @classmethod
    def is_cms_type(cls, finding_type: str) -> bool:
        """Check if finding type represents CMS detection"""
        cms_types = {
            cls.CMS_DETECTED,
            cls.CMS_WORDPRESS,
            cls.CMS_JOOMLA,
            cls.CMS_DRUPAL,
            cls.CMS_MAGENTO,
            cls.CMS_SHOPIFY
        }
        return finding_type in cms_types
```

## 4. Plugin Migration Examples

### Post-Exploit Plugin Migration
```python
# File: track/services/post_exploit.py
# Add after detect() method (line 23)

def detect_from_finding(self, finding: Dict[str, Any], profile: Optional['TargetProfile'] = None) -> float:
    """Activate post-exploit plugin when shell is obtained

    Triggers on:
    - Shell obtained findings
    - Successful RCE exploitation
    - Command execution achieved

    Args:
        finding: Finding dictionary
        profile: Optional target profile for context

    Returns:
        Confidence score (0-100)
    """
    from ..core.constants import FindingTypes

    finding_type = finding.get('type', '').lower()
    description = finding.get('description', '').lower()

    # Perfect match - explicit shell types
    if FindingTypes.is_shell_type(finding_type):
        return 100

    # High confidence - shell indicators in description
    shell_indicators = [
        'shell obtained',
        'got shell',
        'shell access',
        'rce achieved',
        'remote code execution',
        'command execution achieved',
        'reverse shell connected',
        'bind shell established',
        'webshell uploaded',
        'code execution confirmed'
    ]

    if any(indicator in description for indicator in shell_indicators):
        return 85

    # Medium confidence - successful exploitation
    if finding_type == FindingTypes.RCE_FOUND and 'success' in description:
        return 70

    if finding_type == FindingTypes.VULNERABILITY_FOUND and 'exploited' in description:
        return 60

    return 0

# Update get_task_tree to handle finding context
def get_task_tree(self, target: str, port: int, service_info: Dict[str, Any]) -> Dict[str, Any]:
    """Generate post-exploitation enumeration tasks

    Handles both port-based and finding-based activation.
    """
    # Detect activation source
    if service_info.get('activation_source') == 'finding':
        # Finding-based activation - extract OS from finding
        finding = service_info.get('finding', {})
        os_type = self._detect_os_from_finding(finding)
    else:
        # Port-based activation (original logic)
        os_type = service_info.get('os_type', 'linux').lower()

    # Rest of method unchanged...
    if os_type == 'linux':
        return self._get_linux_tasks(target)
    elif os_type == 'windows':
        return self._get_windows_tasks(target)
    else:
        return self._get_generic_tasks(target)

def _detect_os_from_finding(self, finding: Dict[str, Any]) -> str:
    """Detect OS type from finding context"""
    description = finding.get('description', '').lower()

    # Windows indicators
    windows_indicators = ['windows', 'powershell', 'cmd.exe', 'nt authority',
                         'system32', 'iis', 'aspx']
    if any(ind in description for ind in windows_indicators):
        return 'windows'

    # Linux indicators
    linux_indicators = ['linux', 'bash', '/bin/sh', 'www-data', 'apache',
                       'ubuntu', 'debian', 'centos', 'redhat']
    if any(ind in description for ind in linux_indicators):
        return 'linux'

    # Default to linux (most common in OSCP)
    return 'linux'
```

### Windows Privesc Plugin Migration
```python
# File: track/services/windows_privesc.py
# Add after detect() method

def detect_from_finding(self, finding: Dict[str, Any], profile: Optional['TargetProfile'] = None) -> float:
    """Activate on Windows shell or OS detection

    Triggers on:
    - Windows shell obtained
    - Windows OS detected
    - Windows-specific services found

    Args:
        finding: Finding dictionary
        profile: Optional target profile

    Returns:
        Confidence score (0-100)
    """
    from ..core.constants import FindingTypes

    finding_type = finding.get('type', '')
    description = finding.get('description', '').lower()

    # Perfect match - Windows shell explicitly
    if finding_type == FindingTypes.SYSTEM_SHELL:
        return 100

    if finding_type == FindingTypes.ADMIN_SHELL:
        return 95

    # High confidence - Windows OS detected
    if finding_type == FindingTypes.OS_WINDOWS:
        return 95

    # High confidence - Windows shell obtained
    windows_shell_indicators = [
        'windows shell',
        'powershell',
        'cmd.exe',
        'windows command',
        r'nt authority\system',
        r'nt authority\network service',
        r'windows\system32',
        'got shell on windows',
        'windows reverse shell'
    ]

    if finding_type == FindingTypes.SHELL_OBTAINED:
        if any(ind in description for ind in windows_shell_indicators):
            return 90

    # Medium confidence - Windows indicators
    if finding_type == FindingTypes.OS_DETECTED and 'windows' in description:
        return 85

    # Low confidence - Windows services/versions
    windows_service_indicators = [
        'microsoft',
        'windows server',
        'iis/',
        'smb windows',
        'ms17-010',
        'eternalblue',
        'ms08-067'
    ]

    if any(ind in description for ind in windows_service_indicators):
        return 50

    # Check profile for Windows evidence
    if profile:
        os_info = profile.get_os_info()
        if os_info and 'windows' in os_info.lower():
            return 70

    return 0
```

### WordPress Plugin Migration
```python
# File: track/services/wordpress.py
# Add after detect() method

def detect_from_finding(self, finding: Dict[str, Any], profile: Optional['TargetProfile'] = None) -> float:
    """Activate when WordPress CMS is detected

    Triggers on:
    - WordPress explicitly detected
    - WordPress files/paths found
    - WordPress vulnerabilities identified

    Args:
        finding: Finding dictionary
        profile: Optional target profile

    Returns:
        Confidence score (0-100)
    """
    from ..core.constants import FindingTypes

    finding_type = finding.get('type', '')
    description = finding.get('description', '').lower()

    # Perfect match - WordPress explicitly detected
    if finding_type == FindingTypes.CMS_WORDPRESS:
        return 100

    # High confidence - WordPress in CMS detection
    if finding_type == FindingTypes.CMS_DETECTED:
        if 'wordpress' in description:
            return 95

    # High confidence - WordPress paths/files
    wordpress_indicators = [
        'wordpress',
        'wp-content',
        'wp-admin',
        'wp-login.php',
        'wp-includes',
        'wp-json',
        'xmlrpc.php',
        'wp-config',
        'wordpress theme',
        'wordpress plugin'
    ]

    if any(ind in description for ind in wordpress_indicators):
        # Very high confidence if it's a directory or file finding
        if finding_type in ['directory', 'file']:
            return 90
        else:
            return 75

    # Medium confidence - PHP CMS that might be WordPress
    if finding_type == FindingTypes.CMS_DETECTED:
        if 'cms' in description and 'php' in description:
            return 30

    # Low confidence - Generic web finding that could be WordPress
    if finding_type == 'directory' and any(wp in description for wp in ['/blog', '/news', '/content']):
        return 20

    return 0

# Update get_task_tree to use finding context
def get_task_tree(self, target: str, port: int, service_info: Dict[str, Any]) -> Dict[str, Any]:
    """Generate WordPress enumeration task tree

    Handles both port-based and finding-based activation.
    """
    # Determine protocol and port
    if service_info.get('activation_source') == 'finding':
        # Finding-based - need to determine port from profile or finding
        finding = service_info.get('finding', {})
        port = self._extract_port_from_finding(finding, service_info.get('profile'))
        protocol = 'https' if port == 443 else 'http'
    else:
        # Port-based (original logic)
        protocol = 'https' if port == 443 else 'http'

    base_url = f'{protocol}://{target}:{port}' if port not in [80, 443] else f'{protocol}://{target}'

    # Generate tasks...
    # [Rest of existing get_task_tree logic]

def _extract_port_from_finding(self, finding: Dict[str, Any], profile: Optional['TargetProfile']) -> int:
    """Extract port number from finding or profile"""
    # Try to extract from finding description
    import re
    description = finding.get('description', '')
    port_match = re.search(r':(\d+)', description)
    if port_match:
        return int(port_match.group(1))

    # Check profile for HTTP services
    if profile:
        for port_info in profile.get_ports():
            if 'http' in port_info.get('service', '').lower():
                return port_info.get('port')

    # Default to port 80
    return 80
```

## 5. Test Examples

### Unit Test for Finding-Based Activation
```python
# File: tests/track/test_finding_based_activation.py

import pytest
from unittest.mock import Mock, patch
from crack.track.services.registry import ServiceRegistry
from crack.track.services.base import ServicePlugin
from crack.track.core.events import EventBus
from crack.track.core.constants import FindingTypes


class TestFindingActivation:

    def setup_method(self):
        """Reset state before each test"""
        EventBus.clear()
        ServiceRegistry.clear()

    def test_plugin_detect_from_finding_default(self):
        """Default detect_from_finding returns 0"""

        class TestPlugin(ServicePlugin):
            @property
            def name(self): return "test"
            def detect(self, port_info): return False
            def get_task_tree(self, target, port, service_info): return {}

        plugin = TestPlugin()
        finding = {'type': 'shell_obtained', 'description': 'Test'}

        assert plugin.detect_from_finding(finding) == 0

    def test_finding_triggers_plugin_activation(self):
        """Finding successfully activates plugin"""

        task_events = []

        @ServiceRegistry.register
        class TestPlugin(ServicePlugin):
            @property
            def name(self): return "test-plugin"

            def detect(self, port_info): return False

            def detect_from_finding(self, finding, profile=None):
                if finding.get('type') == 'test_trigger':
                    return 100
                return 0

            def get_task_tree(self, target, port, service_info):
                return {
                    'id': 'test-task',
                    'name': 'Test Task from Finding',
                    'type': 'manual'
                }

        # Capture events
        EventBus.on('plugin_tasks_generated', lambda d: task_events.append(d))

        # Initialize and emit finding
        ServiceRegistry.initialize_plugins()
        EventBus.emit('finding_added', {
            'finding': {'type': 'test_trigger', 'description': 'Test finding'},
            'target': '192.168.1.1'
        })

        # Verify task generated
        assert len(task_events) == 1
        assert task_events[0]['plugin'] == 'test-plugin'
        assert task_events[0]['source'] == 'finding_activation'

    def test_confidence_resolution(self):
        """Higher confidence plugin wins"""

        winner = None

        @ServiceRegistry.register
        class LowPlugin(ServicePlugin):
            @property
            def name(self): return "low"
            def detect(self, port_info): return False
            def detect_from_finding(self, finding, profile=None): return 30
            def get_task_tree(self, target, port, service_info):
                nonlocal winner
                winner = 'low'
                return {'id': 'low-task'}

        @ServiceRegistry.register
        class HighPlugin(ServicePlugin):
            @property
            def name(self): return "high"
            def detect(self, port_info): return False
            def detect_from_finding(self, finding, profile=None): return 90
            def get_task_tree(self, target, port, service_info):
                nonlocal winner
                winner = 'high'
                return {'id': 'high-task'}

        ServiceRegistry.initialize_plugins()
        EventBus.emit('finding_added', {
            'finding': {'type': 'test', 'description': 'Test'},
            'target': '192.168.1.1'
        })

        assert winner == 'high'

    def test_deduplication(self):
        """Same finding doesn't activate plugin twice"""

        activation_count = 0

        @ServiceRegistry.register
        class CountPlugin(ServicePlugin):
            @property
            def name(self): return "counter"
            def detect(self, port_info): return False
            def detect_from_finding(self, finding, profile=None): return 100
            def get_task_tree(self, target, port, service_info):
                nonlocal activation_count
                activation_count += 1
                return {'id': f'task-{activation_count}'}

        ServiceRegistry.initialize_plugins()

        # Emit same finding twice
        finding = {'type': 'test', 'description': 'Duplicate test'}
        EventBus.emit('finding_added', {'finding': finding, 'target': '192.168.1.1'})
        EventBus.emit('finding_added', {'finding': finding, 'target': '192.168.1.1'})

        assert activation_count == 1
```

### Integration Test
```python
# File: tests/track/test_finding_plugin_integration.py

def test_shell_finding_activates_post_exploit():
    """Real-world test: shell obtained activates post-exploit plugin"""
    from crack.track.services.registry import ServiceRegistry
    from crack.track.core.events import EventBus
    from crack.track.core.constants import FindingTypes

    ServiceRegistry.initialize_plugins()

    tasks = []
    EventBus.on('plugin_tasks_generated', lambda d: tasks.append(d))

    # Simulate shell obtained
    EventBus.emit('finding_added', {
        'finding': {
            'type': FindingTypes.SHELL_OBTAINED,
            'description': 'Reverse shell obtained as www-data on Linux',
            'source': 'exploit/multi/http/apache_mod_cgi_bash_env_exec'
        },
        'target': '192.168.45.100'
    })

    # Verify post-exploit plugin activated
    assert len(tasks) > 0
    assert any(t['plugin'] == 'post-exploit' for t in tasks)

    # Verify Linux-specific tasks generated
    post_exploit_task = next(t for t in tasks if t['plugin'] == 'post-exploit')
    task_tree = post_exploit_task['task_tree']
    assert 'linux' in task_tree['id'].lower()
```

## 6. Usage Examples

### Example 1: Shell Obtained
```python
# When user gets a shell, emit finding
from crack.track.core.events import EventBus
from crack.track.core.constants import FindingTypes

EventBus.emit('finding_added', {
    'finding': {
        'type': FindingTypes.SHELL_OBTAINED,
        'description': 'Reverse shell obtained as www-data via PHP upload vulnerability',
        'source': 'manual_exploitation',
        'timestamp': '2024-01-15T10:30:00'
    },
    'target': '192.168.45.100'
})

# This automatically activates:
# - post_exploit plugin (Linux enumeration tasks)
# - linux_privesc plugin (privilege escalation tasks)
```

### Example 2: CMS Detection
```python
# When WordPress is detected
EventBus.emit('finding_added', {
    'finding': {
        'type': FindingTypes.CMS_WORDPRESS,
        'description': 'WordPress 5.8.1 detected at /blog/',
        'source': 'http_enumeration',
        'timestamp': '2024-01-15T09:15:00'
    },
    'target': '192.168.45.200'
})

# This automatically activates:
# - wordpress plugin (WPScan, user enum, plugin discovery)
```

### Example 3: OS Detection
```python
# When OS is identified
EventBus.emit('finding_added', {
    'finding': {
        'type': FindingTypes.OS_WINDOWS,
        'description': 'Windows Server 2019 detected via SMB banner',
        'source': 'smb_enumeration',
        'timestamp': '2024-01-15T08:00:00'
    },
    'target': '192.168.45.50'
})

# This automatically activates:
# - windows_privesc plugin (Windows enumeration tasks)
# - windows_core plugin (Windows-specific checks)
```