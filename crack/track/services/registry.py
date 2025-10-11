"""
Service plugin registry with auto-discovery

Plugins register themselves using the @ServiceRegistry.register decorator
"""

from typing import Dict, List, Any, Optional
from .base import ServicePlugin
from ..core.events import EventBus
import logging

logger = logging.getLogger(__name__)


class ServiceRegistry:
    """Central registry for service plugins"""

    _plugins: Dict[str, ServicePlugin] = {}
    _initialized: bool = False

    @classmethod
    def register(cls, plugin_class):
        """Decorator to register a service plugin

        Usage:
            @ServiceRegistry.register
            class HTTPPlugin(ServicePlugin):
                ...

        Args:
            plugin_class: ServicePlugin subclass

        Returns:
            The plugin class (for decorator chaining)
        """
        try:
            plugin = plugin_class()
            cls._plugins[plugin.name] = plugin
            logger.info(f"Registered service plugin: {plugin.name}")

            # Auto-wire event handlers
            cls._setup_event_handlers(plugin)

        except Exception as e:
            logger.error(f"Failed to register plugin {plugin_class}: {e}")

        return plugin_class

    @classmethod
    def _setup_event_handlers(cls, plugin: ServicePlugin):
        """Setup event handlers for plugin

        Args:
            plugin: Service plugin instance
        """
        # Listen for service detection events
        EventBus.on('service_detected', lambda data: cls._handle_service_detected(plugin, data))

        # Listen for task completion events (for on_task_complete callbacks)
        EventBus.on('task_completed', lambda data: cls._handle_task_completed(plugin, data))

        # Listen for finding_added events for finding-based plugin activation
        EventBus.on('finding_added', lambda data: cls._handle_finding_added(plugin, data))

    @classmethod
    def _handle_service_detected(cls, plugin: ServicePlugin, data: Dict[str, Any]):
        """Handle service detection event with conflict resolution

        Args:
            plugin: Service plugin
            data: Event data (target, port, service, version, profile)
        """
        # Extract profile from event
        profile = data.get('profile')
        if not profile:
            logger.warning("service_detected event missing profile - skipping detection")
            return

        port_info = {
            'port': data.get('port'),
            'service': data.get('service'),
            'version': data.get('version'),
            'state': 'open'
        }

        # Check if plugin can handle this service (now returns confidence score)
        detection_result = plugin.detect(port_info, profile)

        # Handle both old boolean and new confidence score formats
        # Penalize boolean returns to encourage proper confidence scoring
        if isinstance(detection_result, bool):
            confidence = 75 if detection_result else 0  # Changed from 100 to 75
        elif isinstance(detection_result, (int, float)):
            confidence = detection_result
        else:
            confidence = 0

        if confidence <= 0:
            return

        # Store plugin confidence for this port
        port_key = f"{data.get('target')}:{data.get('port')}"
        if not hasattr(cls, '_plugin_claims'):
            cls._plugin_claims = {}

        if port_key not in cls._plugin_claims:
            cls._plugin_claims[port_key] = []

        cls._plugin_claims[port_key].append({
            'plugin': plugin,
            'confidence': confidence,
            'data': data
        })

        # Don't generate tasks immediately - wait for all plugins to claim
        # Schedule task generation after a brief delay to collect all claims
        cls._schedule_task_generation(port_key)

    @classmethod
    def _schedule_task_generation(cls, port_key: str):
        """Schedule task generation with conflict resolution

        Args:
            port_key: Unique port identifier (target:port)
        """
        # Simple immediate resolution for now (could be made async with timer)
        # In a production system, this would use threading.Timer for delay
        cls._resolve_plugin_conflicts(port_key)

    @classmethod
    def _resolve_plugin_conflicts(cls, port_key: str):
        """Resolve plugin conflicts and generate tasks for winning plugin

        Args:
            port_key: Unique port identifier (target:port)
        """
        if port_key not in cls._plugin_claims:
            return

        claims = cls._plugin_claims[port_key]
        if not claims:
            return

        # Check if already resolved (prevents duplicate resolution)
        if not hasattr(cls, '_resolved_ports'):
            cls._resolved_ports = set()

        if port_key in cls._resolved_ports:
            return  # Already resolved, skip

        # Mark as resolved immediately
        cls._resolved_ports.add(port_key)

        # Sort by confidence (highest first)
        claims.sort(key=lambda x: x['confidence'], reverse=True)

        # Winner takes all - highest confidence generates tasks
        winner = claims[0]
        plugin = winner['plugin']
        data = winner['data']

        logger.info(f"Plugin '{plugin.name}' won port {port_key} with confidence {winner['confidence']}")

        # Generate task tree for winning plugin only
        try:
            port_info = {
                'port': data.get('port'),
                'service': data.get('service'),
                'version': data.get('version'),
                'state': 'open'
            }

            task_tree = plugin.get_task_tree(
                target=data.get('target'),
                port=data.get('port'),
                service_info=port_info
            )

            # Emit event with generated tasks
            EventBus.emit('plugin_tasks_generated', {
                'plugin': plugin.name,
                'task_tree': task_tree,
                'target': data.get('target')
            })

        except Exception as e:
            logger.error(f"Error generating tasks for {plugin.name}: {e}")

        # Clear claims for this port after resolution
        del cls._plugin_claims[port_key]

    @classmethod
    def _handle_task_completed(cls, plugin: ServicePlugin, data: Dict[str, Any]):
        """Handle task completion event and call plugin's on_task_complete

        Args:
            plugin: Service plugin instance
            data: Event data (task, task_id, output, findings, target, command, exit_code)
        """
        task = data.get('task')
        task_id = data.get('task_id', '')
        output = data.get('output', [])
        target = data.get('target', '')

        if not task_id or not target:
            return

        # Check if this plugin can handle this task (fuzzy matching)
        if not cls._plugin_can_handle_task(plugin, task_id, task):
            return

        # Convert output list to string
        output_str = '\n'.join(output) if isinstance(output, list) else str(output)

        # Call plugin's on_task_complete method
        try:
            new_tasks = plugin.on_task_complete(task_id, output_str, target)

            if new_tasks:
                logger.info(f"Plugin '{plugin.name}' generated {len(new_tasks)} follow-up tasks from '{task_id}'")

                # Emit task generation events for each new task
                for task_def in new_tasks:
                    EventBus.emit('plugin_tasks_generated', {
                        'plugin': plugin.name,
                        'task_tree': task_def,
                        'target': target
                    })

        except Exception as e:
            logger.error(f"Error in {plugin.name}.on_task_complete for task '{task_id}': {e}")

    @classmethod
    def _handle_finding_added(cls, plugin: ServicePlugin, data: Dict[str, Any]):
        """Handle finding_added event with finding-based activation

        Args:
            plugin: Service plugin instance
            data: Event data containing finding and optional profile
        """
        finding = data.get('finding')
        profile = data.get('profile')  # Optional profile for context
        target = data.get('target', 'unknown')

        if not finding:
            return

        # Check if plugin can handle this finding
        try:
            confidence = plugin.detect_from_finding(finding, profile)
        except Exception as e:
            logger.error(f"Error in {plugin.name}.detect_from_finding: {e}")
            return

        if confidence <= 0:
            return  # Plugin not interested in this finding

        # Create unique key for this finding
        finding_type = finding.get('type', 'unknown')
        finding_desc = finding.get('description', '')[:50]  # Truncate for key
        finding_key = f"{finding_type}:{finding_desc}"

        # Initialize tracking structures if needed
        if not hasattr(cls, '_activated_findings'):
            cls._activated_findings = set()
        if not hasattr(cls, '_finding_claims'):
            cls._finding_claims = {}

        # Check deduplication at the plugin-finding level
        # This prevents same plugin from claiming same finding twice
        # (e.g., if event is emitted multiple times)
        activation_key = f"{plugin.name}:{finding_key}"
        if activation_key in cls._activated_findings:
            logger.debug(f"Plugin '{plugin.name}' already activated for finding '{finding_key}'")
            return  # Already activated this plugin for this finding

        # Track plugin confidence for conflict resolution
        if finding_key not in cls._finding_claims:
            cls._finding_claims[finding_key] = []

        # Check if this plugin already made a claim (prevent duplicate claims)
        for claim in cls._finding_claims[finding_key]:
            if claim['plugin'].name == plugin.name:
                return  # Plugin already claimed this finding

        cls._finding_claims[finding_key].append({
            'plugin': plugin,
            'confidence': confidence,
            'data': data
        })

        logger.debug(f"Plugin '{plugin.name}' claimed finding '{finding_key}' with confidence {confidence}")

        # Schedule resolution (use timer to collect all claims first)
        cls._schedule_finding_resolution(finding_key)

    @classmethod
    def _schedule_finding_resolution(cls, finding_key: str):
        """Schedule finding resolution to allow all plugins to register claims

        Uses a small delay to ensure all event handlers have been called.
        This is necessary because EventBus calls handlers sequentially.

        Args:
            finding_key: Unique finding identifier
        """
        import threading

        # Cancel any existing timer for this finding
        if not hasattr(cls, '_finding_timers'):
            cls._finding_timers = {}

        if finding_key in cls._finding_timers:
            cls._finding_timers[finding_key].cancel()

        # Schedule resolution after brief delay (0.001s = 1ms)
        # This allows all event handlers to register their claims first
        timer = threading.Timer(0.001, cls._resolve_finding_conflicts, args=[finding_key])
        cls._finding_timers[finding_key] = timer
        timer.start()

    @classmethod
    def _resolve_finding_conflicts(cls, finding_key: str):
        """Resolve plugin conflicts for finding-based activation

        Multiple plugins may want to activate from same finding.
        Highest confidence wins (same logic as port-based activation).

        Args:
            finding_key: Unique finding identifier
        """
        if finding_key not in cls._finding_claims:
            return

        claims = cls._finding_claims[finding_key]
        if not claims:
            return

        # Check if already resolved (prevents duplicate resolution)
        if not hasattr(cls, '_resolved_findings'):
            cls._resolved_findings = set()

        if finding_key in cls._resolved_findings:
            logger.debug(f"Finding '{finding_key}' already resolved, skipping")
            return  # Already resolved, skip

        # Mark as resolved immediately
        cls._resolved_findings.add(finding_key)

        logger.debug(f"Resolving finding '{finding_key}' with {len(claims)} claims")

        # Sort by confidence (highest first)
        claims.sort(key=lambda x: x['confidence'], reverse=True)

        logger.debug(f"Sorted claims: {[(c['plugin'].name, c['confidence']) for c in claims]}")

        # Winner takes all
        winner = claims[0]
        plugin = winner['plugin']
        data = winner['data']
        confidence = winner['confidence']

        # Log activation with confidence
        finding = data.get('finding', {})
        logger.info(f"Plugin '{plugin.name}' activated via finding '{finding.get('type')}' "
                    f"(confidence: {confidence})")

        # Mark as activated (deduplication)
        activation_key = f"{plugin.name}:{finding_key}"
        cls._activated_findings.add(activation_key)

        # Generate tasks using finding context
        try:
            target = data.get('target', 'unknown')

            # Build service_info with finding context
            service_info = {
                'activation_source': 'finding',
                'finding': finding,
                'finding_type': finding.get('type'),
                'finding_description': finding.get('description'),
                'finding_source': finding.get('source')
            }

            # Call get_task_tree with port=0 (no port for finding-based activation)
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
                'source': 'finding_activation',
                'finding_type': finding.get('type')
            })

            logger.info(f"Generated tasks for '{plugin.name}' from finding activation")

        except Exception as e:
            logger.error(f"Error generating tasks for {plugin.name} from finding: {e}")

        # Clear claims for this finding
        del cls._finding_claims[finding_key]

    @classmethod
    def _plugin_can_handle_task(cls, plugin: ServicePlugin, task_id: str, task: Any) -> bool:
        """Check if plugin can handle this task (fuzzy matching)

        Uses flexible pattern matching to avoid false negatives.

        Args:
            plugin: Service plugin instance
            task_id: Task identifier
            task: Task object (for metadata access)

        Returns:
            True if plugin should handle this task
        """
        plugin_name = plugin.name.lower()
        task_id_lower = task_id.lower()

        # Direct match: task ID contains plugin name
        if plugin_name in task_id_lower:
            return True

        # Service name aliases (fuzzy matching)
        service_aliases = {
            'http': ['web', 'https', 'whatweb', 'gobuster', 'nikto', 'wpscan', 'feroxbuster', 'dirb'],
            'smb': ['smbclient', 'enum4linux', 'smbmap', 'crackmapexec', 'microsoft-ds', 'netbios'],
            'ssh': ['openssh', 'ssh-audit'],
            'sql': ['mysql', 'postgresql', 'mssql', 'oracle', 'mariadb'],
            'ftp': ['vsftpd', 'proftpd'],
            'smtp': ['postfix', 'sendmail', 'exim'],
        }

        # Check if any alias matches
        aliases = service_aliases.get(plugin_name, [])
        for alias in aliases:
            if alias in task_id_lower:
                return True

        # Check task metadata for service hint (if task object has metadata)
        if task and hasattr(task, 'metadata'):
            metadata = task.metadata if isinstance(task.metadata, dict) else {}
            service_hint = metadata.get('service', '').lower()
            category = metadata.get('category', '').lower()

            if plugin_name in service_hint or plugin_name in category:
                return True

            # Check aliases in metadata
            for alias in aliases:
                if alias in service_hint or alias in category:
                    return True

        # Check port number patterns (e.g., http-enum-80, smb-enum-445)
        # Extract port from task ID (format: prefix-action-PORT)
        parts = task_id_lower.split('-')
        if len(parts) >= 2:
            try:
                # Last part might be port
                potential_port = int(parts[-1])

                # Check if port matches plugin's default ports
                if potential_port in plugin.default_ports:
                    return True
            except (ValueError, IndexError):
                pass

        return False

    @classmethod
    def get_plugin(cls, port_info: Dict[str, Any]) -> Optional[ServicePlugin]:
        """Find appropriate plugin for port/service

        Args:
            port_info: Port information dict

        Returns:
            ServicePlugin instance or None
        """
        # Auto-initialize plugins on first access
        if not cls._initialized:
            cls.initialize_plugins()

        for plugin in cls._plugins.values():
            if plugin.detect(port_info):
                return plugin

        # Fallback to generic plugin
        return cls._plugins.get('generic')

    @classmethod
    def get_all_plugins(cls) -> List[ServicePlugin]:
        """Get all registered plugins

        Returns:
            List of service plugins
        """
        # Auto-initialize plugins on first access
        if not cls._initialized:
            cls.initialize_plugins()
        return list(cls._plugins.values())

    @classmethod
    def get_plugin_by_name(cls, name: str) -> Optional[ServicePlugin]:
        """Get plugin by name

        Args:
            name: Plugin name

        Returns:
            ServicePlugin instance or None
        """
        # Auto-initialize plugins on first access
        if not cls._initialized:
            cls.initialize_plugins()
        return cls._plugins.get(name)

    @classmethod
    def initialize_plugins(cls):
        """Initialize all plugins (import plugin modules)

        This should be called at startup to discover and register all plugins
        """
        if cls._initialized:
            return

        # Import all plugin modules to trigger @register decorators
        try:
            from . import http, smb, ssh, sql, ftp, smtp, imap, pop3, mysql, postgresql, nfs, post_exploit, ad_attacks, lateral_movement, business_logic, macos_red_teaming, hardware_physical_access, oracle, mongodb, couchdb, legacy_protocols
        except ImportError as e:
            logger.warning(f"Some plugins failed to import: {e}")

        # Re-register event handlers for ALL plugins (in case EventBus was cleared)
        # This ensures handlers are set up even if plugins were already registered
        for plugin in cls._plugins.values():
            cls._setup_event_handlers(plugin)

        # Load alternative commands registry
        try:
            from ..alternatives.registry import AlternativeCommandRegistry
            AlternativeCommandRegistry.load_all()
            logger.info("Loaded alternative commands registry")
        except ImportError as e:
            logger.warning(f"Alternative commands registry not available: {e}")

        cls._initialized = True
        logger.info(f"Initialized {len(cls._plugins)} service plugins")

    @classmethod
    def clear(cls):
        """Clear resolution state but preserve registered plugins (for testing isolation)

        NOTE: We do NOT clear cls._plugins because plugin registration happens
        at module import time via @ServiceRegistry.register decorators. Once modules
        are imported, the plugins are registered and should persist across tests.
        Clearing _plugins would require re-importing modules, which doesn't work
        since Python caches imports in sys.modules.

        This method only clears:
        - _plugin_claims: Per-port plugin confidence scores
        - _resolved_ports: Set of ports that have been resolved
        - _initialized: Flag to allow re-initialization

        To fully reset for testing, use EventBus.clear() separately to clear event handlers.
        """
        cls._initialized = False
        if hasattr(cls, '_plugin_claims'):
            cls._plugin_claims.clear()
            delattr(cls, '_plugin_claims')
        if hasattr(cls, '_resolved_ports'):
            cls._resolved_ports.clear()
            delattr(cls, '_resolved_ports')

        # Clear finding-based tracking
        if hasattr(cls, '_finding_claims'):
            cls._finding_claims.clear()
            delattr(cls, '_finding_claims')
        if hasattr(cls, '_activated_findings'):
            cls._activated_findings.clear()
            delattr(cls, '_activated_findings')
        if hasattr(cls, '_resolved_findings'):
            cls._resolved_findings.clear()
            delattr(cls, '_resolved_findings')
        if hasattr(cls, '_finding_timers'):
            # Cancel all pending timers
            for timer in cls._finding_timers.values():
                timer.cancel()
            cls._finding_timers.clear()
            delattr(cls, '_finding_timers')
