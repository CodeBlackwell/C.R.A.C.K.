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

    @classmethod
    def _handle_service_detected(cls, plugin: ServicePlugin, data: Dict[str, Any]):
        """Handle service detection event with conflict resolution

        Args:
            plugin: Service plugin
            data: Event data (target, port, service, version)
        """
        port_info = {
            'port': data.get('port'),
            'service': data.get('service'),
            'version': data.get('version'),
            'state': 'open'
        }

        # Check if plugin can handle this service (now returns confidence score)
        detection_result = plugin.detect(port_info)

        # Handle both old boolean and new confidence score formats
        if isinstance(detection_result, bool):
            confidence = 100 if detection_result else 0
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
