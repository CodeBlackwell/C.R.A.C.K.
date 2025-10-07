"""
Event Bus for decoupled component communication

Events:
    - port_discovered: {port, state, target}
    - service_detected: {port, service, version, target}
    - version_detected: {port, service, version, target}
    - task_added: {task, parent}
    - task_completed: {task}
    - phase_changed: {old_phase, new_phase}
    - finding_added: {finding}
"""

from collections import defaultdict
from typing import Callable, Dict, Any, List
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EventBus:
    """Simple event bus for decoupled component communication"""

    _handlers: Dict[str, List[Callable]] = defaultdict(list)
    _debug: bool = False

    @classmethod
    def on(cls, event_name: str, handler: Callable[[Dict[str, Any]], None]):
        """Register event handler

        Args:
            event_name: Name of event to listen for
            handler: Callable that receives event data dict
        """
        cls._handlers[event_name].append(handler)
        if cls._debug:
            logger.debug(f"Registered handler for '{event_name}': {handler.__name__}")

    @classmethod
    def emit(cls, event_name: str, data: Dict[str, Any] = None):
        """Emit event to all registered handlers

        Args:
            event_name: Name of event
            data: Event data dictionary
        """
        data = data or {}

        if cls._debug:
            logger.debug(f"Event '{event_name}' emitted with data: {data}")

        if event_name not in cls._handlers:
            return

        for handler in cls._handlers[event_name]:
            try:
                handler(data)
            except Exception as e:
                logger.error(f"Error in event handler {handler.__name__} for '{event_name}': {e}")

    @classmethod
    def clear(cls, event_name: str = None):
        """Clear handlers for specific event or all events

        Args:
            event_name: Event to clear handlers for (None = all events)
        """
        if event_name:
            cls._handlers[event_name].clear()
        else:
            cls._handlers.clear()

    @classmethod
    def set_debug(cls, enabled: bool):
        """Enable/disable debug logging"""
        cls._debug = enabled

    @classmethod
    def get_handlers(cls, event_name: str) -> List[Callable]:
        """Get list of handlers for event (mainly for testing)"""
        return cls._handlers.get(event_name, [])
