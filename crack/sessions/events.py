"""
Event system for session management.

Provides:
- SessionEvent: Event type enumeration
- EventBus: Thread-safe event bus for session lifecycle events

Events are used to decouple components and enable reactive behaviors
(e.g., auto-upgrade on connection, logging, UI updates).
"""

from enum import Enum, auto
from collections import defaultdict
from typing import Callable, Dict, Any, List
import threading
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SessionEvent(Enum):
    """Session lifecycle event types.

    Events emitted during session and listener lifecycle:
    - SESSION_STARTED: New session created (data: {session_id, target, port})
    - SESSION_DIED: Session connection lost (data: {session_id, reason})
    - SESSION_UPGRADED: Shell upgraded successfully (data: {session_id, method})
    - SESSION_STABILIZED: Shell stabilized post-upgrade (data: {session_id})
    - LISTENER_STARTED: Listener process started (data: {listener_id, port})
    - LISTENER_STOPPED: Listener stopped gracefully (data: {listener_id})
    - LISTENER_CRASHED: Listener crashed unexpectedly (data: {listener_id, error})

    Example:
        >>> EventBus.subscribe(SessionEvent.SESSION_STARTED, handle_new_session)
        >>> EventBus.publish(SessionEvent.SESSION_STARTED, {
        ...     'session_id': 'abc123',
        ...     'target': '192.168.45.150',
        ...     'port': 4444
        ... })
    """
    SESSION_STARTED = auto()
    SESSION_DIED = auto()
    SESSION_UPGRADED = auto()
    SESSION_STABILIZED = auto()
    LISTENER_STARTED = auto()
    LISTENER_STOPPED = auto()
    LISTENER_CRASHED = auto()


class EventBus:
    """Thread-safe event bus for session management events.

    Singleton pattern ensures all components use the same event bus instance.
    Supports subscribing/unsubscribing handlers and publishing events with
    thread-safe execution.

    Thread Safety:
        All operations (subscribe, unsubscribe, publish) are protected by a
        lock to ensure safe concurrent access from multiple threads.

    Example:
        >>> def on_session_started(data: Dict[str, Any]):
        ...     session_id = data.get('session_id')
        ...     print(f"New session: {session_id}")
        ...     # Auto-upgrade new sessions
        ...     session = manager.get_session(session_id)
        ...     enhancer.detect_capabilities(session)
        ...
        >>> # Subscribe handler
        >>> EventBus.subscribe(SessionEvent.SESSION_STARTED, on_session_started)
        >>>
        >>> # Publish event (from SessionManager)
        >>> EventBus.publish(SessionEvent.SESSION_STARTED, {
        ...     'session_id': session.id,
        ...     'target': session.target,
        ...     'port': session.port
        ... })
        >>>
        >>> # Unsubscribe when done
        >>> EventBus.unsubscribe(SessionEvent.SESSION_STARTED, on_session_started)
    """

    _instance = None
    _lock = threading.Lock()
    _handlers: Dict[SessionEvent, List[Callable]] = defaultdict(list)
    _debug: bool = False

    def __new__(cls):
        """Singleton pattern - always return same instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(EventBus, cls).__new__(cls)
        return cls._instance

    @classmethod
    def subscribe(cls, event_type: SessionEvent, callback: Callable[[Dict[str, Any]], None]):
        """Subscribe to event type.

        Args:
            event_type: SessionEvent enum value
            callback: Function to call when event published. Receives event data dict.

        Thread Safety:
            Protected by lock during handler registration

        Example:
            >>> def handle_session_died(data):
            ...     session_id = data.get('session_id')
            ...     reason = data.get('reason', 'unknown')
            ...     logger.warning(f"Session {session_id} died: {reason}")
            ...
            >>> EventBus.subscribe(SessionEvent.SESSION_DIED, handle_session_died)
        """
        with cls._lock:
            cls._handlers[event_type].append(callback)
            if cls._debug:
                logger.debug(f"Subscribed handler {callback.__name__} to {event_type.name}")

    @classmethod
    def unsubscribe(cls, event_type: SessionEvent, callback: Callable[[Dict[str, Any]], None]):
        """Unsubscribe from event type.

        Args:
            event_type: SessionEvent enum value
            callback: Handler function to remove

        Thread Safety:
            Protected by lock during handler removal

        Example:
            >>> EventBus.unsubscribe(SessionEvent.SESSION_STARTED, on_session_started)
        """
        with cls._lock:
            if callback in cls._handlers[event_type]:
                cls._handlers[event_type].remove(callback)
                if cls._debug:
                    logger.debug(f"Unsubscribed handler {callback.__name__} from {event_type.name}")

    @classmethod
    def publish(cls, event_type: SessionEvent, data: Dict[str, Any] = None):
        """Publish event to all subscribed handlers.

        Calls all registered handlers for the event type with provided data.
        Handlers are called synchronously in registration order. Exceptions
        in handlers are caught and logged without affecting other handlers.

        Args:
            event_type: SessionEvent enum value
            data: Event data dictionary (optional)

        Thread Safety:
            Handlers list is copied under lock before execution to allow
            safe concurrent subscription/unsubscription during event handling

        Example:
            >>> # From SessionManager.create_session()
            >>> EventBus.publish(SessionEvent.SESSION_STARTED, {
            ...     'session_id': session.id,
            ...     'target': session.target,
            ...     'port': session.port,
            ...     'type': session.type,
            ...     'protocol': session.protocol
            ... })
            >>>
            >>> # From ShellEnhancer.upgrade_shell()
            >>> EventBus.publish(SessionEvent.SESSION_UPGRADED, {
            ...     'session_id': session.id,
            ...     'method': 'python-pty',
            ...     'capabilities': session.capabilities.to_dict()
            ... })
        """
        data = data or {}

        if cls._debug:
            logger.debug(f"Publishing {event_type.name} with data: {data}")

        # Copy handlers list under lock to allow safe concurrent modification
        with cls._lock:
            handlers = cls._handlers[event_type].copy()

        # Execute handlers outside lock to avoid deadlock
        for handler in handlers:
            try:
                handler(data)
            except Exception as e:
                logger.error(f"Error in event handler {handler.__name__} for {event_type.name}: {e}")

    @classmethod
    def clear(cls, event_type: SessionEvent = None):
        """Clear handlers for specific event or all events.

        Args:
            event_type: Event to clear handlers for (None = clear all)

        Thread Safety:
            Protected by lock during handler clearing

        Example:
            >>> # Clear specific event handlers
            >>> EventBus.clear(SessionEvent.SESSION_STARTED)
            >>>
            >>> # Clear all handlers (useful for testing)
            >>> EventBus.clear()
        """
        with cls._lock:
            if event_type:
                cls._handlers[event_type].clear()
                if cls._debug:
                    logger.debug(f"Cleared handlers for {event_type.name}")
            else:
                cls._handlers.clear()
                if cls._debug:
                    logger.debug("Cleared all event handlers")

    @classmethod
    def set_debug(cls, enabled: bool):
        """Enable/disable debug logging.

        Args:
            enabled: True to enable debug logs, False to disable

        Example:
            >>> EventBus.set_debug(True)
            >>> EventBus.publish(SessionEvent.SESSION_STARTED, {'session_id': '123'})
            # Logs: "Publishing SESSION_STARTED with data: {'session_id': '123'}"
        """
        cls._debug = enabled

    @classmethod
    def get_handlers(cls, event_type: SessionEvent) -> List[Callable]:
        """Get list of handlers for event type.

        Mainly used for testing and debugging.

        Args:
            event_type: SessionEvent enum value

        Returns:
            List of handler functions (copy, not live reference)

        Thread Safety:
            Protected by lock during handler list access

        Example:
            >>> handlers = EventBus.get_handlers(SessionEvent.SESSION_STARTED)
            >>> print(f"Registered handlers: {len(handlers)}")
        """
        with cls._lock:
            return cls._handlers[event_type].copy()

    @classmethod
    def reset(cls):
        """Reset event bus to initial state.

        Clears all handlers and debug state. Useful for testing.

        Thread Safety:
            Protected by lock during reset

        Example:
            >>> # In test teardown
            >>> EventBus.reset()
        """
        with cls._lock:
            cls._handlers.clear()
            cls._debug = False
            if cls._debug:
                logger.debug("Event bus reset")
