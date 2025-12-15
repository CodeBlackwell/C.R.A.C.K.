"""
Session Management Module for CRACK

Provides comprehensive reverse shell and listener management for HTB Hard
targets and OSCP exam scenarios.

Core Components:
    - models: Session, Listener, ShellCapabilities data structures
    - interfaces: Abstract interfaces (ISessionManager, IListener, IStorage, IShellEnhancer)
    - events: EventBus and SessionEvent for reactive behaviors

Quick Start:
    >>> from crack.sessions import Session, Listener, ShellCapabilities
    >>> from crack.sessions import ISessionManager, IStorage, IShellEnhancer
    >>> from crack.sessions import EventBus, SessionEvent
    >>>
    >>> # Create a session
    >>> session = Session(
    ...     type='tcp',
    ...     protocol='reverse',
    ...     target='192.168.45.150',
    ...     port=4444,
    ...     shell_type='bash'
    ... )
    >>>
    >>> # Subscribe to events
    >>> def on_session_started(data):
    ...     print(f"New session: {data['session_id']}")
    >>>
    >>> EventBus.subscribe(SessionEvent.SESSION_STARTED, on_session_started)
    >>>
    >>> # Publish event
    >>> EventBus.publish(SessionEvent.SESSION_STARTED, {
    ...     'session_id': session.id,
    ...     'target': session.target,
    ...     'port': session.port
    ... })

Module Structure:
    sessions/
    ├── __init__.py          # Module initialization (this file)
    ├── models.py            # Data models (Session, Listener, ShellCapabilities)
    ├── interfaces.py        # Abstract interfaces (ISessionManager, IListener, etc.)
    └── events.py            # Event system (EventBus, SessionEvent)

Next Steps (Phase 2 Implementation):
    - manager.py: Concrete SessionManager implementation
    - listeners/: Listener implementations (netcat, socat, metasploit)
    - storage.py: JSON file-based storage implementation
    - enhancer.py: Shell upgrade and stabilization logic
    - cli.py: CLI commands (crack sessions list, crack listen, etc.)

Design Principles:
    - Interface-based design for testability and extensibility
    - Event-driven architecture for decoupled components
    - OSCP-focused: Emphasizes manual techniques and troubleshooting
    - Educational: Extensive documentation and examples
"""

# Core models
from .models import Session, Listener, ShellCapabilities

# Abstract interfaces
from .interfaces import (
    ISessionManager,
    IListener,
    IStorage,
    IShellEnhancer
)

# Event system
from .events import EventBus, SessionEvent

# Tunnel management
from . import tunnel

__all__ = [
    # Models
    'Session',
    'Listener',
    'ShellCapabilities',

    # Interfaces
    'ISessionManager',
    'IListener',
    'IStorage',
    'IShellEnhancer',

    # Events
    'EventBus',
    'SessionEvent',

    # Tunnel
    'tunnel',
]

__version__ = '0.1.0'
__author__ = 'CRACK Development Team'
