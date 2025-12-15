#!/usr/bin/env python3
"""
Session Management System - Usage Example

Demonstrates the core contracts, models, and event system for CRACK's
session management. This example shows typical usage patterns for
implementing session managers, listeners, and shell enhancers.

Run this example:
    python3 sessions/USAGE_EXAMPLE.py
"""

from crack.sessions import (
    Session,
    Listener,
    ShellCapabilities,
    EventBus,
    SessionEvent,
    ISessionManager,
    IListener,
    IStorage,
    IShellEnhancer
)
from typing import Dict, Any, List, Optional


def example_1_basic_session_lifecycle():
    """Example 1: Basic session creation and lifecycle management."""
    print("\n=== Example 1: Basic Session Lifecycle ===")

    # Create a new session
    session = Session(
        type='tcp',
        protocol='reverse',
        target='192.168.45.150',
        port=4444,
        shell_type='bash'
    )

    print(f"Created session: {session.id[:8]}...")
    print(f"  Target: {session.target}:{session.port}")
    print(f"  Status: {session.status}")
    print(f"  Active: {session.is_active()}")

    # Mark session as upgrading
    session.mark_upgrading()
    print(f"\nAfter upgrade start:")
    print(f"  Status: {session.status}")
    print(f"  Active: {session.is_active()}")

    # Mark session as active again
    session.mark_active()
    print(f"\nAfter upgrade complete:")
    print(f"  Status: {session.status}")

    # Serialize and deserialize
    session_data = session.to_dict()
    restored_session = Session.from_dict(session_data)
    print(f"\nSerialization successful:")
    print(f"  Original ID: {session.id}")
    print(f"  Restored ID: {restored_session.id}")
    print(f"  IDs match: {session.id == restored_session.id}")


def example_2_shell_capabilities():
    """Example 2: Shell capability detection and tracking."""
    print("\n=== Example 2: Shell Capabilities ===")

    # Create session with basic shell
    session = Session(
        type='tcp',
        target='192.168.45.150',
        port=4444
    )

    print(f"Initial capabilities:")
    print(f"  PTY: {session.capabilities.has_pty}")
    print(f"  History: {session.capabilities.has_history}")
    print(f"  Tab completion: {session.capabilities.has_tab_completion}")

    # Simulate capability detection
    detected_caps = ShellCapabilities(
        has_pty=False,
        has_history=False,
        has_tab_completion=False,
        shell_type='bash',
        detected_tools=['python3', 'script', 'socat'],
        os_type='linux'
    )

    session.capabilities = detected_caps
    print(f"\nAfter detection:")
    print(f"  Shell type: {session.capabilities.shell_type}")
    print(f"  OS type: {session.capabilities.os_type}")
    print(f"  Available tools: {', '.join(session.capabilities.detected_tools)}")

    # Simulate PTY upgrade
    upgraded_caps = ShellCapabilities(
        has_pty=True,
        has_history=True,
        has_tab_completion=True,
        shell_type='bash',
        detected_tools=['python3', 'script', 'socat'],
        os_type='linux'
    )

    session.capabilities = upgraded_caps
    session.metadata['upgrade_method'] = 'python-pty'

    print(f"\nAfter PTY upgrade:")
    print(f"  PTY: {session.capabilities.has_pty}")
    print(f"  History: {session.capabilities.has_history}")
    print(f"  Upgrade method: {session.metadata['upgrade_method']}")


def example_3_listener_management():
    """Example 3: Listener lifecycle and session tracking."""
    print("\n=== Example 3: Listener Management ===")

    # Create listener
    listener = Listener(
        protocol='tcp',
        port=4444,
        config={
            'tool': 'netcat',
            'command': 'nc -nlvp 4444',
            'auto_upgrade': True
        }
    )

    print(f"Listener ID: {listener.id[:8]}...")
    print(f"  Protocol: {listener.protocol}")
    print(f"  Port: {listener.port}")
    print(f"  Status: {listener.status}")
    print(f"  Running: {listener.is_running()}")

    # Start listener
    listener.start()
    listener.pid = 12345  # Simulated PID
    print(f"\nAfter start:")
    print(f"  Status: {listener.status}")
    print(f"  Running: {listener.is_running()}")
    print(f"  PID: {listener.pid}")

    # Add sessions
    listener.add_session('session-123')
    listener.add_session('session-456')
    print(f"\nActive sessions: {len(listener.session_ids)}")
    for sid in listener.session_ids:
        print(f"  - {sid}")

    # Remove session
    listener.remove_session('session-123')
    print(f"\nAfter disconnect:")
    print(f"  Active sessions: {len(listener.session_ids)}")

    # Stop listener
    listener.stop()
    print(f"\nAfter stop:")
    print(f"  Status: {listener.status}")
    print(f"  Running: {listener.is_running()}")


def example_4_event_system():
    """Example 4: Event-driven architecture with EventBus."""
    print("\n=== Example 4: Event System ===")

    # Define event handlers
    def on_session_started(data: Dict[str, Any]):
        print(f"  [EVENT] Session started: {data['session_id'][:8]}... to {data['target']}:{data['port']}")

    def on_session_upgraded(data: Dict[str, Any]):
        print(f"  [EVENT] Session upgraded: {data['session_id'][:8]}... using {data['method']}")

    def on_session_died(data: Dict[str, Any]):
        print(f"  [EVENT] Session died: {data['session_id'][:8]}... reason: {data.get('reason', 'unknown')}")

    def on_listener_started(data: Dict[str, Any]):
        print(f"  [EVENT] Listener started on port {data['port']}")

    # Subscribe handlers
    EventBus.subscribe(SessionEvent.SESSION_STARTED, on_session_started)
    EventBus.subscribe(SessionEvent.SESSION_UPGRADED, on_session_upgraded)
    EventBus.subscribe(SessionEvent.SESSION_DIED, on_session_died)
    EventBus.subscribe(SessionEvent.LISTENER_STARTED, on_listener_started)

    print("Subscribed to events\n")

    # Simulate session lifecycle
    session = Session(type='tcp', target='192.168.45.150', port=4444)

    # 1. Session starts
    EventBus.publish(SessionEvent.SESSION_STARTED, {
        'session_id': session.id,
        'target': session.target,
        'port': session.port,
        'type': session.type
    })

    # 2. Session upgraded
    EventBus.publish(SessionEvent.SESSION_UPGRADED, {
        'session_id': session.id,
        'method': 'python-pty'
    })

    # 3. Session dies
    EventBus.publish(SessionEvent.SESSION_DIED, {
        'session_id': session.id,
        'reason': 'connection_lost'
    })

    # 4. Listener event
    EventBus.publish(SessionEvent.LISTENER_STARTED, {
        'listener_id': 'listener-123',
        'port': 4444,
        'protocol': 'tcp'
    })

    # Cleanup
    EventBus.reset()
    print("\nEvent bus reset")


def example_5_interface_contracts():
    """Example 5: Understanding the interface contracts."""
    print("\n=== Example 5: Interface Contracts ===")

    print("ISessionManager interface provides:")
    print("  - create_session(type, target, port, **kwargs) -> Session")
    print("  - list_sessions(filters: Dict) -> List[Session]")
    print("  - get_session(id: str) -> Optional[Session]")
    print("  - update_session(id: str, updates: Dict) -> Session")
    print("  - kill_session(id: str) -> bool")
    print("  - cleanup_dead_sessions() -> int")

    print("\nIListener interface provides:")
    print("  - start() -> bool")
    print("  - stop() -> bool")
    print("  - restart() -> bool")
    print("  - status() -> str")
    print("  - on_connection(callback: Callable) -> None")
    print("  - get_active_sessions() -> List[str]")

    print("\nIStorage interface provides:")
    print("  - save_session(session: Session) -> bool")
    print("  - load_session(id: str) -> Optional[Session]")
    print("  - delete_session(id: str) -> bool")
    print("  - query_sessions(filters: Dict) -> List[Session]")
    print("  - save_listener(listener: Listener) -> bool")
    print("  - load_listener(id: str) -> Optional[Listener]")

    print("\nIShellEnhancer interface provides:")
    print("  - detect_capabilities(session: Session) -> ShellCapabilities")
    print("  - upgrade_shell(session: Session, method: str) -> bool")
    print("  - stabilize_shell(session: Session) -> bool")
    print("  - validate_upgrade(session: Session) -> bool")


def example_6_realistic_workflow():
    """Example 6: Realistic reverse shell workflow."""
    print("\n=== Example 6: Realistic Reverse Shell Workflow ===")

    # Step 1: Start listener
    print("Step 1: Starting listener on port 4444")
    listener = Listener(
        protocol='tcp',
        port=4444,
        config={'tool': 'netcat', 'auto_upgrade': True}
    )
    listener.start()
    listener.pid = 12345

    # Step 2: Receive connection
    print("\nStep 2: Receiving reverse shell connection")
    session = Session(
        type='tcp',
        protocol='reverse',
        target='192.168.45.150',
        port=4444,
        metadata={'listener_id': listener.id}
    )
    listener.add_session(session.id)

    EventBus.publish(SessionEvent.SESSION_STARTED, {
        'session_id': session.id,
        'target': session.target,
        'port': session.port
    })

    # Step 3: Detect capabilities
    print("\nStep 3: Detecting shell capabilities")
    session.capabilities = ShellCapabilities(
        has_pty=False,
        shell_type='bash',
        detected_tools=['python3', 'script'],
        os_type='linux'
    )
    print(f"  Shell: {session.capabilities.shell_type}")
    print(f"  Tools: {', '.join(session.capabilities.detected_tools)}")

    # Step 4: Upgrade shell
    print("\nStep 4: Upgrading shell with Python PTY")
    session.mark_upgrading()
    # Simulate upgrade process...
    session.capabilities = ShellCapabilities(
        has_pty=True,
        has_history=True,
        has_tab_completion=True,
        shell_type='bash',
        detected_tools=['python3', 'script'],
        os_type='linux'
    )
    session.mark_active()
    session.metadata['upgrade_method'] = 'python-pty'

    EventBus.publish(SessionEvent.SESSION_UPGRADED, {
        'session_id': session.id,
        'method': 'python-pty'
    })

    # Step 5: Stabilize shell
    print("\nStep 5: Stabilizing shell (stty raw -echo)")
    session.metadata['stabilized'] = True

    EventBus.publish(SessionEvent.SESSION_STABILIZED, {
        'session_id': session.id
    })

    # Step 6: Session summary
    print("\nSession Summary:")
    print(f"  ID: {session.id[:8]}...")
    print(f"  Target: {session.target}:{session.port}")
    print(f"  Status: {session.status}")
    print(f"  PTY: {session.capabilities.has_pty}")
    print(f"  Upgrade method: {session.metadata.get('upgrade_method', 'None')}")
    print(f"  Stabilized: {session.metadata.get('stabilized', False)}")

    # Cleanup
    EventBus.reset()


def main():
    """Run all examples."""
    print("="*70)
    print("CRACK Session Management System - Usage Examples")
    print("="*70)

    example_1_basic_session_lifecycle()
    example_2_shell_capabilities()
    example_3_listener_management()
    example_4_event_system()
    example_5_interface_contracts()
    example_6_realistic_workflow()

    print("\n" + "="*70)
    print("All examples completed successfully!")
    print("="*70)


if __name__ == '__main__':
    main()
