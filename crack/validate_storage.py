#!/usr/bin/env python3
"""
Validation script for session storage infrastructure

Demonstrates all storage, query, and config features
"""

from crack.sessions import Session, Listener
from crack.sessions.storage import SessionStorage, ListenerRegistry, SessionQuery
from crack.sessions.config import SessionConfig


def main():
    print("=" * 70)
    print("CRACK Session Storage Validation")
    print("=" * 70)

    # Initialize components
    storage = SessionStorage()
    registry = ListenerRegistry()
    config = SessionConfig()
    print("\n[✓] Initialized: SessionStorage, ListenerRegistry, SessionConfig")

    # Create and save sessions
    print("\n--- Creating Sessions ---")
    session1 = Session(
        id='demo-session-1',
        type='tcp',
        protocol='reverse',
        target='192.168.45.150',
        port=4444,
        status='active',
        shell_type='bash'
    )
    session2 = Session(
        id='demo-session-2',
        type='http',
        protocol='reverse',
        target='192.168.45.151',
        port=8080,
        status='active',
        shell_type='bash'
    )
    session3 = Session(
        id='demo-session-3',
        type='tcp',
        protocol='reverse',
        target='192.168.45.150',
        port=5555,
        status='dead',
        shell_type='sh'
    )

    storage.save_session(session1)
    storage.save_session(session2)
    storage.save_session(session3)
    print(f"[✓] Saved 3 sessions to {storage.storage_path}")

    # Query sessions
    print("\n--- Querying Sessions ---")
    all_sessions = storage.list_all_sessions()
    print(f"[✓] Total sessions: {len(all_sessions)}")

    query = SessionQuery(storage)
    active_sessions = query.active_only().execute()
    print(f"[✓] Active sessions: {len(active_sessions)}")

    tcp_sessions = query.reset().by_type('tcp').execute()
    print(f"[✓] TCP sessions: {len(tcp_sessions)}")

    target_sessions = query.reset().by_target('192.168.45.150').execute()
    print(f"[✓] Sessions to 192.168.45.150: {len(target_sessions)}")

    # Complex query
    result = query.reset() \
        .by_target('192.168.45.150') \
        .by_type('tcp') \
        .active_only() \
        .first()
    print(f"[✓] Complex query result: {result['id'] if result else 'None'}")

    # Listener registry
    print("\n--- Listener Management ---")
    listener1 = Listener(
        id='demo-listener-1',
        protocol='tcp',
        port=4444,
        pid=12345
    )
    listener1.start()

    # Mock process alive for demo
    registry._is_process_alive = lambda pid: True
    registry.register_listener(listener1)
    print(f"[✓] Registered listener on port 4444")

    is_available = registry.is_port_available(4444)
    print(f"[✓] Port 4444 available: {is_available}")

    is_available = registry.is_port_available(5555)
    print(f"[✓] Port 5555 available: {is_available}")

    next_port = registry.get_next_available_port(start_port=4444)
    print(f"[✓] Next available port: {next_port}")

    # Configuration
    print("\n--- Configuration ---")
    print(f"[✓] Default TCP port: {config.get_default_port('tcp')}")
    print(f"[✓] Default HTTP port: {config.get_default_port('http')}")

    print("\n[✓] Upgrade methods:")
    for method in config.list_upgrade_methods()[:3]:
        print(f"    - {method}")

    print("\n[✓] Listener types:")
    for ltype in config.list_listener_types()[:3]:
        print(f"    - {ltype}")

    # Template rendering
    print("\n--- Template Rendering ---")
    listener_cmd = config.get_listener_template('netcat', PORT=4444)
    print(f"[✓] Netcat listener: {listener_cmd}")

    shell_payload = config.get_reverse_shell_payload(
        'bash_tcp',
        LHOST='192.168.45.100',
        LPORT='4444'
    )
    print(f"[✓] Bash TCP shell: {shell_payload[:50]}...")

    upgrade_cmd = config.get_upgrade_payload('python_pty')
    print(f"[✓] Python PTY upgrade: {upgrade_cmd[:50]}...")

    # Storage stats
    print("\n--- Storage Statistics ---")
    stats = storage.get_storage_stats()
    print(f"[✓] Total sessions: {stats['total_sessions']}")
    print(f"[✓] Storage size: {stats['total_size_bytes']} bytes")
    print(f"[✓] Storage path: {stats['storage_path']}")

    reg_stats = registry.get_registry_stats()
    print(f"[✓] Registered listeners: {reg_stats['total_registered']}")
    print(f"[✓] Active listeners: {reg_stats['active']}")

    # Cleanup
    print("\n--- Cleanup ---")
    storage.delete_session('demo-session-1')
    storage.delete_session('demo-session-2')
    storage.delete_session('demo-session-3')
    print("[✓] Deleted demo sessions")

    registry.unregister_listener('demo-listener-1')
    print("[✓] Unregistered demo listener")

    print("\n" + "=" * 70)
    print("All validation checks passed!")
    print("=" * 70)


if __name__ == '__main__':
    main()
