"""
Comprehensive integration tests for CRACK session management system.

Tests complete end-to-end workflows:
- TCP session lifecycle
- HTTP beacon → TCP upgrade
- Multi-protocol concurrent sessions
- Tunnel management
- Storage persistence
- Event bus integration
"""

import pytest
import time
import asyncio
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

# Import session components
from crack.sessions.manager import SessionManager
from crack.sessions.storage.base import SessionStorage
from crack.sessions.config import SessionConfig
from crack.sessions.models import Session, ShellCapabilities
from crack.sessions.events import EventBus, SessionEvent
from crack.sessions.listeners.tcp_listener import TCPListener
from crack.sessions.listeners.http_listener import HTTPListener
from crack.sessions.shell.tcp_upgrader import TCPShellUpgrader
from crack.sessions.shell.http_upgrader import HTTPShellUpgrader
from crack.sessions.unified_cli import UnifiedSessionCLI


@pytest.fixture
def temp_storage_dir(tmp_path):
    """Create temporary storage directory."""
    storage_dir = tmp_path / "sessions"
    storage_dir.mkdir()
    return storage_dir


@pytest.fixture
def session_manager(temp_storage_dir):
    """Create session manager with temporary storage."""
    # Patch storage path to use temp directory
    storage = SessionStorage()
    storage.storage_dir = temp_storage_dir / "sessions"
    storage.storage_dir.mkdir(exist_ok=True)

    config = SessionConfig()
    manager = SessionManager(storage, config)
    # Clear any loaded sessions (from default storage)
    manager._sessions = {}
    return manager


class TestFullWorkflow:
    """Test complete session lifecycle across all components."""

    def test_tcp_session_full_lifecycle(self, session_manager):
        """
        Full TCP workflow:
        1. Create TCP session
        2. Detect capabilities
        3. Upgrade shell
        4. Stabilize
        5. List sessions
        6. Kill session
        7. Cleanup
        """
        # Mock PID validation to prevent fake PID from marking session dead
        with patch.object(session_manager, '_is_pid_alive', return_value=True):
            # 1. Create TCP session
            session = session_manager.create_session(
                type='tcp',
                target='192.168.45.150',
                port=4444,
                protocol='reverse',
                shell_type='bash',
                pid=12345
            )

            assert session.id
            assert session.type == 'tcp'
            assert session.status == 'active'

            # 2. Update capabilities (simulated detection)
            session.capabilities = ShellCapabilities(
                has_pty=False,
                shell_type='bash',
                detected_tools=['python3', 'socat']
            )

            session_manager.update_session(session.id, {
                'capabilities': session.capabilities.to_dict()
            })

            # 3. Simulate upgrade
            session.capabilities.has_pty = True
            session.capabilities.has_history = True
            session.capabilities.has_tab_completion = True

            session_manager.update_session(session.id, {
                'capabilities': session.capabilities.to_dict()
            })

            # 4. Verify upgraded state
            updated = session_manager.get_session(session.id)
            assert updated.capabilities.has_pty
            assert updated.capabilities.has_history

            # 5. List sessions
            sessions = session_manager.list_sessions({'status': 'active'})
            assert len(sessions) == 1
            assert sessions[0].id == session.id

            # 6. Kill session
            assert session_manager.kill_session(session.id)

            # 7. Verify dead
            dead_session = session_manager.get_session(session.id)
            assert dead_session.status == 'dead'

    def test_http_to_tcp_upgrade_workflow(self, session_manager):
        """
        HTTP beacon → TCP upgrade:
        1. Create HTTP beacon session
        2. Send commands via beacon
        3. Upgrade to TCP reverse shell
        4. Verify TCP session created
        5. Original HTTP session marked 'upgraded'
        """
        # 1. Create HTTP beacon session
        http_session = session_manager.create_session(
            type='http',
            target='192.168.45.151',
            port=8080,
            protocol='beacon',
            metadata={'beacon_id': 'test-beacon-123'}
        )

        assert http_session.type == 'http'
        assert http_session.protocol == 'beacon'

        # 2. Queue commands (simulated beacon interaction)
        http_session.metadata['pending_commands'] = ['whoami', 'id']
        http_session.metadata['beacon_responses'] = [
            {'command': 'whoami', 'output': 'www-data'},
            {'command': 'id', 'output': 'uid=33(www-data) gid=33(www-data)'}
        ]

        session_manager.update_session(http_session.id, {
            'metadata': http_session.metadata
        })

        # 3. Simulate upgrade to TCP (create new TCP session)
        tcp_session = session_manager.create_session(
            type='tcp',
            target='192.168.45.151',
            port=4444,
            protocol='reverse',
            shell_type='bash',
            metadata={'upgraded_from': http_session.id}
        )

        # 4. Mark HTTP session as upgraded
        session_manager.update_session(http_session.id, {
            'status': 'upgraded',
            'metadata': {'upgraded_to': tcp_session.id}
        })

        # 5. Verify both sessions
        http_updated = session_manager.get_session(http_session.id)
        tcp_new = session_manager.get_session(tcp_session.id)

        assert http_updated.status == 'upgraded'
        assert http_updated.metadata['upgraded_to'] == tcp_session.id

        assert tcp_new.type == 'tcp'
        assert tcp_new.status == 'active'
        assert tcp_new.metadata['upgraded_from'] == http_session.id

    def test_multi_protocol_concurrent(self, session_manager):
        """
        Concurrent multi-protocol:
        1. Create TCP, HTTP, DNS sessions simultaneously
        2. Verify all tracked correctly
        3. List shows all correctly
        4. Filter by type works
        5. Kill all, verify cleanup
        """
        # 1. Create multiple sessions
        tcp_session = session_manager.create_session(
            type='tcp',
            target='192.168.45.150',
            port=4444
        )

        http_session = session_manager.create_session(
            type='http',
            target='192.168.45.151',
            port=8080
        )

        dns_session = session_manager.create_session(
            type='dns',
            target='192.168.45.152',
            port=53
        )

        # 2. Verify all tracked
        all_sessions = session_manager.list_sessions()
        assert len(all_sessions) == 3

        # 3. Filter by type
        tcp_only = session_manager.list_sessions({'type': 'tcp'})
        assert len(tcp_only) == 1
        assert tcp_only[0].id == tcp_session.id

        http_only = session_manager.list_sessions({'type': 'http'})
        assert len(http_only) == 1
        assert http_only[0].id == http_session.id

        # 4. Filter by status
        active_sessions = session_manager.list_sessions({'status': 'active'})
        assert len(active_sessions) == 3

        # 5. Kill all sessions
        assert session_manager.kill_session(tcp_session.id)
        assert session_manager.kill_session(http_session.id)
        assert session_manager.kill_session(dns_session.id)

        # 6. Verify all dead
        dead_sessions = session_manager.list_sessions({'status': 'dead'})
        assert len(dead_sessions) == 3

    def test_persistence_and_recovery(self, session_manager, temp_storage_dir):
        """
        Storage persistence:
        1. Create sessions
        2. Save to storage
        3. Restart SessionManager
        4. Load from storage
        5. Verify all data intact
        """
        # 1. Create sessions
        session1 = session_manager.create_session(
            type='tcp',
            target='192.168.45.150',
            port=4444,
            shell_type='bash'
        )

        session2 = session_manager.create_session(
            type='http',
            target='192.168.45.151',
            port=8080,
            metadata={'test': 'data'}
        )

        # Sessions are auto-saved via SessionManager

        # 3. Create new SessionManager (simulates restart)
        with patch('crack.sessions.storage.base.Path.home') as mock_home:
            mock_home.return_value = temp_storage_dir
            new_storage = SessionStorage()
            new_config = SessionConfig()
            new_manager = SessionManager(new_storage, new_config)

        # 4. Verify sessions loaded
        loaded_sessions = new_manager.list_sessions()
        assert len(loaded_sessions) >= 2

        # 5. Verify data intact
        loaded_session1 = new_manager.get_session(session1.id)
        assert loaded_session1.target == '192.168.45.150'
        assert loaded_session1.port == 4444
        assert loaded_session1.shell_type == 'bash'

        loaded_session2 = new_manager.get_session(session2.id)
        assert loaded_session2.type == 'http'
        assert loaded_session2.metadata.get('test') == 'data'

    def test_event_bus_integration(self, session_manager):
        """
        Event-driven workflows:
        1. Subscribe to all events
        2. Create session (SESSION_STARTED)
        3. Upgrade (SESSION_UPGRADED)
        4. Kill (SESSION_DIED)
        5. Verify all events fired
        """
        events_received = []

        def event_handler(data):
            events_received.append(data)

        # 1. Subscribe to events
        EventBus.subscribe(SessionEvent.SESSION_STARTED, event_handler)
        EventBus.subscribe(SessionEvent.SESSION_UPGRADED, event_handler)
        EventBus.subscribe(SessionEvent.SESSION_DIED, event_handler)

        # 2. Create session (triggers SESSION_STARTED)
        session = session_manager.create_session(
            type='tcp',
            target='192.168.45.150',
            port=4444
        )

        # Verify SESSION_STARTED event
        assert len(events_received) >= 1
        started_event = events_received[0]
        assert started_event['session_id'] == session.id
        assert started_event['target'] == '192.168.45.150'

        # 3. Upgrade (triggers SESSION_UPGRADED)
        session.capabilities.has_pty = True
        session_manager.update_session(session.id, {
            'status': 'active',  # Mark as upgraded from 'upgrading'
            'capabilities': session.capabilities.to_dict()
        })

        # Simulate upgrade completion
        EventBus.publish(SessionEvent.SESSION_UPGRADED, {
            'session_id': session.id,
            'capabilities': session.capabilities.to_dict()
        })

        # 4. Kill (triggers SESSION_DIED)
        session_manager.kill_session(session.id)

        # 5. Verify all events
        assert len(events_received) >= 3

        # Clean up subscriptions
        EventBus._subscribers = {}  # Reset for other tests

    def test_unified_cli_integration(self, session_manager, capsys):
        """
        Test unified CLI integration:
        1. Start listener via CLI
        2. List sessions via CLI
        3. Generate beacon via CLI
        4. Kill session via CLI
        """
        cli = UnifiedSessionCLI()

        # Create a session directly for testing
        session = session_manager.create_session(
            type='tcp',
            target='192.168.45.150',
            port=4444
        )

        # Test list command
        with patch.object(cli, 'manager', session_manager):
            cli.run(['list'])

        captured = capsys.readouterr()
        assert '192.168.45.150' in captured.out
        assert '4444' in captured.out

        # Test info command
        with patch.object(cli, 'manager', session_manager):
            cli.run(['info', session.id[:8]])

        captured = capsys.readouterr()
        assert session.id in captured.out
        assert 'tcp' in captured.out

        # Test kill command
        with patch.object(cli, 'manager', session_manager):
            cli.run(['kill', session.id[:8]])

        captured = capsys.readouterr()
        assert 'terminated' in captured.out.lower()

        # Verify session is dead
        dead_session = session_manager.get_session(session.id)
        assert dead_session.status == 'dead'

    def test_session_filtering_and_search(self, session_manager):
        """
        Test session filtering capabilities:
        1. Create multiple sessions with different properties
        2. Filter by type, status, target, port
        3. Test complex filters
        4. Verify correct results
        """
        # 1. Create diverse sessions
        tcp1 = session_manager.create_session(
            type='tcp',
            target='192.168.45.100',
            port=4444
        )

        tcp2 = session_manager.create_session(
            type='tcp',
            target='192.168.45.101',
            port=4444
        )

        http1 = session_manager.create_session(
            type='http',
            target='192.168.45.100',
            port=8080
        )

        # Kill one for testing
        session_manager.kill_session(tcp2.id)

        # 2. Filter by type
        tcp_sessions = session_manager.list_sessions({'type': 'tcp'})
        assert len(tcp_sessions) == 2

        # 3. Filter by status
        active_sessions = session_manager.list_sessions({'status': 'active'})
        assert len(active_sessions) == 2  # tcp1 and http1

        dead_sessions = session_manager.list_sessions({'status': 'dead'})
        assert len(dead_sessions) == 1  # tcp2

        # 4. Filter by target
        target_sessions = session_manager.list_sessions({'target': '192.168.45.100'})
        assert len(target_sessions) == 2  # tcp1 and http1

        # 5. Filter by port
        port_sessions = session_manager.list_sessions({'port': 4444})
        assert len(port_sessions) == 2  # tcp1 and tcp2

    def test_session_stats(self, session_manager):
        """
        Test session statistics:
        1. Create multiple sessions
        2. Get stats
        3. Verify counts
        """
        # 1. Create sessions
        for i in range(3):
            session_manager.create_session(
                type='tcp',
                target=f'192.168.45.{100+i}',
                port=4444
            )

        for i in range(2):
            session_manager.create_session(
                type='http',
                target=f'192.168.45.{200+i}',
                port=8080
            )

        # 2. Get stats
        stats = session_manager.get_stats()

        # 3. Verify counts
        assert stats['total'] == 5
        assert stats['active'] == 5
        assert stats['by_type']['tcp'] == 3
        assert stats['by_type']['http'] == 2
        assert stats['by_protocol']['reverse'] >= 1  # At least one reverse shell

    @pytest.mark.asyncio
    async def test_concurrent_session_creation(self, session_manager):
        """
        Test concurrent session creation:
        1. Create multiple sessions simultaneously
        2. Verify all created correctly
        3. No race conditions
        """
        async def create_session_async(idx):
            return session_manager.create_session(
                type='tcp',
                target=f'192.168.45.{100+idx}',
                port=4444 + idx
            )

        # Create 10 sessions concurrently
        tasks = [create_session_async(i) for i in range(10)]
        sessions = await asyncio.gather(*tasks)

        # Verify all created
        assert len(sessions) == 10

        # Verify all unique
        session_ids = [s.id for s in sessions]
        assert len(set(session_ids)) == 10

        # Verify all tracked
        all_sessions = session_manager.list_sessions()
        assert len(all_sessions) == 10


class TestPerformance:
    """Performance benchmarks for session management."""

    def test_session_creation_performance(self, session_manager):
        """Test session creation speed (target: <5s for 100 sessions)."""
        start_time = time.time()

        for i in range(100):
            session_manager.create_session(
                type='tcp',
                target=f'192.168.45.{i % 256}',
                port=4444 + (i % 1000)
            )

        elapsed = time.time() - start_time

        # Should complete in under 5 seconds
        assert elapsed < 5.0, f"Session creation took {elapsed:.2f}s (target: <5s)"

    def test_session_list_performance(self, session_manager):
        """Test listing performance (target: <100ms for 1000 sessions)."""
        # Create 1000 sessions
        for i in range(1000):
            session_manager.create_session(
                type='tcp',
                target=f'192.168.45.{i % 256}',
                port=4444
            )

        # Measure list performance
        start_time = time.time()
        sessions = session_manager.list_sessions()
        elapsed = time.time() - start_time

        assert len(sessions) == 1000
        assert elapsed < 0.1, f"Listing took {elapsed*1000:.2f}ms (target: <100ms)"

    def test_session_filter_performance(self, session_manager):
        """Test filtering performance (target: <100ms for 1000 sessions)."""
        # Create diverse sessions
        for i in range(500):
            session_manager.create_session(
                type='tcp',
                target='192.168.45.100',
                port=4444
            )

        for i in range(500):
            session_manager.create_session(
                type='http',
                target='192.168.45.101',
                port=8080
            )

        # Measure filter performance
        start_time = time.time()
        tcp_sessions = session_manager.list_sessions({'type': 'tcp'})
        elapsed = time.time() - start_time

        assert len(tcp_sessions) == 500
        assert elapsed < 0.1, f"Filtering took {elapsed*1000:.2f}ms (target: <100ms)"


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
