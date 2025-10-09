"""Tests for Quick Note tool"""
import pytest
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from crack.track.core.state import TargetProfile
from crack.track.interactive.session import InteractiveSession
from crack.track.interactive.shortcuts import ShortcutHandler


@pytest.fixture
def temp_crack_home(tmp_path, monkeypatch):
    """Create temporary .crack directory for testing"""
    crack_home = tmp_path / '.crack'
    crack_home.mkdir()

    targets_dir = crack_home / 'targets'
    targets_dir.mkdir()

    sessions_dir = crack_home / 'sessions'
    sessions_dir.mkdir()

    # Override Storage and InteractiveSession directories
    from crack.track.core.storage import Storage
    from crack.track.interactive.session import InteractiveSession

    monkeypatch.setattr(Storage, 'DEFAULT_DIR', targets_dir)
    monkeypatch.setattr(InteractiveSession, 'SNAPSHOTS_BASE_DIR', sessions_dir)

    return crack_home


class TestQuickNote:
    """Test Quick Note functionality"""

    def test_shortcut_exists(self, temp_crack_home):
        """PROVES: 'qn' shortcut is registered"""
        profile = TargetProfile('192.168.45.100')
        session = InteractiveSession(profile.target)
        handler = ShortcutHandler(session)

        assert 'qn' in handler.shortcuts
        assert handler.shortcuts['qn'][0] == 'Quick note'
        assert handler.shortcuts['qn'][1] == 'quick_note'

    def test_handler_exists(self, temp_crack_home):
        """PROVES: quick_note handler is callable"""
        profile = TargetProfile('192.168.45.100')
        session = InteractiveSession(profile.target)
        handler = ShortcutHandler(session)

        assert hasattr(handler, 'quick_note')
        assert callable(getattr(handler, 'quick_note'))

    def test_note_added_to_profile(self, temp_crack_home, monkeypatch):
        """PROVES: Note is added to profile with timestamp"""
        profile = TargetProfile('192.168.45.106')  # Use different IP
        session = InteractiveSession(profile.target)

        # Simulate user input
        inputs = iter(["Test note from quick note", "manual testing"])
        monkeypatch.setattr('builtins.input', lambda _: next(inputs))

        handler = ShortcutHandler(session)
        handler.quick_note()

        # Verify note added
        assert len(session.profile.notes) == 1
        assert session.profile.notes[0]['note'] == "Test note from quick note"
        assert session.profile.notes[0]['source'] == "manual testing"
        assert 'timestamp' in session.profile.notes[0]

    def test_default_source(self, temp_crack_home, monkeypatch):
        """PROVES: Default source is 'quick-note' when empty"""
        profile = TargetProfile('192.168.45.101')  # Use different IP to avoid collision
        session = InteractiveSession(profile.target)

        # Simulate: note text, then empty source
        inputs = iter(["Another test note", ""])
        monkeypatch.setattr('builtins.input', lambda _: next(inputs))

        handler = ShortcutHandler(session)
        handler.quick_note()

        assert len(session.profile.notes) == 1
        assert session.profile.notes[0]['source'] == 'quick-note'

    def test_empty_note_rejected(self, temp_crack_home, monkeypatch, capsys):
        """PROVES: Empty notes are rejected"""
        profile = TargetProfile('192.168.45.102')  # Use different IP
        session = InteractiveSession(profile.target)

        # Empty note
        monkeypatch.setattr('builtins.input', lambda _: "")

        handler = ShortcutHandler(session)
        handler.quick_note()

        # No note added
        assert len(session.profile.notes) == 0

        # Warning shown
        captured = capsys.readouterr()
        assert "cannot be empty" in captured.out.lower()

    def test_note_persists(self, temp_crack_home, monkeypatch):
        """PROVES: Notes survive save/load cycle"""
        profile = TargetProfile('192.168.45.103')  # Use different IP
        session = InteractiveSession(profile.target)

        inputs = iter(["Persistent note", "test"])
        monkeypatch.setattr('builtins.input', lambda _: next(inputs))

        handler = ShortcutHandler(session)
        handler.quick_note()

        # Reload profile
        loaded = TargetProfile.load('192.168.45.103')
        assert len(loaded.notes) == 1
        assert loaded.notes[0]['note'] == "Persistent note"

    def test_multiple_notes(self, temp_crack_home, monkeypatch):
        """PROVES: Multiple notes can be added"""
        profile = TargetProfile('192.168.45.104')  # Use different IP
        session = InteractiveSession(profile.target)
        handler = ShortcutHandler(session)

        # Add first note
        inputs = iter(["First note", "source1"])
        monkeypatch.setattr('builtins.input', lambda _: next(inputs))
        handler.quick_note()

        # Add second note
        inputs = iter(["Second note", "source2"])
        monkeypatch.setattr('builtins.input', lambda _: next(inputs))
        handler.quick_note()

        assert len(session.profile.notes) == 2
        assert session.profile.notes[0]['note'] == "First note"
        assert session.profile.notes[1]['note'] == "Second note"

    def test_last_action_updated(self, temp_crack_home, monkeypatch):
        """PROVES: Session last_action is updated after adding note"""
        profile = TargetProfile('192.168.45.100')
        session = InteractiveSession(profile.target)

        inputs = iter(["Test action update", "test"])
        monkeypatch.setattr('builtins.input', lambda _: next(inputs))

        handler = ShortcutHandler(session)
        handler.quick_note()

        assert session.last_action == "Added quick note"

    def test_truncated_display(self, temp_crack_home, monkeypatch, capsys):
        """PROVES: Long notes are truncated in success message"""
        profile = TargetProfile('192.168.45.105')  # Use different IP
        session = InteractiveSession(profile.target)

        # Create a note longer than 50 characters
        long_note = "A" * 60
        inputs = iter([long_note, "test"])
        monkeypatch.setattr('builtins.input', lambda _: next(inputs))

        handler = ShortcutHandler(session)
        handler.quick_note()

        # Check full note is saved
        assert len(session.profile.notes) == 1
        assert session.profile.notes[0]['note'] == long_note

        # Check displayed message is truncated
        captured = capsys.readouterr()
        assert "Note added: " + "A" * 50 + "..." in captured.out

    def test_shortcut_in_input_handler(self, temp_crack_home):
        """PROVES: 'qn' is recognized in InputProcessor"""
        from crack.track.interactive.input_handler import InputProcessor

        assert 'qn' in InputProcessor.SHORTCUTS

        # Test parsing
        result = InputProcessor.parse_shortcut('qn')
        assert result == 'qn'
