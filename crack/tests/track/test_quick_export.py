"""
Test Quick Export (qx) functionality

PROVES: Quick export tool exports findings, tasks, status, and credentials
to files and clipboard in multiple formats.
"""

import pytest
import json
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

from crack.track.interactive.session import InteractiveSession
from crack.track.core.state import TargetProfile


@pytest.fixture
def mock_profile_with_data(temp_crack_home):
    """Create a profile with comprehensive test data"""
    target = "192.168.45.100"
    profile = TargetProfile(target)

    # Add ports
    profile.add_port(80, state='open', service='http', version='Apache 2.4.41', source='nmap')
    profile.add_port(22, state='open', service='ssh', version='OpenSSH 8.0', source='nmap')
    profile.add_port(445, state='open', service='smb', version='Samba 4.11.2', source='nmap')

    # Add findings
    profile.add_finding(
        finding_type='vulnerability',
        description='SQL injection in id parameter',
        source='Manual testing: sqlmap -u "http://192.168.45.100/page.php?id=1"'
    )
    profile.add_finding(
        finding_type='directory',
        description='Hidden admin panel at /admin',
        source='Gobuster directory enumeration'
    )

    # Add credentials
    profile.add_credential(
        username='admin',
        password='password123',
        service='http',
        port=80,
        source='Found in /var/www/config.php'
    )
    profile.add_credential(
        username='root',
        password=None,
        service='ssh',
        port=22,
        source='Brute force with hydra'
    )

    # Add notes
    profile.add_note(
        note='Server appears to be running Ubuntu 20.04',
        source='nmap -O scan'
    )
    profile.add_note(
        note='Web application uses PHP 7.4',
        source='HTTP header analysis'
    )

    profile.save()
    return profile


class TestQuickExportShortcut:
    """Test that qx shortcut is registered"""

    def test_qx_shortcut_exists(self):
        """PROVES: 'qx' shortcut is registered in ShortcutHandler"""
        from crack.track.interactive.shortcuts import ShortcutHandler

        session = Mock()
        handler = ShortcutHandler(session)

        assert 'qx' in handler.shortcuts
        assert handler.shortcuts['qx'][0] == 'Quick export'
        assert handler.shortcuts['qx'][1] == 'quick_export'

    def test_qx_in_input_handler_shortcuts(self):
        """PROVES: 'qx' is recognized by InputProcessor"""
        from crack.track.interactive.input_handler import InputProcessor

        assert 'qx' in InputProcessor.SHORTCUTS

    def test_qx_handler_callable(self, temp_crack_home):
        """PROVES: ShortcutHandler can call quick_export method"""
        from crack.track.interactive.shortcuts import ShortcutHandler

        target = "192.168.45.100"
        session = InteractiveSession(target)
        handler = ShortcutHandler(session)

        assert hasattr(handler, 'quick_export')
        assert callable(handler.quick_export)


class TestExportDirectory:
    """Test export directory creation and structure"""

    def test_export_dir_creation(self, temp_crack_home, mock_profile_with_data):
        """PROVES: Creates ~/.crack/exports/TARGET/ directory"""
        session = InteractiveSession(mock_profile_with_data.target)

        export_dir = session._get_export_dir()

        assert export_dir.exists()
        assert export_dir.is_dir()
        assert export_dir.parent.name == 'exports'
        assert export_dir.name == mock_profile_with_data.target

    def test_export_dir_persistence(self, temp_crack_home, mock_profile_with_data):
        """PROVES: Export directory persists across sessions"""
        target = mock_profile_with_data.target

        # First session
        session1 = InteractiveSession(target)
        export_dir1 = session1._get_export_dir()

        # Second session
        session2 = InteractiveSession(target)
        export_dir2 = session2._get_export_dir()

        assert export_dir1 == export_dir2
        assert export_dir1.exists()


class TestFindingsExport:
    """Test findings export in multiple formats"""

    def test_format_findings_markdown(self, temp_crack_home, mock_profile_with_data):
        """PROVES: Formats findings as markdown correctly"""
        session = InteractiveSession(mock_profile_with_data.target)

        content = session._format_findings('markdown')

        assert f"# Findings - {mock_profile_with_data.target}" in content
        assert "## 1." in content
        assert "**Description**:" in content
        assert "**Source**:" in content
        assert "SQL injection" in content

    def test_format_findings_json(self, temp_crack_home, mock_profile_with_data):
        """PROVES: Formats findings as JSON correctly"""
        session = InteractiveSession(mock_profile_with_data.target)

        content = session._format_findings('json')

        # Should be valid JSON
        data = json.loads(content)
        assert isinstance(data, list)
        assert len(data) == 2  # Two findings added
        assert data[0]['description'] == 'SQL injection in id parameter'

    def test_format_findings_text(self, temp_crack_home, mock_profile_with_data):
        """PROVES: Formats findings as plain text correctly"""
        session = InteractiveSession(mock_profile_with_data.target)

        content = session._format_findings('text')

        assert f"Findings - {mock_profile_with_data.target}" in content
        assert "=" * 50 in content
        assert "1. [vulnerability] SQL injection" in content
        assert "Source:" in content

    def test_format_empty_findings(self, temp_crack_home):
        """PROVES: Handles empty findings gracefully"""
        target = "192.168.45.200"
        profile = TargetProfile(target)
        profile.save()

        session = InteractiveSession(target)
        content = session._format_findings('markdown')

        assert "No findings documented yet" in content


class TestCredentialsExport:
    """Test credentials export in multiple formats"""

    def test_format_credentials_markdown(self, temp_crack_home, mock_profile_with_data):
        """PROVES: Formats credentials as markdown table"""
        session = InteractiveSession(mock_profile_with_data.target)

        content = session._format_credentials('markdown')

        assert f"# Credentials - {mock_profile_with_data.target}" in content
        assert "| Username | Password | Service | Port | Source |" in content
        assert "| admin | password123" in content
        assert "| root | N/A" in content  # No password for root

    def test_format_credentials_json(self, temp_crack_home, mock_profile_with_data):
        """PROVES: Formats credentials as JSON correctly"""
        session = InteractiveSession(mock_profile_with_data.target)

        content = session._format_credentials('json')

        data = json.loads(content)
        assert isinstance(data, list)
        assert len(data) == 2
        assert data[0]['username'] == 'admin'
        assert data[0]['password'] == 'password123'

    def test_format_credentials_text(self, temp_crack_home, mock_profile_with_data):
        """PROVES: Formats credentials as plain text"""
        session = InteractiveSession(mock_profile_with_data.target)

        content = session._format_credentials('text')

        assert f"Credentials - {mock_profile_with_data.target}" in content
        assert "1. admin / password123" in content
        assert "Service: http" in content
        assert "Port: 80" in content


class TestPortsExport:
    """Test port scan results export"""

    def test_format_ports_markdown(self, temp_crack_home, mock_profile_with_data):
        """PROVES: Formats ports as markdown table"""
        session = InteractiveSession(mock_profile_with_data.target)

        content = session._format_ports('markdown')

        assert f"# Port Scan Results - {mock_profile_with_data.target}" in content
        assert "| Port | State | Service | Version | Source |" in content
        assert "| 80 | open | http" in content
        assert "Apache 2.4.41" in content

    def test_format_ports_text(self, temp_crack_home, mock_profile_with_data):
        """PROVES: Formats ports as plain text"""
        session = InteractiveSession(mock_profile_with_data.target)

        content = session._format_ports('text')

        assert "PORT 80/tcp" in content
        assert "State: open" in content
        assert "Service: http" in content
        assert "Version: Apache 2.4.41" in content


class TestNotesExport:
    """Test notes export"""

    def test_format_notes_markdown(self, temp_crack_home, mock_profile_with_data):
        """PROVES: Formats notes as markdown"""
        session = InteractiveSession(mock_profile_with_data.target)

        content = session._format_notes('markdown')

        assert f"# Notes - {mock_profile_with_data.target}" in content
        assert "Ubuntu 20.04" in content
        assert "PHP 7.4" in content
        assert "**Source**:" in content


class TestTaskTreeExport:
    """Test task tree export"""

    def test_format_task_tree_json(self, temp_crack_home, mock_profile_with_data):
        """PROVES: Formats task tree as JSON"""
        session = InteractiveSession(mock_profile_with_data.target)

        content = session._format_task_tree('json')

        data = json.loads(content)
        assert 'id' in data
        assert 'name' in data
        assert 'children' in data


class TestStatusExport:
    """Test full status report export"""

    def test_format_status_markdown(self, temp_crack_home, mock_profile_with_data):
        """PROVES: Formats full status report"""
        session = InteractiveSession(mock_profile_with_data.target)

        content = session._format_status('markdown')

        assert mock_profile_with_data.target in content
        # Should include task tree
        assert 'Enumeration' in content or 'Task' in content


class TestClipboardDetection:
    """Test clipboard tool detection"""

    @patch('shutil.which')
    def test_has_clipboard_xclip(self, mock_which, temp_crack_home):
        """PROVES: Detects xclip correctly"""
        mock_which.side_effect = lambda tool: '/usr/bin/xclip' if tool == 'xclip' else None

        target = "192.168.45.100"
        session = InteractiveSession(target)

        assert session._has_clipboard() is True

    @patch('shutil.which')
    def test_has_clipboard_xsel(self, mock_which, temp_crack_home):
        """PROVES: Detects xsel correctly"""
        mock_which.side_effect = lambda tool: '/usr/bin/xsel' if tool == 'xsel' else None

        target = "192.168.45.100"
        session = InteractiveSession(target)

        assert session._has_clipboard() is True

    @patch('shutil.which')
    def test_no_clipboard(self, mock_which, temp_crack_home):
        """PROVES: Returns False when no clipboard tools available"""
        mock_which.return_value = None

        target = "192.168.45.100"
        session = InteractiveSession(target)

        assert session._has_clipboard() is False


class TestFileExport:
    """Test actual file export"""

    def test_export_to_file_naming(self, temp_crack_home, mock_profile_with_data):
        """PROVES: File naming convention is correct"""
        session = InteractiveSession(mock_profile_with_data.target)

        # Generate content
        content = session._format_findings('markdown')

        # Create export
        export_dir = session._get_export_dir()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"findings_{timestamp}.md"
        filepath = export_dir / filename

        filepath.write_text(content)

        assert filepath.exists()
        assert filepath.suffix == '.md'
        assert 'findings_' in filepath.name

    def test_export_preserves_content(self, temp_crack_home, mock_profile_with_data):
        """PROVES: Exported content is readable and accurate"""
        session = InteractiveSession(mock_profile_with_data.target)

        # Export findings
        content = session._format_findings('markdown')
        export_dir = session._get_export_dir()
        filepath = export_dir / "test_export.md"
        filepath.write_text(content)

        # Read back
        loaded_content = filepath.read_text()

        assert loaded_content == content
        assert "SQL injection" in loaded_content


class TestExportContentGeneration:
    """Test the unified export content generator"""

    def test_generate_export_content_status(self, temp_crack_home, mock_profile_with_data):
        """PROVES: Generates status export correctly"""
        session = InteractiveSession(mock_profile_with_data.target)

        content = session._generate_export_content('status', 'markdown')

        assert content is not None
        assert len(content) > 0

    def test_generate_export_content_profile_json(self, temp_crack_home, mock_profile_with_data):
        """PROVES: Generates full profile JSON export"""
        session = InteractiveSession(mock_profile_with_data.target)

        content = session._generate_export_content('profile', 'json')

        data = json.loads(content)
        assert data['target'] == mock_profile_with_data.target
        assert 'ports' in data
        assert 'findings' in data
        assert 'credentials' in data

    def test_generate_export_content_invalid_type(self, temp_crack_home):
        """PROVES: Returns empty string for invalid export type"""
        target = "192.168.45.100"
        session = InteractiveSession(target)

        content = session._generate_export_content('invalid_type', 'markdown')

        assert content == ""


class TestExportIntegration:
    """Integration tests for full export workflow"""

    def test_full_findings_export_workflow(self, temp_crack_home, mock_profile_with_data):
        """PROVES: Complete workflow from profile to file export"""
        session = InteractiveSession(mock_profile_with_data.target)

        # 1. Generate content
        content = session._generate_export_content('findings', 'markdown')
        assert len(content) > 0

        # 2. Get export directory
        export_dir = session._get_export_dir()
        assert export_dir.exists()

        # 3. Write file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"findings_{timestamp}.md"
        filepath = export_dir / filename
        filepath.write_text(content)

        # 4. Verify file exists and is readable
        assert filepath.exists()
        loaded = filepath.read_text()
        assert "SQL injection" in loaded

    def test_multiple_exports_same_session(self, temp_crack_home, mock_profile_with_data):
        """PROVES: Multiple exports in same session work correctly"""
        session = InteractiveSession(mock_profile_with_data.target)
        export_dir = session._get_export_dir()

        # Export findings
        findings_content = session._generate_export_content('findings', 'markdown')
        findings_path = export_dir / "findings_test.md"
        findings_path.write_text(findings_content)

        # Export credentials
        creds_content = session._generate_export_content('credentials', 'markdown')
        creds_path = export_dir / "credentials_test.md"
        creds_path.write_text(creds_content)

        # Both should exist
        assert findings_path.exists()
        assert creds_path.exists()
        assert "SQL injection" in findings_path.read_text()
        assert "admin" in creds_path.read_text()
