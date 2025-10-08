"""
Tests for Smart Suggest (sg) Tool

PROVES: Pattern-based suggestion engine functionality
- Shortcut registration
- Rule evaluation
- Suggestion generation
- Priority sorting
- Task creation from suggestions
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch
from crack.track.interactive.session import InteractiveSession
from crack.track.interactive.shortcuts import ShortcutHandler
from crack.track.interactive.smart_suggest_handler import get_suggestion_rules, create_suggestion_tasks
from crack.track.core.state import TargetProfile
from crack.track.core.task_tree import TaskNode


@pytest.fixture
def mock_profile(tmp_path):
    """Create mock target profile"""
    target = "192.168.45.100"

    # Create profile with minimal setup
    profile = TargetProfile(target)
    profile.metadata = {
        'confirmation_mode': 'smart',
        'environment': 'lab'
    }

    # Mock storage path
    profile.storage_path = tmp_path / f"{target}.json"

    return profile


@pytest.fixture
def mock_session(mock_profile):
    """Create mock interactive session"""
    with patch('crack.track.interactive.session.TargetProfile.load', return_value=mock_profile):
        with patch('crack.track.interactive.session.TargetProfile.exists', return_value=True):
            session = InteractiveSession(mock_profile.target)
            session.profile = mock_profile
            return session


class TestShortcutRegistration:
    """Test sg shortcut registration"""

    def test_sg_shortcut_exists(self, mock_session):
        """PROVES: 'sg' shortcut is registered"""
        handler = ShortcutHandler(mock_session)

        assert 'sg' in handler.shortcuts
        assert handler.shortcuts['sg'][0] == 'Smart suggest'
        assert handler.shortcuts['sg'][1] == 'smart_suggest'

    def test_sg_handler_callable(self, mock_session):
        """PROVES: sg handler method exists and is callable"""
        handler = ShortcutHandler(mock_session)

        assert hasattr(handler, 'smart_suggest')
        assert callable(handler.smart_suggest)

    def test_sg_in_input_shortcuts(self):
        """PROVES: 'sg' is recognized in input handler"""
        from crack.track.interactive.input_handler import InputProcessor

        assert 'sg' in InputProcessor.SHORTCUTS


class TestRuleEvaluation:
    """Test suggestion rule evaluation"""

    def test_mysql_suggestion(self, mock_profile):
        """PROVES: MySQL port triggers suggestion when no enumeration tasks exist"""
        # Manually add port WITHOUT triggering service plugins
        mock_profile.ports[3306] = {
            'state': 'open',
            'service': 'mysql',
            'version': 'MySQL 5.5'
        }

        # Clear any auto-generated tasks
        mock_profile.task_tree.children = []

        # Get rules
        rules = get_suggestion_rules(mock_profile.target)

        # Find MySQL rule
        mysql_rule = next((r for r in rules if r['id'] == 'mysql-no-enum'), None)
        assert mysql_rule is not None

        # Should trigger (no MySQL tasks)
        assert mysql_rule['condition'](mock_profile) is True

    def test_smb_null_session_suggestion(self, mock_profile):
        """PROVES: SMB port triggers null session suggestion"""
        # Manually add port
        mock_profile.ports[445] = {'state': 'open', 'service': 'smb', 'version': 'Samba 3.0'}
        mock_profile.task_tree.children = []

        # Get rules
        rules = get_suggestion_rules(mock_profile.target)

        # Find SMB rule
        smb_rule = next((r for r in rules if r['id'] == 'smb-no-null'), None)
        assert smb_rule is not None

        # Should trigger
        assert smb_rule['condition'](mock_profile) is True

    def test_http_robots_suggestion(self, mock_profile):
        """PROVES: HTTP service suggests robots.txt check"""
        # Manually add port
        mock_profile.ports[80] = {'state': 'open', 'service': 'http', 'version': 'Apache 2.4'}
        mock_profile.task_tree.children = []

        # Get rules
        rules = get_suggestion_rules(mock_profile.target)

        # Find HTTP robots rule
        http_rule = next((r for r in rules if r['id'] == 'http-no-robots'), None)
        assert http_rule is not None

        # Should trigger
        assert http_rule['condition'](mock_profile) is True

    def test_credential_reuse_suggestion(self, mock_profile):
        """PROVES: Credentials trigger reuse testing suggestion"""
        # Add credentials
        mock_profile.credentials.append({
            'username': 'admin',
            'password': 'password123',
            'service': 'http',
            'source': 'config.php'
        })

        # Add multiple services
        mock_profile.add_port(22, 'open', 'ssh')
        mock_profile.add_port(445, 'open', 'smb')

        # Get rules
        rules = get_suggestion_rules(mock_profile.target)

        # Find credential reuse rule
        cred_rule = next((r for r in rules if r['id'] == 'creds-no-reuse'), None)
        assert cred_rule is not None

        # Should trigger
        assert cred_rule['condition'](mock_profile) is True

    def test_high_port_suggestion(self, mock_profile):
        """PROVES: High port with unknown service triggers suggestion"""
        # Add high port with unknown service
        mock_profile.add_port(12345, 'open', 'unknown')

        # Get rules
        rules = get_suggestion_rules(mock_profile.target)

        # Find high port rule
        high_port_rule = next((r for r in rules if r['id'] == 'high-port-unknown'), None)
        assert high_port_rule is not None

        # Should trigger
        assert high_port_rule['condition'](mock_profile) is True

    def test_ftp_anonymous_suggestion(self, mock_profile):
        """PROVES: FTP service suggests anonymous login test"""
        # Manually add port
        mock_profile.ports[21] = {'state': 'open', 'service': 'ftp', 'version': 'vsftpd 3.0'}
        mock_profile.task_tree.children = []

        # Get rules
        rules = get_suggestion_rules(mock_profile.target)

        # Find FTP rule
        ftp_rule = next((r for r in rules if r['id'] == 'ftp-no-anon'), None)
        assert ftp_rule is not None

        # Should trigger
        assert ftp_rule['condition'](mock_profile) is True

    def test_version_cve_suggestion(self, mock_profile):
        """PROVES: Service version suggests CVE search"""
        # Manually add port
        mock_profile.ports[80] = {'state': 'open', 'service': 'http', 'version': 'Apache 2.4.41'}
        mock_profile.task_tree.children = []

        # Get rules
        rules = get_suggestion_rules(mock_profile.target)

        # Find version CVE rule
        version_rule = next((r for r in rules if r['id'] == 'version-no-cve'), None)
        assert version_rule is not None

        # Should trigger
        assert version_rule['condition'](mock_profile) is True

    def test_multiple_web_ports_suggestion(self, mock_profile):
        """PROVES: Multiple web ports suggest complete enumeration"""
        # Manually add ports
        mock_profile.ports[80] = {'state': 'open', 'service': 'http'}
        mock_profile.ports[8080] = {'state': 'open', 'service': 'http'}
        mock_profile.task_tree.children = []

        # Get rules
        rules = get_suggestion_rules(mock_profile.target)

        # Find multi-web rule
        multi_web_rule = next((r for r in rules if r['id'] == 'multi-web-incomplete'), None)
        assert multi_web_rule is not None

        # Should trigger (no HTTP tasks yet)
        assert multi_web_rule['condition'](mock_profile) is True


class TestPrioritySorting:
    """Test suggestion priority sorting"""

    def test_priority_sorting(self, mock_profile):
        """PROVES: Suggestions are sorted by priority"""
        # Manually add services
        mock_profile.ports[80] = {'state': 'open', 'service': 'http'}
        mock_profile.ports[3306] = {'state': 'open', 'service': 'mysql'}
        mock_profile.task_tree.children = []

        # Add vulnerability finding without exploit
        mock_profile.findings.append({
            'type': 'vulnerability',
            'description': 'SQL injection',
            'source': 'Manual test'
        })  # Critical priority

        # Get rules
        rules = get_suggestion_rules(mock_profile.target)

        # Evaluate all rules
        suggestions = []
        for rule in rules:
            try:
                if rule['condition'](mock_profile):
                    suggestions.append(rule)
            except Exception:
                continue

        # Sort by priority
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        suggestions.sort(key=lambda r: priority_order.get(r['priority'], 99))

        # Verify we got some suggestions
        assert len(suggestions) > 0

        # First should be critical priority if one exists
        if any(s['priority'] == 'critical' for s in suggestions):
            assert suggestions[0]['priority'] == 'critical'

    def test_no_suggestions_comprehensive(self, mock_profile):
        """PROVES: No suggestions when enumeration is comprehensive"""
        # Add port with enumeration task
        mock_profile.add_port(3306, 'open', 'mysql')

        # Add MySQL task
        mysql_task = TaskNode(
            task_id='mysql-enum',
            name='MySQL Enumeration',
            task_type='command'
        )
        mock_profile.task_tree.add_child(mysql_task)

        # Get rules
        rules = get_suggestion_rules(mock_profile.target)

        # Find MySQL rule
        mysql_rule = next((r for r in rules if r['id'] == 'mysql-no-enum'), None)

        # Should NOT trigger (task exists)
        assert mysql_rule['condition'](mock_profile) is False


class TestTaskCreation:
    """Test task creation from suggestions"""

    def test_task_creation_from_suggestions(self, mock_profile, capsys):
        """PROVES: Tasks are created from suggestions"""
        # Create suggestions
        suggestions = [
            {
                'id': 'test-suggestion',
                'priority': 'high',
                'suggestion': 'Test suggestion for MySQL',
                'command': 'mysql -h 192.168.45.100 -u root',
                'pattern': 'test_pattern',
                'reasoning': 'Testing task creation'
            }
        ]

        # Create tasks
        created = create_suggestion_tasks(mock_profile, suggestions)

        # Verify task was created
        assert created == 1

        # Check task exists in tree
        all_tasks = mock_profile.task_tree.get_all_tasks()
        suggest_tasks = [t for t in all_tasks if 'SUGGEST' in t.name]

        assert len(suggest_tasks) >= 1

    def test_multiple_task_creation(self, mock_profile):
        """PROVES: Multiple suggestions create multiple tasks"""
        # Create multiple suggestions
        suggestions = [
            {
                'id': 'test-1',
                'priority': 'high',
                'suggestion': 'First suggestion',
                'command': 'command1',
                'pattern': 'pattern1',
                'reasoning': 'reason1'
            },
            {
                'id': 'test-2',
                'priority': 'medium',
                'suggestion': 'Second suggestion',
                'command': 'command2',
                'pattern': 'pattern2',
                'reasoning': 'reason2'
            }
        ]

        # Create tasks
        created = create_suggestion_tasks(mock_profile, suggestions)

        # Verify both tasks created
        assert created == 2


class TestIntegration:
    """Integration tests for full workflow"""

    def test_handle_smart_suggest_full_workflow(self, mock_session, monkeypatch, capsys):
        """PROVES: Full smart suggest workflow works end-to-end"""
        # Manually add port to trigger suggestion
        mock_session.profile.ports[3306] = {'state': 'open', 'service': 'mysql'}
        mock_session.profile.task_tree.children = []

        # Mock user declining task creation
        monkeypatch.setattr('builtins.input', lambda _: 'n')

        # Execute
        mock_session.handle_smart_suggest()

        # Verify output
        captured = capsys.readouterr()
        assert 'Smart Suggest' in captured.out
        assert 'Found' in captured.out and 'suggestion' in captured.out.lower()

    def test_handle_smart_suggest_with_task_creation(self, mock_session, monkeypatch):
        """PROVES: Can create tasks from smart suggest"""
        # Manually add port
        mock_session.profile.ports[3306] = {'state': 'open', 'service': 'mysql'}
        mock_session.profile.task_tree.children = []

        # Mock user accepting task creation
        monkeypatch.setattr('builtins.input', lambda _: 'y')

        # Execute
        mock_session.handle_smart_suggest()

        # Verify tasks were created
        all_tasks = mock_session.profile.task_tree.get_all_tasks()
        suggest_tasks = [t for t in all_tasks if 'SUGGEST' in t.name]

        assert len(suggest_tasks) > 0

    def test_handle_smart_suggest_no_gaps(self, mock_session, monkeypatch, capsys):
        """PROVES: Shows success message when no gaps found"""
        # Don't add any ports or findings

        # Execute
        mock_session.handle_smart_suggest()

        # Verify no suggestions message
        captured = capsys.readouterr()
        assert 'No gaps found' in captured.out or 'enumeration looks comprehensive' in captured.out.lower()


class TestRuleCoverage:
    """Test coverage of all major rule categories"""

    def test_snmp_community_rule(self, mock_profile):
        """PROVES: SNMP triggers community string test"""
        mock_profile.ports[161] = {'state': 'open', 'service': 'snmp'}
        mock_profile.task_tree.children = []

        rules = get_suggestion_rules(mock_profile.target)
        snmp_rule = next((r for r in rules if r['id'] == 'snmp-no-community'), None)

        assert snmp_rule is not None
        assert snmp_rule['condition'](mock_profile) is True

    def test_nfs_showmount_rule(self, mock_profile):
        """PROVES: NFS triggers showmount enumeration"""
        mock_profile.ports[2049] = {'state': 'open', 'service': 'nfs'}
        mock_profile.task_tree.children = []

        rules = get_suggestion_rules(mock_profile.target)
        nfs_rule = next((r for r in rules if r['id'] == 'nfs-no-showmount'), None)

        assert nfs_rule is not None
        assert nfs_rule['condition'](mock_profile) is True

    def test_wordpress_wpscan_rule(self, mock_profile):
        """PROVES: WordPress finding triggers wpscan"""
        mock_profile.findings.append({
            'type': 'discovery',
            'description': 'WordPress installation detected at /wp-content/',
            'source': 'Manual browse'
        })

        rules = get_suggestion_rules(mock_profile.target)
        wp_rule = next((r for r in rules if r['id'] == 'wordpress-no-scan'), None)

        assert wp_rule is not None
        assert wp_rule['condition'](mock_profile) is True


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
