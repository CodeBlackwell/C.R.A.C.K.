"""
Unit tests for FindingsPanel component

Tests rendering, filtering, pagination, and menu generation without TUI integration.
"""

import pytest
from datetime import datetime, timedelta
from crack.track.interactive.panels.findings_panel import FindingsPanel
from crack.track.core.state import TargetProfile


@pytest.fixture
def mock_profile_empty():
    """Create profile with no findings"""
    profile = TargetProfile('192.168.1.100')
    return profile


@pytest.fixture
def mock_profile_with_findings():
    """Create profile with sample findings"""
    profile = TargetProfile('192.168.1.100')

    # Add various types of findings
    now = datetime.now()

    # Add vulnerability finding
    profile.add_finding(
        finding_type='vulnerability',
        description='SQL injection in login form',
        source='sqlmap -u http://192.168.1.100/login.php',
        data={'severity': 'high', 'port': 80}
    )

    # Add directory finding
    profile.add_finding(
        finding_type='directory',
        description='/admin directory discovered',
        source='gobuster dir -u http://192.168.1.100 -w /usr/share/wordlists/dirb/common.txt',
        data={'status_code': 200, 'port': 80}
    )

    # Add credential finding
    profile.add_finding(
        finding_type='credential',
        description='admin:password123',
        source='hydra -l admin -P rockyou.txt ssh://192.168.1.100',
        data={'service': 'ssh', 'port': 22}
    )

    # Add user finding
    profile.add_finding(
        finding_type='user',
        description='User: john (uid=1001)',
        source='enum4linux -U 192.168.1.100',
        data={'port': 445}
    )

    # Add note finding
    profile.add_finding(
        finding_type='note',
        description='Apache 2.4.41 - potential CVE-2021-41773',
        source='manual analysis',
        data={'research_needed': True}
    )

    return profile


@pytest.fixture
def mock_profile_many_findings():
    """Create profile with many findings for pagination testing"""
    profile = TargetProfile('192.168.1.100')

    # Add 25 findings to test pagination
    for i in range(25):
        profile.add_finding(
            finding_type='directory' if i % 2 == 0 else 'vulnerability',
            description=f'Finding #{i+1} - test description',
            source=f'tool-{i+1}'
        )

    return profile


class TestFindingsPanelRender:
    """Test main render method"""

    def test_render_empty_state(self, mock_profile_empty):
        """Test rendering with no findings"""
        panel, choices = FindingsPanel.render(mock_profile_empty)

        # Panel should exist
        assert panel is not None

        # Choices should contain basic actions
        choice_ids = [c['id'] for c in choices]
        assert 'f' in choice_ids  # Filter
        assert 'b' in choice_ids  # Back

        # Should NOT have export (no findings)
        assert 'e' not in choice_ids

    def test_render_with_findings(self, mock_profile_with_findings):
        """Test rendering with findings"""
        panel, choices = FindingsPanel.render(mock_profile_with_findings)

        # Panel should exist
        assert panel is not None

        # Should have export and correlate options
        choice_ids = [c['id'] for c in choices]
        assert 'e' in choice_ids  # Export
        assert 'c' in choice_ids  # Correlate
        assert 'f' in choice_ids  # Filter
        assert 'b' in choice_ids  # Back

        # Should have selection choices (1-5 for 5 findings on page 1)
        assert '1' in choice_ids
        assert '5' in choice_ids

    def test_render_correct_return_type(self, mock_profile_with_findings):
        """Test render returns correct tuple structure"""
        result = FindingsPanel.render(mock_profile_with_findings)

        # Should return tuple
        assert isinstance(result, tuple)
        assert len(result) == 2

        # First element should be Panel
        panel, choices = result
        assert hasattr(panel, 'renderable')  # Rich Panel characteristic

        # Second element should be list of dicts
        assert isinstance(choices, list)
        assert all(isinstance(c, dict) for c in choices)

        # Each choice should have required fields
        for choice in choices:
            assert 'id' in choice
            assert 'label' in choice


class TestFindingsPanelFiltering:
    """Test filtering functionality"""

    def test_filter_all(self, mock_profile_with_findings):
        """Test 'all' filter shows all findings"""
        panel, choices = FindingsPanel.render(
            mock_profile_with_findings,
            filter_type='all'
        )

        # Should have 5 selection choices (1-5)
        choice_ids = [c['id'] for c in choices]
        assert '1' in choice_ids
        assert '5' in choice_ids

    def test_filter_vulnerability(self, mock_profile_with_findings):
        """Test filtering by vulnerability type"""
        panel, choices = FindingsPanel.render(
            mock_profile_with_findings,
            filter_type='vulnerability'
        )

        # Should have only 1 selection choice (vulnerability finding)
        selection_choices = [c for c in choices if c['id'].isdigit()]
        assert len(selection_choices) == 1

        # Verify it's the vulnerability finding
        assert 'SQL injection' in selection_choices[0]['finding']['description']

    def test_filter_directory(self, mock_profile_with_findings):
        """Test filtering by directory type"""
        panel, choices = FindingsPanel.render(
            mock_profile_with_findings,
            filter_type='directory'
        )

        # Should have only 1 selection choice (directory finding)
        selection_choices = [c for c in choices if c['id'].isdigit()]
        assert len(selection_choices) == 1

        # Verify it's the directory finding
        assert '/admin' in selection_choices[0]['finding']['description']

    def test_filter_credential(self, mock_profile_with_findings):
        """Test filtering by credential type"""
        panel, choices = FindingsPanel.render(
            mock_profile_with_findings,
            filter_type='credential'
        )

        # Should have only 1 selection choice (credential finding)
        selection_choices = [c for c in choices if c['id'].isdigit()]
        assert len(selection_choices) == 1

        # Verify it's the credential finding
        assert 'admin:password123' in selection_choices[0]['finding']['description']

    def test_filter_user(self, mock_profile_with_findings):
        """Test filtering by user type"""
        panel, choices = FindingsPanel.render(
            mock_profile_with_findings,
            filter_type='user'
        )

        # Should have only 1 selection choice (user finding)
        selection_choices = [c for c in choices if c['id'].isdigit()]
        assert len(selection_choices) == 1

    def test_filter_note(self, mock_profile_with_findings):
        """Test filtering by note type"""
        panel, choices = FindingsPanel.render(
            mock_profile_with_findings,
            filter_type='note'
        )

        # Should have only 1 selection choice (note finding)
        selection_choices = [c for c in choices if c['id'].isdigit()]
        assert len(selection_choices) == 1


class TestFindingsPanelPagination:
    """Test pagination functionality"""

    def test_pagination_page_1(self, mock_profile_many_findings):
        """Test first page shows 10 findings"""
        panel, choices = FindingsPanel.render(
            mock_profile_many_findings,
            page=1
        )

        # Should have 10 selection choices (1-10)
        selection_choices = [c for c in choices if c['id'].isdigit()]
        assert len(selection_choices) == 10

        # Should have next page option
        choice_ids = [c['id'] for c in choices]
        assert 'n' in choice_ids

        # Should NOT have previous page option
        assert 'p' not in choice_ids

    def test_pagination_page_2(self, mock_profile_many_findings):
        """Test second page shows 10 findings"""
        panel, choices = FindingsPanel.render(
            mock_profile_many_findings,
            page=2
        )

        # Should have 10 selection choices (1-10)
        selection_choices = [c for c in choices if c['id'].isdigit()]
        assert len(selection_choices) == 10

        # Should have both next and previous page options
        choice_ids = [c['id'] for c in choices]
        assert 'n' in choice_ids
        assert 'p' in choice_ids

    def test_pagination_last_page(self, mock_profile_many_findings):
        """Test last page shows remaining findings"""
        panel, choices = FindingsPanel.render(
            mock_profile_many_findings,
            page=3
        )

        # Should have 5 selection choices (25 total / 10 per page = 3 pages, 5 on last)
        selection_choices = [c for c in choices if c['id'].isdigit()]
        assert len(selection_choices) == 5

        # Should have previous page option
        choice_ids = [c['id'] for c in choices]
        assert 'p' in choice_ids

        # Should NOT have next page option
        assert 'n' not in choice_ids

    def test_pagination_invalid_page(self, mock_profile_many_findings):
        """Test invalid page number clamps to valid range"""
        # Page 0 should clamp to page 1
        panel, choices = FindingsPanel.render(
            mock_profile_many_findings,
            page=0
        )
        selection_choices = [c for c in choices if c['id'].isdigit()]
        assert len(selection_choices) == 10

        # Page 999 should clamp to last page (3)
        panel, choices = FindingsPanel.render(
            mock_profile_many_findings,
            page=999
        )
        selection_choices = [c for c in choices if c['id'].isdigit()]
        assert len(selection_choices) == 5

    def test_pagination_next_page_metadata(self, mock_profile_many_findings):
        """Test next page choice contains correct metadata"""
        panel, choices = FindingsPanel.render(
            mock_profile_many_findings,
            page=1
        )

        # Find next page choice
        next_choice = next((c for c in choices if c['id'] == 'n'), None)
        assert next_choice is not None

        # Should have correct page number
        assert next_choice['page'] == 2
        assert next_choice['action'] == 'next_page'

    def test_pagination_prev_page_metadata(self, mock_profile_many_findings):
        """Test previous page choice contains correct metadata"""
        panel, choices = FindingsPanel.render(
            mock_profile_many_findings,
            page=2
        )

        # Find previous page choice
        prev_choice = next((c for c in choices if c['id'] == 'p'), None)
        assert prev_choice is not None

        # Should have correct page number
        assert prev_choice['page'] == 1
        assert prev_choice['action'] == 'prev_page'


class TestFindingsPanelHelperMethods:
    """Test helper methods"""

    def test_get_finding_icon_vulnerability(self):
        """Test vulnerability icon"""
        icon = FindingsPanel._get_finding_icon('vulnerability')
        assert icon == '🔓'

    def test_get_finding_icon_directory(self):
        """Test directory icon"""
        icon = FindingsPanel._get_finding_icon('directory')
        assert icon == '📁'

    def test_get_finding_icon_credential(self):
        """Test credential icon"""
        icon = FindingsPanel._get_finding_icon('credential')
        assert icon == '🔑'

    def test_get_finding_icon_user(self):
        """Test user icon"""
        icon = FindingsPanel._get_finding_icon('user')
        assert icon == '👤'

    def test_get_finding_icon_note(self):
        """Test note icon"""
        icon = FindingsPanel._get_finding_icon('note')
        assert icon == '📝'

    def test_get_finding_icon_unknown(self):
        """Test unknown type returns default icon"""
        icon = FindingsPanel._get_finding_icon('unknown_type')
        assert icon == '•'

    def test_filter_findings_all(self):
        """Test filter_findings with 'all' type"""
        findings = [
            {'type': 'vulnerability'},
            {'type': 'directory'},
            {'type': 'credential'}
        ]
        result = FindingsPanel._filter_findings(findings, 'all')
        assert len(result) == 3

    def test_filter_findings_specific_type(self):
        """Test filter_findings with specific type"""
        findings = [
            {'type': 'vulnerability'},
            {'type': 'directory'},
            {'type': 'vulnerability'}
        ]
        result = FindingsPanel._filter_findings(findings, 'vulnerability')
        assert len(result) == 2

    def test_filter_findings_case_insensitive(self):
        """Test filter_findings is case-insensitive"""
        findings = [
            {'type': 'Vulnerability'},
            {'type': 'VULNERABILITY'}
        ]
        result = FindingsPanel._filter_findings(findings, 'vulnerability')
        assert len(result) == 2

    def test_truncate_short_text(self):
        """Test truncate with text shorter than max length"""
        text = "Short text"
        result = FindingsPanel._truncate(text, 20)
        assert result == "Short text"

    def test_truncate_long_text(self):
        """Test truncate with text longer than max length"""
        text = "This is a very long text that should be truncated"
        result = FindingsPanel._truncate(text, 20)
        assert len(result) == 20
        assert result.endswith('...')

    def test_format_timestamp_recent(self):
        """Test timestamp formatting for recent findings"""
        # Just now
        now = datetime.now().isoformat()
        result = FindingsPanel._format_timestamp(now)
        assert result == "Just now"

    def test_format_timestamp_minutes_ago(self):
        """Test timestamp formatting for minutes ago"""
        five_mins_ago = (datetime.now() - timedelta(minutes=5)).isoformat()
        result = FindingsPanel._format_timestamp(five_mins_ago)
        assert "m ago" in result

    def test_format_timestamp_hours_ago(self):
        """Test timestamp formatting for hours ago"""
        two_hours_ago = (datetime.now() - timedelta(hours=2)).isoformat()
        result = FindingsPanel._format_timestamp(two_hours_ago)
        assert "h ago" in result

    def test_format_timestamp_days_ago(self):
        """Test timestamp formatting for days ago"""
        three_days_ago = (datetime.now() - timedelta(days=3)).isoformat()
        result = FindingsPanel._format_timestamp(three_days_ago)
        assert "d ago" in result

    def test_format_timestamp_old(self):
        """Test timestamp formatting for old findings"""
        old_date = (datetime.now() - timedelta(days=30)).isoformat()
        result = FindingsPanel._format_timestamp(old_date)
        assert "-" in result  # Should show date format

    def test_format_timestamp_invalid(self):
        """Test timestamp formatting with invalid timestamp"""
        result = FindingsPanel._format_timestamp("invalid-timestamp")
        assert result == "invalid-ti"  # First 10 chars

    def test_format_timestamp_empty(self):
        """Test timestamp formatting with empty timestamp"""
        result = FindingsPanel._format_timestamp("")
        assert result == "Unknown"


class TestFindingsPanelChoiceStructure:
    """Test choice menu structure and metadata"""

    def test_selection_choice_structure(self, mock_profile_with_findings):
        """Test selection choices have correct structure"""
        panel, choices = FindingsPanel.render(mock_profile_with_findings)

        # Get selection choices
        selection_choices = [c for c in choices if c['id'].isdigit()]

        for choice in selection_choices:
            assert 'id' in choice
            assert 'label' in choice
            assert 'action' in choice
            assert 'finding' in choice
            assert choice['action'] == 'view'

    def test_filter_choice_structure(self, mock_profile_with_findings):
        """Test filter choice has correct structure"""
        panel, choices = FindingsPanel.render(
            mock_profile_with_findings,
            filter_type='vulnerability'
        )

        # Find filter choice
        filter_choice = next((c for c in choices if c['id'] == 'f'), None)
        assert filter_choice is not None

        assert filter_choice['action'] == 'filter'
        assert filter_choice['current_filter'] == 'vulnerability'

    def test_export_choice_structure(self, mock_profile_with_findings):
        """Test export choice has correct structure"""
        panel, choices = FindingsPanel.render(mock_profile_with_findings)

        # Find export choice
        export_choice = next((c for c in choices if c['id'] == 'e'), None)
        assert export_choice is not None

        assert export_choice['action'] == 'export'

    def test_back_choice_always_present(self, mock_profile_empty):
        """Test back choice is always present"""
        panel, choices = FindingsPanel.render(mock_profile_empty)

        # Find back choice
        back_choice = next((c for c in choices if c['id'] == 'b'), None)
        assert back_choice is not None

        assert back_choice['action'] == 'back'


class TestFindingsPanelSorting:
    """Test findings sorting (newest first)"""

    def test_findings_sorted_newest_first(self):
        """Test findings are sorted by timestamp (newest first)"""
        profile = TargetProfile('192.168.1.100')

        # Add findings with different timestamps
        old_time = (datetime.now() - timedelta(hours=2)).isoformat()
        new_time = datetime.now().isoformat()
        middle_time = (datetime.now() - timedelta(hours=1)).isoformat()

        # Add in random order
        profile.findings.append({
            'type': 'note',
            'description': 'Old finding',
            'source': 'test',
            'timestamp': old_time
        })
        profile.findings.append({
            'type': 'note',
            'description': 'New finding',
            'source': 'test',
            'timestamp': new_time
        })
        profile.findings.append({
            'type': 'note',
            'description': 'Middle finding',
            'source': 'test',
            'timestamp': middle_time
        })

        # Render panel
        panel, choices = FindingsPanel.render(profile)

        # Get selection choices (should be sorted)
        selection_choices = [c for c in choices if c['id'].isdigit()]

        # First should be newest
        assert 'New finding' in selection_choices[0]['finding']['description']
        # Last should be oldest
        assert 'Old finding' in selection_choices[2]['finding']['description']
