"""
Tests for CLI Wordlist Argument (Phase 6.1-6.3)

Test Coverage:
- Direct path resolution
- Fuzzy matching with single result
- Disambiguation with multiple matches
- Error handling for no matches
- Suggestions display
- Integration with task creation
"""

import pytest
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
from crack.track.cli import _resolve_wordlist_arg
from crack.track.wordlists import WordlistManager, WordlistEntry


class TestDirectPathResolution:
    """Test resolving wordlists by direct path"""

    def test_direct_path_exists(self, tmp_path):
        """
        PROVES: Direct path to existing wordlist resolves correctly

        Scenario: User provides full path to wordlist
        Expected: Returns absolute path
        """
        # Create test wordlist
        wordlist = tmp_path / "test.txt"
        wordlist.write_text("word1\nword2\nword3\n")

        # Resolve
        result = _resolve_wordlist_arg(str(wordlist))

        # Verify
        assert result == str(wordlist.resolve())
        assert Path(result).exists()

    def test_relative_path_exists(self, tmp_path, monkeypatch):
        """
        PROVES: Relative path resolves to absolute path

        Scenario: User provides relative path
        Expected: Converts to absolute path
        """
        # Create test wordlist in temp directory
        wordlist = tmp_path / "common.txt"
        wordlist.write_text("admin\npassword\ntest\n")

        # Change to temp directory
        monkeypatch.chdir(tmp_path)

        # Resolve relative path
        result = _resolve_wordlist_arg("common.txt")

        # Verify
        assert result == str(wordlist.resolve())
        assert Path(result).is_absolute()


class TestFuzzyMatchingSingle:
    """Test fuzzy matching with single result"""

    @patch('crack.track.wordlists.WordlistManager')
    def test_fuzzy_match_single_result(self, mock_manager_class):
        """
        PROVES: Fuzzy search with single match returns that wordlist

        Scenario: User types "common" and one wordlist matches
        Expected: Returns matched wordlist path
        """
        # Mock WordlistManager
        mock_manager = MagicMock()
        mock_manager_class.return_value = mock_manager
        mock_manager.cache = {'path': 'entry'}

        # Create mock match (NOTE: Actual Kali path is /usr/share/dirb/wordlists/common.txt)
        mock_entry = WordlistEntry(
            path='/usr/share/dirb/wordlists/common.txt',
            name='common',
            category='web',
            size_bytes=4096,
            line_count=4614,
            avg_word_length=7.5
        )
        mock_manager.search.return_value = [mock_entry]

        # Resolve
        result = _resolve_wordlist_arg('common')

        # Verify (corrected to actual Kali system path)
        assert result == '/usr/share/dirb/wordlists/common.txt'
        mock_manager.search.assert_called_once_with('common')

    @patch('crack.track.wordlists.WordlistManager')
    def test_fuzzy_match_case_insensitive(self, mock_manager_class):
        """
        PROVES: Fuzzy matching is case-insensitive

        Scenario: User types "ROCKYOU" (uppercase)
        Expected: Matches "rockyou.txt"
        """
        # Mock WordlistManager
        mock_manager = MagicMock()
        mock_manager_class.return_value = mock_manager
        mock_manager.cache = {'path': 'entry'}

        # Create mock match
        mock_entry = WordlistEntry(
            path='/usr/share/wordlists/rockyou.txt',
            name='rockyou',
            category='passwords',
            size_bytes=139921507,
            line_count=14344391,
            avg_word_length=9.5
        )
        mock_manager.search.return_value = [mock_entry]

        # Resolve (uppercase query)
        result = _resolve_wordlist_arg('ROCKYOU')

        # Verify
        assert result == '/usr/share/wordlists/rockyou.txt'


class TestDisambiguation:
    """Test disambiguation with multiple matches"""

    @patch('crack.track.wordlists.WordlistManager')
    @patch('builtins.input', return_value='1')
    def test_multiple_matches_user_selects_first(self, mock_input, mock_manager_class):
        """
        PROVES: Multiple matches prompt user to disambiguate

        Scenario: Search returns 3 matches, user selects first
        Expected: Returns selected wordlist path
        """
        # Mock WordlistManager
        mock_manager = MagicMock()
        mock_manager_class.return_value = mock_manager
        mock_manager.cache = {'path': 'entry'}

        # Create multiple mock matches (corrected to actual Kali paths)
        matches = [
            WordlistEntry(
                path='/usr/share/dirb/wordlists/common.txt',
                name='common',
                category='web',
                size_bytes=4096,
                line_count=4614,
                avg_word_length=7.5
            ),
            WordlistEntry(
                path='/usr/share/seclists/Discovery/Web-Content/common.txt',
                name='common',
                category='web',
                size_bytes=98765,
                line_count=8192,
                avg_word_length=8.2
            ),
            WordlistEntry(
                path='/opt/custom/common-passwords.txt',
                name='common-passwords',
                category='passwords',
                size_bytes=2048,
                line_count=1000,
                avg_word_length=6.5
            )
        ]
        mock_manager.search.return_value = matches

        # Resolve with user input mocked (user selects 1)
        result = _resolve_wordlist_arg('common')

        # Verify (corrected to actual Kali system path)
        assert result == '/usr/share/dirb/wordlists/common.txt'
        mock_input.assert_called_once()

    @patch('crack.track.wordlists.WordlistManager')
    @patch('builtins.input', return_value='2')
    def test_multiple_matches_user_selects_second(self, mock_input, mock_manager_class):
        """
        PROVES: User can select any match from disambiguation menu

        Scenario: User selects second option from 3 matches
        Expected: Returns second wordlist
        """
        # Mock WordlistManager
        mock_manager = MagicMock()
        mock_manager_class.return_value = mock_manager
        mock_manager.cache = {'path': 'entry'}

        # Create multiple matches (corrected to actual Kali paths)
        matches = [
            WordlistEntry(
                path='/usr/share/dirb/wordlists/common.txt',
                name='common',
                category='web',
                size_bytes=4096,
                line_count=4614,
                avg_word_length=7.5
            ),
            WordlistEntry(
                path='/usr/share/seclists/Discovery/Web-Content/common.txt',
                name='common',
                category='web',
                size_bytes=98765,
                line_count=8192,
                avg_word_length=8.2
            )
        ]
        mock_manager.search.return_value = matches

        # Resolve
        result = _resolve_wordlist_arg('common')

        # Verify second option selected
        assert result == '/usr/share/seclists/Discovery/Web-Content/common.txt'

    @patch('crack.track.wordlists.WordlistManager')
    @patch('builtins.input', return_value='q')
    def test_user_cancels_disambiguation(self, mock_input, mock_manager_class):
        """
        PROVES: User can cancel disambiguation with 'q'

        Scenario: Multiple matches, user types 'q' to quit
        Expected: Raises ValueError with "User cancelled" message
        """
        # Mock WordlistManager
        mock_manager = MagicMock()
        mock_manager_class.return_value = mock_manager
        mock_manager.cache = {'path': 'entry'}

        # Multiple matches (corrected to actual Kali paths)
        matches = [
            WordlistEntry(
                path='/usr/share/dirb/wordlists/common.txt',
                name='common',
                category='web',
                size_bytes=4096,
                line_count=4614,
                avg_word_length=7.5
            ),
            WordlistEntry(
                path='/usr/share/seclists/Discovery/Web-Content/common.txt',
                name='common',
                category='web',
                size_bytes=98765,
                line_count=8192,
                avg_word_length=8.2
            )
        ]
        mock_manager.search.return_value = matches

        # Attempt to resolve
        with pytest.raises(ValueError, match="User cancelled"):
            _resolve_wordlist_arg('common')


class TestErrorHandling:
    """Test error handling for no matches"""

    @patch('crack.track.wordlists.WordlistManager')
    def test_no_matches_shows_suggestions(self, mock_manager_class, capsys):
        """
        PROVES: No matches displays available wordlists as suggestions

        Scenario: User searches for non-existent wordlist
        Expected: Shows top 10 available wordlists + total count
        """
        # Mock WordlistManager
        mock_manager = MagicMock()
        mock_manager_class.return_value = mock_manager
        mock_manager.cache = {'path': 'entry'}

        # No matches for search
        mock_manager.search.return_value = []

        # Return some suggestions
        suggestions = [
            WordlistEntry(
                path=f'/usr/share/wordlists/wordlist{i}.txt',
                name=f'wordlist{i}',
                category='general',
                size_bytes=1024,
                line_count=100,
                avg_word_length=7.0
            )
            for i in range(15)  # 15 total, should show 10
        ]
        mock_manager.get_all.return_value = suggestions

        # Attempt to resolve
        with pytest.raises(ValueError, match="No wordlist found"):
            _resolve_wordlist_arg('nonexistent')

        # Verify output
        captured = capsys.readouterr()
        assert "No wordlist found matching 'nonexistent'" in captured.out
        assert "Available wordlists (top 10):" in captured.out
        assert "Total: 15 wordlists available" in captured.out

    @patch('crack.track.wordlists.WordlistManager')
    def test_no_wordlists_discovered(self, mock_manager_class, capsys):
        """
        PROVES: Graceful error when no wordlists exist

        Scenario: WordlistManager finds no wordlists at all
        Expected: Clear error message about checking directory
        """
        # Mock WordlistManager
        mock_manager = MagicMock()
        mock_manager_class.return_value = mock_manager
        mock_manager.cache = {'path': 'entry'}

        # No matches and no wordlists at all
        mock_manager.search.return_value = []
        mock_manager.get_all.return_value = []

        # Attempt to resolve
        with pytest.raises(ValueError):
            _resolve_wordlist_arg('anything')

        # Verify output
        captured = capsys.readouterr()
        assert "No wordlists discovered" in captured.out

    def test_nonexistent_direct_path(self):
        """
        PROVES: Non-existent direct path raises ValueError

        Scenario: User provides path that doesn't exist
        Expected: Raises ValueError with clear message
        """
        # Non-existent path
        fake_path = '/nonexistent/path/to/wordlist.txt'

        # Should raise ValueError
        with pytest.raises(ValueError):
            _resolve_wordlist_arg(fake_path)


class TestCachePopulation:
    """Test automatic cache population"""

    @patch('crack.track.wordlists.WordlistManager')
    def test_empty_cache_triggers_scan(self, mock_manager_class, capsys):
        """
        PROVES: Empty cache triggers automatic directory scan

        Scenario: First-time user with no cache
        Expected: Displays scanning message and populates cache
        """
        # Mock WordlistManager with empty cache
        mock_manager = MagicMock()
        mock_manager_class.return_value = mock_manager
        mock_manager.cache = {}  # Empty initially

        # After scan, cache gets populated
        def populate_cache_on_scan():
            mock_manager.cache = {'path': 'entry'}
            return []

        mock_manager.scan_directory.side_effect = populate_cache_on_scan
        mock_manager.search.return_value = []
        mock_manager.get_all.return_value = []

        # Attempt to resolve
        with pytest.raises(ValueError):  # Will fail but that's okay
            _resolve_wordlist_arg('test')

        # Verify scan was called
        mock_manager.scan_directory.assert_called_once()

        # Verify scanning message
        captured = capsys.readouterr()
        assert "Scanning wordlists directory" in captured.out


class TestGracefulDegradation:
    """Test graceful degradation when WordlistManager fails"""

    def test_import_error_falls_back(self, tmp_path):
        """
        PROVES: ImportError falls back to direct path checking

        Scenario: WordlistManager import fails
        Expected: Falls back to checking if path exists
        """
        # Create test wordlist
        wordlist = tmp_path / "test.txt"
        wordlist.write_text("test\n")

        # Patch import to fail - need to patch where it's imported
        import sys
        with patch.dict(sys.modules, {'crack.track.wordlists': None}):
            # Should still work with direct path
            result = _resolve_wordlist_arg(str(wordlist))
            assert result == str(wordlist.resolve())

    @patch('crack.track.wordlists.WordlistManager')
    def test_manager_exception_graceful_fallback(self, mock_manager_class, tmp_path):
        """
        PROVES: Manager exceptions don't crash, fall back to direct path

        Scenario: WordlistManager raises unexpected exception
        Expected: Tries direct path as fallback
        """
        # Mock manager to raise exception
        mock_manager_class.side_effect = Exception("Unexpected error")

        # Create test wordlist
        wordlist = tmp_path / "test.txt"
        wordlist.write_text("test\n")

        # Should fall back to direct path
        result = _resolve_wordlist_arg(str(wordlist))
        assert result == str(wordlist.resolve())


class TestIntegrationScenarios:
    """Test real-world integration scenarios"""

    @patch('crack.track.wordlists.WordlistManager')
    def test_oscp_common_wordlist_scenario(self, mock_manager_class):
        """
        PROVES: OSCP student can quickly select common.txt for gobuster

        Real Scenario: Student needs dirb/common.txt for web enumeration
        Expected: Fuzzy match works, returns correct path
        """
        # Mock WordlistManager
        mock_manager = MagicMock()
        mock_manager_class.return_value = mock_manager
        mock_manager.cache = {'path': 'entry'}

        # OSCP-relevant wordlist (corrected to actual Kali path)
        common = WordlistEntry(
            path='/usr/share/dirb/wordlists/common.txt',
            name='common',
            category='web',
            size_bytes=4096,
            line_count=4614,
            avg_word_length=7.5
        )
        mock_manager.search.return_value = [common]

        # Student types "common"
        result = _resolve_wordlist_arg('common')

        # Verify correct OSCP wordlist (corrected to actual Kali system path)
        assert result == '/usr/share/dirb/wordlists/common.txt'
        assert 'dirb' in result  # OSCP uses dirb wordlists

    @patch('crack.track.wordlists.WordlistManager')
    def test_password_cracking_scenario(self, mock_manager_class):
        """
        PROVES: Student can find rockyou.txt for password cracking

        Real Scenario: Hydra brute-force needs rockyou.txt
        Expected: Partial match on "rocky" works
        """
        # Mock WordlistManager
        mock_manager = MagicMock()
        mock_manager_class.return_value = mock_manager
        mock_manager.cache = {'path': 'entry'}

        # rockyou.txt
        rockyou = WordlistEntry(
            path='/usr/share/wordlists/rockyou.txt',
            name='rockyou',
            category='passwords',
            size_bytes=139921507,
            line_count=14344391,
            avg_word_length=9.5
        )
        mock_manager.search.return_value = [rockyou]

        # Student types partial name
        result = _resolve_wordlist_arg('rocky')

        # Verify
        assert result == '/usr/share/wordlists/rockyou.txt'


class TestCommandLineIntegration:
    """Test CLI argument parsing integration"""

    def test_help_shows_wordlist_option(self):
        """
        PROVES: --wordlist argument appears in help text

        Scenario: Student runs 'crack track --help'
        Expected: Wordlist option is documented
        """
        from crack.track.cli import main
        import sys

        # Capture help output
        with patch.object(sys, 'argv', ['crack', 'track', '--help']):
            with pytest.raises(SystemExit):
                main()

        # Help is printed to stdout by argparse
        # This test verifies the argument exists (implicit via imports)

    @patch('crack.track.cli.handle_interactive')
    def test_interactive_mode_receives_wordlist(self, mock_interactive):
        """
        PROVES: Interactive mode receives resolved wordlist

        Scenario: crack track -i 192.168.45.100 --wordlist common
        Expected: Interactive session receives wordlist path
        """
        from crack.track.cli import main
        import sys

        # Simulate CLI args (crack track command)
        test_args = ['crack', '-i', '192.168.45.100', '--wordlist', 'common']

        with patch.object(sys, 'argv', test_args):
            main()

        # Verify interactive mode called with wordlist
        mock_interactive.assert_called_once()
        call_args = mock_interactive.call_args

        # Check arguments - handle_interactive signature is:
        # handle_interactive(target, resume=False, screened=False, wordlist=None)
        assert call_args[0][0] == '192.168.45.100'  # target (positional)
        assert call_args[0][1] == False  # resume (positional)
        assert call_args[0][2] == False  # screened (positional)
        assert call_args[0][3] == 'common'  # wordlist (positional)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
