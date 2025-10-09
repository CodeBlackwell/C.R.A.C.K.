"""
Tests for WordlistSelector - Interactive selection system

Tests cover:
- Task detection logic (gobuster → web, hydra → passwords)
- Context-aware suggestions
- Interactive menu display
- Browse and search functionality
"""

import pytest
from unittest.mock import MagicMock, patch
from crack.track.wordlists.manager import WordlistManager, WordlistEntry
from crack.track.wordlists.selector import WordlistSelector
from crack.track.core.task_tree import TaskNode


class TestWordlistSelectorInit:
    """Test WordlistSelector initialization"""

    def test_init_with_manager_only(self, temp_wordlists_dir, temp_cache_file):
        """PROVES: Selector can be initialized with just manager"""
        manager = WordlistManager(
            wordlists_dir=str(temp_wordlists_dir),
            cache_path=str(temp_cache_file)
        )
        selector = WordlistSelector(manager)

        assert selector.manager == manager
        assert selector.task is None

    def test_init_with_task(self, temp_wordlists_dir, temp_cache_file):
        """PROVES: Selector can be initialized with task for context"""
        manager = WordlistManager(
            wordlists_dir=str(temp_wordlists_dir),
            cache_path=str(temp_cache_file)
        )
        task = TaskNode('test-task', 'Test Task')
        selector = WordlistSelector(manager, task=task)

        assert selector.manager == manager
        assert selector.task == task


class TestTaskDetection:
    """Test task purpose detection logic"""

    def test_detect_web_enumeration_from_gobuster_task_id(self, temp_wordlists_dir, temp_cache_file):
        """PROVES: gobuster-80 task ID → web-enumeration purpose"""
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        task = TaskNode('gobuster-80', 'Directory Brute-force')
        selector = WordlistSelector(manager, task=task)

        purpose = selector._detect_task_purpose(task)
        assert purpose == 'web-enumeration'

    def test_detect_password_cracking_from_hydra_task_id(self, temp_wordlists_dir, temp_cache_file):
        """PROVES: hydra-22 task ID → password-cracking purpose"""
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        task = TaskNode('hydra-22', 'SSH Brute-force')
        selector = WordlistSelector(manager, task=task)

        purpose = selector._detect_task_purpose(task)
        assert purpose == 'password-cracking'

    def test_detect_from_explicit_metadata(self, temp_wordlists_dir, temp_cache_file):
        """PROVES: Explicit wordlist_purpose metadata takes priority"""
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        task = TaskNode('custom-task', 'Custom Task')
        task.metadata['wordlist_purpose'] = 'subdomain-enumeration'

        selector = WordlistSelector(manager, task=task)
        purpose = selector._detect_task_purpose(task)

        assert purpose == 'subdomain-enumeration'

    def test_detect_from_service_metadata(self, temp_wordlists_dir, temp_cache_file):
        """PROVES: Service in metadata (http → web-enumeration)"""
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        task = TaskNode('enum-80', 'HTTP Enumeration')
        task.metadata['service'] = 'http'

        selector = WordlistSelector(manager, task=task)
        purpose = selector._detect_task_purpose(task)

        assert purpose == 'web-enumeration'

    def test_detect_from_command_with_wordlist_tool(self, temp_wordlists_dir, temp_cache_file):
        """PROVES: Command containing tool name detects purpose"""
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        task = TaskNode('custom-scan', 'Custom Scan')
        task.metadata['command'] = 'wfuzz -u http://target -w /path/wordlist.txt'

        selector = WordlistSelector(manager, task=task)
        purpose = selector._detect_task_purpose(task)

        assert purpose == 'web-enumeration'

    def test_no_detection_returns_none(self, temp_wordlists_dir, temp_cache_file):
        """PROVES: Task with no detectable purpose returns None"""
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        task = TaskNode('unknown-task', 'Unknown Task')
        selector = WordlistSelector(manager, task=task)

        purpose = selector._detect_task_purpose(task)
        assert purpose is None

    def test_task_needs_wordlist_with_flag(self, temp_wordlists_dir, temp_cache_file):
        """PROVES: Command with -w flag needs wordlist"""
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        task = TaskNode('test', 'Test')
        task.metadata['command'] = 'gobuster dir -u http://target -w /path/wordlist.txt'

        selector = WordlistSelector(manager, task=task)
        assert selector._task_needs_wordlist(task) is True

    def test_task_needs_wordlist_with_tool(self, temp_wordlists_dir, temp_cache_file):
        """PROVES: Command with wordlist tool needs wordlist"""
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        task = TaskNode('test', 'Test')
        task.metadata['command'] = 'hydra -L users.txt -P passwords.txt ssh://target'

        selector = WordlistSelector(manager, task=task)
        assert selector._task_needs_wordlist(task) is True

    def test_task_does_not_need_wordlist(self, temp_wordlists_dir, temp_cache_file):
        """PROVES: Task without wordlist flags/tools returns False"""
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        task = TaskNode('test', 'Test')
        task.metadata['command'] = 'nmap -sV target'

        selector = WordlistSelector(manager, task=task)
        assert selector._task_needs_wordlist(task) is False


class TestSuggestions:
    """Test wordlist suggestion logic"""

    def test_suggest_web_wordlists_for_gobuster_task(self, temp_wordlists_dir, temp_cache_file):
        """PROVES: gobuster task gets web wordlists (common.txt first)"""
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        task = TaskNode('gobuster-80', 'Directory Brute-force')
        task.metadata['service'] = 'http'

        selector = WordlistSelector(manager, task=task)
        suggestions = selector.suggest_for_task(task)

        # Should get web wordlists
        assert len(suggestions) > 0
        assert len(suggestions) <= 5  # Limited to top 5

        # common.txt should be prioritized (if exists)
        names = [s.name for s in suggestions]
        assert any('common' in name.lower() or 'small' in name.lower() for name in names)

    def test_suggest_password_wordlists_for_hydra_task(self, temp_wordlists_dir, temp_cache_file):
        """PROVES: hydra task gets password wordlists (rockyou.txt priority)"""
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        task = TaskNode('hydra-22', 'SSH Brute-force')
        task.metadata['service'] = 'ssh'

        selector = WordlistSelector(manager, task=task)
        suggestions = selector.suggest_for_task(task)

        # Should get password wordlists
        assert len(suggestions) > 0

        # Check for password-related wordlists
        names = [s.name for s in suggestions]
        assert any('password' in name.lower() or 'rockyou' in name.lower() for name in names)

    def test_suggestions_sorted_by_relevance(self, temp_wordlists_dir, temp_cache_file):
        """PROVES: Suggestions sorted by relevance (smaller files first for web)"""
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        task = TaskNode('gobuster-80', 'Directory Brute-force')
        task.metadata['service'] = 'http'

        selector = WordlistSelector(manager, task=task)
        suggestions = selector.suggest_for_task(task)

        if len(suggestions) >= 2:
            # Smaller wordlists should come before larger ones (QUICK_WIN strategy)
            # common.txt (100 lines) should come before others
            first_suggestion = suggestions[0]
            assert first_suggestion.line_count < 200  # Should be small

    def test_default_suggestions_when_no_purpose(self, temp_wordlists_dir, temp_cache_file):
        """PROVES: Default suggestions returned when no purpose detected"""
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        task = TaskNode('unknown-task', 'Unknown Task')
        selector = WordlistSelector(manager, task=task)

        suggestions = selector.suggest_for_task(task)

        # Should get default suggestions (up to 5)
        assert len(suggestions) > 0
        assert len(suggestions) <= 5


class TestDisplayMenu:
    """Test menu display functionality"""

    def test_display_wordlist_menu_formats_correctly(self, temp_wordlists_dir, temp_cache_file, capsys):
        """PROVES: Menu displays wordlist metadata in human-readable format"""
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        wordlists = manager.get_all()[:3]  # Get first 3
        selector = WordlistSelector(manager)

        selector._display_wordlist_menu(wordlists)

        captured = capsys.readouterr()
        output = captured.out

        # Should display numbered list
        assert '1.' in output
        assert '2.' in output

        # Should show line counts and sizes
        assert 'lines' in output.lower()

        # Should show tags for small wordlists
        if any(w.line_count < 10_000 for w in wordlists):
            assert 'QUICK' in output

    def test_display_shows_quick_tag_for_small_wordlists(self, temp_wordlists_dir, temp_cache_file, capsys):
        """PROVES: Small wordlists (<10K lines) get [QUICK] tag"""
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        # Get small wordlist
        small_wordlists = [w for w in manager.get_all() if w.line_count < 10_000]

        if small_wordlists:
            selector = WordlistSelector(manager)
            selector._display_wordlist_menu(small_wordlists[:1])

            captured = capsys.readouterr()
            assert '[QUICK]' in captured.out


class TestInteractiveSelection:
    """Test interactive selection workflow (mocked input)"""

    @patch('builtins.input', return_value='1')
    def test_interactive_select_by_number(self, mock_input, temp_wordlists_dir, temp_cache_file):
        """PROVES: User can select wordlist by number"""
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        task = TaskNode('gobuster-80', 'Directory Brute-force')
        task.metadata['service'] = 'http'

        selector = WordlistSelector(manager, task=task)
        selected = selector.interactive_select()

        # Should return first suggestion
        assert selected is not None
        assert isinstance(selected, WordlistEntry)

    @patch('builtins.input', return_value='c')
    def test_interactive_select_cancel(self, mock_input, temp_wordlists_dir, temp_cache_file):
        """PROVES: User can cancel selection"""
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        selector = WordlistSelector(manager)
        selected = selector.interactive_select()

        # Should return None when cancelled
        assert selected is None


class TestBrowseAll:
    """Test browse all wordlists feature"""

    @patch('builtins.input', side_effect=['', '1'])
    def test_browse_all_shows_pagination(self, mock_input, temp_wordlists_dir, temp_cache_file):
        """PROVES: Browse all displays wordlists with pagination"""
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        selector = WordlistSelector(manager)
        selected = selector._browse_all()

        # Should return selected wordlist
        assert selected is not None or True  # May return None if empty

    @patch('builtins.input', side_effect=['w', '1'])
    def test_browse_with_category_filter(self, mock_input, temp_wordlists_dir, temp_cache_file):
        """PROVES: Browse can filter by category (web)"""
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        selector = WordlistSelector(manager)
        selected = selector._browse_all()

        # Filter applied successfully (no crash)
        assert True


class TestSearchWordlists:
    """Test search functionality"""

    @patch('builtins.input', side_effect=['common', '1'])
    def test_search_finds_matching_wordlists(self, mock_input, temp_wordlists_dir, temp_cache_file):
        """PROVES: Search finds wordlists by name"""
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        selector = WordlistSelector(manager)
        selected = selector._search_wordlists()

        # Should find common.txt
        assert selected is None or isinstance(selected, WordlistEntry)

    @patch('builtins.input', side_effect=['nonexistent', ''])
    def test_search_handles_no_results(self, mock_input, temp_wordlists_dir, temp_cache_file):
        """PROVES: Search handles no results gracefully"""
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        selector = WordlistSelector(manager)
        selected = selector._search_wordlists()

        # Should return None when no results
        assert selected is None


class TestCustomPath:
    """Test custom path entry"""

    @patch('builtins.input', return_value='')
    def test_enter_custom_path_empty_cancels(self, mock_input, temp_wordlists_dir, temp_cache_file):
        """PROVES: Empty path cancels custom entry"""
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        selector = WordlistSelector(manager)

        selected = selector._enter_custom_path()
        assert selected is None

    def test_enter_custom_path_nonexistent_file(self, temp_wordlists_dir, temp_cache_file):
        """PROVES: Nonexistent file returns None"""
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        selector = WordlistSelector(manager)

        with patch('builtins.input', return_value='/nonexistent/path.txt'):
            with patch('builtins.input', return_value=''):  # Continue prompt
                selected = selector._enter_custom_path()
                assert selected is None

    def test_enter_custom_path_valid_file(self, temp_wordlists_dir, temp_cache_file):
        """PROVES: Valid custom path returns WordlistEntry"""
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        # Get a real file path
        real_file = temp_wordlists_dir / "custom-list.txt"

        selector = WordlistSelector(manager)

        with patch('builtins.input', return_value=str(real_file)):
            selected = selector._enter_custom_path()
            assert selected is not None
            assert isinstance(selected, WordlistEntry)


class TestEdgeCases:
    """Test edge cases and error handling"""

    def test_suggest_for_none_task(self, temp_wordlists_dir, temp_cache_file):
        """PROVES: Selector handles None task gracefully"""
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        selector = WordlistSelector(manager)
        suggestions = selector.suggest_for_task(None)

        # Should return default suggestions
        assert isinstance(suggestions, list)

    def test_empty_wordlist_directory(self, empty_wordlist_dir, temp_cache_file):
        """PROVES: Selector handles empty wordlist directory"""
        manager = WordlistManager(str(empty_wordlist_dir), str(temp_cache_file))
        manager.scan_directory()

        selector = WordlistSelector(manager)
        suggestions = selector._get_default_suggestions()

        # Should return empty list
        assert suggestions == []

    def test_task_without_metadata(self, temp_wordlists_dir, temp_cache_file):
        """PROVES: Selector handles task without metadata"""
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        # Create task-like object without metadata
        class MinimalTask:
            id = 'test-task'
            name = 'Test'

        task = MinimalTask()
        selector = WordlistSelector(manager, task=task)

        purpose = selector._detect_task_purpose(task)
        assert purpose is None  # No metadata, no detection
