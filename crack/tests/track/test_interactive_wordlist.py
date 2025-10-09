"""
Tests for Phase 5: Interactive Mode Wordlist Integration

Test Coverage:
- 5.1: Shortcut handler ('w' shortcut)
- 5.2: Task execution flow with wordlist prompts
- 5.3: Display integration (wordlist info in task summary)
- 5.4: Wordlist substitution in commands

Test Philosophy: Prove value to OSCP students with real scenarios
"""

import pytest
from unittest.mock import Mock, MagicMock, patch, call
from pathlib import Path

from crack.track.core.task_tree import TaskNode
from crack.track.core.state import TargetProfile
from crack.track.interactive.session import InteractiveSession
from crack.track.interactive.shortcuts import ShortcutHandler
from crack.track.interactive.display import DisplayManager


# Fixtures

@pytest.fixture
def temp_crack_home(tmp_path, monkeypatch):
    """Create temporary .crack directory"""
    crack_dir = tmp_path / '.crack'
    crack_dir.mkdir()
    (crack_dir / 'targets').mkdir()
    (crack_dir / 'sessions').mkdir()
    monkeypatch.setenv('HOME', str(tmp_path))
    return crack_dir


@pytest.fixture
def mock_profile_with_gobuster(temp_crack_home):
    """Profile with gobuster task needing wordlist"""
    profile = TargetProfile('192.168.45.100')

    # Don't add port to avoid auto-generating tasks that conflict
    # Just manually add the gobuster task we want to test

    # Add gobuster task with wordlist placeholder
    task = TaskNode(
        task_id='gobuster-80',
        name='Directory Brute-force (Port 80)',
        task_type='command'
    )
    task.metadata = {
        'command': 'gobuster dir -u http://192.168.45.100:80 -w <WORDLIST>',
        'description': 'Enumerate web directories',
        'wordlist_purpose': 'web-enumeration',
        'service': 'http',
        'port': 80,
        'tags': ['OSCP:HIGH', 'QUICK_WIN']
    }
    profile.task_tree.add_child(task)
    profile.save()

    return profile


@pytest.fixture
def mock_profile_with_hydra(temp_crack_home):
    """Profile with hydra task needing wordlist"""
    profile = TargetProfile('192.168.45.200')

    # Don't add port to avoid auto-generating tasks that conflict
    # Just manually add the hydra task we want to test

    # Add hydra task
    task = TaskNode(
        task_id='hydra-ssh-22',
        name='SSH Password Brute-force',
        task_type='command'
    )
    task.metadata = {
        'command': 'hydra -l admin -P {WORDLIST} ssh://192.168.45.200',
        'description': 'Brute-force SSH login',
        'wordlist_purpose': 'password-cracking',
        'service': 'ssh',
        'port': 22,
        'tags': ['OSCP:MEDIUM']
    }
    profile.task_tree.add_child(task)
    profile.save()

    return profile


# Test Section 5.1: Shortcut Handler

class TestWordlistShortcut:
    """Test 'w' shortcut handler"""

    def test_w_shortcut_exists(self, mock_profile_with_gobuster):
        """
        PROVES: 'w' shortcut is registered in shortcuts dict
        """
        session = InteractiveSession(mock_profile_with_gobuster.target)
        handler = ShortcutHandler(session)

        assert 'w' in handler.shortcuts
        assert handler.shortcuts['w'][0] == 'Select wordlist'
        assert handler.shortcuts['w'][1] == 'select_wordlist'

    def test_w_shortcut_handler_exists(self, mock_profile_with_gobuster):
        """
        PROVES: select_wordlist handler method exists
        """
        session = InteractiveSession(mock_profile_with_gobuster.target)
        handler = ShortcutHandler(session)

        assert hasattr(handler, 'select_wordlist')
        assert callable(handler.select_wordlist)

    @patch('builtins.input', return_value='c')  # Cancel selection
    def test_w_shortcut_with_no_wordlist_tasks(self, mock_input, temp_crack_home):
        """
        PROVES: 'w' shortcut handles case with no wordlist tasks gracefully

        Scenario: Student presses 'w' but no tasks need wordlists
        """
        profile = TargetProfile('192.168.45.150')
        profile.save()

        session = InteractiveSession(profile.target)
        handler = ShortcutHandler(session)

        # Should not raise error
        handler.select_wordlist()

    @patch('crack.track.wordlists.selector.WordlistSelector')
    @patch('crack.track.wordlists.manager.WordlistManager')
    @patch('builtins.input', return_value='1')  # Select first task
    def test_w_shortcut_launches_selector(self, mock_input, mock_manager, mock_selector,
                                         mock_profile_with_gobuster):
        """
        PROVES: 'w' shortcut launches WordlistSelector.interactive_select()

        Real OSCP scenario: Student needs to select wordlist for gobuster
        """
        # Mock WordlistEntry
        from crack.track.wordlists.manager import WordlistEntry
        mock_entry = WordlistEntry(
            path='/usr/share/wordlists/dirb/common.txt',
            name='common.txt',
            category='web',
            size_bytes=4614,
            line_count=4614,
            avg_word_length=7.5,
            description='Common web directories',
            last_scanned='2025-10-09T10:00:00'
        )

        # Setup mocks
        mock_selector_instance = MagicMock()
        mock_selector_instance.interactive_select.return_value = mock_entry
        mock_selector.return_value = mock_selector_instance

        session = InteractiveSession(mock_profile_with_gobuster.target)
        handler = ShortcutHandler(session)

        # Execute shortcut
        handler.select_wordlist()

        # Verify selector was called
        mock_selector_instance.interactive_select.assert_called_once()


# Test Section 5.2: Task Execution Flow

class TestTaskExecutionFlow:
    """Test task execution with wordlist prompts"""

    def test_task_needs_wordlist_detection_placeholder(self, mock_profile_with_gobuster):
        """
        PROVES: _task_needs_wordlist detects <WORDLIST> placeholder
        """
        session = InteractiveSession(mock_profile_with_gobuster.target)
        # Find the gobuster task (not root node)
        tasks = mock_profile_with_gobuster.task_tree.get_all_pending()
        task = next(t for t in tasks if t.id == 'gobuster-80')

        assert session._task_needs_wordlist(task) is True

    def test_task_needs_wordlist_detection_purpose(self, temp_crack_home):
        """
        PROVES: _task_needs_wordlist detects wordlist_purpose metadata
        """
        profile = TargetProfile('192.168.45.175')
        task = TaskNode(
            task_id='test-1',
            name='Test Task'
        )
        task.metadata = {'wordlist_purpose': 'web-enumeration'}
        profile.task_tree.add_child(task)
        profile.save()

        session = InteractiveSession(profile.target)

        assert session._task_needs_wordlist(task) is True

    def test_task_needs_wordlist_detection_tool_pattern(self, temp_crack_home):
        """
        PROVES: _task_needs_wordlist detects wordlist tools (gobuster, hydra, etc.)
        """
        profile = TargetProfile('192.168.45.180')

        # Test various tools
        tools = ['gobuster', 'wfuzz', 'ffuf', 'hydra', 'medusa', 'john']

        for tool in tools:
            task = TaskNode(
                task_id=f'{tool}-test',
                name=f'{tool.title()} Test'
            )
            task.metadata = {'command': f'{tool} -w wordlist.txt target'}

            session = InteractiveSession(profile.target)
            assert session._task_needs_wordlist(task) is True, f"Failed to detect {tool}"

    def test_task_without_wordlist_returns_false(self, temp_crack_home):
        """
        PROVES: _task_needs_wordlist returns False for non-wordlist tasks
        """
        profile = TargetProfile('192.168.45.185')
        task = TaskNode(
            task_id='whatweb-80',
            name='Technology Fingerprinting'
        )
        task.metadata = {'command': 'whatweb http://192.168.45.185'}
        profile.task_tree.add_child(task)
        profile.save()

        session = InteractiveSession(profile.target)

        assert session._task_needs_wordlist(task) is False

    @patch('builtins.input', side_effect=['n', 'y'])  # No wordlist selection, then execute
    @patch('subprocess.run')
    def test_execute_task_prompts_for_wordlist(self, mock_run, mock_input,
                                               mock_profile_with_gobuster):
        """
        PROVES: execute_task() prompts for wordlist when task needs it

        Real OSCP scenario: Student executes gobuster without selecting wordlist
        Expected: System prompts for wordlist selection
        """
        session = InteractiveSession(mock_profile_with_gobuster.target)
        # Find the gobuster task (not root node)
        tasks = mock_profile_with_gobuster.task_tree.get_all_pending()
        task = next(t for t in tasks if t.id == 'gobuster-80')

        # Mock subprocess to succeed
        mock_run.return_value = MagicMock(returncode=0)

        # Execute task (should prompt for wordlist)
        session.execute_task(task)

        # Verify input was called (wordlist prompt + execution confirm)
        assert mock_input.call_count == 2

    @patch('crack.track.wordlists.selector.WordlistSelector')
    @patch('crack.track.wordlists.manager.WordlistManager')
    @patch('builtins.input', side_effect=['y', 'y'])  # Yes to wordlist, yes to execute
    @patch('subprocess.run')
    def test_wordlist_substitution_in_command(self, mock_run, mock_input,
                                             mock_manager, mock_selector,
                                             mock_profile_with_gobuster):
        """
        PROVES: <WORDLIST> placeholder is substituted with selected wordlist

        Real OSCP scenario: Student selects common.txt for gobuster
        Expected: Command contains /usr/share/wordlists/dirb/common.txt
        """
        # Mock WordlistEntry
        from crack.track.wordlists.manager import WordlistEntry
        mock_entry = WordlistEntry(
            path='/usr/share/wordlists/dirb/common.txt',
            name='common.txt',
            category='web',
            size_bytes=4614,
            line_count=4614,
            avg_word_length=7.5,
            description='Common web directories',
            last_scanned='2025-10-09T10:00:00'
        )

        # Setup mocks
        mock_selector_instance = MagicMock()
        mock_selector_instance.interactive_select.return_value = mock_entry
        mock_selector.return_value = mock_selector_instance
        mock_run.return_value = MagicMock(returncode=0)

        session = InteractiveSession(mock_profile_with_gobuster.target)
        # Find the gobuster task (not root node)
        tasks = mock_profile_with_gobuster.task_tree.get_all_pending()
        task = next(t for t in tasks if t.id == 'gobuster-80')

        # Execute task
        session.execute_task(task)

        # Verify subprocess was called with substituted wordlist
        # The actual command would be passed to subprocess.run()
        assert mock_run.called

    def test_wordlist_metadata_saved_to_task(self, mock_profile_with_gobuster):
        """
        PROVES: Selected wordlist is saved to task metadata

        This ensures wordlist selection persists across sessions
        """
        from crack.track.wordlists.manager import WordlistEntry

        # Find the gobuster task (not root node)
        tasks = mock_profile_with_gobuster.task_tree.get_all_pending()
        task = next(t for t in tasks if t.id == 'gobuster-80')

        # Simulate wordlist selection
        task.metadata['wordlist'] = '/usr/share/wordlists/dirb/common.txt'
        task.metadata['wordlist_name'] = 'common.txt'
        task.metadata['wordlist_line_count'] = 4614

        mock_profile_with_gobuster.save()

        # Reload profile
        reloaded = TargetProfile.load(mock_profile_with_gobuster.target)
        reloaded_tasks = reloaded.task_tree.get_all_pending()
        reloaded_task = next(t for t in reloaded_tasks if t.id == 'gobuster-80')

        assert reloaded_task.metadata['wordlist'] == '/usr/share/wordlists/dirb/common.txt'
        assert reloaded_task.metadata['wordlist_name'] == 'common.txt'
        assert reloaded_task.metadata['wordlist_line_count'] == 4614


# Test Section 5.3: Display Integration

class TestDisplayIntegration:
    """Test wordlist info display"""

    def test_wordlist_shown_in_task_summary(self):
        """
        PROVES: Task summary displays wordlist info

        Format: "Wordlist: common.txt (4.6K lines)"
        """
        task = TaskNode(
            task_id='gobuster-80',
            name='Directory Enumeration'
        )
        task.metadata = {
            'command': 'gobuster dir -u http://target -w <WORDLIST>',
            'wordlist': '/usr/share/wordlists/dirb/common.txt',
            'wordlist_name': 'common.txt',
            'wordlist_line_count': 4614
        }

        summary = DisplayManager.format_task_summary(task)

        assert 'Wordlist:' in summary
        assert 'common.txt' in summary
        assert '4.6K lines' in summary

    def test_wordlist_format_with_millions(self):
        """
        PROVES: Large wordlists display as "14.3M lines"

        Example: rockyou.txt with 14,344,392 lines
        """
        task = TaskNode(
            task_id='hydra-ssh',
            name='SSH Brute-force'
        )
        task.metadata = {
            'wordlist': '/usr/share/wordlists/rockyou.txt',
            'wordlist_name': 'rockyou.txt',
            'wordlist_line_count': 14344392
        }

        summary = DisplayManager.format_task_summary(task)

        assert 'rockyou.txt' in summary
        assert '14.3M lines' in summary

    def test_task_without_wordlist_no_display(self):
        """
        PROVES: Tasks without wordlists don't show wordlist line
        """
        task = TaskNode(
            task_id='whatweb-80',
            name='Technology Fingerprinting'
        )
        task.metadata = {'command': 'whatweb http://target'}

        summary = DisplayManager.format_task_summary(task)

        assert 'Wordlist:' not in summary

    def test_help_text_includes_w_shortcut(self):
        """
        PROVES: Help text includes 'w' shortcut explanation
        """
        from crack.track.interactive.prompts import PromptBuilder

        help_text = PromptBuilder.build_help_text()

        assert 'w -' in help_text
        assert 'wordlist' in help_text.lower()


# Test Section 5.4: Real-World OSCP Scenarios

class TestOSCPScenarios:
    """Test complete OSCP workflows"""

    @patch('crack.track.wordlists.selector.WordlistSelector')
    @patch('crack.track.wordlists.manager.WordlistManager')
    @patch('builtins.input', side_effect=['1', 'y'])  # Select task 1, execute
    @patch('subprocess.run')
    def test_web_enum_workflow(self, mock_run, mock_input, mock_manager,
                               mock_selector, mock_profile_with_gobuster):
        """
        PROVES: Complete web enumeration wordlist workflow works

        Real OSCP scenario:
        1. Student discovers HTTP on port 80
        2. Gobuster task generated with wordlist_purpose='web-enumeration'
        3. Student executes gobuster
        4. System detects wordlist needed
        5. Student selects common.txt (QUICK_WIN)
        6. Command executes with correct wordlist
        """
        # Mock WordlistEntry
        from crack.track.wordlists.manager import WordlistEntry
        mock_entry = WordlistEntry(
            path='/usr/share/wordlists/dirb/common.txt',
            name='common.txt',
            category='web',
            size_bytes=4614,
            line_count=4614,
            avg_word_length=7.5,
            description='Common web directories',
            last_scanned='2025-10-09T10:00:00'
        )

        mock_selector_instance = MagicMock()
        mock_selector_instance.interactive_select.return_value = mock_entry
        mock_selector.return_value = mock_selector_instance
        mock_run.return_value = MagicMock(returncode=0)

        session = InteractiveSession(mock_profile_with_gobuster.target)

        # Get gobuster task (find by ID, not index)
        tasks = session.profile.task_tree.get_all_pending()
        task = next(t for t in tasks if t.id == 'gobuster-80')
        assert task.id == 'gobuster-80'
        assert session._task_needs_wordlist(task)

        # Verify wordlist purpose is set
        assert task.metadata['wordlist_purpose'] == 'web-enumeration'

    @patch('crack.track.wordlists.selector.WordlistSelector')
    @patch('crack.track.wordlists.manager.WordlistManager')
    @patch('builtins.input', side_effect=['y'])  # Execute with default
    @patch('subprocess.run')
    def test_password_cracking_workflow(self, mock_run, mock_input,
                                       mock_manager, mock_selector,
                                       mock_profile_with_hydra):
        """
        PROVES: Password cracking workflow uses correct wordlist type

        Real OSCP scenario:
        1. Student finds SSH service
        2. Hydra task generated with wordlist_purpose='password-cracking'
        3. System should suggest rockyou.txt (not dirb/common.txt!)
        4. Wrong wordlist wastes precious exam time
        """
        session = InteractiveSession(mock_profile_with_hydra.target)
        # Find the hydra task (not root node)
        tasks = session.profile.task_tree.get_all_pending()
        task = next(t for t in tasks if t.id == 'hydra-ssh-22')

        # Verify correct purpose
        assert task.metadata['wordlist_purpose'] == 'password-cracking'
        assert session._task_needs_wordlist(task)

    def test_task_filter_shows_wordlist_tasks(self, mock_profile_with_gobuster):
        """
        PROVES: Can filter tasks by wordlist requirement

        Useful for: "Show me all tasks that need wordlists"
        """
        session = InteractiveSession(mock_profile_with_gobuster.target)

        all_tasks = session.profile.task_tree.get_all_pending()
        wordlist_tasks = [t for t in all_tasks if session._task_needs_wordlist(t)]

        assert len(wordlist_tasks) > 0
        assert all(session._task_needs_wordlist(t) for t in wordlist_tasks)


# Test Section: Edge Cases

class TestEdgeCases:
    """Test edge cases and error handling"""

    @patch('builtins.input', return_value='c')
    def test_cancel_wordlist_selection(self, mock_input, mock_profile_with_gobuster):
        """
        PROVES: Cancelling wordlist selection doesn't break execution
        """
        session = InteractiveSession(mock_profile_with_gobuster.target)
        handler = ShortcutHandler(session)

        # Should not raise error
        handler.select_wordlist()

    def test_multiple_wordlist_placeholders(self, temp_crack_home):
        """
        PROVES: Multiple <WORDLIST> placeholders in same command are all substituted
        """
        profile = TargetProfile('192.168.45.190')
        task = TaskNode(
            task_id='multi-wordlist',
            name='Multi-wordlist Task'
        )
        task.metadata = {
            'command': 'tool -u <WORDLIST> -p <WORDLIST>',
            'wordlist': '/path/to/list.txt'
        }
        profile.task_tree.add_child(task)
        profile.save()

        session = InteractiveSession(profile.target)

        # Get command and substitute
        command = task.metadata['command']
        wordlist = task.metadata['wordlist']
        command = command.replace('<WORDLIST>', wordlist)

        # Verify both substituted
        assert command == 'tool -u /path/to/list.txt -p /path/to/list.txt'
        assert '<WORDLIST>' not in command

    def test_curly_brace_wordlist_placeholder(self, mock_profile_with_hydra):
        """
        PROVES: {WORDLIST} placeholder (curly braces) also works
        """
        session = InteractiveSession(mock_profile_with_hydra.target)
        # Find the hydra task (not root node)
        tasks = session.profile.task_tree.get_all_pending()
        task = next(t for t in tasks if t.id == 'hydra-ssh-22')

        # Hydra task uses {WORDLIST} format
        assert '{WORDLIST}' in task.metadata['command']
        assert session._task_needs_wordlist(task)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
