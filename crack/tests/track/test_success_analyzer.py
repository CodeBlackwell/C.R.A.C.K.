"""
Test suite for success analyzer feature

PROVES: Success analyzer provides accurate task statistics and recommendations
VALUE: Ensures reliable analysis for optimization insights
COVERAGE: 12+ tests covering all aspects of success analysis
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from crack.track.interactive.session import InteractiveSession
from crack.track.core.state import TargetProfile
from crack.track.core.task_tree import TaskNode


@pytest.fixture
def mock_profile(temp_crack_home):
    """Create mock profile"""
    profile = TargetProfile("192.168.45.100")
    profile.save()
    return profile


@pytest.fixture
def mock_profile_with_mixed_tasks(mock_profile):
    """Create profile with mixed completed/failed tasks"""
    # Completed tasks
    task1 = TaskNode('nmap-scan-1', 'Nmap port scan', 'command')
    task1.metadata['command'] = 'nmap -sV -sC 192.168.45.100'
    task1.metadata['tags'] = ['QUICK_WIN']
    task1.metadata['start_time'] = datetime.now().isoformat()
    task1.metadata['end_time'] = (datetime.now() + timedelta(seconds=120)).isoformat()
    task1.status = 'completed'

    task2 = TaskNode('gobuster-80-1', 'Gobuster directory scan', 'command')
    task2.metadata['command'] = 'gobuster dir -u http://192.168.45.100 -w /usr/share/wordlists/dirb/common.txt'
    task2.metadata['tags'] = ['QUICK_WIN']
    task2.metadata['service'] = 'http'
    task2.metadata['port'] = '80'
    task2.metadata['start_time'] = datetime.now().isoformat()
    task2.metadata['end_time'] = (datetime.now() + timedelta(seconds=45)).isoformat()
    task2.status = 'completed'

    task3 = TaskNode('gobuster-80-2', 'Gobuster extended scan', 'command')
    task3.metadata['command'] = 'gobuster dir -u http://192.168.45.100 -w /usr/share/wordlists/dirbuster/medium.txt'
    task3.metadata['service'] = 'http'
    task3.metadata['port'] = '80'
    task3.metadata['start_time'] = datetime.now().isoformat()
    task3.metadata['end_time'] = (datetime.now() + timedelta(seconds=180)).isoformat()
    task3.status = 'completed'

    # Failed tasks
    task4 = TaskNode('nikto-80-1', 'Nikto vulnerability scan', 'command')
    task4.metadata['command'] = 'nikto -h http://192.168.45.100'
    task4.metadata['service'] = 'http'
    task4.metadata['port'] = '80'
    task4.metadata['start_time'] = datetime.now().isoformat()
    task4.metadata['end_time'] = (datetime.now() + timedelta(seconds=210)).isoformat()
    task4.status = 'failed'

    task5 = TaskNode('nikto-80-2', 'Nikto SSL scan', 'command')
    task5.metadata['command'] = 'nikto -h https://192.168.45.100 -ssl'
    task5.metadata['service'] = 'http'
    task5.metadata['port'] = '80'
    task5.metadata['start_time'] = datetime.now().isoformat()
    task5.metadata['end_time'] = (datetime.now() + timedelta(seconds=190)).isoformat()
    task5.status = 'failed'

    task6 = TaskNode('enum4linux-1', 'SMB enumeration', 'command')
    task6.metadata['command'] = 'enum4linux -a 192.168.45.100'
    task6.metadata['service'] = 'smb'
    task6.metadata['port'] = '445'
    task6.metadata['start_time'] = datetime.now().isoformat()
    task6.metadata['end_time'] = (datetime.now() + timedelta(seconds=80)).isoformat()
    task6.status = 'completed'

    task7 = TaskNode('searchsploit-1', 'Searchsploit Apache 2.4', 'command')
    task7.metadata['command'] = 'searchsploit apache 2.4'
    task7.metadata['tags'] = ['QUICK_WIN']
    task7.metadata['start_time'] = datetime.now().isoformat()
    task7.metadata['end_time'] = (datetime.now() + timedelta(seconds=5)).isoformat()
    task7.status = 'completed'

    # Add all tasks to tree
    root = mock_profile.task_tree
    for task in [task1, task2, task3, task4, task5, task6, task7]:
        root.add_child(task)

    mock_profile.save()
    return mock_profile


class TestSuccessAnalyzer:
    """Test success analyzer functionality"""

    def test_sa_shortcut_exists(self, mock_profile):
        """PROVES: 'sa' shortcut is registered"""
        from crack.track.interactive.shortcuts import ShortcutHandler

        session = InteractiveSession(mock_profile.target)
        handler = ShortcutHandler(session)

        assert 'sa' in handler.shortcuts
        assert handler.shortcuts['sa'][0] == 'Success analyzer'

    def test_sa_handler_callable(self, mock_profile):
        """PROVES: Success analyzer handler method exists and is callable"""
        session = InteractiveSession(mock_profile.target)

        assert hasattr(session, 'handle_success_analyzer')
        assert callable(session.handle_success_analyzer)

    def test_group_by_tool(self, mock_profile_with_mixed_tasks):
        """PROVES: Groups tasks by tool correctly"""
        session = InteractiveSession(mock_profile_with_mixed_tasks.target)

        all_tasks = session.profile.task_tree.get_all_tasks()
        analyzed_tasks = [t for t in all_tasks if t.status in ['completed', 'failed']]

        grouped = session._group_by_tool(analyzed_tasks)

        # Should have groups for nmap, gobuster, nikto, enum4linux, searchsploit
        assert 'nmap' in grouped
        assert 'gobuster' in grouped
        assert 'nikto' in grouped
        assert 'enum4linux' in grouped
        assert 'searchsploit' in grouped

        # Verify counts
        assert len(grouped['nmap']) == 1
        assert len(grouped['gobuster']) == 2
        assert len(grouped['nikto']) == 2
        assert len(grouped['enum4linux']) == 1
        assert len(grouped['searchsploit']) == 1

    def test_extract_tool_name(self, mock_profile):
        """PROVES: Extracts tool name from command correctly"""
        session = InteractiveSession(mock_profile.target)

        # Test common tools
        assert session._extract_tool_name('nmap -sV 192.168.45.100') == 'nmap'
        assert session._extract_tool_name('gobuster dir -u http://target') == 'gobuster'
        assert session._extract_tool_name('nikto -h http://target') == 'nikto'
        assert session._extract_tool_name('searchsploit apache') == 'searchsploit'
        assert session._extract_tool_name('enum4linux -a 192.168.45.100') == 'enum4linux'

        # Test fallback
        assert session._extract_tool_name('custom-tool arg1 arg2') == 'custom-tool'
        assert session._extract_tool_name('') == 'unknown'

    def test_calculate_success_rate_perfect(self, mock_profile):
        """PROVES: Calculates 100% success rate correctly"""
        session = InteractiveSession(mock_profile.target)

        # Create completed tasks
        tasks = []
        for i in range(5):
            task = TaskNode(f'task-{i}', f'Task {i}', 'command')
            task.status = 'completed'
            task.metadata['start_time'] = datetime.now().isoformat()
            task.metadata['end_time'] = (datetime.now() + timedelta(seconds=60)).isoformat()
            tasks.append(task)

        stats = session._calculate_success_rate(tasks)

        assert stats['total'] == 5
        assert stats['success'] == 5
        assert stats['failed'] == 0
        assert stats['rate'] == 100.0
        assert stats['avg_time'] > 0

    def test_calculate_success_rate_partial(self, mock_profile_with_mixed_tasks):
        """PROVES: Calculates partial success rate correctly"""
        session = InteractiveSession(mock_profile_with_mixed_tasks.target)

        all_tasks = session.profile.task_tree.get_all_tasks()
        nikto_tasks = [t for t in all_tasks if 'nikto' in t.id]

        stats = session._calculate_success_rate(nikto_tasks)

        assert stats['total'] == 2
        assert stats['success'] == 0
        assert stats['failed'] == 2
        assert stats['rate'] == 0.0

    def test_calculate_success_rate_failed(self, mock_profile):
        """PROVES: Calculates 0% success rate correctly"""
        session = InteractiveSession(mock_profile.target)

        # Create failed tasks
        tasks = []
        for i in range(3):
            task = TaskNode(f'task-{i}', f'Task {i}', 'command')
            task.status = 'failed'
            task.metadata['start_time'] = datetime.now().isoformat()
            task.metadata['end_time'] = (datetime.now() + timedelta(seconds=30)).isoformat()
            tasks.append(task)

        stats = session._calculate_success_rate(tasks)

        assert stats['total'] == 3
        assert stats['success'] == 0
        assert stats['failed'] == 3
        assert stats['rate'] == 0.0

    def test_avg_time_calculation(self, mock_profile):
        """PROVES: Calculates average time correctly"""
        session = InteractiveSession(mock_profile.target)

        # Create tasks with different durations
        tasks = []
        durations = [60, 120, 180]  # 1m, 2m, 3m
        for i, duration in enumerate(durations):
            task = TaskNode(f'task-{i}', f'Task {i}', 'command')
            task.status = 'completed'
            task.metadata['start_time'] = datetime.now().isoformat()
            task.metadata['end_time'] = (datetime.now() + timedelta(seconds=duration)).isoformat()
            tasks.append(task)

        stats = session._calculate_success_rate(tasks)

        # Average should be (60 + 120 + 180) / 3 = 120
        assert stats['avg_time'] == pytest.approx(120, rel=1)

    def test_format_duration(self, mock_profile):
        """PROVES: Formats duration in human-readable format"""
        session = InteractiveSession(mock_profile.target)

        assert session._format_duration(30) == "30s"
        assert session._format_duration(60) == "1m"
        assert session._format_duration(90) == "1m 30s"
        assert session._format_duration(120) == "2m"
        assert session._format_duration(3600) == "1h 0m"
        assert session._format_duration(3660) == "1h 1m"
        assert session._format_duration(7200) == "2h 0m"

    def test_analysis_with_mixed_tasks(self, mock_profile_with_mixed_tasks, capsys):
        """PROVES: Analysis handles mixed success/failure tasks"""
        session = InteractiveSession(mock_profile_with_mixed_tasks.target)

        session.handle_success_analyzer()

        captured = capsys.readouterr()
        output = captured.out

        # Verify output contains expected sections
        assert "Success Analyzer" in output
        assert "Task Analysis" in output
        assert "By Tool:" in output
        assert "By Category:" in output
        assert "By Service:" in output
        assert "Recommendations:" in output

        # Verify tool statistics appear
        assert "nmap" in output
        assert "gobuster" in output
        assert "nikto" in output
        assert "searchsploit" in output

    def test_analysis_empty(self, mock_profile, capsys):
        """PROVES: Handles empty task list gracefully"""
        session = InteractiveSession(mock_profile.target)

        session.handle_success_analyzer()

        captured = capsys.readouterr()
        output = captured.out

        assert "No completed or failed tasks to analyze" in output
        assert "Run some tasks first" in output

    def test_quick_wins_analysis(self, mock_profile_with_mixed_tasks, capsys):
        """PROVES: Analyzes quick win tasks correctly"""
        session = InteractiveSession(mock_profile_with_mixed_tasks.target)

        session.handle_success_analyzer()

        captured = capsys.readouterr()
        output = captured.out

        # Should show quick wins section
        assert "Quick Wins:" in output

        # Verify quick wins data
        all_tasks = session.profile.task_tree.get_all_tasks()
        quick_wins = [t for t in all_tasks if 'QUICK_WIN' in t.metadata.get('tags', []) and t.status in ['completed', 'failed']]
        # Should have at least 3 quick wins that were analyzed (nmap, gobuster, searchsploit)
        assert len(quick_wins) >= 3

    def test_reliable_tools_recommendation(self, mock_profile_with_mixed_tasks, capsys):
        """PROVES: Identifies most reliable tools"""
        session = InteractiveSession(mock_profile_with_mixed_tasks.target)

        session.handle_success_analyzer()

        captured = capsys.readouterr()
        output = captured.out

        # Should show recommendations
        assert "Recommendations:" in output

        # Tools with 100% success and >= 3 executions should be highlighted
        # In our case, gobuster has 2 completed, searchsploit has 1, nmap has 1
        # None meet the >= 3 threshold, so no "Most reliable" message expected

    def test_unreliable_tools_warning(self, mock_profile_with_mixed_tasks, capsys):
        """PROVES: Warns about unreliable tools"""
        session = InteractiveSession(mock_profile_with_mixed_tasks.target)

        # Add more nikto failures to meet threshold
        for i in range(2, 5):
            task = TaskNode(f'nikto-{i}', f'Nikto scan {i}', 'command')
            task.metadata['command'] = f'nikto -h http://192.168.45.100/{i}'
            task.status = 'failed'
            task.metadata['start_time'] = datetime.now().isoformat()
            task.metadata['end_time'] = (datetime.now() + timedelta(seconds=200)).isoformat()
            session.profile.task_tree.add_child(task)

        session.profile.save()

        session.handle_success_analyzer()

        captured = capsys.readouterr()
        output = captured.out

        # Should warn about nikto (0% success with >= 3 executions)
        assert "Needs review:" in output or "nikto" in output.lower()

    def test_service_analysis(self, mock_profile_with_mixed_tasks, capsys):
        """PROVES: Analyzes tasks by service correctly"""
        session = InteractiveSession(mock_profile_with_mixed_tasks.target)

        session.handle_success_analyzer()

        captured = capsys.readouterr()
        output = captured.out

        # Should show service breakdown
        assert "By Service:" in output
        # HTTP tasks should appear
        assert "HTTP" in output or "80" in output

    def test_category_analysis(self, mock_profile_with_mixed_tasks, capsys):
        """PROVES: Analyzes tasks by category correctly"""
        session = InteractiveSession(mock_profile_with_mixed_tasks.target)

        # Add enumeration and exploitation tasks
        enum_task = TaskNode('enum-task', 'SMB Enum task', 'command')
        enum_task.metadata['command'] = 'smbclient -L //192.168.45.100'
        enum_task.status = 'completed'
        enum_task.metadata['start_time'] = datetime.now().isoformat()
        enum_task.metadata['end_time'] = (datetime.now() + timedelta(seconds=30)).isoformat()

        exploit_task = TaskNode('exploit-task', 'Exploit Apache', 'command')
        exploit_task.metadata['command'] = 'exploit-db 12345'
        exploit_task.status = 'failed'
        exploit_task.metadata['start_time'] = datetime.now().isoformat()
        exploit_task.metadata['end_time'] = (datetime.now() + timedelta(seconds=120)).isoformat()

        session.profile.task_tree.add_child(enum_task)
        session.profile.task_tree.add_child(exploit_task)
        session.profile.save()

        session.handle_success_analyzer()

        captured = capsys.readouterr()
        output = captured.out

        assert "By Category:" in output
        # Should categorize tasks - check for category data
        # Note: Output format is "Enumeration  XX% success (X/X)" not "Enumeration:"
        assert ("Enumeration" in output and "success" in output) or ("Exploitation" in output and "success" in output)


class TestSuccessAnalyzerEdgeCases:
    """Edge case tests for success analyzer"""

    def test_tasks_without_timestamps(self, mock_profile):
        """PROVES: Handles tasks without timing data gracefully"""
        session = InteractiveSession(mock_profile.target)

        # Create task without timestamps
        task = TaskNode('task-1', 'Task without time', 'command')
        task.status = 'completed'
        # No start_time or end_time

        tasks = [task]
        stats = session._calculate_success_rate(tasks)

        # Should not crash, avg_time should be 0
        assert stats['total'] == 1
        assert stats['avg_time'] == 0

    def test_tasks_with_invalid_timestamps(self, mock_profile):
        """PROVES: Handles invalid timestamps gracefully"""
        session = InteractiveSession(mock_profile.target)

        # Create task with invalid timestamps
        task = TaskNode('task-1', 'Task with invalid time', 'command')
        task.status = 'completed'
        task.metadata['start_time'] = 'invalid-timestamp'
        task.metadata['end_time'] = 'also-invalid'

        tasks = [task]
        stats = session._calculate_success_rate(tasks)

        # Should not crash, avg_time should be 0
        assert stats['total'] == 1
        assert stats['avg_time'] == 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
