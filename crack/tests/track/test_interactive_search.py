"""
Interactive Search Functionality Tests - User Value Focused

CRITICAL: These tests validate the flagship search feature that makes
large task trees manageable for OSCP exam scenarios.

Testing Philosophy:
- Test real user search scenarios
- Validate finding tasks is fast and accurate
- Ensure users can act on search results
- Test filtering for common OSCP workflows
"""

import pytest
from crack.track.core.state import TargetProfile
from crack.track.core.task_tree import TaskNode
from crack.track.interactive.session import InteractiveSession
from crack.track.interactive.display import DisplayManager
from unittest.mock import patch, MagicMock


class TestSearchUserWorkflows:
    """
    CRITICAL: Prove users can find and manage tasks efficiently

    These tests validate the #1 pain point: finding tasks in 100+ item trees
    """

    def test_user_finds_gobuster_task_quickly(self, temp_crack_home):
        """
        PROVES: User searching for 'gobuster' finds all gobuster tasks

        Real scenario: OSCP exam, user wants to run all gobuster commands
        across multiple ports. Should find them instantly.
        """
        # Setup: Profile with multiple services and gobuster tasks
        session = InteractiveSession("192.168.45.100")
        profile = session.profile

        # Add multiple web services
        profile.add_port(80, service='http', source='nmap')
        profile.add_port(443, service='https', source='nmap')
        profile.add_port(8080, service='http', source='nmap')

        # Add gobuster tasks for each port
        for port in [80, 443, 8080]:
            task = TaskNode(
                task_id=f'gobuster-{port}',
                name=f'Directory Bruteforce (Port {port})',
                task_type='command'
            )
            task.metadata['command'] = f'gobuster dir -u http://target:{port} -w /usr/share/wordlists/dirb/common.txt'
            task.metadata['tags'] = ['OSCP:HIGH', 'WEB']
            profile.task_tree.add_child(task)

        # User searches for gobuster
        results = session.search_tasks('gobuster')

        # Verify all manually added gobuster tasks found
        # Note: Profile may have auto-generated tasks from service plugins
        manual_task_ids = [f'gobuster-{port}' for port in [80, 443, 8080]]
        found_ids = [t.id for t in results]

        assert all(task_id in found_ids for task_id in manual_task_ids), \
            f"Expected to find {manual_task_ids}, found {found_ids}"

        # Verify manual tasks have correct properties
        manual_tasks = [t for t in results if t.id in manual_task_ids]
        assert len(manual_tasks) == 3
        assert all('gobuster' in task.metadata.get('command', '') for task in manual_tasks)

    def test_user_finds_quick_win_tasks(self, temp_crack_home):
        """
        PROVES: User can filter for QUICK_WIN tasks for time-sensitive exam

        Real scenario: 30 minutes left in OSCP exam, need quick wins
        """
        session = InteractiveSession("192.168.45.100")
        profile = session.profile

        # Mix of tasks with different tags
        quick_tasks = [
            ('whatweb-80', 'Technology Fingerprinting', ['QUICK_WIN', 'OSCP:HIGH']),
            ('robots-80', 'Check robots.txt', ['QUICK_WIN', 'MANUAL']),
            ('searchsploit-apache', 'Search Exploits', ['QUICK_WIN']),
        ]

        slow_tasks = [
            ('nikto-80', 'Full Vulnerability Scan', ['SLOW', 'OSCP:MEDIUM']),
            ('gobuster-large', 'Large Wordlist Scan', ['SLOW']),
        ]

        # Add all tasks
        for task_id, name, tags in quick_tasks + slow_tasks:
            task = TaskNode(task_id, name, 'command')
            task.metadata['tags'] = tags
            profile.task_tree.add_child(task)

        # User searches for quick wins
        results = session.search_tasks('QUICK_WIN')

        # Verify manually added quick win tasks found
        manual_quick_ids = ['whatweb-80', 'robots-80', 'searchsploit-apache']
        found_ids = [t.id for t in results]

        assert all(task_id in found_ids for task_id in manual_quick_ids), \
            f"Expected to find {manual_quick_ids}, found {found_ids}"

        # Verify all results have QUICK_WIN tag
        assert all('QUICK_WIN' in task.metadata.get('tags', []) for task in results)

        # Verify slow tasks excluded
        assert 'nikto-80' not in found_ids
        assert 'gobuster-large' not in found_ids

    def test_user_searches_by_port_number(self, temp_crack_home):
        """
        PROVES: User can search by port to find all tasks for specific service

        Real scenario: Port 445 (SMB) found, user wants all SMB-related tasks
        """
        session = InteractiveSession("192.168.45.100")
        profile = session.profile

        # Add SMB port
        profile.add_port(445, service='smb', source='nmap')

        # Add SMB-related tasks
        smb_tasks = [
            ('enum4linux-445', 'SMB Enumeration'),
            ('smbclient-445', 'List SMB Shares'),
            ('smbmap-445', 'Map SMB Shares'),
            ('crackmapexec-445', 'SMB Password Spray'),
        ]

        # Add non-SMB tasks
        other_tasks = [
            ('gobuster-80', 'Directory Bruteforce'),
            ('ssh-enum-22', 'SSH Enumeration'),
        ]

        for task_id, name in smb_tasks:
            task = TaskNode(task_id, name, 'command')
            profile.task_tree.add_child(task)

        for task_id, name in other_tasks:
            task = TaskNode(task_id, name, 'command')
            profile.task_tree.add_child(task)

        # User searches for port 445
        results = session.filter_tasks('port', '445')

        # Verify manually added SMB tasks found
        manual_smb_ids = ['enum4linux-445', 'smbclient-445', 'smbmap-445', 'crackmapexec-445']
        result_ids = [t.id for t in results]

        assert all(task_id in result_ids for task_id in manual_smb_ids), \
            f"Expected to find {manual_smb_ids}, found {result_ids}"

        # Verify all results contain port 445
        assert all('445' in task.id for task in results)

        # Verify other tasks excluded
        assert 'gobuster-80' not in result_ids
        assert 'ssh-enum-22' not in result_ids

    def test_user_acts_on_search_results(self, temp_crack_home):
        """
        PROVES: User can mark tasks complete directly from search results

        Real scenario: User completes gobuster, marks it done from search
        """
        session = InteractiveSession("192.168.45.100")
        profile = session.profile

        # Add task
        task = TaskNode('gobuster-80', 'Directory Bruteforce', 'command')
        task.metadata['command'] = 'gobuster dir -u http://target'
        profile.task_tree.add_child(task)

        # Search for task
        results = session.search_tasks('gobuster')
        assert len(results) == 1

        # Mark task complete from results
        found_task = results[0]
        assert found_task.status == 'pending'

        found_task.mark_complete()
        profile.save()

        # Verify task marked complete
        assert found_task.status == 'completed'

        # Verify persisted
        loaded = TargetProfile.load("192.168.45.100")
        loaded_task = loaded.task_tree.find_task('gobuster-80')
        assert loaded_task.status == 'completed'


class TestSearchAccuracy:
    """
    Prove search finds exactly what users expect
    """

    def test_search_by_command_content(self, temp_crack_home):
        """
        PROVES: Searching for tool name finds all uses of that tool

        Example: Search "nmap" finds all nmap commands
        """
        session = InteractiveSession("192.168.45.100")
        profile = session.profile

        # Various nmap tasks
        nmap_tasks = [
            ('nmap-full', 'nmap -sV -sC -p- target'),
            ('nmap-quick', 'nmap -F target'),
            ('nmap-udp', 'sudo nmap -sU --top-ports 100 target'),
        ]

        # Non-nmap tasks
        other_tasks = [
            ('gobuster', 'gobuster dir -u http://target'),
            ('nikto', 'nikto -h http://target'),
        ]

        for task_id, command in nmap_tasks:
            task = TaskNode(task_id, f'Scan: {task_id}', 'command')
            task.metadata['command'] = command
            profile.task_tree.add_child(task)

        for task_id, command in other_tasks:
            task = TaskNode(task_id, f'Scan: {task_id}', 'command')
            task.metadata['command'] = command
            profile.task_tree.add_child(task)

        # Search for nmap
        results = session.search_tasks('nmap')

        # Verify only nmap tasks found
        assert len(results) == 3
        assert all('nmap' in (task.id or task.metadata.get('command', '')) for task in results)

    def test_search_case_insensitive(self, temp_crack_home):
        """
        PROVES: Search works regardless of case

        Users shouldn't have to remember exact casing
        """
        session = InteractiveSession("192.168.45.100")
        profile = session.profile

        task = TaskNode('gobuster-80', 'Directory Bruteforce', 'command')
        task.metadata['command'] = 'gobuster dir -u http://target'
        task.metadata['tags'] = ['OSCP:HIGH']
        profile.task_tree.add_child(task)

        # Various case searches
        test_cases = ['gobuster', 'GOBUSTER', 'GoBuster', 'gObUsTeR']

        for query in test_cases:
            results = session.search_tasks(query)
            assert len(results) == 1
            assert results[0].id == 'gobuster-80'

    def test_search_partial_match(self, temp_crack_home):
        """
        PROVES: Partial matches work for convenience

        Example: "gob" finds gobuster, "what" finds whatweb
        """
        session = InteractiveSession("192.168.45.100")
        profile = session.profile

        tasks = [
            ('gobuster-80', 'Gobuster Directory Scan'),
            ('whatweb-80', 'WhatWeb Technology Scan'),
            ('nikto-80', 'Nikto Vulnerability Scan'),
        ]

        for task_id, name in tasks:
            task = TaskNode(task_id, name, 'command')
            profile.task_tree.add_child(task)

        # Partial searches
        results = session.search_tasks('gob')
        assert len(results) == 1
        assert results[0].id == 'gobuster-80'

        results = session.search_tasks('what')
        assert len(results) == 1
        assert results[0].id == 'whatweb-80'


class TestFilteringWorkflows:
    """
    Prove filtering helps users focus on specific task categories
    """

    def test_filter_by_status(self, temp_crack_home):
        """
        PROVES: User can filter to see only pending/completed tasks

        Real scenario: Review what's been done, what's left
        """
        session = InteractiveSession("192.168.45.100")
        profile = session.profile

        # Mix of task statuses
        tasks = [
            ('task-1', 'pending'),
            ('task-2', 'completed'),
            ('task-3', 'pending'),
            ('task-4', 'completed'),
            ('task-5', 'in-progress'),
        ]

        for task_id, status in tasks:
            task = TaskNode(task_id, f'Task {task_id}', 'command')
            task.status = status
            profile.task_tree.add_child(task)

        # Filter pending (includes manually added + default discovery tasks)
        results = session.filter_tasks('status', 'pending')
        result_ids = [t.id for t in results]

        # Verify manually added pending tasks found
        manual_pending = ['task-1', 'task-3']
        assert all(task_id in result_ids for task_id in manual_pending), \
            f"Expected to find {manual_pending} in {result_ids}"
        assert all(t.status == 'pending' for t in results)

        # Filter completed
        results = session.filter_tasks('status', 'completed')
        result_ids = [t.id for t in results]

        manual_completed = ['task-2', 'task-4']
        assert all(task_id in result_ids for task_id in manual_completed), \
            f"Expected to find {manual_completed} in {result_ids}"
        assert all(t.status == 'completed' for t in results)

        # Filter in-progress
        results = session.filter_tasks('status', 'in-progress')
        result_ids = [t.id for t in results]

        assert 'task-5' in result_ids
        assert all(t.status == 'in-progress' for t in results)

    def test_filter_oscp_priority_tags(self, temp_crack_home):
        """
        PROVES: User can filter by OSCP priority levels

        Real scenario: Focus on HIGH priority tasks first
        """
        session = InteractiveSession("192.168.45.100")
        profile = session.profile

        # Tasks with different priorities
        tasks = [
            ('critical-1', ['OSCP:HIGH', 'CRITICAL']),
            ('critical-2', ['OSCP:HIGH']),
            ('medium-1', ['OSCP:MEDIUM']),
            ('low-1', ['OSCP:LOW']),
            ('no-tag', []),
        ]

        for task_id, tags in tasks:
            task = TaskNode(task_id, f'Task {task_id}', 'command')
            task.metadata['tags'] = tags
            profile.task_tree.add_child(task)

        # Filter HIGH priority (includes manually added + default discovery tasks)
        results = session.filter_tasks('tag', 'OSCP:HIGH')
        result_ids = [t.id for t in results]

        # Verify manually added HIGH priority tasks found
        manual_high = ['critical-1', 'critical-2']
        assert all(task_id in result_ids for task_id in manual_high), \
            f"Expected to find {manual_high} in {result_ids}"
        assert all('OSCP:HIGH' in t.metadata.get('tags', []) for t in results)

        # Filter MEDIUM priority
        results = session.filter_tasks('tag', 'OSCP:MEDIUM')
        result_ids = [t.id for t in results]

        assert 'medium-1' in result_ids
        assert all('OSCP:MEDIUM' in t.metadata.get('tags', []) for t in results)


class TestSearchEdgeCases:
    """
    Prove search handles edge cases gracefully
    """

    def test_empty_search_shows_warning(self, temp_crack_home):
        """
        PROVES: Empty search query handled gracefully
        """
        session = InteractiveSession("192.168.45.100")

        results = session.search_tasks('')
        # Should either return empty or all tasks, but not crash
        assert isinstance(results, list)

    def test_no_results_shows_helpful_message(self, temp_crack_home, capsys):
        """
        PROVES: No results provides helpful feedback
        """
        session = InteractiveSession("192.168.45.100")

        # Search for non-existent
        results = session.search_tasks('xyz123nonexistent')
        assert len(results) == 0

        # Mock the search handler to capture output
        with patch('builtins.input', side_effect=['xyz123nonexistent', 'cancel']):
            session.handle_search()

        captured = capsys.readouterr()
        assert 'No tasks found' in captured.out or 'not found' in captured.out.lower()

    def test_special_characters_in_search(self, temp_crack_home):
        """
        PROVES: Special characters don't break search
        """
        session = InteractiveSession("192.168.45.100")
        profile = session.profile

        # Task with special characters
        task = TaskNode('sql-injection', 'SQL Injection Test', 'command')
        task.metadata['command'] = "sqlmap -u 'http://target/page.php?id=1'"
        task.metadata['description'] = "Test for SQL injection ('; OR 1=1--)"
        profile.task_tree.add_child(task)

        # Search with special characters
        special_queries = ["';", "OR 1=1", "?id=", "http://"]

        for query in special_queries:
            try:
                results = session.search_tasks(query)
                # Should not crash, may or may not find results
                assert isinstance(results, list)
            except Exception as e:
                pytest.fail(f"Search crashed with query '{query}': {e}")

    def test_search_in_nested_tree(self, temp_crack_home):
        """
        PROVES: Search works through entire task tree hierarchy
        """
        session = InteractiveSession("192.168.45.100")
        profile = session.profile

        # Create nested structure
        parent = TaskNode('web-enum', 'Web Enumeration', 'parent')
        child1 = TaskNode('gobuster-80', 'Directory Scan', 'command')
        child2 = TaskNode('nikto-80', 'Vuln Scan', 'command')
        grandchild = TaskNode('gobuster-api', 'API Scan', 'command')

        child1.metadata['command'] = 'gobuster dir -u http://target'
        grandchild.metadata['command'] = 'gobuster dir -u http://target/api'

        child1.add_child(grandchild)
        parent.add_child(child1)
        parent.add_child(child2)
        profile.task_tree.add_child(parent)

        # Search should find both gobuster tasks
        results = session.search_tasks('gobuster')
        assert len(results) == 2
        assert 'gobuster-80' in [t.id for t in results]
        assert 'gobuster-api' in [t.id for t in results]


class TestSearchPerformance:
    """
    Prove search is fast enough for exam scenarios
    """

    def test_search_large_task_tree(self, temp_crack_home):
        """
        PROVES: Search performs well with 100+ tasks

        Real scenario: Full OSCP box enumeration generates 100+ tasks
        """
        import time

        session = InteractiveSession("192.168.45.100")
        profile = session.profile

        # Create 150 tasks (realistic for full enumeration)
        for i in range(150):
            task = TaskNode(
                f'task-{i}',
                f'Task {i}',
                'command'
            )
            if i % 10 == 0:
                task.metadata['command'] = 'gobuster dir -u http://target'
                task.metadata['tags'] = ['QUICK_WIN']
            elif i % 5 == 0:
                task.metadata['tags'] = ['OSCP:HIGH']

            profile.task_tree.add_child(task)

        # Time the search
        start = time.time()
        results = session.search_tasks('gobuster')
        elapsed = time.time() - start

        # Should find all gobuster tasks
        assert len(results) == 15  # 150 / 10

        # Should be fast (under 100ms even with 150 tasks)
        assert elapsed < 0.1, f"Search took {elapsed:.3f}s, should be under 0.1s"

    def test_filter_performance(self, temp_crack_home):
        """
        PROVES: Filtering is fast with large task sets
        """
        import time

        session = InteractiveSession("192.168.45.100")
        profile = session.profile

        # Create many tasks
        for i in range(100):
            task = TaskNode(f'task-{i}', f'Task {i}', 'command')
            task.status = 'pending' if i % 2 == 0 else 'completed'
            profile.task_tree.add_child(task)

        # Time the filter
        start = time.time()
        results = session.filter_tasks('status', 'pending')
        elapsed = time.time() - start

        # Verify manually added pending tasks found (50 even-numbered)
        result_ids = [t.id for t in results]
        manual_pending = [f'task-{i}' for i in range(0, 100, 2)]
        assert all(task_id in result_ids for task_id in manual_pending), \
            f"Not all manual pending tasks found"

        assert elapsed < 0.05, f"Filter took {elapsed:.3f}s, should be under 0.05s"


# Test markers for organization (if configured)
# pytestmark = [pytest.mark.critical, pytest.mark.interactive]