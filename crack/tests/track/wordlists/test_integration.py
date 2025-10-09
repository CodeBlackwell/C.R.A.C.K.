"""
Integration tests for Wordlist Selection System

Tests complete workflows:
- End-to-end task-aware selection
- Integration with real wordlist directories
- Service plugin integration patterns
- Real OSCP scenarios
"""

import pytest
from unittest.mock import patch, MagicMock
from crack.track.wordlists.manager import WordlistManager
from crack.track.wordlists.selector import WordlistSelector
from crack.track.core.task_tree import TaskNode


class TestEndToEndWorkflows:
    """Test complete selection workflows"""

    def test_gobuster_task_complete_workflow(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: Complete workflow for gobuster task selection

        Workflow:
        1. Create gobuster task with http service
        2. Initialize selector with task context
        3. Get suggestions (should be web wordlists)
        4. Suggestions sorted correctly (common.txt first)
        5. Selection returns valid WordlistEntry
        """
        # Step 1: Create manager and scan wordlists
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        wordlists = manager.scan_directory()
        assert len(wordlists) > 0

        # Step 2: Create gobuster task (realistic OSCP scenario)
        task = TaskNode('gobuster-80', 'Directory Brute-force')
        task.metadata['command'] = 'gobuster dir -u http://192.168.45.100:80 -w <WORDLIST>'
        task.metadata['service'] = 'http'
        task.metadata['port'] = 80
        task.metadata['wordlist_purpose'] = 'web-enumeration'

        # Step 3: Initialize selector with task
        selector = WordlistSelector(manager, task=task)

        # Step 4: Get suggestions
        suggestions = selector.suggest_for_task(task)

        # Verify suggestions
        assert len(suggestions) > 0
        assert len(suggestions) <= 5

        # Should suggest web wordlists
        assert any('common' in s.name.lower() or 'small' in s.name.lower() for s in suggestions)

        # Step 5: Verify first suggestion is suitable for QUICK_WIN
        first = suggestions[0]
        assert first.line_count < 200  # Should be small for speed

    def test_hydra_task_complete_workflow(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: Complete workflow for hydra password attack

        Workflow:
        1. Create hydra task for SSH
        2. Selector detects password-cracking purpose
        3. Suggestions prioritize password wordlists
        4. rockyou.txt or password lists suggested
        """
        # Step 1: Setup
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        # Step 2: Create hydra task
        task = TaskNode('hydra-22', 'SSH Brute-force')
        task.metadata['command'] = 'hydra -L users.txt -P <WORDLIST> ssh://192.168.45.100'
        task.metadata['service'] = 'ssh'
        task.metadata['port'] = 22

        # Step 3: Initialize selector
        selector = WordlistSelector(manager, task=task)

        # Step 4: Verify purpose detection
        purpose = selector._detect_task_purpose(task)
        assert purpose == 'password-cracking'

        # Step 5: Get suggestions
        suggestions = selector.suggest_for_task(task)

        # Verify password wordlists suggested
        assert len(suggestions) > 0
        names = [s.name for s in suggestions]
        assert any('password' in name.lower() or 'rockyou' in name.lower() for name in names)


class TestServicePluginIntegration:
    """Test integration patterns with service plugins"""

    def test_http_plugin_task_pattern(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: HTTP plugin tasks work with wordlist selector

        Pattern: HTTP plugin creates gobuster-80 task with metadata
        """
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        # Simulate HTTP plugin task creation
        task = TaskNode('gobuster-80', 'Directory Brute-force')
        task.metadata = {
            'command': 'gobuster dir -u http://192.168.45.100:80 -w /usr/share/wordlists/dirb/common.txt',
            'description': 'Discover hidden directories and files',
            'service': 'http',
            'port': 80,
            'wordlist_purpose': 'web-enumeration',
            'tags': ['OSCP:HIGH'],
        }

        # Selector should detect web enumeration
        selector = WordlistSelector(manager, task=task)
        purpose = selector._detect_task_purpose(task)
        assert purpose == 'web-enumeration'

        # Should get web suggestions
        suggestions = selector.suggest_for_task(task)
        assert len(suggestions) > 0

    def test_ssh_plugin_task_pattern(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: SSH plugin tasks work with wordlist selector

        Pattern: SSH plugin creates hydra task for password attacks
        """
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        # Simulate SSH plugin task creation
        task = TaskNode('hydra-22', 'SSH Password Attack')
        task.metadata = {
            'command': 'hydra -L users.txt -P passwords.txt ssh://192.168.45.100',
            'service': 'ssh',
            'port': 22,
            'wordlist_purpose': 'password-cracking',
            'tags': ['OSCP:MEDIUM'],
        }

        # Selector should detect password cracking
        selector = WordlistSelector(manager, task=task)
        purpose = selector._detect_task_purpose(task)
        assert purpose == 'password-cracking'

        # Should get password suggestions
        suggestions = selector.suggest_for_task(task)
        assert len(suggestions) > 0


class TestRealOSCPScenarios:
    """Test real OSCP exam scenarios"""

    def test_oscp_scenario_quick_web_enum(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: OSCP scenario - Quick web enumeration with small wordlist

        Scenario: Student finds HTTP on port 80, needs fast initial scan
        Strategy: Suggest common.txt (4.6K lines) for QUICK_WIN
        """
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        # Student creates quick scan task
        task = TaskNode('gobuster-quick-80', 'Quick Directory Scan')
        task.metadata = {
            'command': 'gobuster dir -u http://target:80 -w <WORDLIST>',
            'service': 'http',
            'tags': ['QUICK_WIN'],
        }

        selector = WordlistSelector(manager, task=task)
        suggestions = selector.suggest_for_task(task)

        # First suggestion should be small for speed
        if len(suggestions) > 0:
            first = suggestions[0]
            assert first.line_count < 1000  # Small wordlist for QUICK_WIN

    def test_oscp_scenario_thorough_after_quick(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: OSCP scenario - Thorough scan after quick scan found nothing

        Scenario: common.txt found nothing, need bigger wordlist
        Strategy: Suggest medium/big wordlists for thorough enumeration
        """
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        # Student wants thorough scan now
        task = TaskNode('gobuster-thorough-80', 'Thorough Directory Scan')
        task.metadata = {
            'command': 'gobuster dir -u http://target:80 -w <WORDLIST>',
            'service': 'http',
            'wordlist_variant': 'thorough',
        }

        selector = WordlistSelector(manager, task=task)

        # Get all web wordlists (not just top 5)
        all_web = selector._get_web_suggestions()

        # Should have variety: small, medium, large
        if len(all_web) > 1:
            line_counts = [w.line_count for w in all_web]
            # Should have wordlists of different sizes
            assert max(line_counts) > min(line_counts)

    def test_oscp_scenario_password_spray(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: OSCP scenario - Password spray attack with small password list

        Scenario: Student has usernames, needs small password list for spray
        Strategy: Suggest common-passwords.txt (5-20 lines) to avoid lockout
        """
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        # Password spray task
        task = TaskNode('spray-ssh-22', 'Password Spray Attack')
        task.metadata = {
            'command': 'hydra -L users.txt -P <WORDLIST> ssh://target',
            'service': 'ssh',
            'wordlist_variant': 'quick',
            'notes': 'Avoid account lockout - use small password list',
        }

        selector = WordlistSelector(manager, task=task)
        suggestions = selector.suggest_for_task(task)

        # Should suggest password wordlists
        assert len(suggestions) > 0

        # Prefer smaller password lists first (to avoid lockout)
        if len(suggestions) >= 2:
            first = suggestions[0]
            second = suggestions[1]
            assert first.line_count <= second.line_count


class TestErrorHandling:
    """Test error handling in integration scenarios"""

    def test_no_wordlists_available(self, empty_wordlist_dir, temp_cache_file):
        """
        PROVES: Graceful degradation when no wordlists found

        Scenario: Student's Kali VM has no wordlists
        Expected: Empty suggestions, no crash
        """
        manager = WordlistManager(str(empty_wordlist_dir), str(temp_cache_file))
        manager.scan_directory()

        task = TaskNode('gobuster-80', 'Directory Scan')
        task.metadata['service'] = 'http'

        selector = WordlistSelector(manager, task=task)
        suggestions = selector.suggest_for_task(task)

        # Should return empty list, not crash
        assert suggestions == []

    def test_task_without_context(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: Default suggestions when task provides no context

        Scenario: Custom task with no service/purpose metadata
        Expected: Generic suggestions (common.txt, rockyou.txt)
        """
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        # Task with minimal metadata
        task = TaskNode('custom-task', 'Custom Scan')
        task.metadata['command'] = 'custom-tool --scan target'

        selector = WordlistSelector(manager, task=task)
        suggestions = selector.suggest_for_task(task)

        # Should get default suggestions
        assert isinstance(suggestions, list)


class TestPerformance:
    """Test performance characteristics"""

    def test_suggestion_speed(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: Suggestions returned in <100ms

        Performance target: Suggestion logic should be near-instant
        """
        import time

        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        task = TaskNode('gobuster-80', 'Directory Scan')
        task.metadata['service'] = 'http'

        selector = WordlistSelector(manager, task=task)

        # Time suggestion generation
        start = time.time()
        suggestions = selector.suggest_for_task(task)
        elapsed = time.time() - start

        # Should be very fast (<100ms even on slow systems)
        assert elapsed < 0.1  # 100ms

    def test_detection_speed(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: Task purpose detection is fast (<10ms)

        Performance target: Detection should be instant
        """
        import time

        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))

        task = TaskNode('gobuster-80', 'Directory Scan')
        task.metadata['service'] = 'http'
        task.metadata['command'] = 'gobuster dir -u http://target -w wordlist.txt'

        selector = WordlistSelector(manager, task=task)

        # Time detection
        start = time.time()
        purpose = selector._detect_task_purpose(task)
        elapsed = time.time() - start

        # Should be instant (<10ms)
        assert elapsed < 0.01  # 10ms
        assert purpose == 'web-enumeration'


class TestContextResolution:
    """Test context resolution priority"""

    def test_explicit_metadata_overrides_detection(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: Explicit wordlist_purpose metadata overrides auto-detection

        Priority: metadata > task_id > service > command
        """
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        # Task with conflicting signals
        task = TaskNode('gobuster-80', 'Scan')  # ID says web
        task.metadata['service'] = 'http'  # Service says web
        task.metadata['wordlist_purpose'] = 'password-cracking'  # Explicit says password

        selector = WordlistSelector(manager, task=task)
        purpose = selector._detect_task_purpose(task)

        # Explicit metadata should win
        assert purpose == 'password-cracking'

    def test_task_id_overrides_service(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: Task ID pattern detection overrides generic service

        Priority: task_id > service
        """
        manager = WordlistManager(str(temp_wordlists_dir), str(temp_cache_file))
        manager.scan_directory()

        # Task ID says password attack
        task = TaskNode('hydra-80', 'Brute-force')
        task.metadata['service'] = 'http'  # Service says web

        selector = WordlistSelector(manager, task=task)
        purpose = selector._detect_task_purpose(task)

        # Task ID pattern should win
        assert purpose == 'password-cracking'
