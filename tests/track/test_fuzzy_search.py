"""
Test fuzzy search functionality for CRACK Track Interactive Mode

Tests:
1. Fuzzy matching algorithm accuracy
2. Search scoring and ranking
3. Search refinement workflow
4. /search command support
5. Performance benchmarks
"""

import pytest
import sys
import time
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from crack.track.core.state import TargetProfile
from crack.track.core.task_tree import TaskNode
from crack.track.interactive.session import InteractiveSession
from crack.track.interactive.input_handler import InputProcessor


class TestFuzzyMatchingAlgorithm:
    """Test fuzzy matching algorithm behavior"""

    def test_exact_match_scores_100(self, temp_crack_home):
        """Exact matches should score 100"""
        profile = TargetProfile("192.168.45.100")
        profile.save()

        session = InteractiveSession(profile.target)

        # Test exact match
        is_match, score = session._fuzzy_match("gobuster", "gobuster")
        assert is_match is True
        assert score == 100

    def test_substring_match_scores_80(self, temp_crack_home):
        """Substring matches should score 80"""
        profile = TargetProfile("192.168.45.100")
        profile.save()

        session = InteractiveSession(profile.target)

        # Test substring match
        is_match, score = session._fuzzy_match("gob", "gobuster")
        assert is_match is True
        assert score == 80

    def test_partial_char_match_scores_lower(self, temp_crack_home):
        """Partial character matches should score between 50-70"""
        profile = TargetProfile("192.168.45.100")
        profile.save()

        session = InteractiveSession(profile.target)

        # Test partial match (all chars present in order)
        is_match, score = session._fuzzy_match("gbstr", "gobuster")
        assert is_match is True
        assert 50 <= score <= 70

    def test_insufficient_match_returns_false(self, temp_crack_home):
        """Matches with <50% chars should return False"""
        profile = TargetProfile("192.168.45.100")
        profile.save()

        session = InteractiveSession(profile.target)

        # Test insufficient match
        is_match, score = session._fuzzy_match("xyz", "gobuster")
        assert is_match is False
        assert score == 0

    def test_case_insensitive_matching(self, temp_crack_home):
        """Matching should be case-insensitive"""
        profile = TargetProfile("192.168.45.100")
        profile.save()

        session = InteractiveSession(profile.target)

        # Test case variations
        is_match1, score1 = session._fuzzy_match("GOBUSTER", "gobuster")
        is_match2, score2 = session._fuzzy_match("GoBuStEr", "gobuster")

        assert is_match1 is True
        assert is_match2 is True
        assert score1 == 100
        assert score2 == 100


class TestSearchScoringAndRanking:
    """Test search result scoring and ranking"""

    @pytest.fixture
    def profile_with_tasks(self, temp_crack_home):
        """Create profile with multiple searchable tasks"""
        profile = TargetProfile("192.168.45.100")

        # Add diverse tasks
        tasks = [
            {
                'id': 'gobuster-80',
                'name': 'Gobuster Directory Brute-force',
                'metadata': {
                    'command': 'gobuster dir -u http://target -w wordlist.txt',
                    'tags': ['QUICK_WIN', 'HTTP'],
                    'description': 'Brute-force directories'
                }
            },
            {
                'id': 'nikto-80',
                'name': 'Nikto Vulnerability Scan',
                'metadata': {
                    'command': 'nikto -h http://target',
                    'tags': ['SCAN', 'HTTP'],
                    'description': 'Web vulnerability scanner'
                }
            },
            {
                'id': 'enum4linux',
                'name': 'SMB Enumeration',
                'metadata': {
                    'command': 'enum4linux -a target',
                    'tags': ['SMB', 'ENUM'],
                    'description': 'SMB service enumeration'
                }
            },
            {
                'id': 'sqlmap-test',
                'name': 'SQL Injection Test',
                'metadata': {
                    'command': 'sqlmap -u http://target?id=1',
                    'tags': ['SQL', 'INJECTION'],
                    'description': 'Test for SQL injection'
                }
            }
        ]

        for task_data in tasks:
            task = TaskNode(
                task_id=task_data['id'],
                name=task_data['name'],
                task_type='command'
            )
            task.metadata.update(task_data['metadata'])
            profile.task_tree.add_child(task)

        profile.save()
        return profile

    def test_exact_name_match_ranks_highest(self, profile_with_tasks):
        """Exact name matches should rank first"""
        session = InteractiveSession(profile_with_tasks.target)

        results = session.search_tasks("gobuster")

        assert len(results) > 0
        top_task, top_score = results[0]
        assert "gobuster" in top_task.name.lower()
        assert top_score >= 80  # Exact or substring match

    def test_results_sorted_by_score_descending(self, profile_with_tasks):
        """Results should be sorted by score (highest first)"""
        session = InteractiveSession(profile_with_tasks.target)

        results = session.search_tasks("http")

        # Verify descending order
        if len(results) > 1:
            for i in range(len(results) - 1):
                assert results[i][1] >= results[i + 1][1]

    def test_tag_matching_works(self, profile_with_tasks):
        """Search should match tags"""
        session = InteractiveSession(profile_with_tasks.target)

        results = session.search_tasks("QUICK_WIN")

        assert len(results) > 0
        task, score = results[0]
        assert 'QUICK_WIN' in task.metadata.get('tags', [])

    def test_command_matching_works(self, profile_with_tasks):
        """Search should match command text"""
        session = InteractiveSession(profile_with_tasks.target)

        results = session.search_tasks("sqlmap")

        assert len(results) > 0
        task, score = results[0]
        assert "sqlmap" in task.metadata.get('command', '').lower()

    def test_description_matching_works(self, profile_with_tasks):
        """Search should match descriptions"""
        session = InteractiveSession(profile_with_tasks.target)

        results = session.search_tasks("brute-force")

        assert len(results) > 0
        task, score = results[0]
        assert "brute" in task.metadata.get('description', '').lower()

    def test_min_score_threshold_filters_results(self, profile_with_tasks):
        """min_score parameter should filter low-score matches"""
        session = InteractiveSession(profile_with_tasks.target)

        # High threshold
        high_results = session.search_tasks("gob", min_score=80)

        # Low threshold
        low_results = session.search_tasks("gob", min_score=40)

        # Low threshold should return same or more results
        assert len(low_results) >= len(high_results)

    def test_best_match_across_fields_wins(self, profile_with_tasks):
        """If query matches multiple fields, best score is used"""
        session = InteractiveSession(profile_with_tasks.target)

        results = session.search_tasks("http")

        # "http" appears in multiple tasks (command, tags, description)
        # Verify we get results and they're scored appropriately
        assert len(results) >= 2

        for task, score in results:
            # Each result should have "http" somewhere
            has_match = (
                "http" in task.name.lower() or
                "http" in task.metadata.get('command', '').lower() or
                any("http" in tag.lower() for tag in task.metadata.get('tags', [])) or
                "http" in task.metadata.get('description', '').lower()
            )
            assert has_match


class TestSearchPerformance:
    """Test search performance benchmarks"""

    @pytest.fixture
    def large_profile(self, temp_crack_home):
        """Create profile with many tasks for performance testing"""
        profile = TargetProfile("192.168.45.100")

        # Add 100 tasks
        for i in range(100):
            task = TaskNode(
                task_id=f'task-{i}',
                name=f'Task {i}',
                task_type='command'
            )
            task.metadata.update({
                'command': f'command{i} --target TARGET',
                'tags': [f'TAG{i % 10}'],
                'description': f'Description for task {i}'
            })
            profile.task_tree.add_child(task)

        profile.save()
        return profile

    def test_search_completes_under_100ms(self, large_profile):
        """Search should complete in <100ms for typical task trees"""
        session = InteractiveSession(large_profile.target)

        start_time = time.time()
        results = session.search_tasks("command")
        end_time = time.time()

        elapsed_ms = (end_time - start_time) * 1000

        # Should be fast
        assert elapsed_ms < 100, f"Search took {elapsed_ms:.2f}ms (expected <100ms)"

        # Should still return results
        assert len(results) > 0


class TestSearchCommandSupport:
    """Test /search command integration"""

    def test_parse_command_recognizes_slash_prefix(self):
        """InputProcessor should recognize /search command"""
        result = InputProcessor.parse_command("/search gobuster")

        assert result is not None
        command, args = result
        assert command == "search"
        assert args == ["gobuster"]

    def test_parse_command_also_accepts_exclamation(self):
        """InputProcessor should still accept ! prefix"""
        result = InputProcessor.parse_command("!ls -la")

        assert result is not None
        command, args = result
        assert command == "ls"
        assert args == ["-la"]

    def test_parse_any_routes_slash_search_as_command(self):
        """parse_any should route /search as a command"""
        result = InputProcessor.parse_any("/search http", {'choices': []})

        assert result['type'] == 'command'
        command, args = result['value']
        assert command == 'search'


class TestSearchResults:
    """Test search result format and usability"""

    @pytest.fixture
    def simple_profile(self, temp_crack_home):
        """Create simple profile for result testing"""
        profile = TargetProfile("192.168.45.100")

        task = TaskNode(
            task_id='test-task',
            name='Test Task',
            task_type='command'
        )
        task.metadata.update({
            'command': 'echo test',
            'tags': ['TEST'],
            'description': 'A test task'
        })
        profile.task_tree.add_child(task)
        profile.save()
        return profile

    def test_search_returns_tuples(self, simple_profile):
        """search_tasks should return list of (task, score) tuples"""
        session = InteractiveSession(simple_profile.target)

        results = session.search_tasks("test")

        assert isinstance(results, list)
        assert len(results) > 0

        task, score = results[0]
        assert isinstance(task, TaskNode)
        assert isinstance(score, int)
        assert 0 <= score <= 100

    def test_search_results_stored_in_session(self, simple_profile):
        """Search should store results in session state"""
        session = InteractiveSession(simple_profile.target)

        results = session.search_tasks("test")

        # Verify session state updated
        assert session.search_query == "test"
        assert len(session.search_results) == len(results)

        # search_results should contain tasks only (not tuples)
        assert all(isinstance(t, TaskNode) for t in session.search_results)

    def test_empty_search_returns_empty_list(self, simple_profile):
        """Search with no matches should return empty list"""
        session = InteractiveSession(simple_profile.target)

        results = session.search_tasks("nonexistent_xyz123")

        assert isinstance(results, list)
        assert len(results) == 0


class TestSearchEdgeCases:
    """Test edge cases and error handling"""

    def test_search_empty_task_tree(self, temp_crack_home):
        """Search should handle empty task trees gracefully"""
        profile = TargetProfile("192.168.45.100")
        profile.save()

        session = InteractiveSession(profile.target)

        results = session.search_tasks("anything")

        assert isinstance(results, list)
        assert len(results) == 0

    def test_search_special_characters(self, temp_crack_home):
        """Search should handle special characters"""
        profile = TargetProfile("192.168.45.100")

        task = TaskNode(
            task_id='special-task',
            name='Task with $pecial Ch@rs!',
            task_type='command'
        )
        task.metadata['command'] = 'echo "test"'
        profile.task_tree.add_child(task)
        profile.save()

        session = InteractiveSession(profile.target)

        # Should not crash
        results = session.search_tasks("$pecial")
        assert isinstance(results, list)

    def test_search_very_long_query(self, temp_crack_home):
        """Search should handle very long queries"""
        profile = TargetProfile("192.168.45.100")
        profile.save()

        session = InteractiveSession(profile.target)

        long_query = "a" * 1000
        results = session.search_tasks(long_query)

        assert isinstance(results, list)

    def test_fuzzy_match_empty_strings(self, temp_crack_home):
        """Fuzzy match should handle empty strings"""
        profile = TargetProfile("192.168.45.100")
        profile.save()

        session = InteractiveSession(profile.target)

        # Empty query is treated as substring of any text (score 80)
        is_match, score = session._fuzzy_match("", "test")
        assert is_match is True
        assert score == 80  # Substring match


# Fixtures

@pytest.fixture
def temp_crack_home(tmp_path, monkeypatch):
    """Create temporary .crack directory for testing"""
    crack_home = tmp_path / '.crack'
    crack_home.mkdir()

    targets_dir = crack_home / 'targets'
    targets_dir.mkdir()

    sessions_dir = crack_home / 'sessions'
    sessions_dir.mkdir()

    # Mock Path.home() to return temp directory
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)

    return crack_home


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
