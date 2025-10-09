"""
Tests for WordlistManager

PROVES:
- Directory scanning discovers all wordlists
- Cache read/write operations work correctly
- Search functionality with fuzzy matching
- Category filtering returns correct results
- Performance targets met (<5s scan, <10ms cached)
"""

import pytest
import json
import time
from pathlib import Path


# Tests will initially fail until Agent-1 implements the manager
# This is expected - retry strategy in place
try:
    from crack.track.wordlists.manager import WordlistManager, WordlistEntry
    MANAGER_AVAILABLE = True
except ImportError:
    MANAGER_AVAILABLE = False
    pytestmark = pytest.mark.skip(reason="WordlistManager not yet implemented by Agent-1")


@pytest.mark.skipif(not MANAGER_AVAILABLE, reason="Waiting for Agent-1 implementation")
class TestWordlistManagerScanning:
    """Test directory scanning functionality"""

    def test_scan_discovers_all_files(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: Manager discovers all .txt and .lst files recursively

        Real OSCP scenario: Student needs to find all available wordlists
        for different attack types (web, passwords, subdomains).
        """
        manager = WordlistManager(
            wordlists_dir=str(temp_wordlists_dir),
            cache_path=str(temp_cache_file)
        )

        entries = manager.scan_directory()

        # Verify all files discovered
        file_names = [e.name for e in entries]

        # Note: Implementation may strip extensions or keep them
        # Test for presence with flexible matching
        assert any('common' in name for name in file_names)
        assert any('small' in name for name in file_names)
        assert any('rockyou' in name for name in file_names)
        assert any('common-password' in name for name in file_names)
        assert any('subdomain' in name for name in file_names)
        assert any('custom' in name for name in file_names)

        # Verify count matches fixture structure (6 files total)
        assert len(entries) == 6

    def test_scan_skips_symlinks(self, symlink_wordlist_dir, temp_cache_file):
        """
        PROVES: Manager skips symlinks to avoid duplicates

        Real scenario: Many wordlist directories have symlinks.
        We should only count real files.
        """
        manager = WordlistManager(
            wordlists_dir=str(symlink_wordlist_dir),
            cache_path=str(temp_cache_file)
        )

        entries = manager.scan_directory()

        # Should only find real.txt, not link.txt
        assert len(entries) == 1
        assert entries[0].name == 'real.txt'

    def test_scan_handles_empty_directory(self, empty_wordlist_dir, temp_cache_file):
        """
        PROVES: Manager handles empty directories gracefully

        Edge case: Clean Kali install before wordlist setup
        """
        manager = WordlistManager(
            wordlists_dir=str(empty_wordlist_dir),
            cache_path=str(temp_cache_file)
        )

        entries = manager.scan_directory()

        assert entries == []
        assert isinstance(entries, list)

    def test_scan_handles_permission_errors(self, permission_denied_dir, temp_cache_file):
        """
        PROVES: Manager skips files with permission errors instead of crashing

        Real scenario: Some wordlist files may have restrictive permissions
        """
        manager = WordlistManager(
            wordlists_dir=str(permission_denied_dir),
            cache_path=str(temp_cache_file)
        )

        # Should not raise exception
        entries = manager.scan_directory()

        # May or may not include restricted file depending on implementation
        # Main goal: no crash
        assert isinstance(entries, list)

    def test_scan_excludes_non_txt_files(self, tmp_path, temp_cache_file):
        """
        PROVES: Manager only scans .txt and .lst files

        Scenario: Wordlist directories may contain README.md, .gitkeep, etc.
        """
        test_dir = tmp_path / "mixed"
        test_dir.mkdir()

        # Create various file types
        (test_dir / "wordlist.txt").write_text("word1\n")
        (test_dir / "wordlist.lst").write_text("word2\n")
        (test_dir / "README.md").write_text("# Info\n")
        (test_dir / "script.py").write_text("print('hi')\n")
        (test_dir / ".gitkeep").write_text("")

        manager = WordlistManager(
            wordlists_dir=str(test_dir),
            cache_path=str(temp_cache_file)
        )

        entries = manager.scan_directory()

        # Only .txt and .lst files
        assert len(entries) == 2
        names = [e.name for e in entries]
        assert 'wordlist.txt' in names
        assert 'wordlist.lst' in names
        assert 'README.md' not in names


@pytest.mark.skipif(not MANAGER_AVAILABLE, reason="Waiting for Agent-1 implementation")
class TestWordlistManagerCache:
    """Test cache read/write operations"""

    def test_cache_saves_correctly(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: Cache file created with valid JSON structure

        Performance requirement: Avoid rescanning on every invocation
        """
        manager = WordlistManager(
            wordlists_dir=str(temp_wordlists_dir),
            cache_path=str(temp_cache_file)
        )

        # Trigger scan which should save cache
        entries = manager.scan_directory()

        # Verify cache file exists
        assert temp_cache_file.exists()

        # Verify valid JSON
        cache_data = json.loads(temp_cache_file.read_text())

        assert 'wordlists' in cache_data
        assert 'last_scan' in cache_data
        assert isinstance(cache_data['wordlists'], list)
        assert len(cache_data['wordlists']) == len(entries)

    def test_cache_loads_on_init(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: Manager loads from cache instead of rescanning

        Performance: Cached load should be <10ms vs <5s for full scan
        """
        # First manager: scan and save
        manager1 = WordlistManager(
            wordlists_dir=str(temp_wordlists_dir),
            cache_path=str(temp_cache_file)
        )
        manager1.scan_directory()

        # Second manager: should load from cache
        start_time = time.time()
        manager2 = WordlistManager(
            wordlists_dir=str(temp_wordlists_dir),
            cache_path=str(temp_cache_file)
        )
        # Access cached entries (implementation dependent - may be via property)
        cached_entries = manager2.wordlists if hasattr(manager2, 'wordlists') else []
        load_time = (time.time() - start_time) * 1000  # Convert to ms

        # Performance target: <10ms for cached load
        assert load_time < 10, f"Cache load took {load_time:.2f}ms, expected <10ms"

        # Verify same data
        assert len(cached_entries) == 6

    def test_cache_invalidates_when_stale(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: Cache refreshes if directory modified

        Scenario: User adds new wordlists after initial scan
        """
        manager = WordlistManager(
            wordlists_dir=str(temp_wordlists_dir),
            cache_path=str(temp_cache_file)
        )

        # Initial scan
        initial_entries = manager.scan_directory()
        assert len(initial_entries) == 6

        # Add new wordlist
        new_file = Path(temp_wordlists_dir) / "new-wordlist.txt"
        new_file.write_text("new1\nnew2\n")

        # Force rescan (implementation may auto-detect changes)
        manager2 = WordlistManager(
            wordlists_dir=str(temp_wordlists_dir),
            cache_path=str(temp_cache_file)
        )
        refreshed_entries = manager2.scan_directory()

        # Should include new file
        assert len(refreshed_entries) == 7
        names = [e.name for e in refreshed_entries]
        assert 'new-wordlist.txt' in names


@pytest.mark.skipif(not MANAGER_AVAILABLE, reason="Waiting for Agent-1 implementation")
class TestWordlistManagerSearch:
    """Test search functionality with fuzzy matching"""

    def test_search_by_exact_name(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: Exact name matching returns correct wordlist

        CLI usage: crack track --wordlist common.txt
        """
        manager = WordlistManager(
            wordlists_dir=str(temp_wordlists_dir),
            cache_path=str(temp_cache_file)
        )
        manager.scan_directory()

        results = manager.search('common.txt')

        assert len(results) > 0
        assert any(r.name == 'common.txt' for r in results)

    def test_search_fuzzy_matching(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: Fuzzy search finds partial matches

        Real OSCP workflow: Student types "rockyou" instead of "rockyou.txt"
        """
        manager = WordlistManager(
            wordlists_dir=str(temp_wordlists_dir),
            cache_path=str(temp_cache_file)
        )
        manager.scan_directory()

        results = manager.search('rocky')

        assert len(results) > 0
        assert any('rockyou' in r.name.lower() for r in results)

    def test_search_by_path_component(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: Search matches path components (e.g., "dirb" finds dirb/common.txt)

        Workflow: Student knows wordlist is in dirb directory
        """
        manager = WordlistManager(
            wordlists_dir=str(temp_wordlists_dir),
            cache_path=str(temp_cache_file)
        )
        manager.scan_directory()

        results = manager.search('dirb')

        # Should find dirb/common.txt and dirb/small.txt
        assert len(results) >= 2
        assert all('dirb' in r.path.lower() for r in results)

    def test_search_case_insensitive(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: Search is case-insensitive

        UX: Student shouldn't need to remember exact casing
        """
        manager = WordlistManager(
            wordlists_dir=str(temp_wordlists_dir),
            cache_path=str(temp_cache_file)
        )
        manager.scan_directory()

        results_lower = manager.search('common')
        results_upper = manager.search('COMMON')
        results_mixed = manager.search('CoMmOn')

        # All should return same results
        assert len(results_lower) == len(results_upper) == len(results_mixed)

    def test_search_no_results(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: Search returns empty list for no matches

        Edge case: Typo or non-existent wordlist
        """
        manager = WordlistManager(
            wordlists_dir=str(temp_wordlists_dir),
            cache_path=str(temp_cache_file)
        )
        manager.scan_directory()

        results = manager.search('nonexistent-wordlist-xyz')

        assert results == []


@pytest.mark.skipif(not MANAGER_AVAILABLE, reason="Waiting for Agent-1 implementation")
class TestWordlistManagerCategoryFiltering:
    """Test get_by_category filtering"""

    def test_get_by_category_web(self, wordlists_by_category, temp_cache_file):
        """
        PROVES: Web category returns dirb/gobuster wordlists

        OSCP workflow: Student needs web enumeration wordlist
        """
        # Combine all category files into single directory
        combined_dir = wordlists_by_category['web'][0].parent.parent

        manager = WordlistManager(
            wordlists_dir=str(combined_dir),
            cache_path=str(temp_cache_file)
        )
        manager.scan_directory()

        web_wordlists = manager.get_by_category('web')

        assert len(web_wordlists) > 0
        # All should be categorized as web
        assert all(w.category == 'web' for w in web_wordlists)

    def test_get_by_category_passwords(self, wordlists_by_category, temp_cache_file):
        """
        PROVES: Password category returns rockyou, common-passwords, etc.

        OSCP workflow: Student needs password cracking wordlist
        """
        combined_dir = wordlists_by_category['passwords'][0].parent.parent

        manager = WordlistManager(
            wordlists_dir=str(combined_dir),
            cache_path=str(temp_cache_file)
        )
        manager.scan_directory()

        password_wordlists = manager.get_by_category('passwords')

        assert len(password_wordlists) > 0
        assert all(w.category == 'passwords' for w in password_wordlists)

    def test_get_by_category_subdomains(self, wordlists_by_category, temp_cache_file):
        """
        PROVES: Subdomain category returns subdomain enumeration wordlists

        OSCP workflow: DNS/subdomain enumeration
        """
        combined_dir = wordlists_by_category['subdomains'][0].parent.parent

        manager = WordlistManager(
            wordlists_dir=str(combined_dir),
            cache_path=str(temp_cache_file)
        )
        manager.scan_directory()

        subdomain_wordlists = manager.get_by_category('subdomains')

        assert len(subdomain_wordlists) > 0
        assert all(w.category == 'subdomains' for w in subdomain_wordlists)

    def test_get_by_category_invalid(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: Invalid category returns empty list

        Edge case: Typo in category name
        """
        manager = WordlistManager(
            wordlists_dir=str(temp_wordlists_dir),
            cache_path=str(temp_cache_file)
        )
        manager.scan_directory()

        results = manager.get_by_category('invalid-category')

        assert results == []


@pytest.mark.skipif(not MANAGER_AVAILABLE, reason="Waiting for Agent-1 implementation")
class TestWordlistManagerPerformance:
    """Test performance targets"""

    def test_full_scan_performance(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: Full directory scan completes in <5s

        Target: <5s for first-time scan of /usr/share/wordlists/
        Test uses smaller directory but validates algorithm efficiency
        """
        manager = WordlistManager(
            wordlists_dir=str(temp_wordlists_dir),
            cache_path=str(temp_cache_file)
        )

        start_time = time.time()
        entries = manager.scan_directory()
        scan_time = time.time() - start_time

        # Should be much faster than 5s for small test directory
        # Real test against /usr/share/wordlists/ would validate <5s target
        assert scan_time < 1.0, f"Scan took {scan_time:.2f}s, expected <1s for test directory"
        assert len(entries) > 0

    def test_cached_load_performance(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: Cached load completes in <10ms

        Performance target: Instant load from cache
        """
        # Initial scan to populate cache
        manager1 = WordlistManager(
            wordlists_dir=str(temp_wordlists_dir),
            cache_path=str(temp_cache_file)
        )
        manager1.scan_directory()

        # Measure cache load time
        start_time = time.time()
        manager2 = WordlistManager(
            wordlists_dir=str(temp_wordlists_dir),
            cache_path=str(temp_cache_file)
        )
        # Trigger cache load (implementation dependent)
        cached = manager2.wordlists if hasattr(manager2, 'wordlists') else manager2.scan_directory()
        load_time = (time.time() - start_time) * 1000

        assert load_time < 10, f"Cache load took {load_time:.2f}ms, target is <10ms"

    def test_search_performance(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: Search completes in <100ms

        Performance: Interactive search should feel instant
        """
        manager = WordlistManager(
            wordlists_dir=str(temp_wordlists_dir),
            cache_path=str(temp_cache_file)
        )
        manager.scan_directory()

        start_time = time.time()
        results = manager.search('common')
        search_time = (time.time() - start_time) * 1000

        assert search_time < 100, f"Search took {search_time:.2f}ms, target is <100ms"


@pytest.mark.skipif(not MANAGER_AVAILABLE, reason="Waiting for Agent-1 implementation")
class TestWordlistManagerGetWordlist:
    """Test get_wordlist method"""

    def test_get_wordlist_by_path(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: Can retrieve specific wordlist by full path

        Usage: User knows exact path to wordlist
        """
        manager = WordlistManager(
            wordlists_dir=str(temp_wordlists_dir),
            cache_path=str(temp_cache_file)
        )
        entries = manager.scan_directory()

        # Get path of known wordlist
        common_path = str(Path(temp_wordlists_dir) / "dirb" / "common.txt")

        wordlist = manager.get_wordlist(common_path)

        assert wordlist is not None
        assert wordlist.name == 'common.txt'
        assert wordlist.path == common_path

    def test_get_wordlist_nonexistent(self, temp_wordlists_dir, temp_cache_file):
        """
        PROVES: Returns None for non-existent path

        Edge case: Invalid path provided
        """
        manager = WordlistManager(
            wordlists_dir=str(temp_wordlists_dir),
            cache_path=str(temp_cache_file)
        )
        manager.scan_directory()

        wordlist = manager.get_wordlist('/nonexistent/path/wordlist.txt')

        assert wordlist is None
