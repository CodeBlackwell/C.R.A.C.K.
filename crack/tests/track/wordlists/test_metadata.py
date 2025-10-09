"""
Tests for metadata generation

PROVES:
- Metadata generation accuracy (line count, avg word length, size)
- Category detection from path and filename patterns
- Sampling works correctly for large files
- Performance targets met (<200ms for large files)
"""

import pytest
import time
from pathlib import Path


try:
    from crack.track.wordlists.metadata import (
        generate_metadata,
        detect_category,
        _count_lines_fast,
        _calculate_avg_word_length
    )
    METADATA_AVAILABLE = True
except ImportError:
    METADATA_AVAILABLE = False
    pytestmark = pytest.mark.skip(reason="Metadata module not yet implemented by Agent-1")


@pytest.mark.skipif(not METADATA_AVAILABLE, reason="Waiting for Agent-1 implementation")
class TestMetadataGeneration:
    """Test complete metadata generation"""

    def test_generate_metadata_small_file(self, tmp_path):
        """
        PROVES: Metadata accurate for small files (<10K lines)

        Uses exact counting for small files
        """
        small_file = tmp_path / "small.txt"
        content = ["word1", "word2", "word3", "longerword", "a"]
        small_file.write_text("\n".join(content))

        metadata = generate_metadata(str(small_file))

        # Verify all fields populated
        assert metadata.path == str(small_file)
        assert metadata.name == "small.txt"
        assert metadata.size_bytes == small_file.stat().st_size
        assert metadata.line_count == 5
        # Avg word length: (5 + 5 + 5 + 10 + 1) / 5 = 5.2
        assert 5.0 <= metadata.avg_word_length <= 5.5
        assert len(metadata.last_scanned) > 0  # Timestamp set

    def test_generate_metadata_medium_file(self, wordlists_with_various_sizes):
        """
        PROVES: Metadata uses sampling for medium files (5K-50K lines)

        Performance: Should still complete quickly with sampling
        """
        medium_file = wordlists_with_various_sizes['medium']

        start_time = time.time()
        metadata = generate_metadata(str(medium_file))
        gen_time = (time.time() - start_time) * 1000

        # Verify metadata
        assert metadata.line_count == 5000  # Exact or estimated
        assert metadata.avg_word_length > 0
        assert metadata.size_bytes > 0

        # Performance: Should be fast even with sampling
        assert gen_time < 200, f"Metadata generation took {gen_time:.2f}ms, target <200ms"

    def test_generate_metadata_large_file(self, large_wordlist_file):
        """
        PROVES: Large file (100K lines) metadata generation completes in <200ms

        Performance target: Fast estimation for rockyou.txt-sized files
        """
        start_time = time.time()
        metadata = generate_metadata(str(large_wordlist_file))
        gen_time = (time.time() - start_time) * 1000

        # Verify metadata populated (exact values may be estimates)
        assert metadata.line_count > 50000  # At least 50K (may be estimate)
        assert metadata.avg_word_length > 0
        assert metadata.size_bytes == large_wordlist_file.stat().st_size

        # Performance target
        assert gen_time < 200, f"Large file metadata took {gen_time:.2f}ms, target <200ms"

    def test_generate_metadata_empty_file(self, tmp_path):
        """
        PROVES: Handles empty files gracefully

        Edge case: Empty wordlist file
        """
        empty_file = tmp_path / "empty.txt"
        empty_file.write_text("")

        metadata = generate_metadata(str(empty_file))

        assert metadata.line_count == 0
        assert metadata.size_bytes == 0
        assert metadata.avg_word_length == 0.0

    def test_generate_metadata_single_line(self, tmp_path):
        """
        PROVES: Handles single-line files correctly

        Edge case: Wordlist with one word
        """
        single_line = tmp_path / "single.txt"
        single_line.write_text("password")

        metadata = generate_metadata(str(single_line))

        assert metadata.line_count == 1
        assert metadata.avg_word_length == 8.0  # "password" = 8 chars


@pytest.mark.skipif(not METADATA_AVAILABLE, reason="Waiting for Agent-1 implementation")
class TestCategoryDetection:
    """Test category detection from paths and filenames"""

    def test_detect_category_dirb_path(self):
        """
        PROVES: Path containing "dirb" categorized as web

        Real OSCP scenario: /usr/share/wordlists/dirb/common.txt
        """
        category = detect_category(
            path="/usr/share/wordlists/dirb/common.txt",
            filename="common.txt"
        )

        assert category == 'web'

    def test_detect_category_dirbuster_path(self):
        """
        PROVES: Path containing "dirbuster" categorized as web

        Real OSCP scenario: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
        """
        category = detect_category(
            path="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            filename="directory-list-2.3-medium.txt"
        )

        assert category == 'web'

    def test_detect_category_rockyou_filename(self):
        """
        PROVES: Filename "rockyou" categorized as passwords

        Real OSCP scenario: /usr/share/wordlists/rockyou.txt
        """
        category = detect_category(
            path="/usr/share/wordlists/rockyou.txt",
            filename="rockyou.txt"
        )

        assert category == 'passwords'

    def test_detect_category_password_path(self):
        """
        PROVES: Path containing "password" categorized as passwords

        Scenario: /usr/share/wordlists/passwords/common-passwords.txt
        """
        category = detect_category(
            path="/usr/share/wordlists/passwords/common-passwords.txt",
            filename="common-passwords.txt"
        )

        assert category == 'passwords'

    def test_detect_category_subdomain_filename(self):
        """
        PROVES: Filename containing "subdomain" categorized as subdomains

        Scenario: SecLists DNS wordlists
        """
        category = detect_category(
            path="/usr/share/seclists/Discovery/DNS/subdomains-top1000.txt",
            filename="subdomains-top1000.txt"
        )

        assert category == 'subdomains'

    def test_detect_category_username_filename(self):
        """
        PROVES: Filename containing "user" or "username" categorized as usernames

        Scenario: Username enumeration wordlists
        """
        category1 = detect_category(
            path="/usr/share/wordlists/usernames.txt",
            filename="usernames.txt"
        )

        category2 = detect_category(
            path="/usr/share/seclists/Usernames/common-users.txt",
            filename="common-users.txt"
        )

        assert category1 == 'usernames'
        # common-users may be 'usernames' or 'general' depending on implementation
        assert category2 in ['usernames', 'general']

    def test_detect_category_seclists_web_content(self):
        """
        PROVES: SecLists Web-Content categorized as web

        Scenario: /usr/share/seclists/Discovery/Web-Content/
        """
        category = detect_category(
            path="/usr/share/seclists/Discovery/Web-Content/common.txt",
            filename="common.txt"
        )

        assert category == 'web'

    def test_detect_category_generic_fallback(self):
        """
        PROVES: Unrecognized wordlists categorized as general

        Scenario: Custom wordlist with no category hints
        """
        category = detect_category(
            path="/home/user/custom-list.txt",
            filename="custom-list.txt"
        )

        assert category == 'general'

    def test_detect_category_case_insensitive(self):
        """
        PROVES: Category detection is case-insensitive

        Edge case: Mixed-case paths and filenames
        """
        category1 = detect_category(
            path="/usr/share/wordlists/DIRB/COMMON.TXT",
            filename="COMMON.TXT"
        )

        category2 = detect_category(
            path="/usr/share/wordlists/RockYou.txt",
            filename="RockYou.txt"
        )

        assert category1 == 'web'
        assert category2 == 'passwords'


@pytest.mark.skipif(not METADATA_AVAILABLE, reason="Waiting for Agent-1 implementation")
class TestLineCountingFast:
    """Test fast line counting function"""

    def test_count_lines_small_file_exact(self, tmp_path):
        """
        PROVES: Small files (<10K lines) get exact count

        Strategy: Read entire file for accuracy
        """
        small_file = tmp_path / "small.txt"
        lines = [f"line{i}" for i in range(100)]
        small_file.write_text("\n".join(lines))

        count = _count_lines_fast(str(small_file))

        assert count == 100

    def test_count_lines_large_file_estimate(self, large_wordlist_file):
        """
        PROVES: Large files (>50K lines) get fast estimate

        Strategy: Sample-based estimation for performance
        """
        start_time = time.time()
        count = _count_lines_fast(str(large_wordlist_file))
        count_time = (time.time() - start_time) * 1000

        # Should be close to actual count (100K)
        # Allow 10% margin for estimation
        assert 90000 <= count <= 110000

        # Performance: Should be fast (no full file read)
        assert count_time < 100, f"Line counting took {count_time:.2f}ms, should be <100ms"

    def test_count_lines_empty_file(self, tmp_path):
        """
        PROVES: Empty file returns 0

        Edge case: Empty wordlist
        """
        empty_file = tmp_path / "empty.txt"
        empty_file.write_text("")

        count = _count_lines_fast(str(empty_file))

        assert count == 0

    def test_count_lines_no_trailing_newline(self, tmp_path):
        """
        PROVES: Correctly counts lines without trailing newline

        Edge case: Last line doesn't end with \n
        """
        no_newline_file = tmp_path / "no-newline.txt"
        no_newline_file.write_text("line1\nline2\nline3")  # No trailing \n

        count = _count_lines_fast(str(no_newline_file))

        assert count == 3


@pytest.mark.skipif(not METADATA_AVAILABLE, reason="Waiting for Agent-1 implementation")
class TestAvgWordLengthCalculation:
    """Test average word length calculation"""

    def test_calculate_avg_word_length_small_file(self, tmp_path):
        """
        PROVES: Small files get exact average

        Strategy: Read all lines for accuracy
        """
        small_file = tmp_path / "small.txt"
        words = ["short", "medium", "verylongword"]
        small_file.write_text("\n".join(words))

        avg_length = _calculate_avg_word_length(str(small_file))

        # Expected: (5 + 6 + 12) / 3 = 7.67
        assert 7.5 <= avg_length <= 8.0

    def test_calculate_avg_word_length_large_file(self, large_wordlist_file):
        """
        PROVES: Large files use sampling for performance

        Strategy: Sample first/middle/last 1000 lines
        """
        start_time = time.time()
        avg_length = _calculate_avg_word_length(str(large_wordlist_file))
        calc_time = (time.time() - start_time) * 1000

        # Should be reasonable (words are ~8 chars: "word12345")
        assert 5.0 <= avg_length <= 12.0

        # Performance: Should be fast with sampling
        assert calc_time < 100, f"Avg calculation took {calc_time:.2f}ms, should be <100ms"

    def test_calculate_avg_word_length_empty_file(self, tmp_path):
        """
        PROVES: Empty file returns 0.0

        Edge case: No words to calculate average
        """
        empty_file = tmp_path / "empty.txt"
        empty_file.write_text("")

        avg_length = _calculate_avg_word_length(str(empty_file))

        assert avg_length == 0.0

    def test_calculate_avg_word_length_whitespace_handling(self, tmp_path):
        """
        PROVES: Strips whitespace before calculating length

        Edge case: Lines with leading/trailing spaces
        """
        whitespace_file = tmp_path / "whitespace.txt"
        whitespace_file.write_text("  word1  \n  word2  \n  word3  ")

        avg_length = _calculate_avg_word_length(str(whitespace_file))

        # Should calculate based on stripped words (all 5 chars)
        assert 4.5 <= avg_length <= 5.5

    def test_calculate_avg_word_length_empty_lines(self, tmp_path):
        """
        PROVES: Skips empty lines in calculation

        Edge case: Wordlist with blank lines
        """
        empty_lines_file = tmp_path / "empty-lines.txt"
        empty_lines_file.write_text("word1\n\nword2\n\nword3")

        avg_length = _calculate_avg_word_length(str(empty_lines_file))

        # Should only count non-empty lines (all 5 chars)
        assert 4.5 <= avg_length <= 5.5


@pytest.mark.skipif(not METADATA_AVAILABLE, reason="Waiting for Agent-1 implementation")
class TestMetadataPerformance:
    """Test performance requirements"""

    def test_rockyou_sized_file_performance(self, tmp_path):
        """
        PROVES: Metadata generation for rockyou.txt-sized file completes in <200ms

        Real OSCP scenario: Scanning /usr/share/wordlists/ includes rockyou.txt (14M lines)
        Using 100K line file as proxy for performance validation
        """
        # Create 100K line file (proxy for rockyou.txt)
        large_file = tmp_path / "rockyou-proxy.txt"
        with large_file.open('w') as f:
            for i in range(100000):
                f.write(f"password{i:06d}\n")

        # Measure metadata generation
        start_time = time.time()
        metadata = generate_metadata(str(large_file))
        gen_time = (time.time() - start_time) * 1000

        # Verify metadata complete
        assert metadata.line_count > 0
        assert metadata.avg_word_length > 0
        assert metadata.size_bytes > 0

        # Performance target
        assert gen_time < 200, f"Metadata generation took {gen_time:.2f}ms, target <200ms"

    def test_batch_metadata_generation_performance(self, wordlists_with_various_sizes):
        """
        PROVES: Can generate metadata for multiple files efficiently

        Real scenario: Initial scan of entire wordlists directory
        """
        files = [
            wordlists_with_various_sizes['small'],
            wordlists_with_various_sizes['medium'],
            wordlists_with_various_sizes['large']
        ]

        start_time = time.time()
        for file in files:
            metadata = generate_metadata(str(file))
            assert metadata is not None
        total_time = (time.time() - start_time) * 1000

        # Should process all files in reasonable time
        # Target: <500ms for 3 files (small + medium + large)
        assert total_time < 500, f"Batch generation took {total_time:.2f}ms, target <500ms"
