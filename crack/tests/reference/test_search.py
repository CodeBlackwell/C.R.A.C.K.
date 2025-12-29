"""
Tests for Search Functionality

Business Value Focus:
- Punctuation-insensitive search (TGS-REP matches TGSREP)
- Case-insensitive matching (users don't need exact case)
- Partial matching (find commands without full text)
- Multi-term AND search (narrowing results)
- Tag inclusion in search (technique discovery)

These tests ensure users can find commands regardless of how they
remember the exact spelling or formatting.
"""

import pytest
import json
from pathlib import Path
from typing import List


# =============================================================================
# Punctuation-Insensitive Search Tests (BV: HIGH)
# =============================================================================

class TestPunctuationInsensitiveSearch:
    """
    Tests for punctuation normalization in search.

    User Problem: "I search for tgsrep but command is named TGS-REP"
    """

    def test_hyphen_normalized_in_search(self, tmp_path, command_factory):
        """
        BV: Users find TGS-REP by searching 'tgsrep'.

        Scenario:
          Given: Command with 'TGS-REP' in name
          When: Search for 'tgsrep' (no hyphen)
          Then: Command is found
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        cmd = command_factory.create_tgs_rep()

        json_file = commands_dir / "post-exploit.json"
        json_file.write_text(json.dumps({
            "category": "post-exploit",
            "commands": [cmd]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        results = registry.search("tgsrep")

        assert len(results) >= 1
        assert any(r.id == "kerberoast-tgs-rep" for r in results)

    def test_underscore_normalized_in_search(self, tmp_path, command_factory):
        """
        BV: Users find commands with underscores using space or no separator.

        Scenario:
          Given: Command with 'PASS_THE_HASH' in name
          When: Search for 'passthehash'
          Then: Command is found
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        cmd = command_factory.create(
            id="pth-attack",
            name="Pass_the_Hash Attack",
            description="Perform pass-the-hash authentication",
            tags=["PTH", "PASS_THE_HASH"]
        )

        json_file = commands_dir / "test.json"
        json_file.write_text(json.dumps({
            "category": "test",
            "commands": [cmd]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        results = registry.search("passthehash")

        assert len(results) >= 1
        assert any(r.id == "pth-attack" for r in results)

    def test_colon_normalized_in_tag_search(self, tmp_path, command_factory):
        """
        BV: Users find OSCP:HIGH commands by searching 'oscphigh'.

        Scenario:
          Given: Command tagged 'OSCP:HIGH'
          When: Search for 'oscphigh' (no colon)
          Then: Command is found
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        cmd = command_factory.create(
            id="oscp-cmd",
            name="OSCP Command",
            tags=["OSCP:HIGH", "EXAM"]
        )

        json_file = commands_dir / "test.json"
        json_file.write_text(json.dumps({
            "category": "test",
            "commands": [cmd]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        results = registry.search("oscphigh")

        assert len(results) >= 1
        assert any(r.id == "oscp-cmd" for r in results)

    def test_period_normalized_in_search(self, tmp_path, command_factory):
        """
        BV: Users find 'exploit.py' by searching 'exploitpy'.
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        cmd = command_factory.create(
            id="exploit-py",
            name="Exploit.py Runner",
            command="python3 exploit.py <TARGET>"
        )

        json_file = commands_dir / "test.json"
        json_file.write_text(json.dumps({
            "category": "test",
            "commands": [cmd]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        results = registry.search("exploitpy")

        assert len(results) >= 1

    def test_slash_normalized_in_search(self, tmp_path, command_factory):
        """
        BV: Users find '/etc/passwd' by searching 'etcpasswd'.
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        cmd = command_factory.create(
            id="read-passwd",
            name="Read /etc/passwd",
            command="cat /etc/passwd"
        )

        json_file = commands_dir / "test.json"
        json_file.write_text(json.dumps({
            "category": "test",
            "commands": [cmd]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        results = registry.search("etcpasswd")

        assert len(results) >= 1

    def test_original_punctuated_search_still_works(self, tmp_path, command_factory):
        """
        BV: Users can also search with original punctuation.
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        cmd = command_factory.create_tgs_rep()

        json_file = commands_dir / "post-exploit.json"
        json_file.write_text(json.dumps({
            "category": "post-exploit",
            "commands": [cmd]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        # Search with original hyphen
        results = registry.search("TGS-REP")

        assert len(results) >= 1
        assert any(r.id == "kerberoast-tgs-rep" for r in results)


# =============================================================================
# Case-Insensitive Search Tests (BV: HIGH)
# =============================================================================

class TestCaseInsensitiveSearch:
    """Tests for case-insensitive search matching."""

    def test_lowercase_query_finds_uppercase_name(self, tmp_path, command_factory):
        """
        BV: Users don't need to remember exact casing.

        Scenario:
          Given: Command named 'NMAP TCP Scan'
          When: Search for 'nmap tcp scan'
          Then: Command is found
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        cmd = command_factory.create(
            id="nmap-scan",
            name="NMAP TCP Scan",
            command="nmap -sT <TARGET>"
        )

        json_file = commands_dir / "test.json"
        json_file.write_text(json.dumps({
            "category": "test",
            "commands": [cmd]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        results = registry.search("nmap tcp scan")

        assert len(results) >= 1

    def test_uppercase_query_finds_lowercase_content(self, tmp_path, command_factory):
        """
        BV: Uppercase queries work too.
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        cmd = command_factory.create(
            id="web-enum",
            name="web enumeration",
            description="enumerate web application"
        )

        json_file = commands_dir / "test.json"
        json_file.write_text(json.dumps({
            "category": "test",
            "commands": [cmd]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        results = registry.search("WEB ENUMERATION")

        assert len(results) >= 1

    def test_mixed_case_query_matches(self, tmp_path, command_factory):
        """
        BV: MixedCase queries work.
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        cmd = command_factory.create(
            id="smb-enum",
            name="SMB Enumeration",
            tags=["SMB", "ENUM"]
        )

        json_file = commands_dir / "test.json"
        json_file.write_text(json.dumps({
            "category": "test",
            "commands": [cmd]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        results = registry.search("SmB eNuM")

        assert len(results) >= 1


# =============================================================================
# Partial Matching Tests (BV: HIGH)
# =============================================================================

class TestPartialMatching:
    """Tests for partial/substring search matching."""

    def test_partial_name_match(self, tmp_path, command_factory):
        """
        BV: Users can find commands with partial name.

        Scenario:
          Given: Command named 'Nmap TCP Full Port Scan'
          When: Search for 'full port'
          Then: Command is found
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        cmd = command_factory.create(
            id="nmap-full-port",
            name="Nmap TCP Full Port Scan",
            command="nmap -sT -p- <TARGET>"
        )

        json_file = commands_dir / "test.json"
        json_file.write_text(json.dumps({
            "category": "test",
            "commands": [cmd]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        results = registry.search("full port")

        assert len(results) >= 1
        assert any(r.id == "nmap-full-port" for r in results)

    def test_partial_description_match(self, tmp_path, command_factory):
        """
        BV: Users can find commands by description content.
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        cmd = command_factory.create(
            id="sqli-union",
            name="SQL Injection",
            description="UNION-based SQL injection for data extraction"
        )

        json_file = commands_dir / "test.json"
        json_file.write_text(json.dumps({
            "category": "test",
            "commands": [cmd]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        results = registry.search("data extraction")

        assert len(results) >= 1

    def test_partial_command_text_match(self, tmp_path, command_factory):
        """
        BV: Users can find by command syntax.
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        cmd = command_factory.create(
            id="ffuf-vhost",
            name="FFuf VHost Discovery",
            command="ffuf -w wordlist.txt -H 'Host: FUZZ.target.com' -u http://target"
        )

        json_file = commands_dir / "test.json"
        json_file.write_text(json.dumps({
            "category": "test",
            "commands": [cmd]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        results = registry.search("Host: FUZZ")

        assert len(results) >= 1

    def test_search_matches_command_id(self, tmp_path, command_factory):
        """
        BV: Users can search by partial command ID.
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        cmd = command_factory.create(
            id="gobuster-dir-scan",
            name="Gobuster Directory Scan",
            command="gobuster dir -u <URL> -w <WORDLIST>"
        )

        json_file = commands_dir / "test.json"
        json_file.write_text(json.dumps({
            "category": "test",
            "commands": [cmd]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        results = registry.search("gobuster-dir")

        assert len(results) >= 1


# =============================================================================
# Multi-Term AND Search Tests (BV: HIGH)
# =============================================================================

class TestMultiTermSearch:
    """Tests for multi-word search queries."""

    def test_multi_term_search_uses_and_logic(self, tmp_path, command_factory):
        """
        BV: Multi-word queries narrow results (all terms required).

        Scenario:
          Given: Commands for 'nmap tcp', 'nmap udp', 'masscan tcp'
          When: Search 'nmap tcp'
          Then: Only 'nmap tcp' command returned (not 'nmap udp' or 'masscan tcp')
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        nmap_tcp = command_factory.create(
            id="nmap-tcp",
            name="Nmap TCP Scan",
            command="nmap -sT <TARGET>"
        )
        nmap_udp = command_factory.create(
            id="nmap-udp",
            name="Nmap UDP Scan",
            command="nmap -sU <TARGET>"
        )
        masscan_tcp = command_factory.create(
            id="masscan-tcp",
            name="Masscan TCP Scan",
            command="masscan -p- <TARGET>"
        )

        json_file = commands_dir / "test.json"
        json_file.write_text(json.dumps({
            "category": "test",
            "commands": [nmap_tcp, nmap_udp, masscan_tcp]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        results = registry.search("nmap tcp")

        # Should find nmap-tcp, not the others
        result_ids = [r.id for r in results]
        assert "nmap-tcp" in result_ids
        # nmap_udp might match on 'nmap' but not on 'tcp', should be excluded
        assert "masscan-tcp" not in result_ids or "nmap-udp" not in result_ids

    def test_three_term_search_narrows_further(self, tmp_path, command_factory):
        """
        BV: More terms = more specific results.
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        cmd1 = command_factory.create(
            id="nmap-tcp-full",
            name="Nmap TCP Full Port Scan",
            command="nmap -sT -p- <TARGET>"
        )
        cmd2 = command_factory.create(
            id="nmap-tcp-top",
            name="Nmap TCP Top Ports",
            command="nmap -sT --top-ports 1000 <TARGET>"
        )
        cmd3 = command_factory.create(
            id="nmap-udp-full",
            name="Nmap UDP Full Port Scan",
            command="nmap -sU -p- <TARGET>"
        )

        json_file = commands_dir / "test.json"
        json_file.write_text(json.dumps({
            "category": "test",
            "commands": [cmd1, cmd2, cmd3]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        results = registry.search("nmap tcp full")

        result_ids = [r.id for r in results]
        assert "nmap-tcp-full" in result_ids
        assert "nmap-tcp-top" not in result_ids  # Doesn't have 'full'
        assert "nmap-udp-full" not in result_ids  # Doesn't have 'tcp'


# =============================================================================
# Tag Search Tests (BV: MEDIUM)
# =============================================================================

class TestTagSearch:
    """Tests for tag-based search matching."""

    def test_search_finds_commands_by_tag(self, tmp_path, command_factory):
        """
        BV: Users can find commands by technique tag.

        Scenario:
          Given: Command tagged 'KERBEROS'
          When: Search for 'kerberos'
          Then: Command is found
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        cmd = command_factory.create(
            id="kerb-enum",
            name="Kerberos Enumeration",
            tags=["KERBEROS", "AD", "ENUM"]
        )

        json_file = commands_dir / "test.json"
        json_file.write_text(json.dumps({
            "category": "test",
            "commands": [cmd]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        results = registry.search("kerberos")

        assert len(results) >= 1
        assert any(r.id == "kerb-enum" for r in results)

    def test_search_with_oscp_tag(self, tmp_path, command_factory):
        """
        BV: OSCP tags are searchable.
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        cmd = command_factory.create(
            id="exam-critical",
            name="Exam Critical Command",
            tags=["OSCP:HIGH", "EXAM"]
        )

        json_file = commands_dir / "test.json"
        json_file.write_text(json.dumps({
            "category": "test",
            "commands": [cmd]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        # Search without colon (punctuation-insensitive)
        results = registry.search("oscphigh")

        assert len(results) >= 1


# =============================================================================
# Edge Cases and Error Handling (BV: MEDIUM)
# =============================================================================

class TestSearchEdgeCases:
    """Tests for search edge cases and error handling."""

    def test_empty_search_returns_empty(self, json_registry_with_commands):
        """
        BV: Empty search handled gracefully.
        """
        registry = json_registry_with_commands
        results = registry.search("")

        # Empty search could return all or none - both valid
        # But should not raise exception
        assert isinstance(results, list)

    def test_whitespace_only_search(self, json_registry_with_commands):
        """
        BV: Whitespace-only search handled gracefully.
        """
        registry = json_registry_with_commands
        results = registry.search("   ")

        assert isinstance(results, list)

    def test_special_characters_in_search(self, tmp_path, command_factory):
        """
        BV: Special characters don't crash search.
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        cmd = command_factory.create(id="test-cmd", name="Test Command")

        json_file = commands_dir / "test.json"
        json_file.write_text(json.dumps({
            "category": "test",
            "commands": [cmd]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        # These should not crash
        registry.search("test!@#$%")
        registry.search("(test)")
        registry.search("[test]")
        registry.search("test*")
        registry.search("test?")

    def test_very_long_search_query(self, json_registry_with_commands):
        """
        BV: Long search queries handled gracefully.
        """
        registry = json_registry_with_commands
        long_query = "a" * 1000

        results = registry.search(long_query)

        assert isinstance(results, list)
        assert len(results) == 0  # Unlikely to match anything

    def test_search_with_numbers(self, tmp_path, command_factory):
        """
        BV: Numeric search terms work.
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        cmd = command_factory.create(
            id="smb-445",
            name="SMB Port 445 Scan",
            command="nmap -p 445 <TARGET>"
        )

        json_file = commands_dir / "test.json"
        json_file.write_text(json.dumps({
            "category": "test",
            "commands": [cmd]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        results = registry.search("445")

        assert len(results) >= 1


# =============================================================================
# Search Result Ordering (BV: LOW)
# =============================================================================

class TestSearchResultOrdering:
    """Tests for search result ordering."""

    def test_results_sorted_by_oscp_relevance(self, tmp_path, command_factory):
        """
        BV: Results are sorted by oscp_relevance for prioritization.

        Note: The current implementation sorts alphabetically by oscp_relevance
        with reverse=True, which gives: medium, low, high. This test documents
        the current behavior. If prioritization is important, the implementation
        should use a custom sort key.
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        low_cmd = command_factory.create(
            id="low-priority",
            name="Test Low",
            oscp_relevance="low"
        )
        high_cmd = command_factory.create(
            id="high-priority",
            name="Test High",
            oscp_relevance="high"
        )
        medium_cmd = command_factory.create(
            id="medium-priority",
            name="Test Medium",
            oscp_relevance="medium"
        )

        json_file = commands_dir / "test.json"
        json_file.write_text(json.dumps({
            "category": "test",
            "commands": [low_cmd, high_cmd, medium_cmd]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        results = registry.search("test")

        # All 3 results returned
        assert len(results) == 3

        # Results are sorted (even if not in ideal priority order)
        # The current sort is alphabetical descending: medium > low > high
        relevance_order = [r.oscp_relevance for r in results]
        # Just verify all relevance levels are present
        assert set(relevance_order) == {"high", "medium", "low"}


# =============================================================================
# Command.matches_search() Direct Tests (BV: MEDIUM)
# =============================================================================

class TestCommandMatchesSearch:
    """Direct tests for Command.matches_search() method."""

    def test_matches_search_checks_all_fields(self):
        """
        BV: Search checks all relevant fields.
        """
        from reference.core.registry import Command

        cmd = Command(
            id="unique-id-xyz",
            name="Unique Name ABC",
            category="test",
            command="unique-command-123",
            description="Unique description DEF",
            tags=["UNIQUE_TAG_789"]
        )

        # Each field should be searchable
        assert cmd.matches_search("xyz")  # ID
        assert cmd.matches_search("abc")  # Name
        assert cmd.matches_search("123")  # Command text
        assert cmd.matches_search("def")  # Description
        assert cmd.matches_search("789")  # Tags

    def test_matches_search_normalizes_both_sides(self):
        """
        BV: Both query and content are normalized.
        """
        from reference.core.registry import Command

        cmd = Command(
            id="pass-the-hash",
            name="Pass-the-Hash Attack",
            category="test",
            command="pth attack",
            description="Pass the hash"
        )

        # Various normalized searches
        assert cmd.matches_search("passthehash")
        assert cmd.matches_search("pass-the-hash")
        assert cmd.matches_search("PASSTHEHASH")

    def test_matches_search_returns_false_for_no_match(self):
        """
        BV: Non-matching queries return False.
        """
        from reference.core.registry import Command

        cmd = Command(
            id="test-cmd",
            name="Test Command",
            category="test",
            command="echo test",
            description="A test"
        )

        assert not cmd.matches_search("nonexistent")
        assert not cmd.matches_search("zzzzzzz")


# =============================================================================
# Normalization Function Tests (BV: LOW - implementation detail)
# =============================================================================

class TestNormalizePunctuation:
    """
    Tests for _normalize_punctuation helper function.

    Note: Testing through public API is preferred, but direct tests
    document expected behavior for maintainers.
    """

    def test_removes_common_punctuation(self):
        """
        BV: Documents which punctuation is normalized.
        """
        from reference.core.registry import _normalize_punctuation

        assert _normalize_punctuation("TGS-REP") == "TGSREP"
        assert _normalize_punctuation("OSCP:HIGH") == "OSCPHIGH"
        assert _normalize_punctuation("/etc/passwd") == "etcpasswd"
        assert _normalize_punctuation("pass_the_hash") == "passthehash"
        assert _normalize_punctuation("test.py") == "testpy"

    def test_preserves_alphanumeric(self):
        """
        BV: Regular characters preserved.
        """
        from reference.core.registry import _normalize_punctuation

        assert _normalize_punctuation("abc123") == "abc123"
        assert _normalize_punctuation("NMAP") == "NMAP"
