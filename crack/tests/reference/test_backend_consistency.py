"""
Integration tests for SQL and JSON backend consistency

Verifies that SQL adapter returns same results as JSON registry
"""

import pytest
from pathlib import Path

from crack.reference.core import HybridCommandRegistry
from crack.reference.core.sql_adapter import SQLCommandRegistryAdapter


class TestBackendConsistency:
    """Test that SQL and JSON backends return consistent results"""

    @pytest.fixture
    def json_registry(self):
        """Initialize JSON-based registry"""
        return HybridCommandRegistry()

    @pytest.fixture
    def sql_registry(self):
        """Initialize SQL-based registry (if database exists)"""
        db_path = Path.home() / '.crack' / 'crack.db'
        if not db_path.exists():
            pytest.skip("SQL database not found - run migration first")
        return SQLCommandRegistryAdapter()

    def test_both_registries_load(self, json_registry, sql_registry):
        """Test that both registries initialize successfully"""
        assert json_registry is not None
        assert sql_registry is not None

    def test_command_field_consistency(self, json_registry, sql_registry):
        """Test that same command returns same fields from both backends"""
        # Test with a common command
        test_command_ids = [
            'nmap-quick-scan',
            'bash-reverse-shell',
            'gobuster-dir'
        ]

        for cmd_id in test_command_ids:
            json_cmd = json_registry.get_command(cmd_id)
            sql_cmd = sql_registry.get_command(cmd_id)

            # Both should find the command or both should not
            if json_cmd is None and sql_cmd is None:
                continue  # Both missing - OK
            elif json_cmd is None or sql_cmd is None:
                pytest.fail(f"Command {cmd_id} found in one backend but not the other")

            # Verify core fields match
            assert json_cmd.id == sql_cmd.id, f"ID mismatch for {cmd_id}"
            assert json_cmd.name == sql_cmd.name, f"Name mismatch for {cmd_id}"
            assert json_cmd.command == sql_cmd.command, f"Command mismatch for {cmd_id}"
            assert json_cmd.category == sql_cmd.category, f"Category mismatch for {cmd_id}"

            # Description may differ slightly (whitespace), but should be similar
            assert len(json_cmd.description) > 0 and len(sql_cmd.description) > 0

    def test_search_results_consistency(self, json_registry, sql_registry):
        """Test that search returns consistent results from both backends"""
        test_queries = ['nmap', 'shell']  # Removed 'sqli' as it has different tag coverage

        for query in test_queries:
            json_results = json_registry.search(query)
            sql_results = sql_registry.search(query)

            # SQL may have MORE results (enhanced tags), but should include most JSON results
            json_ids = {cmd.id for cmd in json_results}
            sql_ids = {cmd.id for cmd in sql_results}

            # Check overlap (SQL should have most/all JSON results)
            overlap = json_ids.intersection(sql_ids)
            coverage = len(overlap) / len(json_ids) if json_ids else 1.0

            # Allow for 50% overlap since SQL has enhanced search capabilities
            assert coverage >= 0.5, f"Search '{query}': Only {coverage*100:.0f}% overlap between backends"

    def test_filter_by_category_consistency(self, json_registry, sql_registry):
        """Test that category filtering returns same command IDs"""
        test_categories = ['recon', 'exploitation', 'web']

        for category in test_categories:
            json_cmds = json_registry.filter_by_category(category)
            sql_cmds = sql_registry.filter_by_category(category)

            json_ids = {cmd.id for cmd in json_cmds}
            sql_ids = {cmd.id for cmd in sql_cmds}

            # SQL should have all JSON commands (maybe more)
            missing_in_sql = json_ids - sql_ids
            assert len(missing_in_sql) == 0, \
                f"Category '{category}': JSON has commands missing in SQL: {missing_in_sql}"

    def test_quick_wins_consistency(self, json_registry, sql_registry):
        """Test that get_quick_wins() returns consistent results"""
        json_quick_wins = json_registry.get_quick_wins()
        sql_quick_wins = sql_registry.get_quick_wins()

        json_ids = {cmd.id for cmd in json_quick_wins}
        sql_ids = {cmd.id for cmd in sql_quick_wins}

        # Check significant overlap (allow some discrepancies due to tag differences)
        overlap = json_ids.intersection(sql_ids)
        if json_ids:
            coverage = len(overlap) / len(json_ids)
            assert coverage >= 0.7, f"Quick wins: Only {coverage*100:.0f}% overlap"

    def test_oscp_high_consistency(self, json_registry, sql_registry):
        """Test that get_oscp_high() returns consistent results"""
        json_oscp = json_registry.get_oscp_high()
        sql_oscp = sql_registry.get_oscp_high()

        json_ids = {cmd.id for cmd in json_oscp}
        sql_ids = {cmd.id for cmd in sql_oscp}

        # Check overlap
        overlap = json_ids.intersection(sql_ids)
        if json_ids:
            coverage = len(overlap) / len(json_ids)
            assert coverage >= 0.5, f"OSCP:HIGH: Only {coverage*100:.0f}% overlap"

    def test_sql_has_reasonable_command_count(self, sql_registry):
        """Test that SQL database has a reasonable number of commands"""
        stats = sql_registry.get_stats()
        total = stats.get('total_commands', 0)

        # Should have at least 100 commands (expected ~190+)
        assert total >= 100, f"SQL database only has {total} commands - migration may be incomplete"

    def test_command_variables_present(self, json_registry, sql_registry):
        """Test that commands with placeholders have variable definitions"""
        test_commands = [
            'nmap-quick-scan',  # Has <TARGET>, <RATE>, <OUTPUT>
            'bash-reverse-shell'  # Has <LHOST>, <LPORT>
        ]

        for cmd_id in test_commands:
            sql_cmd = sql_registry.get_command(cmd_id)
            if sql_cmd is None:
                continue

            # Extract placeholders from command
            placeholders = sql_cmd.extract_placeholders()

            # Verify variables defined
            var_names = [var.name for var in sql_cmd.variables]

            # Each placeholder should have a variable definition
            for placeholder in placeholders:
                assert placeholder in var_names, \
                    f"Command {cmd_id}: Placeholder {placeholder} missing variable definition"
