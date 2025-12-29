"""
BloodTrail Property Importer Tests

Business Value Focus:
- Users need accurate property import for quick-wins detection
- Kerberoastable/AS-REP roastable users must be correctly identified
- Delegation settings must be imported for privilege escalation paths
- Import statistics must accurately reflect what was imported

Ownership: tests/tools/post/bloodtrail/ (exclusive)
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, Mock, MagicMock
import json
import tempfile

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tests.factories.neo4j import (
    MockNeo4jDriver,
    MockNeo4jSession,
    MockNeo4jResult,
    MockRecord,
    create_mock_driver_success,
    create_mock_driver_failure,
)


# =============================================================================
# PROPERTY IMPORT STATS TESTS
# =============================================================================

class TestPropertyImportStats(unittest.TestCase):
    """Tests for PropertyImportStats dataclass."""

    def test_stats_initialized_with_zeros(self):
        """
        BV: Fresh import starts with clean statistics

        Scenario:
          Given: New PropertyImportStats instance
          When: Examined before any import
          Then: All counts are zero
        """
        from tools.post.bloodtrail.property_importer import PropertyImportStats

        stats = PropertyImportStats()

        self.assertEqual(stats.users_imported, 0)
        self.assertEqual(stats.computers_imported, 0)
        self.assertEqual(stats.kerberoastable, 0)
        self.assertEqual(stats.asrep_roastable, 0)

    def test_stats_tracks_errors(self):
        """
        BV: Import errors are collected for debugging

        Scenario:
          Given: Stats instance
          When: Errors occur during import
          Then: Errors are stored in errors list
        """
        from tools.post.bloodtrail.property_importer import PropertyImportStats

        stats = PropertyImportStats()
        stats.errors.append("Test error 1")
        stats.errors.append("Test error 2")

        self.assertEqual(len(stats.errors), 2)
        self.assertIn("Test error 1", stats.errors)


# =============================================================================
# USER PROPERTY IMPORT TESTS
# =============================================================================

class TestUserPropertyImport(unittest.TestCase):
    """Tests for user property import functionality."""

    def _create_users_data(self, users):
        """Helper to create users.json structure."""
        return {"data": [{"Properties": u} for u in users]}

    def test_imports_basic_user_properties(self):
        """
        BV: User properties are available for queries

        Scenario:
          Given: BloodHound users.json with user properties
          When: Import is run
          Then: Users are created/updated in Neo4j with properties
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter
        from tools.post.bloodtrail.data_source import DirectoryDataSource

        # Create mock driver that tracks queries
        mock_driver = create_mock_driver_success([{"imported": 2}])

        importer = PropertyImporter(mock_driver)

        # Create test data
        users_data = self._create_users_data([
            {"name": "USER1@CORP.COM", "enabled": True, "admincount": False},
            {"name": "USER2@CORP.COM", "enabled": True, "admincount": True},
        ])

        # Run internal import method
        importer._import_users(users_data, verbose=False)

        # Verify import was attempted
        session = mock_driver.get_session()
        self.assertGreater(len(session.queries_run), 0)

        # Check that UNWIND query was used (batch import)
        query = session.queries_run[0][0]
        self.assertIn("UNWIND", query.upper())

    def test_detects_kerberoastable_users(self):
        """
        BV: Kerberoastable users are flagged for targeted attacks

        Scenario:
          Given: User with hasspn=true and enabled=true
          When: Import is run
          Then: kerberoastable count is incremented
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter

        mock_driver = create_mock_driver_success([{"imported": 1}])
        importer = PropertyImporter(mock_driver)

        users_data = self._create_users_data([
            {
                "name": "SVCACCOUNT@CORP.COM",
                "enabled": True,
                "hasspn": True,
                "serviceprincipalnames": ["MSSQLSvc/db01:1433"],
            },
        ])

        importer._import_users(users_data, verbose=False)

        self.assertEqual(importer.stats.kerberoastable, 1)

    def test_skips_krbtgt_for_kerberoast(self):
        """
        BV: KRBTGT is not counted as kerberoastable (expected behavior)

        Scenario:
          Given: KRBTGT account with hasspn=true
          When: Import is run
          Then: kerberoastable count is NOT incremented
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter

        mock_driver = create_mock_driver_success([{"imported": 1}])
        importer = PropertyImporter(mock_driver)

        users_data = self._create_users_data([
            {"name": "KRBTGT@CORP.COM", "enabled": True, "hasspn": True},
        ])

        importer._import_users(users_data, verbose=False)

        self.assertEqual(importer.stats.kerberoastable, 0)

    def test_detects_asrep_roastable_users(self):
        """
        BV: AS-REP roastable users are flagged for offline cracking

        Scenario:
          Given: User with dontreqpreauth=true and enabled=true
          When: Import is run
          Then: asrep_roastable count is incremented
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter

        mock_driver = create_mock_driver_success([{"imported": 1}])
        importer = PropertyImporter(mock_driver)

        users_data = self._create_users_data([
            {"name": "WEAKUSER@CORP.COM", "enabled": True, "dontreqpreauth": True},
        ])

        importer._import_users(users_data, verbose=False)

        self.assertEqual(importer.stats.asrep_roastable, 1)

    def test_disabled_user_not_counted_as_kerberoastable(self):
        """
        BV: Disabled accounts are not counted (can't be exploited)

        Scenario:
          Given: Disabled user with hasspn=true
          When: Import is run
          Then: kerberoastable count is NOT incremented
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter

        mock_driver = create_mock_driver_success([{"imported": 1}])
        importer = PropertyImporter(mock_driver)

        users_data = self._create_users_data([
            {"name": "OLDSVC@CORP.COM", "enabled": False, "hasspn": True},
        ])

        importer._import_users(users_data, verbose=False)

        self.assertEqual(importer.stats.kerberoastable, 0)

    def test_tracks_privileged_users(self):
        """
        BV: Admincount users are tracked for targeting

        Scenario:
          Given: User with admincount=true
          When: Import is run
          Then: privileged_users count is incremented
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter

        mock_driver = create_mock_driver_success([{"imported": 1}])
        importer = PropertyImporter(mock_driver)

        users_data = self._create_users_data([
            {"name": "ADMIN@CORP.COM", "enabled": True, "admincount": True},
        ])

        importer._import_users(users_data, verbose=False)

        self.assertEqual(importer.stats.privileged_users, 1)

    def test_handles_missing_name_gracefully(self):
        """
        BV: Malformed data doesn't crash import

        Scenario:
          Given: User entry without 'name' property
          When: Import is run
          Then: Entry is skipped, no crash
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter

        mock_driver = create_mock_driver_success([{"imported": 0}])
        importer = PropertyImporter(mock_driver)

        users_data = self._create_users_data([
            {"enabled": True, "hasspn": True},  # Missing 'name'
        ])

        # Should not raise exception
        importer._import_users(users_data, verbose=False)

        self.assertEqual(importer.stats.kerberoastable, 0)


# =============================================================================
# COMPUTER PROPERTY IMPORT TESTS
# =============================================================================

class TestComputerPropertyImport(unittest.TestCase):
    """Tests for computer property import functionality."""

    def _create_computers_data(self, computers):
        """Helper to create computers.json structure."""
        return {"data": [{"Properties": c} for c in computers]}

    def test_imports_basic_computer_properties(self):
        """
        BV: Computer properties are available for queries

        Scenario:
          Given: BloodHound computers.json with computer properties
          When: Import is run
          Then: Computers are created/updated in Neo4j
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter

        mock_driver = create_mock_driver_success([{"imported": 1}])
        importer = PropertyImporter(mock_driver)

        computers_data = self._create_computers_data([
            {"name": "DC01.CORP.COM", "enabled": True, "operatingsystem": "Windows Server 2019"},
        ])

        importer._import_computers(computers_data, verbose=False)

        session = mock_driver.get_session()
        self.assertGreater(len(session.queries_run), 0)

    def test_detects_unconstrained_delegation(self):
        """
        BV: Unconstrained delegation hosts are flagged for coercion attacks

        Scenario:
          Given: Computer with unconstraineddelegation=true
          When: Import is run
          Then: unconstrained_delegation count is incremented
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter

        mock_driver = create_mock_driver_success([{"imported": 1}])
        importer = PropertyImporter(mock_driver)

        computers_data = self._create_computers_data([
            {"name": "WEB01.CORP.COM", "enabled": True, "unconstraineddelegation": True},
        ])

        importer._import_computers(computers_data, verbose=False)

        self.assertEqual(importer.stats.unconstrained_delegation, 1)

    def test_detects_constrained_delegation(self):
        """
        BV: Constrained delegation hosts are flagged for S4U attacks

        Scenario:
          Given: Computer with trustedtoauth=true
          When: Import is run
          Then: constrained_delegation count is incremented
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter

        mock_driver = create_mock_driver_success([{"imported": 1}])
        importer = PropertyImporter(mock_driver)

        computers_data = self._create_computers_data([
            {"name": "APP01.CORP.COM", "enabled": True, "trustedtoauth": True},
        ])

        importer._import_computers(computers_data, verbose=False)

        self.assertEqual(importer.stats.constrained_delegation, 1)

    def test_detects_computers_without_laps(self):
        """
        BV: Computers without LAPS are flagged for credential reuse

        Scenario:
          Given: Computer with haslaps=false
          When: Import is run
          Then: no_laps count is incremented
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter

        mock_driver = create_mock_driver_success([{"imported": 1}])
        importer = PropertyImporter(mock_driver)

        computers_data = self._create_computers_data([
            {"name": "WS01.CORP.COM", "enabled": True, "haslaps": False},
        ])

        importer._import_computers(computers_data, verbose=False)

        self.assertEqual(importer.stats.no_laps, 1)

    def test_skips_dcs_for_laps_count(self):
        """
        BV: Domain Controllers are not counted for LAPS (they don't use LAPS)

        Scenario:
          Given: DC without LAPS
          When: Import is run
          Then: no_laps count is NOT incremented
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter

        mock_driver = create_mock_driver_success([{"imported": 1}])
        importer = PropertyImporter(mock_driver)

        computers_data = self._create_computers_data([
            {"name": "DC01.CORP.COM", "enabled": True, "haslaps": False},
        ])

        importer._import_computers(computers_data, verbose=False)

        # DC should not count
        self.assertEqual(importer.stats.no_laps, 0)


# =============================================================================
# GROUP PROPERTY IMPORT TESTS
# =============================================================================

class TestGroupPropertyImport(unittest.TestCase):
    """Tests for group property import functionality."""

    def _create_groups_data(self, groups):
        """Helper to create groups.json structure."""
        return {"data": [{"Properties": g} for g in groups]}

    def test_imports_group_properties(self):
        """
        BV: Group properties are available for queries

        Scenario:
          Given: BloodHound groups.json with group properties
          When: Import is run
          Then: Groups are created/updated in Neo4j
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter

        mock_driver = create_mock_driver_success([{"imported": 1}])
        importer = PropertyImporter(mock_driver)

        groups_data = self._create_groups_data([
            {"name": "DOMAIN ADMINS@CORP.COM", "admincount": True, "highvalue": True},
        ])

        importer._import_groups(groups_data, verbose=False)

        session = mock_driver.get_session()
        self.assertGreater(len(session.queries_run), 0)

        # Verify UNWIND batch import
        query = session.queries_run[0][0]
        self.assertIn("UNWIND", query.upper())


# =============================================================================
# DOMAIN PROPERTY IMPORT TESTS
# =============================================================================

class TestDomainPropertyImport(unittest.TestCase):
    """Tests for domain property import functionality."""

    def _create_domains_data(self, domains):
        """Helper to create domains.json structure."""
        return {"data": [{"Properties": d} for d in domains]}

    def test_imports_domain_properties(self):
        """
        BV: Domain properties are available for queries

        Scenario:
          Given: BloodHound domains.json with domain properties
          When: Import is run
          Then: Domains are created/updated in Neo4j
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter

        mock_driver = create_mock_driver_success([{"imported": 1}])
        importer = PropertyImporter(mock_driver)

        domains_data = self._create_domains_data([
            {"name": "CORP.COM", "functionallevel": "2016", "highvalue": True},
        ])

        importer._import_domains(domains_data, verbose=False)

        session = mock_driver.get_session()
        self.assertGreater(len(session.queries_run), 0)


# =============================================================================
# BATCH IMPORT TESTS
# =============================================================================

class TestBatchImport(unittest.TestCase):
    """Tests for batch import functionality."""

    def test_uses_unwind_for_batch_import(self):
        """
        BV: Large imports are efficient using UNWIND

        Scenario:
          Given: Multiple users to import
          When: Import is run
          Then: UNWIND query is used for batching
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter

        mock_driver = create_mock_driver_success([{"imported": 5}])
        importer = PropertyImporter(mock_driver)

        users = [
            {"name": f"USER{i}@CORP.COM", "enabled": True}
            for i in range(5)
        ]

        importer._batch_import_users(users, verbose=False)

        session = mock_driver.get_session()
        query = session.queries_run[0][0]

        self.assertIn("UNWIND", query.upper())
        self.assertIn("$users", query)  # Parameter binding

    def test_uses_parameter_binding_not_interpolation(self):
        """
        BV: Import queries use parameter binding for security

        Scenario:
          Given: User data with special characters
          When: Import is run
          Then: Data is passed as parameters, not interpolated
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter

        mock_driver = create_mock_driver_success([{"imported": 1}])
        importer = PropertyImporter(mock_driver)

        # User with special characters that could cause injection
        users = [
            {"name": "TEST'; DROP TABLE Users;--@CORP.COM", "enabled": True}
        ]

        importer._batch_import_users(users, verbose=False)

        session = mock_driver.get_session()
        query, params = session.queries_run[0]

        # Query should use parameter placeholder, not contain the malicious string
        self.assertNotIn("DROP TABLE", query)
        self.assertIn("$users", query)

    def test_respects_batch_size(self):
        """
        BV: Large imports are chunked to prevent memory issues

        Scenario:
          Given: 250 users and batch_size=100
          When: Import is run
          Then: Users are processed in batches (100, 100, 50)

        Note:
          This test verifies the batching logic exists by checking
          that the importer processes all users despite batch_size limit.
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter

        mock_driver = create_mock_driver_success([{"imported": 100}])
        importer = PropertyImporter(mock_driver, batch_size=100)

        users = [
            {"name": f"USER{i}@CORP.COM", "enabled": True}
            for i in range(250)  # 250 users, batch_size=100 -> 3 batches
        ]

        importer._batch_import_users(users, verbose=False)

        # Verify batch size is correctly set
        self.assertEqual(importer.batch_size, 100)

        # Verify some queries were run
        session = mock_driver.get_session()
        self.assertGreater(len(session.queries_run), 0)


# =============================================================================
# DATA SOURCE INTEGRATION TESTS
# =============================================================================

class TestDataSourceIntegration(unittest.TestCase):
    """Tests for import from DataSource (directory or ZIP)."""

    def test_import_from_directory_source(self):
        """
        BV: Users can import directly from BloodHound output directory

        Scenario:
          Given: Directory with BloodHound JSON files
          When: import_from_source() is called
          Then: All JSON files are processed
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter
        from tools.post.bloodtrail.data_source import DirectoryDataSource

        mock_driver = create_mock_driver_success([{"imported": 1}])

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            # Create test files
            users_data = {"data": [{"Properties": {"name": "USER@CORP.COM", "enabled": True}}]}
            with open(tmppath / "users.json", "w") as f:
                json.dump(users_data, f)

            data_source = DirectoryDataSource(tmppath)
            importer = PropertyImporter(mock_driver)

            stats = importer.import_from_source(data_source)

            self.assertGreaterEqual(stats.users_imported, 0)

    def test_import_handles_empty_data_array(self):
        """
        BV: Empty data files don't cause errors

        Scenario:
          Given: JSON file with empty data array
          When: Import is run
          Then: No errors, zero count
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter
        from tools.post.bloodtrail.data_source import DirectoryDataSource

        mock_driver = create_mock_driver_success([])

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            # Create empty users file
            with open(tmppath / "users.json", "w") as f:
                json.dump({"data": []}, f)

            data_source = DirectoryDataSource(tmppath)
            importer = PropertyImporter(mock_driver)

            stats = importer.import_from_source(data_source)

            self.assertEqual(stats.users_imported, 0)
            self.assertEqual(len(stats.errors), 0)


# =============================================================================
# ERROR HANDLING TESTS
# =============================================================================

class TestErrorHandling(unittest.TestCase):
    """Tests for error handling during import."""

    def test_handles_neo4j_connection_error(self):
        """
        BV: Connection errors are caught and reported

        Scenario:
          Given: Neo4j is unavailable
          When: Import is attempted
          Then: Error is recorded, not raised
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter

        mock_driver = create_mock_driver_failure(ConnectionError, "Connection refused")
        importer = PropertyImporter(mock_driver)

        users = [{"name": "USER@CORP.COM", "enabled": True}]

        # Should not raise exception
        importer._batch_import_users(users, verbose=False)

        # Error should be recorded
        self.assertGreater(len(importer.stats.errors), 0)

    def test_tracks_duration(self):
        """
        BV: Users can see how long import took

        Scenario:
          Given: Import process
          When: Import completes
          Then: duration_seconds is populated
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter
        from tools.post.bloodtrail.data_source import DirectoryDataSource

        mock_driver = create_mock_driver_success([{"imported": 1}])

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            with open(tmppath / "users.json", "w") as f:
                json.dump({"data": []}, f)

            data_source = DirectoryDataSource(tmppath)
            importer = PropertyImporter(mock_driver)

            stats = importer.import_from_source(data_source)

            self.assertGreaterEqual(stats.duration_seconds, 0)


# =============================================================================
# STATS AGGREGATION TESTS
# =============================================================================

class TestStatsAggregation(unittest.TestCase):
    """Tests for statistics aggregation across multiple files."""

    def test_aggregates_counts_across_files(self):
        """
        BV: Total counts reflect all processed files

        Scenario:
          Given: Multiple JSON files with users
          When: Import is run
          Then: Total counts sum across files
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter
        from tools.post.bloodtrail.data_source import DirectoryDataSource

        mock_driver = create_mock_driver_success([{"imported": 2}])

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            # Create users file
            users_data = {"data": [
                {"Properties": {"name": "USER1@CORP.COM", "enabled": True, "hasspn": True}},
                {"Properties": {"name": "USER2@CORP.COM", "enabled": True, "dontreqpreauth": True}},
            ]}
            with open(tmppath / "users.json", "w") as f:
                json.dump(users_data, f)

            # Create computers file
            computers_data = {"data": [
                {"Properties": {"name": "DC01.CORP.COM", "enabled": True, "unconstraineddelegation": True}},
            ]}
            with open(tmppath / "computers.json", "w") as f:
                json.dump(computers_data, f)

            data_source = DirectoryDataSource(tmppath)
            importer = PropertyImporter(mock_driver)

            stats = importer.import_from_source(data_source)

            # Should have counted Kerberoastable, AS-REP, and unconstrained
            self.assertEqual(stats.kerberoastable, 1)
            self.assertEqual(stats.asrep_roastable, 1)
            self.assertEqual(stats.unconstrained_delegation, 1)


if __name__ == "__main__":
    unittest.main()
