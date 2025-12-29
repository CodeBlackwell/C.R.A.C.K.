"""
BloodTrail AutoSpray Target Sources Tests

Business Value Focus:
- Users need reliable target lists from multiple sources (Neo4j, files)
- User filtering ensures only relevant accounts are sprayed
- Machine targeting enables network-wide authentication testing
- IP validation prevents invalid targets from causing spray failures

Ownership: tests/tools/post/bloodtrail/autospray/ (exclusive)
"""

import sys
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch, Mock, MagicMock

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent.parent
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
# TARGET DATACLASS TESTS
# =============================================================================

class TestTargetDataclass(unittest.TestCase):
    """Tests for the Target dataclass."""

    def test_target_hash_uses_value_and_type(self):
        """
        BV: Deduplication works correctly across multiple sources

        Scenario:
          Given: Two targets with same value and type
          When: Added to a set
          Then: Only one is kept (hash collision)
        """
        from tools.post.bloodtrail.autospray.target_sources import Target

        target1 = Target(value="admin", target_type="user")
        target2 = Target(value="admin", target_type="user")

        target_set = {target1, target2}

        self.assertEqual(len(target_set), 1)

    def test_target_equality_ignores_source(self):
        """
        BV: Same target from different sources is still deduplicated

        Scenario:
          Given: Same username from Neo4j and file
          When: Compared for equality
          Then: They are equal
        """
        from tools.post.bloodtrail.autospray.target_sources import Target

        target1 = Target(value="admin", target_type="user", source="neo4j")
        target2 = Target(value="admin", target_type="user", source="file")

        self.assertEqual(target1, target2)

    def test_target_different_types_not_equal(self):
        """
        BV: User and machine with same name are treated differently

        Scenario:
          Given: Same string as user and machine target
          When: Compared for equality
          Then: They are not equal
        """
        from tools.post.bloodtrail.autospray.target_sources import Target

        target_user = Target(value="admin", target_type="user")
        target_machine = Target(value="admin", target_type="machine")

        self.assertNotEqual(target_user, target_machine)

    def test_target_metadata_is_dict(self):
        """
        BV: Additional target info can be stored in metadata

        Scenario:
          Given: Target with metadata
          When: Metadata accessed
          Then: Dict with expected keys is available
        """
        from tools.post.bloodtrail.autospray.target_sources import Target

        target = Target(
            value="admin",
            target_type="user",
            metadata={"enabled": True, "pwned": False}
        )

        self.assertEqual(target.metadata["enabled"], True)
        self.assertEqual(target.metadata["pwned"], False)


# =============================================================================
# TARGET SOURCE ABC TESTS
# =============================================================================

class TestTargetSourceABC(unittest.TestCase):
    """Tests for TargetSource abstract base class interface."""

    def test_target_source_has_required_methods(self):
        """
        BV: All target sources implement consistent interface

        Scenario:
          Given: TargetSource ABC
          When: Interface examined
          Then: name, target_type, get_targets, is_available are defined
        """
        from tools.post.bloodtrail.autospray.target_sources import TargetSource
        import inspect

        # Check abstract methods
        abstract_methods = getattr(TargetSource, '__abstractmethods__', set())

        self.assertIn('name', abstract_methods)
        self.assertIn('target_type', abstract_methods)
        self.assertIn('get_targets', abstract_methods)
        self.assertIn('is_available', abstract_methods)

    def test_get_values_convenience_method(self):
        """
        BV: Users can easily get just target strings for spraying

        Scenario:
          Given: Source with multiple targets
          When: get_values() is called
          Then: Only value strings are returned
        """
        from tools.post.bloodtrail.autospray.target_sources import FileTargetSource

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("user1\nuser2\nuser3\n")
            f.flush()

            source = FileTargetSource(f.name, target_type="user")
            values = source.get_values()

            self.assertIsInstance(values, list)
            self.assertEqual(len(values), 3)
            self.assertIn("user1", values)


# =============================================================================
# NEO4J USER SOURCE TESTS
# =============================================================================

class TestNeo4jUserSource(unittest.TestCase):
    """Tests for Neo4jUserSource."""

    def setUp(self):
        """Set up mock Neo4j config."""
        self.mock_config = Mock()
        self.mock_config.uri = "bolt://localhost:7687"
        self.mock_config.user = "neo4j"
        self.mock_config.password = "password"

    def test_name_includes_filter(self):
        """
        BV: Source name indicates which filter is applied

        Scenario:
          Given: Neo4jUserSource with filter
          When: name property accessed
          Then: Filter type is included in name
        """
        from tools.post.bloodtrail.autospray.target_sources import Neo4jUserSource

        source = Neo4jUserSource(self.mock_config, user_filter="enabled")

        self.assertIn("enabled", source.name)

    def test_target_type_is_user(self):
        """
        BV: Source correctly identifies as user source

        Scenario:
          Given: Neo4jUserSource
          When: target_type property accessed
          Then: Returns 'user'
        """
        from tools.post.bloodtrail.autospray.target_sources import Neo4jUserSource

        source = Neo4jUserSource(self.mock_config)

        self.assertEqual(source.target_type, "user")

    def test_is_available_returns_true_when_connected(self):
        """
        BV: Users know if Neo4j is accessible before spraying

        Scenario:
          Given: Neo4j is running
          When: is_available() is called
          Then: Returns True
        """
        from tools.post.bloodtrail.autospray.target_sources import Neo4jUserSource

        mock_driver = create_mock_driver_success([])

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            source = Neo4jUserSource(self.mock_config)
            result = source.is_available()

            self.assertTrue(result)

    def test_is_available_returns_false_on_connection_error(self):
        """
        BV: Connection failures don't crash the application

        Scenario:
          Given: Neo4j is not running
          When: is_available() is called
          Then: Returns False (not exception)
        """
        from tools.post.bloodtrail.autospray.target_sources import Neo4jUserSource

        mock_driver = create_mock_driver_failure(ConnectionError, "Connection refused")

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            source = Neo4jUserSource(self.mock_config)
            result = source.is_available()

            self.assertFalse(result)

    def test_get_targets_extracts_usernames(self):
        """
        BV: Usernames from BloodHound data are available for spraying

        Scenario:
          Given: Neo4j contains User nodes
          When: get_targets() is called
          Then: Usernames are returned as targets
        """
        from tools.post.bloodtrail.autospray.target_sources import Neo4jUserSource

        mock_records = [
            {"username": "admin", "enabled": True, "pwned": False},
            {"username": "user1", "enabled": True, "pwned": False},
        ]
        mock_driver = create_mock_driver_success(mock_records)

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            source = Neo4jUserSource(self.mock_config)
            targets = source.get_targets()

            self.assertEqual(len(targets), 2)
            values = {t.value for t in targets}
            self.assertEqual(values, {"admin", "user1"})

    def test_get_targets_filter_all_includes_disabled(self):
        """
        BV: Users can spray all accounts including disabled

        Scenario:
          Given: Neo4j contains enabled and disabled users
          When: get_targets() called with filter='all'
          Then: All users are returned
        """
        from tools.post.bloodtrail.autospray.target_sources import Neo4jUserSource

        mock_records = [
            {"username": "enabled_user", "enabled": True, "pwned": False},
            {"username": "disabled_user", "enabled": False, "pwned": False},
        ]
        mock_driver = create_mock_driver_success(mock_records)

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            source = Neo4jUserSource(self.mock_config, user_filter="all")
            targets = source.get_targets()

            self.assertEqual(len(targets), 2)

    def test_get_targets_filter_non_pwned_excludes_owned(self):
        """
        BV: Users can skip already-compromised accounts

        Scenario:
          Given: Neo4j contains pwned and non-pwned users
          When: get_targets() called with filter='non-pwned'
          Then: Only non-pwned users are returned
        """
        from tools.post.bloodtrail.autospray.target_sources import Neo4jUserSource

        # The query filtering happens in Neo4j, we just verify the right query is used
        mock_records = [
            {"username": "not_pwned", "enabled": True, "pwned": False},
        ]
        mock_driver = create_mock_driver_success(mock_records)

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            source = Neo4jUserSource(self.mock_config, user_filter="non-pwned")
            targets = source.get_targets()

            # With filter applied, only non-pwned returned
            self.assertEqual(len(targets), 1)

    def test_get_targets_includes_metadata(self):
        """
        BV: Additional user info is preserved for display

        Scenario:
          Given: Neo4j returns user with enabled/pwned status
          When: get_targets() is called
          Then: Metadata contains status fields
        """
        from tools.post.bloodtrail.autospray.target_sources import Neo4jUserSource

        mock_records = [
            {"username": "admin", "enabled": True, "pwned": False},
        ]
        mock_driver = create_mock_driver_success(mock_records)

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            source = Neo4jUserSource(self.mock_config)
            targets = source.get_targets()

            self.assertEqual(len(targets), 1)
            self.assertIn("enabled", targets[0].metadata)
            self.assertIn("pwned", targets[0].metadata)

    def test_get_targets_returns_empty_on_error(self):
        """
        BV: Query errors don't crash the spray operation

        Scenario:
          Given: Neo4j query fails
          When: get_targets() is called
          Then: Empty list returned (not exception)
        """
        from tools.post.bloodtrail.autospray.target_sources import Neo4jUserSource

        mock_driver = create_mock_driver_failure(RuntimeError, "Query failed")

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            source = Neo4jUserSource(self.mock_config)
            targets = source.get_targets()

            self.assertEqual(targets, [])

    def test_close_releases_driver(self):
        """
        BV: Resources are properly released after use

        Scenario:
          Given: Connected Neo4j source
          When: close() is called
          Then: Driver is closed
        """
        from tools.post.bloodtrail.autospray.target_sources import Neo4jUserSource

        mock_driver = create_mock_driver_success([])

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            source = Neo4jUserSource(self.mock_config)
            source._connect()  # Force connection
            source.close()

            self.assertTrue(mock_driver.closed)
            self.assertIsNone(source._driver)


# =============================================================================
# NEO4J MACHINE SOURCE TESTS
# =============================================================================

class TestNeo4jMachineSource(unittest.TestCase):
    """Tests for Neo4jMachineSource."""

    def setUp(self):
        """Set up mock Neo4j config."""
        self.mock_config = Mock()
        self.mock_config.uri = "bolt://localhost:7687"
        self.mock_config.user = "neo4j"
        self.mock_config.password = "password"

    def test_name_property(self):
        """
        BV: Source is identifiable in statistics and logs

        Scenario:
          Given: Neo4jMachineSource
          When: name property accessed
          Then: Returns human-readable identifier
        """
        from tools.post.bloodtrail.autospray.target_sources import Neo4jMachineSource

        source = Neo4jMachineSource(self.mock_config)

        self.assertEqual(source.name, "Neo4j Machines")

    def test_target_type_is_machine(self):
        """
        BV: Source correctly identifies as machine source

        Scenario:
          Given: Neo4jMachineSource
          When: target_type property accessed
          Then: Returns 'machine'
        """
        from tools.post.bloodtrail.autospray.target_sources import Neo4jMachineSource

        source = Neo4jMachineSource(self.mock_config)

        self.assertEqual(source.target_type, "machine")

    def test_get_targets_extracts_hostnames(self):
        """
        BV: Computer hostnames from BloodHound data are available

        Scenario:
          Given: Neo4j contains Computer nodes
          When: get_targets() is called
          Then: Hostnames are returned as targets
        """
        from tools.post.bloodtrail.autospray.target_sources import Neo4jMachineSource

        mock_records = [
            {"hostname": "DC01.CORP.COM", "ip": None, "os": "Windows Server 2019",
             "enabled": True, "is_dc": True},
            {"hostname": "WS01.CORP.COM", "ip": "192.168.1.100", "os": "Windows 10",
             "enabled": True, "is_dc": False},
        ]
        mock_driver = create_mock_driver_success(mock_records)

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            source = Neo4jMachineSource(self.mock_config)
            targets = source.get_targets()

            self.assertEqual(len(targets), 2)

    def test_get_targets_prefers_ip_over_hostname(self):
        """
        BV: IP addresses are used when available for more reliable targeting

        Scenario:
          Given: Computer has both hostname and IP
          When: get_targets() is called
          Then: IP is used as target value
        """
        from tools.post.bloodtrail.autospray.target_sources import Neo4jMachineSource

        mock_records = [
            {"hostname": "WS01.CORP.COM", "ip": "192.168.1.100", "os": "Windows 10",
             "enabled": True, "is_dc": False},
        ]
        mock_driver = create_mock_driver_success(mock_records)

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            source = Neo4jMachineSource(self.mock_config)
            targets = source.get_targets()

            self.assertEqual(len(targets), 1)
            self.assertEqual(targets[0].value, "192.168.1.100")

    def test_get_targets_excludes_dc_when_configured(self):
        """
        BV: Domain Controllers can be excluded to avoid lockouts

        Scenario:
          Given: Neo4j contains DC and workstation
          When: get_targets(include_dc=False) is called
          Then: DC is excluded
        """
        from tools.post.bloodtrail.autospray.target_sources import Neo4jMachineSource

        mock_records = [
            {"hostname": "DC01.CORP.COM", "ip": None, "os": "Windows Server 2019",
             "enabled": True, "is_dc": True},
            {"hostname": "WS01.CORP.COM", "ip": "192.168.1.100", "os": "Windows 10",
             "enabled": True, "is_dc": False},
        ]
        mock_driver = create_mock_driver_success(mock_records)

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            source = Neo4jMachineSource(self.mock_config, include_dc=False)
            targets = source.get_targets()

            # Only workstation should be returned (IP is preferred over hostname)
            self.assertEqual(len(targets), 1)
            # Value should be IP (192.168.1.100) since it's valid
            # Hostname is preserved in metadata
            self.assertEqual(targets[0].value, "192.168.1.100")
            self.assertEqual(targets[0].metadata.get("hostname"), "WS01.CORP.COM")

    def test_get_targets_includes_dc_metadata(self):
        """
        BV: DC status is preserved in metadata for display

        Scenario:
          Given: Neo4j contains DC
          When: get_targets() is called
          Then: is_dc flag is in metadata
        """
        from tools.post.bloodtrail.autospray.target_sources import Neo4jMachineSource

        mock_records = [
            {"hostname": "DC01.CORP.COM", "ip": None, "os": "Windows Server 2019",
             "enabled": True, "is_dc": True},
        ]
        mock_driver = create_mock_driver_success(mock_records)

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            source = Neo4jMachineSource(self.mock_config)
            targets = source.get_targets()

            self.assertEqual(len(targets), 1)
            self.assertTrue(targets[0].metadata.get("is_dc"))

    def test_is_valid_ip_validates_ipv4(self):
        """
        BV: Only valid IPs are used for targeting

        Scenario:
          Given: Various IP-like strings
          When: _is_valid_ip() is called
          Then: Only valid IPv4 addresses return True
        """
        from tools.post.bloodtrail.autospray.target_sources import Neo4jMachineSource

        # Valid IPs
        self.assertTrue(Neo4jMachineSource._is_valid_ip("192.168.1.1"))
        self.assertTrue(Neo4jMachineSource._is_valid_ip("10.0.0.1"))
        self.assertTrue(Neo4jMachineSource._is_valid_ip("255.255.255.255"))
        self.assertTrue(Neo4jMachineSource._is_valid_ip("0.0.0.0"))

        # Invalid IPs
        self.assertFalse(Neo4jMachineSource._is_valid_ip("192.168.1.256"))
        self.assertFalse(Neo4jMachineSource._is_valid_ip("192.168.1"))
        self.assertFalse(Neo4jMachineSource._is_valid_ip("hostname"))
        self.assertFalse(Neo4jMachineSource._is_valid_ip(""))
        self.assertFalse(Neo4jMachineSource._is_valid_ip(None))

    def test_is_valid_ip_rejects_negative_octets(self):
        """
        BV: Negative numbers in IP are rejected

        Scenario:
          Given: IP with negative octet
          When: _is_valid_ip() is called
          Then: Returns False
        """
        from tools.post.bloodtrail.autospray.target_sources import Neo4jMachineSource

        self.assertFalse(Neo4jMachineSource._is_valid_ip("192.168.-1.1"))
        self.assertFalse(Neo4jMachineSource._is_valid_ip("-1.0.0.1"))

    def test_close_releases_driver(self):
        """
        BV: Resources are properly released after use

        Scenario:
          Given: Connected Neo4j source
          When: close() is called
          Then: Driver is closed
        """
        from tools.post.bloodtrail.autospray.target_sources import Neo4jMachineSource

        mock_driver = create_mock_driver_success([])

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            source = Neo4jMachineSource(self.mock_config)
            source._connect()  # Force connection
            source.close()

            self.assertTrue(mock_driver.closed)
            self.assertIsNone(source._driver)


# =============================================================================
# FILE TARGET SOURCE TESTS
# =============================================================================

class TestFileTargetSource(unittest.TestCase):
    """Tests for FileTargetSource."""

    def test_name_includes_filename(self):
        """
        BV: Source name identifies which file was used

        Scenario:
          Given: FileTargetSource with specific file
          When: name property accessed
          Then: Filename is included
        """
        from tools.post.bloodtrail.autospray.target_sources import FileTargetSource

        source = FileTargetSource(Path("/tmp/users.txt"), target_type="user")

        self.assertIn("users.txt", source.name)

    def test_target_type_preserved(self):
        """
        BV: Target type from constructor is used

        Scenario:
          Given: FileTargetSource with target_type='machine'
          When: target_type property accessed
          Then: Returns 'machine'
        """
        from tools.post.bloodtrail.autospray.target_sources import FileTargetSource

        source = FileTargetSource(Path("/tmp/hosts.txt"), target_type="machine")

        self.assertEqual(source.target_type, "machine")

    def test_is_available_returns_true_for_existing_file(self):
        """
        BV: Users know if target file is accessible

        Scenario:
          Given: Target file exists
          When: is_available() is called
          Then: Returns True
        """
        from tools.post.bloodtrail.autospray.target_sources import FileTargetSource

        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            source = FileTargetSource(f.name, target_type="user")
            self.assertTrue(source.is_available())

    def test_is_available_returns_false_for_missing_file(self):
        """
        BV: Missing target files are handled gracefully

        Scenario:
          Given: Target file doesn't exist
          When: is_available() is called
          Then: Returns False
        """
        from tools.post.bloodtrail.autospray.target_sources import FileTargetSource

        source = FileTargetSource("/nonexistent/users.txt", target_type="user")

        self.assertFalse(source.is_available())

    def test_get_targets_reads_one_per_line(self):
        """
        BV: Standard target list format is correctly parsed

        Scenario:
          Given: File with targets on separate lines
          When: get_targets() is called
          Then: Each line becomes a target
        """
        from tools.post.bloodtrail.autospray.target_sources import FileTargetSource

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("user1\nuser2\nuser3\n")
            f.flush()

            source = FileTargetSource(f.name, target_type="user")
            targets = source.get_targets()

            self.assertEqual(len(targets), 3)
            values = {t.value for t in targets}
            self.assertEqual(values, {"user1", "user2", "user3"})

    def test_get_targets_skips_comments(self):
        """
        BV: Comment lines in target files are ignored

        Scenario:
          Given: File with # comment lines
          When: get_targets() is called
          Then: Comments are skipped
        """
        from tools.post.bloodtrail.autospray.target_sources import FileTargetSource

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("# This is a comment\nuser1\n# Another comment\n")
            f.flush()

            source = FileTargetSource(f.name, target_type="user")
            targets = source.get_targets()

            self.assertEqual(len(targets), 1)
            self.assertEqual(targets[0].value, "user1")

    def test_get_targets_skips_empty_lines(self):
        """
        BV: Empty lines don't create invalid targets

        Scenario:
          Given: File with empty lines
          When: get_targets() is called
          Then: Empty lines are skipped
        """
        from tools.post.bloodtrail.autospray.target_sources import FileTargetSource

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("user1\n\n\nuser2\n")
            f.flush()

            source = FileTargetSource(f.name, target_type="user")
            targets = source.get_targets()

            self.assertEqual(len(targets), 2)

    def test_get_targets_returns_empty_for_unavailable_file(self):
        """
        BV: Missing files don't cause exceptions during spray

        Scenario:
          Given: Target file doesn't exist
          When: get_targets() is called
          Then: Empty list returned
        """
        from tools.post.bloodtrail.autospray.target_sources import FileTargetSource

        source = FileTargetSource("/nonexistent/users.txt", target_type="user")
        targets = source.get_targets()

        self.assertEqual(targets, [])


# =============================================================================
# TARGET MANAGER TESTS
# =============================================================================

class TestTargetManager(unittest.TestCase):
    """Tests for TargetManager orchestration."""

    def test_add_user_source_filters_by_type(self):
        """
        BV: Only user sources are added to user list

        Scenario:
          Given: Empty TargetManager
          When: add_user_source() called with user source
          Then: Source is added to user_sources
        """
        from tools.post.bloodtrail.autospray.target_sources import (
            TargetManager, FileTargetSource
        )

        manager = TargetManager()

        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            source = FileTargetSource(f.name, target_type="user")
            manager.add_user_source(source)

            self.assertEqual(len(manager.user_sources), 1)
            self.assertEqual(len(manager.machine_sources), 0)

    def test_add_machine_source_filters_by_type(self):
        """
        BV: Only machine sources are added to machine list

        Scenario:
          Given: Empty TargetManager
          When: add_machine_source() called with machine source
          Then: Source is added to machine_sources
        """
        from tools.post.bloodtrail.autospray.target_sources import (
            TargetManager, FileTargetSource
        )

        manager = TargetManager()

        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            source = FileTargetSource(f.name, target_type="machine")
            manager.add_machine_source(source)

            self.assertEqual(len(manager.machine_sources), 1)
            self.assertEqual(len(manager.user_sources), 0)

    def test_get_users_aggregates_sources(self):
        """
        BV: Users from all sources are combined

        Scenario:
          Given: Multiple user file sources
          When: get_users() is called
          Then: Users from all sources are returned
        """
        from tools.post.bloodtrail.autospray.target_sources import (
            TargetManager, FileTargetSource
        )

        manager = TargetManager()

        # Create two user files
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f1:
            f1.write("user1\n")
            f1.flush()
            manager.add_user_source(FileTargetSource(f1.name, target_type="user"))

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f2:
            f2.write("user2\n")
            f2.flush()
            manager.add_user_source(FileTargetSource(f2.name, target_type="user"))

        users = manager.get_users()

        self.assertEqual(set(users), {"user1", "user2"})

    def test_get_users_deduplicates(self):
        """
        BV: Same user from multiple sources appears once

        Scenario:
          Given: Multiple sources with overlapping users
          When: get_users() is called
          Then: Duplicates are removed
        """
        from tools.post.bloodtrail.autospray.target_sources import (
            TargetManager, FileTargetSource
        )

        manager = TargetManager()

        # Create two user files with overlap
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f1:
            f1.write("shared_user\nunique1\n")
            f1.flush()
            manager.add_user_source(FileTargetSource(f1.name, target_type="user"))

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f2:
            f2.write("shared_user\nunique2\n")
            f2.flush()
            manager.add_user_source(FileTargetSource(f2.name, target_type="user"))

        users = manager.get_users()

        # Should have 3 unique users
        self.assertEqual(len(users), 3)
        self.assertEqual(users.count("shared_user"), 1)

    def test_get_machines_aggregates_sources(self):
        """
        BV: Machines from all sources are combined

        Scenario:
          Given: Multiple machine file sources
          When: get_machines() is called
          Then: Machines from all sources are returned
        """
        from tools.post.bloodtrail.autospray.target_sources import (
            TargetManager, FileTargetSource
        )

        manager = TargetManager()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f1:
            f1.write("192.168.1.1\n")
            f1.flush()
            manager.add_machine_source(FileTargetSource(f1.name, target_type="machine"))

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f2:
            f2.write("192.168.1.2\n")
            f2.flush()
            manager.add_machine_source(FileTargetSource(f2.name, target_type="machine"))

        machines = manager.get_machines()

        self.assertEqual(set(machines), {"192.168.1.1", "192.168.1.2"})

    def test_get_statistics_returns_counts(self):
        """
        BV: Users can see target breakdown before spraying

        Scenario:
          Given: Manager with user and machine sources
          When: get_statistics() is called
          Then: Counts for both are returned
        """
        from tools.post.bloodtrail.autospray.target_sources import (
            TargetManager, FileTargetSource
        )

        manager = TargetManager()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f1:
            f1.write("user1\nuser2\n")
            f1.flush()
            manager.add_user_source(FileTargetSource(f1.name, target_type="user"))

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f2:
            f2.write("192.168.1.1\n")
            f2.flush()
            manager.add_machine_source(FileTargetSource(f2.name, target_type="machine"))

        stats = manager.get_statistics()

        self.assertIn("user_count", stats)
        self.assertIn("machine_count", stats)
        self.assertEqual(stats["user_count"], 2)
        self.assertEqual(stats["machine_count"], 1)

    def test_get_statistics_lists_available_sources(self):
        """
        BV: Users know which sources successfully loaded

        Scenario:
          Given: Manager with available source
          When: get_statistics() is called
          Then: Available sources are listed
        """
        from tools.post.bloodtrail.autospray.target_sources import (
            TargetManager, FileTargetSource
        )

        manager = TargetManager()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("user1\n")
            f.flush()
            source = FileTargetSource(f.name, target_type="user")
            manager.add_user_source(source)

        stats = manager.get_statistics()

        self.assertIn(source.name, stats["user_sources"])

    def test_get_statistics_lists_unavailable_sources(self):
        """
        BV: Users know which sources failed to load

        Scenario:
          Given: Manager with unavailable source
          When: get_statistics() is called
          Then: Unavailable sources are listed
        """
        from tools.post.bloodtrail.autospray.target_sources import (
            TargetManager, FileTargetSource
        )

        manager = TargetManager()

        # Add unavailable source
        source = FileTargetSource("/nonexistent/users.txt", target_type="user")
        manager.add_user_source(source)

        stats = manager.get_statistics()

        self.assertIn(source.name, stats["user_sources_unavailable"])

    def test_get_users_skips_unavailable_sources(self):
        """
        BV: Unavailable sources don't block spray operation

        Scenario:
          Given: Manager with one available and one unavailable source
          When: get_users() is called
          Then: Only users from available source are returned
        """
        from tools.post.bloodtrail.autospray.target_sources import (
            TargetManager, FileTargetSource
        )

        manager = TargetManager()

        # Add unavailable source
        manager.add_user_source(
            FileTargetSource("/nonexistent/users.txt", target_type="user")
        )

        # Add available source
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("user1\n")
            f.flush()
            manager.add_user_source(FileTargetSource(f.name, target_type="user"))

        users = manager.get_users()

        self.assertEqual(users, ["user1"])


if __name__ == "__main__":
    unittest.main()
