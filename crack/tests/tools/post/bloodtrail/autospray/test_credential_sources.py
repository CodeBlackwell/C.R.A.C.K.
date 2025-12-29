"""
BloodTrail AutoSpray Credential Sources Tests

Business Value Focus:
- Users need reliable credential gathering from multiple sources (Neo4j, wordlists, potfiles)
- Deduplication ensures efficient spraying without redundant attempts
- Hash detection prevents accidental password spray with hash values
- Source statistics help users understand credential coverage

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
# CREDENTIAL DATACLASS TESTS
# =============================================================================

class TestCredentialDataclass(unittest.TestCase):
    """Tests for the Credential dataclass."""

    def test_credential_hash_uses_value_and_type(self):
        """
        BV: Deduplication works correctly across multiple sources

        Scenario:
          Given: Two credentials with same value and type
          When: Added to a set
          Then: Only one is kept (hash collision)
        """
        from tools.post.bloodtrail.autospray.credential_sources import (
            Credential, CredentialType
        )

        cred1 = Credential(value="Password123", cred_type=CredentialType.PASSWORD)
        cred2 = Credential(value="Password123", cred_type=CredentialType.PASSWORD)

        cred_set = {cred1, cred2}

        self.assertEqual(len(cred_set), 1)

    def test_credential_equality_ignores_source(self):
        """
        BV: Same password from different sources is still deduplicated

        Scenario:
          Given: Same password from wordlist and potfile
          When: Compared for equality
          Then: They are equal
        """
        from tools.post.bloodtrail.autospray.credential_sources import Credential

        cred1 = Credential(value="Summer2024!", source="wordlist")
        cred2 = Credential(value="Summer2024!", source="potfile")

        self.assertEqual(cred1, cred2)

    def test_credential_different_types_not_equal(self):
        """
        BV: Password and hash with same value are treated differently

        Scenario:
          Given: Same string as password and NTLM hash
          When: Compared for equality
          Then: They are not equal (different types)
        """
        from tools.post.bloodtrail.autospray.credential_sources import (
            Credential, CredentialType
        )

        cred_password = Credential(
            value="aabbccdd" * 4,
            cred_type=CredentialType.PASSWORD
        )
        cred_hash = Credential(
            value="aabbccdd" * 4,
            cred_type=CredentialType.NTLM_HASH
        )

        self.assertNotEqual(cred_password, cred_hash)


# =============================================================================
# CREDENTIAL SOURCE ABC TESTS
# =============================================================================

class TestCredentialSourceABC(unittest.TestCase):
    """Tests for CredentialSource abstract base class interface."""

    def test_credential_source_has_required_methods(self):
        """
        BV: All credential sources implement consistent interface

        Scenario:
          Given: CredentialSource ABC
          When: Interface examined
          Then: name, get_credentials, is_available are defined
        """
        from tools.post.bloodtrail.autospray.credential_sources import CredentialSource
        import inspect

        # Check abstract methods
        abstract_methods = getattr(CredentialSource, '__abstractmethods__', set())

        self.assertIn('name', abstract_methods)
        self.assertIn('get_credentials', abstract_methods)
        self.assertIn('is_available', abstract_methods)

    def test_get_passwords_convenience_method(self):
        """
        BV: Users can easily get just password strings for spraying

        Scenario:
          Given: Source with mixed credential types
          When: get_passwords() is called
          Then: Only PASSWORD type values are returned as strings
        """
        from tools.post.bloodtrail.autospray.credential_sources import (
            WordlistSource
        )

        # Create a temp wordlist
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Password123\nSummer2024\n")
            f.flush()

            source = WordlistSource(f.name)
            passwords = source.get_passwords()

            self.assertIsInstance(passwords, list)
            self.assertEqual(len(passwords), 2)
            self.assertIn("Password123", passwords)


# =============================================================================
# NEO4J CREDENTIAL SOURCE TESTS
# =============================================================================

class TestNeo4jCredentialSource(unittest.TestCase):
    """Tests for Neo4jCredentialSource."""

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
          Given: Neo4jCredentialSource
          When: name property accessed
          Then: Returns human-readable identifier
        """
        from tools.post.bloodtrail.autospray.credential_sources import (
            Neo4jCredentialSource
        )

        source = Neo4jCredentialSource(self.mock_config)

        self.assertEqual(source.name, "Neo4j Pwned Users")

    def test_is_available_returns_true_when_connected(self):
        """
        BV: Users know if Neo4j is accessible before spraying

        Scenario:
          Given: Neo4j is running
          When: is_available() is called
          Then: Returns True
        """
        from tools.post.bloodtrail.autospray.credential_sources import (
            Neo4jCredentialSource
        )

        mock_driver = create_mock_driver_success([])

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            source = Neo4jCredentialSource(self.mock_config)
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
        from tools.post.bloodtrail.autospray.credential_sources import (
            Neo4jCredentialSource
        )

        mock_driver = create_mock_driver_failure(ConnectionError, "Connection refused")

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            source = Neo4jCredentialSource(self.mock_config)
            result = source.is_available()

            self.assertFalse(result)

    def test_get_credentials_extracts_passwords(self):
        """
        BV: Passwords from pwned users are available for spraying

        Scenario:
          Given: Neo4j contains pwned users with passwords
          When: get_credentials() is called
          Then: Password credentials are returned
        """
        from tools.post.bloodtrail.autospray.credential_sources import (
            Neo4jCredentialSource, CredentialType
        )

        mock_records = [{
            "username": "ADMIN@CORP.COM",
            "types": ["password"],
            "values": ["Summer2024!"],
        }]
        mock_driver = create_mock_driver_success(mock_records)

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            source = Neo4jCredentialSource(self.mock_config)
            credentials = source.get_credentials()

            self.assertEqual(len(credentials), 1)
            self.assertEqual(credentials[0].value, "Summer2024!")
            self.assertEqual(credentials[0].cred_type, CredentialType.PASSWORD)
            self.assertEqual(credentials[0].username, "ADMIN@CORP.COM")

    def test_get_credentials_extracts_ntlm_hashes(self):
        """
        BV: NTLM hashes from pwned users enable pass-the-hash

        Scenario:
          Given: Neo4j contains pwned users with NTLM hashes
          When: get_credentials() is called
          Then: NTLM hash credentials are returned
        """
        from tools.post.bloodtrail.autospray.credential_sources import (
            Neo4jCredentialSource, CredentialType
        )

        mock_records = [{
            "username": "ADMIN@CORP.COM",
            "types": ["ntlm_hash"],
            "values": ["aabbccdd" * 4],
        }]
        mock_driver = create_mock_driver_success(mock_records)

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            source = Neo4jCredentialSource(self.mock_config)
            credentials = source.get_credentials()

            self.assertEqual(len(credentials), 1)
            self.assertEqual(credentials[0].cred_type, CredentialType.NTLM_HASH)

    def test_get_credentials_handles_parallel_arrays(self):
        """
        BV: Multiple credentials per user are correctly extracted

        Scenario:
          Given: User with both password and NTLM hash
          When: get_credentials() is called
          Then: Both credentials are returned with correct types
        """
        from tools.post.bloodtrail.autospray.credential_sources import (
            Neo4jCredentialSource, CredentialType
        )

        mock_records = [{
            "username": "ADMIN@CORP.COM",
            "types": ["password", "ntlm_hash"],
            "values": ["Summer2024!", "aabbccdd" * 4],
        }]
        mock_driver = create_mock_driver_success(mock_records)

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            source = Neo4jCredentialSource(self.mock_config)
            credentials = source.get_credentials()

            self.assertEqual(len(credentials), 2)
            types = {c.cred_type for c in credentials}
            self.assertIn(CredentialType.PASSWORD, types)
            self.assertIn(CredentialType.NTLM_HASH, types)

    def test_get_credentials_returns_empty_on_error(self):
        """
        BV: Query errors don't crash the spray operation

        Scenario:
          Given: Neo4j query fails
          When: get_credentials() is called
          Then: Empty list returned (not exception)
        """
        from tools.post.bloodtrail.autospray.credential_sources import (
            Neo4jCredentialSource
        )

        mock_driver = create_mock_driver_failure(RuntimeError, "Query failed")

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            source = Neo4jCredentialSource(self.mock_config)
            credentials = source.get_credentials()

            self.assertEqual(credentials, [])

    def test_close_releases_driver(self):
        """
        BV: Resources are properly released after use

        Scenario:
          Given: Connected Neo4j source
          When: close() is called
          Then: Driver is closed
        """
        from tools.post.bloodtrail.autospray.credential_sources import (
            Neo4jCredentialSource
        )

        mock_driver = create_mock_driver_success([])

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            source = Neo4jCredentialSource(self.mock_config)
            source._connect()  # Force connection
            source.close()

            self.assertTrue(mock_driver.closed)
            self.assertIsNone(source._driver)


# =============================================================================
# WORDLIST SOURCE TESTS
# =============================================================================

class TestWordlistSource(unittest.TestCase):
    """Tests for WordlistSource."""

    def test_name_includes_filename(self):
        """
        BV: Source name identifies which wordlist was used

        Scenario:
          Given: WordlistSource with specific file
          When: name property accessed
          Then: Filename is included
        """
        from tools.post.bloodtrail.autospray.credential_sources import WordlistSource

        source = WordlistSource(Path("/tmp/rockyou.txt"))

        self.assertIn("rockyou.txt", source.name)

    def test_is_available_returns_true_for_existing_file(self):
        """
        BV: Users know if wordlist file is accessible

        Scenario:
          Given: Wordlist file exists
          When: is_available() is called
          Then: Returns True
        """
        from tools.post.bloodtrail.autospray.credential_sources import WordlistSource

        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            source = WordlistSource(f.name)
            self.assertTrue(source.is_available())

    def test_is_available_returns_false_for_missing_file(self):
        """
        BV: Missing wordlist files are handled gracefully

        Scenario:
          Given: Wordlist file doesn't exist
          When: is_available() is called
          Then: Returns False
        """
        from tools.post.bloodtrail.autospray.credential_sources import WordlistSource

        source = WordlistSource("/nonexistent/wordlist.txt")

        self.assertFalse(source.is_available())

    def test_get_credentials_reads_one_per_line(self):
        """
        BV: Standard wordlist format is correctly parsed

        Scenario:
          Given: Wordlist with passwords on separate lines
          When: get_credentials() is called
          Then: Each line becomes a credential
        """
        from tools.post.bloodtrail.autospray.credential_sources import WordlistSource

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Password123\nSummer2024!\nWinter2023\n")
            f.flush()

            source = WordlistSource(f.name)
            credentials = source.get_credentials()

            self.assertEqual(len(credentials), 3)
            values = {c.value for c in credentials}
            self.assertEqual(values, {"Password123", "Summer2024!", "Winter2023"})

    def test_get_credentials_skips_comments(self):
        """
        BV: Comment lines in wordlists are ignored

        Scenario:
          Given: Wordlist with # comment lines
          When: get_credentials() is called
          Then: Comments are skipped
        """
        from tools.post.bloodtrail.autospray.credential_sources import WordlistSource

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("# This is a comment\nPassword123\n# Another comment\n")
            f.flush()

            source = WordlistSource(f.name)
            credentials = source.get_credentials()

            self.assertEqual(len(credentials), 1)
            self.assertEqual(credentials[0].value, "Password123")

    def test_get_credentials_skips_empty_lines(self):
        """
        BV: Empty lines don't create invalid credentials

        Scenario:
          Given: Wordlist with empty lines
          When: get_credentials() is called
          Then: Empty lines are skipped
        """
        from tools.post.bloodtrail.autospray.credential_sources import WordlistSource

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Password123\n\n\nSummer2024\n")
            f.flush()

            source = WordlistSource(f.name)
            credentials = source.get_credentials()

            self.assertEqual(len(credentials), 2)

    def test_get_credentials_respects_max_limit(self):
        """
        BV: Large wordlists don't exhaust memory

        Scenario:
          Given: Wordlist with many passwords
          When: get_credentials(max=5) is called
          Then: Only first 5 are returned
        """
        from tools.post.bloodtrail.autospray.credential_sources import WordlistSource

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            for i in range(100):
                f.write(f"Password{i}\n")
            f.flush()

            source = WordlistSource(f.name, max_passwords=5)
            credentials = source.get_credentials()

            self.assertEqual(len(credentials), 5)

    def test_get_credentials_handles_encoding_errors(self):
        """
        BV: Binary/corrupt wordlist data doesn't crash

        Scenario:
          Given: Wordlist with invalid UTF-8 bytes
          When: get_credentials() is called
          Then: Invalid bytes are skipped, valid lines returned
        """
        from tools.post.bloodtrail.autospray.credential_sources import WordlistSource

        with tempfile.NamedTemporaryFile(mode='wb', suffix='.txt', delete=False) as f:
            f.write(b"ValidPassword\n\xff\xfe Invalid\nAnotherValid\n")
            f.flush()

            source = WordlistSource(f.name)
            credentials = source.get_credentials()

            # Should get at least the valid passwords
            values = [c.value for c in credentials]
            self.assertIn("ValidPassword", values)

    def test_get_credentials_returns_empty_for_unavailable_file(self):
        """
        BV: Missing files don't cause exceptions during spray

        Scenario:
          Given: Wordlist file doesn't exist
          When: get_credentials() is called
          Then: Empty list returned
        """
        from tools.post.bloodtrail.autospray.credential_sources import WordlistSource

        source = WordlistSource("/nonexistent/wordlist.txt")
        credentials = source.get_credentials()

        self.assertEqual(credentials, [])


# =============================================================================
# POTFILE SOURCE TESTS
# =============================================================================

class TestPotfileSource(unittest.TestCase):
    """Tests for PotfileSource."""

    def test_name_includes_potfile_name(self):
        """
        BV: Source name identifies which potfile was used

        Scenario:
          Given: PotfileSource with detected file
          When: name property accessed
          Then: Potfile name is included
        """
        from tools.post.bloodtrail.autospray.credential_sources import PotfileSource

        with tempfile.NamedTemporaryFile(suffix='.potfile', delete=False) as f:
            source = PotfileSource(f.name)
            self.assertIn("potfile", source.name.lower())

    def test_is_available_detects_hashcat_potfile(self):
        """
        BV: Standard hashcat potfile location is auto-detected

        Scenario:
          Given: Hashcat potfile exists at default location
          When: is_available() is called with no custom path
          Then: Auto-detection finds it
        """
        from tools.post.bloodtrail.autospray.credential_sources import PotfileSource

        with tempfile.NamedTemporaryFile(suffix='.potfile', delete=False) as f:
            source = PotfileSource(f.name)
            self.assertTrue(source.is_available())

    def test_is_available_returns_false_when_no_potfile(self):
        """
        BV: Missing potfiles are handled gracefully

        Scenario:
          Given: No potfile exists
          When: is_available() is called
          Then: Returns False
        """
        from tools.post.bloodtrail.autospray.credential_sources import PotfileSource

        # Patch all default locations to not exist
        with patch.object(Path, 'exists', return_value=False):
            source = PotfileSource()
            result = source.is_available()

            self.assertFalse(result)

    def test_get_credentials_parses_potfile_format(self):
        """
        BV: Cracked passwords from potfile are usable for spraying

        Scenario:
          Given: Potfile with hash:password entries
          When: get_credentials() is called
          Then: Passwords are extracted
        """
        from tools.post.bloodtrail.autospray.credential_sources import PotfileSource

        with tempfile.NamedTemporaryFile(mode='w', suffix='.potfile', delete=False) as f:
            f.write("aabbccdd11223344aabbccdd11223344:Password123\n")
            f.write("eeffaabb55667788eeffaabb55667788:Summer2024!\n")
            f.flush()

            source = PotfileSource(f.name)
            credentials = source.get_credentials()

            self.assertEqual(len(credentials), 2)
            values = {c.value for c in credentials}
            self.assertEqual(values, {"Password123", "Summer2024!"})

    def test_get_credentials_handles_kerberos_format(self):
        """
        BV: Kerberoast potfile entries are correctly parsed

        Scenario:
          Given: Potfile with $krb5tgs$23$* format entries
          When: get_credentials() is called
          Then: Password after final colon is extracted
        """
        from tools.post.bloodtrail.autospray.credential_sources import PotfileSource

        with tempfile.NamedTemporaryFile(mode='w', suffix='.potfile', delete=False) as f:
            f.write("$krb5tgs$23$*svc_account$CORP.COM$cifs/dc01*$aabbcc...:CrackedPassword\n")
            f.flush()

            source = PotfileSource(f.name)
            credentials = source.get_credentials()

            self.assertEqual(len(credentials), 1)
            self.assertEqual(credentials[0].value, "CrackedPassword")

    def test_get_credentials_deduplicates_passwords(self):
        """
        BV: Same password from multiple hashes is only returned once

        Scenario:
          Given: Potfile with same password for different users
          When: get_credentials() is called
          Then: Password appears only once
        """
        from tools.post.bloodtrail.autospray.credential_sources import PotfileSource

        with tempfile.NamedTemporaryFile(mode='w', suffix='.potfile', delete=False) as f:
            f.write("aabbccdd11223344:CompanyPassword\n")
            f.write("eeffaabb55667788:CompanyPassword\n")
            f.flush()

            source = PotfileSource(f.name)
            credentials = source.get_credentials()

            self.assertEqual(len(credentials), 1)
            self.assertEqual(credentials[0].value, "CompanyPassword")

    def test_looks_like_hash_detects_hex_strings(self):
        """
        BV: Hash values are not mistakenly used as passwords

        Scenario:
          Given: Potfile with truncated/malformed entries
          When: Password extracted looks like hex hash
          Then: It is filtered out
        """
        from tools.post.bloodtrail.autospray.credential_sources import PotfileSource

        # 32+ char hex string looks like a hash
        self.assertTrue(PotfileSource._looks_like_hash("a" * 32))
        self.assertTrue(PotfileSource._looks_like_hash("aabbccdd11223344aabbccdd11223344"))

        # Normal passwords don't look like hashes
        self.assertFalse(PotfileSource._looks_like_hash("Password123"))
        self.assertFalse(PotfileSource._looks_like_hash("Summer2024!"))

    def test_looks_like_hash_detects_dollar_prefix(self):
        """
        BV: Hash format prefixes are recognized

        Scenario:
          Given: Value starting with $
          When: _looks_like_hash() is called
          Then: Returns True
        """
        from tools.post.bloodtrail.autospray.credential_sources import PotfileSource

        self.assertTrue(PotfileSource._looks_like_hash("$krb5tgs$23$*"))
        self.assertTrue(PotfileSource._looks_like_hash("$6$salt$hash"))

    def test_get_credentials_skips_hash_like_values(self):
        """
        BV: Malformed potfile entries with hash-like passwords are skipped

        Scenario:
          Given: Potfile entry where password looks like hash
          When: get_credentials() is called
          Then: Entry is skipped
        """
        from tools.post.bloodtrail.autospray.credential_sources import PotfileSource

        with tempfile.NamedTemporaryFile(mode='w', suffix='.potfile', delete=False) as f:
            # Malformed entry - "password" is actually a hash
            f.write("hash1:aabbccdd11223344aabbccdd11223344\n")
            # Valid entry
            f.write("hash2:RealPassword\n")
            f.flush()

            source = PotfileSource(f.name)
            credentials = source.get_credentials()

            self.assertEqual(len(credentials), 1)
            self.assertEqual(credentials[0].value, "RealPassword")


# =============================================================================
# CREDENTIAL MANAGER TESTS
# =============================================================================

class TestCredentialManager(unittest.TestCase):
    """Tests for CredentialManager orchestration."""

    def test_add_source_adds_to_list(self):
        """
        BV: Multiple sources can be combined for comprehensive spraying

        Scenario:
          Given: Empty CredentialManager
          When: add_source() is called
          Then: Source is added to the list
        """
        from tools.post.bloodtrail.autospray.credential_sources import (
            CredentialManager, WordlistSource
        )

        manager = CredentialManager()

        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            source = WordlistSource(f.name)
            manager.add_source(source)

            self.assertEqual(len(manager.sources), 1)

    def test_remove_source_by_name(self):
        """
        BV: Users can remove unwanted sources

        Scenario:
          Given: Manager with multiple sources
          When: remove_source(name) is called
          Then: Source is removed
        """
        from tools.post.bloodtrail.autospray.credential_sources import (
            CredentialManager, WordlistSource
        )

        manager = CredentialManager()

        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            source = WordlistSource(f.name)
            manager.add_source(source)

            result = manager.remove_source(source.name)

            self.assertTrue(result)
            self.assertEqual(len(manager.sources), 0)

    def test_get_all_credentials_aggregates_sources(self):
        """
        BV: Credentials from all sources are combined

        Scenario:
          Given: Multiple wordlist sources
          When: get_all_credentials() is called
          Then: Credentials from all sources are returned
        """
        from tools.post.bloodtrail.autospray.credential_sources import (
            CredentialManager, WordlistSource
        )

        manager = CredentialManager()

        # Create two wordlists
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f1:
            f1.write("Password1\n")
            f1.flush()
            manager.add_source(WordlistSource(f1.name))

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f2:
            f2.write("Password2\n")
            f2.flush()
            manager.add_source(WordlistSource(f2.name))

        credentials = manager.get_all_credentials()

        values = {c.value for c in credentials}
        self.assertEqual(values, {"Password1", "Password2"})

    def test_get_all_credentials_deduplicates(self):
        """
        BV: Same password from multiple sources appears once

        Scenario:
          Given: Multiple sources with overlapping passwords
          When: get_all_credentials() is called
          Then: Duplicates are removed
        """
        from tools.post.bloodtrail.autospray.credential_sources import (
            CredentialManager, WordlistSource
        )

        manager = CredentialManager()

        # Create two wordlists with overlap
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f1:
            f1.write("SharedPassword\nUnique1\n")
            f1.flush()
            manager.add_source(WordlistSource(f1.name))

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f2:
            f2.write("SharedPassword\nUnique2\n")
            f2.flush()
            manager.add_source(WordlistSource(f2.name))

        credentials = manager.get_all_credentials()

        # Should have 3 unique passwords
        values = [c.value for c in credentials]
        self.assertEqual(len(values), 3)
        self.assertEqual(values.count("SharedPassword"), 1)

    def test_get_all_credentials_caches_results(self):
        """
        BV: Repeated calls don't re-read files

        Scenario:
          Given: First call to get_all_credentials()
          When: Called again without force_refresh
          Then: Cached result is returned
        """
        from tools.post.bloodtrail.autospray.credential_sources import (
            CredentialManager, WordlistSource
        )

        manager = CredentialManager()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Password1\n")
            f.flush()
            manager.add_source(WordlistSource(f.name))

        # First call
        result1 = manager.get_all_credentials()

        # Modify internal cache
        manager._cached_credentials.append(
            type(result1[0])(value="CACHED_MARKER", source="test")
        )

        # Second call should return cached
        result2 = manager.get_all_credentials()

        values = [c.value for c in result2]
        self.assertIn("CACHED_MARKER", values)

    def test_get_all_credentials_force_refresh_reloads(self):
        """
        BV: Users can refresh after adding new sources

        Scenario:
          Given: Cached credentials
          When: get_all_credentials(force_refresh=True) is called
          Then: Fresh data is loaded
        """
        from tools.post.bloodtrail.autospray.credential_sources import (
            CredentialManager, WordlistSource
        )

        manager = CredentialManager()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Password1\n")
            f.flush()
            manager.add_source(WordlistSource(f.name))

        # First call populates cache
        manager.get_all_credentials()

        # Modify cache
        manager._cached_credentials.append(
            type(manager._cached_credentials[0])(value="CACHED_MARKER", source="test")
        )

        # Force refresh should reload
        result = manager.get_all_credentials(force_refresh=True)

        values = [c.value for c in result]
        self.assertNotIn("CACHED_MARKER", values)

    def test_get_passwords_for_spray_returns_only_passwords(self):
        """
        BV: Password spray gets only PASSWORD type credentials

        Scenario:
          Given: Mix of passwords and hashes
          When: get_passwords_for_spray() is called
          Then: Only password strings returned
        """
        from tools.post.bloodtrail.autospray.credential_sources import (
            CredentialManager, WordlistSource
        )

        manager = CredentialManager()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Password1\nPassword2\n")
            f.flush()
            manager.add_source(WordlistSource(f.name))

        passwords = manager.get_passwords_for_spray()

        self.assertEqual(len(passwords), 2)
        self.assertIsInstance(passwords[0], str)

    def test_get_statistics_returns_counts(self):
        """
        BV: Users can see credential breakdown before spraying

        Scenario:
          Given: Manager with multiple sources
          When: get_statistics() is called
          Then: Counts by source and type are returned
        """
        from tools.post.bloodtrail.autospray.credential_sources import (
            CredentialManager, WordlistSource
        )

        manager = CredentialManager()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Password1\nPassword2\n")
            f.flush()
            manager.add_source(WordlistSource(f.name))

        stats = manager.get_statistics()

        self.assertIn("total", stats)
        self.assertIn("by_source", stats)
        self.assertIn("by_type", stats)
        self.assertIn("sources_available", stats)
        self.assertEqual(stats["total"], 2)

    def test_get_statistics_lists_unavailable_sources(self):
        """
        BV: Users know which sources failed to load

        Scenario:
          Given: Manager with unavailable source
          When: get_statistics() is called
          Then: Unavailable sources are listed
        """
        from tools.post.bloodtrail.autospray.credential_sources import (
            CredentialManager, WordlistSource
        )

        manager = CredentialManager()

        # Add unavailable source
        source = WordlistSource("/nonexistent/wordlist.txt")
        manager.add_source(source)

        stats = manager.get_statistics()

        self.assertIn(source.name, stats["sources_unavailable"])


if __name__ == "__main__":
    unittest.main()
