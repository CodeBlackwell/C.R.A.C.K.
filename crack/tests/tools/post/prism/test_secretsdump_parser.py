"""
Tests for Secretsdump Parser

Business Value Focus:
- Parse SAM/NTDS hashes from secretsdump.py output
- Support DCC2 (cached credentials) for offline cracking
- Handle NetNTLM captures from Responder

Test Priority: TIER 1 - CRITICAL (Core Credential Extraction)
"""

import pytest
from pathlib import Path


# =============================================================================
# Sample Secretsdump Content
# =============================================================================

# SAM dump format (local accounts)
SAM_DUMP = """[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
testuser:1001:aad3b435b51404eeaad3b435b51404ee:aabbccdd11223344aabbccdd11223344:::
serviceacct:1002:aad3b435b51404eeaad3b435b51404ee:deadbeef12345678deadbeef12345678:::
"""

# NTDS dump format (domain accounts)
NTDS_DUMP = """[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)
CORP\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::
CORP\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:fedcba9876543210fedcba9876543210:::
CORP\\sqlsvc:1103:aad3b435b51404eeaad3b435b51404ee:aabbccdd11223344aabbccdd11223344:::
CORP\\DC01$:1000:aad3b435b51404eeaad3b435b51404ee:deadbeefcafe1234deadbeefcafe1234:::
"""

# Raw hash file (no header)
RAW_HASHES = """Administrator:500:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::
testuser:1001:aad3b435b51404eeaad3b435b51404ee:aabbccdd11223344aabbccdd11223344:::
admin:1002:aad3b435b51404eeaad3b435b51404ee:11223344aabbccdd11223344aabbccdd:::
service:1003:aad3b435b51404eeaad3b435b51404ee:9876543210abcdef9876543210abcdef:::
"""

# DCC2 cached credentials
DCC2_DUMP = """[*] Dumping cached domain logon information (domain/username:hash)
$DCC2$10240#Administrator#aabbccdd11223344aabbccdd11223344
$DCC2$10240#testuser#deadbeef12345678deadbeef12345678
$DCC2$10240#sqlsvc#9876543210abcdef9876543210abcdef
"""

# History hashes (should be skipped)
HISTORY_HASHES = """Administrator:500:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::
Administrator_history0:500:aad3b435b51404eeaad3b435b51404ee:oldpasswordhash1234567890ab:::
Administrator_history1:500:aad3b435b51404eeaad3b435b51404ee:olderpasswordhash12345678:::
testuser:1001:aad3b435b51404eeaad3b435b51404ee:aabbccdd11223344aabbccdd11223344:::
"""

# Mixed dump with SAM, DCC2
MIXED_DUMP = """[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::
testuser:1001:aad3b435b51404eeaad3b435b51404ee:aabbccdd11223344aabbccdd11223344:::

[*] Dumping cached domain credentials
$DCC2$10240#domainuser#deadbeef12345678deadbeef12345678
"""

# Empty hashes (should be skipped)
EMPTY_HASHES = """Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::
"""

# Non-secretsdump content
NON_SECRETSDUMP = """<html>
<body>Hello World</body>
</html>
"""


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def secretsdump_parser(prism_registry):
    """
    Secretsdump parser instance.

    BV: Consistent parser for secretsdump output tests.
    """
    return prism_registry.get_parser_by_name("secretsdump")


@pytest.fixture
def sam_dump_file(create_temp_file):
    """Create temp SAM dump file."""
    return create_temp_file("sam_dump.txt", SAM_DUMP)


@pytest.fixture
def ntds_dump_file(create_temp_file):
    """Create temp NTDS dump file."""
    return create_temp_file("ntds_dump.txt", NTDS_DUMP)


@pytest.fixture
def raw_hash_file(create_temp_file):
    """Create temp raw hash file."""
    return create_temp_file("hashes.txt", RAW_HASHES)


@pytest.fixture
def dcc2_file(create_temp_file):
    """Create temp DCC2 dump file."""
    return create_temp_file("dcc2_dump.txt", DCC2_DUMP)


@pytest.fixture
def mixed_dump_file(create_temp_file):
    """Create temp mixed dump file."""
    return create_temp_file("mixed_dump.txt", MIXED_DUMP)


@pytest.fixture
def history_file(create_temp_file):
    """Create temp file with history hashes."""
    return create_temp_file("history.txt", HISTORY_HASHES)


# =============================================================================
# Parser Detection Tests
# =============================================================================

class TestSecretsdumpParserDetection:
    """Tests for secretsdump file detection"""

    def test_can_parse_sam_dump(self, secretsdump_parser, sam_dump_file):
        """
        BV: Detect SAM dump output

        Scenario:
          Given: SAM dump file with header
          When: can_parse() is called
          Then: Returns True
        """
        assert secretsdump_parser.can_parse(str(sam_dump_file)) is True

    def test_can_parse_ntds_dump(self, secretsdump_parser, ntds_dump_file):
        """
        BV: Detect NTDS dump output

        Scenario:
          Given: NTDS dump file
          When: can_parse() is called
          Then: Returns True
        """
        assert secretsdump_parser.can_parse(str(ntds_dump_file)) is True

    def test_can_parse_raw_hashes(self, secretsdump_parser, raw_hash_file):
        """
        BV: Detect raw hash file

        Scenario:
          Given: File with hash lines (no header)
          When: can_parse() is called
          Then: Returns True
        """
        assert secretsdump_parser.can_parse(str(raw_hash_file)) is True

    def test_can_parse_dcc2_dump(self, secretsdump_parser, dcc2_file):
        """
        BV: Detect DCC2 dump

        Scenario:
          Given: DCC2 cached credentials file
          When: can_parse() is called
          Then: Returns True
        """
        assert secretsdump_parser.can_parse(str(dcc2_file)) is True

    def test_cannot_parse_non_hash(
        self, secretsdump_parser, create_temp_file
    ):
        """
        BV: Reject non-hash files

        Scenario:
          Given: HTML file (not hashes)
          When: can_parse() is called
          Then: Returns False
        """
        filepath = create_temp_file("page.html", NON_SECRETSDUMP)
        assert secretsdump_parser.can_parse(str(filepath)) is False

    def test_cannot_parse_nonexistent(self, secretsdump_parser):
        """
        BV: Handle missing files gracefully

        Scenario:
          Given: Non-existent file path
          When: can_parse() is called
          Then: Returns False
        """
        assert secretsdump_parser.can_parse("/nonexistent/file.txt") is False


# =============================================================================
# SAM Dump Parsing Tests
# =============================================================================

class TestSAMDumpParsing:
    """Tests for SAM dump parsing"""

    def test_parse_sam_extracts_hashes(
        self, secretsdump_parser, sam_dump_file
    ):
        """
        BV: Extract all hashes from SAM dump

        Scenario:
          Given: SAM dump with 4 accounts
          When: parse() is called
          Then: 3 hashes extracted (skip empty Guest hash)
        """
        summary = secretsdump_parser.parse(str(sam_dump_file))

        # Guest has empty hash, should be skipped
        assert len(summary.credentials) == 3

    def test_parse_sam_extracts_usernames(
        self, secretsdump_parser, sam_dump_file
    ):
        """
        BV: Extract usernames correctly

        Scenario:
          Given: SAM dump
          When: parse() is called
          Then: Usernames extracted
        """
        summary = secretsdump_parser.parse(str(sam_dump_file))

        usernames = [c.username for c in summary.credentials]
        assert 'Administrator' in usernames
        assert 'testuser' in usernames

    def test_parse_sam_sets_correct_type(
        self, secretsdump_parser, sam_dump_file
    ):
        """
        BV: Mark as SAM_HASH type

        Scenario:
          Given: Local SAM dump
          When: parse() is called
          Then: Credentials have SAM_HASH type
        """
        summary = secretsdump_parser.parse(str(sam_dump_file))

        from tools.post.prism.models import CredentialType
        for cred in summary.credentials:
            assert cred.cred_type == CredentialType.SAM_HASH


# =============================================================================
# NTDS Dump Parsing Tests
# =============================================================================

class TestNTDSDumpParsing:
    """Tests for NTDS dump parsing"""

    def test_parse_ntds_extracts_hashes(
        self, secretsdump_parser, ntds_dump_file
    ):
        """
        BV: Extract all hashes from NTDS dump

        Scenario:
          Given: NTDS dump with domain accounts
          When: parse() is called
          Then: All hashes extracted
        """
        summary = secretsdump_parser.parse(str(ntds_dump_file))

        assert len(summary.credentials) == 4

    def test_parse_ntds_extracts_domain(
        self, secretsdump_parser, ntds_dump_file
    ):
        """
        BV: Extract domain from DOMAIN\\user format

        Scenario:
          Given: NTDS dump with domain prefixes
          When: parse() is called
          Then: Domain extracted correctly
        """
        summary = secretsdump_parser.parse(str(ntds_dump_file))

        assert all(c.domain == 'CORP' for c in summary.credentials)

    def test_parse_ntds_sets_correct_type(
        self, secretsdump_parser, ntds_dump_file
    ):
        """
        BV: Mark as NTDS_HASH type

        Scenario:
          Given: NTDS dump
          When: parse() is called
          Then: Credentials have NTDS_HASH type
        """
        summary = secretsdump_parser.parse(str(ntds_dump_file))

        from tools.post.prism.models import CredentialType
        for cred in summary.credentials:
            assert cred.cred_type == CredentialType.NTDS_HASH

    def test_parse_ntds_detects_machine_account(
        self, secretsdump_parser, ntds_dump_file
    ):
        """
        BV: Identify machine accounts (HOSTNAME$)

        Scenario:
          Given: NTDS dump with machine account
          When: parse() is called
          Then: Machine account detected
        """
        summary = secretsdump_parser.parse(str(ntds_dump_file))

        machine_accounts = [c for c in summary.credentials if c.username.endswith('$')]
        assert len(machine_accounts) == 1
        assert machine_accounts[0].username == 'DC01$'


# =============================================================================
# DCC2 Parsing Tests
# =============================================================================

class TestDCC2Parsing:
    """Tests for DCC2 cached credential parsing"""

    def test_parse_dcc2_extracts_hashes(
        self, secretsdump_parser, dcc2_file
    ):
        """
        BV: Extract DCC2 cached credentials

        Scenario:
          Given: DCC2 dump file
          When: parse() is called
          Then: DCC2 hashes extracted
        """
        summary = secretsdump_parser.parse(str(dcc2_file))

        assert len(summary.credentials) == 3

    def test_parse_dcc2_extracts_usernames(
        self, secretsdump_parser, dcc2_file
    ):
        """
        BV: Extract usernames from DCC2 format

        Scenario:
          Given: DCC2 dump
          When: parse() is called
          Then: Usernames extracted correctly
        """
        summary = secretsdump_parser.parse(str(dcc2_file))

        usernames = [c.username for c in summary.credentials]
        assert 'Administrator' in usernames
        assert 'testuser' in usernames

    def test_parse_dcc2_sets_correct_type(
        self, secretsdump_parser, dcc2_file
    ):
        """
        BV: Mark as DCC2 type

        Scenario:
          Given: DCC2 dump
          When: parse() is called
          Then: Credentials have DCC2 type
        """
        summary = secretsdump_parser.parse(str(dcc2_file))

        from tools.post.prism.models import CredentialType
        for cred in summary.credentials:
            assert cred.cred_type == CredentialType.DCC2


# =============================================================================
# Mixed Dump Parsing Tests
# =============================================================================

class TestMixedDumpParsing:
    """Tests for mixed dump parsing"""

    def test_parse_mixed_dump(self, secretsdump_parser, mixed_dump_file):
        """
        BV: Parse dump with multiple credential types

        Scenario:
          Given: File with SAM + DCC2
          When: parse() is called
          Then: All types extracted
        """
        summary = secretsdump_parser.parse(str(mixed_dump_file))

        from tools.post.prism.models import CredentialType

        sam_count = sum(
            1 for c in summary.credentials
            if c.cred_type == CredentialType.SAM_HASH
        )
        dcc2_count = sum(
            1 for c in summary.credentials
            if c.cred_type == CredentialType.DCC2
        )

        assert sam_count == 2
        assert dcc2_count == 1


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Edge case handling tests"""

    def test_skip_history_hashes(self, secretsdump_parser, history_file):
        """
        BV: Skip password history entries

        Scenario:
          Given: Dump with history hashes
          When: parse() is called
          Then: Only current hashes extracted
        """
        summary = secretsdump_parser.parse(str(history_file))

        # Should have Administrator and testuser, not history entries
        assert len(summary.credentials) == 2
        usernames = [c.username for c in summary.credentials]
        assert 'Administrator' in usernames
        assert all('history' not in u.lower() for u in usernames)

    def test_skip_empty_hashes(self, secretsdump_parser, create_temp_file):
        """
        BV: Skip disabled/empty accounts

        Scenario:
          Given: Dump with empty NT hashes
          When: parse() is called
          Then: Empty hashes skipped
        """
        filepath = create_temp_file("empty.txt", EMPTY_HASHES)
        summary = secretsdump_parser.parse(str(filepath))

        # Guest and DefaultAccount have empty hashes
        assert len(summary.credentials) == 1
        assert summary.credentials[0].username == 'Administrator'

    def test_no_duplicates(self, secretsdump_parser, create_temp_file):
        """
        BV: Avoid duplicate credentials

        Scenario:
          Given: File with duplicate hashes
          When: parse() is called
          Then: Each hash appears once
        """
        duplicate_hashes = """Administrator:500:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::
"""
        filepath = create_temp_file("dupes.txt", duplicate_hashes)
        summary = secretsdump_parser.parse(str(filepath))

        assert len(summary.credentials) == 1

    def test_parser_name(self, secretsdump_parser):
        """
        BV: Parser has correct name

        Scenario:
          Given: Secretsdump parser instance
          When: Accessing name property
          Then: Returns 'secretsdump'
        """
        assert secretsdump_parser.name == "secretsdump"

    def test_parser_description(self, secretsdump_parser):
        """
        BV: Parser has description

        Scenario:
          Given: Secretsdump parser instance
          When: Accessing description
          Then: Returns non-empty description
        """
        assert len(secretsdump_parser.description) > 0


# =============================================================================
# Parser Registration Tests
# =============================================================================

class TestParserRegistration:
    """Tests for parser registration"""

    def test_secretsdump_parser_registered(self, prism_registry):
        """
        BV: Secretsdump parser available in registry

        Scenario:
          Given: Initialized parser registry
          When: Looking up secretsdump parser
          Then: Parser is found
        """
        parser = prism_registry.get_parser_by_name("secretsdump")
        assert parser is not None
        assert parser.name == "secretsdump"
