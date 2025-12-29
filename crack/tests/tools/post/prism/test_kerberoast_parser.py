"""
Tests for Kerberoast Parser

Business Value Focus:
- Kerberoasting is a critical AD attack technique
- Parse TGS and AS-REP hashes for offline cracking
- Support multiple tools (GetUserSPNs, Rubeus, raw hashes)

Test Priority: TIER 1 - CRITICAL (Core Credential Extraction)
"""

import pytest
from pathlib import Path


# =============================================================================
# Sample Kerberoast Content
# =============================================================================

# GetUserSPNs.py output format
GETUSERSPNS_OUTPUT = """Impacket v0.11.0 - GetUserSPNs.py

ServicePrincipalName                  Name      MemberOf                                  PasswordLastSet             LastLogon                   Delegation
------------------------------------  --------  ----------------------------------------  --------------------------  --------------------------  ----------
MSSQLSvc/sql.corp.local:1433          sqlsvc    CN=Service Accounts,DC=corp,DC=local      2023-01-15 10:00:00.000000  2023-12-01 08:30:00.000000
HTTP/web.corp.local                   websvc    CN=Service Accounts,DC=corp,DC=local      2023-02-20 14:30:00.000000  2023-12-10 09:45:00.000000

$krb5tgs$23$*sqlsvc$CORP.LOCAL$MSSQLSvc/sql.corp.local:1433*$aabbccdd11223344aabbccdd11223344$abcdef0123456789abcdef0123456789abcdef0123456789
$krb5tgs$23$*websvc$CORP.LOCAL$HTTP/web.corp.local*$11223344aabbccdd11223344aabbccdd$fedcba9876543210fedcba9876543210fedcba9876543210
"""

# Rubeus kerberoast output format
RUBEUS_OUTPUT = """
   ______        _
  (_____ \\      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \\| ___ | | | |/___)
  | |  \\ \\| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0


[*] Action: Kerberoasting

[*] SamAccountName         : sqlsvc
[*] DistinguishedName      : CN=sqlsvc,CN=Users,DC=corp,DC=local
[*] ServicePrincipalName   : MSSQLSvc/sql.corp.local:1433
[*] Hash                   : $krb5tgs$23$*sqlsvc$CORP.LOCAL$MSSQLSvc/sql.corp.local:1433*$aabbccdd$abcdef0123

[*] SamAccountName         : websvc
[*] DistinguishedName      : CN=websvc,CN=Users,DC=corp,DC=local
[*] ServicePrincipalName   : HTTP/web.corp.local
[*] Hash                   : $krb5tgs$23$*websvc$CORP.LOCAL$HTTP/web.corp.local*$11223344$fedcba9876
"""

# Raw TGS hash file (hashcat format)
RAW_TGS_HASHES = """$krb5tgs$23$*sqlsvc$CORP.LOCAL$MSSQLSvc/sql.corp.local*$aabbccdd11223344aabbccdd$abcdef0123456789
$krb5tgs$23$*websvc$CORP.LOCAL$HTTP/web.corp.local*$11223344aabbccdd11223344$fedcba9876543210
$krb5tgs$23$*admin$CORP.LOCAL$cifs/dc.corp.local*$deadbeefcafe1234dead$1234567890abcdef
"""

# AS-REP roast hashes
ASREP_HASHES = """$krb5asrep$23$nopreauth@CORP.LOCAL:aabbccdd11223344aabbccdd11223344$abcdef0123456789
$krb5asrep$23$legacyuser@CORP.LOCAL:11223344aabbccdd11223344aabbccdd$fedcba9876543210
"""

# Mixed TGS and AS-REP
MIXED_HASHES = """$krb5tgs$23$*sqlsvc$CORP.LOCAL$MSSQLSvc/sql*$aabbccdd$abcdef01234567
$krb5asrep$23$nopreauth@CORP.LOCAL:deadbeef$fedcba9876543210
$krb5tgs$23$*websvc$CORP.LOCAL$HTTP/web*$11223344$9876543210abcdef
"""

# Non-kerberos content
NON_KERBEROS = """Administrator:500:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
"""


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def kerberoast_parser(prism_registry):
    """
    Kerberoast parser instance.

    BV: Consistent parser for kerberoast output tests.
    """
    return prism_registry.get_parser_by_name("kerberoast")


@pytest.fixture
def getuserspns_file(create_temp_file):
    """Create temp GetUserSPNs output file."""
    return create_temp_file("getuserspns.txt", GETUSERSPNS_OUTPUT)


@pytest.fixture
def rubeus_file(create_temp_file):
    """Create temp Rubeus output file."""
    return create_temp_file("rubeus_kerberoast.txt", RUBEUS_OUTPUT)


@pytest.fixture
def raw_tgs_file(create_temp_file):
    """Create temp raw TGS hash file."""
    return create_temp_file("tgs_hashes.txt", RAW_TGS_HASHES)


@pytest.fixture
def asrep_file(create_temp_file):
    """Create temp AS-REP hash file."""
    return create_temp_file("asrep_hashes.txt", ASREP_HASHES)


@pytest.fixture
def mixed_file(create_temp_file):
    """Create temp mixed hash file."""
    return create_temp_file("mixed_hashes.txt", MIXED_HASHES)


# =============================================================================
# Parser Detection Tests
# =============================================================================

class TestKerberoastParserDetection:
    """Tests for Kerberoast file detection"""

    def test_can_parse_getuserspns_output(
        self, kerberoast_parser, getuserspns_file
    ):
        """
        BV: Detect GetUserSPNs.py output

        Scenario:
          Given: GetUserSPNs.py output file
          When: can_parse() is called
          Then: Returns True
        """
        assert kerberoast_parser.can_parse(str(getuserspns_file)) is True

    def test_can_parse_rubeus_output(self, kerberoast_parser, rubeus_file):
        """
        BV: Detect Rubeus kerberoast output

        Scenario:
          Given: Rubeus output file
          When: can_parse() is called
          Then: Returns True
        """
        assert kerberoast_parser.can_parse(str(rubeus_file)) is True

    def test_can_parse_raw_tgs_hashes(self, kerberoast_parser, raw_tgs_file):
        """
        BV: Detect raw TGS hash file

        Scenario:
          Given: File with raw $krb5tgs$ hashes
          When: can_parse() is called
          Then: Returns True
        """
        assert kerberoast_parser.can_parse(str(raw_tgs_file)) is True

    def test_can_parse_asrep_hashes(self, kerberoast_parser, asrep_file):
        """
        BV: Detect AS-REP hash file

        Scenario:
          Given: File with $krb5asrep$ hashes
          When: can_parse() is called
          Then: Returns True
        """
        assert kerberoast_parser.can_parse(str(asrep_file)) is True

    def test_cannot_parse_non_kerberos(self, kerberoast_parser, create_temp_file):
        """
        BV: Reject non-kerberos files

        Scenario:
          Given: NTLM hash file (not kerberos)
          When: can_parse() is called
          Then: Returns False
        """
        filepath = create_temp_file("ntlm.txt", NON_KERBEROS)
        assert kerberoast_parser.can_parse(str(filepath)) is False

    def test_cannot_parse_nonexistent(self, kerberoast_parser):
        """
        BV: Handle missing files gracefully

        Scenario:
          Given: Non-existent file path
          When: can_parse() is called
          Then: Returns False
        """
        assert kerberoast_parser.can_parse("/nonexistent/file.txt") is False


# =============================================================================
# GetUserSPNs Parsing Tests
# =============================================================================

class TestGetUserSPNsParsing:
    """Tests for GetUserSPNs.py output parsing"""

    def test_parse_extracts_all_hashes(
        self, kerberoast_parser, getuserspns_file
    ):
        """
        BV: Extract all TGS hashes from GetUserSPNs output

        Scenario:
          Given: GetUserSPNs output with 2 hashes
          When: parse() is called
          Then: 2 credentials extracted
        """
        summary = kerberoast_parser.parse(str(getuserspns_file))

        assert len(summary.credentials) == 2

    def test_parse_extracts_usernames(
        self, kerberoast_parser, getuserspns_file
    ):
        """
        BV: Extract usernames from hashes

        Scenario:
          Given: GetUserSPNs output
          When: parse() is called
          Then: Usernames extracted correctly
        """
        summary = kerberoast_parser.parse(str(getuserspns_file))

        usernames = [c.username for c in summary.credentials]
        assert 'sqlsvc' in usernames
        assert 'websvc' in usernames

    def test_parse_extracts_domain(
        self, kerberoast_parser, getuserspns_file
    ):
        """
        BV: Extract domain from hashes

        Scenario:
          Given: GetUserSPNs output
          When: parse() is called
          Then: Domain extracted correctly
        """
        summary = kerberoast_parser.parse(str(getuserspns_file))

        assert summary.credentials[0].domain == 'CORP.LOCAL'


# =============================================================================
# Rubeus Parsing Tests
# =============================================================================

class TestRubeusParsing:
    """Tests for Rubeus output parsing"""

    def test_parse_rubeus_extracts_hashes(
        self, kerberoast_parser, rubeus_file
    ):
        """
        BV: Extract TGS hashes from Rubeus output

        Scenario:
          Given: Rubeus kerberoast output
          When: parse() is called
          Then: Hashes extracted
        """
        summary = kerberoast_parser.parse(str(rubeus_file))

        assert len(summary.credentials) >= 2

    def test_parse_rubeus_extracts_usernames(
        self, kerberoast_parser, rubeus_file
    ):
        """
        BV: Extract usernames from Rubeus format

        Scenario:
          Given: Rubeus output with SamAccountName
          When: parse() is called
          Then: Usernames extracted
        """
        summary = kerberoast_parser.parse(str(rubeus_file))

        usernames = [c.username for c in summary.credentials]
        assert 'sqlsvc' in usernames


# =============================================================================
# Raw Hash Parsing Tests
# =============================================================================

class TestRawHashParsing:
    """Tests for raw hash file parsing"""

    def test_parse_raw_tgs_hashes(self, kerberoast_parser, raw_tgs_file):
        """
        BV: Parse raw TGS hash file

        Scenario:
          Given: File with $krb5tgs$ hashes only
          When: parse() is called
          Then: All hashes extracted
        """
        summary = kerberoast_parser.parse(str(raw_tgs_file))

        assert len(summary.credentials) == 3

    def test_parse_asrep_hashes(self, kerberoast_parser, asrep_file):
        """
        BV: Parse AS-REP hash file

        Scenario:
          Given: File with $krb5asrep$ hashes
          When: parse() is called
          Then: AS-REP hashes extracted with correct type
        """
        summary = kerberoast_parser.parse(str(asrep_file))

        assert len(summary.credentials) == 2
        # Check credential type
        from tools.post.prism.models import CredentialType
        assert all(
            c.cred_type == CredentialType.KRB5ASREP
            for c in summary.credentials
        )

    def test_parse_mixed_hashes(self, kerberoast_parser, mixed_file):
        """
        BV: Parse file with both TGS and AS-REP hashes

        Scenario:
          Given: File with mixed hash types
          When: parse() is called
          Then: All hashes extracted with correct types
        """
        summary = kerberoast_parser.parse(str(mixed_file))

        from tools.post.prism.models import CredentialType
        tgs_count = sum(
            1 for c in summary.credentials
            if c.cred_type == CredentialType.KRB5TGS
        )
        asrep_count = sum(
            1 for c in summary.credentials
            if c.cred_type == CredentialType.KRB5ASREP
        )

        assert tgs_count == 2
        assert asrep_count == 1


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Edge case handling tests"""

    def test_empty_file_returns_empty(
        self, kerberoast_parser, create_temp_file
    ):
        """
        BV: Handle empty files gracefully

        Scenario:
          Given: Empty file
          When: parse() is called
          Then: Returns empty credentials list
        """
        filepath = create_temp_file("empty.txt", "")
        summary = kerberoast_parser.parse(str(filepath))

        assert len(summary.credentials) == 0

    def test_no_duplicates(self, kerberoast_parser, create_temp_file):
        """
        BV: Avoid duplicate credentials

        Scenario:
          Given: File with duplicate hashes
          When: parse() is called
          Then: Each hash appears once
        """
        duplicate_hashes = """$krb5tgs$23$*sqlsvc$CORP.LOCAL$MSSQLSvc*$aabb$abcdef
$krb5tgs$23$*sqlsvc$CORP.LOCAL$MSSQLSvc*$aabb$abcdef
$krb5tgs$23$*sqlsvc$CORP.LOCAL$MSSQLSvc*$aabb$abcdef
"""
        filepath = create_temp_file("dupes.txt", duplicate_hashes)
        summary = kerberoast_parser.parse(str(filepath))

        # Should deduplicate
        assert len(summary.credentials) <= 1

    def test_parser_name(self, kerberoast_parser):
        """
        BV: Parser has correct name

        Scenario:
          Given: Kerberoast parser instance
          When: Accessing name property
          Then: Returns 'kerberoast'
        """
        assert kerberoast_parser.name == "kerberoast"

    def test_parser_description(self, kerberoast_parser):
        """
        BV: Parser has description

        Scenario:
          Given: Kerberoast parser instance
          When: Accessing description
          Then: Returns non-empty description
        """
        assert len(kerberoast_parser.description) > 0


# =============================================================================
# Parser Registration Tests
# =============================================================================

class TestParserRegistration:
    """Tests for parser registration"""

    def test_kerberoast_parser_registered(self, prism_registry):
        """
        BV: Kerberoast parser available in registry

        Scenario:
          Given: Initialized parser registry
          When: Looking up kerberoast parser
          Then: Parser is found
        """
        parser = prism_registry.get_parser_by_name("kerberoast")
        assert parser is not None
        assert parser.name == "kerberoast"
