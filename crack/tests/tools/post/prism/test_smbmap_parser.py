"""
Tests for SMBMap Parser

Business Value Focus:
- Parse SMB share enumeration for attack surface mapping
- Identify readable/writable shares for exploitation
- Extract file listings for loot discovery

Test Priority: TIER 1 - CRITICAL (Core Enumeration)
"""

import pytest
from pathlib import Path


# =============================================================================
# Sample SMBMap Content
# =============================================================================

# Standard SMBMap output
SMBMAP_OUTPUT = """SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com

[+] IP: 192.168.1.100:445    Name: DC01    Status: Authenticated

        Disk                                                  Permissions    Comment
        ----                                                  -----------    -------
        ADMIN$                                                NO ACCESS      Remote Admin
        C$                                                    NO ACCESS      Default share
        IPC$                                                  NO ACCESS      Remote IPC
        NETLOGON                                              READ ONLY      Logon server share
        SYSVOL                                                READ ONLY      Logon server share
        Users                                                 READ, WRITE
        SharedDocs                                            READ ONLY      Shared Documents
"""

# SMBMap with directory listings
SMBMAP_WITH_DIRS = """SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com

[+] IP: 192.168.1.100:445    Name: DC01    Status: Authenticated

        Disk                                                  Permissions    Comment
        ----                                                  -----------    -------
        Users                                                 READ, WRITE
        SharedDocs                                            READ ONLY      Shared Documents

./Users
dr--r--r--                0 Sat Jul 21 00:37:44 2018    .
dr--r--r--                0 Sat Jul 21 00:37:44 2018    ..
dr--r--r--                0 Sat Jul 21 00:37:44 2018    Administrator
dr--r--r--                0 Sat Jul 21 00:37:44 2018    Default
-r--r--r--              174 Sat Jul 21 00:37:44 2018    desktop.ini

./SharedDocs
dr--r--r--                0 Sun Jan 15 10:00:00 2023    .
dr--r--r--                0 Sun Jan 15 10:00:00 2023    ..
-r--r--r--            15360 Sun Jan 15 10:00:00 2023    passwords.xlsx
-r--r--r--             2048 Sun Jan 15 10:00:00 2023    notes.txt
"""

# Minimal SMBMap output
MINIMAL_OUTPUT = """[+] IP: 10.10.10.100:445    Name: TARGET    Status: Guest session

        Disk                                                  Permissions    Comment
        ----                                                  -----------    -------
        IPC$                                                  NO ACCESS      Remote IPC
        share                                                 READ ONLY
"""

# SMBMap with write access
WRITE_ACCESS_OUTPUT = """SMBMap - Samba Share Enumerator

[+] IP: 192.168.1.50:445    Name: FILE01    Status: Authenticated

        Disk                                                  Permissions    Comment
        ----                                                  -----------    -------
        Backups                                               READ, WRITE    Backup folder
        wwwroot                                               READ, WRITE    Web root
        ADMIN$                                                NO ACCESS      Remote Admin
"""

# Non-SMBMap content
NON_SMBMAP = """nmap scan report for 192.168.1.100
PORT     STATE SERVICE
445/tcp  open  microsoft-ds
"""


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def smbmap_parser(prism_registry):
    """
    SMBMap parser instance.

    BV: Consistent parser for SMBMap output tests.
    """
    return prism_registry.get_parser_by_name("smbmap")


@pytest.fixture
def smbmap_file(create_temp_file):
    """Create temp SMBMap output file."""
    return create_temp_file("smbmap_output.txt", SMBMAP_OUTPUT)


@pytest.fixture
def smbmap_with_dirs_file(create_temp_file):
    """Create temp SMBMap output with directory listings."""
    return create_temp_file("smbmap_dirs.txt", SMBMAP_WITH_DIRS)


@pytest.fixture
def minimal_file(create_temp_file):
    """Create minimal SMBMap output file."""
    return create_temp_file("smbmap_minimal.txt", MINIMAL_OUTPUT)


@pytest.fixture
def write_access_file(create_temp_file):
    """Create SMBMap output with write access."""
    return create_temp_file("smbmap_write.txt", WRITE_ACCESS_OUTPUT)


# =============================================================================
# Parser Detection Tests
# =============================================================================

class TestSmbmapParserDetection:
    """Tests for SMBMap file detection"""

    def test_can_parse_smbmap_output(self, smbmap_parser, smbmap_file):
        """
        BV: Detect SMBMap output by banner

        Scenario:
          Given: SMBMap output with banner
          When: can_parse() is called
          Then: Returns True
        """
        assert smbmap_parser.can_parse(str(smbmap_file)) is True

    def test_can_parse_minimal_output(self, smbmap_parser, minimal_file):
        """
        BV: Detect minimal SMBMap output

        Scenario:
          Given: Minimal SMBMap output (no banner)
          When: can_parse() is called
          Then: Returns True (detected by IP status)
        """
        assert smbmap_parser.can_parse(str(minimal_file)) is True

    def test_cannot_parse_non_smbmap(self, smbmap_parser, create_temp_file):
        """
        BV: Reject non-SMBMap files

        Scenario:
          Given: nmap output (not SMBMap)
          When: can_parse() is called
          Then: Returns False
        """
        filepath = create_temp_file("nmap.txt", NON_SMBMAP)
        assert smbmap_parser.can_parse(str(filepath)) is False

    def test_cannot_parse_nonexistent(self, smbmap_parser):
        """
        BV: Handle missing files gracefully

        Scenario:
          Given: Non-existent file path
          When: can_parse() is called
          Then: Returns False
        """
        assert smbmap_parser.can_parse("/nonexistent/file.txt") is False


# =============================================================================
# Share Parsing Tests
# =============================================================================

class TestShareParsing:
    """Tests for share table parsing"""

    def test_parse_extracts_all_shares(self, smbmap_parser, smbmap_file):
        """
        BV: Extract all shares from output

        Scenario:
          Given: SMBMap output with 7 shares
          When: parse() is called
          Then: All 7 shares extracted
        """
        summary = smbmap_parser.parse(str(smbmap_file))

        assert len(summary.shares) == 7

    def test_parse_extracts_share_names(self, smbmap_parser, smbmap_file):
        """
        BV: Extract share names correctly

        Scenario:
          Given: SMBMap output
          When: parse() is called
          Then: Share names extracted
        """
        summary = smbmap_parser.parse(str(smbmap_file))

        share_names = [s.name for s in summary.shares]
        assert 'ADMIN$' in share_names
        assert 'Users' in share_names
        assert 'NETLOGON' in share_names

    def test_parse_extracts_permissions(self, smbmap_parser, smbmap_file):
        """
        BV: Extract share permissions correctly

        Scenario:
          Given: SMBMap output with various permissions
          When: parse() is called
          Then: Permissions extracted correctly
        """
        from tools.post.prism.models.smbmap_scan import SmbPermission

        summary = smbmap_parser.parse(str(smbmap_file))

        # Find specific shares
        admin_share = next(s for s in summary.shares if s.name == 'ADMIN$')
        users_share = next(s for s in summary.shares if s.name == 'Users')
        netlogon = next(s for s in summary.shares if s.name == 'NETLOGON')

        assert admin_share.permission == SmbPermission.NO_ACCESS
        assert users_share.permission == SmbPermission.READ_WRITE
        assert netlogon.permission == SmbPermission.READ_ONLY


# =============================================================================
# Target Info Tests
# =============================================================================

class TestTargetInfoParsing:
    """Tests for target information parsing"""

    def test_parse_extracts_target_ip(self, smbmap_parser, smbmap_file):
        """
        BV: Extract target IP for reporting

        Scenario:
          Given: SMBMap output
          When: parse() is called
          Then: Target IP extracted
        """
        summary = smbmap_parser.parse(str(smbmap_file))

        assert summary.target_ip == '192.168.1.100'

    def test_parse_extracts_target_hostname(self, smbmap_parser, smbmap_file):
        """
        BV: Extract target hostname

        Scenario:
          Given: SMBMap output with hostname
          When: parse() is called
          Then: Hostname extracted
        """
        summary = smbmap_parser.parse(str(smbmap_file))

        assert summary.target_hostname == 'DC01'

    def test_parse_extracts_port(self, smbmap_parser, smbmap_file):
        """
        BV: Extract target port

        Scenario:
          Given: SMBMap output with port
          When: parse() is called
          Then: Port extracted (default 445)
        """
        summary = smbmap_parser.parse(str(smbmap_file))

        assert summary.target_port == 445


# =============================================================================
# Directory Listing Tests
# =============================================================================

class TestDirectoryListingParsing:
    """Tests for directory listing parsing"""

    def test_parse_extracts_directory_entries(
        self, smbmap_parser, smbmap_with_dirs_file
    ):
        """
        BV: Extract file/directory entries

        Scenario:
          Given: SMBMap output with directory listings
          When: parse() is called
          Then: Entries extracted
        """
        summary = smbmap_parser.parse(str(smbmap_with_dirs_file))

        # Find Users share
        users_share = next(
            (s for s in summary.shares if s.name == 'Users'),
            None
        )

        assert users_share is not None
        # Should have entries (excluding . and ..)
        assert len(users_share.entries) > 0

    def test_parse_identifies_file_types(
        self, smbmap_parser, smbmap_with_dirs_file
    ):
        """
        BV: Distinguish files from directories

        Scenario:
          Given: SMBMap output with mixed entries
          When: parse() is called
          Then: Types correctly identified
        """
        from tools.post.prism.models.smbmap_scan import SmbEntryType

        summary = smbmap_parser.parse(str(smbmap_with_dirs_file))

        # Find SharedDocs share
        docs_share = next(
            (s for s in summary.shares if s.name == 'SharedDocs'),
            None
        )

        if docs_share and docs_share.entries:
            # Should have files
            files = [e for e in docs_share.entries if e.entry_type == SmbEntryType.FILE]
            assert len(files) > 0


# =============================================================================
# Readable/Writable Share Tests
# =============================================================================

class TestShareAccessibility:
    """Tests for share accessibility detection"""

    def test_readable_shares_property(self, smbmap_parser, smbmap_file):
        """
        BV: Identify readable shares for enumeration

        Scenario:
          Given: SMBMap output with mixed permissions
          When: Checking readable_shares
          Then: Only readable shares listed
        """
        summary = smbmap_parser.parse(str(smbmap_file))

        # Readable shares: NETLOGON, SYSVOL, Users, SharedDocs
        assert len(summary.readable_shares) >= 4

    def test_writable_shares_detection(
        self, smbmap_parser, write_access_file
    ):
        """
        BV: Identify writable shares for exploitation

        Scenario:
          Given: SMBMap output with write access
          When: Checking for writable shares
          Then: Writable shares identified
        """
        from tools.post.prism.models.smbmap_scan import SmbPermission

        summary = smbmap_parser.parse(str(write_access_file))

        writable = [
            s for s in summary.shares
            if s.permission == SmbPermission.READ_WRITE
        ]
        assert len(writable) == 2
        names = [s.name for s in writable]
        assert 'Backups' in names
        assert 'wwwroot' in names


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Edge case handling tests"""

    def test_empty_file(self, smbmap_parser, create_temp_file):
        """
        BV: Handle empty files gracefully

        Scenario:
          Given: Empty file
          When: parse() is called
          Then: Returns empty summary
        """
        filepath = create_temp_file("empty.txt", "")
        summary = smbmap_parser.parse(str(filepath))

        assert len(summary.shares) == 0

    def test_parser_name(self, smbmap_parser):
        """
        BV: Parser has correct name

        Scenario:
          Given: SMBMap parser instance
          When: Accessing name property
          Then: Returns 'smbmap'
        """
        assert smbmap_parser.name == "smbmap"

    def test_parser_description(self, smbmap_parser):
        """
        BV: Parser has description

        Scenario:
          Given: SMBMap parser instance
          When: Accessing description
          Then: Returns non-empty description
        """
        assert len(smbmap_parser.description) > 0


# =============================================================================
# Parser Registration Tests
# =============================================================================

class TestParserRegistration:
    """Tests for parser registration"""

    def test_smbmap_parser_registered(self, prism_registry):
        """
        BV: SMBMap parser available in registry

        Scenario:
          Given: Initialized parser registry
          When: Looking up smbmap parser
          Then: Parser is found
        """
        parser = prism_registry.get_parser_by_name("smbmap")
        assert parser is not None
        assert parser.name == "smbmap"
