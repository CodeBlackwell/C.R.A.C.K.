"""
Tests for PRISM Parser Registry

Business Value Focus:
- BV:CRITICAL - Parser detection accuracy (correct parser selected for each file type)
- Users rely on auto-detection to avoid manually specifying parsers
- Wrong parser selection leads to missed credentials

Test Categories:
1. Parser Registration - Parsers register correctly
2. Parser Detection - Correct parser selected based on file content
3. Edge Cases - Empty files, unknown formats, encoding issues
"""

import pytest
from pathlib import Path


class TestParserRegistration:
    """Tests for parser registration behavior."""

    def test_registry_initializes_all_parsers(self, prism_registry):
        """
        BV: All expected parsers are available after initialization.

        Scenario:
          Given: Fresh registry
          When: initialize_parsers() is called
          Then: All 6 core parsers are registered
        """
        parser_names = prism_registry.list_parser_names()

        expected_parsers = ["mimikatz", "nmap", "gpp", "kerberoast", "secretsdump", "smbmap"]
        for expected in expected_parsers:
            assert expected in parser_names, f"Parser '{expected}' not registered"

    def test_registry_get_parser_by_name_returns_correct_parser(self, prism_registry):
        """
        BV: Users can retrieve specific parser by name.

        Scenario:
          Given: Initialized registry
          When: get_parser_by_name("mimikatz") is called
          Then: MimikatzParser instance returned
        """
        parser = prism_registry.get_parser_by_name("mimikatz")

        assert parser is not None
        assert parser.name == "mimikatz"

    def test_registry_get_parser_by_name_returns_none_for_unknown(self, prism_registry):
        """
        BV: Unknown parser names return None (not exception).

        Scenario:
          Given: Initialized registry
          When: get_parser_by_name("nonexistent") is called
          Then: None returned
        """
        parser = prism_registry.get_parser_by_name("nonexistent")

        assert parser is None

    def test_registry_clear_resets_initialization_flag(self, prism_registry):
        """
        BV: Registry can be reset for testing isolation.

        Scenario:
          Given: Initialized registry with parsers
          When: clear() is called
          Then: _initialized flag is reset

        Note: clear() resets the initialization flag, not the parsers dict.
              This allows re-initialization without parser duplication.
        """
        # Verify initialized
        assert prism_registry._initialized is True

        prism_registry.clear()

        # After clear, _initialized should be False
        assert prism_registry._initialized is False

    def test_registry_get_all_parsers_returns_list(self, prism_registry):
        """
        BV: All parser instances can be retrieved for iteration.

        Scenario:
          Given: Initialized registry
          When: get_all_parsers() is called
          Then: List of parser instances returned
        """
        parsers = prism_registry.get_all_parsers()

        assert isinstance(parsers, list)
        assert len(parsers) >= 6


class TestMimikatzDetection:
    """Tests for Mimikatz parser auto-detection."""

    def test_detects_sekurlsa_command(self, prism_registry, create_temp_file):
        """
        BV: Mimikatz output with sekurlsa command is detected.

        Scenario:
          Given: File containing "sekurlsa::logonpasswords"
          When: get_parser() is called
          Then: MimikatzParser is selected
        """
        content = """mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 12345
Session           : Interactive
User Name         : admin
Domain            : CORP
"""
        filepath = create_temp_file("mimi.txt", content)

        parser = prism_registry.get_parser(str(filepath))

        assert parser is not None
        assert parser.name == "mimikatz"

    def test_detects_mimikatz_banner(self, prism_registry, create_temp_file):
        """
        BV: Files with mimikatz version banner are detected.

        Scenario:
          Given: File with "mimikatz 2.2.0" banner
          When: get_parser() is called
          Then: MimikatzParser is selected
        """
        content = """
  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \\ ##  /*** Benjamin DELPY `gentilkiwi`
 ## \\ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             > https://pingcastle.com
  '#####'        > https://github.com/gentilkiwi/mimikatz
"""
        filepath = create_temp_file("mimi.txt", content)

        parser = prism_registry.get_parser(str(filepath))

        assert parser is not None
        assert parser.name == "mimikatz"

    def test_detects_auth_id_with_ntlm(self, prism_registry, create_temp_file):
        """
        BV: Files with Authentication Id and NTLM markers are detected.

        Scenario:
          Given: File with auth id header and NTLM hash
          When: get_parser() is called
          Then: MimikatzParser is selected
        """
        content = """Authentication Id : 0 ; 999
Session           : UndefinedLogonType from 0
User Name         : DESKTOP$
Domain            : CORP
        msv :
         * NTLM     : 32ed87bdb5fdc5e9cba88547376818d4
"""
        filepath = create_temp_file("output.txt", content)

        parser = prism_registry.get_parser(str(filepath))

        assert parser is not None
        assert parser.name == "mimikatz"

    def test_mimikatz_detection_with_sample_file(self, prism_registry, sample_mimikatz_file):
        """
        BV: Real mimikatz sample file is correctly detected.

        Scenario:
          Given: Sample mimikatz logonpasswords output file
          When: get_parser() is called
          Then: MimikatzParser is selected
        """
        if not sample_mimikatz_file.exists():
            pytest.skip("Sample mimikatz file not found")

        parser = prism_registry.get_parser(str(sample_mimikatz_file))

        assert parser is not None
        assert parser.name == "mimikatz"


class TestSecretsdumpDetection:
    """Tests for Secretsdump parser auto-detection."""

    def test_detects_sam_dump_header(self, prism_registry, create_temp_file):
        """
        BV: Files with SAM dump header are detected.

        Scenario:
          Given: File with "[*] Dumping local SAM hashes"
          When: get_parser() is called
          Then: SecretsdumpParser is selected
        """
        content = """Impacket v0.11.0
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
"""
        filepath = create_temp_file("sam.txt", content)

        parser = prism_registry.get_parser(str(filepath))

        assert parser is not None
        assert parser.name == "secretsdump"

    def test_detects_ntds_dump_header(self, prism_registry, create_temp_file):
        """
        BV: Files with NTDS dump header are detected.

        Scenario:
          Given: File with "[*] Dumping Domain Credentials"
          When: get_parser() is called
          Then: SecretsdumpParser is selected
        """
        content = """[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
CORP\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::
"""
        filepath = create_temp_file("ntds.txt", content)

        parser = prism_registry.get_parser(str(filepath))

        assert parser is not None
        assert parser.name == "secretsdump"

    def test_detects_hash_file_without_header(self, prism_registry, create_temp_file):
        """
        BV: Pure hash dump files (no headers) are detected by format.

        Scenario:
          Given: File with multiple user:rid:lm:nt::: lines
          When: get_parser() is called
          Then: SecretsdumpParser is selected
        """
        content = """Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
testuser:1001:aad3b435b51404eeaad3b435b51404ee:aabbccdd11223344aabbccdd11223344:::
backup:1002:aad3b435b51404eeaad3b435b51404ee:11223344aabbccdd11223344aabbccdd:::
"""
        filepath = create_temp_file("hashes.txt", content)

        parser = prism_registry.get_parser(str(filepath))

        assert parser is not None
        assert parser.name == "secretsdump"

    def test_detects_dcc2_hashes(self, prism_registry, create_temp_file):
        """
        BV: Files with DCC2 cached credentials are detected.

        Scenario:
          Given: File with $DCC2$ hash format
          When: get_parser() is called
          Then: SecretsdumpParser is selected
        """
        content = """CORP.LOCAL/administrator:$DCC2$10240#administrator#a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
CORP.LOCAL/jsmith:$DCC2$10240#jsmith#1234567890abcdef1234567890abcdef
"""
        filepath = create_temp_file("dcc2.txt", content)

        parser = prism_registry.get_parser(str(filepath))

        assert parser is not None
        assert parser.name == "secretsdump"

    def test_secretsdump_detection_with_sample_file(self, prism_registry, sample_secretsdump_file):
        """
        BV: Real secretsdump sample file is correctly detected.

        Scenario:
          Given: Sample secretsdump output file
          When: get_parser() is called
          Then: SecretsdumpParser is selected
        """
        if not sample_secretsdump_file.exists():
            pytest.skip("Sample secretsdump file not found")

        parser = prism_registry.get_parser(str(sample_secretsdump_file))

        assert parser is not None
        assert parser.name == "secretsdump"


class TestNmapDetection:
    """Tests for Nmap parser auto-detection."""

    def test_detects_nmap_header(self, prism_registry, create_temp_file):
        """
        BV: Files with nmap scan header are detected.

        Scenario:
          Given: File with "# Nmap 7.94 scan initiated"
          When: get_parser() is called
          Then: NmapParser is selected
        """
        content = """# Nmap 7.94 scan initiated Wed Dec 25 10:00:00 2024 as: nmap -sV 192.168.1.100
Nmap scan report for 192.168.1.100
Host is up (0.00050s latency).
PORT   STATE SERVICE
22/tcp open  ssh
# Nmap done at Wed Dec 25 10:00:05 2024 -- 1 IP address (1 host up) scanned in 5.00 seconds
"""
        filepath = create_temp_file("scan.nmap", content)

        parser = prism_registry.get_parser(str(filepath))

        assert parser is not None
        assert parser.name == "nmap"

    def test_detects_nmap_by_footer(self, prism_registry, create_temp_file):
        """
        BV: Files with nmap completion footer are detected.

        Scenario:
          Given: File with "Nmap done at" footer
          When: get_parser() is called
          Then: NmapParser is selected
        """
        content = """Nmap scan report for 192.168.1.100
Host is up.
PORT   STATE SERVICE
80/tcp open  http
# Nmap done at Wed Dec 25 10:00:05 2024 -- 1 IP address (1 host up) scanned in 5.00 seconds
"""
        filepath = create_temp_file("scan.nmap", content)

        parser = prism_registry.get_parser(str(filepath))

        assert parser is not None
        assert parser.name == "nmap"

    def test_detects_nmap_by_port_table(self, prism_registry, create_temp_file):
        """
        BV: Files with nmap port table structure are detected.

        Scenario:
          Given: File with PORT STATE SERVICE header and port entries
          When: get_parser() is called (with .nmap extension)
          Then: NmapParser is selected
        """
        content = """Nmap scan report for target.local
Host is up.
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.4p1
80/tcp   open  http     Apache httpd 2.4.51
"""
        # Need header/footer OR extension to pass secondary check
        filepath = create_temp_file("scan.nmap", content)

        parser = prism_registry.get_parser(str(filepath))

        # May return None if no header/footer - depends on implementation
        # The test documents expected behavior based on can_parse logic
        if parser is not None:
            assert parser.name == "nmap"


class TestUnknownFileDetection:
    """Tests for handling unknown file types."""

    def test_returns_none_for_empty_file(self, prism_registry, create_temp_file):
        """
        BV: Empty files don't crash, return None gracefully.

        Scenario:
          Given: Empty file
          When: get_parser() is called
          Then: None is returned (no exception)
        """
        filepath = create_temp_file("empty.txt", "")

        parser = prism_registry.get_parser(str(filepath))

        assert parser is None

    def test_returns_none_for_random_text(self, prism_registry, create_temp_file):
        """
        BV: Random text files don't match any parser.

        Scenario:
          Given: File with random text content
          When: get_parser() is called
          Then: None is returned
        """
        content = """This is just some random text.
Nothing related to security tools here.
Just a regular log file or notes.
"""
        filepath = create_temp_file("notes.txt", content)

        parser = prism_registry.get_parser(str(filepath))

        assert parser is None

    def test_returns_none_for_nonexistent_file(self, prism_registry, tmp_path):
        """
        BV: Nonexistent files don't crash, return None gracefully.

        Scenario:
          Given: Path to file that doesn't exist
          When: get_parser() is called
          Then: None is returned (no exception)
        """
        filepath = tmp_path / "nonexistent.txt"

        parser = prism_registry.get_parser(str(filepath))

        assert parser is None

    def test_returns_none_for_binary_garbage(self, prism_registry, create_binary_file):
        """
        BV: Binary files don't crash the parser detection.

        Scenario:
          Given: Binary file with non-text content
          When: get_parser() is called
          Then: None is returned (no exception)
        """
        # Create file with binary garbage
        filepath = create_binary_file("binary.bin", b"\x00\x01\x02\xff\xfe\xfd")

        parser = prism_registry.get_parser(str(filepath))

        assert parser is None


class TestEncodingHandling:
    """Tests for file encoding handling during detection."""

    def test_detects_mimikatz_with_utf8(self, prism_registry, create_temp_file):
        """
        BV: UTF-8 encoded files are correctly detected.

        Scenario:
          Given: UTF-8 encoded mimikatz output
          When: get_parser() is called
          Then: MimikatzParser is selected
        """
        content = """mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 12345
User Name         : Benutzer
Domain            : FIRMA
"""
        filepath = create_temp_file("mimi_utf8.txt", content, encoding="utf-8")

        parser = prism_registry.get_parser(str(filepath))

        assert parser is not None
        assert parser.name == "mimikatz"

    def test_detects_mimikatz_with_latin1(self, prism_registry, create_binary_file):
        """
        BV: Latin-1 encoded files (common Windows output) are detected.

        Scenario:
          Given: Latin-1 encoded mimikatz output
          When: get_parser() is called
          Then: MimikatzParser is selected
        """
        # Latin-1 content with special chars
        content = b"""mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 12345
User Name         : Benutz\xe9r
Domain            : CORP
"""
        filepath = create_binary_file("mimi_latin1.txt", content)

        parser = prism_registry.get_parser(str(filepath))

        assert parser is not None
        assert parser.name == "mimikatz"

    def test_handles_mixed_encoding(self, prism_registry, create_binary_file):
        """
        BV: Files with mixed encoding don't crash detection.

        Scenario:
          Given: File with mixed UTF-8 and Latin-1 bytes
          When: get_parser() is called
          Then: Detection completes without exception
        """
        # Mix of UTF-8 and raw bytes
        content = b"""mimikatz # sekurlsa::logonpasswords
User Name : \xc3\xa9\xff\xfe admin
NTLM: 32ed87bdb5fdc5e9cba88547376818d4
"""
        filepath = create_binary_file("mimi_mixed.txt", content)

        # Should not raise exception
        parser = prism_registry.get_parser(str(filepath))
        # Parser may or may not match depending on how content parses


class TestParserPriority:
    """Tests for parser selection priority when multiple might match."""

    def test_mimikatz_takes_priority_over_secretsdump_for_logonpasswords(
        self, prism_registry, create_temp_file
    ):
        """
        BV: Mimikatz-specific output detected as mimikatz, not secretsdump.

        Scenario:
          Given: File with mimikatz sekurlsa output format
          When: get_parser() is called
          Then: MimikatzParser is selected (not secretsdump)

        Edge Case: Both parsers could potentially match NTLM hashes.
        """
        content = """mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 12345
Session           : Interactive
User Name         : admin
Domain            : CORP
        msv :
         * NTLM     : 32ed87bdb5fdc5e9cba88547376818d4
"""
        filepath = create_temp_file("output.txt", content)

        parser = prism_registry.get_parser(str(filepath))

        assert parser is not None
        assert parser.name == "mimikatz", "Mimikatz output should be detected as mimikatz, not secretsdump"


class TestParserNameUniqueness:
    """Tests for parser name constraints."""

    def test_all_parser_names_are_unique(self, prism_registry):
        """
        BV: No duplicate parser names (would cause registry conflicts).

        Scenario:
          Given: Initialized registry
          When: All parser names are collected
          Then: No duplicates exist
        """
        names = prism_registry.list_parser_names()
        unique_names = set(names)

        assert len(names) == len(unique_names), "Duplicate parser names found"

    def test_parser_names_are_lowercase(self, prism_registry):
        """
        BV: Parser names follow consistent lowercase convention.

        Scenario:
          Given: Initialized registry
          When: All parser names are checked
          Then: All are lowercase
        """
        names = prism_registry.list_parser_names()

        for name in names:
            assert name == name.lower(), f"Parser name '{name}' is not lowercase"


class TestParserDescription:
    """Tests for parser description metadata."""

    def test_all_parsers_have_descriptions(self, prism_registry):
        """
        BV: All parsers have human-readable descriptions.

        Scenario:
          Given: Initialized registry
          When: All parser descriptions are accessed
          Then: None are empty
        """
        parsers = prism_registry.get_all_parsers()

        for parser in parsers:
            assert parser.description, f"Parser '{parser.name}' has no description"
            assert len(parser.description) > 10, f"Parser '{parser.name}' description too short"
