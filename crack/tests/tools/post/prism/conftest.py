"""
PRISM Test Configuration and Fixtures

Provides module-specific fixtures for PRISM parser tests.
Inherits from root conftest.py for shared fixtures.

Business Value Focus:
- Isolated parser registry per test (prevents state leakage)
- Sample output files for real-world testing
- Encoding-aware file creation utilities
"""

import pytest
from pathlib import Path
from typing import Generator, Dict, Any, List


# =============================================================================
# Path Constants
# =============================================================================

PRISM_FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_OUTPUTS_DIR = Path(__file__).parent.parent.parent.parent / "fixtures" / "sample_outputs"


# =============================================================================
# Parser Registry Fixtures
# =============================================================================

@pytest.fixture
def prism_registry():
    """
    Fresh PRISM parser registry with all parsers initialized.

    BV: Each test gets isolated registry state.

    Yields:
        PrismParserRegistry class (not instance - it's a class-based singleton)
    """
    from tools.post.prism.parsers.registry import PrismParserRegistry
    PrismParserRegistry.clear()
    PrismParserRegistry.initialize_parsers()
    yield PrismParserRegistry
    PrismParserRegistry.clear()


@pytest.fixture
def empty_registry():
    """
    Empty PRISM parser registry (no parsers registered).

    BV: Test parser registration behavior.
    """
    from tools.post.prism.parsers.registry import PrismParserRegistry
    PrismParserRegistry.clear()
    yield PrismParserRegistry
    PrismParserRegistry.clear()


# =============================================================================
# Parser Instance Fixtures
# =============================================================================

@pytest.fixture
def mimikatz_parser(prism_registry):
    """
    Mimikatz parser instance.

    BV: Consistent parser for mimikatz output tests.
    """
    return prism_registry.get_parser_by_name("mimikatz")


@pytest.fixture
def nmap_parser(prism_registry):
    """
    Nmap parser instance.

    BV: Consistent parser for nmap output tests.
    """
    return prism_registry.get_parser_by_name("nmap")


@pytest.fixture
def secretsdump_parser(prism_registry):
    """
    Secretsdump parser instance.

    BV: Consistent parser for secretsdump output tests.
    """
    return prism_registry.get_parser_by_name("secretsdump")


# =============================================================================
# Sample Output Fixtures
# =============================================================================

@pytest.fixture
def sample_mimikatz_file() -> Path:
    """
    Path to sample mimikatz logonpasswords output.

    BV: Real-world output for integration-level testing.
    """
    return SAMPLE_OUTPUTS_DIR / "mimikatz_logonpasswords.txt"


@pytest.fixture
def sample_secretsdump_file() -> Path:
    """
    Path to sample secretsdump output.

    BV: Real-world output for integration-level testing.
    """
    return SAMPLE_OUTPUTS_DIR / "secretsdump_output.txt"


@pytest.fixture
def sample_nmap_file() -> Path:
    """
    Path to sample nmap scan output.

    BV: Real-world output for integration-level testing.
    """
    return SAMPLE_OUTPUTS_DIR / "nmap_scan.xml"


# =============================================================================
# File Creation Fixtures
# =============================================================================

@pytest.fixture
def create_temp_file(tmp_path):
    """
    Factory for creating temporary files with content.

    BV: Tests can create file fixtures with specific content/encoding.

    Usage:
        def test_parser(create_temp_file):
            filepath = create_temp_file("test.txt", "content", encoding="utf-8")
    """
    def _create(filename: str, content: str, encoding: str = "utf-8") -> Path:
        filepath = tmp_path / filename
        filepath.write_text(content, encoding=encoding)
        return filepath
    return _create


@pytest.fixture
def create_binary_file(tmp_path):
    """
    Factory for creating temporary binary files.

    BV: Test encoding edge cases with raw bytes.

    Usage:
        def test_latin1(create_binary_file):
            filepath = create_binary_file("test.txt", b"content")
    """
    def _create(filename: str, content: bytes) -> Path:
        filepath = tmp_path / filename
        filepath.write_bytes(content)
        return filepath
    return _create


# =============================================================================
# Credential Creation Fixtures
# =============================================================================

@pytest.fixture
def parsed_summary_factory():
    """
    Factory for creating ParsedSummary objects.

    BV: Reduce boilerplate when testing summary operations.
    """
    from tools.post.prism.models.summary import ParsedSummary

    def _create(
        source_file: str = "test.txt",
        source_tool: str = "test",
        credentials: List = None,
        tickets: List = None,
        sessions: List = None,
    ) -> ParsedSummary:
        summary = ParsedSummary(
            source_file=source_file,
            source_tool=source_tool,
        )
        if credentials:
            summary.credentials = credentials
        if tickets:
            summary.tickets = tickets
        if sessions:
            summary.sessions = sessions
        return summary

    return _create


@pytest.fixture
def logon_session_factory():
    """
    Factory for creating LogonSession objects.

    BV: Reduce boilerplate when testing session-related logic.
    """
    from tools.post.prism.models.session import LogonSession

    _counter = 0

    def _create(
        auth_id_high: int = None,
        auth_id_low: int = None,
        session_type: str = "Interactive",
        username: str = "testuser",
        domain: str = "TESTDOMAIN",
        **kwargs
    ) -> LogonSession:
        nonlocal _counter
        _counter += 1
        return LogonSession(
            auth_id_high=auth_id_high or _counter,
            auth_id_low=auth_id_low or (_counter * 1000),
            session_type=session_type,
            username=username,
            domain=domain,
            **kwargs
        )

    return _create


# =============================================================================
# Sample Content Constants
# =============================================================================

# Minimal mimikatz output for quick tests
MINIMAL_MIMIKATZ = """mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 12345 (00000000:00003039)
Session           : Interactive from 1
User Name         : testuser
Domain            : TESTDOMAIN
        msv :
         [00000003] Primary
         * Username : testuser
         * Domain   : TESTDOMAIN
         * NTLM     : 32ed87bdb5fdc5e9cba88547376818d4
        wdigest :
         * Username : testuser
         * Domain   : TESTDOMAIN
         * Password : TestPassword123!
"""

# Minimal nmap output
MINIMAL_NMAP = """# Nmap 7.94 scan initiated Wed Dec 25 10:00:00 2024 as: nmap -sV 192.168.1.100
Nmap scan report for 192.168.1.100
Host is up (0.00050s latency).
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.4p1
80/tcp   open  http     Apache httpd 2.4.51
443/tcp  open  ssl/http Apache httpd 2.4.51
# Nmap done at Wed Dec 25 10:00:05 2024 -- 1 IP address (1 host up) scanned in 5.00 seconds
"""

# Minimal secretsdump output
MINIMAL_SECRETSDUMP = """[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
testuser:1001:aad3b435b51404eeaad3b435b51404ee:aabbccdd11223344aabbccdd11223344:::
"""


@pytest.fixture
def minimal_mimikatz_content() -> str:
    """Minimal mimikatz output content."""
    return MINIMAL_MIMIKATZ


@pytest.fixture
def minimal_nmap_content() -> str:
    """Minimal nmap output content."""
    return MINIMAL_NMAP


@pytest.fixture
def minimal_secretsdump_content() -> str:
    """Minimal secretsdump output content."""
    return MINIMAL_SECRETSDUMP
