"""
Test Fixtures Package

Contains sample outputs from security tools for parser testing.

Available Fixtures:
- sample_outputs/mimikatz_logonpasswords.txt
- sample_outputs/nmap_scan.xml
- sample_outputs/secretsdump_output.txt

Usage:
    from pathlib import Path

    FIXTURES_DIR = Path(__file__).parent / "sample_outputs"
    mimikatz_path = FIXTURES_DIR / "mimikatz_logonpasswords.txt"
"""

from pathlib import Path

# Convenience path for fixture location
SAMPLE_OUTPUTS_DIR = Path(__file__).parent / "sample_outputs"

# Available fixture files
MIMIKATZ_LOGONPASSWORDS = SAMPLE_OUTPUTS_DIR / "mimikatz_logonpasswords.txt"
NMAP_SCAN_XML = SAMPLE_OUTPUTS_DIR / "nmap_scan.xml"
SECRETSDUMP_OUTPUT = SAMPLE_OUTPUTS_DIR / "secretsdump_output.txt"


def get_fixture_path(filename: str) -> Path:
    """
    Get full path to a fixture file.

    Args:
        filename: Name of fixture file.

    Returns:
        Path to fixture file.

    Raises:
        FileNotFoundError: If fixture doesn't exist.
    """
    path = SAMPLE_OUTPUTS_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Fixture not found: {path}")
    return path


def read_fixture(filename: str, encoding: str = "utf-8") -> str:
    """
    Read fixture file content.

    Args:
        filename: Name of fixture file.
        encoding: File encoding (default: utf-8).

    Returns:
        File content as string.
    """
    path = get_fixture_path(filename)
    return path.read_text(encoding=encoding)


__all__ = [
    "SAMPLE_OUTPUTS_DIR",
    "MIMIKATZ_LOGONPASSWORDS",
    "NMAP_SCAN_XML",
    "SECRETSDUMP_OUTPUT",
    "get_fixture_path",
    "read_fixture",
]
