"""
Enumerator plugin registry.

Provides a flat registry of available enumeration tools.
Zen: "Flat is better than nested" - simple list, no factory patterns.
"""

from typing import List, Optional, Type

from .base import Enumerator, EnumerationResult, AuthLevel
from .enum4linux import Enum4linuxEnumerator
from .ldapsearch import LdapsearchEnumerator
from .kerbrute import KerbruteEnumerator
from .getnpusers import GetNPUsersEnumerator
from .smb_crawler import SMBCrawler, ShareInfo, CrawlResult, create_smb_crawler

# Registry: ordered by preference
# Anonymous-capable tools first, then authenticated-only
# Note: GetNPUsersEnumerator is run separately in Phase 2 (needs user list from Phase 1)
ENUMERATORS: List[Type[Enumerator]] = [
    Enum4linuxEnumerator,   # SMB/RPC - richest data (users, groups, policy)
    LdapsearchEnumerator,   # LDAP - good for UAC flags
    KerbruteEnumerator,     # Kerberos - validates users, detects AS-REP
]


def get_available_enumerators(
    anonymous_only: bool = False,
    require_installed: bool = True
) -> List[Enumerator]:
    """
    Get list of available enumerators.

    Args:
        anonymous_only: Only return enumerators that work without creds
        require_installed: Only return enumerators whose tools are installed

    Returns:
        List of instantiated Enumerator objects
    """
    result = []
    for cls in ENUMERATORS:
        enum = cls()

        if anonymous_only and not enum.supports_anonymous:
            continue

        if require_installed and not enum.is_available():
            continue

        result.append(enum)

    return result


def get_enumerator(enumerator_id: str) -> Optional[Enumerator]:
    """Get specific enumerator by ID"""
    for cls in ENUMERATORS:
        enum = cls()
        if enum.id == enumerator_id:
            return enum
    return None


def list_enumerators() -> List[dict]:
    """List all enumerators with their status"""
    result = []
    for cls in ENUMERATORS:
        enum = cls()
        result.append({
            "id": enum.id,
            "name": enum.name,
            "tool": enum.required_tool,
            "anonymous": enum.supports_anonymous,
            "available": enum.is_available(),
        })
    return result


__all__ = [
    "Enumerator",
    "EnumerationResult",
    "AuthLevel",
    "ENUMERATORS",
    "get_available_enumerators",
    "get_enumerator",
    "list_enumerators",
    "Enum4linuxEnumerator",
    "LdapsearchEnumerator",
    "KerbruteEnumerator",
    "GetNPUsersEnumerator",
    # SMB Crawler
    "SMBCrawler",
    "ShareInfo",
    "CrawlResult",
    "create_smb_crawler",
]
