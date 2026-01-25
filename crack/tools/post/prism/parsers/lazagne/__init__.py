"""
LaZagne Credential Parser

Parses LaZagne JSON output containing extracted credentials from browsers,
Wi-Fi, Windows credential manager, and other sources.
"""

from .parser import LaZagneParser

__all__ = ["LaZagneParser"]
