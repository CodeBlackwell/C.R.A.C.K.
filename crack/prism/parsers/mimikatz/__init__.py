"""
Mimikatz output parser

Supports:
- sekurlsa::logonpasswords
- sekurlsa::tickets
"""

from .parser import MimikatzParser

__all__ = ["MimikatzParser"]
