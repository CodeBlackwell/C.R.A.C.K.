"""
Linux Shadow File Parser

Parses /etc/shadow format files with Linux password hashes.
"""

from .parser import ShadowParser

__all__ = ["ShadowParser"]
