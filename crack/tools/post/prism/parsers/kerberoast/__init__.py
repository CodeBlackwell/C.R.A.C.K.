"""
Kerberoast Parser

Parses Kerberos TGS hashes from GetUserSPNs.py, Rubeus, and raw hash files.
"""

from .parser import KerberoastParser

__all__ = ["KerberoastParser"]
