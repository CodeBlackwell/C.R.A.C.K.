"""
Secretsdump Parser

Parses hash dumps from secretsdump.py, SAM, and NTDS.dit extracts.
"""

from .parser import SecretsdumpParser

__all__ = ["SecretsdumpParser"]
