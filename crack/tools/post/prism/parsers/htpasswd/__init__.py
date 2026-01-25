"""
Htpasswd Parser

Parses Apache .htpasswd files to extract usernames and password hashes.
"""

from .parser import HtpasswdParser

__all__ = ["HtpasswdParser"]
