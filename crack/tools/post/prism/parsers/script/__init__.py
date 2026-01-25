"""
Script Credential Parser

Finds hardcoded credentials in scripts (PowerShell, Bash, Python, YAML, batch).
"""

from .parser import ScriptParser

__all__ = ["ScriptParser"]
