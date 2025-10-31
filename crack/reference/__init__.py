"""
CRACK Reference System - Command Reference and Management

A hybrid reference system that combines human-readable markdown documentation
with programmatic command management for OSCP preparation.
"""

__version__ = "1.0.0"
__author__ = "CRACK Development Team"

from .core import HybridCommandRegistry, SQLCommandRegistryAdapter

__all__ = ['HybridCommandRegistry', 'SQLCommandRegistryAdapter']