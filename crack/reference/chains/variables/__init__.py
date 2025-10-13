"""
Variable resolution system for attack chains.

Provides hierarchical variable scoping and automatic extraction from findings.
"""

from .context import VariableContext, VariableScope
from .extractors import VariableExtractor

__all__ = [
    'VariableContext',
    'VariableScope',
    'VariableExtractor',
]
