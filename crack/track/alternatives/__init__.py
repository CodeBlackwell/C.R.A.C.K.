"""
Alternative Commands System

Dynamic, executable alternatives to automated tasks.
Variables auto-fill from context (profile, task, config) or prompt user interactively.

Usage:
    Press 'alt' in interactive mode to browse/execute alternatives.

Architecture:
    - models: AlternativeCommand, Variable, ExecutionResult data structures
    - context: ContextResolver - auto-fill variables from execution context
    - executor: AlternativeExecutor - dynamic command execution
    - registry: AlternativeCommandRegistry - load/search/filter commands
    - commands/: Command definitions organized by category (for devs to fill)
"""

from .models import AlternativeCommand, Variable, ExecutionResult
from .context import ContextResolver
from .executor import AlternativeExecutor
from .registry import AlternativeCommandRegistry

__all__ = [
    'AlternativeCommand',
    'Variable',
    'ExecutionResult',
    'ContextResolver',
    'AlternativeExecutor',
    'AlternativeCommandRegistry'
]
