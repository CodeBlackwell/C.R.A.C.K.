"""
Adapter Interface - Protocol definition for command registry adapters

This module defines the contract that all backend adapters must implement,
providing type safety and ensuring API compatibility across Neo4j, SQL,
and JSON backends.
"""

from typing import Protocol, List, Dict, Optional, Any
from .registry import Command


class CommandRegistryAdapter(Protocol):
    """
    Protocol defining required interface for all command registry adapters

    All backend adapters (Neo4jCommandRegistryAdapter, SQLCommandRegistryAdapter,
    HybridCommandRegistry) must implement these methods to ensure API compatibility
    and enable proper type checking.

    Type checkers (mypy, pyright) will verify that adapters conform to this protocol.
    """

    def get_command(self, command_id: str) -> Optional[Command]:
        """
        Get single command by ID

        Args:
            command_id: Unique command identifier

        Returns:
            Command dataclass or None if not found
        """
        ...

    def search(
        self,
        query: str,
        category: Optional[str] = None,
        tags: Optional[List[str]] = None,
        oscp_only: bool = False
    ) -> List[Command]:
        """
        Search commands by query string

        Args:
            query: Search term (matches name, description, command text)
            category: Optional category filter
            tags: Optional tag filter
            oscp_only: If True, only return high OSCP relevance commands

        Returns:
            List of matching Command dataclasses
        """
        ...

    def filter_by_category(
        self,
        category: str,
        subcategory: Optional[str] = None
    ) -> List[Command]:
        """
        Get all commands in a category

        Args:
            category: Command category
            subcategory: Optional subcategory filter

        Returns:
            List of Command dataclasses in category
        """
        ...

    def filter_by_tags(
        self,
        tags: List[str],
        match_all: bool = True
    ) -> List[Command]:
        """
        Filter commands by tags

        Args:
            tags: List of tag names
            match_all: If True, command must have all tags; if False, any tag

        Returns:
            List of Command dataclasses matching tag criteria
        """
        ...

    def get_quick_wins(self) -> List[Command]:
        """
        Get quick win commands (QUICK_WIN tag)

        Returns:
            List of Command dataclasses tagged as quick wins
        """
        ...

    def get_oscp_high(self) -> List[Command]:
        """
        Get OSCP high priority commands

        Returns:
            List of Command dataclasses with oscp_relevance='high'
        """
        ...

    def get_stats(self) -> Dict[str, Any]:
        """
        Get registry statistics

        Returns:
            Dict with counts: total_commands, categories, tags, etc.
        """
        ...

    def health_check(self) -> bool:
        """
        Check if backend is available and healthy

        Returns:
            True if backend is operational, False otherwise
        """
        ...

    def interactive_fill(self, command: Command) -> str:
        """
        Interactively prompt user to fill command placeholders

        Args:
            command: Command dataclass to fill

        Returns:
            Filled command string with all placeholders replaced
        """
        ...

    def get_all_commands(self) -> List[Command]:
        """
        Get all commands in registry

        Returns:
            List of all Command dataclasses
        """
        ...

    def get_subcategories(self, category: str) -> List[str]:
        """
        Get subcategories for a given category

        Args:
            category: Category name

        Returns:
            List of subcategory names
        """
        ...

    # Graph-specific methods (optional for non-graph backends)
    # These may raise NotImplementedError for adapters that don't support graph operations

    def find_alternatives(
        self,
        command_id: str,
        max_depth: int = 3
    ) -> List[Command]:
        """
        Find alternative commands (graph traversal)

        Args:
            command_id: Starting command ID
            max_depth: Maximum traversal depth (1-3)

        Returns:
            List of alternative Command dataclasses

        Note:
            May raise NotImplementedError for non-graph backends
        """
        ...

    def find_prerequisites(
        self,
        command_id: str,
        depth: int = 3
    ) -> List[Command]:
        """
        Find prerequisite commands (graph traversal)

        Args:
            command_id: Target command ID
            depth: Maximum traversal depth

        Returns:
            List of prerequisite Command dataclasses in execution order

        Note:
            May raise NotImplementedError for non-graph backends
        """
        ...

    def get_attack_chain_path(
        self,
        chain_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get attack chain with ordered steps

        Args:
            chain_id: Attack chain ID

        Returns:
            Dict with chain metadata and ordered steps, or None

        Note:
            May raise NotImplementedError for non-graph backends
        """
        ...


class ReadOnlyAdapter(Protocol):
    """
    Protocol for read-only adapters (SQL, Neo4j)

    These adapters don't support write operations like add_command
    or save_to_json. Use migration scripts for data modifications.
    """

    def get_command(self, command_id: str) -> Optional[Command]:
        ...

    def search(
        self,
        query: str,
        category: Optional[str] = None,
        tags: Optional[List[str]] = None,
        oscp_only: bool = False
    ) -> List[Command]:
        ...

    def health_check(self) -> bool:
        ...


class MutableAdapter(CommandRegistryAdapter, Protocol):
    """
    Protocol for mutable adapters (JSON-based HybridCommandRegistry)

    Extends CommandRegistryAdapter with write operations.
    """

    def add_command(self, command: Command) -> bool:
        """
        Add new command to registry

        Args:
            command: Command dataclass to add

        Returns:
            True if added successfully, False otherwise
        """
        ...

    def save_to_json(self, filepath: str = None) -> bool:
        """
        Save registry to JSON file

        Args:
            filepath: Optional custom filepath

        Returns:
            True if saved successfully, False otherwise
        """
        ...
