"""
Alternative Commands Registry

Loads, indexes, and provides search/filter capabilities for alternative commands.
"""

import fnmatch
from typing import Dict, List, Optional
from .models import AlternativeCommand


class AlternativeCommandRegistry:
    """Registry for alternative commands"""

    # Class-level storage
    _alternatives: Dict[str, AlternativeCommand] = {}
    _by_category: Dict[str, List[str]] = {}
    _by_task_pattern: Dict[str, List[str]] = {}
    _loaded: bool = False

    @classmethod
    def load_all(cls):
        """
        Load all alternative command definitions from commands/ modules

        This imports all command definition modules and registers their alternatives.
        """
        if cls._loaded:
            return  # Already loaded

        try:
            # Import all command modules
            from .commands import (
                web_enumeration,
                privilege_escalation,
                file_transfer,
                anti_forensics,
                database_enum,
                network_recon
            )

            # Register alternatives from each module
            for module in [
                web_enumeration,
                privilege_escalation,
                file_transfer,
                anti_forensics,
                database_enum,
                network_recon
            ]:
                if hasattr(module, 'ALTERNATIVES'):
                    for alt in module.ALTERNATIVES:
                        cls.register(alt)

            cls._loaded = True

        except ImportError as e:
            # Modules don't exist yet or have errors
            # This is expected during initial setup
            pass

    @classmethod
    def register(cls, alt: AlternativeCommand):
        """
        Register an alternative command

        Args:
            alt: AlternativeCommand to register
        """
        # Store by ID
        cls._alternatives[alt.id] = alt

        # Index by category
        if alt.category not in cls._by_category:
            cls._by_category[alt.category] = []
        cls._by_category[alt.category].append(alt.id)

        # Index by task pattern (if specified)
        if alt.parent_task_pattern:
            if alt.parent_task_pattern not in cls._by_task_pattern:
                cls._by_task_pattern[alt.parent_task_pattern] = []
            cls._by_task_pattern[alt.parent_task_pattern].append(alt.id)

    @classmethod
    def get(cls, alt_id: str) -> Optional[AlternativeCommand]:
        """
        Get alternative by ID

        Args:
            alt_id: Alternative command ID

        Returns:
            AlternativeCommand or None
        """
        return cls._alternatives.get(alt_id)

    @classmethod
    def get_for_task(cls, task_id: str) -> List[AlternativeCommand]:
        """
        Get alternatives for a specific task using pattern matching

        Args:
            task_id: Task ID to match against parent_task_pattern

        Returns:
            List of matching AlternativeCommand objects
        """
        matches = []

        # Check each registered pattern
        for pattern, alt_ids in cls._by_task_pattern.items():
            # Use fnmatch for glob pattern matching
            if fnmatch.fnmatch(task_id, pattern):
                for alt_id in alt_ids:
                    alt = cls._alternatives.get(alt_id)
                    if alt:
                        matches.append(alt)

        return matches

    @classmethod
    def get_by_category(cls, category: str) -> List[AlternativeCommand]:
        """
        Get alternatives by category

        Args:
            category: Category name (e.g., 'web-enumeration')

        Returns:
            List of AlternativeCommand objects
        """
        alt_ids = cls._by_category.get(category, [])
        return [cls._alternatives[aid] for aid in alt_ids if aid in cls._alternatives]

    @classmethod
    def get_by_subcategory(cls, category: str, subcategory: str) -> List[AlternativeCommand]:
        """
        Get alternatives by category and subcategory

        Args:
            category: Category name
            subcategory: Subcategory name

        Returns:
            List of AlternativeCommand objects
        """
        category_alts = cls.get_by_category(category)
        return [alt for alt in category_alts if alt.subcategory == subcategory]

    @classmethod
    def list_all(cls) -> List[AlternativeCommand]:
        """
        Get all registered alternatives

        Returns:
            List of all AlternativeCommand objects
        """
        return list(cls._alternatives.values())

    @classmethod
    def list_categories(cls) -> List[str]:
        """
        Get list of all categories

        Returns:
            List of category names
        """
        return sorted(cls._by_category.keys())

    @classmethod
    def search(cls, query: str) -> List[AlternativeCommand]:
        """
        Search alternatives by name or description

        Args:
            query: Search query (case-insensitive)

        Returns:
            List of matching AlternativeCommand objects
        """
        query_lower = query.lower()
        matches = []

        for alt in cls._alternatives.values():
            # Search in name
            if query_lower in alt.name.lower():
                matches.append(alt)
                continue

            # Search in description
            if query_lower in alt.description.lower():
                matches.append(alt)
                continue

            # Search in tags
            if any(query_lower in tag.lower() for tag in alt.tags):
                matches.append(alt)
                continue

        return matches

    @classmethod
    def filter_by_tags(cls, tags: List[str]) -> List[AlternativeCommand]:
        """
        Filter alternatives by tags

        Args:
            tags: List of tags to match (ANY match, not ALL)

        Returns:
            List of AlternativeCommand objects with matching tags
        """
        matches = []
        tags_lower = [t.lower() for t in tags]

        for alt in cls._alternatives.values():
            alt_tags_lower = [t.lower() for t in alt.tags]
            if any(tag in alt_tags_lower for tag in tags_lower):
                matches.append(alt)

        return matches

    @classmethod
    def filter_by_os(cls, os_type: str) -> List[AlternativeCommand]:
        """
        Filter alternatives by OS type

        Args:
            os_type: 'linux', 'windows', or 'both'

        Returns:
            List of AlternativeCommand objects
        """
        return [
            alt for alt in cls._alternatives.values()
            if alt.os_type == os_type or alt.os_type == 'both'
        ]

    @classmethod
    def get_stats(cls) -> Dict[str, int]:
        """
        Get registry statistics

        Returns:
            Dictionary with counts
        """
        return {
            'total_alternatives': len(cls._alternatives),
            'total_categories': len(cls._by_category),
            'total_patterns': len(cls._by_task_pattern)
        }

    @classmethod
    def clear(cls):
        """Clear all registered alternatives (for testing)"""
        cls._alternatives.clear()
        cls._by_category.clear()
        cls._by_task_pattern.clear()
        cls._loaded = False
