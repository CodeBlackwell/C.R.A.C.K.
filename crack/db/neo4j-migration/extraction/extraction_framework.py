"""
Generic extraction framework for Neo4j data transformation.

This module provides base classes and utilities to reduce repetitive extraction logic
by 80%+ through reusable patterns and declarative configuration.
"""

from typing import List, Dict, Any, Set, Optional, Tuple, Callable
from dataclasses import dataclass, field
import hashlib


@dataclass
class ExtractionContext:
    """
    Shared context for extraction operations.

    Tracks deduplication, ID generation, and error collection across extractors.
    """
    seen_ids: Set[str] = field(default_factory=set)
    id_counter: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def generate_id(self, text: str) -> str:
        """Generate consistent hash-based ID from text"""
        return hashlib.md5(text.encode()).hexdigest()[:16]

    def next_id(self, prefix: str = "entity") -> str:
        """Generate sequential ID with prefix"""
        self.id_counter += 1
        return f"{prefix}_{self.id_counter}"

    def is_seen(self, entity_id: str) -> bool:
        """Check if ID has been seen (for deduplication)"""
        return entity_id in self.seen_ids

    def mark_seen(self, entity_id: str):
        """Mark ID as seen"""
        self.seen_ids.add(entity_id)

    def add_error(self, message: str):
        """Record an error"""
        self.errors.append(message)

    def add_warning(self, message: str):
        """Record a warning"""
        self.warnings.append(message)


class EntityExtractor:
    """
    Base class for entity extraction.

    Provides common patterns:
    - Source data iteration with ID validation
    - Deduplication tracking
    - Error collection
    - Standard extraction interface

    Subclasses override extract_* methods to implement specific extraction logic.
    """

    def __init__(self, context: Optional[ExtractionContext] = None):
        """
        Initialize extractor with shared context.

        Args:
            context: Shared extraction context for deduplication and error tracking.
                    If None, creates new context.
        """
        self.context = context or ExtractionContext()

    def validate_source_id(self, source: Dict[str, Any], id_field: str = 'id') -> Optional[str]:
        """
        Validate that source dict has required ID field.

        Args:
            source: Source dictionary
            id_field: Name of ID field to check (default: 'id')

        Returns:
            ID value if valid, None if missing
        """
        entity_id = source.get(id_field)
        if not entity_id:
            self.context.add_warning(f"Missing {id_field} in source: {source.get('name', 'unknown')}")
            return None
        return entity_id

    def extract_nodes(self, sources: List[Dict], id_field: str = 'id') -> List[Dict]:
        """
        Extract node entities from source data.

        Args:
            sources: List of source dictionaries
            id_field: Field name to use as ID

        Returns:
            List of node dictionaries with all required fields
        """
        raise NotImplementedError("Subclass must implement extract_nodes()")

    def extract_relationships(self, sources: List[Dict], id_field: str = 'id') -> List[Dict]:
        """
        Extract relationship entities from source data.

        Args:
            sources: List of source dictionaries
            id_field: Field name to use as source ID

        Returns:
            List of relationship dictionaries with start/end IDs
        """
        raise NotImplementedError("Subclass must implement extract_relationships()")


class NodeRelationshipExtractor(EntityExtractor):
    """
    Extractor that produces both nodes and relationships.

    Common pattern for extractors like variables, flags, indicators that create:
    1. Unique entity nodes (deduplicated)
    2. Relationships from commands to those nodes
    """

    def extract(self, sources: List[Dict], id_field: str = 'id') -> Tuple[List[Dict], List[Dict]]:
        """
        Extract both nodes and relationships.

        Args:
            sources: List of source dictionaries (typically commands)
            id_field: Field name for source ID

        Returns:
            Tuple of (nodes, relationships)
        """
        nodes = self.extract_nodes(sources, id_field)
        relationships = self.extract_relationships(sources, id_field)
        return nodes, relationships


class SimpleNodeExtractor(EntityExtractor):
    """
    Extractor for simple 1:1 node transformation.

    Use when each source dict maps directly to a single output node.
    Example: Commands, AttackChains
    """

    def __init__(self, field_mapping: Dict[str, str], context: Optional[ExtractionContext] = None):
        """
        Initialize with field mapping configuration.

        Args:
            field_mapping: Dict mapping output field -> source field
            context: Shared extraction context
        """
        super().__init__(context)
        self.field_mapping = field_mapping

    def extract_nodes(self, sources: List[Dict], id_field: str = 'id') -> List[Dict]:
        """
        Extract nodes by applying field mapping to each source.

        Args:
            sources: List of source dictionaries
            id_field: Field name to use as ID

        Returns:
            List of node dictionaries
        """
        nodes = []

        for source in sources:
            # Validate ID
            entity_id = self.validate_source_id(source, id_field)
            if not entity_id:
                continue

            # Apply field mapping
            node = {}
            for output_field, source_field in self.field_mapping.items():
                # Handle nested field access with dot notation
                value = self._get_nested_field(source, source_field)
                node[output_field] = value if value is not None else ''

            nodes.append(node)

        return nodes

    def _get_nested_field(self, source: Dict, field_path: str) -> Any:
        """
        Get field value supporting nested access.

        Args:
            source: Source dictionary
            field_path: Field path (e.g., 'metadata.version')

        Returns:
            Field value or None if not found
        """
        if '.' not in field_path:
            return source.get(field_path)

        # Handle nested access
        parts = field_path.split('.')
        value = source
        for part in parts:
            if not isinstance(value, dict):
                return None
            value = value.get(part)
            if value is None:
                return None
        return value

    def extract_relationships(self, sources: List[Dict], id_field: str = 'id') -> List[Dict]:
        """SimpleNodeExtractor does not extract relationships"""
        return []


class TagExtractor(EntityExtractor):
    """
    Specialized extractor for tags.

    Tags require special handling:
    - Deduplication across multiple sources (commands, chains)
    - Extraction from both direct tags and nested tag lists
    """

    def extract_unique_tags(self, commands: List[Dict], chains: List[Dict]) -> List[Dict]:
        """
        Extract unique tags from commands and chains.

        Args:
            commands: List of command dicts
            chains: List of chain dicts

        Returns:
            List of unique tag dicts with {name, category}
        """
        tags = []
        seen_tags = set()

        # Extract from commands
        for cmd in commands:
            for tag in cmd.get('tags', []):
                tag_name = tag if isinstance(tag, str) else tag.get('name')
                if tag_name and tag_name not in seen_tags:
                    tags.append({
                        'name': tag_name,
                        'category': tag.get('category', '') if isinstance(tag, dict) else ''
                    })
                    seen_tags.add(tag_name)

        # Extract from chains
        for chain in chains:
            for tag in chain.get('tags', []):
                tag_name = tag if isinstance(tag, str) else tag.get('name')
                if tag_name and tag_name not in seen_tags:
                    tags.append({
                        'name': tag_name,
                        'category': tag.get('category', '') if isinstance(tag, dict) else ''
                    })
                    seen_tags.add(tag_name)

        return tags

    def extract_nodes(self, sources: List[Dict], id_field: str = 'id') -> List[Dict]:
        """Not used - tags use extract_unique_tags instead"""
        return []

    def extract_relationships(self, sources: List[Dict], id_field: str = 'id') -> List[Dict]:
        """Not used - tag relationships extracted separately"""
        return []


# Utility functions

def generate_id(text: str) -> str:
    """Generate consistent hash-based ID from text"""
    return hashlib.md5(text.encode()).hexdigest()[:16]


def safe_get(source: Dict, key: str, default: Any = '') -> Any:
    """Safely get value from dict with default"""
    value = source.get(key)
    return value if value is not None else default


def join_list(items: List[str], separator: str = '|') -> str:
    """Join list items into delimited string"""
    if not items:
        return ''
    return separator.join(str(item) for item in items)
