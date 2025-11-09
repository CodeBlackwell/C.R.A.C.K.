"""
Neo4j data pipeline schema module.

Provides unified schema definitions for both data extraction and import stages.
"""

from .shared_schema import (
    BaseSpec,
    NodeSpec,
    RelationshipSpec,
    SchemaDefinition
)
from .schema_loader import SchemaRegistry, SchemaLoadError

__all__ = [
    'BaseSpec',
    'NodeSpec',
    'RelationshipSpec',
    'SchemaDefinition',
    'SchemaRegistry',
    'SchemaLoadError',
]
