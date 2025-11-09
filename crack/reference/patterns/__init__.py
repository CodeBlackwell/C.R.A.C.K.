"""
Advanced query pattern library for Neo4j adapter

Provides pre-built implementations of the 10 advanced query patterns
from db/neo4j-migration/06-ADVANCED-QUERIES.md
"""

from .advanced_queries import GraphQueryPatterns, create_pattern_helper

__all__ = ['GraphQueryPatterns', 'create_pattern_helper']
