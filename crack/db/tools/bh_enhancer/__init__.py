"""
BloodHound Edge Enhancement Utility

Dynamically populates missing Neo4j edges from BloodHound JSON exports,
enabling complete attack path discovery via Cypher queries.

Features:
  - Edge Enhancement: Import missing edges (AdminTo, GenericAll, MemberOf, etc.)
  - Query Library: 63+ pre-built Cypher queries for attack path discovery
  - Query Runner: Execute queries via CLI or programmatically

Credentials (for reference):
  - Neo4j:      neo4j / Neo4j123
  - BloodHound: admin / 1PlaySmarter*

Usage:
    # Edge enhancement
    python -m bh_enhancer /path/to/bh/json/ --preset attack-paths

    # Query library
    python -m bh_enhancer --list-queries
    python -m bh_enhancer --run-query lateral-adminto-nonpriv
    python -m bh_enhancer --search-query DCSync
"""

__version__ = "1.1.0"
__author__ = "OSCP Study"

from .sid_resolver import SIDResolver
from .extractors import (
    ComputerEdgeExtractor,
    ACEExtractor,
    GroupMembershipExtractor,
)
from .main import BHEnhancer
from .query_runner import QueryRunner, Query, QueryResult

__all__ = [
    "SIDResolver",
    "ComputerEdgeExtractor",
    "ACEExtractor",
    "GroupMembershipExtractor",
    "BHEnhancer",
    "QueryRunner",
    "Query",
    "QueryResult",
]
