"""
BloodHound Trail - Edge Enhancement & Query Analysis

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
    crack blood-trail /path/to/bh/json/ --preset attack-paths

    # Query library
    crack blood-trail --list-queries
    crack blood-trail --run-query lateral-adminto-nonpriv
    crack blood-trail --search-query DCSync
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
