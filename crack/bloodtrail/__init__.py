"""
BloodHound Trail - Edge Enhancement & Query Analysis

Dynamically populates missing Neo4j edges from BloodHound JSON exports,
enabling complete attack path discovery via Cypher queries.

Features:
  - Edge Enhancement: Import missing edges (AdminTo, GenericAll, MemberOf, etc.)
  - Query Library: 63+ pre-built Cypher queries for attack path discovery
  - Query Runner: Execute queries via CLI or programmatically
  - ZIP Support: Process SharpHound ZIP output directly (no extraction needed)

Credentials (for reference):
  - Neo4j:      neo4j / Neo4j123
  - BloodHound: admin / 1PlaySmarter*

Usage:
    # Edge enhancement from directory
    crack bloodtrail /path/to/bh/json/ --preset attack-paths

    # Edge enhancement from ZIP file (SharpHound output)
    crack bloodtrail /path/to/sharphound_output.zip --preset attack-paths

    # Query library
    crack bloodtrail --list-queries
    crack bloodtrail --run-query lateral-adminto-nonpriv
    crack bloodtrail --search-query DCSync
"""

__version__ = "1.2.0"
__author__ = "OSCP Study"

from .sid_resolver import SIDResolver
from .extractors import (
    ComputerEdgeExtractor,
    ACEExtractor,
    GroupMembershipExtractor,
)
from .main import BHEnhancer
from .query_runner import QueryRunner, Query, QueryResult
from .data_source import (
    DataSource,
    DirectoryDataSource,
    ZipDataSource,
    create_data_source,
    is_valid_bloodhound_source,
)

__all__ = [
    "SIDResolver",
    "ComputerEdgeExtractor",
    "ACEExtractor",
    "GroupMembershipExtractor",
    "BHEnhancer",
    "QueryRunner",
    "Query",
    "QueryResult",
    "DataSource",
    "DirectoryDataSource",
    "ZipDataSource",
    "create_data_source",
    "is_valid_bloodhound_source",
]
