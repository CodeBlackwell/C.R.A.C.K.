"""
Storage backends for the persistence layer.

- SQLiteStore: Raw blobs (stdout/stderr, file content)
- PersistenceNeo4jAdapter: Relationships and queryable metadata
- DualStore: Unified interface to both
"""

from .sqlite_store import SQLiteStore
from .dual_store import DualStore, get_store, reset_store

# Neo4j is optional
try:
    from .neo4j_store import PersistenceNeo4jAdapter
except ImportError:
    PersistenceNeo4jAdapter = None

__all__ = [
    "SQLiteStore",
    "DualStore",
    "get_store",
    "reset_store",
    "PersistenceNeo4jAdapter",
]
