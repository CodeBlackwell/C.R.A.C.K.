"""
Test Factories Package

Provides factory classes for creating test data with sensible defaults.
Follows the Factory pattern for DRY test data creation.

Available Factories:
- CredentialFactory: Create PRISM Credential objects
- MockNeo4jDriver: Create mock Neo4j driver with configurable responses

Design Principles:
- Factories provide sensible defaults (override only what matters)
- Thread-safe counter for unique IDs
- Reset methods for deterministic test output
- Type-specific factory methods (create_cleartext, create_machine_account)
"""

from .credentials import CredentialFactory
from .neo4j import MockNeo4jDriver, MockNeo4jSession, MockNeo4jResult, MockNeo4jTransaction

__all__ = [
    "CredentialFactory",
    "MockNeo4jDriver",
    "MockNeo4jSession",
    "MockNeo4jResult",
    "MockNeo4jTransaction",
]
