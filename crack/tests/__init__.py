"""
CRACK Test Suite

Provides shared test infrastructure for all CRACK modules:
- Factories: Create test data with sensible defaults
- Assertions: Domain-specific assertion helpers
- Fixtures: Sample tool outputs for parser testing

Usage from test files:
    from tests.factories.credentials import CredentialFactory
    from tests.factories.neo4j import MockNeo4jDriver
    from tests.assertions import assert_credential_valid
"""
