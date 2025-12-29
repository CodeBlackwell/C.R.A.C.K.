"""
Root pytest configuration for CRACK test suite.

Provides shared fixtures for:
- Neo4j mock driver (session-scoped for performance)
- Temporary directories for file-based tests
- Test isolation via autouse fixtures
- Common test utilities

Business Value Focus:
- Fixtures ensure test isolation (no state leakage between tests)
- Session-scoped Neo4j mocks reduce test setup overhead
- Autouse fixtures guarantee clean state for parallel execution
"""

import os
import sys
import pytest
import tempfile
from pathlib import Path
from typing import Generator, Dict, Any, List, Optional
from unittest.mock import Mock, MagicMock

# Ensure crack package is importable from tests
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# =============================================================================
# Session-Scoped Fixtures (Expensive to create, shared across all tests)
# =============================================================================

@pytest.fixture(scope="session")
def project_root() -> Path:
    """
    Absolute path to the CRACK project root.

    BV: Tests can reliably locate project resources regardless of cwd.
    """
    return PROJECT_ROOT


@pytest.fixture(scope="session")
def sample_outputs_dir(project_root: Path) -> Path:
    """
    Path to sample tool output fixtures.

    BV: Centralized location for all sample outputs ensures consistency.
    """
    return project_root / "tests" / "fixtures" / "sample_outputs"


@pytest.fixture(scope="session")
def mock_neo4j_driver_factory():
    """
    Factory for creating mock Neo4j drivers with configurable responses.

    BV: Neo4j tests don't require live database, enabling CI/CD execution.

    Usage:
        def test_something(mock_neo4j_driver_factory):
            driver = mock_neo4j_driver_factory(records=[{"name": "test"}])
    """
    from tests.factories.neo4j import MockNeo4jDriver

    def _factory(
        records: List[Dict[str, Any]] = None,
        should_fail: bool = False,
        failure_exception: Exception = None
    ) -> 'MockNeo4jDriver':
        return MockNeo4jDriver(
            records=records or [],
            should_fail=should_fail,
            failure_exception=failure_exception
        )

    return _factory


# =============================================================================
# Function-Scoped Fixtures (Fresh per test)
# =============================================================================

@pytest.fixture
def tmp_test_dir(tmp_path: Path) -> Path:
    """
    Temporary directory for test file operations.

    BV: File-based tests are isolated and don't pollute filesystem.

    Note: pytest's tmp_path is already unique per test; this fixture
    provides a semantic alias for clarity.
    """
    return tmp_path


@pytest.fixture
def mock_file_content(tmp_test_dir: Path):
    """
    Factory fixture to create temporary files with specified content.

    BV: Tests can create file fixtures without manual cleanup.

    Usage:
        def test_parser(mock_file_content):
            filepath = mock_file_content("output.txt", "some content")
            result = parser.parse(filepath)
    """
    created_files: List[Path] = []

    def _factory(filename: str, content: str, encoding: str = "utf-8") -> Path:
        filepath = tmp_test_dir / filename
        filepath.write_text(content, encoding=encoding)
        created_files.append(filepath)
        return filepath

    yield _factory

    # Cleanup is automatic via tmp_path, but we track for debugging
    # No explicit cleanup needed - pytest handles tmp_path lifecycle


@pytest.fixture
def mock_neo4j_session():
    """
    Fresh mock Neo4j session for each test.

    BV: Each test gets isolated session state for assertions.
    """
    from tests.factories.neo4j import MockNeo4jSession
    return MockNeo4jSession(records=[])


# =============================================================================
# Autouse Fixtures (Run automatically for test isolation)
# =============================================================================

@pytest.fixture(autouse=True)
def reset_singletons():
    """
    Reset any global singletons before each test.

    BV: Prevents state leakage between tests, enabling parallel execution.

    Note: Add new singleton resets here as modules are added.
    """
    # Reset PRISM parser registry if imported
    try:
        from tools.post.prism.parsers.registry import PrismParserRegistry
        PrismParserRegistry.clear()
    except (ImportError, AttributeError):
        pass

    yield

    # Post-test cleanup (if needed)
    try:
        from tools.post.prism.parsers.registry import PrismParserRegistry
        PrismParserRegistry.clear()
    except (ImportError, AttributeError):
        pass


@pytest.fixture(autouse=True)
def isolate_environment(monkeypatch):
    """
    Isolate environment variables for each test.

    BV: Tests don't accidentally depend on or modify real environment.

    Sets safe defaults for common environment variables used by CRACK.
    """
    # Prevent tests from using real Neo4j connection
    monkeypatch.setenv("NEO4J_URI", "bolt://test-mock:7687")
    monkeypatch.setenv("NEO4J_USER", "test_user")
    monkeypatch.setenv("NEO4J_PASSWORD", "test_password")

    # Prevent config file side effects
    monkeypatch.setenv("CRACK_CONFIG_DIR", str(Path(tempfile.gettempdir()) / "crack_test_config"))

    yield


# =============================================================================
# Credential Factory Integration
# =============================================================================

@pytest.fixture
def credential_factory():
    """
    Factory for creating test credentials.

    BV: Consistent credential creation across all test modules.

    Usage:
        def test_dedup(credential_factory):
            cred1 = credential_factory.create(username="admin")
            cred2 = credential_factory.create_cleartext(password="secret")
    """
    from tests.factories.credentials import CredentialFactory
    # Reset counter for deterministic test output
    CredentialFactory.reset()
    return CredentialFactory


@pytest.fixture
def sample_credentials(credential_factory):
    """
    Pre-built collection of sample credentials for common test scenarios.

    BV: Reduces boilerplate when tests need variety of credential types.

    Returns dict with keys:
        - admin_ntlm: Admin user with NTLM hash
        - user_cleartext: Regular user with cleartext password
        - machine_account: DC01$ machine account
        - service_account: SYSTEM service account
        - high_value: Cleartext admin credential (high_value=True)
    """
    return {
        "admin_ntlm": credential_factory.create(
            username="administrator",
            domain="CORP",
            value="aad3b435b51404eeaad3b435b51404ee"
        ),
        "user_cleartext": credential_factory.create_cleartext(
            username="jsmith",
            domain="CORP",
            password="Password123!"
        ),
        "machine_account": credential_factory.create_machine_account(
            name="DC01$",
            domain="CORP"
        ),
        "service_account": credential_factory.create(
            username="LOCAL SERVICE",
            domain="NT AUTHORITY"
        ),
        "high_value": credential_factory.create_cleartext(
            username="admin",
            domain="CORP",
            password="SuperSecret!"
        ),
    }


# =============================================================================
# Neo4j Testing Utilities
# =============================================================================

@pytest.fixture
def mock_neo4j_connection(mock_neo4j_driver_factory, monkeypatch):
    """
    Patches Neo4j GraphDatabase.driver to return mock driver.

    BV: Tests can verify Neo4j interactions without live database.

    Returns the mock driver for assertion access.
    """
    driver = mock_neo4j_driver_factory(records=[])

    mock_graph_db = Mock()
    mock_graph_db.driver.return_value = driver

    monkeypatch.setattr("neo4j.GraphDatabase", mock_graph_db)

    return driver


# =============================================================================
# Assertion Helper Integration
# =============================================================================

@pytest.fixture
def assertions():
    """
    Collection of domain-specific assertion helpers.

    BV: Consistent assertion patterns with clear error messages.

    Usage:
        def test_cred_valid(assertions, credential_factory):
            cred = credential_factory.create()
            assertions.assert_credential_valid(cred)
    """
    from tests.assertions import CrackAssertions
    return CrackAssertions


# =============================================================================
# Pytest Configuration
# =============================================================================

def pytest_configure(config):
    """
    Register custom markers for test categorization.
    """
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests requiring external services"
    )
    config.addinivalue_line(
        "markers", "neo4j: marks tests that interact with Neo4j"
    )
    config.addinivalue_line(
        "markers", "prism: marks PRISM parser tests"
    )
    config.addinivalue_line(
        "markers", "bloodtrail: marks BloodTrail tests"
    )
    config.addinivalue_line(
        "markers", "reference: marks Reference system tests"
    )


def pytest_collection_modifyitems(config, items):
    """
    Auto-mark tests based on path for easy filtering.
    """
    for item in items:
        # Add markers based on test path
        if "prism" in str(item.fspath):
            item.add_marker(pytest.mark.prism)
        if "bloodtrail" in str(item.fspath):
            item.add_marker(pytest.mark.bloodtrail)
        if "reference" in str(item.fspath):
            item.add_marker(pytest.mark.reference)
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
