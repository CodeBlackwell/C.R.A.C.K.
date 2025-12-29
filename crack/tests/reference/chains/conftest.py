"""
Shared fixtures and factories for reference/chains tests.

This module provides:
- ChainFactory: Create test chain definitions with sensible defaults
- SessionFactory: Create test session objects
- ParserResultFactory: Create test parsing results
- Mock command resolver for testing
- Temporary directory fixtures for file-based tests
"""

import json
import pytest
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch


# ==============================================================================
# Factories
# ==============================================================================


class ChainFactory:
    """Factory for creating test attack chain definitions."""

    _counter = 0

    @classmethod
    def create(
        cls,
        chain_id: str = None,
        name: str = None,
        description: str = None,
        version: str = "1.0.0",
        difficulty: str = "intermediate",
        time_estimate: str = "30 minutes",
        oscp_relevant: bool = True,
        steps: List[Dict[str, Any]] = None,
        metadata: Dict[str, Any] = None,
        prerequisites: List[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Create a valid attack chain definition with defaults.

        Override only what matters for your test.

        NOTE: Chain IDs must follow the schema pattern:
        ^[a-z0-9]+-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+$
        This requires exactly 4 hyphen-separated segments.
        """
        cls._counter += 1
        # FIX: Chain ID pattern requires 4 hyphen-separated segments
        # Old pattern: f"test-chain-{cls._counter:03d}" (only 3 segments)
        # New pattern: f"test-chain-{cls._counter:03d}-default" (4 segments)
        chain_id = chain_id or f"test-chain-{cls._counter:03d}-default"
        name = name or f"Test Chain {cls._counter}"

        default_metadata = {
            "author": "Test Author",
            "created": "2025-01-01",
            "updated": "2025-01-01",
            "tags": ["TEST", "OSCP:HIGH"],
            "category": "privilege_escalation",
        }
        if metadata:
            default_metadata.update(metadata)

        default_steps = steps or [
            cls.create_step(step_id="step-1", command_ref="test-command-1"),
        ]

        chain = {
            "id": chain_id,
            "name": name,
            "description": description or f"Test chain {chain_id} for unit testing",
            "version": version,
            "metadata": default_metadata,
            "difficulty": difficulty,
            "time_estimate": time_estimate,
            "oscp_relevant": oscp_relevant,
            "steps": default_steps,
        }

        if prerequisites:
            chain["prerequisites"] = prerequisites

        chain.update(kwargs)
        return chain

    @classmethod
    def create_step(
        cls,
        step_id: str = None,
        name: str = None,
        objective: str = None,
        command_ref: str = "test-command",
        dependencies: List[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Create a valid chain step with defaults."""
        step = {
            "name": name or f"Test Step {step_id or 'default'}",
            "objective": objective or "Test objective",
            "command_ref": command_ref,
        }
        if step_id:
            step["id"] = step_id
        if dependencies:
            step["dependencies"] = dependencies
        step.update(kwargs)
        return step

    @classmethod
    def create_with_circular_deps(cls) -> Dict[str, Any]:
        """Create a chain with circular step dependencies for testing."""
        # FIX: Chain ID must have 4 hyphen-separated segments
        return cls.create(
            chain_id="chain-with-circular-deps",
            steps=[
                cls.create_step(step_id="step-a", dependencies=["step-c"]),
                cls.create_step(step_id="step-b", dependencies=["step-a"]),
                cls.create_step(step_id="step-c", dependencies=["step-b"]),
            ],
        )

    @classmethod
    def create_with_missing_dependency(cls) -> Dict[str, Any]:
        """Create a chain with a step referencing undefined dependency."""
        # FIX: Chain ID must have 4 hyphen-separated segments
        return cls.create(
            chain_id="chain-missing-dep-test",
            steps=[
                cls.create_step(step_id="step-a", dependencies=["nonexistent-step"]),
            ],
        )

    @classmethod
    def create_minimal_valid(cls) -> Dict[str, Any]:
        """Create the most minimal valid chain."""
        # FIX: Chain ID must have 4 hyphen-separated segments
        return cls.create(chain_id="minimal-valid-chain-test")


class SessionFactory:
    """Factory for creating test ChainSession objects."""

    @classmethod
    def create(
        cls,
        chain_id: str = "test-chain",
        target: str = "192.168.1.100",
        current_step_index: int = 0,
        completed_steps: List[str] = None,
        variables: Dict[str, str] = None,
        step_outputs: Dict[str, str] = None,
        step_findings: Dict[str, Dict] = None,
        step_variables: Dict[str, Dict] = None,
    ):
        """Create a ChainSession with defaults - returns the actual class instance."""
        from reference.chains.session_storage import ChainSession

        session = ChainSession(chain_id, target)
        session.current_step_index = current_step_index
        session.completed_steps = completed_steps or []
        session.variables = variables or {}
        session.step_outputs = step_outputs or {}
        session.step_findings = step_findings or {}
        session.step_variables = step_variables or {}
        return session

    @classmethod
    def create_with_progress(
        cls, chain_id: str = "test-chain", target: str = "192.168.1.100"
    ):
        """Create a session with some progress already made."""
        return cls.create(
            chain_id=chain_id,
            target=target,
            current_step_index=2,
            completed_steps=["step-1", "step-2"],
            variables={"<TARGET>": target, "<USER>": "admin"},
            step_outputs={
                "step-1": "Success: Command output here",
                "step-2": "Found: Interesting findings",
            },
        )


class ParserResultFactory:
    """Factory for creating ParsingResult objects."""

    @classmethod
    def create(
        cls,
        parser_name: str = "test-parser",
        success: bool = True,
        findings: Dict[str, Any] = None,
        variables: Dict[str, str] = None,
        selection_required: Dict[str, List] = None,
        warnings: List[str] = None,
        activates_chains: List = None,
    ):
        """Create a ParsingResult with defaults."""
        from reference.chains.parsing.base import ParsingResult

        result = ParsingResult(parser_name=parser_name)
        result.success = success
        result.findings = findings or {}
        result.variables = variables or {}
        result.selection_required = selection_required or {}
        result.warnings = warnings or []
        if activates_chains:
            result.activates_chains = activates_chains
        return result


class MockCommandResolver:
    """Mock command resolver for testing chain validation."""

    def __init__(self, known_commands: List[str] = None):
        """Initialize with a list of known command IDs."""
        self.known_commands = set(known_commands or [])
        self._cache = {}

    def resolve_command_ref(self, ref_id: str):
        """Return a mock command if ID is known, None otherwise."""
        if ref_id in self.known_commands:
            return MagicMock(id=ref_id, name=f"Mock {ref_id}")
        return None

    def extract_command_refs(self, chain: Dict) -> List[str]:
        """Extract command refs from chain steps."""
        refs = []
        for step in chain.get("steps", []):
            if isinstance(step, dict) and step.get("command_ref"):
                refs.append(step["command_ref"])
        return refs

    def validate_references(self, references: List[str]) -> Dict[str, str]:
        """Return dict of missing references with error messages."""
        missing = {}
        for ref in references:
            if ref not in self.known_commands:
                missing[ref] = f"Command reference '{ref}' could not be resolved"
        return missing


# ==============================================================================
# Fixtures - Chain Loading
# ==============================================================================


@pytest.fixture
def temp_chain_dir(tmp_path):
    """Create a temporary directory for chain files."""
    chain_dir = tmp_path / "chains"
    chain_dir.mkdir()
    return chain_dir


@pytest.fixture
def sample_chain_file(temp_chain_dir):
    """Create a sample valid chain JSON file."""
    # FIX: Chain ID must have 4 hyphen-separated segments
    chain = ChainFactory.create(chain_id="sample-test-chain-file")
    filepath = temp_chain_dir / "sample-test-chain-file.json"
    filepath.write_text(json.dumps(chain, indent=2), encoding="utf-8")
    return filepath


@pytest.fixture
def invalid_json_file(temp_chain_dir):
    """Create a file with invalid JSON."""
    filepath = temp_chain_dir / "invalid.json"
    filepath.write_text("{ not valid json }", encoding="utf-8")
    return filepath


@pytest.fixture
def chain_with_invalid_schema(temp_chain_dir):
    """Create a chain file missing required fields."""
    chain = {"id": "missing-fields", "name": "Missing Fields"}
    # Missing: description, version, metadata, difficulty, time_estimate, oscp_relevant, steps
    filepath = temp_chain_dir / "invalid-schema.json"
    filepath.write_text(json.dumps(chain, indent=2), encoding="utf-8")
    return filepath


# ==============================================================================
# Fixtures - Registry
# ==============================================================================


@pytest.fixture
def empty_registry():
    """Create a fresh ChainRegistry instance (reset singleton)."""
    from reference.chains.registry import ChainRegistry

    # Reset the singleton
    ChainRegistry._instance = None
    registry = ChainRegistry()
    # Clear any leftover data
    registry._chains = {}
    registry._filter_cache = {}
    return registry


@pytest.fixture
def populated_registry(empty_registry):
    """Create a registry with some test chains."""
    registry = empty_registry
    # FIX: Chain IDs must have 4 hyphen-separated segments
    chains = [
        ChainFactory.create(
            chain_id="linux-privesc-sudo-test",
            metadata={"category": "privilege_escalation"},
            difficulty="beginner",
        ),
        ChainFactory.create(
            chain_id="linux-privesc-suid-test",
            metadata={"category": "privilege_escalation"},
            difficulty="intermediate",
        ),
        ChainFactory.create(
            chain_id="ad-kerberoast-test-chain",
            metadata={"category": "active_directory"},
            difficulty="advanced",
        ),
    ]
    for chain in chains:
        registry.register_chain(chain["id"], chain)
    return registry


# ==============================================================================
# Fixtures - Validator
# ==============================================================================


@pytest.fixture
def mock_command_resolver():
    """Create a mock command resolver with test commands."""
    return MockCommandResolver(
        known_commands=["test-command", "test-command-1", "check-sudo-privs"]
    )


@pytest.fixture
def chain_validator(mock_command_resolver):
    """Create a ChainValidator with mocked command resolver."""
    from reference.chains.validator import ChainValidator

    validator = ChainValidator(command_resolver=mock_command_resolver)
    return validator


# ==============================================================================
# Fixtures - Session Storage
# ==============================================================================


@pytest.fixture
def temp_session_dir(tmp_path, monkeypatch):
    """Create a temporary session directory and patch Path.home()."""
    session_dir = tmp_path / ".crack" / "chain_sessions"
    session_dir.mkdir(parents=True)

    # Patch Path.home() to return our temp dir's parent
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    return session_dir


@pytest.fixture
def sample_session():
    """Create a sample ChainSession for testing."""
    return SessionFactory.create()


@pytest.fixture
def session_with_progress():
    """Create a ChainSession with progress for testing."""
    return SessionFactory.create_with_progress()


# ==============================================================================
# Fixtures - Activation Manager
# ==============================================================================


@pytest.fixture
def activation_manager():
    """Create a fresh ActivationManager instance."""
    from reference.chains.activation_manager import ActivationManager

    return ActivationManager()


# ==============================================================================
# Fixtures - Parsers
# ==============================================================================


@pytest.fixture
def parser_registry_clean():
    """Create a clean parser registry (clear existing parsers)."""
    from reference.chains.parsing.registry import ParserRegistry

    ParserRegistry.clear()
    yield ParserRegistry
    ParserRegistry.clear()


@pytest.fixture
def sudo_output_nopasswd():
    """Sample sudo -l output with NOPASSWD entries."""
    return """
Matching Defaults entries for user on target:
    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

User user may run the following commands on target:
    (ALL) NOPASSWD: /usr/bin/find
    (ALL) NOPASSWD: /usr/bin/vim
    (root) /usr/bin/less
"""


@pytest.fixture
def sudo_output_all_nopasswd():
    """Sample sudo -l output with NOPASSWD ALL."""
    return """
Matching Defaults entries for user on target:
    env_reset, mail_badpass

User user may run the following commands on target:
    (ALL) NOPASSWD: ALL
"""


@pytest.fixture
def sudo_output_no_privs():
    """Sample sudo -l output with no useful privileges."""
    return """
Sorry, user may not run sudo on this host.
"""


@pytest.fixture
def suid_output_exploitable():
    """Sample SUID enumeration output with exploitable binaries."""
    return """
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/find
/usr/bin/vim.basic
/usr/bin/python3
/snap/core/snap-confine
"""


@pytest.fixture
def suid_output_standard_only():
    """Sample SUID output with only standard system binaries."""
    return """
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/su
/usr/bin/mount
/usr/bin/umount
/usr/bin/ping
"""


@pytest.fixture
def docker_groups_output():
    """Sample groups output showing docker membership."""
    return "kali docker sudo"


@pytest.fixture
def docker_id_output():
    """Sample id output showing docker membership."""
    return "uid=1000(kali) gid=1000(kali) groups=1000(kali),999(docker),27(sudo)"


@pytest.fixture
def docker_ps_output():
    """Sample docker ps output."""
    return """
CONTAINER ID   IMAGE     COMMAND   CREATED       STATUS       PORTS     NAMES
abc123def456   alpine    "sh"      2 hours ago   Up 2 hours             test_container
"""


@pytest.fixture
def docker_images_output():
    """Sample docker images output."""
    return """
REPOSITORY   TAG       IMAGE ID       CREATED       SIZE
alpine       latest    abc123def456   2 weeks ago   5.6MB
ubuntu       20.04     def456abc123   3 weeks ago   72.8MB
"""


@pytest.fixture
def capabilities_output_exploitable():
    """Sample getcap output with exploitable capabilities."""
    return """
/usr/bin/python3.8 = cap_setuid+ep
/usr/bin/vim.basic cap_dac_override=eip
/usr/bin/tar = cap_dac_read_search+ep
"""


@pytest.fixture
def capabilities_output_network_only():
    """Sample getcap output with only network capabilities (not exploitable)."""
    return """
/usr/bin/ping = cap_net_raw+ep
/usr/sbin/iftop = cap_net_admin+ep
"""


# ==============================================================================
# Fixtures - Variable Context
# ==============================================================================


@pytest.fixture
def mock_config_manager():
    """Create a mock ConfigManager for testing variable context."""
    mock = MagicMock()
    mock.placeholders = {
        "<TARGET>": "192.168.1.100",
        "<LHOST>": "10.10.14.5",
        "<LPORT>": "4444",
    }
    mock.get_placeholder = lambda key: mock.placeholders.get(key)
    return mock


@pytest.fixture
def variable_context(sample_session, mock_config_manager):
    """Create a VariableContext for testing."""
    from reference.chains.variables.context import VariableContext

    return VariableContext(sample_session, mock_config_manager)


# ==============================================================================
# Assertion Helpers
# ==============================================================================


class ChainAssertions:
    """Reusable assertion helpers for chain tests."""

    @staticmethod
    def assert_valid_chain(test_case, chain: Dict):
        """Assert chain has all required fields."""
        required = [
            "id",
            "name",
            "description",
            "version",
            "metadata",
            "difficulty",
            "time_estimate",
            "oscp_relevant",
            "steps",
        ]
        for field in required:
            assert field in chain, f"Chain missing required field: {field}"

    @staticmethod
    def assert_valid_step(test_case, step: Dict):
        """Assert step has all required fields."""
        required = ["name", "objective", "command_ref"]
        for field in required:
            assert field in step, f"Step missing required field: {field}"

    @staticmethod
    def assert_parser_success(result, min_findings: int = 0):
        """Assert parser result indicates success."""
        assert result.success, f"Parser failed: {result.warnings}"
        assert len(result.findings) >= min_findings, (
            f"Expected at least {min_findings} findings, got {len(result.findings)}"
        )

    @staticmethod
    def assert_parser_failure(result, expected_warning_substring: str = None):
        """Assert parser result indicates failure."""
        assert not result.success, "Expected parser to fail but it succeeded"
        if expected_warning_substring:
            warnings_text = " ".join(result.warnings)
            assert expected_warning_substring in warnings_text, (
                f"Expected warning containing '{expected_warning_substring}', "
                f"got: {result.warnings}"
            )


# Export assertions for use in tests
@pytest.fixture
def chain_assertions():
    """Provide assertion helpers to tests."""
    return ChainAssertions


# ==============================================================================
# Test Data Constants
# ==============================================================================


# Standard SUID binaries (should NOT be flagged as exploitable)
STANDARD_SUID_BINARIES = [
    "/usr/bin/passwd",
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/ping",
]

# Exploitable GTFOBins SUID binaries
EXPLOITABLE_SUID_BINARIES = [
    "/usr/bin/find",
    "/usr/bin/vim",
    "/usr/bin/python3",
    "/usr/bin/less",
    "/usr/bin/nmap",
]

# GTFOBins sudo binaries
GTFOBINS_SUDO_BINARIES = [
    "find",
    "vim",
    "python",
    "python3",
    "less",
    "nmap",
    "tar",
    "awk",
    "perl",
]

# Exploitable capabilities
EXPLOITABLE_CAPABILITIES = [
    "cap_setuid",
    "cap_setgid",
    "cap_dac_override",
    "cap_dac_read_search",
    "cap_sys_admin",
]
