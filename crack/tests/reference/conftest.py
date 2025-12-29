"""
Reference Test Configuration

Provides fixtures for Reference system tests:
- CommandFactory for creating test commands
- Isolated registry instances
- Mock backends for integration testing

Business Value Focus:
- Test isolation (no state leakage between tests)
- Realistic test data (matches actual command schema)
- Performance (reuse fixtures where safe)
"""

import pytest
import tempfile
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


# =============================================================================
# Command Factory
# =============================================================================

class CommandFactory:
    """
    Factory for creating test Command objects with sensible defaults.

    BV: Consistent command creation across all reference tests.
    Reduces boilerplate while maintaining realistic test data.
    """

    _counter = 0
    _lock = None  # For thread safety if needed

    @classmethod
    def reset(cls):
        """Reset counter for deterministic test output."""
        cls._counter = 0

    @classmethod
    def create(
        cls,
        id: str = None,
        name: str = None,
        category: str = "recon",
        command: str = "echo 'test'",
        description: str = "Test command",
        subcategory: str = "",
        tags: List[str] = None,
        variables: List[Dict[str, Any]] = None,
        oscp_relevance: str = "medium",
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create command dict with defaults. Override only what matters.

        Returns dict (not Command dataclass) for JSON fixture compatibility.
        """
        cls._counter += 1
        return {
            "id": id or f"test-cmd-{cls._counter}",
            "name": name or f"Test Command {cls._counter}",
            "category": category,
            "command": command,
            "description": description,
            "subcategory": subcategory,
            "tags": tags or [],
            "variables": variables or [],
            "oscp_relevance": oscp_relevance,
            **kwargs
        }

    @classmethod
    def create_with_placeholders(
        cls,
        placeholders: List[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create command with placeholder variables.

        Args:
            placeholders: List of placeholder names (e.g., ["<TARGET>", "<PORT>"])
        """
        placeholders = placeholders or ["<TARGET>"]
        command_text = "test " + " ".join(placeholders)
        variables = [
            {
                "name": p,
                "description": f"Description for {p}",
                "example": f"example_{p.strip('<>').lower()}",
                "required": True
            }
            for p in placeholders
        ]
        return cls.create(
            command=command_text,
            variables=variables,
            **kwargs
        )

    @classmethod
    def create_nmap(cls, **kwargs) -> Dict[str, Any]:
        """Create realistic nmap command."""
        return cls.create(
            id=kwargs.pop("id", "nmap-tcp-scan"),
            name=kwargs.pop("name", "Nmap TCP Scan"),
            category="recon",
            command="sudo nmap -sT -sV -Pn -v -p <PORTS> <TARGET>",
            description="TCP connect scan with version detection",
            tags=["NMAP", "RECON", "OSCP:HIGH"],
            variables=[
                {"name": "<TARGET>", "description": "Target IP", "example": "192.168.1.100", "required": True},
                {"name": "<PORTS>", "description": "Port range", "example": "1-1000", "required": True}
            ],
            oscp_relevance="high",
            **kwargs
        )

    @classmethod
    def create_tgs_rep(cls, **kwargs) -> Dict[str, Any]:
        """Create TGS-REP roasting command (for punctuation tests)."""
        return cls.create(
            id="kerberoast-tgs-rep",
            name="TGS-REP Kerberoasting",
            category="post-exploit",
            command="impacket-GetUserSPNs <DOMAIN>/<USER>:<PASSWORD> -dc-ip <DC_IP>",
            description="Extract TGS-REP hashes for offline cracking",
            tags=["KERBEROS", "TGS-REP", "AD", "OSCP:HIGH"],
            variables=[
                {"name": "<DOMAIN>", "description": "AD domain", "example": "CORP.LOCAL", "required": True},
                {"name": "<USER>", "description": "Username", "example": "admin", "required": True},
                {"name": "<PASSWORD>", "description": "Password", "example": "Password123", "required": True},
                {"name": "<DC_IP>", "description": "Domain controller IP", "example": "192.168.1.1", "required": True}
            ],
            oscp_relevance="high",
            **kwargs
        )

    @classmethod
    def create_quick_win(cls, **kwargs) -> Dict[str, Any]:
        """Create QUICK_WIN tagged command."""
        return cls.create(
            id=kwargs.pop("id", "quick-win-cmd"),
            tags=["QUICK_WIN", "OSCP:HIGH"],
            oscp_relevance="high",
            **kwargs
        )

    @classmethod
    def create_batch(cls, count: int, **common_kwargs) -> List[Dict[str, Any]]:
        """Create multiple commands with optional shared properties."""
        return [cls.create(**common_kwargs) for _ in range(count)]


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def command_factory():
    """
    Factory for creating test commands.

    BV: Consistent command creation with sensible defaults.

    Usage:
        def test_something(command_factory):
            cmd = command_factory.create(name="My Command")
    """
    CommandFactory.reset()
    return CommandFactory


@pytest.fixture
def sample_commands(command_factory) -> List[Dict[str, Any]]:
    """
    Pre-built collection of sample commands for common test scenarios.

    BV: Reduces boilerplate when tests need variety of command types.
    """
    return [
        command_factory.create_nmap(),
        command_factory.create_tgs_rep(),
        command_factory.create_quick_win(id="quick-enum", name="Quick Enumeration"),
        command_factory.create(
            id="web-scan",
            name="Web Scanner",
            category="web",
            tags=["WEB", "RECON"],
            oscp_relevance="medium"
        ),
        command_factory.create(
            id="linux-privesc",
            name="Linux Privilege Escalation",
            category="post-exploit",
            subcategory="privesc",
            tags=["LINUX", "PRIVESC", "OSCP:HIGH"],
            oscp_relevance="high"
        ),
    ]


@pytest.fixture
def temp_commands_dir(tmp_path) -> Path:
    """
    Create temporary directory structure for command JSON files.

    BV: Isolated file-based tests don't pollute real data.
    """
    commands_dir = tmp_path / "db" / "data" / "commands"
    commands_dir.mkdir(parents=True)
    return commands_dir


@pytest.fixture
def json_registry_with_commands(tmp_path, sample_commands):
    """
    Create HybridCommandRegistry with sample commands loaded from JSON.

    BV: Tests registry loading behavior with realistic data.
    """
    # Create the commands directory structure
    commands_dir = tmp_path / "db" / "data" / "commands"
    commands_dir.mkdir(parents=True)

    # Write sample commands to JSON file
    recon_file = commands_dir / "recon.json"
    post_file = commands_dir / "post-exploit.json"
    web_file = commands_dir / "web.json"

    recon_cmds = [c for c in sample_commands if c["category"] == "recon"]
    post_cmds = [c for c in sample_commands if c["category"] == "post-exploit"]
    web_cmds = [c for c in sample_commands if c["category"] == "web"]

    if recon_cmds:
        recon_file.write_text(json.dumps({"category": "recon", "commands": recon_cmds}))
    if post_cmds:
        post_file.write_text(json.dumps({"category": "post-exploit", "commands": post_cmds}))
    if web_cmds:
        web_file.write_text(json.dumps({"category": "web", "commands": web_cmds}))

    # Create registry pointing to temp directory (base_path should be tmp_path)
    from reference.core.registry import HybridCommandRegistry
    registry = HybridCommandRegistry(base_path=tmp_path)

    return registry


@pytest.fixture
def empty_registry(tmp_path):
    """
    Create HybridCommandRegistry with no commands.

    BV: Tests edge cases with empty registry.
    """
    commands_dir = tmp_path / "db" / "data" / "commands"
    commands_dir.mkdir(parents=True)

    from reference.core.registry import HybridCommandRegistry
    return HybridCommandRegistry(base_path=tmp_path)


@pytest.fixture
def placeholder_engine():
    """
    Fresh PlaceholderEngine instance.

    BV: Isolated placeholder tests with clean state.
    """
    from reference.core.placeholder import PlaceholderEngine
    return PlaceholderEngine(config_manager=None)


@pytest.fixture
def mock_config_manager():
    """
    Mock ConfigManager with preset values.

    BV: Tests config integration without file system.
    """
    from unittest.mock import Mock

    mock_config = Mock()
    mock_config.get_placeholder_values.return_value = {
        "<TARGET>": "192.168.1.100",
        "<LHOST>": "10.10.14.5",
        "<LPORT>": "4444"
    }
    mock_config.get.side_effect = lambda key, default=None: {
        "<TARGET>": "192.168.1.100",
        "<LHOST>": "10.10.14.5",
        "<LPORT>": "4444"
    }.get(key, default)

    return mock_config


# =============================================================================
# Assertion Helpers
# =============================================================================

class ReferenceAssertions:
    """
    Reusable assertion helpers for Reference tests.

    BV: Consistent assertion patterns with clear error messages.
    """

    @staticmethod
    def assert_command_has_field(test_case, cmd, field_name: str, expected_value=None):
        """Assert command has field with optional value check."""
        assert hasattr(cmd, field_name), f"Command missing field: {field_name}"
        if expected_value is not None:
            actual = getattr(cmd, field_name)
            assert actual == expected_value, (
                f"Command.{field_name} mismatch: expected {expected_value}, got {actual}"
            )

    @staticmethod
    def assert_search_returns_command(results: list, command_id: str):
        """Assert search results contain specific command."""
        ids = [r.id for r in results]
        assert command_id in ids, (
            f"Expected command '{command_id}' in results, got: {ids}"
        )

    @staticmethod
    def assert_search_excludes_command(results: list, command_id: str):
        """Assert search results do not contain specific command."""
        ids = [r.id for r in results]
        assert command_id not in ids, (
            f"Command '{command_id}' should not be in results, but found in: {ids}"
        )

    @staticmethod
    def assert_placeholder_filled(filled_cmd: str, placeholder: str):
        """Assert placeholder is not present in filled command."""
        assert placeholder not in filled_cmd, (
            f"Placeholder '{placeholder}' should be filled, but found in: {filled_cmd}"
        )

    @staticmethod
    def assert_placeholder_present(cmd_text: str, placeholder: str):
        """Assert placeholder is present in command text."""
        assert placeholder in cmd_text, (
            f"Placeholder '{placeholder}' expected but not found in: {cmd_text}"
        )


@pytest.fixture
def assertions():
    """Reference-specific assertion helpers."""
    return ReferenceAssertions
