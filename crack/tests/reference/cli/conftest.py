"""
Shared fixtures for Reference CLI tests

Provides isolated, reusable test components for all CLI test modules.
All fixtures are designed for parallel test execution safety.
"""

import pytest
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ==============================================================================
# FACTORY CLASSES
# ==============================================================================

class CommandFactory:
    """Factory for creating test Command objects with sensible defaults"""

    _counter = 0

    @classmethod
    def create(cls,
               id: str = None,
               name: str = None,
               category: str = "recon",
               subcategory: str = "",
               command: str = "nmap -p <PORT> <TARGET>",
               description: str = "Test command description",
               tags: list = None,
               oscp_relevance: str = "medium",
               variables: list = None,
               **kwargs):
        """Create Command with defaults. Override only what matters."""
        cls._counter += 1
        if id is None:
            id = f"test-command-{cls._counter}"
        if name is None:
            name = f"Test Command {cls._counter}"
        if tags is None:
            tags = ["TEST"]

        # Import here to avoid circular imports
        from crack.reference.core.registry import Command, CommandVariable

        # Create default variables if not provided
        if variables is None:
            variables = [
                CommandVariable(name="<PORT>", description="Target port", example="80"),
                CommandVariable(name="<TARGET>", description="Target IP", example="192.168.1.1")
            ]

        return Command(
            id=id,
            name=name,
            category=category,
            subcategory=subcategory,
            command=command,
            description=description,
            tags=tags,
            oscp_relevance=oscp_relevance,
            variables=variables,
            **kwargs
        )

    @classmethod
    def create_oscp_high(cls, **kwargs):
        """Create OSCP high-relevance command"""
        defaults = {
            "oscp_relevance": "high",
            "tags": ["OSCP:HIGH", "QUICK_WIN"]
        }
        defaults.update(kwargs)
        return cls.create(**defaults)

    @classmethod
    def create_quick_win(cls, **kwargs):
        """Create quick win command"""
        defaults = {
            "tags": ["QUICK_WIN"]
        }
        defaults.update(kwargs)
        return cls.create(**defaults)

    @classmethod
    def create_with_prerequisites(cls, prerequisites: list = None, **kwargs):
        """Create command with prerequisites"""
        if prerequisites is None:
            prerequisites = ["mkdir -p /tmp/output", "nc -lvnp <LPORT>"]
        return cls.create(prerequisites=prerequisites, **kwargs)


class ChainFactory:
    """Factory for creating test chain dictionaries"""

    _counter = 0

    @classmethod
    def create(cls,
               id: str = None,
               name: str = None,
               category: str = "enumeration",
               difficulty: str = "beginner",
               oscp_relevant: bool = True,
               steps: list = None,
               **kwargs) -> dict:
        """Create chain dictionary with defaults"""
        cls._counter += 1
        if id is None:
            id = f"test-chain-{cls._counter}"
        if name is None:
            name = f"Test Chain {cls._counter}"

        if steps is None:
            steps = [
                {
                    "name": "Step 1",
                    "objective": "Initial enumeration",
                    "command_ref": "nmap-full-tcp",
                    "description": "Scan all TCP ports"
                },
                {
                    "name": "Step 2",
                    "objective": "Service enumeration",
                    "command_ref": "nmap-service-scan",
                    "description": "Enumerate service versions"
                }
            ]

        return {
            "id": id,
            "name": name,
            "version": "1.0",
            "description": f"Test chain for {name}",
            "difficulty": difficulty,
            "oscp_relevant": oscp_relevant,
            "time_estimate": "15-30 minutes",
            "metadata": {
                "category": category,
                "platform": "linux",
                "tags": ["TEST", "ENUM"]
            },
            "prerequisites": ["Network access to target"],
            "steps": steps,
            **kwargs
        }


class ThemeFactory:
    """Factory for creating mock theme objects"""

    @classmethod
    def create_mock(cls) -> Mock:
        """Create mock theme that returns input as-is (no ANSI codes)"""
        theme = Mock()
        # Configure all theme methods to return input as-is
        for method in ['primary', 'secondary', 'success', 'error', 'warning',
                       'hint', 'muted', 'command_name', 'prompt', 'bold_white',
                       'info', 'notes_warning', 'notes_tip', 'notes_success',
                       'notes_failure', 'notes_section', 'notes_step', 'notes_code']:
            getattr(theme, method).side_effect = lambda x, m=method: x
        return theme


class ConfigFactory:
    """Factory for creating mock config managers"""

    @classmethod
    def create_mock(cls, variables: dict = None) -> Mock:
        """Create mock ConfigManager"""
        config = Mock()
        if variables is None:
            variables = {
                "LHOST": {"value": "10.10.14.5", "source": "manual"},
                "TARGET": {"value": "192.168.1.100", "source": "auto"},
                "LPORT": {"value": "4444", "source": "manual"}
            }

        config.list_variables.return_value = variables
        config.get_variable.side_effect = lambda k: variables.get(k, {}).get("value")
        config.set_variable.return_value = True
        config.clear_variables.return_value = True
        config.config_path = Path("/tmp/.crack/config.json")
        config.auto_detect_ip.return_value = "10.10.14.5"
        config.auto_detect_interface.return_value = "tun0"
        config.auto_configure.return_value = {"LHOST": "10.10.14.5", "INTERFACE": "tun0"}
        config.open_editor.return_value = True

        return config


class RegistryFactory:
    """Factory for creating mock registries"""

    @classmethod
    def create_mock(cls, commands: list = None) -> Mock:
        """Create mock registry with default commands"""
        registry = Mock()

        if commands is None:
            commands = [
                CommandFactory.create(id="nmap-full-tcp", name="Nmap Full TCP Scan",
                                      category="recon", tags=["OSCP:HIGH", "ENUM"]),
                CommandFactory.create(id="gobuster-dir", name="Gobuster Directory Scan",
                                      category="web", tags=["WEB", "ENUM"]),
                CommandFactory.create_oscp_high(id="bash-reverse-shell", name="Bash Reverse Shell",
                                                category="exploitation"),
                CommandFactory.create_quick_win(id="smb-enum-shares", name="SMB Share Enumeration",
                                                category="recon", tags=["SMB", "QUICK_WIN"])
            ]

        # Create commands dict
        commands_dict = {cmd.id: cmd for cmd in commands}
        registry.commands = commands_dict

        # Mock methods
        registry.get_command.side_effect = lambda id: commands_dict.get(id)
        registry.search.side_effect = lambda q: [
            cmd for cmd in commands if cmd.matches_search(q)
        ]
        registry.filter_by_category.side_effect = lambda cat, subcat=None: [
            cmd for cmd in commands
            if cmd.category == cat and (subcat is None or cmd.subcategory == subcat)
        ]
        registry.filter_by_tags.side_effect = lambda tags, exclude=None: [
            cmd for cmd in commands
            if all(t.upper() in [x.upper() for x in cmd.tags] for t in tags)
        ]
        registry.get_quick_wins.return_value = [
            cmd for cmd in commands if "QUICK_WIN" in cmd.tags
        ]
        registry.get_oscp_high.return_value = [
            cmd for cmd in commands
            if cmd.oscp_relevance == "high" or "OSCP:HIGH" in cmd.tags
        ]
        registry.get_subcategories.return_value = []
        registry.categories = {"recon": "01-recon", "web": "02-web", "exploitation": "03-exploitation"}
        registry.get_stats.return_value = {
            "total_commands": len(commands),
            "by_category": {"recon": 2, "web": 1, "exploitation": 1},
            "top_tags": [("OSCP:HIGH", 2), ("ENUM", 2)],
            "quick_wins": 1,
            "oscp_high": 2
        }
        registry.interactive_fill.side_effect = lambda cmd: cmd.command.replace(
            "<PORT>", "80").replace("<TARGET>", "192.168.1.1")

        return registry


# ==============================================================================
# PYTEST FIXTURES
# ==============================================================================

@pytest.fixture
def mock_theme():
    """Provide isolated mock theme"""
    return ThemeFactory.create_mock()


@pytest.fixture
def mock_config():
    """Provide isolated mock config manager"""
    return ConfigFactory.create_mock()


@pytest.fixture
def mock_registry():
    """Provide isolated mock registry with default commands"""
    return RegistryFactory.create_mock()


@pytest.fixture
def sample_commands():
    """Provide list of sample Command objects"""
    return [
        CommandFactory.create(id="nmap-full-tcp", name="Nmap Full TCP Scan",
                              category="recon", tags=["OSCP:HIGH", "ENUM"]),
        CommandFactory.create(id="gobuster-dir", name="Gobuster Directory Scan",
                              category="web", tags=["WEB", "ENUM"]),
        CommandFactory.create_oscp_high(id="bash-reverse-shell", name="Bash Reverse Shell",
                                        category="exploitation"),
        CommandFactory.create_quick_win(id="smb-enum-shares", name="SMB Share Enumeration",
                                        category="recon", tags=["SMB", "QUICK_WIN"])
    ]


@pytest.fixture
def sample_chains():
    """Provide list of sample chain dictionaries"""
    return [
        ChainFactory.create(id="linux-privesc-suid", name="Linux SUID Privilege Escalation",
                            category="privilege_escalation", difficulty="beginner"),
        ChainFactory.create(id="web-sqli-union", name="SQL Injection Union Attack",
                            category="web", difficulty="intermediate"),
        ChainFactory.create(id="ad-kerberoasting", name="Kerberoasting Attack Chain",
                            category="active_directory", difficulty="intermediate", oscp_relevant=True)
    ]


@pytest.fixture
def capture_stdout():
    """Capture stdout for testing print output"""
    class OutputCapture:
        def __init__(self):
            self.output = StringIO()
            self._patch = None

        def __enter__(self):
            self._patch = patch('sys.stdout', self.output)
            self._patch.__enter__()
            return self

        def __exit__(self, *args):
            self._patch.__exit__(*args)

        def getvalue(self):
            return self.output.getvalue()

        def contains(self, text):
            return text in self.output.getvalue()

    return OutputCapture


@pytest.fixture
def mock_input():
    """Mock input() for interactive tests"""
    class InputMocker:
        def __init__(self, responses: list = None):
            self.responses = responses or []
            self.call_count = 0
            self._patch = None

        def __call__(self, prompt=""):
            if self.call_count < len(self.responses):
                response = self.responses[self.call_count]
                self.call_count += 1
                return response
            raise EOFError("No more mock responses")

        def __enter__(self):
            self._patch = patch('builtins.input', self)
            self._patch.__enter__()
            return self

        def __exit__(self, *args):
            self._patch.__exit__(*args)

    return InputMocker


# ==============================================================================
# ASSERTION HELPERS
# ==============================================================================

class CLIAssertions:
    """Reusable assertion helpers for CLI tests"""

    @staticmethod
    def assert_exit_code(result, expected: int, msg: str = None):
        """Assert CLI returned expected exit code"""
        if msg is None:
            msg = f"Expected exit code {expected}, got {result}"
        assert result == expected, msg

    @staticmethod
    def assert_output_contains(output: str, expected: str, msg: str = None):
        """Assert output contains expected text"""
        if msg is None:
            msg = f"Expected output to contain '{expected}'"
        assert expected in output, f"{msg}\nActual output: {output[:500]}"

    @staticmethod
    def assert_output_not_contains(output: str, unexpected: str, msg: str = None):
        """Assert output does not contain unexpected text"""
        if msg is None:
            msg = f"Expected output to NOT contain '{unexpected}'"
        assert unexpected not in output, f"{msg}\nActual output: {output[:500]}"

    @staticmethod
    def assert_command_displayed(output: str, command_id: str):
        """Assert a command was displayed in output"""
        assert command_id in output, f"Command '{command_id}' not found in output"

    @staticmethod
    def assert_error_displayed(output: str):
        """Assert an error indicator was displayed"""
        error_indicators = ["Error", "error", "failed", "Failed", "not found"]
        assert any(ind in output for ind in error_indicators), \
            f"Expected error message in output, got: {output[:500]}"
