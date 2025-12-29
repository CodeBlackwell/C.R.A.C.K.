"""
Tests for Reference CLI chains.py - Attack chain management commands

Business Value Focus:
- Users need to find and execute attack chains
- Chain search must be intuitive and fast
- Interactive execution guides users through attacks
- Format options support different use cases
"""

import pytest
import sys
import json
from pathlib import Path
from io import StringIO
from unittest.mock import Mock, patch, MagicMock

# Add project root
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tests.reference.cli.conftest import (
    ChainFactory, ThemeFactory, CommandFactory, CLIAssertions
)


class TestChainsCLIInitialization:
    """Tests for ChainsCLI initialization"""

    def test_initialization_with_defaults(self):
        """
        BV: ChainsCLI initializes with default loader and registry

        Scenario:
          Given: No custom loader/registry
          When: ChainsCLI is instantiated
          Then: Default loader and registry are created
        """
        from crack.reference.cli.chains import ChainsCLI

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(theme=mock_theme)

        assert chains_cli.loader is not None
        assert chains_cli.registry is not None
        assert chains_cli.resolver is not None

    def test_initialization_with_custom_dependencies(self):
        """
        BV: ChainsCLI accepts custom loader and registry

        Scenario:
          Given: Custom loader and registry
          When: ChainsCLI is instantiated
          Then: Custom dependencies are used
        """
        from crack.reference.cli.chains import ChainsCLI

        mock_loader = Mock()
        mock_registry = Mock()
        mock_resolver = Mock()
        mock_theme = ThemeFactory.create_mock()

        chains_cli = ChainsCLI(
            chain_loader=mock_loader,
            chain_registry=mock_registry,
            command_resolver=mock_resolver,
            theme=mock_theme
        )

        assert chains_cli.loader == mock_loader
        assert chains_cli.registry == mock_registry
        assert chains_cli.resolver == mock_resolver

    def test_lazy_loading_on_first_access(self):
        """
        BV: Chains are loaded lazily for faster startup

        Scenario:
          Given: ChainsCLI instance
          When: No chain operations performed
          Then: Chains are not loaded yet
        """
        from crack.reference.cli.chains import ChainsCLI

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(theme=mock_theme)

        assert chains_cli._loaded is False


class TestListOrShow:
    """Tests for list_or_show unified handler"""

    def test_list_all_chains_no_query(self):
        """
        BV: No query lists all chains

        Scenario:
          Given: ChainsCLI with chains loaded
          When: list_or_show() is called with no query
          Then: All chains are listed
        """
        from crack.reference.cli.chains import ChainsCLI

        chains = [
            ChainFactory.create(id="chain-1", name="Chain One"),
            ChainFactory.create(id="chain-2", name="Chain Two")
        ]

        mock_registry = Mock()
        mock_registry.filter_chains.return_value = chains
        mock_registry.get_chain.return_value = None

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(chain_registry=mock_registry, theme=mock_theme)
        chains_cli._loaded = True

        output = StringIO()
        with patch('sys.stdout', output):
            result = chains_cli.list_or_show(query=None)

        assert result == 0
        output_text = output.getvalue()
        assert 'chain-1' in output_text
        assert 'chain-2' in output_text

    def test_show_specific_chain_by_id(self):
        """
        BV: Exact chain ID shows full details

        Scenario:
          Given: ChainsCLI with chain
          When: list_or_show() is called with exact ID
          Then: Chain details are displayed
        """
        from crack.reference.cli.chains import ChainsCLI

        chain = ChainFactory.create(id="linux-privesc-suid", name="Linux SUID Escalation")

        mock_registry = Mock()
        mock_registry.get_chain.return_value = chain

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(chain_registry=mock_registry, theme=mock_theme)
        chains_cli._loaded = True

        output = StringIO()
        with patch('sys.stdout', output):
            result = chains_cli.list_or_show(query="linux-privesc-suid")

        assert result == 0
        output_text = output.getvalue()
        assert 'linux-privesc-suid' in output_text
        assert 'Linux SUID Escalation' in output_text

    def test_search_chains_by_keyword(self):
        """
        BV: Keyword search finds matching chains

        Scenario:
          Given: ChainsCLI with chains
          When: list_or_show() is called with keyword
          Then: Matching chains are shown
        """
        from crack.reference.cli.chains import ChainsCLI

        chains = [
            ChainFactory.create(id="sqli-1", name="SQL Injection Basic",
                                category="web"),
            ChainFactory.create(id="sqli-2", name="SQL Injection Advanced",
                                category="web")
        ]

        mock_registry = Mock()
        mock_registry.get_chain.return_value = None  # Not exact match
        mock_registry.filter_chains.return_value = chains

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(chain_registry=mock_registry, theme=mock_theme)
        chains_cli._loaded = True

        output = StringIO()
        with patch('sys.stdout', output):
            result = chains_cli.list_or_show(query="sqli")

        assert result == 0
        output_text = output.getvalue()
        assert 'sqli-1' in output_text or 'SQL Injection' in output_text

    def test_numeric_selection_from_results(self):
        """
        BV: Numeric suffix selects chain from results

        Scenario:
          Given: ChainsCLI with chains
          When: list_or_show() is called with "sqli 1"
          Then: First matching chain is shown in detail
        """
        from crack.reference.cli.chains import ChainsCLI

        chains = [
            ChainFactory.create(id="sqli-1", name="SQL Injection Basic"),
            ChainFactory.create(id="sqli-2", name="SQL Injection Advanced")
        ]

        mock_registry = Mock()
        mock_registry.get_chain.side_effect = lambda x: chains[0] if x == "sqli-1" else None
        mock_registry.filter_chains.return_value = chains

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(chain_registry=mock_registry, theme=mock_theme)
        chains_cli._loaded = True

        output = StringIO()
        with patch('sys.stdout', output):
            result = chains_cli.list_or_show(query="sqli 1")

        assert result == 0
        # Should show details of first chain
        output_text = output.getvalue()
        assert 'sqli-1' in output_text or 'SQL Injection' in output_text

    def test_invalid_selection_number(self):
        """
        BV: Invalid selection shows clear error

        Scenario:
          Given: ChainsCLI with 2 chains
          When: list_or_show() is called with "sqli 5"
          Then: Error about invalid selection
        """
        from crack.reference.cli.chains import ChainsCLI

        chains = [
            ChainFactory.create(id="sqli-1"),
            ChainFactory.create(id="sqli-2")
        ]

        mock_registry = Mock()
        mock_registry.get_chain.return_value = None
        mock_registry.filter_chains.return_value = chains

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(chain_registry=mock_registry, theme=mock_theme)
        chains_cli._loaded = True

        output = StringIO()
        with patch('sys.stdout', output):
            result = chains_cli.list_or_show(query="sqli 5")

        assert result == 1
        assert 'Invalid selection' in output.getvalue()

    def test_no_results_found(self):
        """
        BV: No results shows clear message

        Scenario:
          Given: ChainsCLI
          When: list_or_show() is called with non-matching query
          Then: "No chains found" message
        """
        from crack.reference.cli.chains import ChainsCLI

        mock_registry = Mock()
        mock_registry.get_chain.return_value = None
        mock_registry.filter_chains.return_value = []

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(chain_registry=mock_registry, theme=mock_theme)
        chains_cli._loaded = True

        output = StringIO()
        with patch('sys.stdout', output):
            result = chains_cli.list_or_show(query="nonexistent")

        assert result == 0
        assert 'No' in output.getvalue() and 'found' in output.getvalue()


class TestChainList:
    """Tests for list command"""

    def test_list_filter_by_category(self):
        """
        BV: List filters by category

        Scenario:
          Given: Chains in different categories
          When: list() is called with category filter
          Then: Only matching chains are shown
        """
        from crack.reference.cli.chains import ChainsCLI

        chains = [
            ChainFactory.create(id="privesc-1", category="privilege_escalation")
        ]

        mock_registry = Mock()
        mock_registry.filter_chains.return_value = chains

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(chain_registry=mock_registry, theme=mock_theme)
        chains_cli._loaded = True

        output = StringIO()
        with patch('sys.stdout', output):
            result = chains_cli.list(category="privilege_escalation")

        assert result == 0
        mock_registry.filter_chains.assert_called_once()

    def test_list_filter_by_platform(self):
        """
        BV: List filters by platform

        Scenario:
          Given: Chains for different platforms
          When: list() is called with platform filter
          Then: Only matching chains are shown
        """
        from crack.reference.cli.chains import ChainsCLI

        chains = [
            ChainFactory.create(id="linux-1")
        ]

        mock_registry = Mock()
        mock_registry.filter_chains.return_value = chains

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(chain_registry=mock_registry, theme=mock_theme)
        chains_cli._loaded = True

        result = chains_cli.list(platform="linux")

        assert result == 0

    def test_list_filter_by_difficulty(self):
        """
        BV: List filters by difficulty level

        Scenario:
          Given: Chains with different difficulties
          When: list() is called with difficulty filter
          Then: Only matching chains are shown
        """
        from crack.reference.cli.chains import ChainsCLI

        chains = [
            ChainFactory.create(id="easy-1", difficulty="beginner")
        ]

        mock_registry = Mock()
        mock_registry.filter_chains.return_value = chains

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(chain_registry=mock_registry, theme=mock_theme)
        chains_cli._loaded = True

        result = chains_cli.list(difficulty="beginner")

        assert result == 0

    def test_list_filter_oscp_relevant(self):
        """
        BV: List filters OSCP-relevant chains

        Scenario:
          Given: Mix of OSCP and non-OSCP chains
          When: list() is called with oscp_relevant=True
          Then: Only OSCP chains are shown
        """
        from crack.reference.cli.chains import ChainsCLI

        chains = [
            ChainFactory.create(id="oscp-1", oscp_relevant=True)
        ]

        mock_registry = Mock()
        mock_registry.filter_chains.return_value = chains

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(chain_registry=mock_registry, theme=mock_theme)
        chains_cli._loaded = True

        result = chains_cli.list(oscp_relevant=True)

        assert result == 0


class TestChainShow:
    """Tests for show command"""

    def test_show_displays_chain_details(self):
        """
        BV: Show displays full chain information

        Scenario:
          Given: Chain with all fields
          When: show() is called
          Then: All details are displayed
        """
        from crack.reference.cli.chains import ChainsCLI

        chain = ChainFactory.create(
            id="test-chain",
            name="Test Chain",
            difficulty="intermediate",
            steps=[
                {"name": "Step 1", "objective": "Enum", "command_ref": "nmap-full-tcp"}
            ]
        )

        mock_registry = Mock()
        mock_registry.get_chain.return_value = chain

        mock_resolver = Mock()
        mock_resolver.resolve_command_ref.return_value = None

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(
            chain_registry=mock_registry,
            command_resolver=mock_resolver,
            theme=mock_theme
        )
        chains_cli._loaded = True

        output = StringIO()
        with patch('sys.stdout', output):
            result = chains_cli.show("test-chain")

        assert result == 0
        output_text = output.getvalue()
        assert 'test-chain' in output_text
        assert 'Test Chain' in output_text
        assert 'Step 1' in output_text

    def test_show_not_found(self):
        """
        BV: Show error for non-existent chain

        Scenario:
          Given: Chain ID that doesn't exist
          When: show() is called
          Then: Error message and non-zero exit
        """
        from crack.reference.cli.chains import ChainsCLI

        mock_registry = Mock()
        mock_registry.get_chain.return_value = None

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(chain_registry=mock_registry, theme=mock_theme)
        chains_cli._loaded = True

        output = StringIO()
        with patch('sys.stdout', output):
            result = chains_cli.show("nonexistent")

        assert result == 1
        assert 'not found' in output.getvalue()

    def test_show_resolves_command_refs(self):
        """
        BV: Show resolves command references to raw commands

        Scenario:
          Given: Chain with command_ref in steps
          When: show() is called
          Then: Raw commands are displayed
        """
        from crack.reference.cli.chains import ChainsCLI

        chain = ChainFactory.create(
            id="test-chain",
            steps=[
                {"name": "Step 1", "objective": "Enum", "command_ref": "nmap-full-tcp"}
            ]
        )

        mock_registry = Mock()
        mock_registry.get_chain.return_value = chain

        mock_cmd = Mock()
        mock_cmd.command = "nmap -p- -T4 <TARGET>"

        mock_resolver = Mock()
        mock_resolver.resolve_command_ref.return_value = mock_cmd

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(
            chain_registry=mock_registry,
            command_resolver=mock_resolver,
            theme=mock_theme
        )
        chains_cli._loaded = True

        output = StringIO()
        with patch('sys.stdout', output):
            chains_cli.show("test-chain")

        output_text = output.getvalue()
        assert 'nmap -p-' in output_text or 'Raw Command' in output_text


class TestJsonFormat:
    """Tests for JSON format output"""

    def test_list_json_format(self):
        """
        BV: JSON format produces valid JSON

        Scenario:
          Given: Chains to list
          When: list() is called with format='json'
          Then: Valid JSON is output
        """
        from crack.reference.cli.chains import ChainsCLI

        chains = [
            ChainFactory.create(id="chain-1"),
            ChainFactory.create(id="chain-2")
        ]

        mock_registry = Mock()
        mock_registry.filter_chains.return_value = chains

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(chain_registry=mock_registry, theme=mock_theme)
        chains_cli._loaded = True

        output = StringIO()
        with patch('sys.stdout', output):
            chains_cli.list(format='json')

        result = output.getvalue()
        parsed = json.loads(result)  # Should not raise
        assert isinstance(parsed, list)
        assert len(parsed) == 2

    def test_show_json_format(self):
        """
        BV: Show JSON format for scripting

        Scenario:
          Given: Chain to show
          When: show() is called with format='json'
          Then: Valid JSON is output
        """
        from crack.reference.cli.chains import ChainsCLI

        chain = ChainFactory.create(id="test-chain")

        mock_registry = Mock()
        mock_registry.get_chain.return_value = chain

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(chain_registry=mock_registry, theme=mock_theme)
        chains_cli._loaded = True

        output = StringIO()
        with patch('sys.stdout', output):
            chains_cli.show("test-chain", format='json')

        result = output.getvalue()
        parsed = json.loads(result)
        assert parsed['id'] == 'test-chain'


class TestValidate:
    """Tests for validate command"""

    def test_validate_success(self):
        """
        BV: Validate confirms valid chains

        Scenario:
          Given: Valid chain files
          When: validate() is called
          Then: Success message and zero exit
        """
        from crack.reference.cli.chains import ChainsCLI

        chains = {"chain-1": ChainFactory.create(id="chain-1")}

        mock_loader = Mock()
        mock_loader.load_all_chains.return_value = chains

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(chain_loader=mock_loader, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            result = chains_cli.validate()

        assert result == 0
        assert 'Successfully validated' in output.getvalue()

    def test_validate_failure(self):
        """
        BV: Validate reports errors

        Scenario:
          Given: Invalid chain files
          When: validate() is called
          Then: Error message and non-zero exit
        """
        from crack.reference.cli.chains import ChainsCLI

        mock_loader = Mock()
        mock_loader.load_all_chains.side_effect = ValueError("Invalid chain format")

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(chain_loader=mock_loader, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            result = chains_cli.validate()

        assert result == 1
        assert 'failed' in output.getvalue().lower() or 'error' in output.getvalue().lower()


class TestInteractiveExecution:
    """Tests for execute_interactive command"""

    def test_execute_interactive_launches_executor(self):
        """
        BV: Interactive mode launches chain executor

        Scenario:
          Given: Valid chain ID
          When: execute_interactive() is called
          Then: ChainInteractive is launched
        """
        from crack.reference.cli.chains import ChainsCLI

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(theme=mock_theme)

        # FIX: ChainInteractive is imported inside the execute_interactive method,
        # not at module level. Must patch the source module.
        with patch('crack.reference.chains.interactive.ChainInteractive') as mock_interactive:
            mock_executor = Mock()
            mock_interactive.return_value = mock_executor

            result = chains_cli.execute_interactive("test-chain", target="192.168.1.1")

            mock_interactive.assert_called_once_with("test-chain", "192.168.1.1", False)
            mock_executor.run.assert_called_once()
            assert result == 0

    def test_execute_interactive_handles_invalid_chain(self):
        """
        BV: Invalid chain shows error

        Scenario:
          Given: Invalid chain ID
          When: execute_interactive() is called
          Then: Error message and non-zero exit
        """
        from crack.reference.cli.chains import ChainsCLI

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(theme=mock_theme)

        # FIX: ChainInteractive is imported inside the execute_interactive method,
        # not at module level. Must patch the source module.
        with patch('crack.reference.chains.interactive.ChainInteractive') as mock_interactive:
            mock_interactive.side_effect = ValueError("Chain not found")

            output = StringIO()
            with patch('sys.stdout', output):
                result = chains_cli.execute_interactive("nonexistent")

            assert result == 1
            assert 'Chain not found' in output.getvalue()

    def test_execute_interactive_handles_keyboard_interrupt(self):
        """
        BV: Ctrl+C gracefully exits

        Scenario:
          Given: Interactive execution
          When: User presses Ctrl+C
          Then: Graceful exit with non-zero code
        """
        from crack.reference.cli.chains import ChainsCLI

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(theme=mock_theme)

        # FIX: ChainInteractive is imported inside the execute_interactive method,
        # not at module level. Must patch the source module.
        with patch('crack.reference.chains.interactive.ChainInteractive') as mock_interactive:
            mock_executor = Mock()
            mock_executor.run.side_effect = KeyboardInterrupt()
            mock_interactive.return_value = mock_executor

            output = StringIO()
            with patch('sys.stdout', output):
                result = chains_cli.execute_interactive("test-chain")

            assert result == 1
            assert 'Interrupted' in output.getvalue()

    def test_execute_interactive_resume_session(self):
        """
        BV: Resume flag continues from saved session

        Scenario:
          Given: Previous session exists
          When: execute_interactive() is called with resume=True
          Then: ChainInteractive is called with resume flag
        """
        from crack.reference.cli.chains import ChainsCLI

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(theme=mock_theme)

        # FIX: ChainInteractive is imported inside the execute_interactive method,
        # not at module level. Must patch the source module.
        with patch('crack.reference.chains.interactive.ChainInteractive') as mock_interactive:
            mock_executor = Mock()
            mock_interactive.return_value = mock_executor

            chains_cli.execute_interactive("test-chain", resume=True)

            # Third argument should be True for resume
            mock_interactive.assert_called_once_with("test-chain", None, True)


class TestSearchChains:
    """Tests for _search_chains helper method"""

    def test_search_in_chain_id(self):
        """
        BV: Search finds matches in chain ID

        Scenario:
          Given: Chain with matching ID
          When: _search_chains() is called
          Then: Chain is found
        """
        from crack.reference.cli.chains import ChainsCLI

        chains = [
            ChainFactory.create(id="linux-privesc-suid", name="SUID Escalation")
        ]

        mock_registry = Mock()
        mock_registry.filter_chains.return_value = chains

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(chain_registry=mock_registry, theme=mock_theme)
        chains_cli._loaded = True

        results = chains_cli._search_chains("privesc")

        assert len(results) == 1
        assert results[0]['id'] == 'linux-privesc-suid'

    def test_search_in_chain_name(self):
        """
        BV: Search finds matches in chain name

        Scenario:
          Given: Chain with matching name
          When: _search_chains() is called
          Then: Chain is found
        """
        from crack.reference.cli.chains import ChainsCLI

        # FIX: ChainFactory.create() uses chain_id, not id
        # Also chain_id must have 4 hyphen-separated segments
        # FIX: Search query must be substring of chain name - "kerberoast" matches "Kerberoasting"
        chains = [
            ChainFactory.create(chain_id="chain-1-kerb-attack", name="Kerberoasting Attack")
        ]

        mock_registry = Mock()
        mock_registry.filter_chains.return_value = chains

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(chain_registry=mock_registry, theme=mock_theme)
        chains_cli._loaded = True

        results = chains_cli._search_chains("kerberoast")

        assert len(results) == 1

    def test_search_in_chain_tags(self):
        """
        BV: Search finds matches in chain tags

        Scenario:
          Given: Chain with matching tag
          When: _search_chains() is called
          Then: Chain is found
        """
        from crack.reference.cli.chains import ChainsCLI

        chain = ChainFactory.create(id="chain-1")
        chain['metadata']['tags'] = ["ACTIVE_DIRECTORY", "KERBEROS"]
        chains = [chain]

        mock_registry = Mock()
        mock_registry.filter_chains.return_value = chains

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(chain_registry=mock_registry, theme=mock_theme)
        chains_cli._loaded = True

        results = chains_cli._search_chains("kerberos")

        assert len(results) == 1

    def test_search_case_insensitive(self):
        """
        BV: Search is case-insensitive

        Scenario:
          Given: Chain with mixed-case name
          When: _search_chains() is called with lowercase
          Then: Chain is found
        """
        from crack.reference.cli.chains import ChainsCLI

        chains = [
            ChainFactory.create(id="chain-1", name="SQLI Union Attack")
        ]

        mock_registry = Mock()
        mock_registry.filter_chains.return_value = chains

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(chain_registry=mock_registry, theme=mock_theme)
        chains_cli._loaded = True

        results = chains_cli._search_chains("sqli")

        assert len(results) == 1


class TestChainListFormatting:
    """Tests for chain list text formatting"""

    def test_list_shows_numbering(self):
        """
        BV: List shows numbers for easy selection

        Scenario:
          Given: Multiple chains
          When: Listed in text format
          Then: Numbers are displayed
        """
        from crack.reference.cli.chains import ChainsCLI

        chains = [
            ChainFactory.create(id="chain-1"),
            ChainFactory.create(id="chain-2")
        ]

        mock_registry = Mock()
        mock_registry.filter_chains.return_value = chains

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(chain_registry=mock_registry, theme=mock_theme)
        chains_cli._loaded = True

        output = StringIO()
        with patch('sys.stdout', output):
            chains_cli.list(format='text')

        output_text = output.getvalue()
        assert '1.' in output_text
        assert '2.' in output_text

    def test_list_shows_metadata(self):
        """
        BV: List shows relevant metadata

        Scenario:
          Given: Chains with metadata
          When: Listed in text format
          Then: Category, difficulty, time estimate shown
        """
        from crack.reference.cli.chains import ChainsCLI

        chains = [
            ChainFactory.create(
                id="chain-1",
                category="privilege_escalation",
                difficulty="intermediate"
            )
        ]

        mock_registry = Mock()
        mock_registry.filter_chains.return_value = chains

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(chain_registry=mock_registry, theme=mock_theme)
        chains_cli._loaded = True

        output = StringIO()
        with patch('sys.stdout', output):
            chains_cli.list(format='text')

        output_text = output.getvalue()
        assert 'privilege_escalation' in output_text or 'intermediate' in output_text

    def test_list_shows_oscp_indicator(self):
        """
        BV: List highlights OSCP-relevant chains

        Scenario:
          Given: OSCP-relevant chain
          When: Listed in text format
          Then: OSCP indicator is shown
        """
        from crack.reference.cli.chains import ChainsCLI

        chains = [
            ChainFactory.create(id="chain-1", oscp_relevant=True)
        ]

        mock_registry = Mock()
        mock_registry.filter_chains.return_value = chains

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(chain_registry=mock_registry, theme=mock_theme)
        chains_cli._loaded = True

        output = StringIO()
        with patch('sys.stdout', output):
            chains_cli.list(format='text')

        output_text = output.getvalue()
        assert 'OSCP' in output_text


class TestChainDetailsFormatting:
    """Tests for chain details text formatting"""

    def test_details_shows_prerequisites(self):
        """
        BV: Details show prerequisites

        Scenario:
          Given: Chain with prerequisites
          When: Shown in text format
          Then: Prerequisites are listed
        """
        from crack.reference.cli.chains import ChainsCLI

        chain = ChainFactory.create(
            id="chain-1",
            prerequisites=["Network access", "Valid credentials"]
        )
        chain['prerequisites'] = ["Network access", "Valid credentials"]

        mock_registry = Mock()
        mock_registry.get_chain.return_value = chain

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(chain_registry=mock_registry, theme=mock_theme)
        chains_cli._loaded = True

        output = StringIO()
        with patch('sys.stdout', output):
            chains_cli.show("chain-1")

        output_text = output.getvalue()
        assert 'Prerequisites' in output_text
        assert 'Network access' in output_text

    def test_details_shows_all_steps(self):
        """
        BV: Details show all attack steps

        Scenario:
          Given: Chain with multiple steps
          When: Shown in text format
          Then: All steps are listed with details
        """
        from crack.reference.cli.chains import ChainsCLI

        chain = ChainFactory.create(
            id="chain-1",
            steps=[
                {"name": "Enumeration", "objective": "Discover services", "command_ref": "nmap-full-tcp"},
                {"name": "Exploitation", "objective": "Gain access", "command_ref": "exploit-x"}
            ]
        )

        mock_registry = Mock()
        mock_registry.get_chain.return_value = chain

        mock_resolver = Mock()
        mock_resolver.resolve_command_ref.return_value = None

        mock_theme = ThemeFactory.create_mock()
        chains_cli = ChainsCLI(
            chain_registry=mock_registry,
            command_resolver=mock_resolver,
            theme=mock_theme
        )
        chains_cli._loaded = True

        output = StringIO()
        with patch('sys.stdout', output):
            chains_cli.show("chain-1")

        output_text = output.getvalue()
        assert '1.' in output_text
        assert '2.' in output_text
        assert 'Enumeration' in output_text
        assert 'Exploitation' in output_text
