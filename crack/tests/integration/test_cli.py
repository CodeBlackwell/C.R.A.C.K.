#!/usr/bin/env python3
"""
Integration tests for CLI command routing
Tests the main CLI interface and subcommand execution
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
from io import StringIO

from crack.cli import main, print_banner


class TestCLI:
    """Test CLI functionality"""


    @pytest.mark.integration
    def test_help_display(self):
        """Test help text display"""
        with patch('sys.argv', ['crack', '--help']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    @pytest.mark.integration
    def test_version_display(self):
        """Test version display"""
        with patch('sys.argv', ['crack', '--version']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    @pytest.mark.integration
    def test_no_banner_flag(self, capsys):
        """Test --no-banner flag suppresses banner"""
        with patch('sys.argv', ['crack', '--no-banner', 'enum-scan', '192.168.45.100']):
            with patch('crack.network.enum_scan.main'):
                main()

        captured = capsys.readouterr()
        # Banner should not appear (check for ASCII art characters)
        assert "░▒▓" not in captured.out
        assert "(C)omprehensive" not in captured.out

    @pytest.mark.integration
    def test_enum_scan_command_routing(self):
        """Test enum-scan subcommand routing"""
        with patch('sys.argv', ['crack', 'enum-scan', '192.168.45.100']):
            with patch('crack.network.enum_scan.main') as mock_enum_scan:
                main()
                mock_enum_scan.assert_called_once()

    @pytest.mark.integration
    def test_html_enum_command_routing(self):
        """Test html-enum subcommand routing"""
        with patch('sys.argv', ['crack', 'html-enum', 'http://test.com']):
            with patch('crack.web.html_enum.main') as mock_html_enum:
                main()
                mock_html_enum.assert_called_once()

    @pytest.mark.integration
    def test_param_discover_command_routing(self):
        """Test param-discover subcommand routing"""
        with patch('sys.argv', ['crack', 'param-discover', 'http://test.com/page.php']):
            with patch('crack.web.param_discover.main') as mock_param_discover:
                main()
                mock_param_discover.assert_called_once()

    @pytest.mark.integration
    def test_param_extract_command_routing(self):
        """Test param-extract subcommand routing"""
        with patch('sys.argv', ['crack', 'param-extract', 'http://test.com/form.aspx']):
            with patch('crack.web.param_extract.main') as mock_param_extract:
                main()
                mock_param_extract.assert_called_once()

    @pytest.mark.integration
    def test_sqli_scan_command_routing(self):
        """Test sqli-scan subcommand routing"""
        with patch('sys.argv', ['crack', 'sqli-scan', 'http://test.com/page.php?id=1']):
            with patch('crack.sqli.sqli_scanner.main') as mock_sqli_scan:
                main()
                mock_sqli_scan.assert_called_once()

    @pytest.mark.integration
    def test_sqli_fu_command_routing(self):
        """Test sqli-fu subcommand routing"""
        with patch('sys.argv', ['crack', 'sqli-fu', 'mysql']):
            with patch('crack.sqli.reference.main') as mock_sqli_fu:
                main()
                mock_sqli_fu.assert_called_once()

    @pytest.mark.integration
    def test_no_command_shows_help(self, capsys):
        """Test that running without subcommand shows help"""
        with patch('sys.argv', ['crack']):
            main()

        captured = capsys.readouterr()
        # Should display help and banner
        assert "AVAILABLE TOOLS" in captured.out or "usage:" in captured.out

    @pytest.mark.integration
    def test_invalid_command(self):
        """Test invalid subcommand handling"""
        with patch('sys.argv', ['crack', 'nonexistent-command']):
            with pytest.raises(SystemExit):
                main()

    @pytest.mark.integration
    def test_argument_passthrough(self):
        """Test that tool-specific arguments are passed through"""
        test_args = ['--full', '-o', '/tmp/output', '--verbose']

        with patch('sys.argv', ['crack', 'enum-scan', '192.168.45.100'] + test_args):
            with patch('crack.network.enum_scan.main') as mock_enum_scan:
                main()

                # sys.argv should be modified to pass args to the tool
                import sys
                # The tool's main() will see modified sys.argv
                mock_enum_scan.assert_called_once()

    @pytest.mark.integration
    def test_multiple_flags_combination(self):
        """Test combining global and tool-specific flags"""
        with patch('sys.argv', ['crack', '--no-banner', 'sqli-scan', 'http://test.com', '--verbose']):
            with patch('crack.sqli.sqli_scanner.main') as mock_sqli:
                main()
                mock_sqli.assert_called_once()

    @pytest.mark.integration
    @pytest.mark.fast
    def test_subcommand_help(self):
        """Test that each subcommand can show its own help"""
        subcommands = [
            'enum-scan',
            'html-enum',
            'param-discover',
            'param-extract',
            'sqli-scan',
            'sqli-fu'
        ]

        for subcommand in subcommands:
            module_path = {
                'enum-scan': 'crack.network.enum_scan',
                'html-enum': 'crack.web.html_enum',
                'param-discover': 'crack.web.param_discover',
                'param-extract': 'crack.web.param_extract',
                'sqli-scan': 'crack.sqli.sqli_scanner',
                'sqli-fu': 'crack.sqli.reference'
            }[subcommand]

            with patch('sys.argv', ['crack', subcommand, '--help']):
                with patch(f'{module_path}.main') as mock_main:
                    # The main function should be called even with --help
                    # because we pass through the args
                    main()
                    mock_main.assert_called_once()


class TestCLIIntegrationWithModules:
    """Test CLI integration with actual module imports"""

    @pytest.mark.integration
    def test_import_all_modules(self):
        """Test that all modules can be imported"""
        modules = [
            'crack.network.enum_scan',
            'crack.network.port_scanner',
            'crack.network.parallel_enumerator',
            'crack.web.html_enum',
            'crack.web.param_discover',
            'crack.web.param_extract',
            'crack.sqli.scanner',
            'crack.sqli.techniques',
            'crack.sqli.reference',
            'crack.exploit.cve_lookup',
            'crack.utils.colors',
            'crack.utils.curl_parser'
        ]

        for module_name in modules:
            try:
                __import__(module_name)
            except ImportError as e:
                pytest.fail(f"Failed to import {module_name}: {e}")

    @pytest.mark.integration
    def test_cli_module_connections(self):
        """Test that CLI properly connects to all modules"""
        from crack import cli

        # Check that all command functions exist
        assert hasattr(cli, 'html_enum_command')
        assert hasattr(cli, 'param_discover_command')
        assert hasattr(cli, 'param_extract_command')
        assert hasattr(cli, 'sqli_scan_command')
        assert hasattr(cli, 'sqli_fu_command')
        assert hasattr(cli, 'enum_scan_command')

        # Check they are callable
        assert callable(cli.html_enum_command)
        assert callable(cli.param_discover_command)
        assert callable(cli.param_extract_command)
        assert callable(cli.sqli_scan_command)
        assert callable(cli.sqli_fu_command)
        assert callable(cli.enum_scan_command)

    @pytest.mark.integration
    def test_sys_argv_modification(self):
        """Test that sys.argv is properly modified for subcommands"""
        original_argv = sys.argv.copy()

        try:
            with patch('sys.argv', ['crack', 'enum-scan', '192.168.45.100', '--full']):
                with patch('crack.network.enum_scan.main') as mock_main:
                    from crack.cli import enum_scan_command

                    # Call the command function directly
                    enum_scan_command(['192.168.45.100', '--full'])

                    # sys.argv should have been modified
                    assert sys.argv[0] == 'enum_scan'
                    assert '192.168.45.100' in sys.argv
                    assert '--full' in sys.argv

                    mock_main.assert_called_once()
        finally:
            sys.argv = original_argv

    @pytest.mark.integration
    def test_banner_with_different_commands(self, capsys):
        """Test banner display with various commands"""
        commands = [
            ['crack', 'enum-scan', '192.168.45.100'],
            ['crack', 'html-enum', 'http://test.com'],
            ['crack', 'sqli-scan', 'http://test.com?id=1']
        ]

        for cmd in commands:
            with patch('sys.argv', cmd):
                # Mock the actual command execution
                subcommand = cmd[1].replace('-', '_')
                module_map = {
                    'enum_scan': 'crack.network.enum_scan',
                    'html_enum': 'crack.web.html_enum',
                    'sqli_scan': 'crack.sqli.sqli_scanner'
                }

                with patch(f'{module_map[subcommand]}.main'):
                    main()

                    captured = capsys.readouterr()
                    # Banner should appear (check for ASCII art or subtitle)
                    assert "░▒▓" in captured.out or "(C)omprehensive" in captured.out

    @pytest.mark.integration
    def test_error_handling_in_subcommands(self):
        """Test error handling when subcommand raises exception"""
        with patch('sys.argv', ['crack', 'enum-scan', '192.168.45.100']):
            with patch('crack.network.enum_scan.main') as mock_main:
                mock_main.side_effect = Exception("Test error")

                # Should raise the exception (not caught by CLI)
                with pytest.raises(Exception, match="Test error"):
                    main()

    @pytest.mark.integration
    @pytest.mark.fast
    def test_colors_module_availability(self):
        """Test that Colors module is available to all components"""
        from crack.utils.colors import Colors

        # Check all color codes are defined
        assert hasattr(Colors, 'HEADER')
        assert hasattr(Colors, 'BLUE')
        assert hasattr(Colors, 'CYAN')
        assert hasattr(Colors, 'GREEN')
        assert hasattr(Colors, 'YELLOW')
        assert hasattr(Colors, 'RED')
        assert hasattr(Colors, 'BOLD')
        assert hasattr(Colors, 'END')

        # Check they contain ANSI codes
        assert '\033[' in Colors.BLUE
        assert '\033[' in Colors.END