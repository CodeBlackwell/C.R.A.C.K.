"""
Tests for QuickEditor (Tier 1) - Parameter Menu Editor

15 comprehensive tests validating all QuickEditor functionality.
Uses mocked ParsedCommand and user interaction.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from crack.track.interactive.components.command_editor.quick_editor import QuickEditor, EditResult


class TestParameterExtraction:
    """Test parameter extraction from parsed commands (3 tests)"""

    def test_extract_gobuster_params(self):
        """PROVES: QuickEditor extracts gobuster common parameters"""
        editor = QuickEditor(
            command="gobuster dir -u http://target -w /path/wordlist.txt -t 50",
            metadata={'tool': 'gobuster'}
        )

        # Mock ParsedCommand
        mock_parsed = Mock()
        mock_parsed.tool = 'gobuster'
        mock_parsed.subcommand = 'dir'
        mock_parsed.parameters = {
            'u': 'http://target',
            'w': '/path/wordlist.txt',
            't': '50'
        }
        mock_parsed.arguments = []
        mock_parsed.flags = {}

        # Extract params
        params = editor._extract_common_params(mock_parsed)

        assert 'url' in params
        assert params['url'] == 'http://target'
        assert 'wordlist' in params
        assert params['wordlist'] == '/path/wordlist.txt'
        assert 'threads' in params
        assert params['threads'] == '50'

    def test_extract_nmap_params(self):
        """PROVES: QuickEditor extracts nmap common parameters"""
        editor = QuickEditor(
            command="nmap -sS -p 1-1000 -T4 192.168.1.1",
            metadata={'tool': 'nmap'}
        )

        # Mock ParsedCommand
        mock_parsed = Mock()
        mock_parsed.tool = 'nmap'
        mock_parsed.parameters = {'p': '1-1000', 'T': '4'}
        mock_parsed.arguments = ['192.168.1.1']
        mock_parsed.flags = {'sS': True}

        params = editor._extract_common_params(mock_parsed)

        assert 'target' in params
        assert params['target'] == '192.168.1.1'
        assert 'ports' in params
        assert params['ports'] == '1-1000'
        assert 'timing' in params
        assert params['timing'] == '4'
        assert 'scan_type' in params
        assert 'sS' in params['scan_type']

    def test_extract_nikto_params(self):
        """PROVES: QuickEditor extracts nikto common parameters"""
        editor = QuickEditor(
            command="nikto -h 192.168.1.100 -p 443 -ssl",
            metadata={'tool': 'nikto'}
        )

        # Mock ParsedCommand
        mock_parsed = Mock()
        mock_parsed.tool = 'nikto'
        mock_parsed.parameters = {
            'h': '192.168.1.100',
            'p': '443',
            'ssl': ''
        }
        mock_parsed.arguments = []
        mock_parsed.flags = {}

        params = editor._extract_common_params(mock_parsed)

        assert 'host' in params
        assert params['host'] == '192.168.1.100'
        assert 'port' in params
        assert params['port'] == '443'


class TestParameterEditing:
    """Test parameter editing logic (3 tests)"""

    def test_edit_text_parameter(self):
        """PROVES: QuickEditor can edit text parameters"""
        editor = QuickEditor(
            command="gobuster dir -u http://old -w /wordlist",
            metadata={'tool': 'gobuster'},
            input_callback=lambda prompt: "http://new"
        )

        result = editor._edit_parameter('url', 'http://old')

        assert result == "http://new"

    def test_edit_numeric_parameter(self):
        """PROVES: QuickEditor can edit numeric parameters"""
        editor = QuickEditor(
            command="gobuster dir -u http://target -t 10",
            metadata={'tool': 'gobuster'},
            input_callback=lambda prompt: "100"
        )

        result = editor._edit_parameter('threads', '10')

        assert result == "100"

    def test_edit_path_parameter(self):
        """PROVES: QuickEditor can edit path parameters"""
        editor = QuickEditor(
            command="gobuster dir -w /old/path.txt",
            metadata={'tool': 'gobuster'},
            input_callback=lambda prompt: "/new/path.txt"
        )

        result = editor._edit_parameter('wordlist', '/old/path.txt')

        assert result == "/new/path.txt"


class TestActionHandling:
    """Test action handling (execute, escalate, cancel) (3 tests)"""

    def test_execute_action(self):
        """PROVES: QuickEditor returns execute action after successful edit"""
        editor = QuickEditor(
            command="gobuster dir -u http://target -w /wordlist",
            metadata={'tool': 'gobuster'},
            choice_callback=lambda prompt: "1",  # Select first param
            input_callback=lambda prompt: "http://modified"
        )

        # Mock parser and formatter (import happens inside run())
        with patch('crack.track.interactive.components.command_editor.parser.CommandParser') as mock_parser_class:
            mock_parsed = Mock()
            mock_parsed.tool = 'gobuster'
            mock_parsed.parameters = {'u': 'http://target', 'w': '/wordlist'}
            mock_parsed.arguments = []
            mock_parsed.flags = {}
            mock_parser_class.parse.return_value = mock_parsed

            with patch('crack.track.interactive.components.command_editor.formatter.CommandFormatter') as mock_formatter_class:
                mock_formatter_class.format_command.return_value = "gobuster dir -u http://modified -w /wordlist"

                result = editor.run()

                assert result.action == "execute"
                assert result.command == "gobuster dir -u http://modified -w /wordlist"

    def test_escalate_to_advanced(self):
        """PROVES: QuickEditor escalates to advanced editor on 'a' choice"""
        editor = QuickEditor(
            command="gobuster dir -u http://target",
            metadata={'tool': 'gobuster'},
            choice_callback=lambda prompt: "a"
        )

        # Mock parser
        with patch('crack.track.interactive.components.command_editor.parser.CommandParser') as mock_parser_class:
            mock_parsed = Mock()
            mock_parsed.tool = 'gobuster'
            mock_parsed.parameters = {'u': 'http://target'}
            mock_parsed.arguments = []
            mock_parsed.flags = {}
            mock_parser_class.parse.return_value = mock_parsed

            result = editor.run()

            assert result.action == "escalate"
            assert result.next_tier == "advanced"

    def test_cancel_action(self):
        """PROVES: QuickEditor returns cancel action on 'c' choice"""
        editor = QuickEditor(
            command="gobuster dir -u http://target",
            metadata={'tool': 'gobuster'},
            choice_callback=lambda prompt: "c"
        )

        # Mock parser
        with patch('crack.track.interactive.components.command_editor.parser.CommandParser') as mock_parser_class:
            mock_parsed = Mock()
            mock_parsed.tool = 'gobuster'
            mock_parsed.parameters = {'u': 'http://target'}
            mock_parsed.arguments = []
            mock_parsed.flags = {}
            mock_parser_class.parse.return_value = mock_parsed

            result = editor.run()

            assert result.action == "cancel"
            assert result.command is None


class TestPreviewGeneration:
    """Test preview/diff generation (3 tests)"""

    def test_preview_simple_diff(self):
        """PROVES: QuickEditor generates before/after diff"""
        editor = QuickEditor(
            command="gobuster dir -u http://target",
            metadata={'tool': 'gobuster'}
        )

        diff = editor.get_preview_diff(
            "gobuster dir -u http://old",
            "gobuster dir -u http://new"
        )

        assert "Before:" in diff
        assert "After:" in diff
        assert "http://old" in diff
        assert "http://new" in diff

    def test_preview_multiline_command(self):
        """PROVES: Preview handles multi-line commands"""
        editor = QuickEditor(
            command="nmap -sS -p 1-1000 192.168.1.1",
            metadata={'tool': 'nmap'}
        )

        original = "nmap -sS -p 1-1000 \\\n  192.168.1.1"
        modified = "nmap -sS -p 1-65535 \\\n  192.168.1.1"

        diff = editor.get_preview_diff(original, modified)

        assert "1-1000" in diff
        assert "1-65535" in diff

    def test_preview_parameter_change_visible(self):
        """PROVES: Preview clearly shows parameter changes"""
        editor = QuickEditor(
            command="gobuster dir -w /path/old.txt",
            metadata={'tool': 'gobuster'}
        )

        diff = editor.get_preview_diff(
            "gobuster dir -w /path/old.txt",
            "gobuster dir -w /path/new.txt"
        )

        assert "/path/old.txt" in diff
        assert "/path/new.txt" in diff


class TestEdgeCases:
    """Test edge cases (3 tests)"""

    def test_missing_params_escalates(self):
        """PROVES: QuickEditor escalates when no common params found"""
        editor = QuickEditor(
            command="unknown-tool --flag value",
            metadata={'tool': 'unknown'},
            choice_callback=lambda prompt: "1"
        )

        # Mock parser returning command with no recognized params
        with patch('crack.track.interactive.components.command_editor.parser.CommandParser') as mock_parser_class:
            mock_parsed = Mock()
            mock_parsed.tool = 'unknown'
            mock_parsed.parameters = {}
            mock_parsed.arguments = []
            mock_parsed.flags = {}
            mock_parser_class.parse.return_value = mock_parsed

            result = editor.run()

            # Should escalate to advanced editor
            assert result.action == "escalate"
            assert result.next_tier == "advanced"

    def test_invalid_choice_cancels(self):
        """PROVES: Invalid menu choice returns cancel"""
        editor = QuickEditor(
            command="gobuster dir -u http://target",
            metadata={'tool': 'gobuster'},
            choice_callback=lambda prompt: "99"  # Invalid choice
        )

        # Mock parser
        with patch('crack.track.interactive.components.command_editor.parser.CommandParser') as mock_parser_class:
            mock_parsed = Mock()
            mock_parsed.tool = 'gobuster'
            mock_parsed.parameters = {'u': 'http://target'}
            mock_parsed.arguments = []
            mock_parsed.flags = {}
            mock_parser_class.parse.return_value = mock_parsed

            result = editor.run()

            assert result.action == "cancel"

    def test_empty_input_cancels_edit(self):
        """PROVES: Empty input during edit cancels the operation"""
        editor = QuickEditor(
            command="gobuster dir -u http://target",
            metadata={'tool': 'gobuster'},
            choice_callback=lambda prompt: "1",
            input_callback=lambda prompt: ""  # Empty input
        )

        # Mock parser
        with patch('crack.track.interactive.components.command_editor.parser.CommandParser') as mock_parser_class:
            mock_parsed = Mock()
            mock_parsed.tool = 'gobuster'
            mock_parsed.parameters = {'u': 'http://target'}
            mock_parsed.arguments = []
            mock_parsed.flags = {}
            mock_parser_class.parse.return_value = mock_parsed

            result = editor.run()

            # Empty input should cancel
            assert result.action == "cancel"


class TestMenuBuilding:
    """Test menu building logic (bonus tests for completeness)"""

    def test_build_menu_from_params(self):
        """PROVES: Menu builder creates correct structure"""
        editor = QuickEditor(
            command="gobuster dir -u http://target -w /wordlist",
            metadata={'tool': 'gobuster'}
        )

        params = {
            'url': 'http://target',
            'wordlist': '/wordlist',
            'threads': '50'
        }

        menu = editor._build_menu(params)

        assert len(menu) == 3
        assert ('url', 'http://target') in menu
        assert ('wordlist', '/wordlist') in menu
        assert ('threads', '50') in menu

    def test_escalate_to_raw_editor(self):
        """PROVES: QuickEditor can escalate to raw editor on 'r' choice"""
        editor = QuickEditor(
            command="gobuster dir -u http://target",
            metadata={'tool': 'gobuster'},
            choice_callback=lambda prompt: "r"
        )

        # Mock parser
        with patch('crack.track.interactive.components.command_editor.parser.CommandParser') as mock_parser_class:
            mock_parsed = Mock()
            mock_parsed.tool = 'gobuster'
            mock_parsed.parameters = {'u': 'http://target'}
            mock_parsed.arguments = []
            mock_parsed.flags = {}
            mock_parser_class.parse.return_value = mock_parsed

            result = editor.run()

            assert result.action == "escalate"
            assert result.next_tier == "raw"
