"""
Test CommandParser - 20 comprehensive tests

Test Coverage:
- gobuster: 3 tests
- nmap: 3 tests
- nikto: 3 tests
- hydra: 3 tests
- sqlmap: 3 tests
- Generic fallback: 3 tests
- Edge cases: 2 tests
"""

import pytest
from ..parser import CommandParser, ParsedCommand


class TestGobusterParsing:
    """Test gobuster command parsing (3 tests)"""

    def test_gobuster_dir_basic_params(self):
        """PROVES: Parser extracts gobuster dir subcommand and basic parameters"""
        command = "gobuster dir -u http://192.168.1.100 -w /usr/share/wordlists/dirb/common.txt"

        result = CommandParser.parse(command)

        assert result.tool == "gobuster"
        assert result.subcommand == "dir"
        assert result.parameters['u'] == "http://192.168.1.100"
        assert result.parameters['w'] == "/usr/share/wordlists/dirb/common.txt"
        assert len(result.arguments) == 0

    def test_gobuster_with_threads_and_extensions(self):
        """PROVES: Parser extracts numeric and string parameters"""
        command = "gobuster dir -u http://target -w /path/list.txt -t 50 -x php,html,txt"

        result = CommandParser.parse(command)

        assert result.tool == "gobuster"
        assert result.parameters['t'] == "50"
        assert result.parameters['x'] == "php,html,txt"

    def test_gobuster_with_boolean_flags(self):
        """PROVES: Parser extracts boolean flags (verbose, quiet, expanded)"""
        command = "gobuster dir -u http://target -w /path/list.txt -v -e -q"

        result = CommandParser.parse(command)

        assert result.flags['v'] is True
        assert result.flags['e'] is True
        assert result.flags['q'] is True


class TestNmapParsing:
    """Test nmap command parsing (3 tests)"""

    def test_nmap_basic_scan_types(self):
        """PROVES: Parser extracts nmap scan type flags (-sS, -sV, -sC)"""
        command = "nmap -sS -sV -sC 192.168.1.100"

        result = CommandParser.parse(command)

        assert result.tool == "nmap"
        assert result.flags['sS'] is True
        assert result.flags['sV'] is True
        assert result.flags['sC'] is True
        assert "192.168.1.100" in result.arguments

    def test_nmap_port_range_and_output(self):
        """PROVES: Parser extracts port range and output file parameters"""
        command = "nmap -p 1-65535 -oA scan_results 192.168.1.100"

        result = CommandParser.parse(command)

        assert result.parameters['p'] == "1-65535"
        assert result.parameters['oA'] == "scan_results"
        assert "192.168.1.100" in result.arguments

    def test_nmap_aggressive_with_timing(self):
        """PROVES: Parser extracts aggressive scan and timing parameters"""
        command = "nmap -A -T4 -Pn 192.168.1.0/24"

        result = CommandParser.parse(command)

        assert result.flags['A'] is True
        assert result.flags['Pn'] is True
        assert result.parameters['T'] == "4"  # T4 parsed as -T with value 4
        assert "192.168.1.0/24" in result.arguments


class TestNiktoParsing:
    """Test nikto command parsing (3 tests)"""

    def test_nikto_basic_host_and_port(self):
        """PROVES: Parser extracts nikto host and port parameters"""
        command = "nikto -h 192.168.1.100 -p 80,443"

        result = CommandParser.parse(command)

        assert result.tool == "nikto"
        assert result.parameters['h'] == "192.168.1.100"
        assert result.parameters['p'] == "80,443"

    def test_nikto_ssl_and_tuning(self):
        """PROVES: Parser extracts SSL and tuning parameters"""
        command = "nikto -h https://target -ssl -Tuning 123"

        result = CommandParser.parse(command)

        assert result.parameters['h'] == "https://target"
        assert result.flags['ssl'] is True
        assert result.parameters['Tuning'] == "123"

    def test_nikto_output_format(self):
        """PROVES: Parser extracts output file and format"""
        command = "nikto -h 192.168.1.100 -output results.txt -Format txt"

        result = CommandParser.parse(command)

        assert result.parameters['output'] == "results.txt"
        assert result.parameters['Format'] == "txt"


class TestHydraParsing:
    """Test hydra command parsing (3 tests)"""

    def test_hydra_single_user_password(self):
        """PROVES: Parser extracts single username and password"""
        command = "hydra -l admin -p password123 192.168.1.100 ssh"

        result = CommandParser.parse(command)

        assert result.tool == "hydra"
        assert result.parameters['l'] == "admin"
        assert result.parameters['p'] == "password123"
        assert "192.168.1.100" in result.arguments
        assert "ssh" in result.arguments

    def test_hydra_user_list_and_pass_list(self):
        """PROVES: Parser extracts username list and password list files"""
        command = "hydra -L /path/users.txt -P /path/passwords.txt 192.168.1.100 ftp"

        result = CommandParser.parse(command)

        assert result.parameters['L'] == "/path/users.txt"
        assert result.parameters['P'] == "/path/passwords.txt"

    def test_hydra_threads_and_verbose(self):
        """PROVES: Parser extracts thread count and verbose flags"""
        command = "hydra -l admin -P /path/pass.txt -t 16 -v -V 192.168.1.100 ssh"

        result = CommandParser.parse(command)

        assert result.parameters['t'] == "16"
        assert result.flags['v'] is True
        assert result.flags['V'] is True


class TestSqlmapParsing:
    """Test sqlmap command parsing (3 tests)"""

    def test_sqlmap_basic_url(self):
        """PROVES: Parser extracts URL parameter"""
        command = "sqlmap -u http://target/page.php?id=1"

        result = CommandParser.parse(command)

        assert result.tool == "sqlmap"
        assert result.parameters['u'] == "http://target/page.php?id=1"

    def test_sqlmap_database_enumeration(self):
        """PROVES: Parser extracts database enumeration flags"""
        command = "sqlmap -u http://target/page.php?id=1 --dbs --tables --dump"

        result = CommandParser.parse(command)

        assert result.flags['dbs'] is True
        assert result.flags['tables'] is True
        assert result.flags['dump'] is True

    def test_sqlmap_database_and_table_selection(self):
        """PROVES: Parser extracts database and table selection parameters"""
        command = "sqlmap -u http://target/page.php?id=1 -D testdb -T users -C username,password --dump"

        result = CommandParser.parse(command)

        assert result.parameters['D'] == "testdb"
        assert result.parameters['T'] == "users"
        assert result.parameters['C'] == "username,password"
        assert result.flags['dump'] is True


class TestGenericFallbackParser:
    """Test generic fallback parser (3 tests)"""

    def test_generic_unknown_tool(self):
        """PROVES: Generic parser handles unknown tools"""
        command = "unknowntool --flag1 value1 --flag2 value2 arg1"

        result = CommandParser.parse(command)

        assert result.tool == "unknowntool"
        assert result.parameters['flag1'] == "value1"
        assert result.parameters['flag2'] == "value2"
        assert "arg1" in result.arguments

    def test_generic_mixed_flags_and_params(self):
        """PROVES: Generic parser handles flags with values and trailing positional args"""
        command = "customtool -v --output file.txt --threads 10 arg1 arg2"

        result = CommandParser.parse(command)

        assert result.flags['v'] is True
        assert result.parameters['output'] == "file.txt"
        assert result.parameters['threads'] == "10"
        assert "arg1" in result.arguments
        assert "arg2" in result.arguments

    def test_generic_only_positional_args(self):
        """PROVES: Generic parser handles commands with only positional arguments"""
        command = "simplecmd file1.txt file2.txt file3.txt"

        result = CommandParser.parse(command)

        assert result.tool == "simplecmd"
        assert len(result.arguments) == 3
        assert "file1.txt" in result.arguments


class TestEdgeCases:
    """Test edge cases (2 tests)"""

    def test_quoted_arguments_with_spaces(self):
        """PROVES: Parser handles quoted arguments containing spaces"""
        command = 'gobuster dir -u "http://target with spaces" -w "/path/to/word list.txt"'

        result = CommandParser.parse(command)

        assert result.parameters['u'] == "http://target with spaces"
        assert result.parameters['w'] == "/path/to/word list.txt"

    def test_multiline_command_with_backslashes(self):
        """PROVES: Parser handles multi-line commands with backslash continuations"""
        command = """nmap -sS -sV \\
-p 1-65535 \\
-oA scan_results \\
192.168.1.100"""

        result = CommandParser.parse(command)

        assert result.tool == "nmap"
        assert result.flags['sS'] is True
        assert result.flags['sV'] is True
        assert result.parameters['p'] == "1-65535"
        assert result.parameters['oA'] == "scan_results"
        assert "192.168.1.100" in result.arguments


class TestToolExtraction:
    """Test extract_tool method (bonus coverage)"""

    def test_extract_tool_simple(self):
        """PROVES: extract_tool returns first word"""
        assert CommandParser.extract_tool("nmap -sV 192.168.1.1") == "nmap"

    def test_extract_tool_with_sudo(self):
        """PROVES: extract_tool skips sudo prefix"""
        assert CommandParser.extract_tool("sudo nmap -sV 192.168.1.1") == "nmap"

    def test_extract_tool_empty_command(self):
        """PROVES: extract_tool handles empty command"""
        assert CommandParser.extract_tool("") == ""
        assert CommandParser.extract_tool("   ") == ""
