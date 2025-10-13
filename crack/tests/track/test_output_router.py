"""
Unit tests for OutputRouter - Centralized output path management

Tests cover:
- Directory creation and path resolution
- Tool detection and flag injection
- Fallback output saving
- Edge cases and error handling
"""

import os
import pytest
from pathlib import Path
from crack.track.core.output_router import OutputRouter


class TestOutputRouter:
    """Test OutputRouter functionality"""

    def test_get_scans_dir_creates_directory(self, tmp_path):
        """Test that get_scans_dir creates target-specific directory"""
        # Set CRACK_OUTPUT_DIR to test directory
        os.environ['CRACK_OUTPUT_DIR'] = str(tmp_path)

        scans_dir = OutputRouter.get_scans_dir('192.168.45.100')

        assert scans_dir.exists()
        assert scans_dir.is_dir()
        assert '192.168.45.100' in str(scans_dir)
        assert 'scans' in str(scans_dir)

        # Cleanup
        del os.environ['CRACK_OUTPUT_DIR']

    def test_get_scans_dir_sanitizes_target(self, tmp_path):
        """Test that target names are sanitized for filesystem"""
        os.environ['CRACK_OUTPUT_DIR'] = str(tmp_path)

        # Test various problematic characters
        scans_dir = OutputRouter.get_scans_dir('192.168.45.100:8080')
        assert ':' not in scans_dir.name
        assert '_' in str(scans_dir)  # : replaced with _

        del os.environ['CRACK_OUTPUT_DIR']

    def test_inject_nmap_output_flags(self):
        """Test nmap output flag injection"""
        command = 'nmap -p- 192.168.45.100'
        target = '192.168.45.100'

        modified_cmd, output_file = OutputRouter.inject_output_flags(command, target)

        assert '-oA' in modified_cmd
        assert 'scans/' in modified_cmd
        assert 'nmap_' in modified_cmd
        assert output_file is not None
        # nmap -oA creates base filename without extension, .nmap added by tool
        assert 'nmap_' in str(output_file)

    def test_inject_gobuster_output_flags(self):
        """Test gobuster output flag injection"""
        command = 'gobuster dir -u http://192.168.45.100 -w wordlist.txt'
        target = '192.168.45.100'
        metadata = {'port': 80}

        modified_cmd, output_file = OutputRouter.inject_output_flags(command, target, metadata)

        assert '-o' in modified_cmd
        assert 'gobuster_80_' in modified_cmd
        assert output_file is not None
        assert '.txt' in str(output_file)

    def test_inject_nikto_output_flags(self):
        """Test nikto output flag injection"""
        command = 'nikto -h http://192.168.45.100'
        target = '192.168.45.100'

        modified_cmd, output_file = OutputRouter.inject_output_flags(command, target)

        assert '-output' in modified_cmd
        assert 'nikto_' in modified_cmd
        assert output_file is not None

    def test_no_injection_when_output_already_present(self):
        """Test that existing output flags are not overridden"""
        command = 'gobuster dir -u http://192.168.45.100 -w wordlist.txt -o my_custom_output.txt'
        target = '192.168.45.100'

        modified_cmd, output_file = OutputRouter.inject_output_flags(command, target)

        # Should respect existing output flag
        assert modified_cmd == command
        assert output_file is not None
        assert 'my_custom_output.txt' in str(output_file)

    def test_inject_enum4linux_with_tee(self):
        """Test enum4linux injection using tee"""
        command = 'enum4linux 192.168.45.100'
        target = '192.168.45.100'

        modified_cmd, output_file = OutputRouter.inject_output_flags(command, target)

        assert '| tee' in modified_cmd
        assert 'enum4linux_' in modified_cmd
        assert output_file is not None

    def test_inject_hydra_output_flags(self):
        """Test hydra output flag injection"""
        command = 'hydra -L users.txt -P passwords.txt ssh://192.168.45.100'
        target = '192.168.45.100'

        modified_cmd, output_file = OutputRouter.inject_output_flags(command, target)

        assert '-o' in modified_cmd
        assert 'hydra_' in modified_cmd
        assert output_file is not None

    def test_no_injection_for_unknown_tool(self):
        """Test that unknown tools don't get modified"""
        command = 'custom-unknown-tool 192.168.45.100'
        target = '192.168.45.100'

        modified_cmd, output_file = OutputRouter.inject_output_flags(command, target)

        # Should return original command
        assert modified_cmd == command
        assert output_file is None

    def test_save_captured_output(self, tmp_path):
        """Test fallback output saving"""
        os.environ['CRACK_OUTPUT_DIR'] = str(tmp_path)

        output = "Test output\nLine 2\nLine 3"
        target = '192.168.45.100'
        task_id = 'test-task-123'
        timestamp = '20251013_143000'

        output_file = OutputRouter.save_captured_output(output, target, task_id, timestamp)

        assert output_file.exists()
        assert output_file.is_file()
        assert 'fallback_' in output_file.name
        assert 'test-task-123' in output_file.name
        assert output_file.read_text() == output

        del os.environ['CRACK_OUTPUT_DIR']

    def test_inject_multiple_tools(self):
        """Test injection for multiple different tools"""
        tools_and_patterns = [
            ('wpscan --url http://192.168.45.100', '--output'),
            ('feroxbuster -u http://192.168.45.100', '-o'),
            ('dirb http://192.168.45.100', '-o'),
            ('sqlmap -u http://192.168.45.100', '--output-dir'),
            ('smbmap -H 192.168.45.100', '| tee'),
        ]

        target = '192.168.45.100'

        for command, expected_flag in tools_and_patterns:
            modified_cmd, output_file = OutputRouter.inject_output_flags(command, target)
            assert expected_flag in modified_cmd, f"Failed for: {command}"
            assert output_file is not None or '| tee' in modified_cmd, f"No output file for: {command}"

    def test_inject_with_empty_command(self):
        """Test handling of empty/None command"""
        modified_cmd, output_file = OutputRouter.inject_output_flags('', '192.168.45.100')
        assert modified_cmd == ''
        assert output_file is None

        modified_cmd, output_file = OutputRouter.inject_output_flags(None, '192.168.45.100')
        assert modified_cmd is None
        assert output_file is None

    def test_inject_with_empty_target(self):
        """Test handling of empty target"""
        modified_cmd, output_file = OutputRouter.inject_output_flags('nmap -p- 192.168.45.100', '')
        assert modified_cmd == 'nmap -p- 192.168.45.100'
        assert output_file is None

    def test_directory_priority_with_env_var(self, tmp_path):
        """Test that CRACK_OUTPUT_DIR environment variable takes priority"""
        custom_dir = tmp_path / 'custom_output'
        os.environ['CRACK_OUTPUT_DIR'] = str(custom_dir)

        scans_dir = OutputRouter.get_scans_dir('192.168.45.100')

        assert custom_dir in scans_dir.parents
        assert scans_dir.exists()

        del os.environ['CRACK_OUTPUT_DIR']

    def test_inject_preserves_command_structure(self):
        """Test that command structure and options are preserved"""
        command = 'nmap -p- --min-rate=5000 -T4 -v 192.168.45.100'
        target = '192.168.45.100'

        modified_cmd, output_file = OutputRouter.inject_output_flags(command, target)

        # Ensure all original flags are preserved
        assert '-p-' in modified_cmd
        assert '--min-rate=5000' in modified_cmd
        assert '-T4' in modified_cmd
        assert '-v' in modified_cmd
        assert '192.168.45.100' in modified_cmd

    def test_get_output_file_for_task(self):
        """Test getting expected output file for a task"""
        task_metadata = {
            'command': 'gobuster dir -u http://192.168.45.100 -w wordlist.txt',
            'port': 80
        }
        target = '192.168.45.100'

        output_file = OutputRouter.get_output_file_for_task(task_metadata, target)

        assert output_file is not None
        assert 'gobuster_80_' in str(output_file)
        assert '.txt' in str(output_file)

    def test_sanitize_task_id_in_fallback(self, tmp_path):
        """Test that task IDs are sanitized when creating fallback files"""
        os.environ['CRACK_OUTPUT_DIR'] = str(tmp_path)

        output = "Test"
        target = '192.168.45.100'
        task_id = 'test<task>with:bad*chars'
        timestamp = '20251013_143000'

        output_file = OutputRouter.save_captured_output(output, target, task_id, timestamp)

        # Ensure problematic characters are replaced
        assert '<' not in output_file.name
        assert '>' not in output_file.name
        assert ':' not in output_file.name
        assert '*' not in output_file.name

        del os.environ['CRACK_OUTPUT_DIR']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
