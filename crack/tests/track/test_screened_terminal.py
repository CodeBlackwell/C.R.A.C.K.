"""
Unit tests for screened terminal functionality

Tests the PTY-based terminal, command executor, and output parsing.
"""

import pytest
import os
import time
from pathlib import Path
import tempfile
from unittest.mock import MagicMock, patch, call

from crack.track.core.terminal import ScreenedTerminal, CommandResult
from crack.track.core.command_executor import (
    CommandExecutor,
    ExecutorStrategy,
    SubprocessExecutor,
    ScreenedExecutor,
    ExecutionResult
)
from crack.track.parsers.output_patterns import OutputPatternMatcher
from crack.track.core.task_tree import TaskNode


class TestScreenedTerminal:
    """Test ScreenedTerminal PTY management"""

    def test_terminal_initialization(self):
        """PROVES: Terminal initializes with correct settings"""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / 'logs'
            terminal = ScreenedTerminal('192.168.45.100', log_dir=log_dir)

            assert terminal.target == '192.168.45.100'
            assert terminal.running is False
            assert terminal.master_fd is None
            assert terminal.shell_pid is None
            assert log_dir.exists()

    def test_terminal_start_stop(self):
        """PROVES: Terminal can start and stop cleanly"""
        terminal = ScreenedTerminal('192.168.45.100')

        # Start terminal
        assert terminal.start() is True
        assert terminal.running is True
        assert terminal.master_fd is not None
        assert terminal.shell_pid is not None

        # Stop terminal
        terminal.stop()
        assert terminal.running is False

    def test_command_execution(self):
        """PROVES: Commands execute and return output"""
        terminal = ScreenedTerminal('192.168.45.100')
        terminal.start()

        try:
            # Execute simple command
            result = terminal.execute('echo "test output"', timeout=5)

            assert isinstance(result, CommandResult)
            assert result.success is True
            assert any('test output' in line for line in result.output)
            assert result.command == 'echo "test output"'

        finally:
            terminal.stop()

    def test_command_failure_detection(self):
        """PROVES: Failed commands are detected"""
        terminal = ScreenedTerminal('192.168.45.100')
        terminal.start()

        try:
            # Execute failing command
            result = terminal.execute('nonexistentcommand123', timeout=2)

            assert result.success is False
            assert any('command not found' in line.lower() for line in result.output)

        finally:
            terminal.stop()

    def test_environment_management(self):
        """PROVES: Environment variables can be set and retrieved"""
        terminal = ScreenedTerminal('192.168.45.100')
        terminal.start()

        try:
            # Set environment variable
            terminal.set_environment('TEST_VAR', 'test_value')

            # Get environment
            env = terminal.get_environment()
            assert 'TEST_VAR' in env
            assert env['TEST_VAR'] == 'test_value'

        finally:
            terminal.stop()

    def test_working_directory(self):
        """PROVES: Working directory tracking works"""
        terminal = ScreenedTerminal('192.168.45.100')
        terminal.start()

        try:
            # Get initial directory
            initial_cwd = terminal.get_cwd()
            assert initial_cwd

            # Change directory
            terminal.execute('cd /tmp', timeout=2)
            new_cwd = terminal.get_cwd()
            assert new_cwd == '/tmp'

        finally:
            terminal.stop()

    def test_context_manager(self):
        """PROVES: Terminal works as context manager"""
        with ScreenedTerminal('192.168.45.100') as terminal:
            assert terminal.running is True

            result = terminal.execute('pwd', timeout=2)
            assert result.success is True

        # Terminal should be stopped after context exit
        assert terminal.running is False


class TestCommandExecutor:
    """Test command executor abstraction"""

    def test_executor_factory(self):
        """PROVES: Factory creates correct executor types"""
        # Create subprocess executor
        subprocess_exec = CommandExecutor.create('subprocess')
        assert isinstance(subprocess_exec, SubprocessExecutor)

        # Create screened executor
        screened_exec = CommandExecutor.create('screened')
        assert isinstance(screened_exec, ScreenedExecutor)

        # Verify caching
        subprocess_exec2 = CommandExecutor.create('subprocess')
        assert subprocess_exec is subprocess_exec2

    def test_subprocess_executor(self):
        """PROVES: Subprocess executor runs commands"""
        executor = SubprocessExecutor()

        # Create test task
        task = TaskNode('test-task', 'Test Task')
        task.metadata['command'] = 'echo "test {TARGET}"'

        # Execute
        result = executor.run(task, '192.168.45.100')

        assert isinstance(result, ExecutionResult)
        assert result.command == 'echo "test 192.168.45.100"'
        assert result.success is True
        assert 'test 192.168.45.100' in ' '.join(result.output)

    @patch('crack.track.core.command_executor.ScreenedTerminal')
    def test_screened_executor(self, mock_terminal_class):
        """PROVES: Screened executor uses terminal"""
        # Setup mock terminal
        mock_terminal = MagicMock()
        mock_terminal_class.return_value = mock_terminal
        mock_terminal.start.return_value = True

        # Mock execute result
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.output = ['test output']
        mock_result.duration = 1.0
        mock_result.findings = {}
        mock_terminal.execute.return_value = mock_result

        # Create executor
        executor = ScreenedExecutor()
        executor.terminal = mock_terminal

        # Create test task
        task = TaskNode('test-task', 'Test Task')
        task.metadata['command'] = 'nmap {TARGET}'

        # Execute
        result = executor.run(task, '192.168.45.100')

        # Verify terminal was used
        mock_terminal.execute.assert_called_once()
        assert result.success is True
        assert task.status == 'completed'

    def test_command_substitution(self):
        """PROVES: Placeholders are replaced correctly"""
        executor = SubprocessExecutor()

        task = TaskNode('test-task', 'Test Task')
        task.metadata['command'] = 'nmap -sV {TARGET} -p {target}'

        prepared = executor._prepare_command(task, '192.168.45.100')
        assert prepared == 'nmap -sV 192.168.45.100 -p 192.168.45.100'


class TestOutputPatternMatcher:
    """Test output pattern matching"""

    def test_pattern_initialization(self):
        """PROVES: Pattern matcher initializes with base patterns"""
        matcher = OutputPatternMatcher()

        assert 'success' in matcher.patterns
        assert 'failure' in matcher.patterns
        assert 'ports' in matcher.patterns
        assert 'credentials' in matcher.patterns

    def test_tool_detection(self):
        """PROVES: Tools are detected from commands"""
        matcher = OutputPatternMatcher()

        assert matcher._detect_tool('nmap -sV target') == 'nmap'
        assert matcher._detect_tool('gobuster dir -u http://target') == 'gobuster'
        assert matcher._detect_tool('sqlmap -u http://target') == 'sqlmap'
        assert matcher._detect_tool('custom command') is None

    def test_port_extraction(self):
        """PROVES: Ports are extracted from output"""
        matcher = OutputPatternMatcher()

        output = [
            '80/tcp open http Apache 2.4.41',
            '443/tcp open ssl/https nginx',
            '3306/tcp open mysql MySQL 5.7'
        ]

        task = TaskNode('scan', 'Port Scan')
        task.metadata['command'] = 'nmap target'

        findings = matcher.analyze(output, task)

        assert len(findings['ports']) == 3
        assert any(p['port'] == 80 for p in findings['ports'])
        assert any(p['service'] == 'mysql' for p in findings['ports'])

    def test_credential_extraction(self):
        """PROVES: Credentials are extracted from output"""
        matcher = OutputPatternMatcher()

        output = [
            'Found credentials:',
            'Username: admin',
            'Password: P@ssw0rd123',
            'Login successful'
        ]

        task = TaskNode('brute', 'Credential Brute Force')
        findings = matcher.analyze(output, task)

        assert len(findings['credentials']) >= 1
        cred = findings['credentials'][0]
        assert cred['username'] == 'admin'
        assert cred['password'] == 'P@ssw0rd123'

    def test_vulnerability_detection(self):
        """PROVES: CVEs and vulnerabilities are detected"""
        matcher = OutputPatternMatcher()

        output = [
            'Vulnerability found:',
            'CVE-2021-41773 - Path traversal in Apache',
            'Exploitation successful'
        ]

        task = TaskNode('vuln-scan', 'Vulnerability Scan')
        findings = matcher.analyze(output, task)

        assert len(findings['vulnerabilities']) >= 1
        assert any('CVE-2021-41773' in str(v) for v in findings['vulnerabilities'])

    def test_success_failure_detection(self):
        """PROVES: Overall success/failure is detected"""
        matcher = OutputPatternMatcher()

        # Success case
        success_output = ['Scan complete', '5 ports open']
        task = TaskNode('scan', 'Scan')
        findings = matcher.analyze(success_output, task)
        assert findings['success'] is True

        # Failure case
        failure_output = ['Error: Permission denied', 'Failed to connect']
        findings = matcher.analyze(failure_output, task)
        assert findings['success'] is False

    def test_nmap_specific_parsing(self):
        """PROVES: Nmap output is parsed correctly"""
        matcher = OutputPatternMatcher()

        output = [
            '80/tcp open http Apache httpd 2.4.41',
            '|_http-title: Test Site',
            'OS: Linux 3.10 - 4.11'
        ]

        task = TaskNode('nmap-scan', 'Nmap Scan')
        task.metadata['command'] = 'nmap -sV target'

        findings = matcher.analyze(output, task)

        assert len(findings['ports']) == 1
        assert findings['ports'][0]['port'] == 80
        assert findings['ports'][0]['version'] == 'Apache httpd 2.4.41'

    def test_gobuster_specific_parsing(self):
        """PROVES: Gobuster output is parsed correctly"""
        matcher = OutputPatternMatcher()

        output = [
            '/admin (Status: 301)',
            '/uploads (Status: 200)',
            '/config.php (Status: 403)'
        ]

        task = TaskNode('dir-scan', 'Directory Scan')
        task.metadata['command'] = 'gobuster dir -u http://target'

        findings = matcher.analyze(output, task)

        assert len(findings['directories']) > 0
        assert len(findings['files']) > 0


class TestIntegration:
    """Integration tests for screened mode"""

    def test_end_to_end_screened_execution(self):
        """PROVES: Complete screened workflow works"""
        # Create terminal
        terminal = ScreenedTerminal('192.168.45.100')

        # Create executor with terminal
        executor = ScreenedExecutor(terminal)
        executor.set_parser(OutputPatternMatcher())

        # Create task
        task = TaskNode('echo-test', 'Echo Test')
        task.metadata['command'] = 'echo "Port 80/tcp open http"'

        # Start terminal
        terminal.start()

        try:
            # Execute task
            result = executor.run(task, '192.168.45.100')

            # Verify success
            assert result.success is True
            assert task.status == 'completed'

            # Verify parsing
            if 'ports' in result.findings:
                assert len(result.findings['ports']) > 0

        finally:
            terminal.stop()

    @patch('crack.track.core.terminal.os.fork')
    @patch('crack.track.core.terminal.pty.openpty')
    def test_terminal_error_handling(self, mock_openpty, mock_fork):
        """PROVES: Terminal handles errors gracefully"""
        # Simulate PTY creation failure
        mock_openpty.side_effect = OSError("PTY creation failed")

        terminal = ScreenedTerminal('192.168.45.100')
        result = terminal.start()

        assert result is False
        assert terminal.running is False