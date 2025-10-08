"""
Screened Terminal - PTY-based persistent terminal for command execution

Minimalist implementation using only Python stdlib.
No external dependencies (screen/tmux not required).
"""

import os
import pty
import select
import signal
import termios
import tty
from typing import Optional, Dict, Any, Tuple, List
from datetime import datetime
from pathlib import Path
import json


class CommandResult:
    """Result of command execution"""

    def __init__(self, command: str, success: bool = False):
        self.command = command
        self.success = success
        self.output = []
        self.exit_code = None
        self.duration = 0
        self.findings = {}
        self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary"""
        return {
            'command': self.command,
            'success': self.success,
            'output': self.output,
            'exit_code': self.exit_code,
            'duration': self.duration,
            'findings': self.findings,
            'timestamp': self.timestamp
        }


class ScreenedTerminal:
    """
    Persistent PTY-based terminal for command execution

    German Engineering Principles:
    - Single responsibility: Terminal management only
    - No complex abstractions
    - Direct PTY control
    - Efficient I/O handling
    """

    def __init__(self, target: str, log_dir: Optional[Path] = None):
        """
        Initialize screened terminal

        Args:
            target: Target IP/hostname for context
            log_dir: Directory for session logs
        """
        self.target = target
        self.master_fd = None
        self.slave_fd = None
        self.shell_pid = None
        self.running = False

        # Logging
        self.log_dir = log_dir or Path.home() / '.crack' / 'screened' / target
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.session_log = self.log_dir / f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

        # Output buffer for parsing
        self.output_buffer = []
        self.current_command = None

    def start(self) -> bool:
        """
        Start persistent shell process with PTY

        Returns:
            True if successful, False otherwise
        """
        try:
            # Create PTY pair
            self.master_fd, self.slave_fd = pty.openpty()

            # Fork process
            self.shell_pid = os.fork()

            if self.shell_pid == 0:
                # Child process - exec shell
                os.setsid()
                os.dup2(self.slave_fd, 0)  # stdin
                os.dup2(self.slave_fd, 1)  # stdout
                os.dup2(self.slave_fd, 2)  # stderr

                # Close unused FDs
                os.close(self.master_fd)
                os.close(self.slave_fd)

                # Execute shell
                os.execv('/bin/bash', ['bash', '--norc', '--noprofile'])

            # Parent process
            os.close(self.slave_fd)
            self.running = True

            # Set non-blocking
            import fcntl
            flags = fcntl.fcntl(self.master_fd, fcntl.F_GETFL)
            fcntl.fcntl(self.master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

            # Clear initial prompt
            self._read_output(timeout=0.5)

            return True

        except Exception as e:
            self.running = False
            return False

    def stop(self):
        """Stop terminal and cleanup"""
        if self.shell_pid:
            try:
                os.kill(self.shell_pid, signal.SIGTERM)
                os.waitpid(self.shell_pid, 0)
            except:
                pass

        if self.master_fd:
            try:
                os.close(self.master_fd)
            except:
                pass

        self.running = False

    def execute(self, command: str, timeout: int = 30) -> CommandResult:
        """
        Execute command and capture output

        Args:
            command: Command to execute
            timeout: Execution timeout in seconds

        Returns:
            CommandResult with output and status
        """
        if not self.running:
            raise RuntimeError("Terminal not running")

        result = CommandResult(command)
        self.current_command = command
        start_time = datetime.now()

        try:
            # Clear any pending output
            self._read_output(timeout=0.1)

            # Send command
            os.write(self.master_fd, (command + '\n').encode())

            # Log command
            self._log(f"[COMMAND] {command}")

            # Read output until prompt or timeout
            output_lines = []
            elapsed = 0

            while elapsed < timeout:
                lines = self._read_output(timeout=0.5)
                if lines:
                    output_lines.extend(lines)

                    # Check for command completion (prompt detection)
                    if self._detect_prompt(lines):
                        break

                elapsed = (datetime.now() - start_time).total_seconds()

            # Process results
            result.output = output_lines
            result.duration = elapsed
            result.success = self._check_success(output_lines)

            # Log output
            for line in output_lines:
                self._log(f"[OUTPUT] {line}")

        except Exception as e:
            result.success = False
            result.output.append(f"Error: {str(e)}")

        self.current_command = None
        return result

    def _read_output(self, timeout: float = 0.5) -> List[str]:
        """
        Read available output from terminal

        Args:
            timeout: Read timeout

        Returns:
            List of output lines
        """
        lines = []

        try:
            # Use select for non-blocking read with timeout
            ready, _, _ = select.select([self.master_fd], [], [], timeout)

            if ready:
                data = os.read(self.master_fd, 4096)
                if data:
                    # Decode and split into lines
                    text = data.decode('utf-8', errors='replace')

                    # Handle line buffering
                    self.output_buffer.append(text)

                    # Extract complete lines
                    full_text = ''.join(self.output_buffer)
                    line_list = full_text.split('\n')

                    # Keep incomplete line in buffer
                    self.output_buffer = [line_list[-1]] if line_list[-1] else []

                    # Return complete lines
                    lines = [line.strip() for line in line_list[:-1] if line.strip()]

        except:
            pass

        return lines

    def _detect_prompt(self, lines: List[str]) -> bool:
        """
        Detect shell prompt indicating command completion

        Args:
            lines: Recent output lines

        Returns:
            True if prompt detected
        """
        # Common prompt patterns
        prompt_patterns = [
            '$',  # User prompt
            '#',  # Root prompt
            '>',  # Alternative prompt
            '$ ',
            '# ',
            '> '
        ]

        if lines:
            last_line = lines[-1].strip()
            for pattern in prompt_patterns:
                if last_line.endswith(pattern):
                    return True

        return False

    def _check_success(self, output: List[str]) -> bool:
        """
        Basic success detection from output

        Args:
            output: Command output lines

        Returns:
            True if command appears successful
        """
        # Check for common error patterns
        error_patterns = [
            'error:',
            'Error:',
            'ERROR:',
            'failed',
            'Failed',
            'FAILED',
            'permission denied',
            'Permission denied',
            'not found',
            'No such file',
            'command not found'
        ]

        output_text = '\n'.join(output).lower()

        for pattern in error_patterns:
            if pattern.lower() in output_text:
                # Skip the command echo line
                if pattern.lower() not in self.current_command.lower():
                    return False

        return True

    def _log(self, message: str):
        """
        Log message to session file

        Args:
            message: Message to log
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_line = f"[{timestamp}] {message}\n"

        with open(self.session_log, 'a') as f:
            f.write(log_line)

    def send_raw(self, data: str):
        """
        Send raw data to terminal (for special keys, etc)

        Args:
            data: Raw string to send
        """
        if self.running and self.master_fd:
            os.write(self.master_fd, data.encode())

    def get_environment(self) -> Dict[str, str]:
        """
        Get current environment variables

        Returns:
            Dictionary of environment variables
        """
        result = self.execute('env', timeout=5)
        env_vars = {}

        for line in result.output:
            if '=' in line:
                key, value = line.split('=', 1)
                env_vars[key] = value

        return env_vars

    def set_environment(self, key: str, value: str):
        """
        Set environment variable

        Args:
            key: Variable name
            value: Variable value
        """
        self.execute(f'export {key}="{value}"', timeout=2)

    def get_cwd(self) -> str:
        """
        Get current working directory

        Returns:
            Current directory path
        """
        result = self.execute('pwd', timeout=2)
        if result.output:
            # Skip command echo, get actual output
            for line in result.output:
                if line and not line.startswith('pwd'):
                    return line
        return '/'

    def __enter__(self):
        """Context manager entry"""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.stop()

    def __del__(self):
        """Cleanup on deletion"""
        self.stop()