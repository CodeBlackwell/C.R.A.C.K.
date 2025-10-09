"""
Shell detection and fingerprinting.

Detects:
- Shell type (bash, sh, zsh, powershell, cmd)
- Operating system (linux, windows, macos)
- Available tools (python, socat, script, etc.)
- Current PTY status
"""

import logging
from typing import List, Optional, Dict, Any
from ..models import Session, ShellCapabilities

logger = logging.getLogger(__name__)


class ShellDetector:
    """Detect shell capabilities and environment.

    Probes a shell session to determine available features,
    tools, and current state. Used by ShellUpgrader to select
    appropriate upgrade methods.

    Example:
        >>> detector = ShellDetector()
        >>> session = Session(type='tcp', target='192.168.45.150', port=4444)
        >>> caps = detector.detect_capabilities(session)
        >>> print(f"Shell: {caps.shell_type}, OS: {caps.os_type}")
        >>> if 'python3' in caps.detected_tools:
        ...     print("Python PTY upgrade available")
    """

    # Tools to check for
    COMMON_TOOLS = [
        'python3', 'python', 'python2',
        'socat', 'script', 'expect',
        'tmux', 'screen',
        'wget', 'curl',
        'nc', 'ncat', 'netcat',
        'perl', 'ruby', 'php',
        'bash', 'sh', 'zsh',
        'stty', 'reset'
    ]

    def __init__(self, command_executor=None):
        """Initialize detector.

        Args:
            command_executor: Optional command executor (for testing).
                            If None, uses session's native command execution.
        """
        self.command_executor = command_executor

    def detect_capabilities(self, session: Session) -> ShellCapabilities:
        """Detect complete shell capabilities.

        Args:
            session: Session to probe

        Returns:
            ShellCapabilities with detected features

        Example:
            >>> caps = detector.detect_capabilities(session)
            >>> if caps.has_pty:
            ...     print("PTY already available")
            >>> else:
            ...     print(f"Available upgrade tools: {caps.detected_tools}")
        """
        caps = ShellCapabilities()

        # Detect shell type
        caps.shell_type = self.detect_shell(session)
        logger.debug(f"Detected shell type: {caps.shell_type}")

        # Detect OS
        caps.os_type = self.detect_os(session)
        logger.debug(f"Detected OS: {caps.os_type}")

        # Detect available tools
        caps.detected_tools = self.detect_tools(session)
        logger.debug(f"Detected tools: {caps.detected_tools}")

        # Check PTY status
        caps.has_pty = self.check_pty_status(session)
        logger.debug(f"PTY status: {caps.has_pty}")

        # Test tab completion
        caps.has_tab_completion = caps.has_pty  # Usually linked to PTY

        # Test history
        caps.has_history = caps.has_pty  # Usually linked to PTY

        return caps

    def detect_shell(self, session: Session) -> str:
        """Detect shell type.

        Args:
            session: Session to probe

        Returns:
            Shell type string ('bash', 'sh', 'zsh', 'powershell', 'cmd', 'unknown')

        Example:
            >>> shell_type = detector.detect_shell(session)
            >>> if shell_type == 'bash':
            ...     print("Bash-specific upgrades available")
        """
        # Try $SHELL
        output = self._execute_command(session, 'echo $SHELL')

        if output:
            output_lower = output.lower()
            if 'bash' in output_lower:
                return 'bash'
            elif 'zsh' in output_lower:
                return 'zsh'
            elif 'sh' in output_lower:
                return 'sh'

        # Try Windows detection
        output = self._execute_command(session, 'echo %COMSPEC%')
        if output and 'cmd' in output.lower():
            return 'cmd'

        # Try PowerShell
        output = self._execute_command(session, '$PSVersionTable')
        if output and 'psversion' in output.lower():
            return 'powershell'

        return 'unknown'

    def detect_os(self, session: Session) -> str:
        """Detect operating system.

        Args:
            session: Session to probe

        Returns:
            OS type string ('linux', 'windows', 'macos', 'unknown')

        Example:
            >>> os_type = detector.detect_os(session)
            >>> if os_type == 'linux':
            ...     print("Linux-specific upgrades available")
        """
        # Try Unix uname
        output = self._execute_command(session, 'uname -a')

        if output:
            output_lower = output.lower()
            if 'linux' in output_lower:
                return 'linux'
            elif 'darwin' in output_lower:
                return 'macos'
            elif 'freebsd' in output_lower or 'openbsd' in output_lower:
                return 'bsd'

        # Try Windows ver
        output = self._execute_command(session, 'ver')
        if output and 'windows' in output.lower():
            return 'windows'

        # Try systeminfo (Windows)
        output = self._execute_command(session, 'systeminfo | findstr /B /C:"OS Name"')
        if output and 'windows' in output.lower():
            return 'windows'

        return 'unknown'

    def detect_tools(self, session: Session) -> List[str]:
        """Detect available tools on target.

        Args:
            session: Session to probe

        Returns:
            List of detected tool names

        Example:
            >>> tools = detector.detect_tools(session)
            >>> if 'python3' in tools:
            ...     print("Python 3 available for PTY upgrade")
            >>> if 'socat' in tools:
            ...     print("Socat available for full TTY")
        """
        detected = []

        for tool in self.COMMON_TOOLS:
            if self.check_tool(session, tool):
                detected.append(tool)
                logger.debug(f"Tool detected: {tool}")

        return detected

    def check_tool(self, session: Session, tool: str) -> bool:
        """Check if specific tool exists.

        Args:
            session: Session to probe
            tool: Tool name to check

        Returns:
            True if tool found, False otherwise

        Example:
            >>> if detector.check_tool(session, 'socat'):
            ...     print("Socat is available")
        """
        # Try which command (Unix)
        output = self._execute_command(session, f'which {tool}')
        if output and '/' in output and 'not found' not in output.lower():
            return True

        # Try command -v (more portable)
        output = self._execute_command(session, f'command -v {tool}')
        if output and '/' in output:
            return True

        # Try where (Windows)
        output = self._execute_command(session, f'where {tool}')
        if output and '\\' in output:
            return True

        return False

    def check_pty_status(self, session: Session) -> bool:
        """Check if session has PTY.

        Args:
            session: Session to probe

        Returns:
            True if PTY available, False otherwise

        Example:
            >>> if detector.check_pty_status(session):
            ...     print("PTY already available, no upgrade needed")
            >>> else:
            ...     print("Upgrade required for full TTY")
        """
        # Check tty command
        output = self._execute_command(session, 'tty')

        if output:
            output_lower = output.lower()
            # If we see /dev/pts/X or /dev/ttyX, we have a PTY
            if '/dev/pts/' in output or '/dev/tty' in output:
                return True
            # "not a tty" means no PTY
            if 'not a tty' in output_lower:
                return False

        # Try stty (fails without PTY)
        output = self._execute_command(session, 'stty -a')
        if output and 'rows' in output.lower() and 'columns' in output.lower():
            return True

        return False

    def get_terminal_size(self, session: Session) -> Optional[Dict[str, int]]:
        """Get current terminal size.

        Args:
            session: Session to probe

        Returns:
            Dict with 'rows' and 'cols' keys, or None if unable to detect

        Example:
            >>> size = detector.get_terminal_size(session)
            >>> if size:
            ...     print(f"Terminal: {size['rows']}x{size['cols']}")
        """
        output = self._execute_command(session, 'stty size')

        if output and len(output.split()) == 2:
            try:
                rows, cols = output.split()
                return {'rows': int(rows), 'cols': int(cols)}
            except ValueError:
                pass

        return None

    def _execute_command(self, session: Session, command: str) -> str:
        """Execute command and return output.

        Args:
            session: Session to execute on
            command: Command to execute

        Returns:
            Command output (stdout), or empty string on error
        """
        if self.command_executor:
            # Use injected executor (for testing)
            return self.command_executor(session, command)

        # TODO: Real implementation will use session's command execution
        # For now, return empty string
        # In production: session.execute_command(command)
        return ""

    def quick_detect(self, session: Session) -> Dict[str, Any]:
        """Quick detection for essential info only.

        Faster than full detect_capabilities(), only checks:
        - Shell type
        - OS type
        - PTY status

        Args:
            session: Session to probe

        Returns:
            Dict with 'shell_type', 'os_type', 'has_pty' keys

        Example:
            >>> info = detector.quick_detect(session)
            >>> if not info['has_pty']:
            ...     print("Upgrade needed")
        """
        return {
            'shell_type': self.detect_shell(session),
            'os_type': self.detect_os(session),
            'has_pty': self.check_pty_status(session)
        }
