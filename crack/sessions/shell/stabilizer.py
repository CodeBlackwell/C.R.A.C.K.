"""
Shell stabilization after upgrade.

Applies post-upgrade fixes:
- Terminal size configuration
- Environment variables (TERM, SHELL, etc.)
- Signal handling (Ctrl+C safe)
- History configuration
- Custom prompt

OPSEC Features:
- History disabling (no command artifacts)
- Clean prompt for screenshots
"""

import logging
import subprocess
from typing import Optional, Dict, Any
from ..models import Session
from ..config import SessionConfig
from ..events import EventBus, SessionEvent

logger = logging.getLogger(__name__)


class ShellStabilizer:
    """Shell stabilization after PTY upgrade.

    Applies finishing touches to make upgraded shell fully functional:
    - Fixes terminal size to match local terminal
    - Sets environment variables (TERM, SHELL)
    - Configures signal handling
    - Optionally disables history (OPSEC)

    Example:
        >>> stabilizer = ShellStabilizer()
        >>> session = Session(type='tcp', target='192.168.45.150', port=4444)
        >>>
        >>> # After upgrade
        >>> if stabilizer.stabilize(session):
        ...     print("Shell stabilized - ready for use")
    """

    def __init__(self, config: Optional[SessionConfig] = None,
                 command_executor=None):
        """Initialize stabilizer.

        Args:
            config: SessionConfig instance (creates new if None)
            command_executor: Optional command executor (for testing)
        """
        self.config = config or SessionConfig()
        self.command_executor = command_executor

    def stabilize(self, session: Session, disable_history: bool = True,
                  custom_prompt: bool = True) -> bool:
        """Full shell stabilization.

        Applies all stabilization steps in order:
        1. Fix terminal size
        2. Set TERM variable
        3. Set SHELL variable
        4. Configure signal handling
        5. Disable history (OPSEC)
        6. Set custom prompt

        Args:
            session: Session to stabilize
            disable_history: If True, disable command history (OPSEC)
            custom_prompt: If True, set custom [CRACK] prompt

        Returns:
            True if stabilization successful

        OSCP Manual Steps:
            ```bash
            # After PTY upgrade (in victim shell):
            export TERM=xterm-256color
            export SHELL=/bin/bash
            stty rows 38 cols 116
            stty -echoctl

            # OPSEC: Disable history
            export HISTFILE=/dev/null
            unset HISTFILE
            ```

        Example:
            >>> if stabilizer.stabilize(session):
            ...     print("Shell fully stabilized")
            >>> # With history enabled
            >>> if stabilizer.stabilize(session, disable_history=False):
            ...     print("Stabilized with history enabled")
        """
        logger.info(f"Stabilizing shell for session {session.id[:8]}")

        success = True

        # 1. Fix terminal size
        if not self.fix_terminal_size(session):
            logger.warning("Failed to fix terminal size")
            success = False

        # 2. Set TERM variable
        if not self.set_term_variable(session):
            logger.warning("Failed to set TERM variable")
            success = False

        # 3. Set SHELL variable
        if not self.set_shell_variable(session):
            logger.warning("Failed to set SHELL variable")
            success = False

        # 4. Configure signal handling
        if not self.configure_signal_handling(session):
            logger.warning("Failed to configure signal handling")
            success = False

        # 5. Disable history (OPSEC)
        if disable_history:
            if not self.disable_history(session):
                logger.warning("Failed to disable history")
                # Not critical, continue

        # 6. Set custom prompt
        if custom_prompt:
            if not self.set_custom_prompt(session):
                logger.warning("Failed to set custom prompt")
                # Not critical, continue

        if success:
            # Publish stabilization event
            EventBus.publish(SessionEvent.SESSION_STABILIZED, {
                'session_id': session.id
            })

            logger.info("Shell stabilization complete")

        return success

    def fix_terminal_size(self, session: Session) -> bool:
        """Fix terminal size to match local terminal.

        Detects local terminal size and applies to remote session.

        Args:
            session: Session to fix

        Returns:
            True if size fixed successfully

        Example:
            >>> if stabilizer.fix_terminal_size(session):
            ...     print("Terminal size synchronized")
        """
        logger.debug("Fixing terminal size")

        # Get local terminal size
        local_size = self._get_local_terminal_size()

        if not local_size:
            logger.warning("Could not detect local terminal size")
            # Use default size
            local_size = {'rows': 38, 'cols': 116}

        # Build stty command
        rows = local_size['rows']
        cols = local_size['cols']
        command = f'stty rows {rows} cols {cols}'

        logger.debug(f"Setting terminal size: {rows}x{cols}")

        # Execute command
        return self._execute_command(session, command)

    def set_term_variable(self, session: Session, term: str = 'xterm-256color') -> bool:
        """Set TERM environment variable.

        Args:
            session: Session to configure
            term: Terminal type (default: xterm-256color)

        Returns:
            True if variable set successfully

        Example:
            >>> if stabilizer.set_term_variable(session):
            ...     print("TERM variable set")
        """
        logger.debug(f"Setting TERM={term}")

        command = f'export TERM={term}'
        return self._execute_command(session, command)

    def set_shell_variable(self, session: Session, shell: str = '/bin/bash') -> bool:
        """Set SHELL environment variable.

        Args:
            session: Session to configure
            shell: Shell path (default: /bin/bash)

        Returns:
            True if variable set successfully

        Example:
            >>> if stabilizer.set_shell_variable(session):
            ...     print("SHELL variable set")
        """
        logger.debug(f"Setting SHELL={shell}")

        command = f'export SHELL={shell}'
        return self._execute_command(session, command)

    def configure_signal_handling(self, session: Session) -> bool:
        """Configure signal handling for clean Ctrl+C behavior.

        Prevents ^C from appearing in terminal output.

        Args:
            session: Session to configure

        Returns:
            True if signals configured successfully

        Example:
            >>> if stabilizer.configure_signal_handling(session):
            ...     print("Signals configured - Ctrl+C clean")
        """
        logger.debug("Configuring signal handling")

        # Hide ^C in output
        command = 'stty -echoctl'
        return self._execute_command(session, command)

    def disable_history(self, session: Session) -> bool:
        """Disable command history (OPSEC).

        Prevents command history from being saved to disk,
        reducing forensic artifacts.

        Steps:
            1. Set HISTFILE to /dev/null
            2. Set HISTSIZE to 0
            3. Unset HISTFILE

        Args:
            session: Session to configure

        Returns:
            True if history disabled successfully

        OPSEC Benefit:
            Commands won't be saved to ~/.bash_history,
            reducing forensic footprint.

        Example:
            >>> if stabilizer.disable_history(session):
            ...     print("History disabled - OPSEC active")
        """
        logger.debug("Disabling command history (OPSEC)")

        commands = [
            'export HISTFILE=/dev/null',
            'export HISTSIZE=0',
            'export HISTFILESIZE=0',
            'unset HISTFILE'
        ]

        for cmd in commands:
            if not self._execute_command(session, cmd):
                return False

        logger.info("Command history disabled")
        return True

    def enable_history(self, session: Session) -> bool:
        """Enable command history (reverse disable_history).

        Args:
            session: Session to configure

        Returns:
            True if history enabled successfully

        Example:
            >>> if stabilizer.enable_history(session):
            ...     print("History enabled")
        """
        logger.debug("Enabling command history")

        commands = [
            'export HISTFILE=~/.bash_history',
            'export HISTSIZE=1000',
            'export HISTFILESIZE=2000'
        ]

        for cmd in commands:
            if not self._execute_command(session, cmd):
                return False

        logger.info("Command history enabled")
        return True

    def set_custom_prompt(self, session: Session, prompt: Optional[str] = None) -> bool:
        """Set custom shell prompt.

        Default: Red [CRACK] prefix for easy identification.

        Args:
            session: Session to configure
            prompt: Custom prompt string (None = use default)

        Returns:
            True if prompt set successfully

        Example:
            >>> # Default [CRACK] prompt
            >>> if stabilizer.set_custom_prompt(session):
            ...     print("Custom prompt set")
            >>>
            >>> # Custom prompt
            >>> stabilizer.set_custom_prompt(session, "\\u@\\h:\\w\\$ ")
        """
        if prompt is None:
            # Default: Red [CRACK] prompt
            prompt = r'\[\033[01;31m\][CRACK]\[\033[00m\] \w $ '

        logger.debug(f"Setting custom prompt")

        command = f'export PS1="{prompt}"'
        return self._execute_command(session, command)

    def reset_terminal(self, session: Session) -> bool:
        """Reset terminal to clean state.

        Uses 'reset' command to fully reinitialize terminal.

        Args:
            session: Session to reset

        Returns:
            True if reset successful

        Example:
            >>> if stabilizer.reset_terminal(session):
            ...     print("Terminal reset")
        """
        logger.debug("Resetting terminal")

        command = 'reset'
        return self._execute_command(session, command)

    def apply_bashrc(self, session: Session, bashrc_path: str = '~/.bashrc') -> bool:
        """Apply bashrc configuration.

        Sources bashrc file to apply custom environment.

        Args:
            session: Session to configure
            bashrc_path: Path to bashrc file

        Returns:
            True if bashrc applied successfully

        Example:
            >>> if stabilizer.apply_bashrc(session):
            ...     print("Bashrc applied")
        """
        logger.debug(f"Applying bashrc: {bashrc_path}")

        command = f'source {bashrc_path}'
        return self._execute_command(session, command)

    def _get_local_terminal_size(self) -> Optional[Dict[str, int]]:
        """Get local terminal size.

        Uses stty command to detect size of terminal running
        this code.

        Returns:
            Dict with 'rows' and 'cols', or None if unable to detect
        """
        try:
            result = subprocess.run(
                ['stty', 'size'],
                capture_output=True,
                text=True,
                timeout=2
            )

            if result.returncode == 0 and result.stdout.strip():
                rows, cols = result.stdout.strip().split()
                return {'rows': int(rows), 'cols': int(cols)}

        except (subprocess.TimeoutExpired, ValueError, FileNotFoundError):
            pass

        return None

    def _execute_command(self, session: Session, command: str) -> bool:
        """Execute command on session.

        Args:
            session: Session to execute on
            command: Command to execute

        Returns:
            True if command executed
        """
        if self.command_executor:
            # Use injected executor (for testing)
            self.command_executor(session, command)
            return True

        # TODO: Real implementation will use session's command execution
        # For now, return True
        # In production: return session.execute_command(command)
        return True

    def get_stabilization_checklist(self) -> Dict[str, Any]:
        """Get stabilization checklist for manual execution.

        Returns:
            Dict with manual stabilization steps

        Example:
            >>> checklist = stabilizer.get_stabilization_checklist()
            >>> for step in checklist['steps']:
            ...     print(f"{step['order']}. {step['command']}")
        """
        return {
            'name': 'Shell Stabilization Checklist',
            'description': 'Post-upgrade stabilization steps (OSCP exam safe)',
            'steps': [
                {
                    'order': 1,
                    'name': 'Fix Terminal Size',
                    'command': 'stty rows 38 cols 116',
                    'description': 'Match terminal size to local terminal',
                    'required': True
                },
                {
                    'order': 2,
                    'name': 'Set TERM Variable',
                    'command': 'export TERM=xterm-256color',
                    'description': 'Enable color support and terminal features',
                    'required': True
                },
                {
                    'order': 3,
                    'name': 'Set SHELL Variable',
                    'command': 'export SHELL=/bin/bash',
                    'description': 'Define shell type for subprocesses',
                    'required': True
                },
                {
                    'order': 4,
                    'name': 'Configure Signals',
                    'command': 'stty -echoctl',
                    'description': 'Hide ^C in terminal output',
                    'required': False
                },
                {
                    'order': 5,
                    'name': 'Disable History (OPSEC)',
                    'command': 'export HISTFILE=/dev/null; unset HISTFILE',
                    'description': 'Prevent command history artifacts',
                    'required': False,
                    'opsec': True
                },
                {
                    'order': 6,
                    'name': 'Custom Prompt',
                    'command': 'export PS1="\\[\\033[01;31m\\][CRACK]\\[\\033[00m\\] \\w $ "',
                    'description': 'Set custom prompt for identification',
                    'required': False
                }
            ],
            'oscp_safe': True,
            'time_estimate': '1-2 minutes'
        }
