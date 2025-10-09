"""
Shell multiplexing with tmux/screen.

Provides:
- tmux session wrapping
- screen session wrapping
- Parallel pane management
- Session persistence across disconnects

OSCP Use Cases:
- Run linpeas while manually enumerating
- Keep multiple enumeration tasks running in parallel
- Persist sessions across network interruptions
"""

import logging
from typing import Optional, List, Dict, Any
from ..models import Session

logger = logging.getLogger(__name__)


class ShellMultiplexer:
    """Shell multiplexing with tmux/screen.

    Wraps shell sessions in terminal multiplexers for:
    - Session persistence
    - Multiple panes/windows
    - Parallel command execution
    - Easy switching between tasks

    Example:
        >>> multiplexer = ShellMultiplexer()
        >>> session = Session(type='tcp', target='192.168.45.150', port=4444)
        >>>
        >>> # Wrap in tmux
        >>> if multiplexer.multiplex_tmux(session):
        ...     print("Session wrapped in tmux")
        >>>
        >>> # Create parallel pane
        >>> multiplexer.create_parallel_pane(session)
    """

    def __init__(self, command_executor=None):
        """Initialize multiplexer.

        Args:
            command_executor: Optional command executor (for testing)
        """
        self.command_executor = command_executor

    def multiplex_tmux(self, session: Session, session_name: Optional[str] = None) -> bool:
        """Wrap session in tmux.

        Benefits:
        - Session persistence across disconnects
        - Multiple panes for parallel commands
        - Scroll-back buffer
        - Easy detach/reattach

        Args:
            session: Session to wrap
            session_name: Optional tmux session name (auto-generated if None)

        Returns:
            True if tmux session created

        OSCP Manual Steps:
            ```bash
            # On victim shell:
            tmux new -s crack_session

            # Detach: Ctrl+B, then D
            # Reattach: tmux attach -t crack_session

            # Split horizontal: Ctrl+B, then %
            # Split vertical: Ctrl+B, then "
            # Switch panes: Ctrl+B, then arrow keys
            ```

        Example:
            >>> if multiplexer.multiplex_tmux(session):
            ...     print("Tmux session created - detach with Ctrl+B D")
        """
        logger.info(f"Creating tmux session for {session.id[:8]}")

        # Check if tmux available
        if not self._check_tool(session, 'tmux'):
            logger.warning("tmux not available on target")
            return False

        # Generate session name
        if not session_name:
            session_name = f"crack_{session.id[:8]}"

        # Start tmux session
        command = f'tmux new -s {session_name}'
        success = self._execute_command(session, command)

        if success:
            logger.info(f"Tmux session created: {session_name}")
            # Store tmux session name in metadata
            session.metadata['tmux_session'] = session_name
            return True

        return False

    def multiplex_screen(self, session: Session, session_name: Optional[str] = None) -> bool:
        """Wrap session in screen.

        Alternative to tmux. Older but more widely available.

        Args:
            session: Session to wrap
            session_name: Optional screen session name (auto-generated if None)

        Returns:
            True if screen session created

        OSCP Manual Steps:
            ```bash
            # On victim shell:
            screen -S crack_session

            # Detach: Ctrl+A, then D
            # Reattach: screen -r crack_session

            # New window: Ctrl+A, then C
            # Next window: Ctrl+A, then N
            # List windows: Ctrl+A, then "
            ```

        Example:
            >>> if multiplexer.multiplex_screen(session):
            ...     print("Screen session created - detach with Ctrl+A D")
        """
        logger.info(f"Creating screen session for {session.id[:8]}")

        # Check if screen available
        if not self._check_tool(session, 'screen'):
            logger.warning("screen not available on target")
            return False

        # Generate session name
        if not session_name:
            session_name = f"crack_{session.id[:8]}"

        # Start screen session
        command = f'screen -S {session_name}'
        success = self._execute_command(session, command)

        if success:
            logger.info(f"Screen session created: {session_name}")
            # Store screen session name in metadata
            session.metadata['screen_session'] = session_name
            return True

        return False

    def create_parallel_pane(self, session: Session, direction: str = 'horizontal') -> bool:
        """Create parallel tmux pane.

        Use case: Run linpeas in one pane, enumerate in another.

        Args:
            session: Session with tmux
            direction: Split direction ('horizontal' or 'vertical')

        Returns:
            True if pane created

        OSCP Manual:
            ```bash
            # Horizontal split (side by side):
            Ctrl+B, then %

            # Vertical split (top/bottom):
            Ctrl+B, then "

            # Switch panes:
            Ctrl+B, then arrow keys
            ```

        Example:
            >>> # Create side-by-side panes
            >>> if multiplexer.create_parallel_pane(session, 'horizontal'):
            ...     print("Horizontal pane created")
            >>>     print("Run linpeas in one, enumerate in other")
        """
        logger.info(f"Creating {direction} pane")

        # Check if in tmux session
        if 'tmux_session' not in session.metadata:
            logger.warning("Not in tmux session - call multiplex_tmux() first")
            return False

        # Tmux split commands
        if direction == 'horizontal':
            command = 'tmux split-window -h'
        elif direction == 'vertical':
            command = 'tmux split-window -v'
        else:
            logger.error(f"Invalid direction: {direction}")
            return False

        success = self._execute_command(session, command)

        if success:
            logger.info(f"{direction.capitalize()} pane created")
            return True

        return False

    def list_tmux_sessions(self, session: Session) -> List[str]:
        """List tmux sessions on target.

        Args:
            session: Session to query

        Returns:
            List of tmux session names

        Example:
            >>> sessions = multiplexer.list_tmux_sessions(session)
            >>> for name in sessions:
            ...     print(f"Tmux session: {name}")
        """
        logger.debug("Listing tmux sessions")

        # Check if tmux available
        if not self._check_tool(session, 'tmux'):
            return []

        # List sessions
        command = 'tmux list-sessions -F "#{session_name}"'
        output = self._execute_command_with_output(session, command)

        if output:
            return [line.strip() for line in output.split('\n') if line.strip()]

        return []

    def list_screen_sessions(self, session: Session) -> List[str]:
        """List screen sessions on target.

        Args:
            session: Session to query

        Returns:
            List of screen session names

        Example:
            >>> sessions = multiplexer.list_screen_sessions(session)
            >>> for name in sessions:
            ...     print(f"Screen session: {name}")
        """
        logger.debug("Listing screen sessions")

        # Check if screen available
        if not self._check_tool(session, 'screen'):
            return []

        # List sessions
        command = 'screen -ls'
        output = self._execute_command_with_output(session, command)

        if output:
            # Parse screen -ls output
            # Format: "12345.session_name"
            sessions = []
            for line in output.split('\n'):
                if '.crack_' in line:
                    parts = line.strip().split('.')
                    if len(parts) > 1:
                        sessions.append(parts[1].split()[0])
            return sessions

        return []

    def attach_tmux(self, session: Session, session_name: str) -> bool:
        """Attach to existing tmux session.

        Args:
            session: Session to use
            session_name: Tmux session name

        Returns:
            True if attached

        Example:
            >>> if multiplexer.attach_tmux(session, 'crack_abc123'):
            ...     print("Attached to tmux session")
        """
        logger.info(f"Attaching to tmux session: {session_name}")

        command = f'tmux attach -t {session_name}'
        success = self._execute_command(session, command)

        if success:
            session.metadata['tmux_session'] = session_name
            return True

        return False

    def attach_screen(self, session: Session, session_name: str) -> bool:
        """Attach to existing screen session.

        Args:
            session: Session to use
            session_name: Screen session name

        Returns:
            True if attached

        Example:
            >>> if multiplexer.attach_screen(session, 'crack_abc123'):
            ...     print("Attached to screen session")
        """
        logger.info(f"Attaching to screen session: {session_name}")

        command = f'screen -r {session_name}'
        success = self._execute_command(session, command)

        if success:
            session.metadata['screen_session'] = session_name
            return True

        return False

    def send_keys_to_pane(self, session: Session, keys: str, pane_index: int = 0) -> bool:
        """Send keys to specific tmux pane.

        Useful for automating commands in parallel panes.

        Args:
            session: Session with tmux
            keys: Keys to send
            pane_index: Pane index (0, 1, 2, etc.)

        Returns:
            True if keys sent

        Example:
            >>> # Send command to pane 1
            >>> multiplexer.send_keys_to_pane(session, './linpeas.sh\\n', 1)
        """
        logger.debug(f"Sending keys to pane {pane_index}: {keys}")

        command = f'tmux send-keys -t {pane_index} "{keys}"'
        return self._execute_command(session, command)

    def _check_tool(self, session: Session, tool: str) -> bool:
        """Check if tool exists.

        Args:
            session: Session to check
            tool: Tool name

        Returns:
            True if tool found
        """
        # Delegate to detector if available
        if hasattr(session, 'capabilities') and session.capabilities:
            return tool in session.capabilities.detected_tools

        # Fallback: assume available
        return True

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

        # TODO: Real implementation
        return True

    def _execute_command_with_output(self, session: Session, command: str) -> str:
        """Execute command and return output.

        Args:
            session: Session to execute on
            command: Command to execute

        Returns:
            Command output
        """
        if self.command_executor:
            # Use injected executor (for testing)
            return self.command_executor(session, command) or ""

        # TODO: Real implementation
        return ""

    def get_multiplexer_guide(self) -> Dict[str, Any]:
        """Get multiplexer usage guide.

        Returns:
            Dict with tmux/screen reference

        Example:
            >>> guide = multiplexer.get_multiplexer_guide()
            >>> for cmd in guide['tmux']['commands']:
            ...     print(f"{cmd['action']}: {cmd['keys']}")
        """
        return {
            'tmux': {
                'name': 'Tmux Terminal Multiplexer',
                'prefix': 'Ctrl+B',
                'commands': [
                    {'action': 'New session', 'keys': 'tmux new -s NAME'},
                    {'action': 'Detach', 'keys': 'Ctrl+B, D'},
                    {'action': 'Attach', 'keys': 'tmux attach -t NAME'},
                    {'action': 'List sessions', 'keys': 'tmux list-sessions'},
                    {'action': 'Split horizontal', 'keys': 'Ctrl+B, %'},
                    {'action': 'Split vertical', 'keys': 'Ctrl+B, "'},
                    {'action': 'Switch pane', 'keys': 'Ctrl+B, arrow keys'},
                    {'action': 'Close pane', 'keys': 'Ctrl+B, X'},
                    {'action': 'New window', 'keys': 'Ctrl+B, C'},
                    {'action': 'Next window', 'keys': 'Ctrl+B, N'},
                    {'action': 'Previous window', 'keys': 'Ctrl+B, P'}
                ],
                'oscp_use_cases': [
                    'Run linpeas in one pane, manual enumeration in another',
                    'Keep session alive across network interruptions',
                    'Multiple enumeration tasks in parallel windows',
                    'Detach from long-running scans and check back later'
                ]
            },
            'screen': {
                'name': 'Screen Terminal Multiplexer',
                'prefix': 'Ctrl+A',
                'commands': [
                    {'action': 'New session', 'keys': 'screen -S NAME'},
                    {'action': 'Detach', 'keys': 'Ctrl+A, D'},
                    {'action': 'Attach', 'keys': 'screen -r NAME'},
                    {'action': 'List sessions', 'keys': 'screen -ls'},
                    {'action': 'New window', 'keys': 'Ctrl+A, C'},
                    {'action': 'Next window', 'keys': 'Ctrl+A, N'},
                    {'action': 'Previous window', 'keys': 'Ctrl+A, P'},
                    {'action': 'List windows', 'keys': 'Ctrl+A, "'},
                    {'action': 'Kill window', 'keys': 'Ctrl+A, K'}
                ],
                'oscp_use_cases': [
                    'Older systems may only have screen, not tmux',
                    'Similar use cases to tmux but older interface',
                    'Session persistence for long-running tasks'
                ]
            },
            'comparison': {
                'tmux': 'More modern, better pane management, more active development',
                'screen': 'Older, more widely available, simpler interface',
                'recommendation': 'Use tmux if available, fall back to screen'
            }
        }
