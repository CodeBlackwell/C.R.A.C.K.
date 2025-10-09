"""
Shell enhancement suite for session management.

Provides comprehensive shell upgrade, stabilization, and multiplexing:

- ShellDetector: Detect shell type, OS, available tools
- ShellUpgrader: Auto-upgrade shells with Python PTY, script, socat, etc.
- ShellStabilizer: Post-upgrade stabilization (terminal size, env vars, OPSEC)
- ShellMultiplexer: Tmux/screen integration for parallel tasks

Legacy:
- TCPShellUpgrader: Original TCP-specific upgrader (deprecated, use ShellUpgrader)

Example:
    >>> from sessions.shell import ShellUpgrader, ShellStabilizer
    >>> from sessions.models import Session
    >>>
    >>> session = Session(type='tcp', target='192.168.45.150', port=4444)
    >>>
    >>> # Auto-upgrade shell
    >>> upgrader = ShellUpgrader()
    >>> if upgrader.upgrade_shell(session, 'auto'):
    ...     print("Shell upgraded!")
    >>>
    >>> # Stabilize
    >>> stabilizer = ShellStabilizer()
    >>> if stabilizer.stabilize(session):
    ...     print("Shell stabilized and ready!")
"""

from .detector import ShellDetector
from .upgrader import ShellUpgrader
from .stabilizer import ShellStabilizer
from .multiplexer import ShellMultiplexer
from .tcp_upgrader import TCPShellUpgrader  # Legacy

__all__ = [
    'ShellDetector',
    'ShellUpgrader',
    'ShellStabilizer',
    'ShellMultiplexer',
    'TCPShellUpgrader'  # Legacy
]
