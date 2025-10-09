"""
Listener registry for tracking active listeners and preventing port conflicts

Storage: ~/.crack/sessions/listeners.json
"""

import json
import os
import signal
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional


class ListenerRegistry:
    """Registry for active listeners

    Features:
    - Track active listeners (prevent port conflicts)
    - PID validation (check if process still alive)
    - Port conflict detection
    - Automatic cleanup of stale listeners
    """

    DEFAULT_PATH = Path.home() / ".crack" / "sessions" / "listeners.json"

    def __init__(self, registry_path: Optional[Path] = None):
        """Initialize listener registry

        Args:
            registry_path: Optional custom registry file path
        """
        self.registry_path = registry_path or self.DEFAULT_PATH
        self._ensure_registry_file()

    def _ensure_registry_file(self):
        """Create registry file if it doesn't exist"""
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)

        if not self.registry_path.exists():
            self._save_registry({'listeners': []})

    def _load_registry(self) -> Dict[str, Any]:
        """Load registry from disk

        Returns:
            Registry dictionary
        """
        try:
            with open(self.registry_path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            # Return empty registry on error
            return {'listeners': []}

    def _save_registry(self, data: Dict[str, Any]):
        """Save registry to disk atomically

        Args:
            data: Registry data dictionary
        """
        # Atomic write
        temp_path = self.registry_path.with_suffix('.json.tmp')

        with open(temp_path, 'w') as f:
            json.dump(data, f, indent=2)

        os.replace(temp_path, self.registry_path)

    def _is_process_alive(self, pid: int) -> bool:
        """Check if process is still running

        Args:
            pid: Process ID to check

        Returns:
            True if process is alive
        """
        if pid <= 0:
            return False

        try:
            # Check /proc/<pid> on Linux
            proc_path = Path(f"/proc/{pid}")
            if proc_path.exists():
                return True

            # Fallback: send signal 0 (doesn't actually signal, just checks existence)
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False

    def _serialize_listener(self, listener: Any) -> Dict[str, Any]:
        """Serialize listener object to dictionary

        Args:
            listener: Listener object

        Returns:
            Dictionary representation
        """
        if hasattr(listener, 'to_dict'):
            return listener.to_dict()
        elif hasattr(listener, '__dict__'):
            data = {}
            for key, value in listener.__dict__.items():
                if key.startswith('_'):
                    continue
                if isinstance(value, datetime):
                    data[key] = value.isoformat()
                else:
                    data[key] = value
            return data
        else:
            raise ValueError("Listener must have to_dict() or __dict__")

    def register_listener(self, listener: Any) -> bool:
        """Register a new listener

        Args:
            listener: Listener object with 'id', 'port', 'pid' attributes

        Returns:
            True if registered successfully

        Raises:
            ValueError: If listener missing required attributes
            RuntimeError: If port already in use
        """
        # Validate listener
        if not hasattr(listener, 'id'):
            raise ValueError("Listener must have 'id' attribute")
        if not hasattr(listener, 'port'):
            raise ValueError("Listener must have 'port' attribute")

        # Check for port conflicts
        existing = self.get_listener_by_port(listener.port)
        if existing:
            raise RuntimeError(
                f"Port {listener.port} already in use by listener {existing['id']} "
                f"(PID: {existing.get('pid', 'unknown')})"
            )

        # Load registry
        registry = self._load_registry()

        # Serialize listener
        listener_data = self._serialize_listener(listener)

        # Add registration timestamp
        listener_data['registered_at'] = datetime.now().isoformat()

        # Add to registry
        registry['listeners'].append(listener_data)

        # Save
        self._save_registry(registry)

        return True

    def unregister_listener(self, listener_id: str) -> bool:
        """Unregister a listener

        Args:
            listener_id: Listener identifier

        Returns:
            True if unregistered, False if not found
        """
        registry = self._load_registry()

        # Find and remove listener
        original_count = len(registry['listeners'])
        registry['listeners'] = [
            l for l in registry['listeners']
            if l.get('id') != listener_id
        ]

        # Check if anything was removed
        removed = len(registry['listeners']) < original_count

        if removed:
            self._save_registry(registry)

        return removed

    def get_listener(self, listener_id: str) -> Optional[Dict[str, Any]]:
        """Get listener by ID

        Args:
            listener_id: Listener identifier

        Returns:
            Listener dictionary or None if not found
        """
        registry = self._load_registry()

        for listener in registry['listeners']:
            if listener.get('id') == listener_id:
                return listener

        return None

    def get_listener_by_port(self, port: int) -> Optional[Dict[str, Any]]:
        """Get listener by port number

        Args:
            port: Port number

        Returns:
            Listener dictionary or None if not found
        """
        registry = self._load_registry()

        for listener in registry['listeners']:
            if listener.get('port') == port:
                # Verify process is still alive
                pid = listener.get('pid')
                if pid and self._is_process_alive(pid):
                    return listener
                # Process dead, remove stale entry
                self.unregister_listener(listener.get('id'))
                return None

        return None

    def list_active_listeners(self) -> List[Dict[str, Any]]:
        """List all active listeners

        Only returns listeners whose processes are still alive

        Returns:
            List of active listener dictionaries
        """
        registry = self._load_registry()
        active_listeners = []

        for listener in registry['listeners']:
            pid = listener.get('pid')

            # Check if process is alive
            if pid and self._is_process_alive(pid):
                active_listeners.append(listener)

        return active_listeners

    def cleanup_stale_listeners(self) -> int:
        """Remove listeners whose processes are no longer running

        Returns:
            Number of stale listeners removed
        """
        registry = self._load_registry()
        original_count = len(registry['listeners'])

        # Keep only listeners with alive processes
        active_listeners = []
        for listener in registry['listeners']:
            pid = listener.get('pid')

            if pid and self._is_process_alive(pid):
                active_listeners.append(listener)
            # Else: skip (remove) this listener

        registry['listeners'] = active_listeners

        removed_count = original_count - len(active_listeners)

        if removed_count > 0:
            self._save_registry(registry)

        return removed_count

    def is_port_available(self, port: int) -> bool:
        """Check if a port is available

        Args:
            port: Port number to check

        Returns:
            True if port is available (not in registry or process dead)
        """
        return self.get_listener_by_port(port) is None

    def get_next_available_port(self, start_port: int = 4444, max_attempts: int = 100) -> Optional[int]:
        """Find next available port

        Args:
            start_port: Port to start searching from
            max_attempts: Maximum number of ports to try

        Returns:
            Next available port or None if none found
        """
        for offset in range(max_attempts):
            port = start_port + offset
            if self.is_port_available(port):
                return port

        return None

    def get_registry_stats(self) -> Dict[str, Any]:
        """Get registry statistics

        Returns:
            Dictionary with registry stats
        """
        registry = self._load_registry()
        all_listeners = registry.get('listeners', [])
        active_listeners = self.list_active_listeners()

        return {
            'total_registered': len(all_listeners),
            'active': len(active_listeners),
            'stale': len(all_listeners) - len(active_listeners),
            'registry_path': str(self.registry_path)
        }
