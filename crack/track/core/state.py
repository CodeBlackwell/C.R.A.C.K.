"""
Target profile state management

Manages the complete state of target enumeration including:
- Discovered ports and services
- Task tree
- Findings and credentials
- Phase progression
"""

from datetime import datetime
from typing import Dict, Any, List, Optional
from .task_tree import TaskNode
from .storage import Storage
from .events import EventBus


class TargetProfile:
    """Complete state for a target"""

    def __init__(self, target: str):
        """
        Args:
            target: Target IP or hostname
        """
        self.target = target
        self.created = datetime.now().isoformat()
        self.updated = datetime.now().isoformat()
        self.phase = 'discovery'
        self.status = 'new'  # new, in-progress, completed

        # Discovered information
        self.ports: Dict[int, Dict[str, Any]] = {}
        self.findings: List[Dict[str, Any]] = []
        self.credentials: List[Dict[str, Any]] = []
        self.notes: List[Dict[str, Any]] = []
        self.imported_files: List[Dict[str, Any]] = []

        # Task tree (root node)
        self.task_tree = TaskNode(
            task_id='root',
            name=f'Enumeration: {target}',
            task_type='parent'
        )

        # Auto-initialize with discovery phase tasks
        # Import here to avoid circular dependency
        from ..phases.registry import PhaseManager
        initial_tasks = PhaseManager.get_initial_tasks(self.phase, target)
        for task in initial_tasks:
            self.task_tree.add_child(task)

        # Initialize service plugins
        from ..services.registry import ServiceRegistry
        ServiceRegistry.initialize_plugins()

        # Listen for plugin-generated tasks
        EventBus.on('plugin_tasks_generated', self._handle_plugin_tasks)

    def _handle_plugin_tasks(self, data: Dict[str, Any]):
        """Handle plugin-generated tasks event

        Args:
            data: Event data containing task_tree (as dict)
        """
        # Only add tasks for this target
        if data.get('target') != self.target:
            return

        task_dict = data.get('task_tree')
        if not task_dict:
            return

        # Ensure dict has required fields for from_dict()
        task_dict = self._normalize_task_dict(task_dict)

        # Convert dict to TaskNode
        task_node = TaskNode.from_dict(task_dict)
        self.task_tree.add_child(task_node)

    def _normalize_task_dict(self, task_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure task dict has all required fields

        Args:
            task_dict: Task dictionary from plugin

        Returns:
            Normalized task dictionary
        """
        # Add defaults for missing fields
        if 'status' not in task_dict:
            task_dict['status'] = 'pending'
        if 'metadata' not in task_dict:
            task_dict['metadata'] = {}

        # Recursively normalize children
        for child in task_dict.get('children', []):
            self._normalize_task_dict(child)

        return task_dict

    def add_port(self, port: int, state: str = 'open', service: str = None, version: str = None, source: str = None, **kwargs):
        """Add or update port information

        Args:
            port: Port number
            state: Port state (open, closed, filtered)
            service: Service name
            version: Service version
            source: Source of information (command, file, manual entry)
            **kwargs: Additional port metadata
        """
        if port not in self.ports:
            self.ports[port] = {}

        self.ports[port].update({
            'state': state,
            'service': service,
            'version': version,
            'source': source or 'N/A',
            'updated_at': datetime.now().isoformat(),
            **kwargs
        })

        self._update_timestamp()

        # Emit events for service plugins
        EventBus.emit('port_discovered', {
            'target': self.target,
            'port': port,
            'state': state
        })

        if service:
            EventBus.emit('service_detected', {
                'target': self.target,
                'port': port,
                'service': service,
                'version': version
            })

        if version:
            EventBus.emit('version_detected', {
                'target': self.target,
                'port': port,
                'service': service,
                'version': version
            })

    def add_finding(self, finding_type: str, description: str, source: str = None, **kwargs):
        """Add enumeration finding

        Args:
            finding_type: Type of finding (vulnerability, directory, user, etc.)
            description: Description of finding
            source: Source command/location (required for tracking)
            **kwargs: Additional metadata
        """
        if not source:
            raise ValueError("Finding source is required for documentation tracking")

        finding = {
            'timestamp': datetime.now().isoformat(),
            'type': finding_type,
            'description': description,
            'source': source,
            **kwargs
        }
        self.findings.append(finding)
        self._update_timestamp()

        EventBus.emit('finding_added', {'finding': finding})

    def add_credential(self, username: str, password: str = None, hash_value: str = None, source: str = None, **kwargs):
        """Add discovered credential

        Args:
            username: Username
            password: Plaintext password (optional)
            hash_value: Password hash (optional)
            source: Source command/location (required for tracking)
            **kwargs: Additional metadata (service, port, etc.)
        """
        if not source:
            raise ValueError("Credential source is required for documentation tracking")

        credential = {
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'password': password,
            'hash': hash_value,
            'source': source,
            **kwargs
        }
        self.credentials.append(credential)
        self._update_timestamp()

    def add_note(self, note: str, **kwargs):
        """Add freeform note

        Args:
            note: Note text
            **kwargs: Additional metadata
        """
        note_entry = {
            'timestamp': datetime.now().isoformat(),
            'note': note,
            **kwargs
        }
        self.notes.append(note_entry)
        self._update_timestamp()

    def add_imported_file(self, filepath: str, file_type: str):
        """Track imported file

        Args:
            filepath: Path to imported file
            file_type: Type of file (nmap, burp, etc.)
        """
        self.imported_files.append({
            'file': filepath,
            'type': file_type,
            'timestamp': datetime.now().isoformat()
        })
        self._update_timestamp()

    def set_phase(self, phase: str):
        """Change enumeration phase

        Args:
            phase: New phase name
        """
        old_phase = self.phase
        self.phase = phase
        self._update_timestamp()

        EventBus.emit('phase_changed', {
            'old_phase': old_phase,
            'new_phase': phase,
            'target': self.target
        })

    def get_task(self, task_id: str) -> Optional[TaskNode]:
        """Find task by ID

        Args:
            task_id: Task ID

        Returns:
            TaskNode if found, None otherwise
        """
        return self.task_tree.find_task(task_id)

    def add_task(self, task: TaskNode, parent_id: str = None):
        """Add task to tree

        Args:
            task: TaskNode to add
            parent_id: Parent task ID (None = root)
        """
        if parent_id:
            parent = self.get_task(parent_id)
            if parent:
                parent.add_child(task)
            else:
                raise ValueError(f"Parent task '{parent_id}' not found")
        else:
            self.task_tree.add_child(task)

        self._update_timestamp()

    def mark_task_done(self, task_id: str):
        """Mark task as completed

        Args:
            task_id: Task ID
        """
        task = self.get_task(task_id)
        if task:
            task.mark_complete()
            self._update_timestamp()
        else:
            raise ValueError(f"Task '{task_id}' not found")

    def get_progress(self) -> Dict[str, int]:
        """Get overall progress statistics"""
        return self.task_tree.get_progress()

    def _update_timestamp(self):
        """Update the 'updated' timestamp"""
        self.updated = datetime.now().isoformat()
        self.status = 'in-progress'

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for storage"""
        return {
            'target': self.target,
            'created': self.created,
            'updated': self.updated,
            'phase': self.phase,
            'status': self.status,
            'ports': self.ports,
            'findings': self.findings,
            'credentials': self.credentials,
            'notes': self.notes,
            'imported_files': self.imported_files,
            'task_tree': self.task_tree.to_dict()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TargetProfile':
        """Deserialize from dictionary (handles old format profiles gracefully)"""
        # Create new profile (this initializes all defaults including task tree)
        profile = cls.__new__(cls)  # Skip __init__ to manually set fields
        profile.target = data['target']

        # Use defaults for missing fields (backward compatibility)
        profile.created = data.get('created', datetime.now().isoformat())
        profile.updated = data.get('updated', datetime.now().isoformat())
        profile.phase = data.get('phase', 'discovery')
        profile.status = data.get('status', 'new')
        profile.ports = data.get('ports', {})

        # Convert port keys back to integers
        profile.ports = {int(k): v for k, v in profile.ports.items()} if profile.ports else {}

        profile.findings = data.get('findings', [])
        profile.credentials = data.get('credentials', [])
        profile.notes = data.get('notes', [])
        profile.imported_files = data.get('imported_files', [])

        # Restore task tree or create new one
        if 'task_tree' in data:
            profile.task_tree = TaskNode.from_dict(data['task_tree'])
        else:
            # Old format without task tree - create default root
            profile.task_tree = TaskNode(
                task_id='root',
                name=f'Enumeration: {profile.target}',
                task_type='parent'
            )

        return profile

    def save(self):
        """Save profile to disk"""
        Storage.save(self.target, self.to_dict())

    @classmethod
    def load(cls, target: str) -> Optional['TargetProfile']:
        """Load profile from disk

        Args:
            target: Target IP or hostname

        Returns:
            TargetProfile if found, None otherwise
        """
        data = Storage.load(target)
        if data:
            return cls.from_dict(data)
        return None

    @classmethod
    def exists(cls, target: str) -> bool:
        """Check if profile exists

        Args:
            target: Target IP or hostname

        Returns:
            True if profile exists
        """
        return Storage.exists(target)

    def __repr__(self):
        return f"<TargetProfile target={self.target} phase={self.phase} ports={len(self.ports)}>"
