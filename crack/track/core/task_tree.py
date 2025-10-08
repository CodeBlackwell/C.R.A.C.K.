"""
Hierarchical task tree system

Tasks can have children (subtasks) and dynamically grow based on findings.
Tasks can be marked as pending, in-progress, completed, or skipped.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from .events import EventBus


class TaskNode:
    """Self-managing hierarchical task node"""

    def __init__(
        self,
        task_id: str,
        name: str,
        task_type: str = 'command',
        parent: 'TaskNode' = None
    ):
        """
        Args:
            task_id: Unique identifier
            name: Human-readable name
            task_type: Type of task (command, research, manual, parent)
            parent: Parent task node
        """
        self.id = task_id
        self.name = name
        self.type = task_type
        self.status = 'pending'  # pending, in-progress, completed, skipped
        self.children: List[TaskNode] = []
        self.parent = parent

        # Metadata
        self.metadata: Dict[str, Any] = {
            'command': None,
            'description': None,
            'spawned_by': None,
            'depends_on': [],  # List of task IDs
            'tags': [],
            'created_at': datetime.now().isoformat(),
            'completed_at': None,
            'notes': []
        }

    def add_child(self, child_task: 'TaskNode') -> 'TaskNode':
        """Add subtask to this task

        Args:
            child_task: Child task node

        Returns:
            The child task (for chaining)
        """
        child_task.parent = self
        self.children.append(child_task)
        EventBus.emit('task_added', {'task': child_task, 'parent': self})
        return child_task

    def mark_complete(self):
        """Mark task as completed and check parent completion"""
        self.status = 'completed'
        self.metadata['completed_at'] = datetime.now().isoformat()

        # Emit completion event
        EventBus.emit('task_completed', {'task': self})

        # Check if parent task is now complete (all children done)
        if self.parent and self.parent.type == 'parent':
            if all(c.status == 'completed' for c in self.parent.children):
                self.parent.mark_complete()

    def mark_skipped(self, reason: str = None):
        """Mark task as skipped"""
        self.status = 'skipped'
        if reason:
            self.metadata['notes'].append(f"Skipped: {reason}")

    def mark_completed(self):
        """Alias for mark_complete() for backwards compatibility"""
        return self.mark_complete()

    def add_note(self, note: str):
        """Add note to task"""
        self.metadata['notes'].append({
            'timestamp': datetime.now().isoformat(),
            'note': note
        })

    def get_next_actionable(self, root_node: Optional['TaskNode'] = None) -> Optional['TaskNode']:
        """Find next pending leaf task (DFS) with dependency checking

        Args:
            root_node: Root of the task tree (for dependency resolution)

        Returns:
            Next actionable task or None
        """
        # If this is a pending leaf task, check dependencies
        if self.status == 'pending' and not self.children:
            # Check if all dependencies are completed
            if self._dependencies_satisfied(root_node):
                return self

        # Otherwise, check children
        for child in self.children:
            next_task = child.get_next_actionable(root_node or self._find_root())
            if next_task:
                return next_task

        return None

    def _dependencies_satisfied(self, root_node: Optional['TaskNode'] = None) -> bool:
        """Check if all task dependencies are satisfied

        Args:
            root_node: Root node for finding dependencies

        Returns:
            True if all dependencies are completed or if no dependencies exist
        """
        depends_on = self.metadata.get('depends_on', [])
        if not depends_on:
            return True

        # Find root if not provided
        if not root_node:
            root_node = self._find_root()

        # Check each dependency
        for dep_id in depends_on:
            dep_task = root_node.find_task(dep_id) if root_node else None
            if dep_task and dep_task.status != 'completed':
                return False

        return True

    def _find_root(self) -> 'TaskNode':
        """Find the root node of this task tree

        Returns:
            Root TaskNode
        """
        current = self
        while current.parent:
            current = current.parent
        return current

    def get_all_pending(self) -> List['TaskNode']:
        """Get all pending tasks in subtree"""
        pending = []

        if self.status == 'pending':
            pending.append(self)

        for child in self.children:
            pending.extend(child.get_all_pending())

        return pending

    def get_all_completed(self) -> List['TaskNode']:
        """Get all completed tasks in subtree"""
        completed = []

        if self.status == 'completed':
            completed.append(self)

        for child in self.children:
            completed.extend(child.get_all_completed())

        return completed

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'type': self.type,
            'status': self.status,
            'metadata': self.metadata,
            'children': [child.to_dict() for child in self.children]
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], parent: 'TaskNode' = None) -> 'TaskNode':
        """Deserialize from dictionary"""
        task = cls(
            task_id=data['id'],
            name=data['name'],
            task_type=data['type'],
            parent=parent
        )
        task.status = data['status']
        task.metadata = data['metadata']

        # Recursively create children
        for child_data in data.get('children', []):
            child = cls.from_dict(child_data, parent=task)
            task.children.append(child)

        return task

    def find_task(self, task_id: str) -> Optional['TaskNode']:
        """Find task by ID in subtree

        Args:
            task_id: Task ID to find

        Returns:
            TaskNode if found, None otherwise
        """
        if self.id == task_id:
            return self

        for child in self.children:
            found = child.find_task(task_id)
            if found:
                return found

        return None

    def get_depth(self) -> int:
        """Get depth of this task in tree (0 = root)"""
        depth = 0
        current = self.parent
        while current:
            depth += 1
            current = current.parent
        return depth

    def start_timer(self):
        """Start timing this task"""
        if 'start_time' not in self.metadata:
            self.metadata['start_time'] = datetime.now().isoformat()

    def stop_timer(self):
        """Stop timing and calculate duration"""
        if 'start_time' in self.metadata and 'end_time' not in self.metadata:
            self.metadata['end_time'] = datetime.now().isoformat()

            # Calculate duration in seconds
            start = datetime.fromisoformat(self.metadata['start_time'])
            end = datetime.fromisoformat(self.metadata['end_time'])
            self.metadata['duration_seconds'] = int((end - start).total_seconds())

    def get_duration(self) -> Optional[int]:
        """Get task duration in seconds"""
        return self.metadata.get('duration_seconds')

    def get_formatted_duration(self) -> str:
        """Get human-readable duration"""
        duration = self.get_duration()
        if duration is None:
            # Check if still running
            if 'start_time' in self.metadata and 'end_time' not in self.metadata:
                start = datetime.fromisoformat(self.metadata['start_time'])
                elapsed = int((datetime.now() - start).total_seconds())
                hours = elapsed // 3600
                minutes = (elapsed % 3600) // 60
                seconds = elapsed % 60
                return f"{hours:02d}:{minutes:02d}:{seconds:02d} (running)"
            return "Not timed"

        hours = duration // 3600
        minutes = (duration % 3600) // 60
        seconds = duration % 60
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def get_progress(self) -> Dict[str, int]:
        """Get progress statistics for this subtree"""
        all_tasks = self._get_all_descendants()
        all_tasks.append(self)

        return {
            'total': len(all_tasks),
            'completed': len([t for t in all_tasks if t.status == 'completed']),
            'in_progress': len([t for t in all_tasks if t.status == 'in-progress']),
            'pending': len([t for t in all_tasks if t.status == 'pending']),
            'skipped': len([t for t in all_tasks if t.status == 'skipped'])
        }

    def _get_all_descendants(self) -> List['TaskNode']:
        """Get all descendant tasks"""
        descendants = []
        for child in self.children:
            descendants.append(child)
            descendants.extend(child._get_all_descendants())
        return descendants

    def __repr__(self):
        return f"<TaskNode id={self.id} name={self.name} status={self.status} children={len(self.children)}>"
