"""
Task Filter - Minimal filter system for tasks

Filter Syntax:
- port:80 - Filter by port number
- port:80,443 - Multiple ports (OR logic)
- status:pending - Task status
- service:http - Service name
- tag:QUICK_WIN - Tag name
- Combined: port:80 status:pending (AND logic)

Implementation: <80 lines, regex parser, reuse existing components
"""

import re
from typing import List, Dict, Optional
from ..core.task_tree import TaskNode


class TaskFilter:
    """Parse and apply task filters (minimal implementation)"""

    def __init__(self, filter_str: str):
        """
        Parse filter string

        Args:
            filter_str: Filter expression (e.g., "port:80 status:pending")
        """
        self.raw = filter_str.strip()
        self.criteria = self._parse(self.raw)

    def _parse(self, filter_str: str) -> Dict[str, List[str]]:
        """
        Parse filter string into criteria dict

        Returns:
            Dict with keys: ports, statuses, services, tags
        """
        criteria = {
            'ports': [],
            'statuses': [],
            'services': [],
            'tags': []
        }

        if not filter_str:
            return criteria

        # Pattern: key:value (handles comma-separated values)
        pattern = r'(\w+):([^\s]+)'
        matches = re.findall(pattern, filter_str)

        for key, value in matches:
            key_lower = key.lower()

            if key_lower == 'port':
                # Handle comma-separated ports
                ports = value.split(',')
                criteria['ports'].extend([p.strip() for p in ports if p.strip()])
            elif key_lower == 'status':
                criteria['statuses'].append(value.lower())
            elif key_lower == 'service':
                criteria['services'].append(value.lower())
            elif key_lower == 'tag':
                criteria['tags'].append(value.upper())

        return criteria

    def matches(self, task: TaskNode) -> bool:
        """
        Check if task matches all criteria (AND logic)

        Args:
            task: TaskNode to check

        Returns:
            True if task matches all criteria
        """
        # Port filter
        if self.criteria['ports']:
            task_port = task.metadata.get('port')
            if not task_port or str(task_port) not in self.criteria['ports']:
                return False

        # Status filter
        if self.criteria['statuses']:
            if task.status not in self.criteria['statuses']:
                return False

        # Service filter
        if self.criteria['services']:
            task_service = task.metadata.get('service', '').lower()
            if not any(svc in task_service for svc in self.criteria['services']):
                return False

        # Tag filter
        if self.criteria['tags']:
            task_tags = task.metadata.get('tags', [])
            if not any(tag in task_tags for tag in self.criteria['tags']):
                return False

        return True

    def apply(self, tasks: List[TaskNode]) -> List[TaskNode]:
        """
        Filter task list

        Args:
            tasks: List of TaskNode objects

        Returns:
            Filtered list
        """
        return [task for task in tasks if self.matches(task)]
