"""
Base service plugin class

Service plugins are self-contained modules that:
1. Detect if they can handle a port/service
2. Generate task trees for enumeration
3. Parse results and spawn additional tasks
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional


class ServicePlugin(ABC):
    """Base class for service-specific enumeration plugins"""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique service identifier (http, smb, ssh, etc.)"""
        pass

    @property
    def default_ports(self) -> List[int]:
        """Common ports for this service (optional)

        Returns:
            List of port numbers
        """
        return []

    @property
    def service_names(self) -> List[str]:
        """Service names this plugin handles

        Returns:
            List of service name variations (e.g., ['http', 'https', 'http-proxy'])
        """
        return [self.name]

    @abstractmethod
    def detect(self, port_info: Dict[str, Any]) -> bool:
        """Determine if this plugin can handle this port/service

        Args:
            port_info: Port information dict with keys: port, state, service, version

        Returns:
            True if this plugin should handle this port
        """
        pass

    @abstractmethod
    def get_task_tree(self, target: str, port: int, service_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate task tree for this service

        Args:
            target: Target IP/hostname
            port: Port number
            service_info: Service information dict

        Returns:
            Task definition dict with structure:
            {
                'id': 'task-id',
                'name': 'Task Name',
                'type': 'parent',
                'children': [...]
            }
        """
        pass

    def on_task_complete(self, task_id: str, result: str, target: str) -> List[Dict[str, Any]]:
        """Parse tool output and potentially spawn new tasks

        Args:
            task_id: Completed task ID
            result: Tool output/result
            target: Target IP/hostname

        Returns:
            List of new task definitions to add
        """
        return []

    def get_manual_alternatives(self, task_id: str) -> List[str]:
        """Get manual alternatives for automated tasks (OSCP exam preparation)

        Args:
            task_id: Task ID

        Returns:
            List of manual command alternatives
        """
        return []

    def __repr__(self):
        return f"<ServicePlugin name={self.name}>"
