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
    def detect(self, port_info: Dict[str, Any], profile: 'TargetProfile') -> float:
        """Determine if this plugin can handle this port/service

        Args:
            port_info: Port information dict with keys: port, state, service, version
            profile: Target profile for accessing findings, task progress, etc.

        Returns:
            Confidence score (0-100) that this plugin should handle this port
            - 0: Cannot handle this service
            - 1-30: Low confidence (might handle if no better match)
            - 31-70: Medium confidence (likely match)
            - 71-90: High confidence (strong match)
            - 91-100: Perfect match (exact version/service match)

            For backward compatibility, can still return bool (True=100, False=0)
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

    def detect_from_finding(self, finding: Dict[str, Any], profile: Optional['TargetProfile'] = None) -> float:
        """Determine if this plugin should activate based on a finding

        This method enables context-aware plugin activation beyond port-based detection.
        Plugins should override this method if they want to activate based on findings
        (e.g., shell obtained, OS detected, CMS discovered, credentials found).

        Args:
            finding: Finding dictionary with keys:
                - type: Finding type (e.g., 'shell_obtained', 'cms_wordpress')
                - description: Human-readable description
                - source: Tool/method that discovered the finding
                - timestamp: When the finding was made
            profile: Optional TargetProfile for additional context (OS, services, etc.)

        Returns:
            Confidence score (0-100) that this plugin should handle this finding:
            - 0: Cannot handle this finding (default)
            - 1-30: Low confidence
            - 31-70: Medium confidence
            - 71-90: High confidence
            - 91-100: Perfect match

        Examples:
            # Post-exploit plugin activates on shell obtained
            if finding.get('type') == 'shell_obtained':
                return 100

            # WordPress plugin activates on CMS detection
            if finding.get('type') == 'cms_wordpress':
                return 95

        Note:
            Default implementation returns 0 (plugins opt-in to finding-based activation).
            This ensures backward compatibility with existing plugins.
        """
        return 0

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
