"""
Findings Processor - Converts findings into actionable tasks

Bridges the gap between output analysis and task generation.
Listens for finding_added events and generates appropriate follow-up tasks.
"""

from typing import Dict, Any, List, Optional
from ..core.events import EventBus
from ..core.task_tree import TaskNode
import logging

logger = logging.getLogger(__name__)


class FindingsProcessor:
    """Convert findings into actionable tasks"""

    def __init__(self, target: str):
        """
        Initialize findings processor

        Args:
            target: Target IP/hostname
        """
        self.target = target
        self.processed_findings = set()  # Deduplication tracking

        # Register converters for each finding type
        self.converters = {
            'directory': self._convert_directory_finding,
            'directories': self._convert_directory_finding,  # Alias
            'file': self._convert_file_finding,
            'files': self._convert_file_finding,  # Alias
            'credential': self._convert_credential_finding,
            'credentials': self._convert_credential_finding,  # Alias
            'vulnerability': self._convert_vuln_finding,
            'vulnerabilities': self._convert_vuln_finding,  # Alias
            'service': self._convert_service_finding,
            'services': self._convert_service_finding,  # Alias
            'user': self._convert_user_finding,
            'users': self._convert_user_finding,  # Alias
        }

        # Listen for finding_added events
        EventBus.on('finding_added', self.process_finding)

    def process_finding(self, data: Dict[str, Any]):
        """Process finding and generate tasks

        Args:
            data: Event data containing finding dict
        """
        finding = data.get('finding')
        if not finding:
            return

        finding_type = finding.get('type', '').lower()
        description = finding.get('description', '')

        # Create unique fingerprint for deduplication
        fingerprint = f"{finding_type}:{description}"
        if fingerprint in self.processed_findings:
            logger.debug(f"Skipping duplicate finding: {fingerprint}")
            return

        # Mark as processed
        self.processed_findings.add(fingerprint)

        # Convert finding to tasks
        if finding_type in self.converters:
            try:
                tasks = self.converters[finding_type](finding)
                for task in tasks:
                    self._emit_task(task)
            except Exception as e:
                logger.error(f"Error converting finding {finding_type}: {e}")

    def _emit_task(self, task_dict: Dict[str, Any]):
        """Emit task generation event

        Args:
            task_dict: Task definition dictionary
        """
        EventBus.emit('plugin_tasks_generated', {
            'target': self.target,
            'task_tree': task_dict
        })

    def _convert_directory_finding(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert directory finding to tasks

        Args:
            finding: Finding dict

        Returns:
            List of task definitions
        """
        description = finding.get('description', '')
        tasks = []

        # Extract path from description (format: "/admin" or "{'path': '/admin', 'status': 200}")
        path = description
        if isinstance(description, dict):
            path = description.get('path', '')
        elif isinstance(description, str):
            # Try to extract path from string representation
            import re
            match = re.search(r"'path':\s*'([^']+)'", description)
            if match:
                path = match.group(1)
            elif description.startswith('/'):
                path = description.split()[0]

        if not path or not path.startswith('/'):
            return tasks

        # Generate tasks for interesting directories
        interesting_dirs = ['/admin', '/login', '/dashboard', '/config', '/backup',
                           '/upload', '/uploads', '/api', '/console', '/manager']

        if any(interesting in path.lower() for interesting in interesting_dirs):
            task_id = f"dir-inspect-{path.replace('/', '-').strip('-')}"
            tasks.append({
                'id': task_id,
                'name': f"Inspect {path}",
                'type': 'parent',
                'status': 'pending',
                'metadata': {
                    'category': 'web',
                    'description': f'Investigate interesting directory: {path}',
                    'finding_source': finding.get('source', 'Unknown')
                },
                'children': [
                    {
                        'id': f"{task_id}-check",
                        'name': f"Check {path} for common files",
                        'type': 'executable',
                        'status': 'pending',
                        'metadata': {
                            'command': f'curl -s http://{self.target}{path}/',
                            'description': f'Check for index/default files in {path}'
                        }
                    }
                ]
            })

        return tasks

    def _convert_file_finding(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert file finding to tasks

        Args:
            finding: Finding dict

        Returns:
            List of task definitions
        """
        description = finding.get('description', '')
        tasks = []

        # Extract file path
        path = description
        if isinstance(description, dict):
            path = description.get('path', '')

        if not path:
            return tasks

        # Generate tasks for interesting files
        interesting_files = ['.config', '.backup', '.bak', '.sql', '.db',
                            '.env', 'config.php', 'web.config', '.git']

        if any(ext in path.lower() for ext in interesting_files):
            task_id = f"file-fetch-{path.replace('/', '-').strip('-')}"
            tasks.append({
                'id': task_id,
                'name': f"Fetch {path}",
                'type': 'executable',
                'status': 'pending',
                'metadata': {
                    'command': f'curl -s http://{self.target}{path}',
                    'category': 'web',
                    'description': f'Download interesting file: {path}',
                    'finding_source': finding.get('source', 'Unknown')
                }
            })

        return tasks

    def _convert_credential_finding(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert credential finding to tasks

        Args:
            finding: Finding dict

        Returns:
            List of task definitions
        """
        # Credentials are valuable but don't automatically generate tasks
        # They're stored in profile.credentials for manual use
        # Future: Could generate SSH/RDP/SMB login tasks
        logger.info(f"Credential found (manual verification recommended): {finding.get('description')}")
        return []

    def _convert_vuln_finding(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert vulnerability finding to tasks

        Args:
            finding: Finding dict

        Returns:
            List of task definitions
        """
        description = finding.get('description', '')
        tasks = []

        # Extract CVE ID if present
        import re
        cve_match = re.search(r'(CVE-\d{4}-\d{4,})', description, re.IGNORECASE)
        if cve_match:
            cve_id = cve_match.group(1).upper()
            task_id = f"vuln-research-{cve_id.replace('-', '').lower()}"
            tasks.append({
                'id': task_id,
                'name': f"Research {cve_id}",
                'type': 'executable',
                'status': 'pending',
                'metadata': {
                    'command': f'searchsploit {cve_id}',
                    'category': 'exploit',
                    'description': f'Research exploit availability for {cve_id}',
                    'finding_source': finding.get('source', 'Unknown')
                }
            })

        return tasks

    def _convert_service_finding(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert service finding to tasks

        Service findings are typically handled by ServicePlugins via service_detected events.
        This converter is for services discovered AFTER initial enumeration (e.g., from banner grabs).

        Args:
            finding: Finding dict

        Returns:
            List of task definitions
        """
        # Services are handled by service plugins, not findings processor
        # This is a placeholder for future enhancement
        return []

    def _convert_user_finding(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert user finding to tasks

        Args:
            finding: Finding dict

        Returns:
            List of task definitions
        """
        description = finding.get('description', '')
        tasks = []

        # Extract username
        username = description
        if isinstance(description, dict):
            username = description.get('username', '')

        if not username:
            return tasks

        # Generate password guessing task for discovered users
        # (Conservative - only common passwords)
        task_id = f"user-test-{username.replace(' ', '-').lower()}"
        tasks.append({
            'id': task_id,
            'name': f"Test common passwords for {username}",
            'type': 'executable',
            'status': 'pending',
            'metadata': {
                'command': f'# Manual: Try {username}:{username}, {username}:password, {username}:admin',
                'category': 'auth',
                'description': f'Test common passwords for user: {username}',
                'finding_source': finding.get('source', 'Unknown')
            }
        })

        return tasks

    def clear_history(self):
        """Clear processed findings history (for testing/reset)"""
        self.processed_findings.clear()
