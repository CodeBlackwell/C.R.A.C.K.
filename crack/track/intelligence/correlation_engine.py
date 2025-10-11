"""
Correlation Intelligence Engine - Method 1 (Reactive)

Analyzes findings in real-time to detect cross-service correlation opportunities.
Triggers attack chains when vulnerability patterns are detected.

Examples:
- Credential found on MySQL -> Try on SSH, FTP, SMB
- Username enumerated -> Generate password spray tasks
- Technology detected -> Search for version-specific exploits
"""

from typing import Dict, Any, List, Optional
import logging
from ..core.events import EventBus

logger = logging.getLogger(__name__)


class CorrelationIntelligence:
    """Method 1: Reactive event-driven correlation intelligence"""

    # Cross-service correlation patterns
    CREDENTIAL_SPRAY_SERVICES = ['ssh', 'ftp', 'smb', 'rdp', 'telnet', 'mysql', 'postgresql',
                                  'mssql', 'oracle', 'vnc', 'ldap', 'pop3', 'imap']

    # Attack chain triggers
    CHAIN_TRIGGERS = {
        'sql_injection': 'sqli_to_shell',
        'sqli': 'sqli_to_shell',
        'sqli_found': 'sqli_to_shell',
        'lfi': 'lfi_to_rce',
        'lfi_found': 'lfi_to_rce',
        'file_upload': 'upload_to_shell',
        'file_upload_found': 'upload_to_shell',
        'xxe': 'xxe_to_data_exfil',
        'xxe_found': 'xxe_to_data_exfil',
        'deserialization': 'deser_to_rce',
        'deserialization_vulnerability': 'deser_to_rce',
        'deserialization_found': 'deser_to_rce',
        'command_injection': 'cmdi_to_shell',
        'cmdi': 'cmdi_to_shell',
        'cmdi_found': 'cmdi_to_shell',
        'ssti': 'ssti_to_rce',
        'ssti_found': 'ssti_to_rce',
        'rce': 'rce_to_shell',
        'rce_found': 'rce_to_shell'
    }

    def __init__(self, target: str, profile: 'TargetProfile', config: Dict[str, Any]):
        """
        Initialize correlation intelligence engine

        Args:
            target: Target IP/hostname
            profile: TargetProfile instance
            config: Intelligence configuration
        """
        self.target = target
        self.profile = profile
        self.config = config
        self.processed_findings = set()  # Deduplication

        # Register event handlers
        self._register_handlers()

        logger.info(f"[CORRELATION] Initialized for {target}")

    def _register_handlers(self):
        """Register EventBus handlers for correlation"""
        EventBus.on('finding_added', self.on_finding_added)
        logger.debug("[CORRELATION] Event handlers registered")

    def on_finding_added(self, data: Dict[str, Any]):
        """
        Process new findings for correlation opportunities

        Args:
            data: Event data with finding dict
        """
        finding = data.get('finding')
        if not finding:
            logger.debug("[CORRELATION] No finding in event data")
            return

        finding_type = finding.get('type', '').lower()
        description = finding.get('description', '')

        # Deduplicate
        fingerprint = f"{finding_type}:{description}"
        if fingerprint in self.processed_findings:
            logger.debug(f"[CORRELATION] Skipping duplicate: {fingerprint}")
            return

        self.processed_findings.add(fingerprint)
        logger.info(f"[CORRELATION] Processing finding: {finding_type}")

        # Generate correlated tasks
        tasks = []

        # Credential correlation
        if finding_type in ['credential', 'credential_found', 'credentials']:
            tasks.extend(self._generate_credential_spray(finding))

        # Username correlation
        elif finding_type in ['user', 'user_found', 'users']:
            tasks.extend(self._generate_username_tasks(finding))

        # Vulnerability chain detection
        elif finding_type in ['vulnerability', 'sql_injection', 'sqli', 'sqli_found',
                              'lfi', 'lfi_found', 'command_injection', 'cmdi', 'cmdi_found',
                              'ssti', 'ssti_found', 'rce', 'rce_found',
                              'file_upload', 'file_upload_found',
                              'xxe', 'xxe_found', 'deserialization',
                              'deserialization_vulnerability', 'deserialization_found']:
            chain_name = self._detect_chain_trigger(finding_type)
            if chain_name:
                tasks.append(self._create_chain_trigger_task(chain_name, finding_type))
                logger.info(f"[CORRELATION] Chain triggered: {chain_name}")

        # Emit tasks if any generated
        for task in tasks:
            EventBus.emit('plugin_tasks_generated', {
                'target': self.target,
                'task_tree': task,
                'source': 'correlation'
            })
            logger.debug(f"[CORRELATION] Emitted task: {task.get('id')}")

    def _create_chain_trigger_task(self, chain_name: str, finding_type: str) -> Dict[str, Any]:
        """
        Create attack chain trigger notification task

        Args:
            chain_name: Name of the attack chain
            finding_type: Type of finding that triggered chain

        Returns:
            Task dictionary
        """
        return {
            'id': f'chain-trigger-{chain_name}',
            'name': f'Attack Chain Detected: {chain_name}',
            'type': 'notification',
            'status': 'pending',
            'metadata': {
                'chain_name': chain_name,
                'trigger_finding': finding_type,
                'in_attack_chain': True,
                'chain_progress': 0.0,
                'intelligence_source': 'correlation',
                'category': 'methodology'
            }
        }

    def _generate_credential_spray(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate credential spray tasks across services

        Args:
            finding: Credential finding

        Returns:
            List of spray task dicts
        """
        tasks = []

        # Extract credential details
        description = finding.get('description', '')

        # Parse username:password from description
        username = None
        password = None

        if isinstance(description, dict):
            username = description.get('username', '')
            password = description.get('password', '')
        elif ':' in str(description):
            parts = str(description).split(':', 1)
            username = parts[0].strip()
            password = parts[1].strip() if len(parts) > 1 else ''

        if not username:
            logger.debug("[CORRELATION] No username in credential, skipping spray")
            return tasks

        # Get active services from profile ports
        for port, port_info in self.profile.ports.items():
            service_name = port_info.get('service', '').lower()
            port_state = port_info.get('state', '')

            # Only spray on open ports
            if port_state != 'open':
                continue

            # Check if service accepts authentication
            if any(svc in service_name for svc in self.CREDENTIAL_SPRAY_SERVICES):
                task_id = f'cred-spray-{username}-{service_name}-{port}'

                # Build appropriate command based on service
                command = self._build_spray_command(service_name, username, password, port)

                tasks.append({
                    'id': task_id,
                    'name': f'Try credential on {service_name}:{port}',
                    'type': 'executable',
                    'status': 'pending',
                    'metadata': {
                        'command': command,
                        'category': 'credential_reuse',
                        'source': 'correlation',
                        'intelligence_source': 'correlation',
                        'matches_oscp_pattern': True,
                        'oscp_likelihood': 0.7  # High probability
                    }
                })

        if tasks:
            logger.info(f"[CORRELATION] Generated {len(tasks)} credential spray tasks")

        return tasks

    def _build_spray_command(self, service: str, username: str, password: str, port: int) -> str:
        """
        Build service-specific credential spray command

        Args:
            service: Service name
            username: Username to test
            password: Password to test
            port: Service port

        Returns:
            Command string
        """
        # Build appropriate command based on service type
        if 'ssh' in service:
            return f'sshpass -p "{password}" ssh {username}@{self.target} -p {port}'
        elif 'ftp' in service:
            return f'ftp {self.target} {port} -u {username}:{password}'
        elif 'smb' in service:
            return f'smbclient -U {username}%{password} //{self.target}/ADMIN$ -p {port}'
        elif 'mysql' in service:
            return f'mysql -h {self.target} -P {port} -u {username} -p{password}'
        elif 'postgresql' in service:
            return f'psql -h {self.target} -p {port} -U {username}'
        else:
            # Generic manual note
            return f'# Try {username}:{password} on {service}:{port}'

    def _generate_username_tasks(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate username-based tasks (password guessing)

        Args:
            finding: Username finding

        Returns:
            List of task dicts
        """
        tasks = []
        description = finding.get('description', '')

        # Extract username
        username = str(description).strip() if description else None
        if isinstance(description, dict):
            username = description.get('username', '')

        if not username:
            logger.debug("[CORRELATION] No username in finding, skipping")
            return tasks

        # Generate common password testing task
        task_id = f'user-pwtest-{username.lower().replace(" ", "-")}'
        tasks.append({
            'id': task_id,
            'name': f'Test common passwords for {username}',
            'type': 'executable',
            'status': 'pending',
            'metadata': {
                'command': f'# Try {username}:{username}, {username}:password, {username}:Password123',
                'category': 'auth',
                'source': 'correlation',
                'intelligence_source': 'correlation',
                'matches_oscp_pattern': True,
                'oscp_likelihood': 0.6
            }
        })

        logger.info(f"[CORRELATION] Generated username task for {username}")
        return tasks

    def _detect_chain_trigger(self, finding_type: str) -> Optional[str]:
        """
        Detect if finding triggers an attack chain

        Args:
            finding_type: Type of finding

        Returns:
            Chain name if triggered, None otherwise
        """
        chain = self.CHAIN_TRIGGERS.get(finding_type.lower())
        if chain:
            logger.debug(f"[CORRELATION] Detected chain: {finding_type} -> {chain}")
        return chain

    def get_correlation_tasks(self) -> List[Dict[str, Any]]:
        """
        Get all pending correlation tasks (for TaskOrchestrator)

        Returns:
            List of task suggestions
        """
        # In Stage 2, return empty (tasks emitted via events)
        # Future: Could maintain a queue for manual retrieval
        return []

    def clear_history(self):
        """Clear processed findings history (for testing/reset)"""
        self.processed_findings.clear()
        logger.debug("[CORRELATION] Cleared processed findings history")
