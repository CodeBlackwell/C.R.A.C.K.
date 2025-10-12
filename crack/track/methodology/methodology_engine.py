"""
Methodology State Machine - Method 2 (Proactive)

Provides phase-based guidance following OSCP penetration testing methodology.
Detects quick-win opportunities and ensures systematic enumeration.

Phases:
1. RECONNAISSANCE - Initial port/service scanning
2. SERVICE_ENUMERATION - Deep service enumeration
3. VULNERABILITY_DISCOVERY - Finding weaknesses
4. EXPLOITATION - Gaining initial access
5. PRIVILEGE_ESCALATION - Elevating privileges
6. LATERAL_MOVEMENT - Moving to other systems
"""

from typing import Dict, Any, List, Optional
import logging
import json
from pathlib import Path
from .phases import Phase, PhaseTransition
from .attack_chains import AttackChain, ChainRegistry
from .chain_executor import ChainExecutor

logger = logging.getLogger(__name__)


class MethodologyEngine:
    """Method 2: Proactive methodology state machine"""

    # Quick-win patterns (OSCP high-probability vulnerabilities)
    QUICK_WIN_PATTERNS = [
        {
            'id': 'tomcat-default-creds',
            'service': 'tomcat',
            'version': None,  # Any version
            'description': 'Try default Tomcat credentials',
            'command': '# Try tomcat:tomcat, admin:admin on manager interface',
            'oscp_likelihood': 0.8
        },
        {
            'id': 'smb-anonymous',
            'service': 'smb',
            'version': None,
            'description': 'Test SMB anonymous access',
            'command': 'smbclient -N -L //{target}',
            'oscp_likelihood': 0.7
        },
        {
            'id': 'apache-2.4.49',
            'service': 'apache',
            'version': '2.4.49',
            'description': 'Apache 2.4.49 Path Traversal (CVE-2021-41773)',
            'command': 'curl http://{target}/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd',
            'oscp_likelihood': 0.9
        },
        {
            'id': 'ftp-anonymous',
            'service': 'ftp',
            'version': None,
            'description': 'Test FTP anonymous access',
            'command': 'ftp {target}  # Try username: anonymous',
            'oscp_likelihood': 0.6
        }
    ]

    def __init__(self, target: str, profile: 'TargetProfile', config: Dict[str, Any]):
        """
        Initialize methodology engine

        Args:
            target: Target IP/hostname
            profile: TargetProfile instance
            config: Intelligence configuration
        """
        self.target = target
        self.profile = profile
        self.config = config

        # Initialize phase tracking
        self.current_phase = Phase.RECONNAISSANCE
        self.phase_history = [Phase.RECONNAISSANCE]
        self.phase_progress = {phase: 0.0 for phase in Phase}

        # Initialize attack chains (Stage 3)
        self.chain_registry = self._load_attack_chains()
        self.chain_executor = ChainExecutor(target, profile, self.chain_registry)

        logger.info(f"[METHODOLOGY] Initialized at {self.current_phase.name} phase")
        logger.info(f"[METHODOLOGY] Loaded {len(self.chain_registry.list_all())} attack chains")

    def get_phase_suggestions(self) -> List[Dict[str, Any]]:
        """
        Generate task suggestions based on current methodology phase

        Returns:
            List of phase-appropriate task suggestions
        """
        suggestions = []

        logger.debug(f"[METHODOLOGY] Generating suggestions for {self.current_phase.name}")

        # Priority 1: Quick-wins for current services
        quick_wins = self._detect_quick_wins()
        suggestions.extend(quick_wins)

        # Priority 2: Attack chain next steps (Stage 3)
        chain_suggestions = self._get_chain_suggestions()
        suggestions.extend(chain_suggestions)

        # Priority 3: Phase-specific tasks
        phase_tasks = self._get_phase_tasks()
        suggestions.extend(phase_tasks)

        # Tag all with phase alignment
        for task in suggestions:
            task['phase_alignment'] = True
            task['current_phase'] = self.current_phase.name
            task['intelligence_source'] = 'methodology'

        logger.info(f"[METHODOLOGY] Generated {len(suggestions)} suggestions")
        return suggestions

    def _detect_quick_wins(self) -> List[Dict[str, Any]]:
        """
        Detect high-probability OSCP vulnerabilities from current services

        Returns:
            List of quick-win task suggestions
        """
        tasks = []

        # Get services from profile
        services = self._get_services_from_profile()

        for service in services:
            service_name = service.get('service', '').lower()
            service_version = service.get('version', '')
            port = service.get('port')

            # Match against quick-win patterns
            for pattern in self.QUICK_WIN_PATTERNS:
                if pattern['service'] in service_name:
                    # Check version match if specified
                    if pattern['version'] and pattern['version'] not in service_version:
                        continue

                    task_id = f"quickwin-{pattern['id']}-{port}"
                    command = pattern['command'].replace('{target}', self.target)

                    tasks.append({
                        'id': task_id,
                        'name': f"🎯 {pattern['description']}",
                        'type': 'executable',
                        'status': 'pending',
                        'metadata': {
                            'command': command,
                            'category': 'quick_win',
                            'matches_oscp_pattern': True,
                            'oscp_likelihood': pattern['oscp_likelihood'],
                            'estimated_time_minutes': 2
                        }
                    })

        if tasks:
            logger.info(f"[METHODOLOGY] Detected {len(tasks)} quick-wins")

        return tasks

    def _get_services_from_profile(self) -> List[Dict[str, Any]]:
        """
        Extract services from profile (handles multiple storage formats)

        Returns:
            List of service dicts with port, service, version
        """
        services = []

        # Check if profile has ports dict
        if hasattr(self.profile, 'ports') and self.profile.ports:
            for port, port_info in self.profile.ports.items():
                service_dict = {
                    'port': port,
                    'service': port_info.get('service', ''),
                    'version': port_info.get('version', '')
                }
                services.append(service_dict)

        return services

    def _get_phase_tasks(self) -> List[Dict[str, Any]]:
        """
        Get standard tasks for current phase

        Returns:
            List of phase-appropriate tasks
        """
        tasks = []

        if self.current_phase == Phase.RECONNAISSANCE:
            tasks.extend(self._get_recon_tasks())
        elif self.current_phase == Phase.SERVICE_ENUMERATION:
            tasks.extend(self._get_service_enum_tasks())
        elif self.current_phase == Phase.VULNERABILITY_DISCOVERY:
            tasks.extend(self._get_vuln_discovery_tasks())
        # Other phases handled by ServicePlugins

        return tasks

    def _get_recon_tasks(self) -> List[Dict[str, Any]]:
        """Reconnaissance phase tasks"""
        return [
            {
                'id': 'recon-full-port-scan',
                'name': 'Full TCP port scan',
                'type': 'executable',
                'status': 'pending',
                'metadata': {
                    'command': f'nmap -p- -sS -T4 {self.target}',
                    'estimated_time_minutes': 10
                }
            }
        ]

    def _get_service_enum_tasks(self) -> List[Dict[str, Any]]:
        """Service enumeration phase tasks"""
        # Placeholder - ServicePlugins handle most of this
        return []

    def _get_vuln_discovery_tasks(self) -> List[Dict[str, Any]]:
        """Vulnerability discovery phase tasks"""
        return [
            {
                'id': 'vuln-searchsploit-scan',
                'name': 'Search for service exploits',
                'type': 'manual',
                'status': 'pending',
                'metadata': {
                    'command': 'searchsploit <service_name> <version>',
                    'estimated_time_minutes': 5
                }
            }
        ]

    def transition_to(self, new_phase: Phase) -> bool:
        """
        Attempt phase transition with validation

        Args:
            new_phase: Target phase

        Returns:
            True if transition successful
        """
        if self._can_transition_to(new_phase):
            old_phase = self.current_phase
            self.current_phase = new_phase
            self.phase_history.append(new_phase)

            logger.info(f"[METHODOLOGY] Phase transition: {old_phase.name} -> {new_phase.name}")
            return True
        else:
            logger.warning(f"[METHODOLOGY] Cannot transition to {new_phase.name} - requirements not met")
            return False

    def _can_transition_to(self, target_phase: Phase) -> bool:
        """
        Check if phase transition is valid

        Args:
            target_phase: Desired phase

        Returns:
            True if transition allowed
        """
        # Allow backward transitions (for testing/refinement)
        if target_phase.value < self.current_phase.value:
            return True

        # Check forward transition requirements
        transition = PhaseTransition.get_transition(self.current_phase, target_phase)
        if not transition:
            return False

        # Check requirements met
        for req in transition.requirements:
            if not self._check_requirement(req):
                logger.debug(f"[METHODOLOGY] Requirement not met: {req}")
                return False

        return True

    def _check_requirement(self, requirement: str) -> bool:
        """
        Check if phase requirement is satisfied

        Args:
            requirement: Requirement string

        Returns:
            True if met
        """
        # Stage 2: Simplified checks
        # Future: Check profile state for actual completion

        if requirement == 'port_scan_complete':
            return len(self.profile.ports) > 0 if hasattr(self.profile, 'ports') else False
        elif requirement == 'services_enumerated':
            return len(self.profile.findings) > 0 if hasattr(self.profile, 'findings') else False
        elif requirement == 'vulnerabilities_identified':
            # Check for any vulnerability findings
            if hasattr(self.profile, 'findings'):
                return any('vuln' in f.get('type', '').lower() for f in self.profile.findings)
            return False

        # Default: assume met for Stage 2
        return True

    def _load_attack_chains(self) -> ChainRegistry:
        """
        Load attack chains from JSON catalog

        Returns:
            Populated ChainRegistry
        """
        registry = ChainRegistry()

        # Find attack_chains.json in intelligence/patterns/
        chains_file = Path(__file__).parent.parent / 'intelligence' / 'patterns' / 'attack_chains.json'

        if not chains_file.exists():
            logger.warning(f"[METHODOLOGY] Attack chains file not found: {chains_file}")
            return registry

        try:
            with open(chains_file, 'r') as f:
                data = json.load(f)

            # Load chains from JSON
            for chain_data in data.get('attack_chains', []):
                chain = AttackChain.from_dict(chain_data)
                registry.register(chain)

            logger.info(f"[METHODOLOGY] Loaded {len(registry.list_all())} attack chains from JSON")

        except Exception as e:
            logger.error(f"[METHODOLOGY] Failed to load attack chains: {e}")

        return registry

    def _get_chain_suggestions(self) -> List[Dict[str, Any]]:
        """
        Get next step suggestions from active attack chains

        Returns:
            List of chain-based task suggestions
        """
        tasks = []

        # Get next steps from ChainExecutor
        chain_steps = self.chain_executor.get_next_steps(max_chains=3)

        for suggestion in chain_steps:
            step = suggestion['step']
            chain_name = suggestion['chain_name']
            progress = suggestion['progress']
            step_index = suggestion['step_index']

            # Convert ChainStep to task dict
            task_id = f"chain-{suggestion['chain_id']}-step-{step_index}"

            # Replace placeholders in command template
            command = step.command_template
            command = command.replace('<TARGET>', self.target)
            command = command.replace('<PORT>', '80')  # TODO: Get from context

            tasks.append({
                'id': task_id,
                'name': f"⛓️ [{chain_name}] {step.name}",
                'type': 'executable' if not step.manual else 'manual',
                'status': 'pending',
                'metadata': {
                    'command': command,
                    'category': 'attack_chain',
                    'chain_id': suggestion['chain_id'],
                    'chain_name': chain_name,
                    'step_id': step.id,
                    'step_index': step_index,
                    'chain_progress': progress,
                    'description': step.description,
                    'success_indicators': step.success_indicators,
                    'failure_indicators': step.failure_indicators,
                    'estimated_time_minutes': step.estimated_time_minutes,
                    'manual': step.manual
                }
            })

        if tasks:
            logger.info(f"[METHODOLOGY] Generated {len(tasks)} chain suggestions")

        return tasks
