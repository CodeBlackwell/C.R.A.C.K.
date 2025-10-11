"""
Data-driven phase definitions

Each phase defines:
- Entry tasks
- Exit conditions
- Next phase
"""

from typing import Dict, Any, List, Callable


def _has_ports(state: Dict[str, Any]) -> bool:
    """Check if any ports discovered"""
    return len(state.get('ports', {})) > 0


def _has_services(state: Dict[str, Any]) -> bool:
    """Check if services detected on ports"""
    ports = state.get('ports', {})
    return any(port_info.get('service') for port_info in ports.values())


def _has_enumeration_tasks(state: Dict[str, Any]) -> bool:
    """Check if service-specific enumeration started"""
    # This is checked via task tree having service-specific tasks
    return True  # Advanced when plugins create tasks


# Phase definitions (data-driven)
PHASES: Dict[str, Dict[str, Any]] = {
    'discovery': {
        'name': 'Host Discovery',
        'description': 'Verify target is alive and discover open ports',
        'initial_tasks': [
            {
                'id': 'ping-check',
                'name': 'Verify host is alive',
                'type': 'scan',  # Changed from 'command' to 'scan'
                'scan_profiles': [  # Reference profiles instead of hardcoded command
                    'host-icmp-ping',      # Default ICMP ping
                    'host-tcp-syn',        # TCP SYN ping (ICMP bypass)
                    'host-ack',            # TCP ACK ping (stateless FW bypass)
                    'host-arp',            # ARP ping (local network)
                    'host-disable-ping'    # Skip host discovery (-Pn)
                ],
                'default_profile': 'host-icmp-ping',  # Default for OSCP
                'metadata': {
                    'description': 'Quick ICMP ping to verify host responds',
                    'tags': ['QUICK_WIN', 'OSCP:HIGH'],
                    'allow_custom': True,  # Allow user to enter custom discovery command
                    'notes': [
                        'Choose discovery method based on network restrictions',
                        'ICMP blocked? Try TCP SYN ping to common ports',
                        'Local network? Use ARP ping (most reliable)',
                        'All blocked? Use -Pn to skip discovery'
                    ]
                }
            },
            {
                'id': 'port-discovery',
                'name': 'Port Discovery',
                'type': 'scan',  # Changed from 'command' to 'scan'
                'scan_profiles': [  # Reference profiles instead of hardcoded command
                    'lab-quick',      # Quick scan option
                    'lab-full',       # Full scan option
                    'stealth-normal', # Stealth option
                    'aggressive-full' # Aggressive option
                ],
                'default_profile': 'lab-quick',  # Default for OSCP
                'metadata': {
                    'description': 'Discover open ports on target',
                    'tags': ['OSCP:HIGH'],
                    'allow_custom': True,  # Allow user to enter custom nmap command
                    'notes': [
                        'Choose scan strategy based on environment',
                        'Labs: use lab-quick or lab-full',
                        'Production: use stealth-normal',
                        'Full scan critical for OSCP - finds unusual high ports'
                    ]
                }
            }
        ],
        'exit_condition': _has_ports,
        'next_phase': 'service-detection'
    },

    'service-detection': {
        'name': 'Service Enumeration',
        'description': 'Identify running services and versions',
        'initial_tasks': [
            {
                'id': 'service-scan',
                'name': 'Service version detection',
                'type': 'scan',  # Changed from 'command' to 'scan'
                'scan_profiles': [
                    'service-detect-default'  # Default service detection profile
                ],
                'default_profile': 'service-detect-default',
                'metadata': {
                    'description': 'Detect services and run default NSE scripts',
                    'tags': ['OSCP:HIGH'],
                    'requires_ports': True,  # Must have discovered ports first
                    'notes': [
                        'Runs after port discovery completes',
                        'Probes open ports to identify exact service versions',
                        'Critical for CVE matching and exploit selection',
                        'Import results to auto-populate service-specific tasks'
                    ]
                }
            }
        ],
        'exit_condition': _has_services,
        'next_phase': 'service-specific',
        'dynamic': True  # Tasks generated based on discovered ports
    },

    'service-specific': {
        'name': 'Service-Specific Enumeration',
        'description': 'Deep enumeration of each service',
        'initial_tasks': [],  # Populated dynamically by service plugins
        'exit_condition': _has_enumeration_tasks,
        'next_phase': 'exploitation',
        'dynamic': True,  # Fully plugin-driven
        'note': 'Tasks auto-generated based on detected services (HTTP, SMB, SSH, etc.)'
    },

    'exploitation': {
        'name': 'Vulnerability Exploitation',
        'description': 'Attempt to exploit discovered vulnerabilities',
        'initial_tasks': [
            {
                'id': 'review-findings',
                'name': 'Review all findings and prioritize targets',
                'type': 'manual',
                'metadata': {
                    'description': 'Analyze enumeration results and plan exploitation',
                    'tags': ['MANUAL']
                }
            }
        ],
        'exit_condition': lambda state: False,  # Manual advancement
        'next_phase': 'post-exploitation',
        'dynamic': True  # Exploit tasks created based on vulns found
    },

    'post-exploitation': {
        'name': 'Post-Exploitation',
        'description': 'Privilege escalation and lateral movement',
        'initial_tasks': [],  # Added when shell obtained
        'exit_condition': lambda state: False,  # Manual advancement
        'next_phase': None,  # Final phase
        'dynamic': True
    }
}


def get_phase_order() -> List[str]:
    """Get ordered list of phase names"""
    return ['discovery', 'service-detection', 'service-specific', 'exploitation', 'post-exploitation']


def get_next_phase(current_phase: str) -> str:
    """Get next phase name

    Args:
        current_phase: Current phase name

    Returns:
        Next phase name or None if final
    """
    return PHASES.get(current_phase, {}).get('next_phase')
