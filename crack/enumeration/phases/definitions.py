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
                'type': 'command',
                'metadata': {
                    'command': 'ping -c 3 {TARGET}',
                    'description': 'Quick ICMP ping to verify host responds',
                    'tags': ['QUICK_WIN', 'OSCP:HIGH'],
                    'flag_explanations': {
                        '-c 3': 'Send 3 ICMP echo requests'
                    }
                }
            },
            {
                'id': 'quick-port-scan',
                'name': 'Quick top ports scan',
                'type': 'command',
                'metadata': {
                    'command': 'nmap --top-ports 1000 {TARGET} -oN quick_scan.nmap',
                    'description': 'Fast scan of most common 1000 ports',
                    'tags': ['QUICK_WIN', 'OSCP:HIGH'],
                    'flag_explanations': {
                        '--top-ports 1000': 'Scan 1000 most common ports (much faster than full scan)',
                        '-oN': 'Save normal output format'
                    },
                    'notes': [
                        'Completes in 1-2 minutes',
                        'Finds 90% of open ports quickly',
                        'Follow up with full scan if needed'
                    ]
                }
            },
            {
                'id': 'port-discovery',
                'name': 'Discover all ports (full scan)',
                'type': 'command',
                'metadata': {
                    'command': 'nmap -p- --min-rate 1000 {TARGET} -oA port_scan',
                    'description': 'Comprehensive scan of all 65535 ports',
                    'tags': ['OSCP:HIGH'],
                    'flag_explanations': {
                        '-p-': 'Scan all 65535 TCP ports (thorough enumeration)',
                        '--min-rate 1000': 'Send at least 1000 packets/second (faster for labs)',
                        '-oA': 'Save output in all formats (XML, gnmap, nmap)'
                    },
                    'notes': [
                        'Takes 5-10 minutes typically',
                        'Finds unusual high ports',
                        'Critical for OSCP - never skip'
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
                'type': 'command',
                'metadata': {
                    'command': 'nmap -sV -sC -p {PORTS} {TARGET} -oA service_scan',
                    'description': 'Detect services and run default NSE scripts',
                    'tags': ['OSCP:HIGH'],
                    'notes': [
                        '-sV: Service version detection (critical for CVE matching)',
                        '-sC: Default NSE scripts (finds low-hanging fruit)',
                        '-p: Target only open ports (faster)',
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
