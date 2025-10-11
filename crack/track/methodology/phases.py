"""
Methodology Phase Definitions

Defines the 6 phases of OSCP penetration testing methodology
and valid transitions between them.
"""

from enum import Enum, auto
from typing import List, Optional
from dataclasses import dataclass


class Phase(Enum):
    """Penetration testing methodology phases"""
    RECONNAISSANCE = auto()
    SERVICE_ENUMERATION = auto()
    VULNERABILITY_DISCOVERY = auto()
    EXPLOITATION = auto()
    PRIVILEGE_ESCALATION = auto()
    LATERAL_MOVEMENT = auto()


@dataclass
class PhaseTransition:
    """Defines valid phase transition with requirements"""
    from_phase: Phase
    to_phase: Phase
    requirements: List[str]

    # Valid transitions
    TRANSITIONS = [
        # Recon -> Service Enum
        ('RECONNAISSANCE', 'SERVICE_ENUMERATION', ['port_scan_complete']),
        # Service Enum -> Vuln Discovery
        ('SERVICE_ENUMERATION', 'VULNERABILITY_DISCOVERY', ['services_enumerated']),
        # Vuln Discovery -> Exploitation
        ('VULNERABILITY_DISCOVERY', 'EXPLOITATION', ['vulnerabilities_identified']),
        # Exploitation -> PrivEsc
        ('EXPLOITATION', 'PRIVILEGE_ESCALATION', ['initial_access']),
        # PrivEsc -> Lateral Movement
        ('PRIVILEGE_ESCALATION', 'LATERAL_MOVEMENT', ['elevated_privileges'])
    ]

    @classmethod
    def get_transition(cls, from_phase: Phase, to_phase: Phase) -> Optional['PhaseTransition']:
        """Get transition definition if valid"""
        for trans in cls.TRANSITIONS:
            if trans[0] == from_phase.name and trans[1] == to_phase.name:
                return PhaseTransition(from_phase, to_phase, trans[2])
        return None
