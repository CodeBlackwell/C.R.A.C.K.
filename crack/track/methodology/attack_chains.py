"""
Attack Chain Definitions - Multi-step attack sequences

Defines reusable attack chains for common OSCP exploitation patterns.
Each chain consists of ordered steps with success/failure indicators.

Examples:
- SQLi → Shell: Detect SQLi → Enumerate DB → Dump credentials → Auth → Shell
- LFI → RCE: Verify LFI → Find vector → Poison logs → Trigger RCE → Shell
- Upload → Shell: Find upload → Bypass filters → Upload shell → Access shell
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)


@dataclass
class ChainStep:
    """Single step in an attack chain"""
    id: str
    name: str
    description: str
    command_template: str
    success_indicators: List[str] = field(default_factory=list)
    failure_indicators: List[str] = field(default_factory=list)
    estimated_time_minutes: int = 5
    manual: bool = False  # True if requires manual intervention

    def __post_init__(self):
        """Validate step after initialization"""
        if not self.id or not self.name:
            raise ValueError("ChainStep requires id and name")
        if not self.command_template and not self.manual:
            raise ValueError("ChainStep requires command_template unless manual=True")


@dataclass
class AttackChain:
    """Multi-step attack sequence"""
    id: str
    name: str
    description: str
    trigger_finding_types: List[str]  # Finding types that activate this chain
    steps: List[ChainStep] = field(default_factory=list)
    required_phase: Optional[str] = None  # e.g., "EXPLOITATION"
    oscp_relevance: float = 0.5  # 0.0-1.0 likelihood in OSCP

    def __post_init__(self):
        """Validate chain after initialization"""
        if not self.id or not self.name:
            raise ValueError("AttackChain requires id and name")
        if not self.trigger_finding_types:
            raise ValueError("AttackChain requires trigger_finding_types")

    def get_current_step_index(self, completed_steps: List[str]) -> int:
        """
        Get index of next step to execute

        Args:
            completed_steps: List of completed step IDs

        Returns:
            Index of next step (0-based), or len(steps) if all complete
        """
        for i, step in enumerate(self.steps):
            if step.id not in completed_steps:
                return i
        return len(self.steps)

    def get_next_step(self, completed_steps: List[str]) -> Optional[ChainStep]:
        """
        Get next step to execute

        Args:
            completed_steps: List of completed step IDs

        Returns:
            Next ChainStep or None if chain complete
        """
        idx = self.get_current_step_index(completed_steps)
        if idx < len(self.steps):
            return self.steps[idx]
        return None

    def get_progress(self, completed_steps: List[str]) -> float:
        """
        Calculate chain completion percentage

        Args:
            completed_steps: List of completed step IDs

        Returns:
            Progress as 0.0-1.0
        """
        if not self.steps:
            return 0.0

        completed_count = sum(1 for step in self.steps if step.id in completed_steps)
        return completed_count / len(self.steps)

    def is_complete(self, completed_steps: List[str]) -> bool:
        """Check if all steps completed"""
        return self.get_progress(completed_steps) >= 1.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'trigger_finding_types': self.trigger_finding_types,
            'steps': [
                {
                    'id': step.id,
                    'name': step.name,
                    'description': step.description,
                    'command_template': step.command_template,
                    'success_indicators': step.success_indicators,
                    'failure_indicators': step.failure_indicators,
                    'estimated_time_minutes': step.estimated_time_minutes,
                    'manual': step.manual
                }
                for step in self.steps
            ],
            'required_phase': self.required_phase,
            'oscp_relevance': self.oscp_relevance
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AttackChain':
        """Create AttackChain from dictionary"""
        steps = [
            ChainStep(
                id=step['id'],
                name=step['name'],
                description=step['description'],
                command_template=step['command_template'],
                success_indicators=step.get('success_indicators', []),
                failure_indicators=step.get('failure_indicators', []),
                estimated_time_minutes=step.get('estimated_time_minutes', 5),
                manual=step.get('manual', False)
            )
            for step in data.get('steps', [])
        ]

        return cls(
            id=data['id'],
            name=data['name'],
            description=data['description'],
            trigger_finding_types=data['trigger_finding_types'],
            steps=steps,
            required_phase=data.get('required_phase'),
            oscp_relevance=data.get('oscp_relevance', 0.5)
        )


class ChainRegistry:
    """Registry of available attack chains"""

    def __init__(self):
        """Initialize empty registry"""
        self.chains: Dict[str, AttackChain] = {}
        logger.info("[CHAINS] Registry initialized")

    def register(self, chain: AttackChain):
        """
        Register an attack chain

        Args:
            chain: AttackChain to register
        """
        self.chains[chain.id] = chain
        logger.info(f"[CHAINS] Registered: {chain.id} ({len(chain.steps)} steps)")

    def get(self, chain_id: str) -> Optional[AttackChain]:
        """Get chain by ID"""
        return self.chains.get(chain_id)

    def get_by_trigger(self, finding_type: str) -> List[AttackChain]:
        """
        Get chains that match a finding type

        Args:
            finding_type: Type of finding

        Returns:
            List of matching chains
        """
        matches = []
        for chain in self.chains.values():
            if finding_type.lower() in [t.lower() for t in chain.trigger_finding_types]:
                matches.append(chain)
        return matches

    def list_all(self) -> List[AttackChain]:
        """Get all registered chains"""
        return list(self.chains.values())
