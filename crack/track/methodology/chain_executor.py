"""
Chain Executor - Attack chain orchestration and progress tracking

Manages execution of multi-step attack chains, tracks progress,
validates step completion, and coordinates with MethodologyEngine.

Responsibilities:
- Track active chains per target
- Validate step completion based on success/failure indicators
- Persist chain progress to profile
- Emit events for intelligence system
"""

from typing import Dict, Any, List, Optional
import logging
import re
from datetime import datetime
from ..core.events import EventBus

logger = logging.getLogger(__name__)


# Minimal supporting classes (to be replaced by Agent 1's implementation)
class ChainStep:
    """Individual step in an attack chain"""

    def __init__(self, step_id: str, name: str, command: str,
                 success_indicators: List[str] = None,
                 failure_indicators: List[str] = None):
        self.id = step_id
        self.name = name
        self.command = command
        self.success_indicators = success_indicators or []
        self.failure_indicators = failure_indicators or []


class AttackChain:
    """Attack chain definition"""

    def __init__(self, chain_id: str, name: str, steps: List[ChainStep]):
        self.id = chain_id
        self.name = name
        self.steps = steps

    def is_complete(self, completed_steps: List[str]) -> bool:
        """Check if all steps are completed"""
        return all(step.id in completed_steps for step in self.steps)

    def get_progress(self, completed_steps: List[str]) -> float:
        """Get completion percentage (0.0-1.0)"""
        if not self.steps:
            return 1.0
        return len([s for s in completed_steps if s in [step.id for step in self.steps]]) / len(self.steps)

    def get_next_step(self, completed_steps: List[str]) -> Optional[ChainStep]:
        """Get next uncompleted step"""
        for step in self.steps:
            if step.id not in completed_steps:
                return step
        return None

    def get_current_step_index(self, completed_steps: List[str]) -> int:
        """Get index of current step"""
        for i, step in enumerate(self.steps):
            if step.id not in completed_steps:
                return i + 1  # 1-indexed
        return len(self.steps)


class ChainRegistry:
    """Registry of available attack chains"""

    def __init__(self):
        self._chains: Dict[str, AttackChain] = {}

    def register(self, chain: AttackChain):
        """Register a chain"""
        self._chains[chain.id] = chain

    def get(self, chain_id: str) -> Optional[AttackChain]:
        """Get chain by ID"""
        return self._chains.get(chain_id)

    def list(self) -> List[AttackChain]:
        """List all chains"""
        return list(self._chains.values())


class ChainProgress:
    """Track progress of a single attack chain"""

    def __init__(self, chain: AttackChain, target: str):
        """
        Initialize chain progress tracker

        Args:
            chain: AttackChain to track
            target: Target IP/hostname
        """
        self.chain = chain
        self.target = target
        self.completed_steps: List[str] = []
        self.failed_steps: List[str] = []
        self.started_at: Optional[str] = None
        self.completed_at: Optional[str] = None

    def start(self):
        """Mark chain as started"""
        if not self.started_at:
            self.started_at = datetime.now().isoformat()
            logger.info(f"[CHAIN.START] {self.chain.id} started for {self.target}")

    def mark_step_complete(self, step_id: str):
        """
        Mark a step as completed

        Args:
            step_id: ID of completed step
        """
        if step_id not in self.completed_steps:
            self.completed_steps.append(step_id)
            logger.info(f"[CHAIN.STEP.COMPLETE] {self.chain.id}: {step_id}")

        # Check if chain complete
        if self.chain.is_complete(self.completed_steps):
            self.completed_at = datetime.now().isoformat()
            logger.info(f"[CHAIN.COMPLETE] {self.chain.id} completed for {self.target}")

    def mark_step_failed(self, step_id: str):
        """
        Mark a step as failed

        Args:
            step_id: ID of failed step
        """
        if step_id not in self.failed_steps:
            self.failed_steps.append(step_id)
            logger.warning(f"[CHAIN.STEP.FAILED] {self.chain.id}: {step_id}")

    def get_progress(self) -> float:
        """Get chain completion percentage (0.0-1.0)"""
        return self.chain.get_progress(self.completed_steps)

    def get_next_step(self) -> Optional[ChainStep]:
        """Get next step to execute"""
        return self.chain.get_next_step(self.completed_steps)

    def is_complete(self) -> bool:
        """Check if chain is complete"""
        return self.chain.is_complete(self.completed_steps)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for persistence"""
        return {
            'chain_id': self.chain.id,
            'target': self.target,
            'completed_steps': self.completed_steps,
            'failed_steps': self.failed_steps,
            'started_at': self.started_at,
            'completed_at': self.completed_at,
            'progress': self.get_progress()
        }


class ChainExecutor:
    """Manages attack chain execution and progress tracking"""

    def __init__(self, target: str, profile: 'TargetProfile', registry: ChainRegistry):
        """
        Initialize chain executor

        Args:
            target: Target IP/hostname
            profile: TargetProfile for state persistence
            registry: ChainRegistry with available chains
        """
        self.target = target
        self.profile = profile
        self.registry = registry
        self.active_chains: Dict[str, ChainProgress] = {}

        # Load persisted progress from profile
        self._load_progress()

        logger.info(f"[CHAIN.EXECUTOR] Initialized for {target}")

    def _load_progress(self):
        """Load chain progress from profile"""
        chain_data = self.profile.metadata.get('attack_chains', {})

        for chain_id, progress_data in chain_data.items():
            chain = self.registry.get(chain_id)
            if chain:
                progress = ChainProgress(chain, self.target)
                progress.completed_steps = progress_data.get('completed_steps', [])
                progress.failed_steps = progress_data.get('failed_steps', [])
                progress.started_at = progress_data.get('started_at')
                progress.completed_at = progress_data.get('completed_at')
                self.active_chains[chain_id] = progress
                logger.info(f"[CHAIN.LOAD] Restored progress for {chain_id}: {len(progress.completed_steps)} steps")

    def _save_progress(self):
        """Persist chain progress to profile"""
        chain_data = {
            chain_id: progress.to_dict()
            for chain_id, progress in self.active_chains.items()
        }
        self.profile.metadata['attack_chains'] = chain_data
        self.profile.save()
        logger.debug(f"[CHAIN.SAVE] Persisted {len(chain_data)} chain progresses")

    def activate_chain(self, chain_id: str) -> bool:
        """
        Activate an attack chain

        Args:
            chain_id: ID of chain to activate

        Returns:
            True if activated, False if already active or not found
        """
        if chain_id in self.active_chains:
            logger.debug(f"[CHAIN.ACTIVATE] {chain_id} already active")
            return False

        chain = self.registry.get(chain_id)
        if not chain:
            logger.error(f"[CHAIN.ACTIVATE] Chain not found: {chain_id}")
            return False

        progress = ChainProgress(chain, self.target)
        progress.start()
        self.active_chains[chain_id] = progress
        self._save_progress()

        # Emit event
        EventBus.emit('chain_activated', {
            'chain_id': chain_id,
            'target': self.target,
            'steps_total': len(chain.steps)
        })

        return True

    def check_step_completion(self, step: ChainStep, output: str) -> bool:
        """
        Check if step completed based on output

        Args:
            step: ChainStep to validate
            output: Command output to analyze

        Returns:
            True if success indicators found, False if failure indicators found
        """
        # Check failure indicators first
        for indicator in step.failure_indicators:
            if re.search(indicator, output, re.IGNORECASE):
                logger.debug(f"[CHAIN.CHECK] Failure indicator found: {indicator}")
                return False

        # Check success indicators
        success_count = 0
        for indicator in step.success_indicators:
            if re.search(indicator, output, re.IGNORECASE):
                success_count += 1
                logger.debug(f"[CHAIN.CHECK] Success indicator found: {indicator}")

        # Require at least one success indicator
        return success_count > 0

    def update_progress(self, chain_id: str, step_id: str, output: str, success: bool):
        """
        Update chain progress after step execution

        Args:
            chain_id: ID of chain
            step_id: ID of executed step
            output: Command output
            success: Whether user marked as successful
        """
        if chain_id not in self.active_chains:
            logger.warning(f"[CHAIN.UPDATE] Chain not active: {chain_id}")
            return

        progress = self.active_chains[chain_id]

        if success:
            progress.mark_step_complete(step_id)
        else:
            progress.mark_step_failed(step_id)

        self._save_progress()

        # Emit event
        EventBus.emit('chain_step_completed', {
            'chain_id': chain_id,
            'step_id': step_id,
            'success': success,
            'progress': progress.get_progress(),
            'complete': progress.is_complete()
        })

    def get_next_steps(self, max_chains: int = 3) -> List[Dict[str, Any]]:
        """
        Get next steps from active chains

        Args:
            max_chains: Maximum number of chains to suggest from

        Returns:
            List of next step suggestions
        """
        suggestions = []

        # Sort chains by progress (continue higher-progress chains first)
        sorted_chains = sorted(
            self.active_chains.values(),
            key=lambda p: p.get_progress(),
            reverse=True
        )

        for progress in sorted_chains[:max_chains]:
            if progress.is_complete():
                continue

            next_step = progress.get_next_step()
            if next_step:
                suggestions.append({
                    'chain_id': progress.chain.id,
                    'chain_name': progress.chain.name,
                    'step': next_step,
                    'progress': progress.get_progress(),
                    'step_index': progress.chain.get_current_step_index(progress.completed_steps)
                })

        return suggestions

    def get_active_chains(self) -> List[Dict[str, Any]]:
        """Get list of active chains with progress"""
        return [
            {
                'chain_id': progress.chain.id,
                'chain_name': progress.chain.name,
                'progress': progress.get_progress(),
                'completed_steps': len(progress.completed_steps),
                'total_steps': len(progress.chain.steps),
                'is_complete': progress.is_complete()
            }
            for progress in self.active_chains.values()
        ]
