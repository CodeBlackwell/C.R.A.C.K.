"""
Base phase class for enumeration progression
"""

from typing import Callable, Dict, Any, List
from abc import ABC, abstractmethod


class Phase(ABC):
    """Base class for enumeration phases"""

    def __init__(self, name: str, description: str):
        """
        Args:
            name: Phase name (discovery, service-detection, etc.)
            description: Human-readable description
        """
        self.name = name
        self.description = description

    @abstractmethod
    def get_initial_tasks(self, target: str) -> List[Dict[str, Any]]:
        """Get initial tasks for this phase

        Args:
            target: Target IP/hostname

        Returns:
            List of task dictionaries
        """
        pass

    @abstractmethod
    def can_advance(self, state: Dict[str, Any]) -> bool:
        """Check if phase exit conditions are met

        Args:
            state: Current target state

        Returns:
            True if can advance to next phase
        """
        pass

    def get_next_phase(self) -> str:
        """Get next phase name

        Returns:
            Next phase name or None if final phase
        """
        return None

    def on_enter(self, state: Dict[str, Any]):
        """Called when entering this phase

        Args:
            state: Current target state
        """
        pass

    def on_exit(self, state: Dict[str, Any]):
        """Called when exiting this phase

        Args:
            state: Current target state
        """
        pass

    def __repr__(self):
        return f"<Phase name={self.name}>"
