"""
Chain activation manager for cross-chain linking.

Manages activation stack and prevents circular activations.
Thread-safe operations for multi-chain scenarios.
"""

from typing import List, Set, Tuple, Optional
import threading


class ActivationManager:
    """
    Manages chain activation state and prevents circular references.

    Tracks the activation stack (parent→child relationships) and prevents
    circular activations (A→B→A). Allows re-activation after return
    (A→B→return→A→B is OK).

    Thread-safe for concurrent chain execution scenarios.

    Example:
        manager = ActivationManager()

        # Check before activating
        can_activate, reason = manager.can_activate("chain-a", "chain-b")
        if can_activate:
            manager.push_activation("chain-a")
            manager.record_activation("chain-a", "chain-b")
            # ... execute chain-b ...
            manager.pop_activation()

    Attributes:
        activation_stack: Current chain activation path (ordered list)
        activation_history: All activation transitions ever made (set of tuples)
    """

    def __init__(self):
        """Initialize activation manager with empty state"""
        self._activation_stack: List[str] = []
        self._activation_history: Set[Tuple[str, str]] = set()
        self._lock = threading.Lock()

    @property
    def activation_stack(self) -> List[str]:
        """Get current activation stack (copy)"""
        with self._lock:
            return self._activation_stack.copy()

    @property
    def activation_history(self) -> Set[Tuple[str, str]]:
        """Get activation history (copy)"""
        with self._lock:
            return self._activation_history.copy()

    def can_activate(self, from_chain: str, to_chain: str) -> Tuple[bool, str]:
        """
        Check if activation is allowed (circular prevention).

        Args:
            from_chain: Current chain identifier
            to_chain: Target chain identifier

        Returns:
            Tuple of (allowed: bool, reason: str)

        Examples:
            >>> manager = ActivationManager()
            >>> manager.push_activation("chain-a")
            >>> manager.can_activate("chain-a", "chain-b")
            (True, "Activation allowed")
            >>> manager.push_activation("chain-b")
            >>> manager.can_activate("chain-b", "chain-a")
            (False, "Circular activation prevented: chain-a already active")
        """
        with self._lock:
            # Check if to_chain is already in activation stack (circular)
            if to_chain in self._activation_stack:
                depth = self._activation_stack.index(to_chain)
                return False, (
                    f"Circular activation prevented: {to_chain} already active "
                    f"at depth {depth} in stack {self._activation_stack}"
                )

            return True, "Activation allowed"

    def push_activation(self, chain_id: str) -> None:
        """
        Add chain to activation stack.

        Args:
            chain_id: Chain identifier to push

        Note:
            Does not check for circular references. Use can_activate() first.
        """
        with self._lock:
            self._activation_stack.append(chain_id)

    def pop_activation(self) -> Optional[str]:
        """
        Remove and return top of activation stack.

        Returns:
            Chain identifier that was popped, or None if stack was empty

        Example:
            >>> manager = ActivationManager()
            >>> manager.push_activation("chain-a")
            >>> manager.pop_activation()
            'chain-a'
            >>> manager.pop_activation()
            None
        """
        with self._lock:
            if self._activation_stack:
                return self._activation_stack.pop()
            return None

    def record_activation(self, from_chain: str, to_chain: str) -> None:
        """
        Record activation transition in history.

        Args:
            from_chain: Source chain identifier
            to_chain: Target chain identifier

        Note:
            History is used for analytics/reporting. Does not affect circular prevention.
        """
        with self._lock:
            self._activation_history.add((from_chain, to_chain))

    def get_current_chain(self) -> Optional[str]:
        """
        Get current chain from top of stack.

        Returns:
            Current chain identifier, or None if stack is empty

        Example:
            >>> manager = ActivationManager()
            >>> manager.push_activation("chain-a")
            >>> manager.get_current_chain()
            'chain-a'
        """
        with self._lock:
            return self._activation_stack[-1] if self._activation_stack else None

    def get_activation_depth(self) -> int:
        """
        Get current activation depth (stack size).

        Returns:
            Number of chains in activation stack

        Example:
            >>> manager = ActivationManager()
            >>> manager.get_activation_depth()
            0
            >>> manager.push_activation("chain-a")
            >>> manager.push_activation("chain-b")
            >>> manager.get_activation_depth()
            2
        """
        with self._lock:
            return len(self._activation_stack)

    def clear_stack(self) -> None:
        """
        Clear activation stack (for testing/reset).

        Note:
            Does not clear history. Use clear_history() separately if needed.
        """
        with self._lock:
            self._activation_stack.clear()

    def clear_history(self) -> None:
        """Clear activation history (for testing/reset)"""
        with self._lock:
            self._activation_history.clear()

    def reset(self) -> None:
        """Reset all state (stack + history)"""
        with self._lock:
            self._activation_stack.clear()
            self._activation_history.clear()

    def __repr__(self) -> str:
        """String representation for debugging"""
        with self._lock:
            return (
                f"ActivationManager(stack={self._activation_stack}, "
                f"history_count={len(self._activation_history)})"
            )
