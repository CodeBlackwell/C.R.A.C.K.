"""
Tests for ActivationManager - Chain activation state and circular prevention.

Business Value Focus:
- Circular chain activations are prevented to avoid infinite loops
- Activation stack tracks current execution context
- Thread-safe operations for concurrent scenarios
- Activation history enables workflow debugging
"""

import pytest
import threading
import time
from unittest.mock import MagicMock

from reference.chains.activation_manager import ActivationManager


# ==============================================================================
# Test: Basic Activation Operations
# ==============================================================================


class TestBasicActivation:
    """Tests for basic activation stack operations."""

    def test_push_activation(self, activation_manager):
        """
        BV: Chains can be pushed onto the activation stack.

        Scenario:
          Given: An empty activation manager
          When: push_activation() is called
          Then: Chain is added to the stack
        """
        activation_manager.push_activation("chain-a")

        assert activation_manager.activation_stack == ["chain-a"]
        assert activation_manager.get_current_chain() == "chain-a"

    def test_pop_activation(self, activation_manager):
        """
        BV: Chains can be popped from the activation stack.

        Scenario:
          Given: An activation manager with one chain
          When: pop_activation() is called
          Then: Chain is removed and returned
        """
        activation_manager.push_activation("chain-a")
        popped = activation_manager.pop_activation()

        assert popped == "chain-a"
        assert activation_manager.activation_stack == []

    def test_pop_empty_stack_returns_none(self, activation_manager):
        """
        BV: Popping empty stack returns None (no error).

        Scenario:
          Given: An empty activation manager
          When: pop_activation() is called
          Then: None is returned
        """
        result = activation_manager.pop_activation()
        assert result is None

    def test_get_current_chain(self, activation_manager):
        """
        BV: Current chain is the top of the stack.

        Scenario:
          Given: A stack with multiple chains
          When: get_current_chain() is called
          Then: Returns the most recently pushed chain
        """
        activation_manager.push_activation("chain-a")
        activation_manager.push_activation("chain-b")
        activation_manager.push_activation("chain-c")

        assert activation_manager.get_current_chain() == "chain-c"

    def test_get_current_chain_empty_returns_none(self, activation_manager):
        """
        BV: Empty stack returns None for current chain.

        Scenario:
          Given: An empty activation manager
          When: get_current_chain() is called
          Then: None is returned
        """
        assert activation_manager.get_current_chain() is None

    def test_get_activation_depth(self, activation_manager):
        """
        BV: Activation depth shows nesting level.

        Scenario:
          Given: Multiple chains on the stack
          When: get_activation_depth() is called
          Then: Returns the number of active chains
        """
        assert activation_manager.get_activation_depth() == 0

        activation_manager.push_activation("chain-a")
        assert activation_manager.get_activation_depth() == 1

        activation_manager.push_activation("chain-b")
        assert activation_manager.get_activation_depth() == 2


# ==============================================================================
# Test: Circular Activation Prevention
# ==============================================================================


class TestCircularPrevention:
    """Tests for circular activation detection."""

    def test_can_activate_allowed(self, activation_manager):
        """
        BV: New chains can be activated if not already in stack.

        Scenario:
          Given: chain-a is active
          When: can_activate() is called for chain-b
          Then: Returns (True, "Activation allowed")
        """
        activation_manager.push_activation("chain-a")

        allowed, reason = activation_manager.can_activate("chain-a", "chain-b")

        assert allowed is True
        assert "allowed" in reason.lower()

    def test_can_activate_circular_prevented(self, activation_manager):
        """
        BV: Circular activation is prevented with clear explanation.

        Scenario:
          Given: chain-a and chain-b are active (a -> b)
          When: can_activate() is called for chain-a (would create b -> a)
          Then: Returns (False, reason explaining circular)
        """
        activation_manager.push_activation("chain-a")
        activation_manager.push_activation("chain-b")

        allowed, reason = activation_manager.can_activate("chain-b", "chain-a")

        assert allowed is False
        assert "circular" in reason.lower()
        assert "chain-a" in reason

    def test_can_activate_shows_stack_depth(self, activation_manager):
        """
        BV: Circular prevention message shows where in stack chain exists.

        Scenario:
          Given: A -> B -> C active
          When: Attempting C -> A
          Then: Reason shows A is at depth 0
        """
        activation_manager.push_activation("chain-a")
        activation_manager.push_activation("chain-b")
        activation_manager.push_activation("chain-c")

        allowed, reason = activation_manager.can_activate("chain-c", "chain-a")

        assert not allowed
        assert "depth" in reason.lower()

    def test_direct_self_activation_prevented(self, activation_manager):
        """
        BV: A chain cannot activate itself.

        Scenario:
          Given: chain-a is active
          When: can_activate("chain-a", "chain-a")
          Then: Returns (False, circular prevented)
        """
        activation_manager.push_activation("chain-a")

        allowed, reason = activation_manager.can_activate("chain-a", "chain-a")

        assert not allowed

    def test_reactivation_after_return_allowed(self, activation_manager):
        """
        BV: A chain can be reactivated after it returns.

        Scenario:
          Given: A -> B executed and B returned (popped)
          When: A tries to activate B again
          Then: Activation is allowed
        """
        # First execution: A -> B
        activation_manager.push_activation("chain-a")
        activation_manager.push_activation("chain-b")
        activation_manager.pop_activation()  # B returns

        # Second activation: A -> B again
        allowed, reason = activation_manager.can_activate("chain-a", "chain-b")

        assert allowed is True


# ==============================================================================
# Test: Activation History
# ==============================================================================


class TestActivationHistory:
    """Tests for activation history tracking."""

    def test_record_activation(self, activation_manager):
        """
        BV: Activation transitions are recorded for analytics.

        Scenario:
          Given: An activation manager
          When: record_activation() is called
          Then: Transition is recorded in history
        """
        activation_manager.record_activation("chain-a", "chain-b")

        history = activation_manager.activation_history
        assert ("chain-a", "chain-b") in history

    def test_activation_history_is_set(self, activation_manager):
        """
        BV: Duplicate activations are not recorded twice.

        Scenario:
          Given: An activation A -> B is recorded
          When: Same activation is recorded again
          Then: History still contains only one entry
        """
        activation_manager.record_activation("chain-a", "chain-b")
        activation_manager.record_activation("chain-a", "chain-b")

        history = activation_manager.activation_history
        assert len([h for h in history if h == ("chain-a", "chain-b")]) == 1

    def test_history_property_returns_copy(self, activation_manager):
        """
        BV: History property returns a copy (external modifications safe).

        Scenario:
          Given: An activation manager with history
          When: History is retrieved and modified
          Then: Internal history is unchanged
        """
        activation_manager.record_activation("a", "b")
        history = activation_manager.activation_history
        history.add(("x", "y"))

        assert ("x", "y") not in activation_manager.activation_history


# ==============================================================================
# Test: Stack Property Safety
# ==============================================================================


class TestStackPropertySafety:
    """Tests for stack property returning copies."""

    def test_activation_stack_returns_copy(self, activation_manager):
        """
        BV: Stack property returns copy to prevent external modification.

        Scenario:
          Given: An activation manager with chains on stack
          When: Stack is retrieved and modified externally
          Then: Internal stack is unchanged
        """
        activation_manager.push_activation("chain-a")
        stack = activation_manager.activation_stack
        stack.append("chain-external")

        assert "chain-external" not in activation_manager.activation_stack


# ==============================================================================
# Test: Clear and Reset
# ==============================================================================


class TestClearAndReset:
    """Tests for clearing state."""

    def test_clear_stack(self, activation_manager):
        """
        BV: Stack can be cleared for testing or reset scenarios.

        Scenario:
          Given: An activation manager with chains on stack
          When: clear_stack() is called
          Then: Stack is empty, history preserved
        """
        activation_manager.push_activation("chain-a")
        activation_manager.push_activation("chain-b")
        activation_manager.record_activation("chain-a", "chain-b")

        activation_manager.clear_stack()

        assert activation_manager.activation_stack == []
        assert len(activation_manager.activation_history) == 1

    def test_clear_history(self, activation_manager):
        """
        BV: History can be cleared separately from stack.

        Scenario:
          Given: An activation manager with history
          When: clear_history() is called
          Then: History is empty, stack preserved
        """
        activation_manager.push_activation("chain-a")
        activation_manager.record_activation("x", "y")

        activation_manager.clear_history()

        assert activation_manager.activation_stack == ["chain-a"]
        assert len(activation_manager.activation_history) == 0

    def test_reset_clears_all(self, activation_manager):
        """
        BV: Reset clears both stack and history.

        Scenario:
          Given: An activation manager with state
          When: reset() is called
          Then: Both stack and history are empty
        """
        activation_manager.push_activation("chain-a")
        activation_manager.record_activation("a", "b")

        activation_manager.reset()

        assert activation_manager.activation_stack == []
        assert len(activation_manager.activation_history) == 0


# ==============================================================================
# Test: Thread Safety
# ==============================================================================


class TestThreadSafety:
    """Tests for thread-safe operations."""

    def test_concurrent_push_operations(self, activation_manager):
        """
        BV: Concurrent push operations don't corrupt the stack.

        Scenario:
          Given: Multiple threads pushing to the stack
          When: All threads complete
          Then: All pushes are recorded (no lost updates)
        """
        num_threads = 10
        pushes_per_thread = 100

        def push_chains():
            for i in range(pushes_per_thread):
                activation_manager.push_activation(f"chain-{threading.current_thread().name}-{i}")

        threads = []
        for i in range(num_threads):
            t = threading.Thread(target=push_chains, name=f"t{i}")
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # All pushes should be recorded
        assert activation_manager.get_activation_depth() == num_threads * pushes_per_thread

    def test_concurrent_can_activate_checks(self, activation_manager):
        """
        BV: Concurrent can_activate() calls are safe.

        Scenario:
          Given: One chain on the stack
          When: Multiple threads check can_activate() simultaneously
          Then: All checks complete without error or race condition
        """
        activation_manager.push_activation("base-chain")
        results = []
        errors = []

        def check_activation():
            try:
                for i in range(100):
                    allowed, reason = activation_manager.can_activate(
                        "base-chain", f"new-chain-{i}"
                    )
                    results.append(allowed)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=check_activation) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert all(r is True for r in results)

    def test_concurrent_push_pop_operations(self, activation_manager):
        """
        BV: Mixed push/pop operations are thread-safe.

        Scenario:
          Given: Multiple threads pushing and popping
          When: All threads complete
          Then: No crashes or data corruption
        """
        errors = []

        def push_pop_cycle():
            try:
                for i in range(50):
                    activation_manager.push_activation(f"chain-{i}")
                    time.sleep(0.001)
                    activation_manager.pop_activation()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=push_pop_cycle) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0


# ==============================================================================
# Test: String Representation
# ==============================================================================


class TestStringRepresentation:
    """Tests for string representation (debugging)."""

    def test_repr_shows_state(self, activation_manager):
        """
        BV: String representation helps with debugging.

        Scenario:
          Given: An activation manager with state
          When: repr() is called
          Then: Output shows stack and history count
        """
        activation_manager.push_activation("chain-a")
        activation_manager.record_activation("a", "b")

        rep = repr(activation_manager)

        assert "ActivationManager" in rep
        assert "chain-a" in rep
        assert "history_count" in rep


# ==============================================================================
# Test: Complex Activation Scenarios
# ==============================================================================


class TestComplexScenarios:
    """Tests for complex multi-chain activation scenarios."""

    def test_deep_chain_activation(self, activation_manager):
        """
        BV: Deep chain nesting is handled correctly.

        Scenario:
          Given: A -> B -> C -> D -> E chain activation
          When: Attempting to activate A from E
          Then: Circular prevention kicks in at correct depth
        """
        chains = ["chain-a", "chain-b", "chain-c", "chain-d", "chain-e"]
        for chain in chains:
            activation_manager.push_activation(chain)

        # Try to go back to chain-a
        allowed, reason = activation_manager.can_activate("chain-e", "chain-a")

        assert not allowed
        assert "depth 0" in reason  # chain-a is at depth 0

    def test_sibling_chain_activation(self, activation_manager):
        """
        BV: Sibling chains can be activated (not circular).

        Scenario:
          Given: A -> B, then B completes
          When: A tries to activate C
          Then: Activation is allowed
        """
        activation_manager.push_activation("chain-a")
        activation_manager.push_activation("chain-b")
        activation_manager.pop_activation()  # B completes

        allowed, reason = activation_manager.can_activate("chain-a", "chain-c")

        assert allowed is True

    def test_diamond_pattern_allowed(self, activation_manager):
        """
        BV: Diamond pattern (A -> B, A -> C, both lead to D) works.

        Scenario:
          Given: A is active
          When: A activates B, B activates D, then back to A, A activates C
          Then: C can also activate D (D not currently active)
        """
        # First path: A -> B -> D
        activation_manager.push_activation("chain-a")
        activation_manager.push_activation("chain-b")
        activation_manager.push_activation("chain-d")

        # D and B complete
        activation_manager.pop_activation()  # D
        activation_manager.pop_activation()  # B

        # Second path: A -> C
        allowed, _ = activation_manager.can_activate("chain-a", "chain-c")
        assert allowed

        activation_manager.push_activation("chain-c")

        # C wants to activate D (D is not active)
        allowed, reason = activation_manager.can_activate("chain-c", "chain-d")
        assert allowed

    def test_workflow_with_history_tracking(self, activation_manager):
        """
        BV: Full workflow with history tracking for reporting.

        Scenario:
          Given: A complete chain workflow
          When: Multiple chains are activated and complete
          Then: History records all transitions
        """
        # Simulate: enum -> exploit -> privesc
        activation_manager.push_activation("enumeration")
        activation_manager.record_activation("root", "enumeration")

        activation_manager.push_activation("exploit")
        activation_manager.record_activation("enumeration", "exploit")

        activation_manager.push_activation("privesc")
        activation_manager.record_activation("exploit", "privesc")

        # Verify history
        history = activation_manager.activation_history
        assert ("root", "enumeration") in history
        assert ("enumeration", "exploit") in history
        assert ("exploit", "privesc") in history

        # Stack should show current path
        assert activation_manager.activation_stack == [
            "enumeration",
            "exploit",
            "privesc",
        ]
