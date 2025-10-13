"""
Tests for ActivationManager - circular prevention and state management.

Validates chain activation stack, history tracking, and thread safety.
"""

import pytest
import threading
import time
from crack.reference.chains.activation_manager import ActivationManager


class TestActivationManagerBasics:
    """Test basic activation manager operations"""

    def test_initial_state_empty(self):
        """New ActivationManager has empty state"""
        manager = ActivationManager()

        assert manager.get_activation_depth() == 0
        assert manager.get_current_chain() is None
        assert manager.activation_stack == []
        assert manager.activation_history == set()

    def test_push_single_activation(self):
        """Can push single chain to activation stack"""
        manager = ActivationManager()
        manager.push_activation("chain-a")

        assert manager.get_activation_depth() == 1
        assert manager.get_current_chain() == "chain-a"
        assert manager.activation_stack == ["chain-a"]

    def test_push_multiple_activations(self):
        """Can push multiple chains to activation stack"""
        manager = ActivationManager()
        manager.push_activation("chain-a")
        manager.push_activation("chain-b")
        manager.push_activation("chain-c")

        assert manager.get_activation_depth() == 3
        assert manager.get_current_chain() == "chain-c"
        assert manager.activation_stack == ["chain-a", "chain-b", "chain-c"]

    def test_pop_activation(self):
        """Can pop chain from activation stack"""
        manager = ActivationManager()
        manager.push_activation("chain-a")
        manager.push_activation("chain-b")

        popped = manager.pop_activation()

        assert popped == "chain-b"
        assert manager.get_activation_depth() == 1
        assert manager.get_current_chain() == "chain-a"

    def test_pop_empty_stack_returns_none(self):
        """Popping empty stack returns None"""
        manager = ActivationManager()

        popped = manager.pop_activation()

        assert popped is None
        assert manager.get_activation_depth() == 0

    def test_pop_until_empty(self):
        """Can pop all chains until stack is empty"""
        manager = ActivationManager()
        manager.push_activation("chain-a")
        manager.push_activation("chain-b")

        assert manager.pop_activation() == "chain-b"
        assert manager.pop_activation() == "chain-a"
        assert manager.pop_activation() is None
        assert manager.get_activation_depth() == 0


class TestCircularPrevention:
    """Test circular activation prevention"""

    def test_can_activate_simple(self):
        """Can activate when no circular reference"""
        manager = ActivationManager()
        manager.push_activation("chain-a")

        can_activate, reason = manager.can_activate("chain-a", "chain-b")

        assert can_activate is True
        assert reason == "Activation allowed"

    def test_prevent_direct_circular(self):
        """Prevent direct circular activation (A→B→A)"""
        manager = ActivationManager()
        manager.push_activation("chain-a")
        manager.push_activation("chain-b")

        can_activate, reason = manager.can_activate("chain-b", "chain-a")

        assert can_activate is False
        assert "Circular activation prevented" in reason
        assert "chain-a" in reason

    def test_prevent_deep_circular(self):
        """Prevent deep circular activation (A→B→C→A)"""
        manager = ActivationManager()
        manager.push_activation("chain-a")
        manager.push_activation("chain-b")
        manager.push_activation("chain-c")

        can_activate, reason = manager.can_activate("chain-c", "chain-a")

        assert can_activate is False
        assert "Circular activation prevented" in reason
        assert "chain-a" in reason

    def test_prevent_self_activation(self):
        """Prevent chain from activating itself (A→A)"""
        manager = ActivationManager()
        manager.push_activation("chain-a")

        can_activate, reason = manager.can_activate("chain-a", "chain-a")

        assert can_activate is False
        assert "Circular activation prevented" in reason

    def test_allow_reactivation_after_return(self):
        """Allow re-activation after returning (A→B→pop→A→B is OK)"""
        manager = ActivationManager()

        # First activation: A→B
        manager.push_activation("chain-a")
        manager.push_activation("chain-b")
        manager.pop_activation()  # Return from B

        # Second activation: A→B again (should be allowed)
        can_activate, reason = manager.can_activate("chain-a", "chain-b")

        assert can_activate is True
        assert reason == "Activation allowed"

    def test_complex_activation_flow(self):
        """Test complex activation/deactivation flow"""
        manager = ActivationManager()

        # A→B
        manager.push_activation("chain-a")
        manager.push_activation("chain-b")
        assert manager.can_activate("chain-b", "chain-c")[0] is True

        # A→B→C
        manager.push_activation("chain-c")
        assert manager.can_activate("chain-c", "chain-a")[0] is False  # Circular

        # A→B (return from C)
        manager.pop_activation()
        assert manager.can_activate("chain-b", "chain-c")[0] is True  # Can re-enter C

        # A (return from B)
        manager.pop_activation()
        assert manager.can_activate("chain-a", "chain-b")[0] is True  # Can re-enter B


class TestActivationHistory:
    """Test activation history tracking"""

    def test_record_activation(self):
        """Can record activation in history"""
        manager = ActivationManager()

        manager.record_activation("chain-a", "chain-b")

        assert ("chain-a", "chain-b") in manager.activation_history

    def test_record_multiple_activations(self):
        """Can record multiple activations in history"""
        manager = ActivationManager()

        manager.record_activation("chain-a", "chain-b")
        manager.record_activation("chain-b", "chain-c")
        manager.record_activation("chain-c", "chain-d")

        history = manager.activation_history
        assert ("chain-a", "chain-b") in history
        assert ("chain-b", "chain-c") in history
        assert ("chain-c", "chain-d") in history
        assert len(history) == 3

    def test_history_persists_after_pop(self):
        """History persists even after popping from stack"""
        manager = ActivationManager()

        manager.push_activation("chain-a")
        manager.record_activation("chain-a", "chain-b")
        manager.push_activation("chain-b")
        manager.pop_activation()  # Pop chain-b

        # History still contains the activation
        assert ("chain-a", "chain-b") in manager.activation_history

    def test_duplicate_activations_only_recorded_once(self):
        """Duplicate activations only appear once in history (set behavior)"""
        manager = ActivationManager()

        manager.record_activation("chain-a", "chain-b")
        manager.record_activation("chain-a", "chain-b")  # Duplicate

        assert len(manager.activation_history) == 1

    def test_bidirectional_activations_both_recorded(self):
        """A→B and B→A are different and both recorded"""
        manager = ActivationManager()

        manager.record_activation("chain-a", "chain-b")
        manager.record_activation("chain-b", "chain-a")

        history = manager.activation_history
        assert ("chain-a", "chain-b") in history
        assert ("chain-b", "chain-a") in history
        assert len(history) == 2


class TestActivationManagerState:
    """Test state management methods"""

    def test_clear_stack(self):
        """clear_stack() removes all activations from stack"""
        manager = ActivationManager()
        manager.push_activation("chain-a")
        manager.push_activation("chain-b")
        manager.record_activation("chain-a", "chain-b")

        manager.clear_stack()

        assert manager.get_activation_depth() == 0
        assert manager.activation_stack == []
        # History is NOT cleared
        assert len(manager.activation_history) == 1

    def test_clear_history(self):
        """clear_history() removes all history entries"""
        manager = ActivationManager()
        manager.push_activation("chain-a")
        manager.record_activation("chain-a", "chain-b")
        manager.record_activation("chain-b", "chain-c")

        manager.clear_history()

        # Stack is NOT cleared
        assert manager.get_activation_depth() == 1
        # History is cleared
        assert manager.activation_history == set()

    def test_reset(self):
        """reset() clears both stack and history"""
        manager = ActivationManager()
        manager.push_activation("chain-a")
        manager.push_activation("chain-b")
        manager.record_activation("chain-a", "chain-b")

        manager.reset()

        assert manager.get_activation_depth() == 0
        assert manager.activation_stack == []
        assert manager.activation_history == set()

    def test_repr(self):
        """__repr__ provides useful debug information"""
        manager = ActivationManager()
        manager.push_activation("chain-a")
        manager.push_activation("chain-b")
        manager.record_activation("chain-a", "chain-b")

        repr_str = repr(manager)

        assert "ActivationManager" in repr_str
        assert "chain-a" in repr_str
        assert "chain-b" in repr_str
        assert "history_count" in repr_str


class TestThreadSafety:
    """Test thread-safe operations"""

    def test_concurrent_push_operations(self):
        """Multiple threads can push safely"""
        manager = ActivationManager()
        errors = []

        def push_chain(chain_id):
            try:
                for i in range(10):
                    manager.push_activation(f"{chain_id}-{i}")
                    time.sleep(0.001)  # Simulate work
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=push_chain, args=(f"chain-{i}",))
            for i in range(5)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert manager.get_activation_depth() == 50  # 5 threads × 10 pushes

    def test_concurrent_push_and_pop(self):
        """Push and pop operations are thread-safe"""
        manager = ActivationManager()
        errors = []

        def push_chains():
            try:
                for i in range(20):
                    manager.push_activation(f"chain-push-{i}")
                    time.sleep(0.001)
            except Exception as e:
                errors.append(e)

        def pop_chains():
            try:
                for i in range(20):
                    manager.pop_activation()
                    time.sleep(0.001)
            except Exception as e:
                errors.append(e)

        push_thread = threading.Thread(target=push_chains)
        pop_thread = threading.Thread(target=pop_chains)

        push_thread.start()
        pop_thread.start()
        push_thread.join()
        pop_thread.join()

        assert len(errors) == 0
        # Final depth depends on race conditions, but should not crash

    def test_concurrent_reads_safe(self):
        """Multiple threads can read state safely"""
        manager = ActivationManager()
        manager.push_activation("chain-a")
        manager.push_activation("chain-b")
        errors = []
        results = []

        def read_state():
            try:
                for _ in range(100):
                    depth = manager.get_activation_depth()
                    current = manager.get_current_chain()
                    stack = manager.activation_stack
                    results.append((depth, current, len(stack)))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=read_state) for _ in range(5)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(results) == 500  # 5 threads × 100 reads

    def test_concurrent_history_recording(self):
        """Multiple threads can record history safely"""
        manager = ActivationManager()
        errors = []

        def record_activations(thread_id):
            try:
                for i in range(10):
                    manager.record_activation(f"chain-{thread_id}", f"target-{i}")
                    time.sleep(0.001)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=record_activations, args=(i,))
            for i in range(5)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        # Each thread records 10 unique transitions
        assert len(manager.activation_history) == 50


class TestEdgeCases:
    """Test edge cases and boundary conditions"""

    def test_very_deep_activation_stack(self):
        """Can handle very deep activation stacks"""
        manager = ActivationManager()

        # Push 1000 chains
        for i in range(1000):
            manager.push_activation(f"chain-{i}")

        assert manager.get_activation_depth() == 1000
        assert manager.get_current_chain() == "chain-999"

        # Can detect circular at any depth
        can_activate, _ = manager.can_activate("chain-999", "chain-0")
        assert can_activate is False

    def test_activation_with_special_characters(self):
        """Chain IDs with special characters are handled correctly"""
        manager = ActivationManager()

        special_ids = [
            "chain-with-dashes",
            "chain_with_underscores",
            "chain.with.dots",
            "chain:with:colons",
            "chain/with/slashes"
        ]

        for chain_id in special_ids:
            manager.push_activation(chain_id)

        assert manager.get_activation_depth() == len(special_ids)
        assert manager.get_current_chain() == special_ids[-1]

    def test_empty_string_chain_id(self):
        """Empty string chain ID is allowed (though not recommended)"""
        manager = ActivationManager()
        manager.push_activation("")

        assert manager.get_activation_depth() == 1
        assert manager.get_current_chain() == ""

    def test_activation_stack_is_copy(self):
        """activation_stack property returns copy (not reference)"""
        manager = ActivationManager()
        manager.push_activation("chain-a")

        stack1 = manager.activation_stack
        stack1.append("external-modification")

        stack2 = manager.activation_stack

        # Original stack unchanged
        assert len(stack2) == 1
        assert "external-modification" not in stack2

    def test_activation_history_is_copy(self):
        """activation_history property returns copy (not reference)"""
        manager = ActivationManager()
        manager.record_activation("chain-a", "chain-b")

        history1 = manager.activation_history
        history1.add(("external", "modification"))

        history2 = manager.activation_history

        # Original history unchanged
        assert len(history2) == 1
        assert ("external", "modification") not in history2
