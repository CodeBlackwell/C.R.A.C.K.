"""
Tests for track/intelligence/telemetry.py - Anonymous usage statistics

Validates telemetry collection for intelligence system effectiveness:
- Initialization with opt-in/opt-out
- Suggestion tracking
- Chain tracking
- Pattern detection tracking
- Derived metrics calculation
- Persistence
- Privacy guarantees
"""

import pytest
from pathlib import Path
from crack.track.intelligence.telemetry import Telemetry


class TestTelemetryInitialization:
    """Tests for Telemetry initialization"""

    def test_disabled_telemetry_skips_collection(self, temp_crack_home, tmp_path):
        """
        GIVEN: Telemetry initialized with enabled=False
        WHEN: Methods called to record metrics
        THEN: No data collected or persisted
        """
        storage_path = tmp_path / "telemetry.json"
        telemetry = Telemetry(storage_path=storage_path, enabled=False)

        # Try to record various metrics
        telemetry.record_intelligence_suggestion(5)
        telemetry.record_suggestion_accepted("test-suggestion")
        telemetry.record_chain_attempt("test-chain")
        telemetry.record_chain_completion("test-chain", 0.8)
        telemetry.record_pattern_detection()
        telemetry.record_weight_update()

        # Verify no file created (nothing persisted)
        assert not storage_path.exists()

        # Verify get_metrics returns empty when disabled
        metrics = telemetry.get_metrics()
        assert metrics == {}

    def test_initialization_loads_existing_metrics(self, temp_crack_home, tmp_path):
        """
        GIVEN: Existing telemetry file with data
        WHEN: Telemetry initialized
        THEN: Existing metrics loaded
        """
        storage_path = tmp_path / "telemetry.json"

        # Create existing metrics file
        import json
        existing_data = {
            'intelligence_suggestions': 10,
            'suggestions_accepted': 5,
            'chain_attempts': 3,
            'chain_completions': 2,
            'pattern_detections': 8,
            'weight_updates': 4,
            'started_at': '2025-01-01T00:00:00'
        }
        storage_path.write_text(json.dumps(existing_data, indent=2))

        # Initialize telemetry
        telemetry = Telemetry(storage_path=storage_path, enabled=True)

        # Verify data loaded
        assert telemetry.metrics['intelligence_suggestions'] == 10
        assert telemetry.metrics['suggestions_accepted'] == 5
        assert telemetry.metrics['chain_attempts'] == 3
        assert telemetry.metrics['chain_completions'] == 2

    def test_initialization_handles_corrupted_file(self, temp_crack_home, tmp_path):
        """
        GIVEN: Corrupted telemetry file
        WHEN: Telemetry initialized
        THEN: Defaults to fresh metrics without crashing
        """
        storage_path = tmp_path / "telemetry.json"
        storage_path.write_text("invalid json{{{")

        # Should not crash
        telemetry = Telemetry(storage_path=storage_path, enabled=True)

        # Should have default metrics
        assert telemetry.metrics['intelligence_suggestions'] == 0
        assert telemetry.metrics['suggestions_accepted'] == 0


class TestSuggestionTracking:
    """Tests for suggestion tracking"""

    def test_record_intelligence_suggestion_increments_counter(self, temp_crack_home, tmp_path):
        """
        GIVEN: Telemetry enabled
        WHEN: Intelligence suggestions recorded
        THEN: Counter incremented correctly
        """
        storage_path = tmp_path / "telemetry.json"
        telemetry = Telemetry(storage_path=storage_path, enabled=True)

        telemetry.record_intelligence_suggestion(3)
        assert telemetry.metrics['intelligence_suggestions'] == 3

        telemetry.record_intelligence_suggestion(2)
        assert telemetry.metrics['intelligence_suggestions'] == 5

    def test_record_suggestion_accepted_tracks_acceptance(self, temp_crack_home, tmp_path):
        """
        GIVEN: Telemetry enabled
        WHEN: User accepts suggestions
        THEN: Acceptance counter incremented
        """
        storage_path = tmp_path / "telemetry.json"
        telemetry = Telemetry(storage_path=storage_path, enabled=True)

        telemetry.record_suggestion_accepted("suggestion-1")
        assert telemetry.metrics['suggestions_accepted'] == 1

        telemetry.record_suggestion_accepted("suggestion-2")
        assert telemetry.metrics['suggestions_accepted'] == 2


class TestChainTracking:
    """Tests for attack chain tracking"""

    def test_record_chain_attempt_tracks_attempts(self, temp_crack_home, tmp_path):
        """
        GIVEN: Telemetry enabled
        WHEN: Chain attempts recorded
        THEN: Attempt counter incremented
        """
        storage_path = tmp_path / "telemetry.json"
        telemetry = Telemetry(storage_path=storage_path, enabled=True)

        telemetry.record_chain_attempt("smb-chain")
        assert telemetry.metrics['chain_attempts'] == 1

        telemetry.record_chain_attempt("http-chain")
        assert telemetry.metrics['chain_attempts'] == 2

    def test_record_chain_completion_tracks_completions(self, temp_crack_home, tmp_path):
        """
        GIVEN: Telemetry enabled
        WHEN: Chain completions recorded
        THEN: Completion counter incremented
        """
        storage_path = tmp_path / "telemetry.json"
        telemetry = Telemetry(storage_path=storage_path, enabled=True)

        telemetry.record_chain_completion("smb-chain", 0.8)
        assert telemetry.metrics['chain_completions'] == 1

        telemetry.record_chain_completion("http-chain", 1.0)
        assert telemetry.metrics['chain_completions'] == 2


class TestPatternTracking:
    """Tests for pattern detection tracking"""

    def test_record_pattern_detection(self, temp_crack_home, tmp_path):
        """
        GIVEN: Telemetry enabled
        WHEN: Pattern detections recorded
        THEN: Detection counter incremented
        """
        storage_path = tmp_path / "telemetry.json"
        telemetry = Telemetry(storage_path=storage_path, enabled=True)

        telemetry.record_pattern_detection()
        assert telemetry.metrics['pattern_detections'] == 1

        telemetry.record_pattern_detection()
        assert telemetry.metrics['pattern_detections'] == 2

    def test_record_weight_update(self, temp_crack_home, tmp_path):
        """
        GIVEN: Telemetry enabled
        WHEN: Weight updates recorded
        THEN: Update counter incremented
        """
        storage_path = tmp_path / "telemetry.json"
        telemetry = Telemetry(storage_path=storage_path, enabled=True)

        telemetry.record_weight_update()
        assert telemetry.metrics['weight_updates'] == 1

        telemetry.record_weight_update()
        assert telemetry.metrics['weight_updates'] == 2


class TestDerivedMetrics:
    """Tests for derived metric calculations"""

    def test_acceptance_rate_calculation(self, temp_crack_home, tmp_path):
        """
        GIVEN: Suggestions generated and some accepted
        WHEN: get_metrics() called
        THEN: Correct acceptance rate calculated
        """
        storage_path = tmp_path / "telemetry.json"
        telemetry = Telemetry(storage_path=storage_path, enabled=True)

        telemetry.record_intelligence_suggestion(10)
        telemetry.record_suggestion_accepted("s1")
        telemetry.record_suggestion_accepted("s2")
        telemetry.record_suggestion_accepted("s3")

        metrics = telemetry.get_metrics()
        assert metrics['acceptance_rate'] == 0.3

    def test_acceptance_rate_zero_suggestions(self, temp_crack_home, tmp_path):
        """
        GIVEN: No suggestions generated
        WHEN: get_metrics() called
        THEN: Acceptance rate is 0.0
        """
        storage_path = tmp_path / "telemetry.json"
        telemetry = Telemetry(storage_path=storage_path, enabled=True)

        metrics = telemetry.get_metrics()
        assert metrics['acceptance_rate'] == 0.0

    def test_completion_rate_calculation(self, temp_crack_home, tmp_path):
        """
        GIVEN: Chain attempts with some completions
        WHEN: get_metrics() called
        THEN: Correct completion rate calculated
        """
        storage_path = tmp_path / "telemetry.json"
        telemetry = Telemetry(storage_path=storage_path, enabled=True)

        telemetry.record_chain_attempt("chain-1")
        telemetry.record_chain_attempt("chain-2")
        telemetry.record_chain_attempt("chain-3")
        telemetry.record_chain_attempt("chain-4")

        telemetry.record_chain_completion("chain-1", 0.8)
        telemetry.record_chain_completion("chain-3", 1.0)

        metrics = telemetry.get_metrics()
        assert metrics['completion_rate'] == 0.5

    def test_completion_rate_zero_attempts(self, temp_crack_home, tmp_path):
        """
        GIVEN: No chain attempts
        WHEN: get_metrics() called
        THEN: Completion rate is 0.0
        """
        storage_path = tmp_path / "telemetry.json"
        telemetry = Telemetry(storage_path=storage_path, enabled=True)

        metrics = telemetry.get_metrics()
        assert metrics['completion_rate'] == 0.0


class TestPersistence:
    """Tests for metric persistence"""

    def test_metrics_persist_across_instances(self, temp_crack_home, tmp_path):
        """
        GIVEN: Telemetry with recorded metrics
        WHEN: New instance created with same storage path
        THEN: Metrics survive reload
        """
        storage_path = tmp_path / "telemetry.json"

        # First instance
        telemetry1 = Telemetry(storage_path=storage_path, enabled=True)
        telemetry1.record_intelligence_suggestion(5)
        telemetry1.record_suggestion_accepted("test")
        telemetry1.record_chain_attempt("chain-1")

        # Verify persisted
        assert storage_path.exists()

        # Second instance
        telemetry2 = Telemetry(storage_path=storage_path, enabled=True)

        # Verify metrics loaded
        assert telemetry2.metrics['intelligence_suggestions'] == 5
        assert telemetry2.metrics['suggestions_accepted'] == 1
        assert telemetry2.metrics['chain_attempts'] == 1

    def test_clear_metrics_resets_all_counters(self, temp_crack_home, tmp_path):
        """
        GIVEN: Telemetry with collected metrics
        WHEN: clear_metrics() called
        THEN: All counters reset to zero
        """
        storage_path = tmp_path / "telemetry.json"
        telemetry = Telemetry(storage_path=storage_path, enabled=True)

        # Record various metrics
        telemetry.record_intelligence_suggestion(10)
        telemetry.record_suggestion_accepted("test")
        telemetry.record_chain_attempt("chain-1")
        telemetry.record_chain_completion("chain-1", 0.8)
        telemetry.record_pattern_detection()
        telemetry.record_weight_update()

        # Clear metrics
        telemetry.clear_metrics()

        # Verify all reset
        assert telemetry.metrics['intelligence_suggestions'] == 0
        assert telemetry.metrics['suggestions_accepted'] == 0
        assert telemetry.metrics['chain_attempts'] == 0
        assert telemetry.metrics['chain_completions'] == 0
        assert telemetry.metrics['pattern_detections'] == 0
        assert telemetry.metrics['weight_updates'] == 0

        # Verify new started_at timestamp
        assert 'started_at' in telemetry.metrics


class TestPrivacy:
    """Tests for privacy guarantees"""

    def test_metrics_contain_no_sensitive_data(self, temp_crack_home, tmp_path):
        """
        GIVEN: Telemetry with recorded metrics
        WHEN: Metrics inspected
        THEN: No IP addresses, targets, or credentials present

        PRIVACY GUARANTEE: Only anonymous counters stored
        """
        storage_path = tmp_path / "telemetry.json"
        telemetry = Telemetry(storage_path=storage_path, enabled=True)

        # Record metrics with sensitive IDs (should be ignored in storage)
        telemetry.record_intelligence_suggestion(5)
        telemetry.record_suggestion_accepted("192.168.45.100-suggestion")
        telemetry.record_chain_attempt("192.168.45.100-smb-chain")
        telemetry.record_chain_completion("192.168.45.100-http-chain", 0.8)

        # Get metrics
        metrics = telemetry.get_metrics()

        # Verify only counters (no IDs stored)
        assert 'intelligence_suggestions' in metrics
        assert 'suggestions_accepted' in metrics
        assert 'chain_attempts' in metrics
        assert 'chain_completions' in metrics

        # Verify no sensitive keys
        sensitive_keys = ['ip', 'target', 'password', 'credential', 'username']
        for key in sensitive_keys:
            assert key not in str(metrics).lower()

        # Verify file content is also clean
        import json
        with open(storage_path, 'r') as f:
            file_content = f.read()
            for key in sensitive_keys:
                assert key not in file_content.lower()
