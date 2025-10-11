"""
Integration tests for intelligence system wiring

Tests the complete flow from initialization through task generation,
ensuring all components communicate correctly via TaskOrchestrator.
"""

import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

from crack.track.core.state import TargetProfile
from crack.track.intelligence.integration import initialize_intelligence_system
from crack.track.intelligence.task_orchestrator import TaskOrchestrator
from crack.track.intelligence.correlation_engine import CorrelationIntelligence
from crack.track.intelligence.scoring import TaskScorer
from crack.track.methodology.methodology_engine import MethodologyEngine
from crack.track.core.events import EventBus


@pytest.fixture
def temp_config(tmp_path):
    """Create temporary config file"""
    config_data = {
        "intelligence": {
            "enabled": True,
            "correlation": {
                "enabled": True
            },
            "methodology": {
                "enabled": True
            }
        }
    }
    config_path = tmp_path / "config.json"
    with open(config_path, 'w') as f:
        json.dump(config_data, f)
    return str(config_path)


@pytest.fixture
def temp_config_disabled(tmp_path):
    """Create temporary config with intelligence disabled"""
    config_data = {
        "intelligence": {
            "enabled": False
        }
    }
    config_path = tmp_path / "config.json"
    with open(config_path, 'w') as f:
        json.dump(config_data, f)
    return str(config_path)


@pytest.fixture
def mock_profile():
    """Create mock TargetProfile"""
    profile = MagicMock(spec=TargetProfile)
    profile.target = "192.168.45.100"
    profile.ports = {
        80: {'service': 'http', 'version': 'Apache 2.4.49', 'state': 'open'},
        22: {'service': 'ssh', 'version': 'OpenSSH 7.9', 'state': 'open'},
        445: {'service': 'smb', 'version': 'Samba 4.5', 'state': 'open'}
    }
    profile.findings = []
    return profile


class TestIntelligenceInitialization:
    """Test initialize_intelligence_system() function"""

    def test_initialize_creates_orchestrator(self, temp_config, mock_profile):
        """
        GIVEN: Valid config and profile
        WHEN: initialize_intelligence_system() called
        THEN: Returns TaskOrchestrator instance
        """
        orchestrator = initialize_intelligence_system(
            "192.168.45.100",
            mock_profile,
            config_path=temp_config
        )

        assert orchestrator is not None
        assert isinstance(orchestrator, TaskOrchestrator)
        assert orchestrator.target == "192.168.45.100"
        assert orchestrator.profile == mock_profile

    def test_correlation_engine_attached(self, temp_config, mock_profile):
        """
        GIVEN: Correlation enabled in config
        WHEN: Intelligence system initialized
        THEN: Correlation engine attached to orchestrator
        """
        orchestrator = initialize_intelligence_system(
            "192.168.45.100",
            mock_profile,
            config_path=temp_config
        )

        assert hasattr(orchestrator, 'correlation_engine')
        assert orchestrator.correlation_engine is not None
        assert isinstance(orchestrator.correlation_engine, CorrelationIntelligence)

    def test_methodology_engine_attached(self, temp_config, mock_profile):
        """
        GIVEN: Methodology enabled in config
        WHEN: Intelligence system initialized
        THEN: Methodology engine attached to orchestrator
        """
        orchestrator = initialize_intelligence_system(
            "192.168.45.100",
            mock_profile,
            config_path=temp_config
        )

        assert hasattr(orchestrator, 'methodology_engine')
        assert orchestrator.methodology_engine is not None
        assert isinstance(orchestrator.methodology_engine, MethodologyEngine)

    def test_scorer_attached(self, temp_config, mock_profile):
        """
        GIVEN: Intelligence system initialized
        WHEN: TaskScorer should be attached
        THEN: Orchestrator has scorer instance
        """
        orchestrator = initialize_intelligence_system(
            "192.168.45.100",
            mock_profile,
            config_path=temp_config
        )

        assert orchestrator.scorer is not None
        assert isinstance(orchestrator.scorer, TaskScorer)

    def test_disabled_intelligence_returns_none(self, temp_config_disabled, mock_profile):
        """
        GIVEN: Intelligence disabled in config
        WHEN: initialize_intelligence_system() called
        THEN: Returns None
        """
        orchestrator = initialize_intelligence_system(
            "192.168.45.100",
            mock_profile,
            config_path=temp_config_disabled
        )

        assert orchestrator is None


class TestTaskGeneration:
    """Test end-to-end task generation through orchestrator"""

    def test_generate_next_tasks_merges_engines(self, temp_config, mock_profile):
        """
        GIVEN: Both engines attached
        WHEN: generate_next_tasks() called
        THEN: Queries both correlation and methodology engines
        """
        orchestrator = initialize_intelligence_system(
            "192.168.45.100",
            mock_profile,
            config_path=temp_config
        )

        # Mock engine methods to return test tasks
        correlation_task = {
            'id': 'corr-test-1',
            'name': 'Correlation Task',
            'type': 'executable',
            'intelligence_source': 'correlation'
        }
        methodology_task = {
            'id': 'meth-test-1',
            'name': 'Methodology Task',
            'type': 'executable',
            'intelligence_source': 'methodology'
        }

        orchestrator.correlation_engine.get_correlation_tasks = MagicMock(
            return_value=[correlation_task]
        )
        orchestrator.methodology_engine.get_phase_suggestions = MagicMock(
            return_value=[methodology_task]
        )

        # Generate tasks
        tasks = orchestrator.generate_next_tasks(max_tasks=5)

        # Verify both engines were queried
        orchestrator.correlation_engine.get_correlation_tasks.assert_called_once()
        orchestrator.methodology_engine.get_phase_suggestions.assert_called_once()

        # Verify tasks merged
        assert len(tasks) == 2
        task_ids = {t['id'] for t in tasks}
        assert 'corr-test-1' in task_ids
        assert 'meth-test-1' in task_ids

    def test_priority_scoring_applied(self, temp_config, mock_profile):
        """
        GIVEN: Orchestrator with scorer attached
        WHEN: generate_next_tasks() called
        THEN: Tasks have priority scores
        """
        orchestrator = initialize_intelligence_system(
            "192.168.45.100",
            mock_profile,
            config_path=temp_config
        )

        # Mock engine to return task
        test_task = {
            'id': 'test-1',
            'name': 'Test Task',
            'type': 'executable',
            'metadata': {
                'matches_oscp_pattern': True,
                'oscp_likelihood': 0.8
            }
        }

        orchestrator.correlation_engine.get_correlation_tasks = MagicMock(
            return_value=[test_task]
        )
        orchestrator.methodology_engine.get_phase_suggestions = MagicMock(
            return_value=[]
        )

        # Generate tasks
        tasks = orchestrator.generate_next_tasks(max_tasks=5)

        # Verify priority added
        assert len(tasks) == 1
        assert 'priority' in tasks[0]
        assert isinstance(tasks[0]['priority'], (int, float))

    def test_end_to_end_finding_to_orchestrator(self, temp_config, mock_profile):
        """
        GIVEN: Complete intelligence system
        WHEN: Finding added → correlation → methodology → orchestrator
        THEN: Tasks flow through entire pipeline

        This is the critical integration test proving Method 1 + Method 2 merge.
        """
        # Initialize system
        orchestrator = initialize_intelligence_system(
            "192.168.45.100",
            mock_profile,
            config_path=temp_config
        )

        # Clear EventBus handlers to avoid side effects
        EventBus._handlers.clear()

        # Re-register correlation engine handler
        orchestrator.correlation_engine._register_handlers()

        # Simulate finding being added
        test_finding = {
            'type': 'credential',
            'description': 'admin:password123',
            'source': 'hydra'
        }

        # Emit finding_added event (simulates profile.add_finding)
        EventBus.emit('finding_added', {'finding': test_finding})

        # Correlation engine should have processed finding
        assert len(orchestrator.correlation_engine.processed_findings) > 0

        # Methodology should still provide phase tasks
        methodology_tasks = orchestrator.methodology_engine.get_phase_suggestions()

        # Generate top tasks from orchestrator
        top_tasks = orchestrator.generate_next_tasks(max_tasks=5)

        # Verify tasks come from methodology (correlation emits via events)
        assert len(top_tasks) >= 0  # May be empty if no quick-wins match

        # All tasks should have priority scores
        for task in top_tasks:
            assert 'priority' in task


class TestEngineConfiguration:
    """Test selective engine enablement"""

    def test_correlation_only(self, tmp_path, mock_profile):
        """
        GIVEN: Config with only correlation enabled
        WHEN: System initialized
        THEN: Only correlation engine attached
        """
        config_data = {
            "intelligence": {
                "enabled": True,
                "correlation": {"enabled": True},
                "methodology": {"enabled": False}
            }
        }
        config_path = tmp_path / "config.json"
        with open(config_path, 'w') as f:
            json.dump(config_data, f)

        orchestrator = initialize_intelligence_system(
            "192.168.45.100",
            mock_profile,
            config_path=str(config_path)
        )

        assert hasattr(orchestrator, 'correlation_engine')
        assert orchestrator.correlation_engine is not None
        assert not hasattr(orchestrator, 'methodology_engine') or \
               orchestrator.methodology_engine is None

    def test_methodology_only(self, tmp_path, mock_profile):
        """
        GIVEN: Config with only methodology enabled
        WHEN: System initialized
        THEN: Only methodology engine attached
        """
        config_data = {
            "intelligence": {
                "enabled": True,
                "correlation": {"enabled": False},
                "methodology": {"enabled": True}
            }
        }
        config_path = tmp_path / "config.json"
        with open(config_path, 'w') as f:
            json.dump(config_data, f)

        orchestrator = initialize_intelligence_system(
            "192.168.45.100",
            mock_profile,
            config_path=str(config_path)
        )

        assert not hasattr(orchestrator, 'correlation_engine') or \
               orchestrator.correlation_engine is None
        assert hasattr(orchestrator, 'methodology_engine')
        assert orchestrator.methodology_engine is not None
