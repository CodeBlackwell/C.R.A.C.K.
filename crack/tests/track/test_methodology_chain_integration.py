"""
Integration tests for MethodologyEngine attack chain functionality

Tests the complete flow:
1. MethodologyEngine loads attack chains from JSON
2. ChainExecutor tracks chain progress
3. Chains appear in phase suggestions
4. Chain progress persists to profile
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

from crack.track.methodology.methodology_engine import MethodologyEngine
from crack.track.methodology.phases import Phase
from crack.track.core.state import TargetProfile


@pytest.fixture
def mock_profile():
    """Create mock TargetProfile"""
    profile = MagicMock(spec=TargetProfile)
    profile.target = "192.168.45.100"
    profile.ports = {
        80: {'service': 'http', 'version': 'Apache 2.4.41', 'state': 'open'},
        445: {'service': 'smb', 'version': 'Samba 4.5.0', 'state': 'open'}
    }
    profile.findings = []
    profile.metadata = {}
    return profile


@pytest.fixture
def mock_config():
    """Create mock intelligence config"""
    return {
        'enabled': True,
        'methodology': {'enabled': True}
    }


class TestMethodologyChainLoading:
    """Test attack chain loading from JSON"""

    def test_methodology_loads_attack_chains_from_json(self, mock_profile, mock_config):
        """
        GIVEN: attack_chains.json exists
        WHEN: MethodologyEngine initialized
        THEN: Chains loaded into registry
        """
        engine = MethodologyEngine("192.168.45.100", mock_profile, mock_config)

        # Verify chains loaded
        assert engine.chain_registry is not None
        chains = engine.chain_registry.list_all()
        assert len(chains) > 0  # Should have loaded chains from JSON

    def test_loaded_chains_have_valid_structure(self, mock_profile, mock_config):
        """
        GIVEN: Chains loaded from JSON
        WHEN: Inspecting chain structure
        THEN: All required fields present
        """
        engine = MethodologyEngine("192.168.45.100", mock_profile, mock_config)

        chains = engine.chain_registry.list_all()
        assert len(chains) >= 10  # Agent 2 created 10+ chains

        # Check first chain structure
        chain = chains[0]
        assert chain.id
        assert chain.name
        assert chain.description
        assert len(chain.steps) > 0
        assert chain.oscp_relevance >= 0.0 and chain.oscp_relevance <= 1.0

    def test_chain_steps_have_commands(self, mock_profile, mock_config):
        """
        GIVEN: Chains loaded from JSON
        WHEN: Inspecting chain steps
        THEN: Steps have command templates
        """
        engine = MethodologyEngine("192.168.45.100", mock_profile, mock_config)

        chains = engine.chain_registry.list_all()
        chain = chains[0]

        # Check steps
        assert len(chain.steps) > 0
        for step in chain.steps:
            assert step.id
            assert step.name
            # Command template or manual alternative required
            assert step.command_template or step.manual


class TestChainExecutorIntegration:
    """Test ChainExecutor integration with MethodologyEngine"""

    def test_chain_executor_initialized_with_registry(self, mock_profile, mock_config):
        """
        GIVEN: MethodologyEngine initialized
        WHEN: Checking ChainExecutor
        THEN: Executor has access to registry
        """
        engine = MethodologyEngine("192.168.45.100", mock_profile, mock_config)

        assert engine.chain_executor is not None
        assert engine.chain_executor.registry is engine.chain_registry

    def test_activate_chain_via_executor(self, mock_profile, mock_config):
        """
        GIVEN: MethodologyEngine with chains
        WHEN: Activating a chain
        THEN: Chain tracked in executor
        """
        engine = MethodologyEngine("192.168.45.100", mock_profile, mock_config)

        # Get first chain
        chains = engine.chain_registry.list_all()
        assert len(chains) > 0
        chain = chains[0]

        # Activate chain
        success = engine.chain_executor.activate_chain(chain.id)
        assert success is True

        # Verify active
        active_chains = engine.chain_executor.get_active_chains()
        assert len(active_chains) == 1
        assert active_chains[0]['chain_id'] == chain.id

    def test_chain_progress_persists_to_profile(self, mock_profile, mock_config):
        """
        GIVEN: Chain activated
        WHEN: Progress updated
        THEN: Persists to profile metadata
        """
        engine = MethodologyEngine("192.168.45.100", mock_profile, mock_config)

        # Activate chain
        chains = engine.chain_registry.list_all()
        chain = chains[0]
        engine.chain_executor.activate_chain(chain.id)

        # Update progress (simulate step completion)
        step = chain.steps[0]
        engine.chain_executor.update_progress(chain.id, step.id, "success output", True)

        # Verify persisted
        assert 'attack_chains' in mock_profile.metadata
        assert chain.id in mock_profile.metadata['attack_chains']
        chain_data = mock_profile.metadata['attack_chains'][chain.id]
        assert step.id in chain_data['completed_steps']


class TestPhaseChainSuggestions:
    """Test chain suggestions in phase tasks"""

    def test_get_phase_suggestions_includes_chain_steps(self, mock_profile, mock_config):
        """
        GIVEN: Chain activated with pending steps
        WHEN: get_phase_suggestions() called
        THEN: Chain steps appear in suggestions
        """
        engine = MethodologyEngine("192.168.45.100", mock_profile, mock_config)

        # Activate a chain
        chains = engine.chain_registry.list_all()
        sqli_chains = [c for c in chains if 'sqli' in c.id.lower() or 'sql' in c.id.lower()]

        if sqli_chains:
            chain = sqli_chains[0]
            engine.chain_executor.activate_chain(chain.id)

            # Get suggestions
            suggestions = engine.get_phase_suggestions()

            # Check for chain suggestions
            chain_tasks = [s for s in suggestions if s['metadata'].get('category') == 'attack_chain']
            assert len(chain_tasks) > 0

            # Verify chain metadata
            chain_task = chain_tasks[0]
            assert 'chain_id' in chain_task['metadata']
            assert 'step_id' in chain_task['metadata']
            assert 'chain_progress' in chain_task['metadata']

    def test_chain_suggestions_have_commands(self, mock_profile, mock_config):
        """
        GIVEN: Active chain with next step
        WHEN: Suggestions generated
        THEN: Commands have placeholders replaced
        """
        engine = MethodologyEngine("192.168.45.100", mock_profile, mock_config)

        # Activate chain
        chains = engine.chain_registry.list_all()
        chain = chains[0]
        engine.chain_executor.activate_chain(chain.id)

        # Get suggestions
        suggestions = engine.get_phase_suggestions()
        chain_tasks = [s for s in suggestions if s['metadata'].get('category') == 'attack_chain']

        if chain_tasks:
            chain_task = chain_tasks[0]
            command = chain_task['metadata']['command']

            # Verify placeholders replaced
            assert '<TARGET>' not in command
            assert '192.168.45.100' in command

    def test_chain_suggestions_tagged_with_phase(self, mock_profile, mock_config):
        """
        GIVEN: Chain suggestions generated
        WHEN: Checking task metadata
        THEN: All tagged with phase alignment
        """
        engine = MethodologyEngine("192.168.45.100", mock_profile, mock_config)

        # Activate chain
        chains = engine.chain_registry.list_all()
        chain = chains[0]
        engine.chain_executor.activate_chain(chain.id)

        # Get suggestions
        suggestions = engine.get_phase_suggestions()

        # All should have phase metadata
        for suggestion in suggestions:
            assert suggestion['phase_alignment'] is True
            assert suggestion['current_phase'] == Phase.RECONNAISSANCE.name
            assert suggestion['intelligence_source'] == 'methodology'


class TestEndToEndChainFlow:
    """Test complete attack chain lifecycle"""

    def test_complete_chain_lifecycle(self, mock_profile, mock_config):
        """
        PROVES: Complete chain flow from load → activate → progress → complete

        Steps:
        1. Load chains from JSON
        2. Activate a chain
        3. Get next step suggestion
        4. Mark step complete
        5. Verify progress updates
        6. Complete all steps
        7. Verify chain completion
        """
        engine = MethodologyEngine("192.168.45.100", mock_profile, mock_config)

        # 1. Verify chains loaded
        chains = engine.chain_registry.list_all()
        assert len(chains) > 0

        # 2. Activate chain
        chain = chains[0]
        engine.chain_executor.activate_chain(chain.id)

        # 3. Get next step
        next_steps = engine.chain_executor.get_next_steps(max_chains=1)
        assert len(next_steps) == 1
        assert next_steps[0]['progress'] == 0.0  # No steps completed

        # 4. Mark first step complete
        step = next_steps[0]['step']
        engine.chain_executor.update_progress(chain.id, step.id, "success", True)

        # 5. Verify progress updated
        next_steps = engine.chain_executor.get_next_steps(max_chains=1)
        assert next_steps[0]['progress'] > 0.0

        # 6. Complete all steps
        for step in chain.steps:
            engine.chain_executor.update_progress(chain.id, step.id, "success", True)

        # 7. Verify completion
        active_chains = engine.chain_executor.get_active_chains()
        assert active_chains[0]['is_complete'] is True
        assert active_chains[0]['progress'] == 1.0
