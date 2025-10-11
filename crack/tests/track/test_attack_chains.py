"""
Tests for attack chain core classes

VALUE DELIVERED:
- Validates attack chain data structures
- Tests progress tracking logic
- Ensures serialization/deserialization works
- Proves registry pattern functions correctly
"""

import pytest
from crack.track.methodology.attack_chains import ChainStep, AttackChain, ChainRegistry


class TestChainStep:
    """ChainStep dataclass tests"""

    def test_chain_step_creation(self):
        """ChainStep creates with valid data"""
        step = ChainStep(
            id="test-step",
            name="Test Step",
            description="Test description",
            command_template="echo test"
        )

        assert step.id == "test-step"
        assert step.name == "Test Step"
        assert step.command_template == "echo test"
        assert step.manual is False
        assert step.estimated_time_minutes == 5

    def test_chain_step_validation_requires_id(self):
        """ChainStep raises error without id"""
        with pytest.raises(ValueError, match="requires id and name"):
            ChainStep(
                id="",
                name="Test",
                description="Test",
                command_template="echo test"
            )

    def test_chain_step_validation_requires_name(self):
        """ChainStep raises error without name"""
        with pytest.raises(ValueError, match="requires id and name"):
            ChainStep(
                id="test",
                name="",
                description="Test",
                command_template="echo test"
            )

    def test_chain_step_requires_command_unless_manual(self):
        """ChainStep requires command unless manual=True"""
        # Should fail without command
        with pytest.raises(ValueError, match="requires command_template unless manual=True"):
            ChainStep(
                id="test",
                name="Test",
                description="Test",
                command_template=""
            )

        # Should succeed with manual=True
        step = ChainStep(
            id="test",
            name="Test",
            description="Test",
            command_template="",
            manual=True
        )
        assert step.manual is True


class TestAttackChain:
    """AttackChain dataclass tests"""

    def test_attack_chain_creation(self):
        """AttackChain creates with valid data"""
        chain = AttackChain(
            id="test-chain",
            name="Test Chain",
            description="Test chain description",
            trigger_finding_types=["sqli", "lfi"]
        )

        assert chain.id == "test-chain"
        assert chain.name == "Test Chain"
        assert chain.trigger_finding_types == ["sqli", "lfi"]
        assert chain.oscp_relevance == 0.5

    def test_attack_chain_requires_trigger_types(self):
        """AttackChain raises error without trigger types"""
        with pytest.raises(ValueError, match="requires trigger_finding_types"):
            AttackChain(
                id="test",
                name="Test",
                description="Test",
                trigger_finding_types=[]
            )

    def test_get_current_step_index_returns_correct_index(self):
        """get_current_step_index() returns correct index"""
        chain = AttackChain(
            id="test",
            name="Test",
            description="Test",
            trigger_finding_types=["test"],
            steps=[
                ChainStep(id="step1", name="Step 1", description="D", command_template="cmd1"),
                ChainStep(id="step2", name="Step 2", description="D", command_template="cmd2"),
                ChainStep(id="step3", name="Step 3", description="D", command_template="cmd3")
            ]
        )

        # No steps completed
        assert chain.get_current_step_index([]) == 0

        # First step completed
        assert chain.get_current_step_index(["step1"]) == 1

        # First two steps completed
        assert chain.get_current_step_index(["step1", "step2"]) == 2

        # All steps completed
        assert chain.get_current_step_index(["step1", "step2", "step3"]) == 3

    def test_get_next_step_returns_next_uncompleted_step(self):
        """get_next_step() returns next uncompleted step"""
        chain = AttackChain(
            id="test",
            name="Test",
            description="Test",
            trigger_finding_types=["test"],
            steps=[
                ChainStep(id="step1", name="Step 1", description="D", command_template="cmd1"),
                ChainStep(id="step2", name="Step 2", description="D", command_template="cmd2")
            ]
        )

        # No steps completed - should return step1
        next_step = chain.get_next_step([])
        assert next_step.id == "step1"

        # Step1 completed - should return step2
        next_step = chain.get_next_step(["step1"])
        assert next_step.id == "step2"

        # All completed - should return None
        next_step = chain.get_next_step(["step1", "step2"])
        assert next_step is None

    def test_get_progress_calculates_percentage_correctly(self):
        """get_progress() returns correct percentage"""
        chain = AttackChain(
            id="test",
            name="Test",
            description="Test",
            trigger_finding_types=["test"],
            steps=[
                ChainStep(id="step1", name="Step 1", description="D", command_template="cmd1"),
                ChainStep(id="step2", name="Step 2", description="D", command_template="cmd2"),
                ChainStep(id="step3", name="Step 3", description="D", command_template="cmd3"),
                ChainStep(id="step4", name="Step 4", description="D", command_template="cmd4")
            ]
        )

        # 0% complete
        assert chain.get_progress([]) == 0.0

        # 25% complete
        assert chain.get_progress(["step1"]) == 0.25

        # 50% complete
        assert chain.get_progress(["step1", "step2"]) == 0.5

        # 75% complete
        assert chain.get_progress(["step1", "step2", "step3"]) == 0.75

        # 100% complete
        assert chain.get_progress(["step1", "step2", "step3", "step4"]) == 1.0

    def test_is_complete_detects_completion(self):
        """is_complete() detects completion"""
        chain = AttackChain(
            id="test",
            name="Test",
            description="Test",
            trigger_finding_types=["test"],
            steps=[
                ChainStep(id="step1", name="Step 1", description="D", command_template="cmd1"),
                ChainStep(id="step2", name="Step 2", description="D", command_template="cmd2")
            ]
        )

        # Not complete
        assert chain.is_complete([]) is False
        assert chain.is_complete(["step1"]) is False

        # Complete
        assert chain.is_complete(["step1", "step2"]) is True

    def test_to_dict_serializes_correctly(self):
        """to_dict() serializes correctly"""
        chain = AttackChain(
            id="test",
            name="Test Chain",
            description="Test description",
            trigger_finding_types=["sqli"],
            steps=[
                ChainStep(
                    id="step1",
                    name="Step 1",
                    description="First step",
                    command_template="cmd1",
                    success_indicators=["success"],
                    failure_indicators=["fail"],
                    estimated_time_minutes=10
                )
            ],
            required_phase="EXPLOITATION",
            oscp_relevance=0.8
        )

        data = chain.to_dict()

        assert data['id'] == "test"
        assert data['name'] == "Test Chain"
        assert data['trigger_finding_types'] == ["sqli"]
        assert len(data['steps']) == 1
        assert data['steps'][0]['id'] == "step1"
        assert data['steps'][0]['command_template'] == "cmd1"
        assert data['required_phase'] == "EXPLOITATION"
        assert data['oscp_relevance'] == 0.8

    def test_from_dict_deserializes_correctly(self):
        """from_dict() deserializes correctly"""
        data = {
            'id': 'test',
            'name': 'Test Chain',
            'description': 'Test description',
            'trigger_finding_types': ['sqli', 'lfi'],
            'steps': [
                {
                    'id': 'step1',
                    'name': 'Step 1',
                    'description': 'First step',
                    'command_template': 'cmd1',
                    'success_indicators': ['success'],
                    'failure_indicators': ['fail'],
                    'estimated_time_minutes': 10,
                    'manual': False
                }
            ],
            'required_phase': 'EXPLOITATION',
            'oscp_relevance': 0.8
        }

        chain = AttackChain.from_dict(data)

        assert chain.id == 'test'
        assert chain.name == 'Test Chain'
        assert chain.trigger_finding_types == ['sqli', 'lfi']
        assert len(chain.steps) == 1
        assert chain.steps[0].id == 'step1'
        assert chain.steps[0].command_template == 'cmd1'
        assert chain.required_phase == 'EXPLOITATION'
        assert chain.oscp_relevance == 0.8


class TestChainRegistry:
    """ChainRegistry tests"""

    def test_chain_registry_registers_chains(self):
        """Registry registers chains"""
        registry = ChainRegistry()
        chain = AttackChain(
            id="test-chain",
            name="Test Chain",
            description="Test",
            trigger_finding_types=["test"]
        )

        registry.register(chain)

        assert "test-chain" in registry.chains
        assert registry.chains["test-chain"] == chain

    def test_chain_registry_get_retrieves_by_id(self):
        """Registry.get() retrieves by ID"""
        registry = ChainRegistry()
        chain = AttackChain(
            id="test-chain",
            name="Test Chain",
            description="Test",
            trigger_finding_types=["test"]
        )

        registry.register(chain)

        retrieved = registry.get("test-chain")
        assert retrieved == chain

        # Non-existent chain
        assert registry.get("nonexistent") is None

    def test_chain_registry_get_by_trigger_finds_matching_chains(self):
        """Registry.get_by_trigger() finds matching chains"""
        registry = ChainRegistry()

        sqli_chain = AttackChain(
            id="sqli-chain",
            name="SQLi Chain",
            description="SQLi attack",
            trigger_finding_types=["sqli"]
        )

        lfi_chain = AttackChain(
            id="lfi-chain",
            name="LFI Chain",
            description="LFI attack",
            trigger_finding_types=["lfi"]
        )

        multi_chain = AttackChain(
            id="multi-chain",
            name="Multi Chain",
            description="Multi-vector",
            trigger_finding_types=["sqli", "lfi"]
        )

        registry.register(sqli_chain)
        registry.register(lfi_chain)
        registry.register(multi_chain)

        # Find SQLi chains
        sqli_matches = registry.get_by_trigger("sqli")
        assert len(sqli_matches) == 2
        assert sqli_chain in sqli_matches
        assert multi_chain in sqli_matches

        # Find LFI chains
        lfi_matches = registry.get_by_trigger("lfi")
        assert len(lfi_matches) == 2
        assert lfi_chain in lfi_matches
        assert multi_chain in lfi_matches

        # Case insensitive
        sqli_matches_upper = registry.get_by_trigger("SQLI")
        assert len(sqli_matches_upper) == 2

    def test_chain_registry_list_all_returns_all_chains(self):
        """Registry.list_all() returns all chains"""
        registry = ChainRegistry()

        chain1 = AttackChain(
            id="chain1",
            name="Chain 1",
            description="Test",
            trigger_finding_types=["test1"]
        )

        chain2 = AttackChain(
            id="chain2",
            name="Chain 2",
            description="Test",
            trigger_finding_types=["test2"]
        )

        registry.register(chain1)
        registry.register(chain2)

        all_chains = registry.list_all()
        assert len(all_chains) == 2
        assert chain1 in all_chains
        assert chain2 in all_chains
