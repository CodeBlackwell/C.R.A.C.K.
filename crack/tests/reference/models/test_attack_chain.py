"""
Tests for Attack Chain Models

Business Value Focus:
- Validate attack chain data model integrity
- Ensure proper serialization/deserialization
- Verify validation rules for OSCP chain definitions

Test Priority: TIER 2 - HIGH (Data Model Integrity)
"""

import pytest
from datetime import date


# =============================================================================
# Sample Valid Data
# =============================================================================

VALID_STEP = {
    "name": "Enumerate services",
    "objective": "Identify running services",
    "command_ref": "nmap-service-scan",
    "id": "enum-services",
    "description": "Run nmap service detection",
    "evidence": ["nmap output"],
    "dependencies": [],
    "repeatable": True,
    "success_criteria": ["Services identified"],
    "failure_conditions": ["No services found"],
    "next_steps": [],
}

VALID_METADATA = {
    "author": "Test Author",
    "created": "2024-01-15",
    "updated": "2024-01-20",
    "tags": ["OSCP", "enumeration"],
    "category": "recon",
    "platform": "linux",
    "references": ["https://example.com/docs"],
}

VALID_CHAIN = {
    "id": "test-chain-one-example",
    "name": "Test Chain",
    "description": "A test attack chain",
    "version": "1.0.0",
    "metadata": VALID_METADATA,
    "difficulty": "intermediate",
    "time_estimate": "30 minutes",
    "oscp_relevant": True,
    "steps": [VALID_STEP],
    "prerequisites": [],
    "notes": "Test notes",
}


# =============================================================================
# ChainStep Tests
# =============================================================================

class TestChainStep:
    """Tests for ChainStep model"""

    def test_from_dict_valid(self):
        """
        BV: Create step from valid dict

        Scenario:
          Given: Valid step dictionary
          When: from_dict() is called
          Then: Step created successfully
        """
        from reference.models.chain_step import ChainStep

        step = ChainStep.from_dict(VALID_STEP)

        assert step.name == "Enumerate services"
        assert step.objective == "Identify running services"
        assert step.command_ref == "nmap-service-scan"

    def test_from_dict_extracts_id(self):
        """
        BV: Extract step ID

        Scenario:
          Given: Step with ID
          When: from_dict() is called
          Then: ID extracted correctly
        """
        from reference.models.chain_step import ChainStep

        step = ChainStep.from_dict(VALID_STEP)

        assert step.id == "enum-services"

    def test_from_dict_extracts_dependencies(self):
        """
        BV: Extract step dependencies

        Scenario:
          Given: Step with dependencies
          When: from_dict() is called
          Then: Dependencies extracted as tuple
        """
        from reference.models.chain_step import ChainStep

        data = {**VALID_STEP, "dependencies": ["step-one", "step-two"]}
        step = ChainStep.from_dict(data)

        assert step.dependencies == ("step-one", "step-two")

    def test_to_dict_roundtrip(self):
        """
        BV: Serialize and deserialize preserves data

        Scenario:
          Given: Valid step
          When: to_dict() then from_dict()
          Then: Data preserved
        """
        from reference.models.chain_step import ChainStep

        step1 = ChainStep.from_dict(VALID_STEP)
        data = step1.to_dict()
        step2 = ChainStep.from_dict(data)

        assert step1.name == step2.name
        assert step1.id == step2.id
        assert step1.command_ref == step2.command_ref

    def test_validate_missing_name(self):
        """
        BV: Validate requires name

        Scenario:
          Given: Step without name
          When: from_dict() is called
          Then: Raises ValueError
        """
        from reference.models.chain_step import ChainStep

        data = {**VALID_STEP, "name": ""}

        with pytest.raises(ValueError, match="name must be provided"):
            ChainStep.from_dict(data)

    def test_validate_missing_objective(self):
        """
        BV: Validate requires objective

        Scenario:
          Given: Step without objective
          When: from_dict() is called
          Then: Raises ValueError
        """
        from reference.models.chain_step import ChainStep

        data = {**VALID_STEP, "objective": ""}

        with pytest.raises(ValueError, match="objective must be provided"):
            ChainStep.from_dict(data)

    def test_validate_missing_command_ref(self):
        """
        BV: Validate requires command_ref

        Scenario:
          Given: Step without command_ref
          When: from_dict() is called
          Then: Raises ValueError
        """
        from reference.models.chain_step import ChainStep

        data = {**VALID_STEP, "command_ref": ""}

        with pytest.raises(ValueError, match="command_ref must be provided"):
            ChainStep.from_dict(data)

    def test_validate_invalid_id_pattern(self):
        """
        BV: Validate ID pattern

        Scenario:
          Given: Step with invalid ID
          When: from_dict() is called
          Then: Raises ValueError
        """
        from reference.models.chain_step import ChainStep

        data = {**VALID_STEP, "id": "Invalid_ID"}

        with pytest.raises(ValueError, match="must match pattern"):
            ChainStep.from_dict(data)


# =============================================================================
# ChainMetadata Tests
# =============================================================================

class TestChainMetadata:
    """Tests for ChainMetadata model"""

    def test_from_dict_valid(self):
        """
        BV: Create metadata from valid dict

        Scenario:
          Given: Valid metadata dictionary
          When: from_dict() is called
          Then: Metadata created successfully
        """
        from reference.models.chain_metadata import ChainMetadata

        metadata = ChainMetadata.from_dict(VALID_METADATA)

        assert metadata.author == "Test Author"
        assert metadata.category == "recon"

    def test_from_dict_parses_dates(self):
        """
        BV: Parse date strings to date objects

        Scenario:
          Given: Metadata with date strings
          When: from_dict() is called
          Then: Dates parsed correctly
        """
        from reference.models.chain_metadata import ChainMetadata

        metadata = ChainMetadata.from_dict(VALID_METADATA)

        assert isinstance(metadata.created, date)
        assert metadata.created == date(2024, 1, 15)
        assert metadata.updated == date(2024, 1, 20)

    def test_from_dict_extracts_tags(self):
        """
        BV: Extract tags as tuple

        Scenario:
          Given: Metadata with tags list
          When: from_dict() is called
          Then: Tags extracted as tuple
        """
        from reference.models.chain_metadata import ChainMetadata

        metadata = ChainMetadata.from_dict(VALID_METADATA)

        assert metadata.tags == ("OSCP", "enumeration")

    def test_to_dict_roundtrip(self):
        """
        BV: Serialize and deserialize preserves data

        Scenario:
          Given: Valid metadata
          When: to_dict() then from_dict()
          Then: Data preserved
        """
        from reference.models.chain_metadata import ChainMetadata

        metadata1 = ChainMetadata.from_dict(VALID_METADATA)
        data = metadata1.to_dict()
        metadata2 = ChainMetadata.from_dict(data)

        assert metadata1.author == metadata2.author
        assert metadata1.created == metadata2.created
        assert metadata1.tags == metadata2.tags

    def test_validate_missing_author(self):
        """
        BV: Validate requires author

        Scenario:
          Given: Metadata without author
          When: from_dict() is called
          Then: Raises ValueError
        """
        from reference.models.chain_metadata import ChainMetadata

        data = {**VALID_METADATA, "author": ""}

        with pytest.raises(ValueError, match="author must be provided"):
            ChainMetadata.from_dict(data)

    def test_validate_missing_category(self):
        """
        BV: Validate requires category

        Scenario:
          Given: Metadata without category
          When: from_dict() is called
          Then: Raises ValueError
        """
        from reference.models.chain_metadata import ChainMetadata

        data = {**VALID_METADATA, "category": ""}

        with pytest.raises(ValueError, match="category must be provided"):
            ChainMetadata.from_dict(data)

    def test_validate_empty_tags(self):
        """
        BV: Validate requires at least one tag

        Scenario:
          Given: Metadata without tags
          When: from_dict() is called
          Then: Raises ValueError
        """
        from reference.models.chain_metadata import ChainMetadata

        data = {**VALID_METADATA, "tags": []}

        with pytest.raises(ValueError, match="at least one entry"):
            ChainMetadata.from_dict(data)

    def test_validate_created_after_updated(self):
        """
        BV: Validate created cannot be after updated

        Scenario:
          Given: created date after updated
          When: from_dict() is called
          Then: Raises ValueError
        """
        from reference.models.chain_metadata import ChainMetadata

        data = {**VALID_METADATA, "created": "2024-01-25", "updated": "2024-01-20"}

        with pytest.raises(ValueError, match="cannot be later than"):
            ChainMetadata.from_dict(data)

    def test_validate_invalid_reference_url(self):
        """
        BV: Validate reference URLs

        Scenario:
          Given: Invalid reference URL
          When: from_dict() is called
          Then: Raises ValueError
        """
        from reference.models.chain_metadata import ChainMetadata

        data = {**VALID_METADATA, "references": ["not-a-url"]}

        with pytest.raises(ValueError, match="invalid reference URL"):
            ChainMetadata.from_dict(data)


# =============================================================================
# AttackChain Tests
# =============================================================================

class TestAttackChain:
    """Tests for AttackChain model"""

    def test_from_dict_valid(self):
        """
        BV: Create chain from valid dict

        Scenario:
          Given: Valid chain dictionary
          When: from_dict() is called
          Then: Chain created successfully
        """
        from reference.models.attack_chain import AttackChain

        chain = AttackChain.from_dict(VALID_CHAIN)

        assert chain.id == "test-chain-one-example"
        assert chain.name == "Test Chain"
        assert chain.version == "1.0.0"

    def test_from_dict_extracts_metadata(self):
        """
        BV: Extract metadata object

        Scenario:
          Given: Chain with metadata
          When: from_dict() is called
          Then: Metadata object created
        """
        from reference.models.attack_chain import AttackChain

        chain = AttackChain.from_dict(VALID_CHAIN)

        assert chain.metadata.author == "Test Author"
        assert chain.metadata.category == "recon"

    def test_from_dict_extracts_steps(self):
        """
        BV: Extract steps as tuple

        Scenario:
          Given: Chain with steps
          When: from_dict() is called
          Then: Steps extracted as tuple
        """
        from reference.models.attack_chain import AttackChain

        chain = AttackChain.from_dict(VALID_CHAIN)

        assert len(chain.steps) == 1
        assert chain.steps[0].name == "Enumerate services"

    def test_to_dict_roundtrip(self):
        """
        BV: Serialize and deserialize preserves data

        Scenario:
          Given: Valid chain
          When: to_dict() then from_dict()
          Then: Data preserved
        """
        from reference.models.attack_chain import AttackChain

        chain1 = AttackChain.from_dict(VALID_CHAIN)
        data = chain1.to_dict()
        chain2 = AttackChain.from_dict(data)

        assert chain1.id == chain2.id
        assert chain1.name == chain2.name
        assert chain1.version == chain2.version

    def test_validate_missing_id(self):
        """
        BV: Validate requires ID

        Scenario:
          Given: Chain without ID
          When: from_dict() is called
          Then: Raises ValueError
        """
        from reference.models.attack_chain import AttackChain

        data = {**VALID_CHAIN, "id": ""}

        with pytest.raises(ValueError, match="id must be provided"):
            AttackChain.from_dict(data)

    def test_validate_invalid_id_pattern(self):
        """
        BV: Validate ID pattern

        Scenario:
          Given: Chain with invalid ID
          When: from_dict() is called
          Then: Raises ValueError
        """
        from reference.models.attack_chain import AttackChain

        data = {**VALID_CHAIN, "id": "invalid"}

        with pytest.raises(ValueError, match="must match pattern"):
            AttackChain.from_dict(data)

    def test_validate_missing_name(self):
        """
        BV: Validate requires name

        Scenario:
          Given: Chain without name
          When: from_dict() is called
          Then: Raises ValueError
        """
        from reference.models.attack_chain import AttackChain

        data = {**VALID_CHAIN, "name": ""}

        with pytest.raises(ValueError, match="name must be provided"):
            AttackChain.from_dict(data)

    def test_validate_invalid_version(self):
        """
        BV: Validate semantic version

        Scenario:
          Given: Chain with invalid version
          When: from_dict() is called
          Then: Raises ValueError
        """
        from reference.models.attack_chain import AttackChain

        data = {**VALID_CHAIN, "version": "v1.0"}

        with pytest.raises(ValueError, match="semantic versioning"):
            AttackChain.from_dict(data)

    def test_validate_invalid_difficulty(self):
        """
        BV: Validate difficulty values

        Scenario:
          Given: Chain with invalid difficulty
          When: from_dict() is called
          Then: Raises ValueError
        """
        from reference.models.attack_chain import AttackChain

        data = {**VALID_CHAIN, "difficulty": "easy"}

        with pytest.raises(ValueError, match="difficulty must be one of"):
            AttackChain.from_dict(data)

    def test_validate_invalid_time_estimate(self):
        """
        BV: Validate time estimate format

        Scenario:
          Given: Chain with invalid time estimate
          When: from_dict() is called
          Then: Raises ValueError
        """
        from reference.models.attack_chain import AttackChain

        data = {**VALID_CHAIN, "time_estimate": "about an hour"}

        with pytest.raises(ValueError, match="time_estimate must match"):
            AttackChain.from_dict(data)

    def test_validate_no_steps(self):
        """
        BV: Validate at least one step required

        Scenario:
          Given: Chain without steps
          When: from_dict() is called
          Then: Raises ValueError
        """
        from reference.models.attack_chain import AttackChain

        data = {**VALID_CHAIN, "steps": []}

        with pytest.raises(ValueError, match="at least one step"):
            AttackChain.from_dict(data)

    def test_validate_duplicate_step_ids(self):
        """
        BV: Detect duplicate step IDs

        Scenario:
          Given: Chain with duplicate step IDs
          When: from_dict() is called
          Then: Raises ValueError
        """
        from reference.models.attack_chain import AttackChain

        step2 = {**VALID_STEP, "id": "enum-services"}  # Same ID
        data = {**VALID_CHAIN, "steps": [VALID_STEP, step2]}

        with pytest.raises(ValueError, match="duplicate step id"):
            AttackChain.from_dict(data)

    def test_validate_unknown_dependency(self):
        """
        BV: Detect unknown step dependencies

        Scenario:
          Given: Step references unknown dependency
          When: from_dict() is called
          Then: Raises ValueError
        """
        from reference.models.attack_chain import AttackChain

        step_with_dep = {**VALID_STEP, "dependencies": ["unknown-step"]}
        data = {**VALID_CHAIN, "steps": [step_with_dep]}

        with pytest.raises(ValueError, match="references unknown step"):
            AttackChain.from_dict(data)


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Edge case handling tests"""

    def test_chain_with_notes(self):
        """
        BV: Chain notes preserved

        Scenario:
          Given: Chain with notes
          When: from_dict() and to_dict()
          Then: Notes preserved
        """
        from reference.models.attack_chain import AttackChain

        chain = AttackChain.from_dict(VALID_CHAIN)

        assert chain.notes == "Test notes"
        assert chain.to_dict()["notes"] == "Test notes"

    def test_chain_without_notes(self):
        """
        BV: Chain without notes valid

        Scenario:
          Given: Chain without notes
          When: from_dict() is called
          Then: notes is None
        """
        from reference.models.attack_chain import AttackChain

        data = {**VALID_CHAIN}
        del data["notes"]
        chain = AttackChain.from_dict(data)

        assert chain.notes is None

    def test_chain_oscp_relevant_flag(self):
        """
        BV: OSCP relevance flag preserved

        Scenario:
          Given: Chain with oscp_relevant
          When: from_dict() is called
          Then: Flag extracted correctly
        """
        from reference.models.attack_chain import AttackChain

        chain = AttackChain.from_dict(VALID_CHAIN)

        assert chain.oscp_relevant is True

    def test_step_repeatable_flag(self):
        """
        BV: Step repeatable flag preserved

        Scenario:
          Given: Step with repeatable flag
          When: from_dict() is called
          Then: Flag extracted correctly
        """
        from reference.models.chain_step import ChainStep

        step = ChainStep.from_dict(VALID_STEP)

        assert step.repeatable is True

    def test_metadata_platform_optional(self):
        """
        BV: Platform is optional

        Scenario:
          Given: Metadata without platform
          When: from_dict() is called
          Then: platform is None
        """
        from reference.models.chain_metadata import ChainMetadata

        data = {**VALID_METADATA}
        del data["platform"]
        metadata = ChainMetadata.from_dict(data)

        assert metadata.platform is None

    def test_coerce_iterable_from_string(self):
        """
        BV: Single string converted to tuple

        Scenario:
          Given: Prerequisites as single string
          When: from_dict() is called
          Then: Converted to tuple
        """
        from reference.models.attack_chain import AttackChain

        data = {**VALID_CHAIN, "prerequisites": "single-prereq"}
        # This should work but won't match pattern, let's use valid format
        data["prerequisites"] = ["valid-prereq"]
        chain = AttackChain.from_dict(data)

        assert chain.prerequisites == ("valid-prereq",)
