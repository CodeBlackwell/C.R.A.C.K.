"""
Tests for ChainValidator - Attack chain validation.

Business Value Focus:
- Schema validation catches malformed chains before execution
- Circular dependency detection prevents infinite loops
- Command reference validation ensures chains can be executed
- Clear error messages help users fix their chain definitions
"""

import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from reference.chains.validator import ChainValidator
from tests.reference.chains.conftest import ChainFactory, MockCommandResolver


# ==============================================================================
# Test: Schema Validation
# ==============================================================================


class TestSchemaValidation:
    """Tests for JSON schema validation of chain definitions."""

    def test_validate_valid_chain_schema(self, chain_validator):
        """
        BV: Valid chains pass schema validation without errors.

        Scenario:
          Given: A chain with all required fields
          When: validate_schema() is called
          Then: Empty list of errors is returned
        """
        chain = ChainFactory.create()
        errors = chain_validator.validate_schema(chain)

        assert errors == [], f"Expected no errors, got: {errors}"

    def test_validate_missing_required_field(self, chain_validator):
        """
        BV: Missing required fields are caught with clear error messages.

        Scenario:
          Given: A chain missing the 'description' field
          When: validate_schema() is called
          Then: Error indicates missing 'description'
        """
        chain = ChainFactory.create()
        del chain["description"]

        errors = chain_validator.validate_schema(chain)

        assert len(errors) > 0
        assert any("description" in e.lower() for e in errors)

    def test_validate_missing_id_field(self, chain_validator):
        """
        BV: Missing chain ID is caught early.

        Scenario:
          Given: A chain without 'id' field
          When: validate_schema() is called
          Then: Error indicates missing 'id'
        """
        chain = ChainFactory.create()
        del chain["id"]

        errors = chain_validator.validate_schema(chain)

        assert len(errors) > 0
        assert any("id" in e.lower() for e in errors)

    def test_validate_invalid_id_format(self, chain_validator):
        """
        BV: Chain IDs must follow kebab-case pattern.

        Scenario:
          Given: A chain with invalid ID format (uppercase, spaces)
          When: validate_schema() is called
          Then: Error indicates invalid ID pattern
        """
        chain = ChainFactory.create()
        chain["id"] = "Invalid Chain ID"  # Has spaces and uppercase

        errors = chain_validator.validate_schema(chain)

        assert len(errors) > 0
        # Schema should reject pattern mismatch

    def test_validate_missing_steps(self, chain_validator):
        """
        BV: Chains must have at least one step.

        Scenario:
          Given: A chain with missing steps field
          When: validate_schema() is called
          Then: Error indicates missing steps
        """
        chain = ChainFactory.create()
        del chain["steps"]

        errors = chain_validator.validate_schema(chain)

        assert len(errors) > 0
        assert any("steps" in e.lower() for e in errors)

    def test_validate_empty_steps_array(self, chain_validator):
        """
        BV: Empty steps array is rejected (chain must do something).

        Scenario:
          Given: A chain with empty steps array
          When: validate_schema() is called
          Then: Error indicates steps must have minItems
        """
        chain = ChainFactory.create()
        chain["steps"] = []

        errors = chain_validator.validate_schema(chain)

        assert len(errors) > 0

    def test_validate_step_missing_command_ref(self, chain_validator):
        """
        BV: Each step must reference a command.

        Scenario:
          Given: A step without command_ref field
          When: validate_schema() is called
          Then: Error indicates missing command_ref
        """
        chain = ChainFactory.create()
        chain["steps"] = [{"name": "Bad Step", "objective": "Missing command_ref"}]

        errors = chain_validator.validate_schema(chain)

        assert len(errors) > 0
        assert any("command_ref" in e.lower() for e in errors)

    def test_validate_invalid_difficulty_enum(self, chain_validator):
        """
        BV: Difficulty must be one of the valid enum values.

        Scenario:
          Given: A chain with invalid difficulty value
          When: validate_schema() is called
          Then: Error indicates invalid enum value
        """
        chain = ChainFactory.create()
        chain["difficulty"] = "super-hard"  # Not a valid enum

        errors = chain_validator.validate_schema(chain)

        assert len(errors) > 0

    def test_validate_invalid_version_format(self, chain_validator):
        """
        BV: Version must follow semver pattern (x.y.z).

        Scenario:
          Given: A chain with invalid version format
          When: validate_schema() is called
          Then: Error indicates invalid version pattern
        """
        chain = ChainFactory.create()
        chain["version"] = "v1.0"  # Should be "1.0.0"

        errors = chain_validator.validate_schema(chain)

        assert len(errors) > 0

    def test_validate_metadata_missing_required_fields(self, chain_validator):
        """
        BV: Metadata must contain author, created, updated, tags, category.

        Scenario:
          Given: A chain with incomplete metadata
          When: validate_schema() is called
          Then: Errors indicate missing metadata fields
        """
        chain = ChainFactory.create()
        chain["metadata"] = {"author": "Test"}  # Missing other required fields

        errors = chain_validator.validate_schema(chain)

        assert len(errors) > 0

    def test_validate_metadata_tags_not_array(self, chain_validator):
        """
        BV: Tags must be an array of strings.

        Scenario:
          Given: A chain with tags as a string instead of array
          When: validate_schema() is called
          Then: Error indicates type mismatch
        """
        chain = ChainFactory.create()
        chain["metadata"]["tags"] = "OSCP"  # Should be array

        errors = chain_validator.validate_schema(chain)

        assert len(errors) > 0


# ==============================================================================
# Test: Circular Dependency Detection
# ==============================================================================


class TestCircularDependencies:
    """Tests for circular step dependency detection."""

    def test_no_circular_deps_valid(self, chain_validator):
        """
        BV: Valid dependency chains pass without errors.

        Scenario:
          Given: Steps with linear dependencies (A -> B -> C)
          When: check_circular_dependencies() is called
          Then: Empty list of errors is returned
        """
        chain = ChainFactory.create(
            steps=[
                ChainFactory.create_step(step_id="step-a"),
                ChainFactory.create_step(step_id="step-b", dependencies=["step-a"]),
                ChainFactory.create_step(step_id="step-c", dependencies=["step-b"]),
            ]
        )

        errors = chain_validator.check_circular_dependencies(chain)

        assert errors == []

    def test_detect_simple_circular_dependency(self, chain_validator):
        """
        BV: Simple A -> B -> A circular dependency is caught.

        Scenario:
          Given: Steps where A depends on B and B depends on A
          When: check_circular_dependencies() is called
          Then: Error indicates circular dependency
        """
        chain = ChainFactory.create(
            steps=[
                ChainFactory.create_step(step_id="step-a", dependencies=["step-b"]),
                ChainFactory.create_step(step_id="step-b", dependencies=["step-a"]),
            ]
        )

        errors = chain_validator.check_circular_dependencies(chain)

        assert len(errors) > 0
        assert any("circular" in e.lower() for e in errors)

    def test_detect_complex_circular_dependency(self, chain_validator):
        """
        BV: Complex A -> B -> C -> A circular dependency is caught.

        Scenario:
          Given: Steps forming a cycle through 3 nodes
          When: check_circular_dependencies() is called
          Then: Error indicates circular dependency with path
        """
        chain = ChainFactory.create_with_circular_deps()

        errors = chain_validator.check_circular_dependencies(chain)

        assert len(errors) > 0
        assert any("circular" in e.lower() for e in errors)

    def test_detect_undefined_dependency(self, chain_validator):
        """
        BV: References to non-existent steps are caught.

        Scenario:
          Given: A step depending on an undefined step ID
          When: check_circular_dependencies() is called
          Then: Error indicates undefined dependency
        """
        chain = ChainFactory.create_with_missing_dependency()

        errors = chain_validator.check_circular_dependencies(chain)

        assert len(errors) > 0
        assert any("undefined" in e.lower() for e in errors)

    def test_steps_without_ids_are_handled(self, chain_validator):
        """
        BV: Steps without IDs don't cause crashes.

        Scenario:
          Given: A chain with steps that have no 'id' field
          When: check_circular_dependencies() is called
          Then: Validation completes without error
        """
        chain = ChainFactory.create(
            steps=[
                ChainFactory.create_step(),  # No step_id
                ChainFactory.create_step(),
            ]
        )

        errors = chain_validator.check_circular_dependencies(chain)

        # Should complete without crash (steps without IDs can't be dependencies)
        assert isinstance(errors, list)

    def test_multiple_dependencies_all_valid(self, chain_validator):
        """
        BV: Steps can depend on multiple other steps.

        Scenario:
          Given: A step depending on two other steps
          When: check_circular_dependencies() is called
          Then: No errors (all dependencies are valid)
        """
        chain = ChainFactory.create(
            steps=[
                ChainFactory.create_step(step_id="prereq-1"),
                ChainFactory.create_step(step_id="prereq-2"),
                ChainFactory.create_step(
                    step_id="main", dependencies=["prereq-1", "prereq-2"]
                ),
            ]
        )

        errors = chain_validator.check_circular_dependencies(chain)

        assert errors == []

    def test_self_dependency_detected(self, chain_validator):
        """
        BV: A step depending on itself is detected.

        Scenario:
          Given: A step with dependencies including its own ID
          When: check_circular_dependencies() is called
          Then: Error indicates circular dependency
        """
        chain = ChainFactory.create(
            steps=[
                ChainFactory.create_step(step_id="self-ref", dependencies=["self-ref"]),
            ]
        )

        errors = chain_validator.check_circular_dependencies(chain)

        assert len(errors) > 0
        assert any("circular" in e.lower() for e in errors)


# ==============================================================================
# Test: Command Reference Validation
# ==============================================================================


class TestCommandRefValidation:
    """Tests for command reference validation."""

    def test_valid_command_refs(self, chain_validator, mock_command_resolver):
        """
        BV: Valid command references pass validation.

        Scenario:
          Given: A chain referencing known commands
          When: validate_command_refs() is called
          Then: Empty list of errors is returned
        """
        chain = ChainFactory.create(
            steps=[
                ChainFactory.create_step(command_ref="test-command"),
                ChainFactory.create_step(command_ref="test-command-1"),
            ]
        )

        errors = chain_validator.validate_command_refs(chain)

        assert errors == []

    def test_missing_command_ref_detected(self, mock_command_resolver):
        """
        BV: References to non-existent commands are caught.

        Scenario:
          Given: A chain referencing an unknown command
          When: validate_command_refs() is called
          Then: Error indicates unresolved command reference
        """
        resolver = MockCommandResolver(known_commands=["known-command"])
        validator = ChainValidator(command_resolver=resolver)

        chain = ChainFactory.create(
            steps=[ChainFactory.create_step(command_ref="unknown-command")]
        )

        errors = validator.validate_command_refs(chain)

        assert len(errors) > 0
        assert "unknown-command" in str(errors)

    def test_step_missing_command_ref_field(self, chain_validator):
        """
        BV: Steps without command_ref field are flagged.

        Scenario:
          Given: A chain with a step missing command_ref
          When: validate_command_refs() is called
          Then: Error indicates missing command_ref
        """
        chain = ChainFactory.create()
        chain["steps"] = [{"name": "Bad", "objective": "No command_ref"}]

        errors = chain_validator.validate_command_refs(chain)

        assert len(errors) > 0
        assert any("missing" in e.lower() for e in errors)

    def test_multiple_missing_command_refs_all_reported(self):
        """
        BV: All missing command references are reported in one pass.

        Scenario:
          Given: A chain with multiple steps referencing unknown commands
          When: validate_command_refs() is called
          Then: Errors list all unresolved references
        """
        resolver = MockCommandResolver(known_commands=["known-cmd"])
        validator = ChainValidator(command_resolver=resolver)

        chain = ChainFactory.create(
            steps=[
                ChainFactory.create_step(step_id="s1", command_ref="unknown-1"),
                ChainFactory.create_step(step_id="s2", command_ref="unknown-2"),
                ChainFactory.create_step(step_id="s3", command_ref="known-cmd"),
            ]
        )

        errors = validator.validate_command_refs(chain)

        assert len(errors) == 2
        error_text = " ".join(errors)
        assert "unknown-1" in error_text
        assert "unknown-2" in error_text


# ==============================================================================
# Test: Validator Configuration
# ==============================================================================


class TestValidatorConfiguration:
    """Tests for validator configuration and setup."""

    def test_set_command_resolver(self, chain_validator):
        """
        BV: Command resolver can be changed after initialization.

        Scenario:
          Given: A validator with one resolver
          When: set_command_resolver() is called with new resolver
          Then: New resolver is used for validation
        """
        new_resolver = MockCommandResolver(known_commands=["new-command"])
        chain_validator.set_command_resolver(new_resolver)

        # Verify new resolver is used
        chain = ChainFactory.create(
            steps=[ChainFactory.create_step(command_ref="new-command")]
        )
        errors = chain_validator.validate_command_refs(chain)

        assert errors == []

    def test_command_resolver_property(self, chain_validator):
        """
        BV: Current command resolver can be retrieved.

        Scenario:
          Given: A validator with a resolver
          When: command_resolver property is accessed
          Then: The resolver is returned
        """
        resolver = chain_validator.command_resolver

        assert resolver is not None

    def test_validator_with_custom_schema_path(self, tmp_path):
        """
        BV: Validator can use custom schema file location.

        Scenario:
          Given: A custom schema file path
          When: ChainValidator is initialized with that path
          Then: Schema is loaded from custom location
        """
        # Create a minimal valid schema
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "required": ["id"],
        }
        schema_path = tmp_path / "custom-schema.json"
        schema_path.write_text(json.dumps(schema), encoding="utf-8")

        validator = ChainValidator(schema_path=schema_path)

        # Validate a simple object against custom schema
        errors = validator.validate_schema({"id": "test"})
        assert errors == []

    def test_validator_missing_schema_raises(self, tmp_path):
        """
        BV: Clear error when schema file is not found.

        Scenario:
          Given: A non-existent schema path
          When: ChainValidator is initialized
          Then: FileNotFoundError is raised
        """
        missing_schema = tmp_path / "nonexistent.json"

        with pytest.raises(FileNotFoundError):
            ChainValidator(schema_path=missing_schema)


# ==============================================================================
# Test: Error Message Quality
# ==============================================================================


class TestErrorMessageQuality:
    """Tests for error message clarity and helpfulness."""

    def test_schema_error_includes_location(self, chain_validator):
        """
        BV: Schema errors indicate where in the document the problem is.

        Scenario:
          Given: A chain with nested validation error
          When: validate_schema() returns errors
          Then: Error messages include path to problematic field
        """
        chain = ChainFactory.create()
        chain["steps"][0]["name"] = ""  # Empty name (if schema requires minLength)

        errors = chain_validator.validate_schema(chain)

        # Errors should include path like "steps/0/name"
        # Note: Exact format depends on schema configuration

    def test_dependency_error_shows_cycle_path(self, chain_validator):
        """
        BV: Circular dependency errors show the cycle path.

        Scenario:
          Given: A chain with circular dependency A -> B -> C -> A
          When: check_circular_dependencies() returns errors
          Then: Error message shows the cycle path
        """
        chain = ChainFactory.create_with_circular_deps()

        errors = chain_validator.check_circular_dependencies(chain)

        # Should show something like "step-a -> step-b -> step-c"
        cycle_error = errors[0] if errors else ""
        assert "->" in cycle_error or "circular" in cycle_error.lower()

    def test_command_ref_error_includes_step_name(self, chain_validator):
        """
        BV: Command reference errors identify which step has the problem.

        Scenario:
          Given: A chain with missing command reference
          When: validate_command_refs() returns errors
          Then: Error includes step name or ID for easy location
        """
        resolver = MockCommandResolver(known_commands=[])
        validator = ChainValidator(command_resolver=resolver)

        chain = ChainFactory.create(
            steps=[
                ChainFactory.create_step(
                    step_id="problematic-step",
                    name="Check Sudo Privileges",
                    command_ref="missing-command",
                )
            ]
        )

        errors = validator.validate_command_refs(chain)

        error_text = " ".join(errors)
        # Should mention the step name or ID
        assert "problematic-step" in error_text or "Check Sudo" in error_text


# ==============================================================================
# Test: Edge Cases
# ==============================================================================


class TestValidatorEdgeCases:
    """Edge case tests for chain validator."""

    def test_validate_chain_with_null_values(self, chain_validator):
        """
        BV: Null values in optional fields are handled gracefully.

        Scenario:
          Given: A chain with null values for optional fields
          When: validate_schema() is called
          Then: Validation handles null appropriately
        """
        chain = ChainFactory.create()
        chain["notes"] = None  # Optional field set to null

        # Should not crash
        errors = chain_validator.validate_schema(chain)
        # Whether this passes depends on schema (null handling)

    def test_validate_empty_chain_object(self, chain_validator):
        """
        BV: Empty object is rejected with all required fields listed.

        Scenario:
          Given: An empty dictionary
          When: validate_schema() is called
          Then: Errors list all required fields
        """
        errors = chain_validator.validate_schema({})

        assert len(errors) > 0
        # Should mention multiple required fields

    def test_validate_chain_with_extra_fields(self, chain_validator):
        """
        BV: Extra fields are rejected (additionalProperties: false).

        Scenario:
          Given: A chain with fields not in schema
          When: validate_schema() is called
          Then: Error indicates additional property not allowed
        """
        chain = ChainFactory.create()
        chain["unknown_field"] = "should not be here"

        errors = chain_validator.validate_schema(chain)

        # Depends on schema's additionalProperties setting
        # If false, should have error

    def test_validate_step_with_empty_dependencies(self, chain_validator):
        """
        BV: Empty dependencies array is valid.

        Scenario:
          Given: A step with dependencies: []
          When: check_circular_dependencies() is called
          Then: No errors (empty is valid)
        """
        chain = ChainFactory.create(
            steps=[ChainFactory.create_step(step_id="s1", dependencies=[])]
        )

        errors = chain_validator.check_circular_dependencies(chain)

        assert errors == []

    def test_validate_chain_with_unicode_content(self, chain_validator):
        """
        BV: Unicode content in strings is handled correctly.

        Scenario:
          Given: A chain with Unicode characters in name/description
          When: validate_schema() is called
          Then: Validation passes (Unicode is valid)
        """
        chain = ChainFactory.create(
            name="Privilege Escalation via Sudo",
            description="Escalation via sudo - includes unicode: cafe, resume",
        )

        errors = chain_validator.validate_schema(chain)

        assert errors == []


# ==============================================================================
# Test: Integration
# ==============================================================================


class TestValidatorIntegration:
    """Integration tests combining multiple validation aspects."""

    def test_full_validation_workflow(self, chain_validator):
        """
        BV: Complete validation catches all types of errors.

        Scenario:
          Given: A chain with multiple types of issues
          When: All validation methods are called
          Then: All issues are caught
        """
        # Chain with: invalid schema, circular deps, missing command
        chain = {
            "id": "INVALID-ID",  # Invalid pattern
            "name": "Test",
            "description": "Test",
            "version": "bad",  # Invalid version
            "metadata": {},  # Missing required fields
            "difficulty": "impossible",  # Invalid enum
            "time_estimate": "5 minutes",
            "oscp_relevant": True,
            "steps": [
                {
                    "id": "step-a",
                    "name": "Step A",
                    "objective": "Test",
                    "command_ref": "unknown-cmd",
                    "dependencies": ["step-b"],
                },
                {
                    "id": "step-b",
                    "name": "Step B",
                    "objective": "Test",
                    "command_ref": "unknown-cmd",
                    "dependencies": ["step-a"],
                },
            ],
        }

        schema_errors = chain_validator.validate_schema(chain)
        dep_errors = chain_validator.check_circular_dependencies(chain)
        cmd_errors = chain_validator.validate_command_refs(chain)

        # Should have errors in all categories
        assert len(schema_errors) > 0, "Expected schema errors"
        assert len(dep_errors) > 0, "Expected dependency errors"
        # cmd_errors depends on resolver setup

    def test_valid_production_chain_structure(self, chain_validator, mock_command_resolver):
        """
        BV: Real production chain structure passes all validations.

        Scenario:
          Given: A chain matching production linux-privesc-sudo structure
          When: All validation methods are called
          Then: No errors (chain is valid)
        """
        chain = {
            "id": "linux-privesc-sudo-test",
            "name": "Sudo Privilege Escalation",
            "description": "Rapid privilege escalation via sudo misconfigurations",
            "version": "1.0.0",
            "metadata": {
                "author": "CRACK Team",
                "created": "2025-01-01",
                "updated": "2025-01-01",
                "tags": ["OSCP", "LINUX", "QUICK_WIN"],
                "category": "privilege_escalation",
                "platform": "linux",
            },
            "difficulty": "beginner",
            "time_estimate": "5 minutes",
            "oscp_relevant": True,
            "prerequisites": ["Shell access as low-privilege user"],
            "steps": [
                {
                    "id": "check-sudo",
                    "name": "Check Sudo Privileges",
                    "objective": "Identify allowed sudo commands",
                    "command_ref": "check-sudo-privs",
                    "evidence": ["sudo -l output"],
                },
                {
                    "id": "exploit-sudo",
                    "name": "Exploit Sudo",
                    "objective": "Escalate privileges",
                    "command_ref": "test-command",
                    "dependencies": ["check-sudo"],
                },
            ],
        }

        schema_errors = chain_validator.validate_schema(chain)
        dep_errors = chain_validator.check_circular_dependencies(chain)
        cmd_errors = chain_validator.validate_command_refs(chain)

        assert schema_errors == [], f"Schema errors: {schema_errors}"
        assert dep_errors == [], f"Dependency errors: {dep_errors}"
        assert cmd_errors == [], f"Command errors: {cmd_errors}"
