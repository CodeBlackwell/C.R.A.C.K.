"""
Tests for VariableContext - Hierarchical variable resolution.

Business Value Focus:
- Variables from different scopes are resolved with correct priority
- Parser output overrides config values when needed
- Session variables persist across steps
- Users understand where variable values come from
"""

import pytest
from unittest.mock import MagicMock

from reference.chains.variables.context import VariableContext, VariableScope
from reference.chains.variables.extractors import VariableExtractor
from tests.reference.chains.conftest import SessionFactory


# ==============================================================================
# Test: Variable Resolution Priority
# ==============================================================================


class TestVariableResolutionPriority:
    """Tests for hierarchical variable resolution."""

    def test_step_variable_highest_priority(self, variable_context):
        """
        BV: Step-scoped variables override all other sources.

        Scenario:
          Given: Same variable in step, session, and config
          When: resolve() is called with step_id
          Then: Step value is returned
        """
        # Set up all three levels
        variable_context.set_step_variable("step-1", "<TARGET>", "step-target")
        variable_context.set_session_variable("<TARGET>", "session-target")
        # Config already has <TARGET> from fixture

        result = variable_context.resolve("<TARGET>", step_id="step-1")

        assert result == "step-target"

    def test_session_variable_overrides_config(self, variable_context):
        """
        BV: Session variables override config values.

        Scenario:
          Given: Same variable in session and config
          When: resolve() is called without step_id
          Then: Session value is returned
        """
        variable_context.set_session_variable("<LHOST>", "10.10.10.10")
        # Config has LHOST = 10.10.14.5

        result = variable_context.resolve("<LHOST>")

        assert result == "10.10.10.10"

    def test_config_variable_when_no_override(self, variable_context):
        """
        BV: Config values are used when no higher-priority override.

        Scenario:
          Given: Variable only in config
          When: resolve() is called
          Then: Config value is returned
        """
        result = variable_context.resolve("<LPORT>")

        assert result == "4444"

    def test_default_value_when_no_source(self, variable_context):
        """
        BV: Default value is used when variable not found anywhere.

        Scenario:
          Given: Variable not in any scope
          When: resolve() is called with default
          Then: Default value is returned
        """
        result = variable_context.resolve("<UNKNOWN>", default="fallback")

        assert result == "fallback"

    def test_none_when_no_source_and_no_default(self, variable_context):
        """
        BV: None returned when variable not found and no default.

        Scenario:
          Given: Variable not in any scope
          When: resolve() is called without default
          Then: None is returned
        """
        result = variable_context.resolve("<MISSING>")

        assert result is None


# ==============================================================================
# Test: Step-Scoped Variables
# ==============================================================================


class TestStepScopedVariables:
    """Tests for step-scoped variable management."""

    def test_set_step_variable(self, variable_context):
        """
        BV: Step variables can be set and retrieved.

        Scenario:
          Given: A variable context
          When: set_step_variable() is called
          Then: Variable is available for that step
        """
        variable_context.set_step_variable("step-1", "<BINARY>", "/usr/bin/find")

        result = variable_context.resolve("<BINARY>", step_id="step-1")

        assert result == "/usr/bin/find"

    def test_step_variable_isolated_to_step(self, variable_context):
        """
        BV: Step variables don't leak to other steps.

        Scenario:
          Given: Variable set for step-1
          When: resolve() called for step-2
          Then: Variable is not found
        """
        variable_context.set_step_variable("step-1", "<BINARY>", "/usr/bin/find")

        result = variable_context.resolve("<BINARY>", step_id="step-2")

        assert result is None

    def test_get_step_variables(self, variable_context):
        """
        BV: All variables for a step can be retrieved together.

        Scenario:
          Given: Multiple variables set for a step
          When: get_step_variables() is called
          Then: All variables are returned as dict
        """
        variable_context.set_step_variable("step-1", "<A>", "value-a")
        variable_context.set_step_variable("step-1", "<B>", "value-b")

        vars = variable_context.get_step_variables("step-1")

        assert vars == {"<A>": "value-a", "<B>": "value-b"}

    def test_get_step_variables_returns_copy(self, variable_context):
        """
        BV: Returned dict is a copy (modifications don't affect context).

        Scenario:
          Given: Step variables are retrieved
          When: Returned dict is modified
          Then: Original context is unchanged
        """
        variable_context.set_step_variable("step-1", "<X>", "original")
        vars = variable_context.get_step_variables("step-1")
        vars["<X>"] = "modified"

        result = variable_context.resolve("<X>", step_id="step-1")

        assert result == "original"

    def test_clear_step_variables(self, variable_context):
        """
        BV: Step variables can be cleared for re-execution.

        Scenario:
          Given: Variables set for a step
          When: clear_step_variables() is called
          Then: Variables are removed
        """
        variable_context.set_step_variable("step-1", "<VAR>", "value")
        variable_context.clear_step_variables("step-1")

        result = variable_context.resolve("<VAR>", step_id="step-1")

        assert result is None


# ==============================================================================
# Test: Session-Scoped Variables
# ==============================================================================


class TestSessionScopedVariables:
    """Tests for session-scoped variable management."""

    def test_set_session_variable(self, variable_context):
        """
        BV: Session variables persist across steps.

        Scenario:
          Given: Variable set via set_session_variable()
          When: resolve() called from any step
          Then: Variable is available
        """
        variable_context.set_session_variable("<USER>", "admin")

        result1 = variable_context.resolve("<USER>", step_id="step-1")
        result2 = variable_context.resolve("<USER>", step_id="step-2")

        assert result1 == "admin"
        assert result2 == "admin"

    def test_session_variable_stored_in_session_object(self, variable_context):
        """
        BV: Session variables are stored in ChainSession for persistence.

        Scenario:
          Given: Variable set via context
          When: Checking session object
          Then: Variable is in session.variables
        """
        variable_context.set_session_variable("<CRED>", "password123")

        assert variable_context.session.variables["<CRED>"] == "password123"


# ==============================================================================
# Test: Config Variable Access
# ==============================================================================


class TestConfigVariableAccess:
    """Tests for config-scoped variable access."""

    def test_config_variable_with_angle_brackets(self, variable_context):
        """
        BV: Config lookup handles <PLACEHOLDER> format.

        Scenario:
          Given: Config has '<TARGET>' key
          When: resolve('<TARGET>') is called
          Then: Config value is returned
        """
        result = variable_context.resolve("<TARGET>")

        assert result == "192.168.1.100"

    def test_config_variable_normalized(self, variable_context):
        """
        BV: Variable names are normalized for config lookup.

        Scenario:
          Given: Variable name with angle brackets
          When: resolve() is called
          Then: Brackets are stripped for config lookup
        """
        # Config stores as <LHOST> but lookup should work
        result = variable_context.resolve("<LHOST>")

        assert result == "10.10.14.5"


# ==============================================================================
# Test: Get All Variables
# ==============================================================================


class TestGetAllVariables:
    """Tests for retrieving merged variable context."""

    def test_get_all_variables_merges_scopes(self, variable_context):
        """
        BV: All variables from all scopes are merged correctly.

        Scenario:
          Given: Variables in config, session, and step
          When: get_all_variables() is called
          Then: All are returned with correct precedence
        """
        variable_context.set_session_variable("<SESSION_VAR>", "from-session")
        variable_context.set_step_variable("step-1", "<STEP_VAR>", "from-step")

        all_vars = variable_context.get_all_variables(step_id="step-1")

        assert "<SESSION_VAR>" in all_vars
        assert "<STEP_VAR>" in all_vars
        # Config vars should also be present (from mock)

    def test_get_all_variables_without_step(self, variable_context):
        """
        BV: get_all_variables() works without step_id.

        Scenario:
          Given: Config and session variables
          When: get_all_variables() called without step_id
          Then: Returns config + session merged
        """
        variable_context.set_session_variable("<VAR>", "session-value")

        all_vars = variable_context.get_all_variables()

        assert "<VAR>" in all_vars


# ==============================================================================
# Test: Required Variables Detection
# ==============================================================================


class TestRequiredVariablesDetection:
    """Tests for finding unfilled placeholders."""

    def test_get_required_variables(self, variable_context):
        """
        BV: Unfilled placeholders are identified.

        Scenario:
          Given: A command with placeholders and some filled
          When: get_required_variables() is called
          Then: Unfilled placeholders are returned
        """
        command = "nmap -p <PORT> <TARGET> -oN <OUTPUT>"
        filled = {"<TARGET>": "192.168.1.1"}

        required = variable_context.get_required_variables(command, filled)

        assert "<PORT>" in required
        assert "<OUTPUT>" in required
        assert "<TARGET>" not in required

    def test_get_required_variables_all_filled(self, variable_context):
        """
        BV: Empty list when all placeholders are filled.

        Scenario:
          Given: A command where all placeholders have values
          When: get_required_variables() is called
          Then: Empty list is returned
        """
        command = "nmap <TARGET>"
        filled = {"<TARGET>": "192.168.1.1"}

        required = variable_context.get_required_variables(command, filled)

        assert required == []

    def test_get_required_variables_none_filled(self, variable_context):
        """
        BV: All placeholders returned when none filled.

        Scenario:
          Given: A command with multiple unfilled placeholders
          When: get_required_variables() called with empty dict
          Then: All placeholders are returned
        """
        command = "ssh <USER>@<TARGET> -p <PORT>"

        required = variable_context.get_required_variables(command, {})

        assert len(required) == 3
        assert "<USER>" in required
        assert "<TARGET>" in required
        assert "<PORT>" in required


# ==============================================================================
# Test: Variable Source Identification
# ==============================================================================


class TestVariableSourceIdentification:
    """Tests for identifying where variables come from."""

    def test_get_variable_source_step(self, variable_context):
        """
        BV: Step-scoped variables are identified as STEP source.

        Scenario:
          Given: Variable set at step level
          When: get_variable_source() is called
          Then: Returns VariableScope.STEP
        """
        variable_context.set_step_variable("step-1", "<VAR>", "value")

        source = variable_context.get_variable_source("<VAR>", step_id="step-1")

        assert source == VariableScope.STEP

    def test_get_variable_source_session(self, variable_context):
        """
        BV: Session-scoped variables are identified as SESSION source.

        Scenario:
          Given: Variable set at session level
          When: get_variable_source() is called
          Then: Returns VariableScope.SESSION
        """
        variable_context.set_session_variable("<VAR>", "value")

        source = variable_context.get_variable_source("<VAR>")

        assert source == VariableScope.SESSION

    def test_get_variable_source_config(self, variable_context):
        """
        BV: Config-scoped variables are identified as CONFIG source.

        Scenario:
          Given: Variable in config (no step or session override)
          When: get_variable_source() is called
          Then: Returns VariableScope.CONFIG
        """
        source = variable_context.get_variable_source("<TARGET>")

        assert source == VariableScope.CONFIG

    def test_get_variable_source_default(self, variable_context):
        """
        BV: Unknown variables return DEFAULT source.

        Scenario:
          Given: Variable not found anywhere
          When: get_variable_source() is called
          Then: Returns VariableScope.DEFAULT
        """
        source = variable_context.get_variable_source("<UNKNOWN>")

        assert source == VariableScope.DEFAULT


# ==============================================================================
# Test: Variable Extractor
# ==============================================================================


class TestVariableExtractor:
    """Tests for VariableExtractor utility class."""

    def test_extract_single_value_auto_resolves(self):
        """
        BV: Single-value findings are auto-resolved to variables.

        Scenario:
          Given: Findings with single exploitable binary
          When: extract() is called
          Then: Variable is directly set (no selection required)
        """
        findings = {"exploitable_binaries": ["/usr/bin/find"]}

        candidates = VariableExtractor.extract(findings)

        assert candidates["<TARGET_BIN>"] == "/usr/bin/find"

    def test_extract_multiple_values_requires_selection(self):
        """
        BV: Multiple values require user selection.

        Scenario:
          Given: Findings with multiple exploitable binaries
          When: extract() is called
          Then: Selection info is returned
        """
        findings = {
            "exploitable_binaries": ["/usr/bin/find", "/usr/bin/vim", "/usr/bin/less"]
        }

        candidates = VariableExtractor.extract(findings)

        result = candidates["<TARGET_BIN>"]
        assert isinstance(result, dict)
        assert "select_from" in result
        assert len(result["select_from"]) == 3

    def test_extract_empty_list_skipped(self):
        """
        BV: Empty findings are skipped.

        Scenario:
          Given: Findings with empty exploitable_binaries
          When: extract() is called
          Then: No variable is added
        """
        findings = {"exploitable_binaries": []}

        candidates = VariableExtractor.extract(findings)

        assert "<TARGET_BIN>" not in candidates

    def test_extract_string_value(self):
        """
        BV: Direct string values are extracted.

        Scenario:
          Given: Findings with docker socket path as string
          When: extract() is called
          Then: Variable is set to that string
        """
        findings = {"docker_socket_path": "/var/run/docker.sock"}

        candidates = VariableExtractor.extract(findings)

        assert candidates["<DOCKER_SOCKET>"] == "/var/run/docker.sock"

    def test_extract_dict_value_extracts_primary_field(self):
        """
        BV: Complex dict values extract the primary field.

        Scenario:
          Given: Findings with dict containing path/name/value
          When: extract() is called
          Then: Primary field is extracted
        """
        findings = {
            "exploitable_binaries": {"path": "/usr/bin/find", "severity": "high"}
        }

        candidates = VariableExtractor.extract(findings)

        assert candidates["<TARGET_BIN>"] == "/usr/bin/find"

    def test_extract_list_of_dicts(self):
        """
        BV: Lists of dicts extract the primary field from each.

        Scenario:
          Given: Findings with list of binary info dicts
          When: extract() is called
          Then: Primary fields are extracted for selection
        """
        findings = {
            "exploitable_binaries": [
                {"path": "/usr/bin/find", "name": "find"},
                {"path": "/usr/bin/vim", "name": "vim"},
            ]
        }

        candidates = VariableExtractor.extract(findings)

        result = candidates["<TARGET_BIN>"]
        assert isinstance(result, dict)
        assert "select_from" in result
        assert "/usr/bin/find" in result["select_from"]
        assert "/usr/bin/vim" in result["select_from"]

    def test_extraction_rules_coverage(self):
        """
        BV: Common finding types are mapped to variables.

        Scenario:
          Given: Various finding types
          When: Checking EXTRACTION_RULES
          Then: Common types are mapped
        """
        rules = VariableExtractor.EXTRACTION_RULES

        # Check key mappings exist
        assert "exploitable_binaries" in rules
        assert "directories" in rules
        assert "users" in rules
        assert "running_containers" in rules
        assert "gtfobins_binaries" in rules

    def test_add_custom_rule(self):
        """
        BV: Custom extraction rules can be added.

        Scenario:
          Given: A new finding type
          When: add_rule() is called
          Then: New findings are extracted
        """
        # Add custom rule
        VariableExtractor.add_rule("custom_findings", "<CUSTOM_VAR>")

        findings = {"custom_findings": ["value1", "value2"]}
        candidates = VariableExtractor.extract(findings)

        assert "<CUSTOM_VAR>" in candidates

        # Cleanup
        VariableExtractor.remove_rule("custom_findings")

    def test_remove_rule(self):
        """
        BV: Extraction rules can be removed.

        Scenario:
          Given: A custom rule was added
          When: remove_rule() is called
          Then: Rule is removed
        """
        VariableExtractor.add_rule("temp_finding", "<TEMP>")
        VariableExtractor.remove_rule("temp_finding")

        findings = {"temp_finding": ["value"]}
        candidates = VariableExtractor.extract(findings)

        assert "<TEMP>" not in candidates


# ==============================================================================
# Test: Edge Cases
# ==============================================================================


class TestVariableContextEdgeCases:
    """Edge case tests for variable context."""

    def test_resolve_without_config(self, sample_session):
        """
        BV: Context works without config manager.

        Scenario:
          Given: VariableContext created without config
          When: resolve() is called
          Then: Falls through to session/default
        """
        context = VariableContext(sample_session, config_manager=None)
        context.set_session_variable("<VAR>", "session-value")

        result = context.resolve("<VAR>")

        assert result == "session-value"

    def test_resolve_config_lookup_strips_brackets(self, variable_context):
        """
        BV: Config lookup handles variables with/without brackets.

        Scenario:
          Given: Config stores '<TARGET>'
          When: resolve('<TARGET>') is called
          Then: Config is queried correctly
        """
        # Config mock uses get_placeholder with brackets
        result = variable_context.resolve("<TARGET>")
        assert result == "192.168.1.100"

    def test_session_without_variables_attr(self, mock_config_manager):
        """
        BV: set_session_variable creates variables attr if missing.

        Scenario:
          Given: Session object without 'variables' attribute
          When: set_session_variable() is called
          Then: Attribute is created
        """
        session = MagicMock(spec=[])  # No 'variables' attribute
        context = VariableContext(session, mock_config_manager)

        context.set_session_variable("<NEW>", "value")

        assert hasattr(session, "variables")
        assert session.variables["<NEW>"] == "value"


# ==============================================================================
# Test: Integration
# ==============================================================================


class TestVariableContextIntegration:
    """Integration tests for variable context in chain execution."""

    def test_full_resolution_workflow(self, variable_context):
        """
        BV: Complete variable resolution workflow.

        Scenario:
          Given: Variables at all scope levels
          When: Command template is resolved
          Then: All placeholders are filled correctly
        """
        # Setup: Config has TARGET, LHOST, LPORT
        # Add session variable
        variable_context.set_session_variable("<USER>", "admin")
        # Add step variable (highest priority)
        variable_context.set_step_variable("step-1", "<LPORT>", "8888")

        # Resolve all needed variables
        target = variable_context.resolve("<TARGET>", step_id="step-1")
        lhost = variable_context.resolve("<LHOST>", step_id="step-1")
        lport = variable_context.resolve("<LPORT>", step_id="step-1")
        user = variable_context.resolve("<USER>", step_id="step-1")

        assert target == "192.168.1.100"  # From config
        assert lhost == "10.10.14.5"  # From config
        assert lport == "8888"  # From step (overrides config)
        assert user == "admin"  # From session

    def test_parser_output_to_variables(self, variable_context):
        """
        BV: Parser findings become step variables for next steps.

        Scenario:
          Given: Parser output with exploitable binaries
          When: Findings are extracted and stored
          Then: Variables are available for resolution
        """
        # Simulate parser output
        findings = {
            "exploitable_binaries": ["/usr/bin/find"],
            "gtfobins_binaries": [
                {"binary": "find", "command": "/usr/bin/find", "run_as": "root"}
            ],
        }

        # Extract variables
        candidates = VariableExtractor.extract(findings)

        # Store in step context
        for var_name, value in candidates.items():
            if isinstance(value, str):
                variable_context.set_step_variable("sudo-check", var_name, value)

        # Verify resolution
        target_bin = variable_context.resolve("<TARGET_BIN>", step_id="sudo-check")
        assert target_bin == "/usr/bin/find"
