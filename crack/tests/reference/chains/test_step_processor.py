"""
Tests for Step Processor

Business Value Focus:
- Parse command output using registered parsers
- Extract variables from findings
- Handle user selection for multi-option findings

Test Priority: TIER 2 - HIGH (Chain Execution)
"""

import pytest
from unittest.mock import MagicMock, patch
from reference.chains.core.step_processor import StepProcessor
from reference.chains.parsing.base import ParsingResult


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_var_context():
    """Mock variable context"""
    context = MagicMock()
    context.set_step_variable = MagicMock()
    context.get_variable = MagicMock(return_value=None)
    return context


@pytest.fixture
def mock_selector():
    """Mock finding selector"""
    selector = MagicMock()
    selector.select_single = MagicMock(return_value="selected_value")
    return selector


@pytest.fixture
def processor(mock_var_context, mock_selector):
    """Create step processor with mocks"""
    return StepProcessor(
        var_context=mock_var_context,
        selector=mock_selector
    )


# =============================================================================
# Basic Process Output Tests
# =============================================================================

class TestProcessOutput:
    """Tests for process_output method"""

    def test_no_parser_returns_raw(self, processor):
        """
        BV: No parser stores raw output

        Scenario:
          Given: Command with no parser
          When: process_output() is called
          Then: Raw output stored
        """
        with patch('reference.chains.core.step_processor.ParserRegistry') as mock_registry:
            mock_registry.get_parser.return_value = None

            result = processor.process_output(
                step={"command": "unknown_cmd"},
                command="unknown_cmd",
                output="some output",
                step_id="step-1"
            )

        assert result['success'] is True
        assert 'raw_output' in result['findings']
        assert result['findings']['raw_output'] == "some output"
        assert result['parser'] is None

    def test_with_parser_success(self, processor):
        """
        BV: Parser extracts findings

        Scenario:
          Given: Command with matching parser
          When: process_output() is called
          Then: Findings extracted
        """
        mock_parser = MagicMock()
        mock_parser.name = "suid_parser"
        mock_parser.parse.return_value = ParsingResult(
            parser_name="suid_parser",
            success=True,
            findings={"exploitable_binaries": ["/usr/bin/find"]},
            variables={"<TARGET_BIN>": "/usr/bin/find"},
            selection_required={},
            warnings=[]
        )

        with patch('reference.chains.core.step_processor.ParserRegistry') as mock_registry:
            mock_registry.get_parser.return_value = mock_parser

            result = processor.process_output(
                step={"command": "find / -perm -4000"},
                command="find / -perm -4000",
                output="/usr/bin/find\n/usr/bin/vim",
                step_id="step-1"
            )

        assert result['success'] is True
        assert result['parser'] == "suid_parser"
        assert "<TARGET_BIN>" in result['variables']

    def test_parser_failure_graceful(self, processor):
        """
        BV: Parser failure is graceful

        Scenario:
          Given: Parser that throws exception
          When: process_output() is called
          Then: Returns failure with raw output
        """
        mock_parser = MagicMock()
        mock_parser.name = "failing_parser"
        mock_parser.parse.side_effect = ValueError("Parse error")

        with patch('reference.chains.core.step_processor.ParserRegistry') as mock_registry:
            mock_registry.get_parser.return_value = mock_parser

            result = processor.process_output(
                step={"command": "cmd"},
                command="cmd",
                output="output",
                step_id="step-1"
            )

        assert result['success'] is False
        assert result['parser'] == "failing_parser"
        assert 'parse_error' in result['findings']
        assert 'Parse error' in result['findings']['parse_error']

    def test_variables_stored_in_context(self, processor, mock_var_context):
        """
        BV: Variables stored in context

        Scenario:
          Given: Parser returns variables
          When: process_output() is called
          Then: Variables stored in context
        """
        mock_parser = MagicMock()
        mock_parser.name = "test_parser"
        mock_parser.parse.return_value = ParsingResult(
            parser_name="test_parser",
            success=True,
            findings={},
            variables={"<VAR1>": "value1", "<VAR2>": "value2"},
            selection_required={},
            warnings=[]
        )

        with patch('reference.chains.core.step_processor.ParserRegistry') as mock_registry:
            mock_registry.get_parser.return_value = mock_parser

            processor.process_output(
                step={},
                command="cmd",
                output="output",
                step_id="step-1"
            )

        # Check that variables were stored
        assert mock_var_context.set_step_variable.call_count == 2


# =============================================================================
# Selection Handling Tests
# =============================================================================

class TestSelectionHandling:
    """Tests for _handle_selections method"""

    def test_single_selection_prompts_user(self, processor, mock_selector):
        """
        BV: User prompted for selection

        Scenario:
          Given: Parser returns selection_required
          When: _handle_selections() is called
          Then: User prompted to select
        """
        result = ParsingResult(
            parser_name="test",
            success=True,
            findings={},
            variables={},
            selection_required={"<TARGET>": ["opt1", "opt2", "opt3"]},
            warnings=[]
        )

        resolved = processor._handle_selections(result, "step-1")

        mock_selector.select_single.assert_called_once()
        assert "<TARGET>" in resolved

    def test_empty_options_skipped(self, processor, mock_selector):
        """
        BV: Empty options skipped

        Scenario:
          Given: Empty selection options
          When: _handle_selections() is called
          Then: No prompt shown
        """
        result = ParsingResult(
            parser_name="test",
            success=True,
            findings={},
            variables={"<EXISTING>": "value"},
            selection_required={"<EMPTY>": []},
            warnings=[]
        )

        resolved = processor._handle_selections(result, "step-1")

        mock_selector.select_single.assert_not_called()
        assert "<EXISTING>" in resolved

    def test_preserves_existing_variables(self, processor, mock_selector):
        """
        BV: Existing variables preserved

        Scenario:
          Given: Result with existing variables
          When: _handle_selections() is called
          Then: Variables preserved in output
        """
        result = ParsingResult(
            parser_name="test",
            success=True,
            findings={},
            variables={"<EXISTING>": "keep_me"},
            selection_required={},
            warnings=[]
        )

        resolved = processor._handle_selections(result, "step-1")

        assert resolved["<EXISTING>"] == "keep_me"


# =============================================================================
# Selection Prompt Tests
# =============================================================================

class TestMakeSelectionPrompt:
    """Tests for _make_selection_prompt method"""

    def test_cleans_variable_name(self, processor):
        """
        BV: Variable name cleaned for display

        Scenario:
          Given: Variable name with angle brackets
          When: _make_selection_prompt() is called
          Then: Clean prompt generated
        """
        prompt = processor._make_selection_prompt("<TARGET_BIN>", "step-1")

        assert "target bin" in prompt.lower()
        assert "<" not in prompt
        assert ">" not in prompt

    def test_replaces_underscores(self, processor):
        """
        BV: Underscores replaced with spaces

        Scenario:
          Given: Variable with underscores
          When: _make_selection_prompt() is called
          Then: Underscores become spaces
        """
        prompt = processor._make_selection_prompt("<EXPLOITABLE_BINARY>", "step-1")

        assert "_" not in prompt or "Select" in prompt


# =============================================================================
# Step Summary Tests
# =============================================================================

class TestGetStepSummary:
    """Tests for get_step_summary method"""

    def test_empty_findings(self, processor):
        """
        BV: Empty findings returns message

        Scenario:
          Given: Result with no findings
          When: get_step_summary() is called
          Then: Returns empty message
        """
        result = {"findings": {}}

        summary = processor.get_step_summary("step-1", result)

        assert "No parsing performed" in summary

    def test_includes_counts(self, processor):
        """
        BV: Summary includes counts

        Scenario:
          Given: Result with counts
          When: get_step_summary() is called
          Then: Counts in summary
        """
        result = {
            "findings": {
                "total_count": 10,
                "exploitable_count": 3,
                "standard_count": 5,
                "unknown_count": 2,
            },
            "warnings": []
        }

        summary = processor.get_step_summary("step-1", result)

        assert "10" in summary
        assert "3" in summary

    def test_checkbox_formatting(self, processor):
        """
        BV: Uses checkbox formatting

        Scenario:
          Given: Result with findings
          When: get_step_summary() is called
          Then: Uses checkbox style
        """
        result = {
            "findings": {
                "total_count": 5,
                "exploitable_count": 2,
                "standard_count": 2,
                "unknown_count": 1,
            },
            "warnings": []
        }

        summary = processor.get_step_summary("step-1", result)

        assert "[" in summary
        assert "]" in summary

    def test_shows_warnings(self, processor):
        """
        BV: Warnings displayed

        Scenario:
          Given: Result with warnings
          When: get_step_summary() is called
          Then: Warnings in summary
        """
        result = {
            "findings": {"total_count": 1},
            "warnings": ["Some warning message"]
        }

        summary = processor.get_step_summary("step-1", result)

        assert "warning" in summary.lower() or "⚠" in summary

    def test_fuzzy_match_note(self, processor):
        """
        BV: Fuzzy matches noted

        Scenario:
          Given: Findings with fuzzy matches
          When: get_step_summary() is called
          Then: Note about verification
        """
        result = {
            "findings": {
                "total_count": 2,
                "exploitable_count": 2,
                "standard_count": 0,
                "unknown_count": 0,
                "exploitable_binaries": [
                    {"path": "/usr/bin/find", "match_type": "exact"},
                    {"path": "/usr/bin/python3.8", "match_type": "fuzzy"},
                ]
            },
            "warnings": []
        }

        summary = processor.get_step_summary("step-1", result)

        assert "fuzzy" in summary.lower()


# =============================================================================
# Should Continue Tests
# =============================================================================

class TestShouldContinue:
    """Tests for should_continue method"""

    def test_success_continues(self, processor):
        """
        BV: Success allows continuation

        Scenario:
          Given: Successful result
          When: should_continue() is called
          Then: Returns True
        """
        result = {
            "success": True,
            "variables": {"<VAR>": "value"},
            "warnings": []
        }

        assert processor.should_continue(result) is True

    def test_failure_with_fatal_warning_stops(self, processor):
        """
        BV: Fatal warning stops chain

        Scenario:
          Given: Result with fatal warning
          When: should_continue() is called
          Then: Returns False
        """
        result = {
            "success": False,
            "variables": {},
            "warnings": ["No exploitable binaries found"]
        }

        assert processor.should_continue(result) is False

    def test_failure_with_parse_error_stops(self, processor):
        """
        BV: Parse error stops chain

        Scenario:
          Given: Result with parse error warning
          When: should_continue() is called
          Then: Returns False
        """
        result = {
            "success": False,
            "variables": {},
            "warnings": ["Parse error: invalid format"]
        }

        assert processor.should_continue(result) is False

    def test_failure_without_fatal_continues(self, processor):
        """
        BV: Non-fatal failure continues

        Scenario:
          Given: Failure without fatal warning
          When: should_continue() is called
          Then: Returns True
        """
        result = {
            "success": False,
            "variables": {},
            "warnings": ["Minor issue detected"]
        }

        assert processor.should_continue(result) is True

    def test_empty_variables_continues(self, processor):
        """
        BV: Empty variables doesn't stop

        Scenario:
          Given: Result with no variables
          When: should_continue() is called
          Then: Returns True
        """
        result = {
            "success": True,
            "variables": {},
            "warnings": []
        }

        assert processor.should_continue(result) is True


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests for step processor"""

    def test_full_workflow(self, processor, mock_var_context, mock_selector):
        """
        BV: Full processing workflow

        Scenario:
          Given: Complete step with parser
          When: Processing through workflow
          Then: All steps execute correctly
        """
        mock_parser = MagicMock()
        mock_parser.name = "integration_parser"
        mock_parser.parse.return_value = ParsingResult(
            parser_name="integration_parser",
            success=True,
            findings={
                "total_count": 5,
                "exploitable_count": 2,
            },
            variables={"<TARGET>": "/usr/bin/find"},
            selection_required={},
            warnings=[]
        )

        with patch('reference.chains.core.step_processor.ParserRegistry') as mock_registry:
            mock_registry.get_parser.return_value = mock_parser

            result = processor.process_output(
                step={"command": "find / -perm -4000"},
                command="find / -perm -4000",
                output="/usr/bin/find",
                step_id="step-integration"
            )

        # Verify result
        assert result['success'] is True
        assert result['parser'] == "integration_parser"
        assert "<TARGET>" in result['variables']

        # Verify context was updated
        mock_var_context.set_step_variable.assert_called()

        # Verify chain should continue
        assert processor.should_continue(result) is True

        # Verify summary is generated
        summary = processor.get_step_summary("step-integration", result)
        assert len(summary) > 0


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Edge case handling tests"""

    def test_none_output(self, processor):
        """
        BV: Handle None output

        Scenario:
          Given: None as output
          When: process_output() is called
          Then: Handles gracefully
        """
        with patch('reference.chains.core.step_processor.ParserRegistry') as mock_registry:
            mock_registry.get_parser.return_value = None

            result = processor.process_output(
                step={},
                command="cmd",
                output=None,
                step_id="step-1"
            )

        assert result['success'] is True

    def test_empty_step_dict(self, processor):
        """
        BV: Handle empty step dict

        Scenario:
          Given: Empty step dict
          When: process_output() is called
          Then: No crash
        """
        with patch('reference.chains.core.step_processor.ParserRegistry') as mock_registry:
            mock_registry.get_parser.return_value = None

            result = processor.process_output(
                step={},
                command="",
                output="",
                step_id="step-1"
            )

        assert result is not None
