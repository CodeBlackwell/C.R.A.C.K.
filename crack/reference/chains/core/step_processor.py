"""
Step processor - Orchestrates execution lifecycle with parsing and selection.

Coordinates between parsers, variable resolution, and user interaction.
"""

from typing import Dict, Any, Optional
from ..parsing.registry import ParserRegistry
from ..parsing.base import ParsingResult
from ..variables.context import VariableContext
from ..variables.extractors import VariableExtractor
from ..filtering.selector import FindingSelector


class StepProcessor:
    """
    Handle single step execution lifecycle.

    Responsibilities:
    1. Parse command output using registered parsers
    2. Extract variables from findings
    3. Handle user selection for multi-option findings
    4. Update variable context for subsequent steps
    5. Persist findings to session
    """

    def __init__(self, var_context: VariableContext, selector: FindingSelector):
        """
        Initialize step processor.

        Args:
            var_context: Variable resolution context
            selector: Interactive selection UI
        """
        self.var_context = var_context
        self.selector = selector

    def process_output(
        self, step: Dict[str, Any], command: str, output: str, step_id: str
    ) -> Dict[str, Any]:
        """
        Parse output and extract findings/variables.

        Args:
            step: Chain step dictionary
            command: Executed command string
            output: Command output (stdout)
            step_id: Step identifier

        Returns:
            Dictionary with:
            - 'findings': Parsed findings dict
            - 'variables': Resolved variables dict
            - 'parser': Parser name (or None)
            - 'success': Whether parsing succeeded
            - 'warnings': List of warning messages
        """
        # 1. Find appropriate parser
        parser = ParserRegistry.get_parser(step, command)

        if not parser:
            # No parser available - store raw output
            return {
                'findings': {'raw_output': output},
                'variables': {},
                'parser': None,
                'success': True,
                'warnings': ['No parser available for this command type'],
            }

        # 2. Parse output
        try:
            result = parser.parse(output, step, command)
        except Exception as e:
            # Parser failed - graceful fallback
            return {
                'findings': {'raw_output': output, 'parse_error': str(e)},
                'variables': {},
                'parser': parser.name,
                'success': False,
                'warnings': [f'Parser failed: {str(e)}'],
            }

        # 3. Handle user selections
        resolved_vars = self._handle_selections(result, step_id)

        # 4. Store variables in context
        for var_name, value in resolved_vars.items():
            self.var_context.set_step_variable(step_id, var_name, value)

        # 5. Return complete result
        return {
            'findings': result.findings,
            'variables': resolved_vars,
            'parser': result.parser_name,
            'success': result.success,
            'warnings': result.warnings,
        }

    def _handle_selections(
        self, result: ParsingResult, step_id: str
    ) -> Dict[str, str]:
        """
        Handle user selection for multi-option findings.

        Args:
            result: Parsing result with selections
            step_id: Step identifier

        Returns:
            Dictionary of resolved variables
        """
        resolved = result.variables.copy()

        # Process each selection requirement
        for var_name, options in result.selection_required.items():
            if not options:
                continue

            # Present options to user
            selected = self.selector.select_single(
                options=options,
                prompt=self._make_selection_prompt(var_name, step_id),
                allow_skip=False,
            )

            if selected:
                resolved[var_name] = selected

        return resolved

    def _make_selection_prompt(self, var_name: str, step_id: str) -> str:
        """
        Generate user-friendly prompt for variable selection.

        Args:
            var_name: Variable name (e.g., '<TARGET_BIN>')
            step_id: Step identifier

        Returns:
            Prompt string
        """
        # Clean up variable name for display
        clean_name = var_name.strip('<>').replace('_', ' ').lower()
        return f"Select {clean_name} for next step:"

    def get_step_summary(self, step_id: str, result: Dict[str, Any]) -> str:
        """
        Generate checkbox-formatted summary matching verification checklist style.

        Args:
            step_id: Step identifier
            result: Process output result

        Returns:
            Formatted summary string with checkboxes
        """
        lines = []
        findings = result.get('findings', {})

        if not findings:
            return "No parsing performed"

        # Get counts
        total = findings.get('total_count', 0)
        exploitable = findings.get('exploitable_count', 0)
        standard = findings.get('standard_count', 0)
        unknown = findings.get('unknown_count', 0)

        # Checkbox formatting (matches verification checklist)
        lines.append("Parsing Results:")
        lines.append(f"  [{'✓' if total > 0 else '□'}] SUID binaries found ({total} total)")
        lines.append(f"  [{'✓' if exploitable > 0 else '□'}] Exploitable binaries detected ({exploitable} GTFOBins matches)")
        lines.append(f"  [{'✓' if standard > 0 else '□'}] Standard system binaries filtered ({standard} expected)")

        if unknown > 0:
            lines.append(f"  [⚠] Unknown binaries detected ({unknown} require manual review)")

        # Show fuzzy match details if present
        if exploitable > 0:
            exploitable_list = findings.get('exploitable_binaries', [])
            if exploitable_list and isinstance(exploitable_list[0], dict):
                exact_count = sum(1 for b in exploitable_list if b.get('match_type') == 'exact')
                fuzzy_count = sum(1 for b in exploitable_list if b.get('match_type') == 'fuzzy')

                if fuzzy_count > 0:
                    lines.append(f"      Note: {fuzzy_count} fuzzy match(es) - verify exploit compatibility")

        # Warnings
        warnings = result.get('warnings', [])
        if warnings:
            for warning in warnings:
                lines.append(f"  [⚠] {warning}")

        return '\n'.join(lines)

    def should_continue(self, result: Dict[str, Any]) -> bool:
        """
        Determine if chain should continue based on step result.

        Args:
            result: Process output result

        Returns:
            True if chain can continue, False if fatal error
        """
        # Success flag
        if not result.get('success', True):
            # Check if there are any warnings that are fatal
            warnings = result.get('warnings', [])
            fatal_patterns = ['no exploitable', 'parse error', 'failed']

            for warning in warnings:
                warning_lower = warning.lower()
                if any(pattern in warning_lower for pattern in fatal_patterns):
                    return False

        # Check if required variables are missing
        variables = result.get('variables', {})
        if not variables:
            # No variables extracted - might be issue
            # But not fatal - some steps don't need variables
            pass

        return True
