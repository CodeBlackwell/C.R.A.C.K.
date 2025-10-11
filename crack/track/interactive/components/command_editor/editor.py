"""
CommandEditor - Three-Tier Command Editor Orchestrator

Coordinates between QuickEditor, AdvancedEditor, and RawEditor tiers
with smart routing, escalation, and state preservation.

NO TUI RENDERING - Pure logic component returning EditResult.
"""

from pathlib import Path
from typing import Optional, Dict
from .quick_editor import QuickEditor, EditResult
from .advanced_editor import AdvancedEditor
from .raw_editor import RawEditor


class CommandEditor:
    """
    Three-tier command editor orchestrator.

    Tier Selection Logic:
    1. QuickEditor (Tier 1) - IF tool has common params AND no escalation needed
    2. AdvancedEditor (Tier 2) - IF tool has JSON schema AND user escalates from Quick
    3. RawEditor (Tier 3) - IF user escalates from Advanced OR no schema exists

    Escalation Flow:
    Quick --[a]--> Advanced --[r]--> Raw
    Quick --------[r]---------------> Raw

    Features:
    - Smart tier routing based on tool capabilities
    - Seamless escalation with state preservation
    - Loop prevention (max 10 iterations)
    - Exception handling with graceful degradation
    - Schema caching for performance
    - Comprehensive debug logging
    """

    # Maximum escalation iterations to prevent infinite loops
    MAX_ITERATIONS = 10

    def __init__(
        self,
        command: str,
        metadata: Dict,
        profile: Optional['TargetProfile'] = None,
        logger: Optional['TUIDebugLogger'] = None
    ):
        """
        Initialize CommandEditor orchestrator.

        Args:
            command: Original command string
            metadata: Task metadata (must contain 'tool' key)
            profile: Optional TargetProfile (not used by orchestration logic)
            logger: Optional debug logger instance
        """
        self.original_command = command
        self.current_command = command  # Preserves edits across tiers
        self.metadata = metadata
        self.profile = profile
        self.current_tier: Optional[str] = None
        self._schema_cache: Dict[str, bool] = {}  # Cache schema existence checks
        self.logger = logger

        # Log initialization
        if self.logger:
            from ...log_types import LogCategory, LogLevel
            self.logger.log(
                "CommandEditor initialized",
                category=LogCategory.UI_EDITOR,
                level=LogLevel.NORMAL,
                command_length=len(command),
                tool=metadata.get('tool')
            )

    def edit(self) -> Optional[EditResult]:
        """
        Main orchestration loop (NO TUI rendering).

        Returns:
            EditResult with action="execute" and modified command
            OR None if user cancelled

        Raises:
            None - All exceptions caught and handled gracefully
        """
        # Select starting tier
        self.current_tier = self._select_initial_tier()

        # Safety counter to prevent infinite escalation loops
        iterations = 0

        # Loop until execute or cancel
        while iterations < self.MAX_ITERATIONS:
            iterations += 1

            try:
                # Run current tier
                result = self._run_tier(self.current_tier)

                if result.action == "execute":
                    # User confirmed - return final command
                    if self.logger:
                        from ...log_types import LogCategory, LogLevel
                        self.logger.log(
                            "Editor complete",
                            category=LogCategory.UI_EDITOR,
                            level=LogLevel.NORMAL,
                            tier=self.current_tier,
                            iterations=iterations
                        )
                    return result

                elif result.action == "cancel":
                    # User cancelled - return None
                    if self.logger:
                        from ...log_types import LogCategory, LogLevel
                        self.logger.log(
                            "Editor cancelled",
                            category=LogCategory.UI_EDITOR,
                            level=LogLevel.NORMAL,
                            tier=self.current_tier
                        )
                    return None

                elif result.action == "escalate":
                    # User wants to escalate to different tier
                    escalated_result = self._handle_escalation(result)

                    if escalated_result is None:
                        # Invalid escalation or user cancelled
                        return None

                    # Check what the escalated tier returned
                    if escalated_result.action == "execute":
                        # Final result - return it
                        return escalated_result
                    elif escalated_result.action == "escalate":
                        # Escalated tier also wants to escalate - continue loop
                        # This handles chained/invalid escalations
                        result = escalated_result
                        continue
                    else:
                        # Other actions (shouldn't happen) - treat as cancel
                        return None

                else:
                    # Unknown action - treat as cancel
                    if self.logger:
                        from ...log_types import LogCategory, LogLevel
                        self.logger.log(
                            "Unknown action - cancelling",
                            category=LogCategory.UI_EDITOR,
                            level=LogLevel.NORMAL,
                            action=result.action
                        )
                    return None

            except Exception as e:
                # Graceful degradation on exception
                if self.logger:
                    from ...log_types import LogCategory, LogLevel
                    self.logger.error(
                        f"Exception in tier {self.current_tier}: {e}",
                        category=LogCategory.SYSTEM_ERROR
                    )
                return None

        # Safety fallback if max iterations reached
        if self.logger:
            from ...log_types import LogCategory, LogLevel
            self.logger.error(
                "Max iterations reached - preventing infinite loop",
                category=LogCategory.SYSTEM_ERROR,
                iterations=iterations
            )
        return None

    def _select_initial_tier(self) -> str:
        """
        Determine starting tier based on tool capabilities.

        Logic:
        1. Try QuickEditor if tool in COMMON_PARAMS
        2. Fallback to AdvancedEditor if schema exists
        3. Fallback to RawEditor if no schema

        Returns:
            "quick", "advanced", or "raw"
        """
        tool = self.metadata.get('tool', 'unknown')

        # Try QuickEditor first
        if tool in QuickEditor.COMMON_PARAMS:
            tier = "quick"
        elif self._has_schema(tool):
            # Fallback to AdvancedEditor if schema exists
            tier = "advanced"
        else:
            # Fallback to RawEditor
            tier = "raw"

        # Log tier selection
        if self.logger:
            from ...log_types import LogCategory, LogLevel
            self.logger.log(
                f"Tier selected: {tier}",
                category=LogCategory.UI_EDITOR_TIER,
                level=LogLevel.VERBOSE,
                tool=tool,
                has_schema=self._has_schema(tool),
                in_common_params=(tool in QuickEditor.COMMON_PARAMS)
            )

        return tier

    def _run_tier(self, tier: str) -> EditResult:
        """
        Execute specific tier editor.

        Args:
            tier: "quick", "advanced", or "raw"

        Returns:
            EditResult from tier editor

        Raises:
            Exception: Caught by caller (edit method)
        """
        # Log tier execution start
        if self.logger:
            from ...log_types import LogCategory, LogLevel
            self.logger.log(
                f"Running tier: {tier}",
                category=LogCategory.UI_EDITOR_TIER,
                level=LogLevel.VERBOSE,
                command_length=len(self.current_command)
            )

        if tier == "quick":
            editor = QuickEditor(self.current_command, self.metadata)
            return editor.run()

        elif tier == "advanced":
            editor = AdvancedEditor(self.current_command, self.metadata)
            return editor.run()

        elif tier == "raw":
            editor = RawEditor(self.current_command, self.original_command)
            return editor.run()

        else:
            # Unknown tier - return cancel
            if self.logger:
                from ...log_types import LogCategory, LogLevel
                self.logger.error(
                    f"Unknown tier: {tier}",
                    category=LogCategory.SYSTEM_ERROR
                )
            return EditResult(command=None, action="cancel")

    def _handle_escalation(self, result: EditResult) -> Optional[EditResult]:
        """
        Handle tier escalation requests.

        Args:
            result: EditResult with action="escalate" and next_tier

        Returns:
            Final EditResult after escalation completes
            OR None if user cancelled or invalid escalation
        """
        next_tier = result.next_tier

        # Update current command with any edits made
        if result.command:
            self.current_command = result.command

        # Log escalation
        if self.logger:
            from ...log_types import LogCategory, LogLevel
            self.logger.log(
                "Tier escalation",
                category=LogCategory.UI_EDITOR_TIER,
                level=LogLevel.NORMAL,
                from_tier=self.current_tier,
                to_tier=next_tier,
                reason="user requested"
            )

        # Validate escalation path and run next tier
        escalated_result = None

        if self.current_tier == "quick":
            if next_tier == "advanced":
                self.current_tier = "advanced"
                escalated_result = self._run_tier("advanced")
            elif next_tier == "raw":
                self.current_tier = "raw"
                escalated_result = self._run_tier("raw")

        elif self.current_tier == "advanced":
            if next_tier == "raw":
                self.current_tier = "raw"
                escalated_result = self._run_tier("raw")

        # Check if escalation was invalid
        if escalated_result is None:
            # Invalid escalation path
            if self.logger:
                from ...log_types import LogCategory, LogLevel
                self.logger.error(
                    "Invalid escalation path",
                    category=LogCategory.UI_EDITOR_TIER,
                    from_tier=self.current_tier,
                    to_tier=next_tier
                )
            return None

        # Check result from escalated tier
        if escalated_result.action == "cancel":
            # User cancelled in escalated tier
            return None

        # Return the result (execute or further escalate)
        return escalated_result

    def _has_schema(self, tool: str) -> bool:
        """
        Check if schema exists (cached).

        Args:
            tool: Tool name

        Returns:
            True if schema file exists
        """
        # Check cache first
        if tool in self._schema_cache:
            is_cached = True
            exists = self._schema_cache[tool]
        else:
            is_cached = False
            schema_path = Path(__file__).parent / "schemas" / f"{tool}.json"
            exists = schema_path.exists()
            self._schema_cache[tool] = exists

        # Log schema check
        if self.logger:
            from ...log_types import LogCategory, LogLevel
            self.logger.log(
                f"Schema check for {tool}",
                category=LogCategory.UI_EDITOR_SCHEMA,
                level=LogLevel.VERBOSE,
                exists=exists,
                cached=is_cached
            )

        return exists
