"""
Dynamic command execution with variable filling

Executes alternative commands with:
1. Auto-fill from context (where possible)
2. Interactive prompting for missing values
3. Template substitution
4. Confirmation before execution
5. Output capture
"""

import subprocess
from typing import Dict, Optional
from .models import AlternativeCommand, ExecutionResult, Variable
from .context import ContextResolver


class AlternativeExecutor:
    """Execute alternative commands with dynamic variable filling"""

    @staticmethod
    def execute(
        alt_cmd: AlternativeCommand,
        context: ContextResolver,
        interactive: bool = True,
        dry_run: bool = False
    ) -> ExecutionResult:
        """
        Execute alternative command with dynamic variable filling

        Args:
            alt_cmd: AlternativeCommand to execute
            context: ContextResolver for auto-filling variables
            interactive: Prompt user for missing variables
            dry_run: Only generate command, don't execute

        Returns:
            ExecutionResult with execution details
        """
        # Step 1: Auto-resolve variables from context
        values = AlternativeExecutor._auto_resolve_variables(alt_cmd, context)

        # Step 2: Prompt for missing required variables (if interactive)
        if interactive:
            missing_required = AlternativeExecutor._get_missing_required(alt_cmd, values)

            if missing_required:
                try:
                    user_values = AlternativeExecutor._prompt_for_variables(
                        missing_required,
                        context
                    )
                    values.update(user_values)
                except KeyboardInterrupt:
                    return ExecutionResult(
                        success=False,
                        command='',
                        cancelled=True
                    )

        # Step 3: Validate all required variables have values
        missing = AlternativeExecutor._get_missing_required(alt_cmd, values)
        if missing:
            missing_names = [v.name for v in missing]
            return ExecutionResult(
                success=False,
                command='',
                error=f"Missing required variables: {', '.join(missing_names)}",
                cancelled=True
            )

        # Step 4: Fill template
        final_command = AlternativeExecutor._fill_template(
            alt_cmd.command_template,
            values
        )

        # Step 5: Dry run (just return command without executing)
        if dry_run:
            return ExecutionResult(
                success=True,
                command=final_command,
                variables_used=values
            )

        # Step 6: Confirm execution (if interactive)
        if interactive:
            print(f"\nFinal command: {final_command}")
            confirm = input("Execute? [Y/n]: ").strip().lower()
            if confirm and confirm not in ['y', 'yes']:
                return ExecutionResult(
                    success=False,
                    command=final_command,
                    cancelled=True,
                    variables_used=values
                )

        # Step 7: Execute command
        try:
            result = subprocess.run(
                final_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            return ExecutionResult(
                success=result.returncode == 0,
                command=final_command,
                output=result.stdout,
                error=result.stderr,
                return_code=result.returncode,
                variables_used=values
            )

        except subprocess.TimeoutExpired:
            return ExecutionResult(
                success=False,
                command=final_command,
                error="Command timed out after 5 minutes",
                return_code=-1,
                variables_used=values
            )

        except Exception as e:
            return ExecutionResult(
                success=False,
                command=final_command,
                error=str(e),
                return_code=-1,
                variables_used=values
            )

    @staticmethod
    def _auto_resolve_variables(
        alt_cmd: AlternativeCommand,
        context: ContextResolver
    ) -> Dict[str, str]:
        """Auto-resolve variables from context (Phase 6.5: with context hints)"""
        values = {}

        # Extract context hints from task metadata if available (Phase 6.5)
        context_hints = None
        if context.task and context.task.metadata.get('alternative_context'):
            context_hints = context.task.metadata['alternative_context']

        for var in alt_cmd.get_auto_resolve_variables():
            resolved = context.resolve(var.name, context_hints=context_hints)
            if resolved is not None:
                values[var.name] = resolved

        return values

    @staticmethod
    def _get_missing_required(
        alt_cmd: AlternativeCommand,
        values: Dict[str, str]
    ) -> list:
        """Get required variables that don't have values"""
        return [
            var for var in alt_cmd.get_required_variables()
            if var.name not in values
        ]

    @staticmethod
    def _prompt_for_variables(
        variables: list,
        context: ContextResolver
    ) -> Dict[str, str]:
        """
        Interactively prompt user for variable values

        Args:
            variables: List of Variable objects to prompt for
            context: ContextResolver (for showing suggested values)

        Returns:
            Dictionary of {variable_name: user_input}

        Raises:
            KeyboardInterrupt: User cancelled input
        """
        values = {}

        print("\nEnter values for placeholders:")

        for var in variables:
            # Build prompt with description and example
            prompt_parts = [f"  {var.name}"]

            if var.description:
                prompt_parts.append(f"({var.description})")

            if var.example:
                prompt_parts.append(f"[e.g., {var.example}]")

            # Check if we have a suggested value from config
            suggested = context.resolve(var.name)
            if suggested:
                prompt_parts.append(f"[config: {suggested}]")

            prompt = ' '.join(prompt_parts) + ": "

            # Get user input
            user_input = input(prompt).strip()

            # If empty and we have suggested value, use that
            if not user_input and suggested:
                user_input = suggested

            # Validate required fields
            if not user_input and var.required:
                raise ValueError(f"Required variable {var.name} not provided")

            if user_input:
                values[var.name] = user_input

        return values

    @staticmethod
    def _fill_template(template: str, values: Dict[str, str]) -> str:
        """
        Fill command template with values

        Args:
            template: Command template with <PLACEHOLDER> variables
            values: Dictionary of {variable_name: value}

        Returns:
            Final command string
        """
        final_command = template

        # Replace each variable (with or without angle brackets)
        for var_name, var_value in values.items():
            # Replace <VAR_NAME> format
            final_command = final_command.replace(f"<{var_name}>", var_value)
            # Also replace {VAR_NAME} format (alternative syntax)
            final_command = final_command.replace(f"{{{var_name}}}", var_value)

        return final_command

    @staticmethod
    def generate_command_only(
        alt_cmd: AlternativeCommand,
        values: Dict[str, str]
    ) -> str:
        """
        Generate final command without execution

        Args:
            alt_cmd: AlternativeCommand
            values: Variable values (must include all required variables)

        Returns:
            Final command string
        """
        return AlternativeExecutor._fill_template(alt_cmd.command_template, values)
