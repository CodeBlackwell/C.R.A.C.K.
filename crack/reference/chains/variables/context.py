"""
Variable context with hierarchical scoping.

Provides priority-based variable resolution: step > session > config > default.
"""

from enum import Enum
from typing import Dict, Optional, List, Any


class VariableScope(Enum):
    """Variable scope levels (priority order)"""

    STEP = "step"  # Highest priority - current step only
    SESSION = "session"  # Session-wide - persisted across steps
    CONFIG = "config"  # User config file
    DEFAULT = "default"  # Lowest priority - fallback values


class VariableContext:
    """
    Hierarchical variable resolution with scoping.

    Variables are resolved with the following priority:
    1. Step-scoped variables (set by output parsing)
    2. Session-scoped variables (persisted across steps)
    3. Config-scoped variables (user config file)
    4. Default values (from command variable definitions)

    This allows flexible variable management where:
    - Parsed output can override config values
    - User selections persist across chain execution
    - Config provides sensible defaults
    """

    def __init__(self, session, config_manager=None):
        """
        Initialize variable context.

        Args:
            session: ChainSession instance
            config_manager: ConfigManager instance (optional)
        """
        self.session = session
        self.config = config_manager

        # Step-scoped variables: {step_id: {var_name: value}}
        self.step_vars: Dict[str, Dict[str, str]] = {}

    def resolve(
        self, var_name: str, step_id: Optional[str] = None, default: Optional[str] = None
    ) -> Optional[str]:
        """
        Resolve variable with hierarchical priority.

        Args:
            var_name: Variable name (e.g., '<TARGET>')
            step_id: Current step ID (for step-scoped lookup)
            default: Default value if not found anywhere

        Returns:
            Resolved value or None
        """
        # 1. Step-scoped (highest priority)
        if step_id and step_id in self.step_vars:
            if var_name in self.step_vars[step_id]:
                return self.step_vars[step_id][var_name]

        # 2. Session-scoped
        if hasattr(self.session, 'variables') and var_name in self.session.variables:
            return self.session.variables[var_name]

        # 3. Config-scoped
        if self.config:
            # Strip angle brackets for config lookup
            clean_name = var_name.strip('<>')
            config_value = self.config.get_placeholder(f'<{clean_name}>')
            if config_value:
                return config_value

        # 4. Default value
        return default

    def set_step_variable(self, step_id: str, var_name: str, value: str):
        """
        Set step-scoped variable.

        Args:
            step_id: Step identifier
            var_name: Variable name
            value: Variable value
        """
        if step_id not in self.step_vars:
            self.step_vars[step_id] = {}
        self.step_vars[step_id][var_name] = value

    def set_session_variable(self, var_name: str, value: str):
        """
        Set session-scoped variable (persists across steps).

        Args:
            var_name: Variable name
            value: Variable value
        """
        if not hasattr(self.session, 'variables'):
            self.session.variables = {}
        self.session.variables[var_name] = value

    def get_step_variables(self, step_id: str) -> Dict[str, str]:
        """
        Get all variables for a specific step.

        Args:
            step_id: Step identifier

        Returns:
            Dictionary of variable name -> value
        """
        return self.step_vars.get(step_id, {}).copy()

    def get_all_variables(self, step_id: Optional[str] = None) -> Dict[str, str]:
        """
        Get all currently resolved variables.

        Args:
            step_id: Current step ID (for step-scoped inclusion)

        Returns:
            Merged dictionary of all variables (step > session > config)
        """
        all_vars = {}

        # Start with config
        if self.config and hasattr(self.config, 'placeholders'):
            all_vars.update(self.config.placeholders)

        # Override with session
        if hasattr(self.session, 'variables'):
            all_vars.update(self.session.variables)

        # Override with step
        if step_id and step_id in self.step_vars:
            all_vars.update(self.step_vars[step_id])

        return all_vars

    def get_required_variables(self, command: str, filled: Dict[str, str]) -> List[str]:
        """
        Extract placeholders that still need values.

        Args:
            command: Command template with <PLACEHOLDERS>
            filled: Already-filled variables

        Returns:
            List of variable names that need resolution
        """
        import re

        placeholders = re.findall(r'<([A-Z_0-9]+)>', command)
        return [f'<{p}>' for p in placeholders if f'<{p}>' not in filled]

    def clear_step_variables(self, step_id: str):
        """
        Clear all variables for a specific step.

        Args:
            step_id: Step identifier
        """
        if step_id in self.step_vars:
            del self.step_vars[step_id]

    def get_variable_source(
        self, var_name: str, step_id: Optional[str] = None
    ) -> VariableScope:
        """
        Determine where a variable's value comes from.

        Args:
            var_name: Variable name
            step_id: Current step ID

        Returns:
            VariableScope indicating source
        """
        # Check in priority order
        if step_id and step_id in self.step_vars and var_name in self.step_vars[step_id]:
            return VariableScope.STEP

        if hasattr(self.session, 'variables') and var_name in self.session.variables:
            return VariableScope.SESSION

        if self.config:
            clean_name = var_name.strip('<>')
            if self.config.get_placeholder(f'<{clean_name}>'):
                return VariableScope.CONFIG

        return VariableScope.DEFAULT
