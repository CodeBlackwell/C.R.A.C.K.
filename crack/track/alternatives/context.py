"""
Context resolution for variable auto-filling

Resolves variable values from execution context in priority order:
1. Task metadata (port, service from current task)
2. Profile state (target IP, discovered services)
3. Config (LHOST, LPORT, wordlists from ~/.crack/config.json)
4. None (will prompt user)
"""

from typing import Optional, Dict, Any


class ContextResolver:
    """Resolve variables from execution context"""

    def __init__(self, profile=None, task=None, config=None):
        """
        Initialize context resolver

        Args:
            profile: TargetProfile instance (optional)
            task: TaskNode instance (optional)
            config: ConfigManager instance (optional)
        """
        self.profile = profile
        self.task = task
        self.config = config

    def resolve(self, variable_name: str) -> Optional[str]:
        """
        Auto-resolve variable from context

        Args:
            variable_name: Variable name (without angle brackets)

        Returns:
            Resolved value or None if not found in context
        """
        # Normalize variable name (remove <> if present)
        var_name = variable_name.strip('<>')

        # Priority 1: Task metadata (port, service, etc.)
        if self.task:
            task_value = self._resolve_from_task(var_name)
            if task_value is not None:
                return task_value

        # Priority 2: Profile state (target, discovered services)
        if self.profile:
            profile_value = self._resolve_from_profile(var_name)
            if profile_value is not None:
                return profile_value

        # Priority 3: Config (LHOST, LPORT, wordlists)
        if self.config:
            config_value = self._resolve_from_config(var_name)
            if config_value is not None:
                return config_value

        # Not found - will need to prompt user
        return None

    def _resolve_from_task(self, var_name: str) -> Optional[str]:
        """Resolve from task metadata"""
        if not self.task or not hasattr(self.task, 'metadata'):
            return None

        metadata = self.task.metadata

        # Common task-level variables
        if var_name == 'PORT':
            port = metadata.get('port')
            return str(port) if port is not None else None

        if var_name == 'SERVICE':
            return metadata.get('service')

        if var_name == 'VERSION':
            return metadata.get('version')

        # Check metadata directly for any other variables
        if var_name.lower() in metadata:
            value = metadata[var_name.lower()]
            return str(value) if value is not None else None

        return None

    def _resolve_from_profile(self, var_name: str) -> Optional[str]:
        """Resolve from profile state"""
        if not self.profile:
            return None

        # Target IP/hostname
        if var_name in ['TARGET', 'TARGET_IP', 'TARGET_HOST']:
            return self.profile.target

        # Phase
        if var_name == 'PHASE':
            return self.profile.phase

        # Common port (if only one port discovered)
        if var_name == 'PORT' and len(self.profile.ports) == 1:
            return str(list(self.profile.ports.keys())[0])

        # Try to get from profile metadata
        if hasattr(self.profile, 'metadata') and var_name in self.profile.metadata:
            value = self.profile.metadata[var_name]
            return str(value) if value is not None else None

        return None

    def _resolve_from_config(self, var_name: str) -> Optional[str]:
        """Resolve from config"""
        if not self.config:
            return None

        # Try to get from config.variables
        if hasattr(self.config, 'variables') and var_name in self.config.variables:
            var_config = self.config.variables[var_name]
            if isinstance(var_config, dict):
                return var_config.get('value')
            return str(var_config)

        # Try direct config attribute
        if hasattr(self.config, 'config'):
            config_dict = self.config.config
            if 'variables' in config_dict and var_name in config_dict['variables']:
                var_config = config_dict['variables'][var_name]
                if isinstance(var_config, dict):
                    return var_config.get('value')
                return str(var_config)

        return None

    def get_resolution_source(self, variable_name: str) -> Optional[str]:
        """
        Get the source of resolution for debugging

        Args:
            variable_name: Variable name

        Returns:
            Source name ('task', 'profile', 'config') or None
        """
        var_name = variable_name.strip('<>')

        if self.task and self._resolve_from_task(var_name) is not None:
            return 'task'

        if self.profile and self._resolve_from_profile(var_name) is not None:
            return 'profile'

        if self.config and self._resolve_from_config(var_name) is not None:
            return 'config'

        return None

    def get_all_resolvable(self) -> Dict[str, str]:
        """
        Get all variables that can be resolved from context

        Returns:
            Dictionary of {variable_name: value} for all resolvable variables
        """
        resolvable = {}

        # Common variables to check
        common_vars = [
            'TARGET', 'TARGET_IP', 'TARGET_HOST',
            'PORT', 'SERVICE', 'VERSION',
            'LHOST', 'LPORT',
            'WORDLIST', 'THREADS', 'INTERFACE',
            'PHASE'
        ]

        for var in common_vars:
            value = self.resolve(var)
            if value is not None:
                resolvable[var] = value

        return resolvable
