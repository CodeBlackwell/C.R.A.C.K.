"""
SQL Plugin Mixin - Base class for SQL-backed service plugins

Provides get_task_tree_from_sql() method that:
1. Retrieves task templates from PluginRepository
2. Fills command templates using CommandRepository
3. Performs variable substitution (target, port, service_info)
4. Returns task tree in same format as hardcoded plugins (backwards compatible)

Usage:
    class FTPPlugin(ServicePlugin, SQLPluginMixin):
        def get_task_tree(self, target, port, service_info):
            # Try SQL backend first
            try:
                return self.get_task_tree_from_sql(target, port, service_info)
            except Exception as e:
                # Fallback to hardcoded (if SQL fails)
                return self._get_hardcoded_task_tree(target, port, service_info)
"""

import os
from typing import Dict, Any, List, Optional
from pathlib import Path


class SQLPluginMixin:
    """Mixin class providing SQL backend integration for service plugins"""

    def get_task_tree_from_sql(
        self,
        target: str,
        port: int,
        service_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate task tree from SQL database

        Args:
            target: Target IP/hostname
            port: Port number
            service_info: Service detection info (service, version, product)

        Returns:
            Task tree dict compatible with existing plugin format:
            {
                'id': 'plugin-enum-PORT',
                'name': 'Plugin Enumeration (Port PORT)',
                'type': 'parent',
                'children': [...]
            }

        Raises:
            ImportError: If SQL backend not available
            Exception: If plugin not found or database error
        """
        # Check if SQL backend is enabled
        if not self._sql_enabled():
            raise Exception("SQL backend not enabled (set CRACK_USE_SQL=1)")

        # Import SQL dependencies
        try:
            from db.repositories import PluginRepository, CommandRepository
            from reference.core.sql_adapter import SQLCommandRegistryAdapter
        except ImportError as e:
            raise ImportError(f"SQL backend dependencies not available: {e}")

        # Get plugin name (from self.name property)
        plugin_name = self.name

        # Initialize repositories
        plugin_repo = PluginRepository()
        command_repo = CommandRepository()

        # Get plugin tasks from database
        try:
            plugin_info = plugin_repo.get_plugin(plugin_name)
            if not plugin_info:
                raise Exception(f"Plugin '{plugin_name}' not found in database")

            # Create task instance with variable substitution
            task_tree = plugin_repo.create_task_instance(
                plugin_name=plugin_name,
                target=target,
                port=port,
                service_info=service_info
            )
        except Exception as e:
            raise Exception(f"Failed to load plugin tasks from SQL: {e}")

        # Fill command templates for all tasks
        self._fill_commands_recursive(task_tree, command_repo)

        # Return root task (remove wrapper if present)
        if 'children' in task_tree and isinstance(task_tree['children'], list):
            # Wrap in plugin root node
            return {
                'id': f'{plugin_name}-enum-{port}',
                'name': f'{plugin_name.upper()} Enumeration (Port {port})',
                'type': 'parent',
                'children': task_tree['children']
            }

        return task_tree

    def _fill_commands_recursive(
        self,
        task_node: Dict[str, Any],
        command_repo: Any
    ):
        """
        Recursively fill command templates in task tree

        Args:
            task_node: Task dict (modified in place)
            command_repo: CommandRepository instance
        """
        # Process children first (depth-first)
        if 'children' in task_node and isinstance(task_node['children'], list):
            for child in task_node['children']:
                self._fill_commands_recursive(child, command_repo)

        # Fill this task's command if it has one
        if task_node.get('command_id') and task_node.get('variable_map'):
            try:
                # Get command from repository
                command = command_repo.find_by_id(task_node['command_id'])

                if command:
                    # Fill placeholders with variables
                    filled_command = self._fill_command_template(
                        command['command_template'],
                        task_node['variable_map']
                    )

                    # Add to metadata
                    if 'metadata' not in task_node:
                        task_node['metadata'] = {}

                    task_node['metadata']['command'] = filled_command

                    # Add flag explanations if available
                    if command.get('flags'):
                        task_node['metadata']['flag_explanations'] = {
                            flag['flag']: flag['explanation']
                            for flag in command['flags']
                        }

                    # Add success/failure indicators
                    if command.get('success_indicators'):
                        task_node['metadata']['success_indicators'] = [
                            ind['pattern'] for ind in command['success_indicators']
                        ]

                    if command.get('failure_indicators'):
                        task_node['metadata']['failure_indicators'] = [
                            ind['pattern'] for ind in command['failure_indicators']
                        ]

                    # Add other metadata
                    task_node['metadata']['description'] = command.get('description', '')
                    task_node['metadata']['notes'] = command.get('notes', '')
                    task_node['metadata']['time_estimate'] = command.get('time_estimate', '')

                    # Add tags from command
                    if command.get('tags'):
                        command_tags = [tag['name'] for tag in command['tags']]
                        task_node['metadata']['tags'] = command_tags

            except Exception as e:
                # Don't fail entire tree if one command fails to fill
                print(f"Warning: Failed to fill command {task_node.get('command_id')}: {e}")

    def _fill_command_template(
        self,
        template: str,
        variable_map: Dict[str, str]
    ) -> str:
        """
        Fill command template with variables

        Args:
            template: Command template with <PLACEHOLDER> syntax
            variable_map: Dict of variable values

        Returns:
            Filled command string

        Example:
            template: 'nmap -p <PORT> <TARGET>'
            variable_map: {'target': '192.168.1.1', 'port': '80'}
            result: 'nmap -p 80 192.168.1.1'
        """
        result = template

        # Replace each placeholder
        for var_name, var_value in variable_map.items():
            placeholder = f'<{var_name.upper()}>'
            result = result.replace(placeholder, str(var_value))

        return result

    def _sql_enabled(self) -> bool:
        """
        Check if SQL backend is enabled

        Returns:
            True if CRACK_USE_SQL environment variable is set to 1/true/yes
        """
        env_value = os.environ.get('CRACK_USE_SQL', '').lower()
        return env_value in ['1', 'true', 'yes', 'on']

    def get_fallback_task_tree(
        self,
        target: str,
        port: int,
        service_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Fallback to hardcoded task tree if SQL fails

        This method should be overridden by plugins that maintain
        backwards compatibility with hardcoded task trees.

        Args:
            target: Target IP/hostname
            port: Port number
            service_info: Service info dict

        Returns:
            Hardcoded task tree

        Raises:
            NotImplementedError: If plugin doesn't provide fallback
        """
        raise NotImplementedError(
            f"Plugin {self.name} does not provide hardcoded fallback. "
            f"Ensure SQL backend is available and populated."
        )


class SQLPluginMixinV2(SQLPluginMixin):
    """
    Enhanced SQL mixin with automatic fallback and migration support

    This version automatically tries SQL first, falls back to hardcoded,
    and provides migration helpers.

    Usage:
        class FTPPlugin(ServicePlugin, SQLPluginMixinV2):
            def get_task_tree(self, target, port, service_info):
                return self.get_task_tree_auto(target, port, service_info)

            def _get_hardcoded_task_tree(self, target, port, service_info):
                # Original hardcoded implementation
                return {...}
    """

    def get_task_tree_auto(
        self,
        target: str,
        port: int,
        service_info: Dict[str, Any],
        prefer_sql: bool = True
    ) -> Dict[str, Any]:
        """
        Automatically choose SQL or hardcoded backend

        Args:
            target: Target IP/hostname
            port: Port number
            service_info: Service info dict
            prefer_sql: If True, try SQL first (default)

        Returns:
            Task tree from SQL or hardcoded fallback
        """
        if prefer_sql and self._sql_enabled():
            try:
                return self.get_task_tree_from_sql(target, port, service_info)
            except Exception as e:
                # Log warning and fall back
                print(f"[Warning] SQL backend failed for {self.name}: {e}")
                print(f"[Warning] Falling back to hardcoded task tree")

        # Use hardcoded fallback
        if hasattr(self, '_get_hardcoded_task_tree'):
            return self._get_hardcoded_task_tree(target, port, service_info)
        else:
            raise NotImplementedError(
                f"Plugin {self.name} has no hardcoded fallback. "
                f"Enable SQL backend: export CRACK_USE_SQL=1"
            )

    def _get_hardcoded_task_tree(
        self,
        target: str,
        port: int,
        service_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Hardcoded task tree implementation (to be overridden)

        Args:
            target: Target IP/hostname
            port: Port number
            service_info: Service info dict

        Returns:
            Task tree dict
        """
        raise NotImplementedError(
            f"Plugin {self.name} must implement _get_hardcoded_task_tree() "
            f"or ensure SQL backend is populated"
        )


# Convenience function for checking SQL availability
def check_sql_backend() -> bool:
    """
    Check if SQL backend is available and populated

    Returns:
        True if SQL backend is usable
    """
    try:
        from db.repositories import PluginRepository
        repo = PluginRepository()
        plugins = repo.get_all_plugins()
        return len(plugins) > 0
    except:
        return False


# Migration helper
def migrate_plugin_to_sql(plugin_file: Path) -> bool:
    """
    Run migration script on plugin file

    Args:
        plugin_file: Path to plugin .py file

    Returns:
        True if migration successful
    """
    import subprocess

    script_path = Path(__file__).parent.parent.parent / 'scripts' / 'migrate_plugin_to_sql.py'

    try:
        result = subprocess.run(
            ['python3', str(script_path), str(plugin_file), '--apply'],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception as e:
        print(f"Migration failed: {e}")
        return False
