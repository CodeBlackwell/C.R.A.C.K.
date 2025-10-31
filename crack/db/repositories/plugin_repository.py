"""
Plugin Repository - Database access layer for service plugin operations

Provides methods for:
- Getting plugin task templates
- Resolving command references for tasks
- Managing plugin task hierarchies
- Variable substitution for dynamic tasks
"""

import psycopg2
import psycopg2.extras
import json
from typing import List, Optional, Dict, Any
from pathlib import Path
from ..config import get_db_config


class PluginRepository:
    """Repository for plugin task template queries and operations"""

    def __init__(self, db_config: Dict[str, Any] = None):
        """
        Initialize repository with database configuration

        Args:
            db_config: PostgreSQL connection config (default: from get_db_config())
        """
        if db_config is None:
            db_config = get_db_config()
        self.db_config = db_config

    def _get_connection(self) -> psycopg2.extensions.connection:
        """Get database connection with DictCursor"""
        conn = psycopg2.connect(**self.db_config)
        return conn

    def get_plugin(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """
        Get plugin information by name

        Args:
            plugin_name: Plugin name (e.g., 'ftp', 'mysql')

        Returns:
            Dict with plugin data or None if not found
        """
        conn = self._get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        cursor.execute("""
            SELECT id, name, python_class, python_module, description,
                   service_patterns, default_ports
            FROM service_plugins
            WHERE name = %s
        """, (plugin_name,))

        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        plugin = dict(row)
        # Parse JSON fields
        plugin['service_patterns'] = json.loads(plugin.get('service_patterns', '[]'))
        plugin['default_ports'] = json.loads(plugin.get('default_ports', '[]'))
        return plugin

    def get_plugin_tasks(self, plugin_name: str, include_children: bool = True) -> List[Dict[str, Any]]:
        """
        Get all task templates for a plugin

        Args:
            plugin_name: Plugin name (e.g., 'ftp')
            include_children: If True, include nested child tasks

        Returns:
            List of task template dicts with command references
        """
        conn = self._get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # Get plugin ID
        cursor.execute("SELECT id FROM service_plugins WHERE name = %s", (plugin_name,))
        plugin_row = cursor.fetchone()
        if not plugin_row:
            conn.close()
            return []

        plugin_id = plugin_row['id']

        # Get all tasks for this plugin
        cursor.execute("""
            SELECT id, task_id, task_name, task_type, parent_task_id,
                   command_id, priority, description, tags, requires_auth
            FROM plugin_task_templates
            WHERE plugin_id = %s
            ORDER BY parent_task_id NULLS FIRST, priority ASC
        """, (plugin_id,))

        tasks = [dict(row) for row in cursor.fetchall()]

        # Parse JSON fields
        for task in tasks:
            task['tags'] = json.loads(task.get('tags', '[]')) if task.get('tags') else []

        # Get variables for each task
        for task in tasks:
            cursor.execute("""
                SELECT variable_name, variable_source, default_value, required, description
                FROM plugin_task_variables
                WHERE task_template_id = %s
            """, (task['id'],))
            task['variables'] = [dict(r) for r in cursor.fetchall()]

        conn.close()

        if include_children:
            # Build task hierarchy
            return self._build_task_hierarchy(tasks)
        return tasks

    def _build_task_hierarchy(self, tasks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Build hierarchical task tree from flat list

        Args:
            tasks: Flat list of tasks

        Returns:
            List of root tasks with nested children
        """
        # Create task lookup by ID
        task_map = {task['id']: task for task in tasks}

        # Add children arrays
        for task in tasks:
            task['children'] = []

        # Build hierarchy
        root_tasks = []
        for task in tasks:
            if task['parent_task_id'] is None:
                root_tasks.append(task)
            else:
                parent = task_map.get(task['parent_task_id'])
                if parent:
                    parent['children'].append(task)

        return root_tasks

    def get_task_with_command(self, task_id: int) -> Optional[Dict[str, Any]]:
        """
        Get task template with full command details

        Args:
            task_id: Task template ID

        Returns:
            Dict with task and command data
        """
        conn = self._get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # Get task with command join
        cursor.execute("""
            SELECT
                t.id, t.task_id, t.task_name, t.task_type, t.description,
                t.command_id, t.priority, t.tags, t.requires_auth,
                c.name as command_name, c.command_template, c.description as command_description,
                c.category, c.oscp_relevance, c.notes as command_notes
            FROM plugin_task_templates t
            LEFT JOIN commands c ON t.command_id = c.id
            WHERE t.id = %s
        """, (task_id,))

        row = cursor.fetchone()
        if not row:
            conn.close()
            return None

        task = dict(row)
        task['tags'] = json.loads(task.get('tags', '[]')) if task.get('tags') else []

        # Get variables
        cursor.execute("""
            SELECT variable_name, variable_source, default_value, required, description
            FROM plugin_task_variables
            WHERE task_template_id = %s
        """, (task_id,))
        task['variables'] = [dict(r) for r in cursor.fetchall()]

        conn.close()
        return task

    def create_task_instance(
        self,
        plugin_name: str,
        target: str,
        port: int,
        service_info: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Create runtime task instance from template

        Args:
            plugin_name: Plugin name
            target: Target IP/hostname
            port: Target port
            service_info: Optional service detection info

        Returns:
            Task tree with filled commands
        """
        tasks = self.get_plugin_tasks(plugin_name)

        # Fill variables in each task
        for task in self._flatten_tasks(tasks):
            task['instance_id'] = f"{task['task_id']}-{port}"

            # Build variable substitution map
            var_map = {
                'target': target,
                'port': str(port),
                'service': service_info.get('service', '') if service_info else '',
                'version': service_info.get('version', '') if service_info else ''
            }

            # Add custom variables from task
            for var in task.get('variables', []):
                var_name = var['variable_name']
                if var_name not in var_map:
                    # Use default value if provided
                    var_map[var_name] = var.get('default_value', f'<{var_name.upper()}>')

            task['variable_map'] = var_map

        return {'children': tasks}

    def _flatten_tasks(self, tasks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Flatten hierarchical task tree to list

        Args:
            tasks: Hierarchical task list

        Returns:
            Flat list of all tasks
        """
        flat = []
        for task in tasks:
            flat.append(task)
            if task.get('children'):
                flat.extend(self._flatten_tasks(task['children']))
        return flat

    def add_task_template(
        self,
        plugin_name: str,
        task_id: str,
        task_name: str,
        task_type: str,
        command_id: str = None,
        parent_task_id: int = None,
        priority: int = 0,
        description: str = '',
        tags: List[str] = None,
        requires_auth: bool = False
    ) -> int:
        """
        Add a new task template to a plugin

        Args:
            plugin_name: Plugin name
            task_id: Task identifier
            task_name: Human-readable name
            task_type: 'parent', 'command', 'manual', 'research'
            command_id: Optional command ID from commands table
            parent_task_id: Optional parent task ID
            priority: Execution priority
            description: Task description
            tags: List of tags
            requires_auth: Requires authentication

        Returns:
            New task template ID
        """
        conn = self._get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # Get plugin ID
        cursor.execute("SELECT id FROM service_plugins WHERE name = %s", (plugin_name,))
        plugin_row = cursor.fetchone()
        if not plugin_row:
            conn.close()
            raise ValueError(f"Plugin not found: {plugin_name}")

        plugin_id = plugin_row['id']

        # Insert task (use RETURNING for PostgreSQL)
        cursor.execute("""
            INSERT INTO plugin_task_templates
            (plugin_id, task_id, task_name, task_type, parent_task_id,
             command_id, priority, description, tags, requires_auth)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            plugin_id, task_id, task_name, task_type, parent_task_id,
            command_id, priority, description,
            json.dumps(tags) if tags else None,
            requires_auth
        ))

        task_template_id = cursor.fetchone()['id']
        conn.commit()
        conn.close()

        return task_template_id

    def add_task_variable(
        self,
        task_template_id: int,
        variable_name: str,
        variable_source: str,
        default_value: str = None,
        required: bool = True,
        description: str = ''
    ) -> int:
        """
        Add a variable to a task template

        Args:
            task_template_id: Task template ID
            variable_name: Variable name (e.g., 'target', 'port')
            variable_source: Source type ('target', 'port', 'config', etc.)
            default_value: Optional default value
            required: Is variable required?
            description: Variable description

        Returns:
            New variable ID
        """
        conn = self._get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        cursor.execute("""
            INSERT INTO plugin_task_variables
            (task_template_id, variable_name, variable_source, default_value, required, description)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (task_template_id, variable_name, variable_source, default_value, required, description))

        variable_id = cursor.fetchone()['id']
        conn.commit()
        conn.close()

        return variable_id

    def get_all_plugins(self) -> List[Dict[str, Any]]:
        """
        Get all registered plugins

        Returns:
            List of plugin dicts
        """
        conn = self._get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        cursor.execute("""
            SELECT id, name, python_class, python_module, description,
                   service_patterns, default_ports
            FROM service_plugins
            ORDER BY name
        """)

        plugins = []
        for row in cursor.fetchall():
            plugin = dict(row)
            plugin['service_patterns'] = json.loads(plugin.get('service_patterns', '[]'))
            plugin['default_ports'] = json.loads(plugin.get('default_ports', '[]'))
            plugins.append(plugin)

        conn.close()
        return plugins

    def count_plugin_tasks(self, plugin_name: str) -> int:
        """
        Count tasks for a plugin

        Args:
            plugin_name: Plugin name

        Returns:
            Number of tasks
        """
        conn = self._get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        cursor.execute("""
            SELECT COUNT(*) as count
            FROM plugin_task_templates t
            JOIN service_plugins p ON t.plugin_id = p.id
            WHERE p.name = %s
        """, (plugin_name,))

        row = cursor.fetchone()
        conn.close()
        return row['count'] if row else 0
