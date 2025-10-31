#!/usr/bin/env python3
"""
Plugin to SQL Migration Script

Extracts commands, metadata, and task structures from service plugin .py files
and generates SQL INSERT statements for:
- commands table (unified command registry)
- command_flags table (flag explanations)
- command_success_indicators table
- command_failure_indicators table
- plugin_task_templates table
- plugin_task_variables table

Usage:
    python3 scripts/migrate_plugin_to_sql.py track/services/ftp.py --output migrations/ftp_commands.sql
    python3 scripts/migrate_plugin_to_sql.py track/services/ftp.py --apply  # Apply directly to database
"""

import ast
import re
import json
import argparse
import sqlite3
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple


class PluginExtractor:
    """Extract command metadata from service plugin Python files"""

    def __init__(self, plugin_file: Path):
        self.plugin_file = plugin_file
        self.plugin_name = plugin_file.stem  # ftp.py -> ftp
        self.commands = []
        self.task_templates = []

    def extract(self) -> Dict[str, Any]:
        """
        Parse plugin file and extract all command metadata

        Returns:
            Dict with 'commands' and 'task_templates' lists
        """
        with open(self.plugin_file, 'r') as f:
            content = f.read()

        tree = ast.parse(content)

        # Find the get_task_tree method
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == 'get_task_tree':
                self._extract_from_task_tree(node, content)
                break

        return {
            'plugin_name': self.plugin_name,
            'commands': self.commands,
            'task_templates': self.task_templates
        }

    def _extract_from_task_tree(self, func_node: ast.FunctionDef, source: str):
        """Recursively extract tasks from get_task_tree method"""
        for node in ast.walk(func_node):
            if isinstance(node, ast.Dict):
                task_dict = self._parse_dict_node(node, source)
                if task_dict and 'metadata' in task_dict:
                    self._process_task(task_dict)

    def _parse_dict_node(self, dict_node: ast.Dict, source: str) -> Optional[Dict[str, Any]]:
        """Parse AST Dict node into Python dict"""
        try:
            result = {}
            for key, value in zip(dict_node.keys, dict_node.values):
                if key is None:
                    continue

                key_name = None
                if isinstance(key, ast.Constant):
                    key_name = key.value
                elif isinstance(key, ast.Str):
                    key_name = key.s

                if key_name:
                    result[key_name] = self._parse_value_node(value, source)

            return result if result else None
        except:
            return None

    def _parse_value_node(self, node: ast.AST, source: str) -> Any:
        """Parse AST value node into Python value"""
        if isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.Str):
            return node.s
        elif isinstance(node, ast.Num):
            return node.n
        elif isinstance(node, ast.List):
            return [self._parse_value_node(item, source) for item in node.elts]
        elif isinstance(node, ast.Dict):
            return self._parse_dict_node(node, source)
        elif isinstance(node, ast.JoinedStr):
            # f-string - extract template
            parts = []
            for value in node.values:
                if isinstance(value, ast.Constant):
                    parts.append(value.value)
                elif isinstance(value, ast.FormattedValue):
                    # Replace formatted values with placeholders
                    if isinstance(value.value, ast.Name):
                        parts.append(f'<{value.value.id.upper()}>')
                    else:
                        parts.append('<VALUE>')
            return ''.join(parts)
        else:
            # For other node types, try to get source code
            try:
                return ast.get_source_segment(source, node)
            except:
                return str(node)

    def _process_task(self, task: Dict[str, Any]):
        """Process a task dict and extract command metadata"""
        metadata = task.get('metadata', {})

        if not metadata or 'command' not in metadata:
            return

        command_template = metadata.get('command', '')

        # Generate command ID from task ID or command text
        task_id = task.get('id', '')
        command_id = self._generate_command_id(task_id, command_template)

        # Extract command data
        command_data = {
            'id': command_id,
            'name': task.get('name', '').replace(f' (Port {task.get("port", "")})' if 'port' in task else '', ''),
            'command_template': self._normalize_command(command_template),
            'description': metadata.get('description', ''),
            'category': self._infer_category(metadata),
            'subcategory': self.plugin_name,
            'tags': metadata.get('tags', []),
            'oscp_relevance': self._extract_oscp_relevance(metadata.get('tags', [])),
            'notes': metadata.get('notes', ''),
            'time_estimate': metadata.get('time_estimate', ''),
            'flag_explanations': metadata.get('flag_explanations', {}),
            'success_indicators': metadata.get('success_indicators', []),
            'failure_indicators': metadata.get('failure_indicators', []),
            'alternatives': metadata.get('alternatives', []),
            'next_steps': metadata.get('next_steps', [])
        }

        self.commands.append(command_data)

        # Create task template entry
        task_template = {
            'task_id': task_id,
            'task_name': task.get('name', ''),
            'task_type': task.get('type', 'command'),
            'command_id': command_id,
            'description': metadata.get('description', ''),
            'tags': metadata.get('tags', []),
            'priority': 0,  # Will be set based on order
            'requires_auth': 'AUTH' in ' '.join(metadata.get('tags', [])),
        }

        self.task_templates.append(task_template)

    def _generate_command_id(self, task_id: str, command: str) -> str:
        """Generate unique command ID"""
        if task_id:
            # Remove port suffix
            base_id = re.sub(r'-\d+$', '', task_id)
            return base_id

        # Generate from command
        tool = command.split()[0] if command else 'unknown'
        return f'{self.plugin_name}-{tool}'

    def _normalize_command(self, command: str) -> str:
        """
        Normalize command template by replacing variables with placeholders

        Examples:
            f'nmap -p {port} {target}' -> 'nmap -p <PORT> <TARGET>'
            f'{target}' -> '<TARGET>'
        """
        # Already has f-string placeholders from AST parsing
        if '<' in command and '>' in command:
            return command

        # Manual placeholder detection patterns
        patterns = [
            (r'\{target\}', '<TARGET>'),
            (r'\{port\}', '<PORT>'),
            (r'\{service\}', '<SERVICE>'),
            (r'\{version\}', '<VERSION>'),
            (r'\{product\}', '<PRODUCT>'),
        ]

        result = command
        for pattern, replacement in patterns:
            result = re.sub(pattern, replacement, result)

        return result

    def _infer_category(self, metadata: Dict[str, Any]) -> str:
        """Infer command category from metadata"""
        tags = ' '.join(metadata.get('tags', [])).lower()

        if 'exploit' in tags or 'privesc' in tags:
            return 'exploitation'
        elif 'enum' in tags or 'recon' in tags:
            return 'recon'
        elif 'post_exploit' in tags:
            return 'post-exploit'
        else:
            return 'recon'  # Default

    def _extract_oscp_relevance(self, tags: List[str]) -> str:
        """Extract OSCP relevance from tags"""
        for tag in tags:
            if 'OSCP:HIGH' in tag:
                return 'high'
            elif 'OSCP:MEDIUM' in tag:
                return 'medium'
            elif 'OSCP:LOW' in tag:
                return 'low'
        return 'medium'


class SQLGenerator:
    """Generate SQL INSERT statements from extracted command data"""

    def __init__(self, plugin_data: Dict[str, Any]):
        self.plugin_data = plugin_data
        self.plugin_name = plugin_data['plugin_name']

    def generate(self) -> str:
        """
        Generate complete SQL migration script

        Returns:
            SQL string with all INSERT statements
        """
        sql_parts = []

        # Header
        sql_parts.append(f"""-- Generated Migration: {self.plugin_name.upper()} Plugin Commands
-- Auto-generated from track/services/{self.plugin_name}.py
-- Date: {self._get_timestamp()}
--
-- Tables populated:
--   - commands (unified command registry)
--   - command_flags
--   - command_success_indicators
--   - command_failure_indicators
--   - plugin_task_templates
--   - plugin_task_variables
--   - command_tags (via INSERT OR IGNORE)

BEGIN TRANSACTION;

""")

        # Get plugin ID
        sql_parts.append(f"""-- Get plugin ID for {self.plugin_name}
""")

        # Insert commands
        for idx, cmd in enumerate(self.plugin_data['commands'], 1):
            sql_parts.append(self._generate_command_insert(cmd, idx))

        # Insert task templates
        for idx, task in enumerate(self.plugin_data['task_templates'], 1):
            sql_parts.append(self._generate_task_template_insert(task, idx))

        sql_parts.append("""
COMMIT;

-- Validation Queries:
""")
        sql_parts.append(f"-- SELECT COUNT(*) FROM commands WHERE subcategory = '{self.plugin_name}';\n")
        sql_parts.append(f"-- SELECT COUNT(*) FROM plugin_task_templates WHERE plugin_id = (SELECT id FROM service_plugins WHERE name = '{self.plugin_name}');\n")

        return '\n'.join(sql_parts)

    def _generate_command_insert(self, cmd: Dict[str, Any], order: int) -> str:
        """Generate INSERT for commands table and related tables"""
        sql = []

        # Main command insert
        sql.append(f"""
-- Command {order}: {cmd['name']}
INSERT OR REPLACE INTO commands (
    id, name, command_template, description, category, subcategory,
    oscp_relevance, notes, time_estimate
) VALUES (
    {self._sql_string(cmd['id'])},
    {self._sql_string(cmd['name'])},
    {self._sql_string(cmd['command_template'])},
    {self._sql_string(cmd['description'])},
    {self._sql_string(cmd['category'])},
    {self._sql_string(cmd['subcategory'])},
    {self._sql_string(cmd['oscp_relevance'])},
    {self._sql_string(cmd['notes'])},
    {self._sql_string(cmd.get('time_estimate', ''))}
);
""")

        # Tags
        for tag in cmd.get('tags', []):
            sql.append(f"""INSERT OR IGNORE INTO tags (name) VALUES ({self._sql_string(tag)});
INSERT OR IGNORE INTO command_tags (command_id, tag_id)
VALUES ({self._sql_string(cmd['id'])}, (SELECT id FROM tags WHERE name = {self._sql_string(tag)}));
""")

        # Flags
        for flag, explanation in cmd.get('flag_explanations', {}).items():
            sql.append(f"""INSERT INTO command_flags (command_id, flag, explanation)
VALUES ({self._sql_string(cmd['id'])}, {self._sql_string(flag)}, {self._sql_string(explanation)});
""")

        # Success indicators
        for indicator in cmd.get('success_indicators', []):
            sql.append(f"""INSERT INTO command_success_indicators (command_id, pattern, description)
VALUES ({self._sql_string(cmd['id'])}, {self._sql_string(indicator)}, {self._sql_string(indicator)});
""")

        # Failure indicators
        for indicator in cmd.get('failure_indicators', []):
            sql.append(f"""INSERT INTO command_failure_indicators (command_id, pattern, description)
VALUES ({self._sql_string(cmd['id'])}, {self._sql_string(indicator)}, {self._sql_string(indicator)});
""")

        # Variables (extract from command template)
        variables = self._extract_variables(cmd['command_template'])
        for var_name in variables:
            sql.append(f"""INSERT INTO command_variables (command_id, name, description, is_required)
VALUES ({self._sql_string(cmd['id'])}, {self._sql_string(var_name)}, {self._sql_string(f'{var_name} value')}, 1);
""")

        return ''.join(sql)

    def _generate_task_template_insert(self, task: Dict[str, Any], priority: int) -> str:
        """Generate INSERT for plugin_task_templates"""
        sql = f"""
-- Task Template: {task['task_name']}
INSERT INTO plugin_task_templates (
    plugin_id, task_id, task_name, task_type, command_id,
    priority, description, tags, requires_auth
) VALUES (
    (SELECT id FROM service_plugins WHERE name = {self._sql_string(self.plugin_name)}),
    {self._sql_string(task['task_id'])},
    {self._sql_string(task['task_name'])},
    {self._sql_string(task['task_type'])},
    {self._sql_string(task['command_id'])},
    {priority},
    {self._sql_string(task['description'])},
    {self._sql_string(json.dumps(task.get('tags', [])))},
    {1 if task.get('requires_auth') else 0}
);
"""

        # Task variables
        if task['command_id']:
            variables = self._extract_variables_from_command_id(task['command_id'])
            for var_name in variables:
                var_source = self._infer_variable_source(var_name)
                sql += f"""INSERT INTO plugin_task_variables (
    task_template_id, variable_name, variable_source, required
) VALUES (
    (SELECT id FROM plugin_task_templates WHERE task_id = {self._sql_string(task['task_id'])} AND plugin_id = (SELECT id FROM service_plugins WHERE name = {self._sql_string(self.plugin_name)})),
    {self._sql_string(var_name)},
    {self._sql_string(var_source)},
    1
);
"""

        return sql

    def _extract_variables(self, command_template: str) -> List[str]:
        """Extract placeholder variables from command template"""
        return list(set(re.findall(r'<(\w+)>', command_template)))

    def _extract_variables_from_command_id(self, command_id: str) -> List[str]:
        """Lookup command template and extract variables"""
        # This is a simplified version - in practice, would query the command
        return ['TARGET', 'PORT']  # Common defaults

    def _infer_variable_source(self, var_name: str) -> str:
        """Infer variable source from name"""
        var_lower = var_name.lower()

        if var_lower == 'target':
            return 'target'
        elif var_lower == 'port':
            return 'port'
        elif var_lower in ['service', 'version', 'product']:
            return 'service_info'
        elif var_lower in ['lhost', 'lport', 'interface']:
            return 'config'
        else:
            return 'prompt'

    def _sql_string(self, value: Any) -> str:
        """Format value as SQL string literal"""
        if value is None:
            return 'NULL'
        elif isinstance(value, bool):
            return '1' if value else '0'
        elif isinstance(value, (int, float)):
            return str(value)
        else:
            # Escape single quotes
            escaped = str(value).replace("'", "''")
            return f"'{escaped}'"

    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def apply_to_database(sql: str, db_path: str = None):
    """Apply SQL migration directly to database"""
    if db_path is None:
        db_path = str(Path.home() / '.crack' / 'crack.db')

    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.executescript(sql)
        conn.commit()
        print(f"✓ Migration applied successfully to {db_path}")
    except sqlite3.Error as e:
        print(f"✗ Database error: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(
        description='Extract commands from service plugin and generate SQL migration'
    )
    parser.add_argument(
        'plugin_file',
        type=Path,
        help='Path to plugin .py file (e.g., track/services/ftp.py)'
    )
    parser.add_argument(
        '--output', '-o',
        type=Path,
        help='Output SQL file path (default: migrations/PLUGIN_commands.sql)'
    )
    parser.add_argument(
        '--apply', '-a',
        action='store_true',
        help='Apply migration directly to database'
    )
    parser.add_argument(
        '--db-path',
        type=str,
        help='Database path (default: ~/.crack/crack.db)'
    )

    args = parser.parse_args()

    if not args.plugin_file.exists():
        print(f"Error: Plugin file not found: {args.plugin_file}")
        return 1

    # Extract plugin data
    print(f"[*] Extracting commands from {args.plugin_file}...")
    extractor = PluginExtractor(args.plugin_file)
    plugin_data = extractor.extract()

    print(f"[+] Extracted {len(plugin_data['commands'])} commands")
    print(f"[+] Extracted {len(plugin_data['task_templates'])} task templates")

    # Generate SQL
    print("[*] Generating SQL migration...")
    generator = SQLGenerator(plugin_data)
    sql = generator.generate()

    # Output or apply
    if args.apply:
        print("[*] Applying migration to database...")
        apply_to_database(sql, args.db_path)
    else:
        # Determine output path
        if args.output:
            output_path = args.output
        else:
            output_path = Path('db/migrations') / f"{plugin_data['plugin_name']}_commands.sql"

        # Create directory if needed
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Write SQL file
        with open(output_path, 'w') as f:
            f.write(sql)

        print(f"[+] Migration written to {output_path}")
        print(f"\nTo apply:")
        print(f"  sqlite3 ~/.crack/crack.db < {output_path}")
        print(f"  OR")
        print(f"  python3 {__file__} {args.plugin_file} --apply")

    return 0


if __name__ == '__main__':
    exit(main())
