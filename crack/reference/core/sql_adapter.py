"""
SQL Adapter - Backwards-compatible adapter for CommandRepository

Provides a bridge between the SQL database (CommandRepository) and the existing
Command dataclass interface used by HybridCommandRegistry.

This adapter allows existing code to use the SQL backend without any modifications,
maintaining full backwards compatibility during the transition period.

Usage:
    # Drop-in replacement for HybridCommandRegistry
    from crack.reference.core.sql_adapter import SQLCommandRegistryAdapter

    registry = SQLCommandRegistryAdapter()
    cmd = registry.get_command('bash-reverse-shell')
    results = registry.search('nmap')
"""

from typing import List, Dict, Optional, Any
from pathlib import Path

# Import the Command and CommandVariable dataclasses
from .registry import Command, CommandVariable


class SQLCommandRegistryAdapter:
    """
    Adapter to make CommandRepository API-compatible with HybridCommandRegistry

    This class wraps the SQL-based CommandRepository and exposes the same
    interface as HybridCommandRegistry, allowing seamless migration.
    """

    def __init__(self, db_config: Dict[str, Any] = None, config_manager=None, theme=None):
        """
        Initialize adapter with SQL repository

        Args:
            db_config: PostgreSQL connection config (default: from get_db_config())
            config_manager: ConfigManager instance for placeholder values
            theme: ReferenceTheme instance for colorized output
        """
        from db.repositories import CommandRepository
        from db.config import get_db_config

        if db_config is None:
            db_config = get_db_config()

        self.repo = CommandRepository(db_config)
        self.config_manager = config_manager
        self.theme = theme

        if self.theme is None:
            from .colors import ReferenceTheme
            self.theme = ReferenceTheme()

        # API compatibility attributes (match HybridCommandRegistry)
        self.base_path = None  # SQL backend doesn't use file paths
        self.categories = {
            'recon': '01-recon',
            'web': '02-web',
            'exploitation': '03-exploitation',
            'post-exploit': '04-post-exploitation',
            'enumeration': '05-enumeration',
            'pivoting': '06-pivoting',
            'file-transfer': '07-file-transfer',
            'custom': 'custom'
        }
        self.subcategories = {}  # Populated dynamically from database
        self.commands = {}  # Not pre-loaded (query on demand for performance)

        # Cache for categories and subcategories
        self._categories_cache = None
        self._subcategories_cache = None

    def _to_command_dataclass(self, sql_result: Dict[str, Any]) -> Optional[Command]:
        """
        Convert SQL repository result to Command dataclass

        Args:
            sql_result: Dict returned from CommandRepository

        Returns:
            Command dataclass instance or None if input is None
        """
        if sql_result is None:
            return None

        # Convert variables from SQL format to CommandVariable dataclasses
        variables = []
        for var in sql_result.get('variables', []):
            variables.append(CommandVariable(
                name=var.get('name', ''),
                description=var.get('description', ''),
                example=var.get('example_value', ''),
                required=var.get('is_required', True)
            ))

        # Extract tag names from SQL tag objects
        tags = [tag.get('name', '') for tag in sql_result.get('tags', [])]

        # Convert flag_explanations from list format to dict
        flag_explanations = {}
        for flag in sql_result.get('flags', []):
            flag_explanations[flag.get('flag', '')] = flag.get('explanation', '')

        # Extract success/failure indicator patterns
        success_indicators = [
            ind.get('pattern', '')
            for ind in sql_result.get('success_indicators', [])
        ]
        failure_indicators = [
            ind.get('pattern', '')
            for ind in sql_result.get('failure_indicators', [])
        ]

        # Get relationship command IDs
        alternatives = [
            rel.get('target_command_id', '')
            for rel in sql_result.get('alternatives', [])
        ]
        prerequisites = [
            rel.get('source_command_id', '')
            for rel in sql_result.get('prerequisites', [])
        ]
        next_steps = [
            rel.get('target_command_id', '')
            for rel in sql_result.get('next_steps', [])
        ]

        # Build Command dataclass
        return Command(
            id=sql_result.get('id', ''),
            name=sql_result.get('name', ''),
            category=sql_result.get('category', 'custom'),
            command=sql_result.get('command_template', ''),
            description=sql_result.get('description', ''),
            subcategory=sql_result.get('subcategory', ''),
            tags=tags,
            variables=variables,
            flag_explanations=flag_explanations,
            success_indicators=success_indicators,
            failure_indicators=failure_indicators,
            next_steps=next_steps,
            alternatives=alternatives,
            prerequisites=prerequisites,
            troubleshooting={},  # SQL schema doesn't have this yet
            notes=sql_result.get('notes', ''),
            oscp_relevance=sql_result.get('oscp_relevance', 'medium')
        )

    def get_command(self, command_id: str) -> Optional[Command]:
        """
        Get command by ID (API-compatible with HybridCommandRegistry)

        Args:
            command_id: Command identifier

        Returns:
            Command dataclass or None if not found
        """
        sql_result = self.repo.find_by_id(command_id)
        return self._to_command_dataclass(sql_result)

    def search(
        self,
        query: str,
        category: Optional[str] = None,
        tags: Optional[List[str]] = None,
        oscp_only: bool = False
    ) -> List[Command]:
        """
        Search commands by query (API-compatible with HybridCommandRegistry)

        Args:
            query: Search query string
            category: Optional category filter
            tags: Optional tag filter
            oscp_only: Filter to high OSCP relevance only

        Returns:
            List of Command dataclasses matching query
        """
        # Use the SQL repository's search_by_tags method
        # Search in name, description, command text, and tags
        all_commands = self.repo.get_all_commands()

        results = []
        query_lower = query.lower()

        for cmd_dict in all_commands:
            # Convert to Command dataclass
            cmd = self._to_command_dataclass(cmd_dict)
            if not cmd:
                continue

            # Apply filters
            if category and cmd.category != category:
                continue

            if oscp_only and cmd.oscp_relevance != 'high':
                continue

            if tags:
                # Check if command has all tags
                cmd_tags_upper = [t.upper() for t in cmd.tags]
                if not all(tag.upper() in cmd_tags_upper for tag in tags):
                    continue

            if cmd.matches_search(query):
                results.append(cmd)

        # Sort by OSCP relevance (high first)
        relevance_order = {'high': 3, 'medium': 2, 'low': 1}
        return sorted(
            results,
            key=lambda x: relevance_order.get(x.oscp_relevance, 0),
            reverse=True
        )

    def filter_by_category(self, category: str, subcategory: str = None) -> List[Command]:
        """
        Get all commands in a category (API-compatible with HybridCommandRegistry)

        Args:
            category: Category name (e.g., 'web', 'recon')
            subcategory: Optional subcategory filter

        Returns:
            List of Command dataclasses in the category
        """
        sql_results = self.repo.search_by_category(category, subcategory)
        return [
            self._to_command_dataclass(cmd_dict)
            for cmd_dict in sql_results
        ]

    def get_subcategories(self, category: str) -> List[str]:
        """
        Get all subcategories for a category

        Args:
            category: Category name

        Returns:
            List of subcategory names
        """
        # Query database for unique subcategories in this category
        commands = self.filter_by_category(category)
        subcats = set()
        for cmd in commands:
            if cmd.subcategory:
                subcats.add(cmd.subcategory)
        return sorted(list(subcats))

    def filter_by_tags(
        self,
        tags: List[str],
        match_all: bool = True,
        exclude_tags: List[str] = None
    ) -> List[Command]:
        """
        Filter commands by tags (API-compatible with HybridCommandRegistry)

        Args:
            tags: List of tags to match (case-insensitive)
            match_all: If True, command must have ALL tags (AND), else ANY tag (OR)
            exclude_tags: Optional list of tags to exclude

        Returns:
            List of Command dataclasses with matching tags
        """
        # Use SQL repository's tag search
        sql_results = self.repo.search_by_tags(tags, match_all=match_all)
        commands = [
            self._to_command_dataclass(cmd_dict)
            for cmd_dict in sql_results
        ]

        # Apply exclusion filter if provided
        if exclude_tags:
            exclude_tags_upper = [tag.upper() for tag in exclude_tags]
            commands = [
                cmd for cmd in commands
                if not any(tag.upper() in exclude_tags_upper for tag in cmd.tags)
            ]

        return commands

    def get_quick_wins(self) -> List[Command]:
        """
        Get commands tagged as quick wins

        Returns:
            List of Command dataclasses with QUICK_WIN tag
        """
        return self.filter_by_tags(['QUICK_WIN'])

    def get_oscp_high(self) -> List[Command]:
        """
        Get OSCP high-relevance commands

        Returns:
            List of high-priority OSCP commands
        """
        all_commands = self.repo.get_all_commands(oscp_only=True)
        return [
            self._to_command_dataclass(cmd_dict)
            for cmd_dict in all_commands
        ]

    def get_stats(self) -> Dict[str, Any]:
        """
        Get registry statistics (API-compatible with HybridCommandRegistry)

        Returns:
            Dict with statistics
        """
        # Get total count
        total = self.repo.count_commands()

        # Count by category
        categories = ['recon', 'web', 'exploitation', 'post-exploit',
                     'enumeration', 'pivoting', 'file-transfer', 'custom']
        by_category = {}
        by_subcategory = {}

        for cat in categories:
            cmds = self.filter_by_category(cat)
            by_category[cat] = len(cmds)

            # Get subcategories
            subcats = self.get_subcategories(cat)
            if subcats:
                by_subcategory[cat] = {}
                for subcat in subcats:
                    subcat_cmds = self.filter_by_category(cat, subcat)
                    by_subcategory[cat][subcat] = len(subcat_cmds)

        # Get tag counts
        all_commands = self.repo.get_all_commands()
        tag_counts = {}
        for cmd_dict in all_commands:
            for tag in cmd_dict.get('tags', []):
                tag_name = tag.get('name', '')
                tag_counts[tag_name] = tag_counts.get(tag_name, 0) + 1

        return {
            'total_commands': total,
            'by_category': by_category,
            'by_subcategory': by_subcategory,
            'top_tags': sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            'quick_wins': len(self.get_quick_wins()),
            'oscp_high': len(self.get_oscp_high())
        }

    def interactive_fill(self, command: Command) -> str:
        """
        Interactively fill command placeholders (API-compatible with HybridCommandRegistry)

        Args:
            command: Command dataclass to fill

        Returns:
            Filled command string
        """
        values = {}
        placeholders = command.extract_placeholders()

        t = self.theme  # Shorthand

        # Header
        print(f"\n{t.primary('[*] Filling command:')} {t.command_name(command.name)}")
        print(f"{t.primary('[*] Command:')} {t.hint(command.command)}\n")

        # Pre-load config values if available
        config_values = {}
        if self.config_manager:
            config_values = self.config_manager.get_placeholder_values()

        try:
            for placeholder in placeholders:
                # Check if we have a config value for this placeholder
                config_value = config_values.get(placeholder, '')

                # Find variable definition
                var = next((v for v in command.variables if v.name == placeholder), None)

                if var:
                    # Build colorized prompt
                    prompt_parts = [
                        t.prompt("Enter value for"),
                        t.placeholder(placeholder)
                    ]
                    if var.description:
                        prompt_parts.append(t.hint(f"({var.description})"))
                    if var.example:
                        prompt_parts.append(t.hint(f"[e.g., {var.example}]"))
                    if config_value:
                        prompt_parts.append(t.hint(f"[config: {t.value(config_value)}]"))
                    if not var.required:
                        prompt_parts.append(t.hint("(optional)"))

                    prompt = " ".join(prompt_parts) + t.prompt(": ")
                    value = input(prompt).strip()

                    # Use config value if user just pressed enter and we have one
                    if not value and config_value:
                        value = config_value
                        print(f"  {t.success('✓')} Using configured value: {t.value(config_value)}")

                    if value or var.required:
                        values[placeholder] = value
                else:
                    # Placeholder not defined in variables
                    prompt_parts = [
                        t.prompt("Enter value for"),
                        t.placeholder(placeholder)
                    ]
                    if config_value:
                        prompt_parts.append(t.hint(f"[config: {t.value(config_value)}]"))

                    prompt = " ".join(prompt_parts) + t.prompt(": ")
                    value = input(prompt).strip()

                    # Use config value if user just pressed enter
                    if not value and config_value:
                        value = config_value
                        print(f"  {t.success('✓')} Using configured value: {t.value(config_value)}")

                    if value:
                        values[placeholder] = value

        except KeyboardInterrupt:
            print(f"\n{t.warning('[Cancelled by user]')}")
            return ""

        filled_command = command.fill_placeholders(values)
        print(f"\n{t.success('[+] Final command:')} {t.command_name(filled_command)}")
        return filled_command

    def add_command(self, command: Command):
        """
        Add a command to the registry

        Note: This is a stub for API compatibility. SQL insertion requires
        proper normalization and should use the migration script.

        Args:
            command: Command dataclass to add
        """
        raise NotImplementedError(
            "Adding commands to SQL backend not yet implemented. "
            "Use the migration script: python3 -m db.migrate commands"
        )

    def save_to_json(self, category: str = None):
        """
        Save commands to JSON files

        Note: This is a stub for API compatibility. SQL backend doesn't
        support exporting to JSON yet.

        Args:
            category: Optional category to save
        """
        raise NotImplementedError(
            "Exporting SQL commands to JSON not yet implemented. "
            "Use: sqlite3 ~/.crack/crack.db .dump"
        )

    def health_check(self) -> bool:
        """
        Test database connectivity

        Returns:
            True if connection successful, False otherwise
        """
        try:
            with self.repo.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                    return cur.fetchone()[0] == 1
        except:
            return False

    def get_all_commands(self) -> List[Command]:
        """
        Get all commands in registry

        Returns:
            List of all Command objects
        """
        all_commands = self.repo.get_all_commands()
        return [
            self._to_command_dataclass(cmd_dict)
            for cmd_dict in all_commands
        ]

    def validate_schema(self) -> List[str]:
        """
        Validate all commands against schema

        Returns:
            List of validation errors
        """
        errors = []
        all_commands = self.repo.get_all_commands()

        for cmd_dict in all_commands:
            cmd = self._to_command_dataclass(cmd_dict)
            if not cmd:
                continue

            # Check required fields
            if not cmd.id:
                errors.append("Command missing ID")
            if not cmd.command:
                errors.append(f"Command {cmd.id} missing command text")
            if not cmd.description:
                errors.append(f"Command {cmd.id} missing description")

            # Check placeholder consistency
            placeholders = cmd.extract_placeholders()
            var_names = [var.name for var in cmd.variables]

            for placeholder in placeholders:
                if placeholder not in var_names:
                    errors.append(
                        f"Command {cmd.id}: placeholder {placeholder} not defined in variables"
                    )

        return errors

    def find_alternatives(self, command_id: str, max_depth: int = 1) -> List[Command]:
        """
        Find alternative commands up to N hops using recursive CTE

        Args:
            command_id: Source command ID
            max_depth: Maximum traversal depth (default 1)

        Returns:
            List of alternative Command objects ordered by depth and name
        """
        if max_depth == 1:
            # Simple case: direct alternatives
            sql_results = self.repo.find_related_commands(command_id, 'alternative')
            return [self._to_command_dataclass(cmd_dict) for cmd_dict in sql_results]

        # Recursive CTE for multi-hop traversal
        query = """
        WITH RECURSIVE alternatives(command_id, alternative_id, depth) AS (
            SELECT source_command_id, target_command_id, 1
            FROM command_relations
            WHERE source_command_id = %s AND relation_type = 'alternative'

            UNION ALL

            SELECT a.command_id, cr.target_command_id, a.depth + 1
            FROM alternatives a
            JOIN command_relations cr ON a.alternative_id = cr.source_command_id
            WHERE cr.relation_type = 'alternative' AND a.depth < %s
        )
        SELECT DISTINCT c.* FROM commands c
        JOIN alternatives a ON c.id = a.alternative_id
        ORDER BY a.depth, c.name
        """

        try:
            with self.repo.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(query, (command_id, max_depth))
                    rows = cur.fetchall()

                    commands = []
                    for row in rows:
                        # Convert row to dict matching command structure
                        cmd_dict = {
                            'id': row[0],
                            'name': row[1],
                            'command_template': row[2],
                            'description': row[3],
                            'category': row[4],
                            'subcategory': row[5],
                            'notes': row[6],
                            'oscp_relevance': row[7]
                        }
                        # Fetch full command details with relationships
                        full_cmd = self.repo.find_by_id(cmd_dict['id'])
                        if full_cmd:
                            commands.append(self._to_command_dataclass(full_cmd))

                    return commands
        except Exception as e:
            print(f"Error in find_alternatives: {e}")
            return []

    def find_prerequisites(self, command_id: str, depth: int = 1) -> List[Command]:
        """
        Find prerequisite commands up to N hops using recursive CTE

        Args:
            command_id: Target command ID
            depth: Maximum traversal depth (default 1)

        Returns:
            List of prerequisite Command objects ordered by depth (deepest first)
        """
        if depth == 1:
            # Simple case: direct prerequisites
            sql_results = self.repo.find_related_commands(command_id, 'prerequisite')
            return [self._to_command_dataclass(cmd_dict) for cmd_dict in sql_results]

        # Recursive CTE for multi-hop traversal (reverse direction)
        query = """
        WITH RECURSIVE prerequisites(command_id, prerequisite_id, depth) AS (
            SELECT target_command_id, source_command_id, 1
            FROM command_relations
            WHERE target_command_id = %s AND relation_type = 'prerequisite'

            UNION ALL

            SELECT p.command_id, cr.source_command_id, p.depth + 1
            FROM prerequisites p
            JOIN command_relations cr ON p.prerequisite_id = cr.target_command_id
            WHERE cr.relation_type = 'prerequisite' AND p.depth < %s
        )
        SELECT DISTINCT c.*, p.depth FROM commands c
        JOIN prerequisites p ON c.id = p.prerequisite_id
        ORDER BY p.depth DESC, c.name
        """

        try:
            with self.repo.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(query, (command_id, depth))
                    rows = cur.fetchall()

                    commands = []
                    for row in rows:
                        # Convert row to dict matching command structure
                        cmd_dict = {
                            'id': row[0],
                            'name': row[1],
                            'command_template': row[2],
                            'description': row[3],
                            'category': row[4],
                            'subcategory': row[5],
                            'notes': row[6],
                            'oscp_relevance': row[7]
                        }
                        # Fetch full command details with relationships
                        full_cmd = self.repo.find_by_id(cmd_dict['id'])
                        if full_cmd:
                            commands.append(self._to_command_dataclass(full_cmd))

                    return commands
        except Exception as e:
            print(f"Error in find_prerequisites: {e}")
            return []

    def get_attack_chain_path(self, chain_id: str) -> Dict[str, Any]:
        """
        Get attack chain with ordered steps and command details

        Args:
            chain_id: Attack chain ID

        Returns:
            Dict with chain info, steps, and execution order
        """
        query_chain = """
        SELECT id, name, description, category, platform, difficulty,
               time_estimate, oscp_relevant, author, version
        FROM attack_chains
        WHERE id = %s
        """

        query_steps = """
        SELECT cs.id, cs.name, cs.step_order, cs.objective, cs.description,
               cs.evidence, cs.success_criteria, cs.failure_conditions,
               cs.command_id
        FROM chain_steps cs
        WHERE cs.chain_id = %s
        ORDER BY cs.step_order
        """

        query_dependencies = """
        SELECT source_step_id, target_step_id
        FROM step_dependencies
        WHERE source_step_id IN (
            SELECT id FROM chain_steps WHERE chain_id = %s
        )
        """

        try:
            with self.repo.get_connection() as conn:
                with conn.cursor() as cur:
                    # Get chain metadata
                    cur.execute(query_chain, (chain_id,))
                    chain_row = cur.fetchone()
                    if not chain_row:
                        return None

                    # Get steps
                    cur.execute(query_steps, (chain_id,))
                    step_rows = cur.fetchall()

                    # Get dependencies
                    cur.execute(query_dependencies, (chain_id,))
                    dep_rows = cur.fetchall()

                    # Build dependency map
                    dependencies = {}
                    for source_id, target_id in dep_rows:
                        if source_id not in dependencies:
                            dependencies[source_id] = []
                        dependencies[source_id].append(target_id)

                    # Build steps list
                    steps = []
                    for row in step_rows:
                        step_id, name, order, objective, description, evidence, success_criteria, failure_conditions, command_id = row

                        # Get command if specified
                        command = None
                        if command_id:
                            cmd_dict = self.repo.find_by_id(command_id)
                            if cmd_dict:
                                command = self._to_command_dataclass(cmd_dict)

                        steps.append({
                            'id': step_id,
                            'name': name,
                            'order': order,
                            'objective': objective,
                            'description': description,
                            'evidence': evidence,
                            'success_criteria': success_criteria,
                            'failure_conditions': failure_conditions,
                            'command': command,
                            'dependencies': dependencies.get(step_id, [])
                        })

                    return {
                        'id': chain_row[0],
                        'name': chain_row[1],
                        'description': chain_row[2],
                        'category': chain_row[3],
                        'platform': chain_row[4],
                        'difficulty': chain_row[5],
                        'time_estimate': chain_row[6],
                        'oscp_relevant': chain_row[7],
                        'author': chain_row[8],
                        'version': chain_row[9],
                        'steps': steps,
                        'execution_order': [s['id'] for s in sorted(steps, key=lambda x: x['order'])]
                    }

        except Exception as e:
            print(f"Error in get_attack_chain_path: {e}")
            return None


# Convenience functions for module-level access
def load_registry(db_path: str = None) -> SQLCommandRegistryAdapter:
    """
    Load the SQL-backed command registry

    Args:
        db_path: Optional path to SQLite database

    Returns:
        SQLCommandRegistryAdapter instance
    """
    return SQLCommandRegistryAdapter(db_path)


def quick_search(query: str, db_path: str = None) -> List[Command]:
    """
    Quick search without instantiating full adapter

    Args:
        query: Search query string
        db_path: Optional path to SQLite database

    Returns:
        List of matching Command dataclasses
    """
    adapter = SQLCommandRegistryAdapter(db_path)
    return adapter.search(query)
