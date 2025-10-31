"""
Command Repository - Database access layer for command operations

Provides methods for:
- Finding commands by ID, service, tag, category
- Retrieving command metadata (flags, variables, relationships)
- Interactive variable substitution
- Alternative command lookup
"""

import psycopg2
import psycopg2.extras
import json
from typing import List, Optional, Dict, Any
from pathlib import Path
from ..config import get_db_config


class CommandRepository:
    """Repository for command queries and operations"""

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

    def find_by_id(self, command_id: str) -> Optional[Dict[str, Any]]:
        """
        Get command with all metadata (flags, variables, tags, relationships)

        Args:
            command_id: Command identifier (e.g., 'nmap-quick-scan')

        Returns:
            Dict with command data or None if not found

        Example:
            >>> repo = CommandRepository()
            >>> cmd = repo.find_by_id('nmap-quick-scan')
            >>> print(cmd['name'])
            'Quick Full Port Scan'
        """
        conn = self._get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # Get base command
        cursor.execute("SELECT * FROM commands WHERE id = %s", (command_id,))
        row = cursor.fetchone()
        if not row:
            return None

        command = dict(row)

        # Get flags
        cursor.execute("""
            SELECT flag, explanation, is_required
            FROM command_flags
            WHERE command_id = %s
            ORDER BY flag
        """, (command_id,))
        command['flags'] = [dict(r) for r in cursor.fetchall()]

        # Get variables
        cursor.execute("""
            SELECT v.name, v.description, v.data_type, v.default_value,
                   cv.is_required, cv.example_value, cv.position
            FROM command_vars cv
            JOIN variables v ON cv.variable_id = v.id
            WHERE cv.command_id = %s
            ORDER BY cv.position
        """, (command_id,))
        command['variables'] = [dict(r) for r in cursor.fetchall()]

        # Get tags
        cursor.execute("""
            SELECT t.name, t.category, t.description, t.color
            FROM command_tags ct
            JOIN tags t ON ct.tag_id = t.id
            WHERE ct.command_id = %s
            ORDER BY t.name
        """, (command_id,))
        command['tags'] = [dict(r) for r in cursor.fetchall()]

        # Get success indicators
        cursor.execute("""
            SELECT pattern, pattern_type, description
            FROM command_indicators
            WHERE command_id = %s AND indicator_type = 'success'
            ORDER BY priority
        """, (command_id,))
        command['success_indicators'] = [dict(r) for r in cursor.fetchall()]

        # Get failure indicators
        cursor.execute("""
            SELECT pattern, pattern_type, description
            FROM command_indicators
            WHERE command_id = %s AND indicator_type = 'failure'
            ORDER BY priority
        """, (command_id,))
        command['failure_indicators'] = [dict(r) for r in cursor.fetchall()]

        conn.close()
        return command

    def find_by_service(self, service_name: str, oscp_only: bool = False) -> List[Dict[str, Any]]:
        """
        Get all commands for a service, ordered by priority

        Args:
            service_name: Service name (e.g., 'http', 'smb')
            oscp_only: If True, only return high-relevance OSCP commands

        Returns:
            List of command dicts with priority information

        Example:
            >>> repo = CommandRepository()
            >>> cmds = repo.find_by_service('http', oscp_only=True)
            >>> for cmd in cmds:
            ...     print(f"{cmd['priority']}: {cmd['name']}")
        """
        conn = self._get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        query = """
            SELECT c.id, c.name, c.command_template, c.description,
                   c.oscp_relevance, sc.priority, sc.context
            FROM commands c
            JOIN service_commands sc ON c.id = sc.command_id
            JOIN services s ON sc.service_id = s.id
            WHERE s.name = %s
        """
        params = [service_name]

        if oscp_only:
            query += " AND c.oscp_relevance = 'high'"

        query += " ORDER BY sc.priority ASC"

        cursor.execute(query, params)
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results

    def find_alternatives(self, command_id: str) -> List[Dict[str, Any]]:
        """
        Get alternative commands if primary fails

        Args:
            command_id: Primary command ID

        Returns:
            List of alternative commands ordered by priority

        Example:
            >>> repo = CommandRepository()
            >>> alts = repo.find_alternatives('gobuster-dir')
            >>> for alt in alts:
            ...     print(f"{alt['name']}: {alt['notes']}")
        """
        conn = self._get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        cursor.execute("""
            SELECT c.id, c.name, c.command_template, c.description,
                   cr.notes, cr.priority
            FROM command_relations cr
            JOIN commands c ON cr.target_command_id = c.id
            WHERE cr.source_command_id = %s AND cr.relation_type = 'alternative'
            ORDER BY cr.priority ASC
        """, (command_id,))

        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results

    def find_prerequisites(self, command_id: str) -> List[Dict[str, Any]]:
        """
        Get commands that should be run before this one

        Args:
            command_id: Command ID

        Returns:
            List of prerequisite commands
        """
        conn = self._get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        cursor.execute("""
            SELECT c.id, c.name, c.command_template, c.description,
                   cr.notes, cr.condition
            FROM command_relations cr
            JOIN commands c ON cr.target_command_id = c.id
            WHERE cr.source_command_id = %s AND cr.relation_type = 'prerequisite'
            ORDER BY cr.priority ASC
        """, (command_id,))

        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results

    def find_next_steps(self, command_id: str) -> List[Dict[str, Any]]:
        """
        Get commands that should be run after this one succeeds

        Args:
            command_id: Command ID

        Returns:
            List of next-step commands
        """
        conn = self._get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        cursor.execute("""
            SELECT c.id, c.name, c.command_template, c.description,
                   cr.notes, cr.condition
            FROM command_relations cr
            JOIN commands c ON cr.target_command_id = c.id
            WHERE cr.source_command_id = %s AND cr.relation_type = 'next_step'
            ORDER BY cr.priority ASC
        """, (command_id,))

        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results

    def search_by_tags(self, tags: List[str], match_all: bool = True) -> List[Dict[str, Any]]:
        """
        Search commands by tags

        Args:
            tags: List of tag names
            match_all: If True, command must have ALL tags. If False, ANY tag.

        Returns:
            List of matching commands

        Example:
            >>> repo = CommandRepository()
            >>> cmds = repo.search_by_tags(['OSCP:HIGH', 'ENUM'], match_all=True)
        """
        conn = self._get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        placeholders = ','.join(['%s'] * len(tags))

        if match_all:
            # Must have ALL tags
            query = f"""
                SELECT DISTINCT c.id, c.name, c.command_template, c.description, c.oscp_relevance
                FROM commands c
                JOIN command_tags ct ON c.id = ct.command_id
                JOIN tags t ON ct.tag_id = t.id
                WHERE t.name IN ({placeholders})
                GROUP BY c.id, c.name, c.command_template, c.description, c.oscp_relevance
                HAVING COUNT(DISTINCT t.name) = %s
            """
            cursor.execute(query, tags + [len(tags)])
        else:
            # Must have ANY tag
            query = f"""
                SELECT DISTINCT c.id, c.name, c.command_template, c.description, c.oscp_relevance
                FROM commands c
                JOIN command_tags ct ON c.id = ct.command_id
                JOIN tags t ON ct.tag_id = t.id
                WHERE t.name IN ({placeholders})
            """
            cursor.execute(query, tags)

        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results

    def search_by_category(self, category: str, subcategory: str = None) -> List[Dict[str, Any]]:
        """
        Search commands by category

        Args:
            category: Main category (recon, web, exploitation, etc.)
            subcategory: Optional subcategory filter

        Returns:
            List of matching commands
        """
        conn = self._get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        if subcategory:
            cursor.execute("""
                SELECT id, name, command_template, description, oscp_relevance
                FROM commands
                WHERE category = %s AND subcategory = %s
                ORDER BY oscp_relevance DESC, name
            """, (category, subcategory))
        else:
            cursor.execute("""
                SELECT id, name, command_template, description, oscp_relevance
                FROM commands
                WHERE category = %s
                ORDER BY oscp_relevance DESC, name
            """, (category,))

        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results

    def interactive_fill(self, command_id: str, config: Dict[str, str] = None) -> str:
        """
        Fill placeholders with values (priority: config > example > default > prompt)

        Args:
            command_id: Command ID to fill
            config: Dict of variable values from config file

        Returns:
            Command string with all variables substituted

        Example:
            >>> repo = CommandRepository()
            >>> config = {'<TARGET>': '192.168.1.100', '<LHOST>': '192.168.45.200'}
            >>> filled = repo.interactive_fill('nmap-quick-scan', config)
            >>> print(filled)
            'nmap -Pn -p- --min-rate=1000 192.168.1.100 -oA scan_results'
        """
        if config is None:
            config = {}

        command = self.find_by_id(command_id)
        if not command:
            raise ValueError(f"Command '{command_id}' not found")

        template = command['command_template']

        # Process each variable in order
        for var in command['variables']:
            var_name = var['name']
            value = None

            # Priority 1: Config
            if var_name in config:
                value = config[var_name]
            # Priority 2: Example value
            elif var['example_value']:
                value = var['example_value']
            # Priority 3: Default value
            elif var['default_value']:
                value = var['default_value']
            # Priority 4: Prompt user
            else:
                if var['is_required']:
                    value = input(f"Enter {var_name} ({var['description']}): ")
                else:
                    value = input(f"Enter {var_name} (optional, {var['description']}): ") or ""

            # Substitute
            template = template.replace(var_name, str(value))

        return template

    def get_all_commands(self, oscp_only: bool = False) -> List[Dict[str, Any]]:
        """
        Get all commands in database

        Args:
            oscp_only: If True, only return high-relevance OSCP commands

        Returns:
            List of all commands
        """
        conn = self._get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        query = """
            SELECT id, name, command_template, description, category, oscp_relevance
            FROM commands
        """

        if oscp_only:
            query += " WHERE oscp_relevance = 'high'"

        query += " ORDER BY category, name"

        cursor.execute(query)
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results

    def count_commands(self) -> int:
        """Get total number of commands in database"""
        conn = self._get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute("SELECT COUNT(*) as count FROM commands")
        count = cursor.fetchone()['count']
        conn.close()
        return count
