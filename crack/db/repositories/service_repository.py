"""
Service Repository - Database access layer for service operations

Provides methods for:
- Getting commands for detected services
- Service detection and matching
- Service alias resolution
"""

import psycopg2
import psycopg2.extras
from typing import List, Optional, Dict, Any
from pathlib import Path
from ..config import get_db_config


class ServiceRepository:
    """Repository for service queries and operations"""

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

    def get_commands_for_service(self, service_name: str, context: str = None, priority_order: bool = True) -> List[Dict[str, Any]]:
        """
        Get commands applicable to a service

        Args:
            service_name: Service name (e.g., 'http', 'smb')
            context: Optional context filter ('enumeration', 'exploitation', 'post-exploit')
            priority_order: If True, order by execution priority

        Returns:
            List of commands with metadata
        """
        conn = self._get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        query = """
            SELECT c.id, c.name, c.command_template, c.description,
                   sc.priority, sc.context, sc.required_confidence
            FROM service_commands sc
            JOIN commands c ON sc.command_id = c.id
            JOIN services s ON sc.service_id = s.id
            WHERE s.name = %s
        """
        params = [service_name]

        if context:
            query += " AND sc.context = %s"
            params.append(context)

        if priority_order:
            query += " ORDER BY sc.priority ASC"

        cursor.execute(query, params)
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results

    # Placeholder methods - to be implemented
    def detect_service(self, port: int, service_string: str) -> Optional[str]:
        """Detect service from port and service string"""
        # TODO: Implement service detection logic
        pass

    def resolve_alias(self, alias: str) -> Optional[str]:
        """Resolve service alias to canonical name"""
        # TODO: Implement alias resolution
        pass
