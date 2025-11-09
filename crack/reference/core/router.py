"""
Command Registry Router - Intelligent Backend Selection

Routes queries to PostgreSQL or Neo4j based on query type:
- Simple lookups → PostgreSQL (faster for indexed queries)
- Graph traversals → Neo4j (10x+ faster for multi-hop)
- Automatic fallback to PostgreSQL if Neo4j unavailable
"""

import logging
from typing import List, Dict, Optional, Any, TypeVar
from enum import Enum

from .registry import Command, CommandVariable

logger = logging.getLogger(__name__)


class BackendType(Enum):
    """Backend selection strategy"""
    POSTGRESQL = "postgresql"
    NEO4J = "neo4j"
    JSON = "json"
    AUTO = "auto"


class QueryComplexity(Enum):
    """Query complexity classification"""
    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"


class CommandRegistryRouter:
    """
    Dual-backend router with intelligent query routing

    Decision Matrix:
    - get_command() → Always PostgreSQL (indexed)
    - search() → PostgreSQL (full-text index)
    - find_alternatives(depth=1) → PostgreSQL (single JOIN)
    - find_alternatives(depth≥2) → Neo4j (graph traversal)
    - get_attack_chain_path() → Neo4j (complex dependencies)
    """

    def __init__(
        self,
        config_manager=None,
        theme=None,
        backend_preference: BackendType = BackendType.AUTO,
        enable_fallback: bool = True
    ):
        """
        Initialize router with backend auto-detection

        Args:
            config_manager: ConfigManager instance
            theme: ReferenceTheme instance
            backend_preference: Preferred backend (default: AUTO)
            enable_fallback: Enable fallback on error (default: True)
        """
        self.config_manager = config_manager
        self.theme = theme
        self.backend_preference = backend_preference
        self.enable_fallback = enable_fallback

        if self.theme is None:
            from .colors import ReferenceTheme
            self.theme = ReferenceTheme()

        # Initialize backends
        self.neo4j_adapter = None
        self.pg_adapter = None
        self.json_adapter = None

        self.neo4j_available = False
        self.pg_available = False
        self.json_available = False

        # Try Neo4j first (best for graph queries)
        self._initialize_neo4j()

        # Try PostgreSQL (best for simple queries)
        self._initialize_postgresql()

        # JSON fallback (always available)
        self._initialize_json()

        # Validate at least one backend is available
        if not (self.neo4j_available or self.pg_available or self.json_available):
            raise RuntimeError("No database backends available")

        self._log_backend_status()

    def _initialize_neo4j(self):
        """Initialize Neo4j adapter if available"""
        try:
            from .neo4j_adapter import Neo4jCommandRegistryAdapter, Neo4jConnectionError

            self.neo4j_adapter = Neo4jCommandRegistryAdapter(
                config_manager=self.config_manager,
                theme=self.theme
            )

            # Test health
            if self.neo4j_adapter.health_check():
                self.neo4j_available = True
                logger.info("Neo4j backend initialized successfully")
            else:
                logger.warning("Neo4j connection failed health check")
                self.neo4j_adapter = None

        except Neo4jConnectionError as e:
            logger.debug(f"Neo4j unavailable: {e}")
        except ImportError:
            logger.debug("Neo4j adapter not available (neo4j package not installed)")
        except Exception as e:
            logger.debug(f"Neo4j initialization failed: {e}")

    def _initialize_postgresql(self):
        """Initialize PostgreSQL adapter if available"""
        try:
            from .sql_adapter import SQLCommandRegistryAdapter
            from db.config import get_db_config
            import psycopg2

            db_config = get_db_config()
            self.pg_adapter = SQLCommandRegistryAdapter(
                db_config=db_config,
                config_manager=self.config_manager,
                theme=self.theme
            )

            # Test health
            if self.pg_adapter.health_check():
                self.pg_available = True
                logger.info("PostgreSQL backend initialized successfully")
            else:
                logger.warning("PostgreSQL connection failed health check")
                self.pg_adapter = None

        except ImportError:
            logger.debug("PostgreSQL adapter not available (psycopg2 not installed)")
        except Exception as e:
            logger.debug(f"PostgreSQL initialization failed: {e}")

    def _initialize_json(self):
        """Initialize JSON fallback (always available)"""
        try:
            from .registry import HybridCommandRegistry

            self.json_adapter = HybridCommandRegistry(
                config_manager=self.config_manager,
                theme=self.theme
            )
            self.json_available = True
            logger.info("JSON backend initialized successfully")

        except Exception as e:
            logger.error(f"JSON initialization failed: {e}")

    def _log_backend_status(self):
        """Log which backends are available"""
        backends = []
        if self.neo4j_available:
            backends.append("Neo4j")
        if self.pg_available:
            backends.append("PostgreSQL")
        if self.json_available:
            backends.append("JSON")

        logger.info(f"Available backends: {', '.join(backends)}")

    def _select_backend(self, operation: str, **kwargs):
        """
        Select optimal backend for operation

        Args:
            operation: Operation name (e.g., 'find_alternatives')
            **kwargs: Operation parameters (e.g., depth=3)

        Returns:
            Backend adapter instance
        """
        complexity = self._assess_query_complexity(operation, **kwargs)

        # Graph operations prefer Neo4j
        is_graph_operation = operation in [
            'find_alternatives',
            'find_prerequisites',
            'get_attack_chain_path'
        ]

        if complexity == QueryComplexity.COMPLEX and is_graph_operation:
            # Prefer Neo4j for complex graph queries
            if self.neo4j_available:
                return self.neo4j_adapter
            elif self.pg_available:
                logger.debug(f"Neo4j unavailable, using PostgreSQL for {operation}")
                return self.pg_adapter
            else:
                return self.json_adapter

        # Simple queries prefer PostgreSQL
        elif complexity in [QueryComplexity.SIMPLE, QueryComplexity.MODERATE]:
            if self.pg_available:
                return self.pg_adapter
            elif self.neo4j_available:
                return self.neo4j_adapter
            else:
                return self.json_adapter

        # Default to first available
        return self._get_primary_backend()

    def _assess_query_complexity(self, query_type: str, **params) -> QueryComplexity:
        """
        Classify query complexity to guide backend selection

        Rules:
        - Single node lookup: SIMPLE
        - 1-hop relationships: MODERATE
        - 2+ hop traversals: COMPLEX
        """
        if query_type == 'find_alternatives':
            depth = params.get('max_depth', 1)
            if depth == 1:
                return QueryComplexity.MODERATE
            else:
                return QueryComplexity.COMPLEX

        elif query_type == 'find_prerequisites':
            return QueryComplexity.COMPLEX

        elif query_type == 'get_attack_chain_path':
            return QueryComplexity.COMPLEX

        elif query_type == 'filter_by_tags':
            tag_count = len(params.get('tags', []))
            if tag_count <= 2:
                return QueryComplexity.SIMPLE
            else:
                return QueryComplexity.MODERATE

        elif query_type in ['get_command', 'search', 'filter_by_category']:
            return QueryComplexity.SIMPLE

        else:
            return QueryComplexity.MODERATE

    def _get_primary_backend(self):
        """Get primary backend (first available)"""
        if self.pg_available:
            return self.pg_adapter
        elif self.neo4j_available:
            return self.neo4j_adapter
        else:
            return self.json_adapter

    def _get_primary_backend_name(self) -> str:
        """Get name of primary backend"""
        if self.pg_available and self.neo4j_available:
            return "Router (PostgreSQL + Neo4j)"
        elif self.pg_available:
            return "PostgreSQL"
        elif self.neo4j_available:
            return "Neo4j"
        elif self.json_available:
            return "JSON"
        else:
            return "None"

    def _get_fallback_backend(self, failed_backend):
        """
        Get fallback backend after failure

        Args:
            failed_backend: Backend that failed

        Returns:
            Alternative backend or None
        """
        if failed_backend == self.neo4j_adapter:
            if self.pg_available:
                logger.info("Falling back from Neo4j to PostgreSQL")
                return self.pg_adapter
            elif self.json_available:
                logger.info("Falling back from Neo4j to JSON")
                return self.json_adapter

        elif failed_backend == self.pg_adapter:
            if self.neo4j_available:
                logger.info("Falling back from PostgreSQL to Neo4j")
                return self.neo4j_adapter
            elif self.json_available:
                logger.info("Falling back from PostgreSQL to JSON")
                return self.json_adapter

        elif failed_backend == self.json_adapter:
            # No fallback from JSON
            return None

        return None

    def _route_with_fallback(
        self,
        operation_name: str,
        method_name: str,
        default_return: Any,
        **params
    ) -> Any:
        """
        Generic routing with automatic fallback

        Eliminates 270+ lines of duplicate fallback code by providing
        a single implementation that all public methods delegate to.

        Args:
            operation_name: Name for backend selection (e.g., 'get_command')
            method_name: Method to call on backend (usually same as operation_name)
            default_return: Value to return on error (None, [], {}, etc.)
            **params: Parameters to pass to the backend method

        Returns:
            Result from backend or default_return on error

        Example:
            >>> # Old way (15 lines):
            >>> def get_command(self, command_id):
            ...     backend = self._select_backend('get_command', command_id=command_id)
            ...     try:
            ...         return backend.get_command(command_id)
            ...     except Exception as e:
            ...         logger.error(f"Error: {e}")
            ...         if self.enable_fallback:
            ...             fallback = self._get_fallback_backend(backend)
            ...             if fallback:
            ...                 return fallback.get_command(command_id)
            ...         return None

            >>> # New way (1 line):
            >>> def get_command(self, command_id):
            ...     return self._route_with_fallback('get_command', 'get_command', None, command_id=command_id)
        """
        # Select optimal backend for this operation
        backend = self._select_backend(operation_name, **params)

        try:
            # Get method from backend
            method = getattr(backend, method_name)
            return method(**params)

        except Exception as e:
            logger.error(f"Error in {operation_name}: {e}", exc_info=True)

            # Try fallback if enabled
            if not self.enable_fallback:
                return default_return

            fallback = self._get_fallback_backend(backend)
            if fallback and hasattr(fallback, method_name):
                try:
                    method = getattr(fallback, method_name)
                    return method(**params)
                except Exception as e2:
                    logger.error(f"Fallback also failed for {operation_name}: {e2}", exc_info=True)

            return default_return

    # ========================================================================
    # Simple Queries (PostgreSQL Preferred)
    # ========================================================================

    def get_command(self, command_id: str) -> Optional[Command]:
        """Get single command by ID with fallback"""
        return self._route_with_fallback('get_command', 'get_command', None, command_id=command_id)

    def search(
        self,
        query: str,
        category: Optional[str] = None,
        tags: Optional[List[str]] = None,
        oscp_only: bool = False
    ) -> List[Command]:
        """Search commands with fallback"""
        return self._route_with_fallback(
            'search', 'search', [],
            query=query, category=category, tags=tags, oscp_only=oscp_only
        )

    def filter_by_category(self, category: str, subcategory: str = None) -> List[Command]:
        """Filter by category with fallback"""
        return self._route_with_fallback(
            'filter_by_category', 'filter_by_category', [],
            category=category, subcategory=subcategory
        )

    def filter_by_tags(
        self,
        tags: List[str],
        match_all: bool = True
    ) -> List[Command]:
        """Filter by tags with fallback"""
        return self._route_with_fallback(
            'filter_by_tags', 'filter_by_tags', [],
            tags=tags, match_all=match_all
        )

    def get_quick_wins(self) -> List[Command]:
        """Get quick wins with fallback"""
        return self._route_with_fallback('get_quick_wins', 'get_quick_wins', [])

    def get_oscp_high(self) -> List[Command]:
        """Get OSCP high priority commands with fallback"""
        return self._route_with_fallback('get_oscp_high', 'get_oscp_high', [])

    # ========================================================================
    # Graph Queries (Neo4j Preferred)
    # ========================================================================

    def find_alternatives(
        self,
        command_id: str,
        max_depth: int = 3
    ) -> List:
        """Find alternative commands with fallback"""
        return self._route_with_fallback(
            'find_alternatives', 'find_alternatives', [],
            command_id=command_id, max_depth=max_depth
        )

    def find_prerequisites(self, command_id: str) -> List[Command]:
        """Find prerequisite commands with fallback"""
        return self._route_with_fallback(
            'find_prerequisites', 'find_prerequisites', [],
            command_id=command_id
        )

    def get_attack_chain_path(self, chain_id: str) -> Optional[Dict[str, Any]]:
        """Get attack chain path with fallback"""
        return self._route_with_fallback('get_attack_chain_path', 'get_attack_chain_path', None, chain_id=chain_id)

    # ========================================================================
    # Utility Methods
    # ========================================================================

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics from all backends"""
        stats = {
            'backends': {
                'neo4j': {
                    'available': self.neo4j_available,
                    'healthy': self.neo4j_adapter.health_check() if self.neo4j_available else False,
                    'stats': self.neo4j_adapter.get_stats() if self.neo4j_available else {}
                },
                'postgresql': {
                    'available': self.pg_available,
                    'healthy': self.pg_adapter.health_check() if self.pg_available else False,
                    'stats': self.pg_adapter.get_stats() if self.pg_available else {}
                },
                'json': {
                    'available': self.json_available
                }
            },
            'routing_mode': self.backend_preference.value,
            'active_backend': self._get_primary_backend_name()
        }
        return stats

    def health_check(self) -> Dict[str, Any]:
        """Check health of all backends"""
        return {
            'neo4j': {
                'available': self.neo4j_available,
                'healthy': self.neo4j_adapter.health_check() if self.neo4j_available else False
            },
            'sql': {
                'available': self.pg_available,
                'healthy': self.pg_adapter.health_check() if self.pg_available else False
            },
            'json': {
                'available': self.json_available
            },
            'active_backend': self._get_primary_backend_name()
        }

    def interactive_fill(self, command: Command) -> str:
        """Interactively fill command with fallback"""
        return self._route_with_fallback('interactive_fill', 'interactive_fill', '', command=command)

    def get_all_commands(self) -> List[Command]:
        """Get all commands with fallback"""
        return self._route_with_fallback('get_all_commands', 'get_all_commands', [])

    def get_subcategories(self, category: str) -> List[str]:
        """Get subcategories with fallback"""
        return self._route_with_fallback('get_subcategories', 'get_subcategories', [], category=category)

    @property
    def categories(self):
        """Get categories from primary backend"""
        backend = self._get_primary_backend()
        if hasattr(backend, 'categories'):
            return backend.categories
        return {}
