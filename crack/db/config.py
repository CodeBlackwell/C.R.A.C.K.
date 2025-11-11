"""
Database connection configuration for CRACK dual-backend system

Provides centralized configuration for both PostgreSQL and Neo4j
with environment variable support for flexible deployment
"""
import os
import logging
from dataclasses import dataclass, field
from typing import Dict, Optional, Any

logger = logging.getLogger(__name__)


@dataclass
class RouterConfig:
    """
    Router configuration for intelligent backend selection

    Centralizes router behavior configuration including backend preferences,
    fallback settings, and query complexity thresholds.
    """
    backend_preference: str = 'auto'  # 'auto', 'neo4j', 'sql', 'json'
    enable_fallback: bool = True
    graph_query_depth_threshold: int = 2  # Depth at which to prefer Neo4j
    connection_timeout: int = 5  # Seconds to wait for backend connection
    max_retries: int = 3
    cache_enabled: bool = True
    cache_ttl: int = 300  # Cache time-to-live in seconds

    @classmethod
    def from_env(cls) -> 'RouterConfig':
        """
        Load router configuration from environment variables

        Environment variables:
            CRACK_ROUTER_BACKEND - Backend preference (auto/neo4j/sql/json)
            CRACK_ROUTER_FALLBACK - Enable fallback (true/false)
            CRACK_ROUTER_GRAPH_THRESHOLD - Depth threshold for Neo4j (default: 2)
            CRACK_ROUTER_TIMEOUT - Connection timeout seconds (default: 5)
            CRACK_ROUTER_RETRIES - Max retry attempts (default: 3)
            CRACK_ROUTER_CACHE - Enable caching (true/false)
            CRACK_ROUTER_CACHE_TTL - Cache TTL seconds (default: 300)

        Returns:
            RouterConfig instance
        """
        return cls(
            backend_preference=os.getenv('CRACK_ROUTER_BACKEND', 'auto'),
            enable_fallback=os.getenv('CRACK_ROUTER_FALLBACK', 'true').lower() == 'true',
            graph_query_depth_threshold=int(os.getenv('CRACK_ROUTER_GRAPH_THRESHOLD', '2')),
            connection_timeout=int(os.getenv('CRACK_ROUTER_TIMEOUT', '5')),
            max_retries=int(os.getenv('CRACK_ROUTER_RETRIES', '3')),
            cache_enabled=os.getenv('CRACK_ROUTER_CACHE', 'true').lower() == 'true',
            cache_ttl=int(os.getenv('CRACK_ROUTER_CACHE_TTL', '300'))
        )


@dataclass
class ImportConfig:
    """
    Configuration for Neo4j CSV import operations

    Centralizes batch sizes, timeouts, and retry logic for data migration.
    """
    batch_size: int = 1000
    max_retries: int = 3
    retry_delay: int = 2  # Seconds between retries
    connection_timeout: int = 30
    transaction_timeout: int = 120  # Seconds for long-running imports
    validation_enabled: bool = True
    skip_on_error: bool = False  # Continue import even if some batches fail
    verbose: bool = False

    @classmethod
    def from_env(cls) -> 'ImportConfig':
        """
        Load import configuration from environment variables

        Environment variables:
            NEO4J_IMPORT_BATCH_SIZE - Rows per transaction (default: 1000)
            NEO4J_IMPORT_RETRIES - Max retry attempts (default: 3)
            NEO4J_IMPORT_RETRY_DELAY - Seconds between retries (default: 2)
            NEO4J_IMPORT_TIMEOUT - Connection timeout (default: 30)
            NEO4J_IMPORT_TX_TIMEOUT - Transaction timeout (default: 120)
            NEO4J_IMPORT_VALIDATE - Enable validation (default: true)
            NEO4J_IMPORT_SKIP_ERRORS - Continue on errors (default: false)
            NEO4J_IMPORT_VERBOSE - Verbose output (default: false)

        Returns:
            ImportConfig instance
        """
        return cls(
            batch_size=int(os.getenv('NEO4J_IMPORT_BATCH_SIZE', '1000')),
            max_retries=int(os.getenv('NEO4J_IMPORT_RETRIES', '3')),
            retry_delay=int(os.getenv('NEO4J_IMPORT_RETRY_DELAY', '2')),
            connection_timeout=int(os.getenv('NEO4J_IMPORT_TIMEOUT', '30')),
            transaction_timeout=int(os.getenv('NEO4J_IMPORT_TX_TIMEOUT', '120')),
            validation_enabled=os.getenv('NEO4J_IMPORT_VALIDATE', 'true').lower() == 'true',
            skip_on_error=os.getenv('NEO4J_IMPORT_SKIP_ERRORS', 'false').lower() == 'true',
            verbose=os.getenv('NEO4J_IMPORT_VERBOSE', 'false').lower() == 'true'
        )


@dataclass
class Neo4jConfig:
    """
    Neo4j connection configuration with validation

    Centralizes all Neo4j configuration parameters and provides validation.
    Eliminates magic numbers and hardcoded values throughout the codebase.
    """
    uri: str
    user: str
    password: str
    database: str = 'neo4j'
    max_connection_lifetime: int = 3600
    max_connection_pool_size: int = 50
    connection_acquisition_timeout: int = 60
    max_retries: int = 3
    search_result_limit: int = 50
    encrypted: bool = False

    # Development default (logged with warning)
    DEV_DEFAULT_PASSWORD: str = field(default='Neo4j123', repr=False, init=False)

    @classmethod
    def from_env(cls, require_password: bool = False) -> 'Neo4jConfig':
        """
        Load Neo4j configuration from environment variables

        Args:
            require_password: If True, raises ValueError when NEO4J_PASSWORD not set

        Returns:
            Neo4jConfig instance

        Raises:
            ValueError: If require_password=True and NEO4J_PASSWORD not set

        Environment variables:
            NEO4J_URI - Bolt connection URI (default: bolt://localhost:7687)
            NEO4J_USER - Neo4j username (default: neo4j)
            NEO4J_PASSWORD - Neo4j password (REQUIRED for production)
            NEO4J_DATABASE - Database name (default: neo4j)
            NEO4J_MAX_LIFETIME - Max connection lifetime seconds (default: 3600)
            NEO4J_MAX_POOL_SIZE - Max connection pool size (default: 50)
            NEO4J_CONNECTION_TIMEOUT - Connection timeout seconds (default: 60)
            NEO4J_MAX_RETRIES - Max retry attempts (default: 3)
            NEO4J_SEARCH_LIMIT - Search result limit (default: 50)
            NEO4J_ENCRYPTED - Use encrypted connection (default: false)

        Example:
            >>> # Production (requires NEO4J_PASSWORD)
            >>> config = Neo4jConfig.from_env(require_password=True)

            >>> # Development (allows default password with warning)
            >>> config = Neo4jConfig.from_env()
        """
        password = os.getenv('NEO4J_PASSWORD')
        config = cls(
            uri=os.getenv('NEO4J_URI', 'bolt://localhost:7687'),
            user=os.getenv('NEO4J_USER', 'neo4j'),
            password='',  # Set below with validation
            database=os.getenv('NEO4J_DATABASE', 'neo4j'),
            max_connection_lifetime=int(os.getenv('NEO4J_MAX_LIFETIME', '3600')),
            max_connection_pool_size=int(os.getenv('NEO4J_MAX_POOL_SIZE', '50')),
            connection_acquisition_timeout=int(os.getenv('NEO4J_CONNECTION_TIMEOUT', '60')),
            max_retries=int(os.getenv('NEO4J_MAX_RETRIES', '3')),
            search_result_limit=int(os.getenv('NEO4J_SEARCH_LIMIT', '50')),
            encrypted=os.getenv('NEO4J_ENCRYPTED', 'false').lower() == 'true'
        )

        # Handle password with validation and warning
        if not password:
            if require_password:
                raise ValueError(
                    "NEO4J_PASSWORD environment variable is required for production. "
                    "Set via: export NEO4J_PASSWORD='your_password'"
                )
            else:
                # Use development default with warning
                config.password = config.DEV_DEFAULT_PASSWORD
                logger.warning(
                    "Using default Neo4j password for development. "
                    "For production, set NEO4J_PASSWORD environment variable. "
                    f"Current default: {config.DEV_DEFAULT_PASSWORD[:3]}***"
                )
        else:
            config.password = password

        return config

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert config to dict for compatibility with dict-based code

        Returns:
            Dict with connection parameters (compatible with GraphDatabase.driver)
        """
        return {
            'uri': self.uri,
            'user': self.user,
            'password': self.password,
            'database': self.database,
            'max_connection_lifetime': self.max_connection_lifetime,
            'max_connection_pool_size': self.max_connection_pool_size,
            'connection_acquisition_timeout': self.connection_acquisition_timeout,
            'encrypted': self.encrypted
        }


def get_neo4j_config() -> Dict[str, Any]:
    """
    Get Neo4j connection parameters (legacy dict interface)

    DEPRECATED: Use Neo4jConfig.from_env() instead for better type safety
    and configuration management.

    Returns:
        Dict with connection parameters

    Environment variables (optional overrides):
        NEO4J_URI - Bolt connection URI (default: bolt://localhost:7687)
        NEO4J_USER - Neo4j username (default: neo4j)
        NEO4J_PASSWORD - Neo4j password (default: Neo4j123 with warning)
        NEO4J_DATABASE - Database name (default: neo4j)
        NEO4J_MAX_POOL_SIZE - Max connection pool size (default: 50)
        NEO4J_CONNECTION_TIMEOUT - Connection timeout in seconds (default: 60)

    Example:
        >>> from neo4j import GraphDatabase
        >>> config = get_neo4j_config()
        >>> driver = GraphDatabase.driver(
        ...     config['uri'],
        ...     auth=(config['user'], config['password']),
        ...     max_connection_lifetime=config['max_connection_lifetime']
        ... )
    """
    # Use Neo4jConfig for consistency and warning
    config = Neo4jConfig.from_env()
    return config.to_dict()


def validate_neo4j_connection(config: Optional[Dict[str, Any]] = None) -> bool:
    """
    Test Neo4j connection with given config

    Args:
        config: Optional config dict (uses get_neo4j_config() if None)

    Returns:
        True if connection successful, False otherwise

    Example:
        >>> if validate_neo4j_connection():
        ...     print("Neo4j connection OK")
    """
    if config is None:
        config = get_neo4j_config()

    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(
            config['uri'],
            auth=(config['user'], config['password']),
            max_connection_lifetime=config['max_connection_lifetime'],
            max_connection_pool_size=config['max_connection_pool_size'],
            connection_acquisition_timeout=config['connection_acquisition_timeout'],
            encrypted=config['encrypted']
        )

        with driver.session(database=config['database']) as session:
            result = session.run("RETURN 1 AS test")
            assert result.single()['test'] == 1

        driver.close()
        return True
    except Exception as e:
        print(f"Neo4j connection validation failed: {e}")
        return False
