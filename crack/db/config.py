"""
Database connection configuration for CRACK dual-backend system

Provides centralized configuration for both PostgreSQL and Neo4j
with environment variable support for flexible deployment
"""
import os
from typing import Dict, Optional, Any


def get_db_config() -> Dict[str, any]:
    """
    Get PostgreSQL connection parameters

    Returns:
        Dict with connection parameters (host, port, database, user, password)

    Environment variables (optional overrides):
        CRACK_DB_HOST - Database host (default: localhost)
        CRACK_DB_PORT - Database port (default: 5432)
        CRACK_DB_NAME - Database name (default: crack)
        CRACK_DB_USER - Database user (default: crack_user)
        CRACK_DB_PASSWORD - Database password (default: crack_password)

    Example:
        >>> config = get_db_config()
        >>> conn = psycopg2.connect(**config)
    """
    return {
        'host': os.getenv('CRACK_DB_HOST', 'localhost'),
        'port': int(os.getenv('CRACK_DB_PORT', '5432')),
        'dbname': os.getenv('CRACK_DB_NAME', 'crack'),
        'user': os.getenv('CRACK_DB_USER', 'crack_user'),
        'password': os.getenv('CRACK_DB_PASSWORD', 'crack_pass')
    }


def get_connection_string() -> str:
    """
    Get PostgreSQL connection string (DSN format)

    Returns:
        Connection string in format: postgresql://user:pass@host:port/database

    Example:
        >>> dsn = get_connection_string()
        >>> conn = psycopg2.connect(dsn)
    """
    config = get_db_config()
    return (f"postgresql://{config['user']}:{config['password']}@"
            f"{config['host']}:{config['port']}/{config['dbname']}")


def validate_connection(config: Optional[Dict[str, any]] = None) -> bool:
    """
    Test database connection with given config

    Args:
        config: Optional config dict (uses get_db_config() if None)

    Returns:
        True if connection successful, False otherwise

    Example:
        >>> if validate_connection():
        ...     print("Database connection OK")
    """
    if config is None:
        config = get_db_config()

    try:
        import psycopg2
        conn = psycopg2.connect(**config)
        conn.close()
        return True
    except Exception as e:
        print(f"Connection validation failed: {e}")
        return False


def get_neo4j_config() -> Dict[str, Any]:
    """
    Get Neo4j connection parameters

    Returns:
        Dict with connection parameters (uri, user, password, database, pool settings)

    Environment variables (optional overrides):
        NEO4J_URI - Bolt connection URI (default: bolt://localhost:7687)
        NEO4J_USER - Neo4j username (default: neo4j)
        NEO4J_PASSWORD - Neo4j password (default: crack_password)
        NEO4J_DATABASE - Database name (default: neo4j, Community Edition only supports 'neo4j')
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
    return {
        'uri': os.getenv('NEO4J_URI', 'bolt://localhost:7687'),
        'user': os.getenv('NEO4J_USER', 'neo4j'),
        'password': os.getenv('NEO4J_PASSWORD', 'Afrodeeziak21'),
        'database': os.getenv('NEO4J_DATABASE', 'neo4j'),
        'max_connection_lifetime': int(os.getenv('NEO4J_MAX_LIFETIME', '3600')),
        'max_connection_pool_size': int(os.getenv('NEO4J_MAX_POOL_SIZE', '50')),
        'connection_acquisition_timeout': int(os.getenv('NEO4J_CONNECTION_TIMEOUT', '60')),
        'encrypted': os.getenv('NEO4J_ENCRYPTED', 'false').lower() == 'true',
    }


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
