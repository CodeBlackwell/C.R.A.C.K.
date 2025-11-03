"""
PostgreSQL connection configuration for CRACK database

Provides centralized database configuration with environment variable support
"""
import os
from typing import Dict, Optional


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
