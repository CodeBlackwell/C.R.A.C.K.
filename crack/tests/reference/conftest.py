#!/usr/bin/env python3
"""
Shared fixtures for Reference System tests
Includes fixtures for Neo4j, SQL, and Router testing
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, MagicMock


# ============================================================================
# Command Sample Data Fixtures
# ============================================================================

@pytest.fixture
def sample_command_data():
    """Sample command data for testing"""
    return {
        "id": "test-command",
        "name": "Test Command",
        "category": "test",
        "subcategory": "unit",
        "command": "echo <MESSAGE>",
        "description": "Test command for unit tests",
        "tags": ["OSCP:HIGH", "TEST"],
        "variables": [
            {
                "name": "<MESSAGE>",
                "description": "Message to echo",
                "example": "Hello World",
                "required": True
            }
        ],
        "flag_explanations": {
            "echo": "Print message to stdout"
        },
        "oscp_relevance": "high"
    }


@pytest.fixture
def sample_nmap_command():
    """Sample nmap command for testing"""
    return {
        "id": "nmap-quick-scan",
        "name": "Nmap Quick Scan",
        "category": "recon",
        "subcategory": "network",
        "command": "sudo nmap -sV -sC -Pn -v <TARGET>",
        "description": "Quick service version detection scan",
        "tags": ["OSCP:HIGH", "NMAP", "RECON"],
        "variables": [
            {
                "name": "<TARGET>",
                "description": "Target IP or hostname",
                "example": "192.168.45.100",
                "required": True
            }
        ],
        "flag_explanations": {
            "-sV": "Service version detection",
            "-sC": "Run default scripts",
            "-Pn": "Skip ping, assume host is up",
            "-v": "Verbose output"
        },
        "oscp_relevance": "high"
    }


@pytest.fixture
def sample_web_command():
    """Sample web enumeration command for testing"""
    return {
        "id": "gobuster-dir",
        "name": "Gobuster Directory Brute Force",
        "category": "web",
        "subcategory": "enumeration",
        "command": "gobuster dir -u http://<TARGET>:<PORT> -w <WORDLIST> -t <THREADS>",
        "description": "Directory and file brute forcing",
        "tags": ["OSCP:HIGH", "WEB", "ENUMERATION"],
        "variables": [
            {
                "name": "<TARGET>",
                "description": "Target IP or hostname",
                "example": "192.168.45.100",
                "required": True
            },
            {
                "name": "<PORT>",
                "description": "Web server port",
                "example": "80",
                "required": False
            },
            {
                "name": "<WORDLIST>",
                "description": "Wordlist file path",
                "example": "/usr/share/wordlists/dirb/common.txt",
                "required": True
            },
            {
                "name": "<THREADS>",
                "description": "Number of concurrent threads",
                "example": "50",
                "required": False
            }
        ],
        "alternatives": ["dirbuster", "ffuf-dir"],
        "oscp_relevance": "high"
    }


# ============================================================================
# Neo4j Test Fixtures
# ============================================================================

@pytest.fixture(scope="session")
def neo4j_test_config():
    """
    Neo4j configuration for testing

    Returns:
        Dict with Neo4j connection parameters
    """
    try:
        from db.config import get_neo4j_config
        return get_neo4j_config()
    except Exception:
        return {
            'uri': 'bolt://localhost:7687',
            'user': 'neo4j',
            'password': 'crack_password',
            'database': 'neo4j'
        }


@pytest.fixture(scope="session")
def neo4j_driver(neo4j_test_config):
    """
    Create Neo4j driver for testing

    Yields:
        Neo4j driver instance or skips if unavailable
    """
    try:
        from neo4j import GraphDatabase

        driver = GraphDatabase.driver(
            neo4j_test_config['uri'],
            auth=(neo4j_test_config['user'], neo4j_test_config['password'])
        )

        # Test connection
        with driver.session(database=neo4j_test_config.get('database', 'neo4j')) as session:
            session.run("RETURN 1").single()

        yield driver

        driver.close()
    except ImportError:
        pytest.skip("Neo4j driver not installed")
    except Exception as e:
        pytest.skip(f"Neo4j not available: {e}")


@pytest.fixture
def neo4j_test_session(neo4j_driver, neo4j_test_config):
    """
    Create Neo4j session for individual tests

    Yields:
        Neo4j session
    """
    with neo4j_driver.session(database=neo4j_test_config.get('database', 'neo4j')) as session:
        yield session


# ============================================================================
# SQL Test Fixtures
# ============================================================================

@pytest.fixture(scope="session")
def sql_test_db_path(tmp_path_factory):
    """
    Create temporary SQLite database for testing

    Returns:
        Path to test database
    """
    db_path = tmp_path_factory.mktemp("data") / "test_crack.db"
    return str(db_path)


@pytest.fixture
def sql_connection(sql_test_db_path):
    """
    Create SQL connection for testing

    Yields:
        Database connection (SQLite or PostgreSQL)
    """
    try:
        import sqlite3

        conn = sqlite3.connect(sql_test_db_path)
        conn.row_factory = sqlite3.Row

        yield conn

        conn.close()
    except Exception as e:
        pytest.skip(f"SQL connection failed: {e}")


# ============================================================================
# Adapter Test Fixtures
# ============================================================================

@pytest.fixture
def config_manager():
    """Create ConfigManager instance for testing"""
    from crack.reference.core import ConfigManager
    return ConfigManager()


@pytest.fixture
def reference_theme():
    """Create ReferenceTheme instance for testing"""
    from crack.reference.core import ReferenceTheme
    return ReferenceTheme()


@pytest.fixture
def mock_config_manager():
    """Create mock ConfigManager for testing without config file"""
    mock_config = MagicMock()
    mock_config.get.return_value = None
    mock_config.set.return_value = None
    return mock_config


# ============================================================================
# Known Test Data Fixtures
# ============================================================================

@pytest.fixture
def known_command_ids():
    """
    List of command IDs known to exist in test data

    Returns:
        List of command ID strings
    """
    return [
        'nmap-quick-scan',
        'nmap-full-scan',
        'gobuster-dir',
        'bash-reverse-shell',
        'linpeas-download',
        'ssh-authlog-poison'
    ]


@pytest.fixture
def known_categories():
    """
    List of categories that should exist

    Returns:
        List of category names
    """
    return [
        'recon',
        'web',
        'exploitation',
        'post-exploit',
        'enumeration',
        'pivoting',
        'file-transfer'
    ]


@pytest.fixture
def known_tags():
    """
    List of tags that should exist

    Returns:
        List of tag names
    """
    return [
        'OSCP:HIGH',
        'OSCP:MEDIUM',
        'OSCP:LOW',
        'QUICK_WIN',
        'WINDOWS',
        'LINUX',
        'WEB',
        'RECON'
    ]


@pytest.fixture
def known_attack_chains():
    """
    List of attack chain IDs that should exist

    Returns:
        List of attack chain ID strings
    """
    return [
        'linux-privesc-suid-basic',
        'linux-privesc-sudo',
        'web-sqli-exploitation'
    ]


# ============================================================================
# Mock Backend Fixtures
# ============================================================================

@pytest.fixture
def mock_neo4j_adapter():
    """
    Create mock Neo4j adapter for testing without database

    Returns:
        MagicMock configured as Neo4j adapter
    """
    from crack.reference.core import Command, CommandVariable

    mock_adapter = MagicMock()

    # Configure mock to return Command objects
    sample_cmd = Command(
        id='mock-command',
        name='Mock Command',
        category='test',
        command='echo <TEST>',
        description='Mock command for testing',
        variables=[
            CommandVariable('<TEST>', 'Test variable', 'value', True)
        ]
    )

    mock_adapter.get_command.return_value = sample_cmd
    mock_adapter.search.return_value = [sample_cmd]
    mock_adapter.filter_by_category.return_value = [sample_cmd]
    mock_adapter.filter_by_tags.return_value = [sample_cmd]
    mock_adapter.health_check.return_value = True
    mock_adapter.get_stats.return_value = {'command_count': 1}

    return mock_adapter


@pytest.fixture
def mock_sql_adapter():
    """
    Create mock SQL adapter for testing without database

    Returns:
        MagicMock configured as SQL adapter
    """
    from crack.reference.core import Command, CommandVariable

    mock_adapter = MagicMock()

    # Configure mock to return Command objects
    sample_cmd = Command(
        id='mock-sql-command',
        name='Mock SQL Command',
        category='test',
        command='echo <TEST>',
        description='Mock SQL command for testing',
        variables=[
            CommandVariable('<TEST>', 'Test variable', 'value', True)
        ]
    )

    mock_adapter.get_command.return_value = sample_cmd
    mock_adapter.search.return_value = [sample_cmd]
    mock_adapter.filter_by_category.return_value = [sample_cmd]
    mock_adapter.filter_by_tags.return_value = [sample_cmd]
    mock_adapter.health_check.return_value = True
    mock_adapter.get_stats.return_value = {'total_commands': 1}

    return mock_adapter


# ============================================================================
# Test Data Cleanup Fixtures
# ============================================================================

@pytest.fixture(autouse=True)
def cleanup_test_data():
    """
    Cleanup fixture that runs after each test

    Note: Does NOT clean up Neo4j or SQL data - only in-memory test state
    """
    yield

    # Add any cleanup logic here if needed
    # (e.g., clearing caches, resetting singletons)
    pass


# ============================================================================
# Pytest Configuration Hooks
# ============================================================================

def pytest_configure(config):
    """Register custom markers for reference tests"""
    config.addinivalue_line(
        "markers", "neo4j: tests that require Neo4j database"
    )
    config.addinivalue_line(
        "markers", "router: tests for router integration"
    )
    config.addinivalue_line(
        "markers", "validation: tests for data migration validation"
    )
    config.addinivalue_line(
        "markers", "slow: slow-running tests (>1 second)"
    )
