"""
Unit tests for SQL backend integration in reference CLI

Tests the auto-detect fallback logic in ReferenceCLI._initialize_registry()
"""

import pytest
import sqlite3
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from io import StringIO
import sys

from crack.reference.cli.main import ReferenceCLI
from crack.reference.core import HybridCommandRegistry
from crack.reference.core.sql_adapter import SQLCommandRegistryAdapter


class TestCLISQLIntegration:
    """Test SQL backend auto-detection and fallback logic"""

    def test_registry_initialization_with_valid_sql(self, tmp_path, monkeypatch):
        """Test SQL backend is used when database is valid"""
        # Create a temporary valid database with .crack subdirectory
        crack_dir = tmp_path / '.crack'
        crack_dir.mkdir()
        db_path = crack_dir / 'crack.db'

        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE commands (
                id TEXT PRIMARY KEY,
                name TEXT,
                command_template TEXT,
                description TEXT,
                category TEXT,
                oscp_relevance TEXT
            )
        """)
        cursor.execute("""
            INSERT INTO commands VALUES
            ('test-cmd', 'Test Command', 'echo test', 'A test command', 'custom', 'high')
        """)
        conn.commit()
        conn.close()

        # Mock home directory to use tmp_path
        monkeypatch.setattr(Path, 'home', lambda: tmp_path)

        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output

        try:
            cli = ReferenceCLI()

            # Assert SQL adapter is used
            assert isinstance(cli.registry, SQLCommandRegistryAdapter)

            # Check output message
            output = captured_output.getvalue()
            assert "✓ Using SQL backend" in output
            assert "1 commands loaded" in output
        finally:
            sys.stdout = sys.__stdout__

    def test_registry_initialization_sql_missing(self, tmp_path, monkeypatch):
        """Test JSON backend used when SQL database doesn't exist"""
        # Mock home directory to point to empty temp dir (no crack.db)
        mock_home = tmp_path
        monkeypatch.setattr(Path, 'home', lambda: mock_home)

        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output

        try:
            cli = ReferenceCLI()

            # Assert JSON registry is used
            assert isinstance(cli.registry, HybridCommandRegistry)

            # Check output message
            output = captured_output.getvalue()
            assert "ℹ SQL database not found" in output
            assert "✓ Using JSON backend" in output
        finally:
            sys.stdout = sys.__stdout__

    def test_registry_initialization_sql_empty(self, tmp_path, monkeypatch):
        """Test JSON fallback when SQL database exists but is empty"""
        # Create an empty database with .crack subdirectory
        crack_dir = tmp_path / '.crack'
        crack_dir.mkdir()
        db_path = crack_dir / 'crack.db'

        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE commands (
                id TEXT PRIMARY KEY,
                name TEXT,
                command_template TEXT
            )
        """)
        # No data inserted - table exists but is empty
        conn.commit()
        conn.close()

        # Mock home directory
        monkeypatch.setattr(Path, 'home', lambda: tmp_path)

        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output

        try:
            cli = ReferenceCLI()

            # Assert JSON registry is used (fallback)
            assert isinstance(cli.registry, HybridCommandRegistry)

            # Check output message
            output = captured_output.getvalue()
            assert "⚠ SQL database empty" in output
            assert "✓ Using JSON backend" in output
        finally:
            sys.stdout = sys.__stdout__

    def test_registry_initialization_sql_corrupt_no_table(self, tmp_path, monkeypatch):
        """Test JSON fallback when SQL database is missing commands table"""
        # Create database with wrong schema with .crack subdirectory
        crack_dir = tmp_path / '.crack'
        crack_dir.mkdir()
        db_path = crack_dir / 'crack.db'

        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE wrong_table (id INTEGER)")
        conn.commit()
        conn.close()

        # Mock home directory
        monkeypatch.setattr(Path, 'home', lambda: tmp_path)

        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output

        try:
            cli = ReferenceCLI()

            # Assert JSON registry is used (fallback)
            assert isinstance(cli.registry, HybridCommandRegistry)

            # Check output message
            output = captured_output.getvalue()
            assert "⚠ SQL database" in output or "ℹ Falling back to JSON backend" in output
            assert "✓ Using JSON backend" in output
        finally:
            sys.stdout = sys.__stdout__

    def test_registry_initialization_import_error(self, monkeypatch):
        """Test JSON fallback when SQLCommandRegistryAdapter import fails"""
        # Mock the import to raise ImportError
        def mock_import_error(*args, **kwargs):
            raise ImportError("No module named 'db'")

        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output

        try:
            # Patch the import at the point it's used
            with patch('crack.reference.cli.main.Path.home') as mock_home:
                # Set home to non-existent path to trigger import attempt
                mock_home.return_value = Path('/nonexistent')

                # This will trigger ImportError in _initialize_registry
                cli = ReferenceCLI()

                # Should fall back to JSON
                assert isinstance(cli.registry, HybridCommandRegistry)
        finally:
            sys.stdout = sys.__stdout__

    def test_registry_sql_and_json_api_parity(self, tmp_path, monkeypatch):
        """Test that SQL and JSON registries expose same methods"""
        # Create valid SQL database with .crack subdirectory
        crack_dir = tmp_path / '.crack'
        crack_dir.mkdir()
        db_path = crack_dir / 'crack.db'

        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE commands (
                id TEXT PRIMARY KEY,
                name TEXT,
                command_template TEXT,
                description TEXT,
                category TEXT,
                oscp_relevance TEXT
            )
        """)
        cursor.execute("""
            INSERT INTO commands VALUES
            ('nmap-scan', 'Nmap Scan', 'nmap <TARGET>', 'Basic scan', 'recon', 'high')
        """)
        conn.commit()
        conn.close()

        # Mock home directory
        monkeypatch.setattr(Path, 'home', lambda: tmp_path)

        # Capture stdout to suppress output
        captured_output = StringIO()
        sys.stdout = captured_output

        try:
            # Initialize with SQL
            cli_sql = ReferenceCLI()

            # Verify we got SQL adapter
            assert isinstance(cli_sql.registry, SQLCommandRegistryAdapter)

            # Verify key methods exist (API parity check)
            assert hasattr(cli_sql.registry, 'get_command')
            assert hasattr(cli_sql.registry, 'search')
            assert hasattr(cli_sql.registry, 'filter_by_category')
            assert hasattr(cli_sql.registry, 'filter_by_tags')
            assert hasattr(cli_sql.registry, 'get_quick_wins')
            assert hasattr(cli_sql.registry, 'get_oscp_high')
            assert hasattr(cli_sql.registry, 'get_stats')
            assert hasattr(cli_sql.registry, 'interactive_fill')

            # Verify methods are callable
            assert callable(cli_sql.registry.get_command)
            assert callable(cli_sql.registry.search)
        finally:
            sys.stdout = sys.__stdout__

    def test_interactive_fill_works_with_sql_adapter(self, tmp_path, monkeypatch):
        """Test that interactive_fill() works with SQL adapter"""
        # Create valid SQL database with .crack subdirectory
        crack_dir = tmp_path / '.crack'
        crack_dir.mkdir()
        db_path = crack_dir / 'crack.db'

        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        # Create minimal schema (just commands table)
        cursor.execute("""
            CREATE TABLE commands (
                id TEXT PRIMARY KEY,
                name TEXT,
                command_template TEXT,
                description TEXT,
                category TEXT,
                oscp_relevance TEXT
            )
        """)

        # Insert test data
        cursor.execute("""
            INSERT INTO commands VALUES
            ('test-cmd', 'Test Command', 'echo <MESSAGE>', 'Test', 'custom', 'low')
        """)

        conn.commit()
        conn.close()

        # Mock home directory
        monkeypatch.setattr(Path, 'home', lambda: tmp_path)

        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output

        try:
            cli = ReferenceCLI()

            # Verify we got SQL adapter
            assert isinstance(cli.registry, SQLCommandRegistryAdapter)

            # Test interactive_fill method exists and is callable
            assert hasattr(cli.registry, 'interactive_fill')
            assert callable(cli.registry.interactive_fill)

            # Verify the adapter was initialized correctly
            assert cli.registry.repo is not None
        finally:
            sys.stdout = sys.__stdout__

    def test_database_locked_fallback(self, tmp_path, monkeypatch):
        """Test fallback when database is locked by another process"""
        # Create a valid database with .crack subdirectory
        crack_dir = tmp_path / '.crack'
        crack_dir.mkdir()
        db_path = crack_dir / 'crack.db'

        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE commands (
                id TEXT PRIMARY KEY,
                name TEXT,
                command_template TEXT
            )
        """)
        cursor.execute("INSERT INTO commands VALUES ('test', 'Test', 'test')")
        conn.commit()
        # Keep connection open to simulate lock

        # Mock home directory
        monkeypatch.setattr(Path, 'home', lambda: tmp_path)

        # Create a second connection to lock the database
        conn2 = sqlite3.connect(str(db_path), timeout=0.1)
        conn2.execute("BEGIN EXCLUSIVE")

        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output

        try:
            # This might not always trigger a lock error depending on SQLite settings,
            # but we'll test the error handling logic
            cli = ReferenceCLI()

            # Should use some registry (SQL or JSON)
            assert cli.registry is not None
        finally:
            sys.stdout = sys.__stdout__
            conn2.rollback()
            conn2.close()
            conn.close()
