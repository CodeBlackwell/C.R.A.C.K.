"""
Unit tests for PluginRepository

Tests SQL-backed plugin task template queries and runtime instance creation.
Coverage target: 90%+

NOTE: These tests use PostgreSQL test database with transaction rollback for isolation.
"""

import pytest
import psycopg2
import psycopg2.extras
from pathlib import Path
from unittest.mock import Mock, patch

from db.repositories import PluginRepository
from db.config import get_db_config


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture(scope="session")
def test_db_config():
    """
    PostgreSQL test database configuration.

    Uses separate test database to avoid conflicts with production data.
    """
    config = get_db_config()
    config['database'] = 'crack_test'  # Use test database
    return config


@pytest.fixture(scope="session")
def test_db_schema(test_db_config):
    """
    Create test database and load schema once per test session.

    This fixture:
    1. Creates crack_test database
    2. Loads full schema from db/schema.sql
    3. Applies Phase 4 migrations (002_service_plugins.sql)
    4. Applies ALL pilot migrations (FTP, NFS, SMTP, MySQL, SSH)
    5. Drops database after all tests complete
    """
    # Create test database (connect to default 'postgres' database first)
    admin_config = test_db_config.copy()
    admin_config['database'] = 'postgres'

    admin_conn = psycopg2.connect(**admin_config)
    admin_conn.autocommit = True
    admin_cursor = admin_conn.cursor()

    # Drop if exists, then create
    admin_cursor.execute("DROP DATABASE IF EXISTS crack_test")
    admin_cursor.execute("CREATE DATABASE crack_test")
    admin_cursor.close()
    admin_conn.close()

    # Connect to test database and load schema
    test_conn = psycopg2.connect(**test_db_config)
    test_cursor = test_conn.cursor()

    # Load schema
    schema_path = Path(__file__).parent.parent.parent / "db" / "schema.sql"
    with open(schema_path) as f:
        test_cursor.execute(f.read())

    # Load Phase 4 schema extension
    migration_002 = Path(__file__).parent.parent.parent / "db" / "migrations" / "002_service_plugins.sql"
    with open(migration_002) as f:
        test_cursor.execute(f.read())

    # Load ALL pilot migrations (in order)
    migrations_dir = Path(__file__).parent.parent.parent / "db" / "migrations"
    pilot_migrations = [
        "003_ftp_plugin_commands_CORRECTED.sql",
        "004_nfs_plugin_commands.sql",
        "005_smtp_plugin_commands.sql",
        "006_mysql_plugin_commands.sql",
        "007_ssh_plugin_commands.sql"
    ]

    for migration_file in pilot_migrations:
        migration_path = migrations_dir / migration_file
        with open(migration_path) as f:
            # PostgreSQL doesn't have executescript, execute each statement
            sql_content = f.read()
            test_cursor.execute(sql_content)

    test_conn.commit()
    test_cursor.close()
    test_conn.close()

    yield test_db_config

    # Cleanup: Drop test database after all tests
    admin_conn = psycopg2.connect(**admin_config)
    admin_conn.autocommit = True
    admin_cursor = admin_conn.cursor()
    admin_cursor.execute("DROP DATABASE IF EXISTS crack_test")
    admin_cursor.close()
    admin_conn.close()


@pytest.fixture
def test_db(test_db_schema):
    """
    Provide test database with transaction rollback for test isolation.

    Each test runs in a transaction that's rolled back after completion,
    ensuring tests don't interfere with each other.
    """
    conn = psycopg2.connect(**test_db_schema)

    yield test_db_schema

    # Rollback any changes made during test
    conn.rollback()
    conn.close()


@pytest.fixture
def plugin_repo(test_db):
    """PluginRepository instance connected to test database"""
    return PluginRepository(db_config=test_db)


@pytest.fixture
def sample_service_info():
    """Sample service_info dict for testing"""
    return {
        'service': 'ftp',
        'version': 'vsftpd 3.0.3',
        'banner': '220 Welcome to FTP server'
    }


# ============================================================================
# TESTS - Initialization
# ============================================================================

class TestPluginRepositoryInit:
    """Test repository initialization and connection handling"""

    def test_init_with_valid_db(self, test_db):
        """Repository initializes with valid database config"""
        repo = PluginRepository(db_config=test_db)
        assert repo.db_config == test_db

    def test_connection_uses_dict_cursor(self, plugin_repo):
        """Connection uses DictCursor for dict-like access"""
        conn = plugin_repo._get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        # Verify it's a PostgreSQL connection
        assert isinstance(conn, psycopg2.extensions.connection)
        cursor.close()
        conn.close()

    def test_get_plugin_method_returns_plugin_data(self, plugin_repo):
        """get_plugin() retrieves plugin information from database"""
        plugin = plugin_repo.get_plugin('ftp')
        assert plugin is not None
        assert plugin['name'] == 'ftp'
        assert 'service_patterns' in plugin
        assert 'default_ports' in plugin


# ============================================================================
# TESTS - get_plugin_tasks()
# ============================================================================

class TestGetPluginTasks:
    """Test retrieving task templates for a plugin"""

    def test_get_ftp_tasks_returns_list(self, plugin_repo):
        """get_plugin_tasks('ftp') returns list of task dicts"""
        tasks = plugin_repo.get_plugin_tasks('ftp')
        assert isinstance(tasks, list)
        assert len(tasks) > 0

    def test_ftp_task_structure(self, plugin_repo):
        """Each task has required fields"""
        tasks = plugin_repo.get_plugin_tasks('ftp')
        first_task = tasks[0]

        # Required fields
        assert 'task_id' in first_task
        assert 'task_name' in first_task
        assert 'task_type' in first_task
        assert 'command_id' in first_task or first_task['task_type'] == 'parent'

    def test_hierarchical_structure_includes_children(self, plugin_repo):
        """Tasks with include_children=True have 'children' field"""
        tasks = plugin_repo.get_plugin_tasks('ftp', include_children=True)

        # FTP has flat structure - all tasks have empty children list
        for task in tasks:
            assert 'children' in task
            assert isinstance(task['children'], list)
            # FTP tasks are all leaf nodes (no children)
            assert len(task['children']) == 0

    def test_flat_structure_no_children(self, plugin_repo):
        """Tasks with include_children=False have no 'children' field"""
        tasks = plugin_repo.get_plugin_tasks('ftp', include_children=False)
        for task in tasks:
            assert 'children' not in task

    def test_nonexistent_plugin_returns_empty(self, plugin_repo):
        """Requesting nonexistent plugin returns empty list"""
        tasks = plugin_repo.get_plugin_tasks('nonexistent-plugin')
        assert tasks == []

    def test_get_nfs_tasks_returns_list(self, plugin_repo):
        """get_plugin_tasks('nfs') returns NFS task templates"""
        tasks = plugin_repo.get_plugin_tasks('nfs')
        assert isinstance(tasks, list)
        assert len(tasks) >= 8, f"Expected 8+ NFS tasks, got {len(tasks)}"

    def test_get_smtp_tasks_returns_list(self, plugin_repo):
        """get_plugin_tasks('smtp') returns SMTP task templates"""
        tasks = plugin_repo.get_plugin_tasks('smtp')
        assert isinstance(tasks, list)
        assert len(tasks) >= 10, f"Expected 10+ SMTP tasks, got {len(tasks)}"

    def test_get_mysql_tasks_nested_hierarchy(self, plugin_repo):
        """get_plugin_tasks('mysql') returns nested task structure"""
        tasks = plugin_repo.get_plugin_tasks('mysql', include_children=True)

        # MySQL has parent with nested children
        assert len(tasks) >= 1

        # Find parent task
        parent_tasks = [t for t in tasks if t.get('task_type') == 'parent']
        assert len(parent_tasks) >= 1, "MySQL should have at least 1 parent task"

    def test_get_ssh_tasks_returns_list(self, plugin_repo):
        """get_plugin_tasks('ssh') returns SSH task templates (nested structure)"""
        tasks = plugin_repo.get_plugin_tasks('ssh', include_children=True)
        assert isinstance(tasks, list)
        # SSH has 1 parent with 12 children
        assert len(tasks) == 1, f"Expected 1 parent task, got {len(tasks)}"
        assert tasks[0]['task_type'] == 'parent'
        assert len(tasks[0]['children']) >= 12, f"Expected 12+ child tasks, got {len(tasks[0]['children'])}"

    def test_all_plugins_registered(self, plugin_repo):
        """All 5 pilot plugins are registered in database"""
        plugins = plugin_repo.get_all_plugins()
        plugin_names = [p['name'] for p in plugins]

        for expected in ['ftp', 'nfs', 'smtp', 'mysql', 'ssh']:
            assert expected in plugin_names, f"Plugin {expected} not registered"


# ============================================================================
# TESTS - create_task_instance()
# ============================================================================

class TestCreateTaskInstance:
    """Test runtime task instance creation with variable substitution"""

    def test_create_ftp_instance(self, plugin_repo, sample_service_info):
        """create_task_instance() returns task tree with substituted variables"""
        instance = plugin_repo.create_task_instance(
            'ftp',
            '192.168.45.100',
            21,
            sample_service_info
        )

        assert 'children' in instance
        assert len(instance['children']) > 0

    def test_variable_map_created(self, plugin_repo, sample_service_info):
        """create_task_instance() creates variable_map for each task"""
        instance = plugin_repo.create_task_instance('ftp', '192.168.45.100', 21, sample_service_info)

        # Find a command task
        command_task = self._find_command_task(instance['children'])

        assert 'variable_map' in command_task
        assert command_task['variable_map']['target'] == '192.168.45.100'
        assert command_task['variable_map']['port'] == '21'

    def test_variable_map_includes_service_info(self, plugin_repo, sample_service_info):
        """variable_map includes service and version from service_info"""
        instance = plugin_repo.create_task_instance('ftp', '192.168.45.100', 21, sample_service_info)

        command_task = self._find_command_task(instance['children'])

        assert 'service' in command_task['variable_map']
        assert 'version' in command_task['variable_map']
        assert command_task['variable_map']['service'] == 'ftp'
        assert command_task['variable_map']['version'] == 'vsftpd 3.0.3'

    def test_instance_id_unique_per_port(self, plugin_repo, sample_service_info):
        """Instance IDs include port for uniqueness"""
        instance = plugin_repo.create_task_instance('ftp', '192.168.45.100', 21, sample_service_info)

        command_task = self._find_command_task(instance['children'])
        assert '-21' in command_task['instance_id']

    def test_create_instance_all_plugins(self, plugin_repo):
        """All 5 plugins can create runtime instances"""
        test_cases = [
            ('ftp', '192.168.45.100', 21),
            ('nfs', '192.168.45.101', 2049),
            ('smtp', '192.168.45.102', 25),
            ('mysql', '192.168.45.103', 3306),
            ('ssh', '192.168.45.104', 22),
        ]

        for plugin_name, target, port in test_cases:
            instance = plugin_repo.create_task_instance(
                plugin_name, target, port, {'service': plugin_name}
            )

            assert 'children' in instance, f"{plugin_name} missing children"
            assert len(instance['children']) > 0, f"{plugin_name} has no tasks"

    def test_variable_substitution_all_plugins(self, plugin_repo):
        """Variable substitution works for all 5 plugins"""
        test_cases = [
            ('ftp', '192.168.45.100', 21),
            ('nfs', '192.168.45.101', 2049),
            ('smtp', '192.168.45.102', 25),
            ('mysql', '192.168.45.103', 3306),
            ('ssh', '192.168.45.104', 22),
        ]

        for plugin_name, target, port in test_cases:
            instance = plugin_repo.create_task_instance(
                plugin_name, target, port, {'service': plugin_name}
            )

            # Find first command task (recursively)
            cmd_task = self._find_command_task(instance['children'])
            if cmd_task:
                var_map = cmd_task.get('variable_map', {})
                assert var_map.get('target') == target, f"{plugin_name} target not substituted"
                assert var_map.get('port') == str(port), f"{plugin_name} port not substituted"

    def test_mysql_nested_instance_creation(self, plugin_repo):
        """MySQL plugin creates nested task instances"""
        instance = plugin_repo.create_task_instance(
            'mysql', '192.168.45.100', 3306, {'service': 'mysql'}
        )

        # MySQL migration has nested structure
        assert len(instance['children']) >= 1

        # Check for parent task
        has_parent = any(
            task.get('task_type') == 'parent' or 'children' in task
            for task in instance['children']
        )
        assert has_parent, "MySQL should have nested task structure"

    # Helper method
    def _find_command_task(self, tasks):
        """Recursively find first command-type task"""
        for task in tasks:
            if task.get('type') == 'command' or task.get('task_type') == 'command':
                return task
            if 'children' in task and task['children']:
                found = self._find_command_task(task['children'])
                if found:
                    return found
        return None


# ============================================================================
# TESTS - Performance Benchmarks
# ============================================================================

class TestPerformance:
    """Performance benchmarks for repository methods"""

    def test_get_plugin_tasks_performance(self, plugin_repo):
        """get_plugin_tasks() completes in <100ms"""
        import time

        iterations = 10
        start = time.time()
        for _ in range(iterations):
            plugin_repo.get_plugin_tasks('ftp')
        elapsed = (time.time() - start) / iterations

        assert elapsed < 0.1, f"get_plugin_tasks took {elapsed*1000:.2f}ms (target: <100ms)"

    def test_create_task_instance_performance(self, plugin_repo, sample_service_info):
        """create_task_instance() completes in <100ms"""
        import time

        iterations = 10
        start = time.time()
        for _ in range(iterations):
            plugin_repo.create_task_instance('ftp', '192.168.45.100', 21, sample_service_info)
        elapsed = (time.time() - start) / iterations

        assert elapsed < 0.1, f"create_task_instance took {elapsed*1000:.2f}ms (target: <100ms)"


# ============================================================================
# TESTS - Command Resolution
# ============================================================================

class TestCommandResolution:
    """Test command resolution via SQLCommandRegistryAdapter integration"""

    def test_task_links_to_command(self, plugin_repo):
        """Task templates link to commands table correctly"""
        from crack.reference.core.sql_adapter import SQLCommandRegistryAdapter

        adapter = SQLCommandRegistryAdapter()

        # Test for each plugin
        for plugin_name in ['ftp', 'nfs', 'smtp', 'mysql', 'ssh']:
            tasks = plugin_repo.get_plugin_tasks(plugin_name, include_children=True)

            # Find task with command_id (may be nested in children)
            tasks_with_cmd = self._find_tasks_with_command_id(tasks)
            assert len(tasks_with_cmd) > 0, f"{plugin_name} has no tasks with command_id"

            # Resolve first command
            cmd_id = tasks_with_cmd[0]['command_id']
            command = adapter.get_command(cmd_id)
            assert command is not None, f"Command {cmd_id} not found for {plugin_name}"

    def _find_tasks_with_command_id(self, tasks):
        """Recursively find all tasks with command_id"""
        result = []
        for task in tasks:
            if task.get('command_id'):
                result.append(task)
            if 'children' in task:
                result.extend(self._find_tasks_with_command_id(task['children']))
        return result

    def test_all_command_ids_valid(self, plugin_repo):
        """All task template command_ids reference existing commands"""
        from crack.reference.core.sql_adapter import SQLCommandRegistryAdapter

        adapter = SQLCommandRegistryAdapter()

        for plugin_name in ['ftp', 'nfs', 'smtp', 'mysql', 'ssh']:
            tasks = plugin_repo.get_plugin_tasks(plugin_name, include_children=True)

            # Find all tasks with command_id (recursively)
            tasks_with_cmd = self._find_tasks_with_command_id(tasks)

            for task in tasks_with_cmd:
                cmd_id = task.get('command_id')
                if cmd_id:
                    command = adapter.get_command(cmd_id)
                    assert command is not None, f"Invalid command_id: {cmd_id} in {plugin_name}"
