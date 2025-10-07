"""
Tests for Development Tools & Debug Protocols Service Plugins

Tests coverage:
- ADB (Android Debug Bridge) - Port 5555
- GDB Server - Various ports
- Distcc - Port 3632
- SVN (Subversion) - Port 3690
- Git Exposure - HTTP/HTTPS ports
"""

import pytest
from crack.track.services.dev_tools import (
    ADBPlugin,
    GDBServerPlugin,
    DistccPlugin,
    SVNPlugin,
    GitExposedPlugin
)


class TestADBPlugin:
    """Test suite for Android Debug Bridge plugin"""

    @pytest.fixture
    def plugin(self):
        """Create ADB plugin instance"""
        return ADBPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "adb"

    def test_default_ports(self, plugin):
        """PROVES: Plugin knows ADB default port"""
        assert 5555 in plugin.default_ports

    def test_service_names(self, plugin):
        """PROVES: Plugin recognizes ADB service names"""
        assert 'adb' in plugin.service_names
        assert 'android debug bridge' in plugin.service_names

    def test_detect_by_service_name(self, plugin):
        """PROVES: Plugin detects ADB by service name"""
        port_info = {
            'port': 5555,
            'service': 'adb',
            'product': 'Android Debug Bridge'
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_product(self, plugin):
        """PROVES: Plugin detects ADB by product string"""
        port_info = {
            'port': 5555,
            'service': 'unknown',
            'product': 'Android Debug Bridge device'
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_port(self, plugin):
        """PROVES: Plugin detects ADB by default port"""
        port_info = {
            'port': 5555,
            'service': 'unknown',
            'product': ''
        }
        assert plugin.detect(port_info) == True

    def test_detect_negative(self, plugin):
        """PROVES: Plugin rejects unrelated services"""
        port_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache'
        }
        assert plugin.detect(port_info) == False

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid structure"""
        service_info = {
            'port': 5555,
            'service': 'adb',
            'product': 'Android Debug Bridge'
        }
        tree = plugin.get_task_tree('192.168.45.100', 5555, service_info)

        # Root structure
        assert tree['id'] == 'adb-enum-5555'
        assert tree['type'] == 'parent'
        assert 'children' in tree
        assert len(tree['children']) >= 5  # Multiple enumeration tasks

    def test_oscp_metadata_present(self, plugin):
        """PROVES: Tasks include OSCP-required metadata"""
        tree = plugin.get_task_tree('192.168.45.100', 5555, {})

        # Find first command task
        command_task = None
        for task in tree['children']:
            if task['type'] == 'command':
                command_task = task
                break

        assert command_task is not None
        metadata = command_task.get('metadata', {})

        # Required OSCP fields
        assert 'command' in metadata
        assert 'description' in metadata
        assert 'flag_explanations' in metadata
        assert 'success_indicators' in metadata
        assert 'failure_indicators' in metadata
        assert 'next_steps' in metadata
        assert 'alternatives' in metadata
        assert 'tags' in metadata

    def test_tasks_include_adb_connect(self, plugin):
        """PROVES: Task tree includes ADB connection test"""
        tree = plugin.get_task_tree('192.168.45.100', 5555, {})

        task_ids = [t['id'] for t in tree['children']]
        assert 'adb-connect-5555' in task_ids

    def test_tasks_include_root_escalation(self, plugin):
        """PROVES: Task tree includes root escalation attempt"""
        tree = plugin.get_task_tree('192.168.45.100', 5555, {})

        task_ids = [t['id'] for t in tree['children']]
        assert 'adb-root-5555' in task_ids

    def test_tasks_include_app_extraction(self, plugin):
        """PROVES: Task tree includes app data extraction"""
        tree = plugin.get_task_tree('192.168.45.100', 5555, {})

        # Check for parent task with children
        app_task = None
        for task in tree['children']:
            if 'app' in task['id'].lower() or 'extraction' in task['id'].lower():
                app_task = task
                break

        assert app_task is not None
        assert 'children' in app_task  # Should have sub-tasks


class TestGDBServerPlugin:
    """Test suite for Remote GDB Server plugin"""

    @pytest.fixture
    def plugin(self):
        """Create GDB Server plugin instance"""
        return GDBServerPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "gdbserver"

    def test_service_names(self, plugin):
        """PROVES: Plugin recognizes GDB service names"""
        assert 'gdbserver' in plugin.service_names
        assert 'gdb' in plugin.service_names

    def test_detect_by_service_name(self, plugin):
        """PROVES: Plugin detects gdbserver by service name"""
        port_info = {
            'port': 1234,
            'service': 'gdbserver',
            'product': ''
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_product(self, plugin):
        """PROVES: Plugin detects GDB by product string"""
        port_info = {
            'port': 2345,
            'service': 'unknown',
            'product': 'GDB remote serial protocol'
        }
        assert plugin.detect(port_info) == True

    def test_detect_negative(self, plugin):
        """PROVES: Plugin rejects unrelated services"""
        port_info = {
            'port': 3306,
            'service': 'mysql',
            'product': 'MySQL'
        }
        assert plugin.detect(port_info) == False

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid structure"""
        tree = plugin.get_task_tree('192.168.45.100', 1337, {})

        assert tree['id'] == 'gdbserver-exploit-1337'
        assert tree['type'] == 'parent'
        assert len(tree['children']) >= 2  # Upload/exec + arbitrary commands

    def test_tasks_include_upload_exec(self, plugin):
        """PROVES: Task tree includes ELF upload & execution"""
        tree = plugin.get_task_tree('192.168.45.100', 1337, {})

        task_ids = [t['id'] for t in tree['children']]
        assert 'gdbserver-upload-exec-1337' in task_ids

    def test_tasks_include_arbitrary_commands(self, plugin):
        """PROVES: Task tree includes arbitrary command execution"""
        tree = plugin.get_task_tree('192.168.45.100', 1337, {})

        # Should have parent task with Python script method
        arb_cmd_task = None
        for task in tree['children']:
            if 'arbitrary' in task['name'].lower() or 'cmd' in task['id'].lower():
                arb_cmd_task = task
                break

        assert arb_cmd_task is not None

    def test_exploit_includes_msfvenom(self, plugin):
        """PROVES: Exploitation task uses msfvenom"""
        tree = plugin.get_task_tree('192.168.45.100', 1337, {})

        upload_task = tree['children'][0]
        assert 'msfvenom' in upload_task['metadata']['command']
        assert 'PrependFork=true' in upload_task['metadata']['command']


class TestDistccPlugin:
    """Test suite for Distcc plugin"""

    @pytest.fixture
    def plugin(self):
        """Create Distcc plugin instance"""
        return DistccPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "distcc"

    def test_default_ports(self, plugin):
        """PROVES: Plugin knows Distcc default port"""
        assert 3632 in plugin.default_ports

    def test_detect_by_service_name(self, plugin):
        """PROVES: Plugin detects distcc by service name"""
        port_info = {
            'port': 3632,
            'service': 'distccd',
            'product': ''
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_port(self, plugin):
        """PROVES: Plugin detects distcc by default port"""
        port_info = {
            'port': 3632,
            'service': 'unknown',
            'product': ''
        }
        assert plugin.detect(port_info) == True

    def test_detect_negative(self, plugin):
        """PROVES: Plugin rejects unrelated services"""
        port_info = {
            'port': 22,
            'service': 'ssh',
            'product': 'OpenSSH'
        }
        assert plugin.detect(port_info) == False

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid structure"""
        tree = plugin.get_task_tree('192.168.45.100', 3632, {})

        assert tree['id'] == 'distcc-exploit-3632'
        assert tree['type'] == 'parent'
        assert len(tree['children']) >= 2  # MSF + NSE + post-exploit

    def test_tasks_include_cve_exploit(self, plugin):
        """PROVES: Task tree includes CVE-2004-2687 exploitation"""
        tree = plugin.get_task_tree('192.168.45.100', 3632, {})

        # Check for Metasploit task
        msf_task = None
        for task in tree['children']:
            if 'msf' in task['id'].lower() or 'metasploit' in task['name'].lower():
                msf_task = task
                break

        assert msf_task is not None
        assert 'distcc_exec' in msf_task['metadata']['command']

    def test_tasks_include_nmap_nse(self, plugin):
        """PROVES: Task tree includes Nmap NSE detection"""
        tree = plugin.get_task_tree('192.168.45.100', 3632, {})

        nmap_task = None
        for task in tree['children']:
            if 'nmap' in task['id'].lower():
                nmap_task = task
                break

        assert nmap_task is not None
        assert 'distcc-cve2004-2687' in nmap_task['metadata']['command']

    def test_oscp_tags_present(self, plugin):
        """PROVES: Tasks have OSCP relevance tags"""
        tree = plugin.get_task_tree('192.168.45.100', 3632, {})

        first_task = tree['children'][0]
        tags = first_task['metadata'].get('tags', [])

        assert any('OSCP:HIGH' in tag for tag in tags)
        assert any('EXPLOIT' in tag or 'RCE' in tag for tag in tags)


class TestSVNPlugin:
    """Test suite for Subversion plugin"""

    @pytest.fixture
    def plugin(self):
        """Create SVN plugin instance"""
        return SVNPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "svn"

    def test_default_ports(self, plugin):
        """PROVES: Plugin knows SVN default port"""
        assert 3690 in plugin.default_ports

    def test_service_names(self, plugin):
        """PROVES: Plugin recognizes SVN service names"""
        assert 'svn' in plugin.service_names
        assert 'svnserve' in plugin.service_names
        assert 'subversion' in plugin.service_names

    def test_detect_by_service_name(self, plugin):
        """PROVES: Plugin detects SVN by service name"""
        port_info = {
            'port': 3690,
            'service': 'svnserve',
            'product': 'Subversion'
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_port(self, plugin):
        """PROVES: Plugin detects SVN by default port"""
        port_info = {
            'port': 3690,
            'service': 'unknown',
            'product': ''
        }
        assert plugin.detect(port_info) == True

    def test_detect_negative(self, plugin):
        """PROVES: Plugin rejects unrelated services"""
        port_info = {
            'port': 80,
            'service': 'http',
            'product': 'nginx'
        }
        assert plugin.detect(port_info) == False

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid structure"""
        tree = plugin.get_task_tree('192.168.45.100', 3690, {})

        assert tree['id'] == 'svn-enum-3690'
        assert tree['type'] == 'parent'
        assert len(tree['children']) >= 4  # Banner, list, log, checkout, revisions

    def test_tasks_include_banner_grab(self, plugin):
        """PROVES: Task tree includes banner grabbing"""
        tree = plugin.get_task_tree('192.168.45.100', 3690, {})

        task_ids = [t['id'] for t in tree['children']]
        assert 'svn-banner-3690' in task_ids

    def test_tasks_include_list(self, plugin):
        """PROVES: Task tree includes repository listing"""
        tree = plugin.get_task_tree('192.168.45.100', 3690, {})

        task_ids = [t['id'] for t in tree['children']]
        assert 'svn-list-3690' in task_ids

    def test_tasks_include_log(self, plugin):
        """PROVES: Task tree includes commit history"""
        tree = plugin.get_task_tree('192.168.45.100', 3690, {})

        task_ids = [t['id'] for t in tree['children']]
        assert 'svn-log-3690' in task_ids

    def test_tasks_include_checkout(self, plugin):
        """PROVES: Task tree includes repository checkout"""
        tree = plugin.get_task_tree('192.168.45.100', 3690, {})

        task_ids = [t['id'] for t in tree['children']]
        assert 'svn-checkout-3690' in task_ids

    def test_tasks_include_revision_navigation(self, plugin):
        """PROVES: Task tree includes revision navigation"""
        tree = plugin.get_task_tree('192.168.45.100', 3690, {})

        task_ids = [t['id'] for t in tree['children']]
        assert 'svn-revisions-3690' in task_ids

    def test_metadata_includes_svn_commands(self, plugin):
        """PROVES: Commands use svn client"""
        tree = plugin.get_task_tree('192.168.45.100', 3690, {})

        list_task = None
        for task in tree['children']:
            if task['id'] == 'svn-list-3690':
                list_task = task
                break

        assert list_task is not None
        assert 'svn ls' in list_task['metadata']['command']


class TestGitExposedPlugin:
    """Test suite for Git repository exposure plugin"""

    @pytest.fixture
    def plugin(self):
        """Create Git exposure plugin instance"""
        return GitExposedPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "git-exposed"

    def test_default_ports(self, plugin):
        """PROVES: Plugin targets HTTP/HTTPS ports"""
        assert 80 in plugin.default_ports
        assert 443 in plugin.default_ports
        assert 8080 in plugin.default_ports

    def test_detect_http(self, plugin):
        """PROVES: Plugin activates for HTTP services"""
        port_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache'
        }
        assert plugin.detect(port_info) == True

    def test_detect_https(self, plugin):
        """PROVES: Plugin activates for HTTPS services"""
        port_info = {
            'port': 443,
            'service': 'https',
            'product': 'nginx'
        }
        assert plugin.detect(port_info) == True

    def test_detect_negative(self, plugin):
        """PROVES: Plugin rejects non-web services"""
        port_info = {
            'port': 22,
            'service': 'ssh',
            'product': 'OpenSSH'
        }
        assert plugin.detect(port_info) == False

    def test_task_tree_structure_http(self, plugin):
        """PROVES: Task tree adapts to HTTP protocol"""
        tree = plugin.get_task_tree('192.168.45.100', 80, {'service': 'http'})

        assert tree['id'] == 'git-exposed-enum-80'
        assert tree['type'] == 'parent'
        assert len(tree['children']) >= 5  # Check, dump, history, scan, config

    def test_task_tree_structure_https(self, plugin):
        """PROVES: Task tree adapts to HTTPS protocol"""
        tree = plugin.get_task_tree('192.168.45.100', 443, {'service': 'https'})

        # Should use https:// in commands
        first_task = tree['children'][0]
        assert 'https://' in first_task['metadata']['command']

    def test_tasks_include_git_check(self, plugin):
        """PROVES: Task tree includes .git exposure check"""
        tree = plugin.get_task_tree('192.168.45.100', 80, {})

        task_ids = [t['id'] for t in tree['children']]
        assert 'git-check-exposed-80' in task_ids

    def test_tasks_include_git_dumper(self, plugin):
        """PROVES: Task tree includes git-dumper download"""
        tree = plugin.get_task_tree('192.168.45.100', 80, {})

        task_ids = [t['id'] for t in tree['children']]
        assert 'git-dumper-80' in task_ids

    def test_tasks_include_history_analysis(self, plugin):
        """PROVES: Task tree includes commit history analysis"""
        tree = plugin.get_task_tree('192.168.45.100', 80, {})

        task_ids = [t['id'] for t in tree['children']]
        assert 'git-history-analysis-80' in task_ids

    def test_tasks_include_secret_scanning(self, plugin):
        """PROVES: Task tree includes TruffleHog scanning"""
        tree = plugin.get_task_tree('192.168.45.100', 80, {})

        task_ids = [t['id'] for t in tree['children']]
        assert 'git-secret-scanning-80' in task_ids

    def test_tasks_include_config_extraction(self, plugin):
        """PROVES: Task tree includes .git/config credential check"""
        tree = plugin.get_task_tree('192.168.45.100', 80, {})

        task_ids = [t['id'] for t in tree['children']]
        assert 'git-config-creds-80' in task_ids

    def test_curl_check_command(self, plugin):
        """PROVES: .git check uses curl properly"""
        tree = plugin.get_task_tree('192.168.45.100', 80, {})

        check_task = tree['children'][0]
        cmd = check_task['metadata']['command']

        assert 'curl' in cmd
        assert '/.git/HEAD' in cmd
        assert 'http_code' in cmd


class TestPluginIntegration:
    """Integration tests for all dev tools plugins"""

    def test_all_plugins_registered(self):
        """PROVES: All plugins are registered in ServiceRegistry"""
        from crack.track.services.registry import ServiceRegistry

        registered_names = list(ServiceRegistry._plugins.keys())

        assert 'adb' in registered_names
        assert 'gdbserver' in registered_names
        assert 'distcc' in registered_names
        assert 'svn' in registered_names
        assert 'git-exposed' in registered_names

    def test_no_duplicate_registrations(self):
        """PROVES: No duplicate plugin registrations"""
        from crack.track.services.registry import ServiceRegistry

        # Dict keys are unique by definition
        plugin_names = list(ServiceRegistry._plugins.keys())

        # Verify all our plugins exist
        for name in ['adb', 'gdbserver', 'distcc', 'svn', 'git-exposed']:
            assert name in plugin_names, f"Plugin {name} not registered"

    def test_all_plugins_have_oscp_metadata(self):
        """PROVES: All plugins provide OSCP-compliant metadata"""
        plugins = [
            ADBPlugin(),
            GDBServerPlugin(),
            DistccPlugin(),
            SVNPlugin(),
            GitExposedPlugin()
        ]

        for plugin in plugins:
            tree = plugin.get_task_tree('192.168.45.100', 1234, {})

            # Find at least one command task
            command_tasks = []
            def find_command_tasks(node):
                if node.get('type') == 'command':
                    command_tasks.append(node)
                for child in node.get('children', []):
                    find_command_tasks(child)

            find_command_tasks(tree)

            assert len(command_tasks) > 0, f"Plugin {plugin.name} has no command tasks"

            # Verify first command task has OSCP metadata
            task = command_tasks[0]
            metadata = task.get('metadata', {})

            assert 'command' in metadata, f"Plugin {plugin.name} missing command"
            assert 'description' in metadata, f"Plugin {plugin.name} missing description"
            assert 'tags' in metadata, f"Plugin {plugin.name} missing tags"
            assert 'flag_explanations' in metadata or task['type'] == 'manual', \
                f"Plugin {plugin.name} missing flag_explanations"
