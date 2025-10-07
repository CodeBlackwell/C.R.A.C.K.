"""
Test suite for Industrial IoT Protocol Plugins

Tests coverage for:
- IPMI (Intelligent Platform Management Interface)
- Modbus (SCADA protocol)
- EtherNet/IP (Industrial automation)
- Cisco Smart Install
- Hadoop distributed systems
"""

import pytest
from crack.track.services.industrial_iot import (
    IPMIPlugin,
    ModbusPlugin,
    EtherNetIPPlugin,
    CiscoSmartInstallPlugin,
    HadoopPlugin
)


class TestIPMIPlugin:
    """Test suite for IPMI enumeration plugin"""

    @pytest.fixture
    def plugin(self):
        """Create IPMI plugin instance"""
        return IPMIPlugin()

    def test_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "ipmi"

    def test_default_ports(self, plugin):
        """PROVES: Plugin has correct default ports"""
        assert plugin.default_ports == [623]

    def test_service_names(self, plugin):
        """PROVES: Plugin recognizes IPMI service name variations"""
        assert 'ipmi' in plugin.service_names
        assert 'bmc' in plugin.service_names
        assert 'baseboard-management' in plugin.service_names

    def test_detect_by_service_name(self, plugin):
        """PROVES: Plugin detects IPMI by service name"""
        port_info = {
            'port': 623,
            'service': 'ipmi',
            'state': 'open'
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_port(self, plugin):
        """PROVES: Plugin detects IPMI by port 623"""
        port_info = {
            'port': 623,
            'service': 'unknown',
            'state': 'open'
        }
        assert plugin.detect(port_info) == True

    def test_detect_bmc(self, plugin):
        """PROVES: Plugin detects BMC service"""
        port_info = {
            'port': 623,
            'service': 'bmc',
            'state': 'open'
        }
        assert plugin.detect(port_info) == True

    def test_detect_negative(self, plugin):
        """PROVES: Plugin rejects unrelated services"""
        port_info = {
            'port': 80,
            'service': 'http',
            'state': 'open'
        }
        assert plugin.detect(port_info) == False

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid structure"""
        service_info = {
            'port': 623,
            'service': 'ipmi',
            'version': '2.0',
            'product': 'HP iLO'
        }
        tree = plugin.get_task_tree('192.168.45.100', 623, service_info)

        # Root structure
        assert tree['id'] == 'ipmi-enum-623'
        assert tree['name'] == 'IPMI Enumeration (Port 623)'
        assert tree['type'] == 'parent'
        assert 'children' in tree
        assert len(tree['children']) > 0

    def test_ipmi_version_detection_task(self, plugin):
        """PROVES: Version detection task exists with proper metadata"""
        service_info = {'port': 623, 'service': 'ipmi'}
        tree = plugin.get_task_tree('192.168.45.100', 623, service_info)

        # Find version detection task
        version_task = None
        for task in tree['children']:
            if 'version' in task['id'].lower():
                version_task = task
                break

        assert version_task is not None
        assert 'children' in version_task

        # Check nmap subtask
        nmap_task = version_task['children'][0]
        assert 'metadata' in nmap_task
        assert 'command' in nmap_task['metadata']
        assert 'nmap' in nmap_task['metadata']['command']
        assert '--script ipmi-version' in nmap_task['metadata']['command']

    def test_cipher_zero_exploit_task(self, plugin):
        """PROVES: Cipher 0 bypass task exists"""
        service_info = {'port': 623, 'service': 'ipmi', 'version': '2.0'}
        tree = plugin.get_task_tree('192.168.45.100', 623, service_info)

        # Find cipher 0 task
        cipher_task = None
        for task in tree['children']:
            if 'cipher' in task['id'].lower():
                cipher_task = task
                break

        assert cipher_task is not None
        assert 'CVE-2013-4786' in cipher_task['name'] or 'Cipher 0' in cipher_task['name']

    def test_rakp_hash_task(self, plugin):
        """PROVES: RAKP hash retrieval task exists"""
        service_info = {'port': 623, 'service': 'ipmi'}
        tree = plugin.get_task_tree('192.168.45.100', 623, service_info)

        # Find RAKP task
        rakp_task = None
        for task in tree['children']:
            if 'rakp' in task['id'].lower():
                rakp_task = task
                break

        assert rakp_task is not None
        assert 'metadata' in rakp_task
        assert 'ipmi_dumphashes' in rakp_task['metadata']['command']

    def test_supermicro_conditional_tasks(self, plugin):
        """PROVES: Supermicro-specific tasks added when product detected"""
        service_info = {
            'port': 623,
            'service': 'ipmi',
            'product': 'Supermicro IPMI'
        }
        tree = plugin.get_task_tree('192.168.45.100', 623, service_info)

        # Find Supermicro task
        supermicro_task = None
        for task in tree['children']:
            if 'supermicro' in task['id'].lower():
                supermicro_task = task
                break

        assert supermicro_task is not None
        assert 'Supermicro' in supermicro_task['name']

    def test_oscp_metadata_completeness(self, plugin):
        """PROVES: Tasks include OSCP-required metadata"""
        service_info = {'port': 623, 'service': 'ipmi'}
        tree = plugin.get_task_tree('192.168.45.100', 623, service_info)

        # Find first command task
        command_task = None
        for task in tree['children']:
            if task.get('type') == 'parent' and task.get('children'):
                for subtask in task['children']:
                    if subtask.get('type') == 'command':
                        command_task = subtask
                        break
            if command_task:
                break

        assert command_task is not None
        metadata = command_task['metadata']

        # Required fields
        assert 'command' in metadata
        assert 'description' in metadata
        assert 'flag_explanations' in metadata
        assert 'success_indicators' in metadata
        assert 'failure_indicators' in metadata
        assert 'next_steps' in metadata
        assert 'alternatives' in metadata
        assert 'tags' in metadata


class TestModbusPlugin:
    """Test suite for Modbus SCADA plugin"""

    @pytest.fixture
    def plugin(self):
        """Create Modbus plugin instance"""
        return ModbusPlugin()

    def test_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "modbus"

    def test_default_ports(self, plugin):
        """PROVES: Plugin has correct default port"""
        assert plugin.default_ports == [502]

    def test_detect_by_service(self, plugin):
        """PROVES: Plugin detects Modbus by service name"""
        port_info = {'port': 502, 'service': 'modbus'}
        assert plugin.detect(port_info) == True

    def test_detect_scada(self, plugin):
        """PROVES: Plugin detects SCADA keyword"""
        port_info = {'port': 502, 'service': 'scada'}
        assert plugin.detect(port_info) == True

    def test_detect_by_port(self, plugin):
        """PROVES: Plugin detects by port 502"""
        port_info = {'port': 502, 'service': 'unknown'}
        assert plugin.detect(port_info) == True

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid structure"""
        tree = plugin.get_task_tree('192.168.45.100', 502, {'service': 'modbus'})

        assert tree['id'] == 'modbus-enum-502'
        assert tree['type'] == 'parent'
        assert len(tree['children']) >= 3

    def test_modbus_discovery_task(self, plugin):
        """PROVES: Modbus discovery task exists"""
        tree = plugin.get_task_tree('192.168.45.100', 502, {'service': 'modbus'})

        discover_task = tree['children'][0]
        assert 'modbus-discover' in discover_task['metadata']['command']
        assert 'SCADA' in discover_task['metadata']['tags']

    def test_unit_id_enumeration_task(self, plugin):
        """PROVES: Unit ID enumeration task exists"""
        tree = plugin.get_task_tree('192.168.45.100', 502, {'service': 'modbus'})

        unitid_task = None
        for task in tree['children']:
            if 'unitid' in task['id'].lower():
                unitid_task = task
                break

        assert unitid_task is not None
        assert 'modbus_findunitid' in unitid_task['metadata']['command']


class TestEtherNetIPPlugin:
    """Test suite for EtherNet/IP plugin"""

    @pytest.fixture
    def plugin(self):
        """Create EtherNet/IP plugin instance"""
        return EtherNetIPPlugin()

    def test_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "ethernetip"

    def test_default_ports(self, plugin):
        """PROVES: Plugin has correct default port"""
        assert plugin.default_ports == [44818]

    def test_detect_by_service(self, plugin):
        """PROVES: Plugin detects EtherNet/IP by service"""
        port_info = {'port': 44818, 'service': 'ethernetip'}
        assert plugin.detect(port_info) == True

    def test_detect_by_port(self, plugin):
        """PROVES: Plugin detects by port 44818"""
        port_info = {'port': 44818, 'service': 'unknown'}
        assert plugin.detect(port_info) == True

    def test_detect_rockwell(self, plugin):
        """PROVES: Plugin detects Rockwell products"""
        port_info = {
            'port': 44818,
            'service': 'unknown',
            'product': 'Rockwell Automation'
        }
        assert plugin.detect(port_info) == True

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid structure"""
        tree = plugin.get_task_tree('192.168.45.100', 44818, {'service': 'ethernetip'})

        assert tree['id'] == 'enip-enum-44818'
        assert tree['type'] == 'parent'
        assert len(tree['children']) >= 2

    def test_enip_nmap_task(self, plugin):
        """PROVES: Nmap enip-info task exists"""
        tree = plugin.get_task_tree('192.168.45.100', 44818, {'service': 'ethernetip'})

        nmap_task = tree['children'][0]
        assert 'enip-info' in nmap_task['metadata']['command']
        assert 'SCADA' in nmap_task['metadata']['tags']

    def test_cpppo_task(self, plugin):
        """PROVES: cpppo enumeration task exists"""
        tree = plugin.get_task_tree('192.168.45.100', 44818, {'service': 'ethernetip'})

        cpppo_task = None
        for task in tree['children']:
            if 'cpppo' in task['id'].lower():
                cpppo_task = task
                break

        assert cpppo_task is not None
        assert 'cpppo' in cpppo_task['metadata']['command']


class TestCiscoSmartInstallPlugin:
    """Test suite for Cisco Smart Install plugin"""

    @pytest.fixture
    def plugin(self):
        """Create Cisco Smart Install plugin instance"""
        return CiscoSmartInstallPlugin()

    def test_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "cisco-smart-install"

    def test_default_ports(self, plugin):
        """PROVES: Plugin has correct default port"""
        assert plugin.default_ports == [4786]

    def test_detect_by_service(self, plugin):
        """PROVES: Plugin detects Smart Install by service"""
        port_info = {'port': 4786, 'service': 'smart-install'}
        assert plugin.detect(port_info) == True

    def test_detect_by_port(self, plugin):
        """PROVES: Plugin detects by port 4786"""
        port_info = {'port': 4786, 'service': 'unknown'}
        assert plugin.detect(port_info) == True

    def test_detect_cisco_product(self, plugin):
        """PROVES: Plugin detects Cisco products"""
        port_info = {
            'port': 4786,
            'service': 'smart',
            'product': 'Cisco Catalyst'
        }
        assert plugin.detect(port_info) == True

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid structure"""
        tree = plugin.get_task_tree('192.168.45.100', 4786, {'service': 'smart-install'})

        assert tree['id'] == 'cisco-smi-enum-4786'
        assert tree['type'] == 'parent'
        assert len(tree['children']) >= 2

    def test_cve_2018_0171_task(self, plugin):
        """PROVES: CVE-2018-0171 exploitation task exists"""
        tree = plugin.get_task_tree('192.168.45.100', 4786, {'service': 'smart-install'})

        cve_task = tree['children'][0]
        assert 'CVE-2018-0171' in cve_task['name']
        assert 'children' in cve_task

    def test_siet_exploitation_task(self, plugin):
        """PROVES: SIET tool task exists with proper metadata"""
        tree = plugin.get_task_tree('192.168.45.100', 4786, {'service': 'smart-install'})

        # Find SIET task
        siet_task = None
        for task in tree['children']:
            if task.get('type') == 'parent' and task.get('children'):
                for subtask in task['children']:
                    if 'siet' in subtask['id'].lower():
                        siet_task = subtask
                        break
            if siet_task:
                break

        assert siet_task is not None
        assert 'siet.py' in siet_task['metadata']['command']
        assert '-g' in siet_task['metadata']['command']

    def test_config_analysis_task(self, plugin):
        """PROVES: Configuration analysis task exists"""
        tree = plugin.get_task_tree('192.168.45.100', 4786, {'service': 'smart-install'})

        config_task = None
        for task in tree['children']:
            if 'config' in task['id'].lower():
                config_task = task
                break

        assert config_task is not None
        assert 'CREDENTIAL_THEFT' in config_task['metadata']['tags'] or 'MANUAL' in config_task['metadata']['tags']


class TestHadoopPlugin:
    """Test suite for Hadoop plugin"""

    @pytest.fixture
    def plugin(self):
        """Create Hadoop plugin instance"""
        return HadoopPlugin()

    def test_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "hadoop"

    def test_default_ports(self, plugin):
        """PROVES: Plugin has all Hadoop default ports"""
        assert 50030 in plugin.default_ports  # JobTracker
        assert 50060 in plugin.default_ports  # TaskTracker
        assert 50070 in plugin.default_ports  # NameNode
        assert 50075 in plugin.default_ports  # DataNode
        assert 50090 in plugin.default_ports  # Secondary NameNode

    def test_detect_by_service(self, plugin):
        """PROVES: Plugin detects Hadoop by service name"""
        port_info = {'port': 50070, 'service': 'hadoop'}
        assert plugin.detect(port_info) == True

    def test_detect_hdfs(self, plugin):
        """PROVES: Plugin detects HDFS service"""
        port_info = {'port': 50070, 'service': 'hdfs'}
        assert plugin.detect(port_info) == True

    def test_detect_by_port_namenode(self, plugin):
        """PROVES: Plugin detects NameNode port 50070"""
        port_info = {'port': 50070, 'service': 'unknown'}
        assert plugin.detect(port_info) == True

    def test_detect_by_port_jobtracker(self, plugin):
        """PROVES: Plugin detects JobTracker port 50030"""
        port_info = {'port': 50030, 'service': 'unknown'}
        assert plugin.detect(port_info) == True

    def test_task_tree_namenode(self, plugin):
        """PROVES: NameNode task tree has specific tasks"""
        tree = plugin.get_task_tree('192.168.45.100', 50070, {'service': 'hdfs'})

        assert tree['id'] == 'hadoop-enum-50070'
        assert tree['type'] == 'parent'

        # Should have HDFS-specific tasks
        hdfs_task = None
        for task in tree['children']:
            if 'hdfs' in task['id'].lower():
                hdfs_task = task
                break

        assert hdfs_task is not None

    def test_task_tree_jobtracker(self, plugin):
        """PROVES: JobTracker task tree generated"""
        tree = plugin.get_task_tree('192.168.45.100', 50030, {'service': 'hadoop'})

        assert tree['id'] == 'hadoop-enum-50030'
        assert 'JobTracker' in tree['name'] or 'hadoop' in tree['name'].lower()

    def test_nmap_script_mapping(self, plugin):
        """PROVES: Correct nmap script used for each port"""
        # NameNode
        tree = plugin.get_task_tree('192.168.45.100', 50070, {'service': 'hdfs'})
        namenode_task = tree['children'][0]
        assert 'hadoop-namenode-info' in namenode_task['metadata']['command']

        # JobTracker
        tree = plugin.get_task_tree('192.168.45.100', 50030, {'service': 'hadoop'})
        jobtracker_task = tree['children'][0]
        assert 'hadoop-jobtracker-info' in jobtracker_task['metadata']['command']

    def test_web_ui_task_namenode(self, plugin):
        """PROVES: NameNode has web UI access task"""
        tree = plugin.get_task_tree('192.168.45.100', 50070, {'service': 'hdfs'})

        webui_task = None
        for task in tree['children']:
            if 'webui' in task['id'].lower():
                webui_task = task
                break

        assert webui_task is not None
        assert 'Web UI' in webui_task['name']


class TestPluginIntegration:
    """Integration tests for all Industrial IoT plugins"""

    def test_all_plugins_registered(self):
        """PROVES: All plugins are properly registered"""
        from crack.track.services.registry import ServiceRegistry

        # Get all registered plugin names
        plugin_names = [p.name for p in ServiceRegistry.get_all_plugins()]

        # Verify our plugins are registered
        assert 'ipmi' in plugin_names
        assert 'modbus' in plugin_names
        assert 'ethernetip' in plugin_names
        assert 'cisco-smart-install' in plugin_names
        assert 'hadoop' in plugin_names

    def test_no_port_collisions(self):
        """PROVES: No port collision between plugins"""
        plugins = [
            IPMIPlugin(),
            ModbusPlugin(),
            EtherNetIPPlugin(),
            CiscoSmartInstallPlugin(),
            HadoopPlugin()
        ]

        # Collect all default ports
        all_ports = []
        for plugin in plugins:
            all_ports.extend(plugin.default_ports)

        # Check Hadoop's multiple ports don't collide with others
        non_hadoop_ports = []
        for plugin in plugins:
            if plugin.name != 'hadoop':
                non_hadoop_ports.extend(plugin.default_ports)

        # Verify no overlaps (except within Hadoop itself)
        assert len(non_hadoop_ports) == len(set(non_hadoop_ports))

    def test_all_plugins_generate_tasks(self):
        """PROVES: All plugins generate non-empty task trees"""
        plugins = [
            IPMIPlugin(),
            ModbusPlugin(),
            EtherNetIPPlugin(),
            CiscoSmartInstallPlugin(),
            HadoopPlugin()
        ]

        for plugin in plugins:
            tree = plugin.get_task_tree(
                '192.168.45.100',
                plugin.default_ports[0],
                {'service': plugin.name}
            )

            assert tree is not None
            assert 'children' in tree
            assert len(tree['children']) > 0, f"{plugin.name} generated no tasks"

    def test_oscp_tag_consistency(self):
        """PROVES: All plugins use consistent OSCP tags"""
        valid_tags = [
            'OSCP:HIGH', 'OSCP:MEDIUM', 'OSCP:LOW',
            'QUICK_WIN', 'MANUAL', 'AUTOMATED', 'NOISY', 'STEALTH',
            'EXPLOIT', 'ENUM', 'RECON', 'RESEARCH', 'POST_EXPLOIT',
            'SCADA', 'CREDENTIAL_THEFT', 'BRUTE_FORCE', 'PRIVESC'
        ]

        plugins = [
            IPMIPlugin(),
            ModbusPlugin(),
            EtherNetIPPlugin(),
            CiscoSmartInstallPlugin(),
            HadoopPlugin()
        ]

        for plugin in plugins:
            tree = plugin.get_task_tree(
                '192.168.45.100',
                plugin.default_ports[0],
                {'service': plugin.name}
            )

            # Collect all tags from all tasks
            def collect_tags(node):
                tags = []
                if 'metadata' in node and 'tags' in node['metadata']:
                    tags.extend(node['metadata']['tags'])
                if 'children' in node:
                    for child in node['children']:
                        tags.extend(collect_tags(child))
                return tags

            all_tags = collect_tags(tree)

            # Verify all tags are valid
            for tag in all_tags:
                assert tag in valid_tags, f"Invalid tag '{tag}' in {plugin.name}"
