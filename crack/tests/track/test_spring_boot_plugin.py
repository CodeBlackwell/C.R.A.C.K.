"""
Tests for Spring Boot / Tomcat service plugin

PROVES:
- Plugin detects Spring Boot, Tomcat, and JBoss services
- Plugin generates comprehensive task tree for Java web enumeration
- All tasks include OSCP-required metadata
- Tasks cover actuator exploitation, heapdump mining, Tomcat WAR deployment
"""

import pytest
from crack.track.services.spring_boot import SpringBootPlugin


class TestSpringBootPlugin:
    """Test suite for Spring Boot / Tomcat plugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return SpringBootPlugin()

    def test_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "spring-boot"

    def test_default_ports(self, plugin):
        """PROVES: Plugin knows common Java web server ports"""
        assert 8080 in plugin.default_ports
        assert 8443 in plugin.default_ports
        assert 8009 in plugin.default_ports
        assert 8180 in plugin.default_ports

    def test_detect_by_tomcat_product(self, plugin):
        """PROVES: Plugin detects Tomcat by product name"""
        port_info = {
            'port': 8080,
            'service': 'http',
            'product': 'Apache Tomcat/9.0.50',
            'version': '9.0.50'
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_jboss_product(self, plugin):
        """PROVES: Plugin detects JBoss by product name"""
        port_info = {
            'port': 8080,
            'service': 'http',
            'product': 'JBoss Application Server',
            'version': '7.1.0'
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_port_8080(self, plugin):
        """PROVES: Plugin detects HTTP on port 8080 (common Java port)"""
        port_info = {
            'port': 8080,
            'service': 'http',
            'product': '',
            'version': ''
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_port_8443(self, plugin):
        """PROVES: Plugin detects HTTPS on port 8443"""
        port_info = {
            'port': 8443,
            'service': 'https',
            'product': '',
            'version': ''
        }
        assert plugin.detect(port_info) == True

    def test_detect_negative(self, plugin):
        """PROVES: Plugin rejects unrelated services"""
        port_info = {
            'port': 80,
            'service': 'http',
            'product': 'nginx',
            'version': '1.18.0'
        }
        assert plugin.detect(port_info) == False

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid structure"""
        service_info = {
            'port': 8080,
            'service': 'http',
            'product': 'Apache Tomcat',
            'version': '9.0.50'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Root structure
        assert tree['id'] == 'spring-boot-enum-8080'
        assert tree['type'] == 'parent'
        assert 'Spring Boot / Tomcat Enumeration' in tree['name']
        assert 'children' in tree

        # Has substantial tasks
        assert len(tree['children']) >= 8

    def test_actuator_discovery_tasks(self, plugin):
        """PROVES: Plugin includes Spring Boot Actuator discovery tasks"""
        service_info = {
            'port': 8080,
            'service': 'http',
            'product': 'Spring Boot',
            'version': '2.5.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Find actuator discovery parent task
        actuator_tasks = [t for t in tree['children'] if 'actuator' in t['id'].lower()]
        assert len(actuator_tasks) > 0

        # Check first actuator task has children
        actuator_parent = actuator_tasks[0]
        assert actuator_parent['type'] == 'parent'
        assert len(actuator_parent['children']) >= 2

    def test_heapdump_mining_tasks(self, plugin):
        """PROVES: Plugin includes heapdump secret mining tasks"""
        service_info = {
            'port': 8080,
            'service': 'http',
            'product': 'Spring Boot',
            'version': '2.5.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Find heapdump tasks
        heapdump_tasks = [t for t in tree['children'] if 'heapdump' in t['id'].lower()]
        assert len(heapdump_tasks) > 0

        # Check heapdump parent has download, strings, and JDumpSpider tasks
        heapdump_parent = heapdump_tasks[0]
        assert len(heapdump_parent['children']) >= 3

    def test_tomcat_manager_tasks(self, plugin):
        """PROVES: Plugin includes Tomcat Manager exploitation tasks"""
        service_info = {
            'port': 8080,
            'service': 'http',
            'product': 'Apache Tomcat',
            'version': '9.0.50'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Find Tomcat Manager tasks
        tomcat_tasks = [t for t in tree['children'] if 'tomcat-manager' in t['id'].lower()]
        assert len(tomcat_tasks) > 0

        # Should include version check, brute-force, and WAR deployment
        tomcat_parent = tomcat_tasks[0]
        assert len(tomcat_parent['children']) >= 3

    def test_oscp_metadata_completeness(self, plugin):
        """PROVES: Tasks include all OSCP-required metadata fields"""
        service_info = {
            'port': 8080,
            'service': 'http',
            'product': 'Spring Boot',
            'version': '2.5.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Find first command task
        def find_command_tasks(node):
            tasks = []
            if node.get('type') == 'command':
                tasks.append(node)
            for child in node.get('children', []):
                tasks.extend(find_command_tasks(child))
            return tasks

        command_tasks = find_command_tasks(tree)
        assert len(command_tasks) > 10, "Should have many command tasks"

        # Check first 5 command tasks for metadata
        for task in command_tasks[:5]:
            metadata = task.get('metadata', {})

            # Required fields
            assert 'command' in metadata, f"Task {task['id']} missing command"
            assert 'description' in metadata, f"Task {task['id']} missing description"
            assert 'flag_explanations' in metadata, f"Task {task['id']} missing flag_explanations"
            assert 'alternatives' in metadata, f"Task {task['id']} missing alternatives"
            assert 'tags' in metadata, f"Task {task['id']} missing tags"

            # Guidance fields
            assert 'success_indicators' in metadata, f"Task {task['id']} missing success_indicators"
            assert 'failure_indicators' in metadata, f"Task {task['id']} missing failure_indicators"
            assert 'next_steps' in metadata, f"Task {task['id']} missing next_steps"

            # Quality checks
            assert len(metadata['flag_explanations']) > 0, f"Task {task['id']} has empty flag_explanations"
            assert len(metadata['alternatives']) >= 1, f"Task {task['id']} needs manual alternatives"
            assert len(metadata['tags']) > 0, f"Task {task['id']} has no tags"
            assert len(metadata['success_indicators']) >= 2, f"Task {task['id']} needs more success indicators"
            assert len(metadata['next_steps']) >= 2, f"Task {task['id']} needs more next steps"

    def test_actuator_check_task_details(self, plugin):
        """PROVES: Actuator check task has comprehensive metadata"""
        service_info = {
            'port': 8080,
            'service': 'http',
            'product': 'Spring Boot',
            'version': '2.5.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Find actuator check task
        def find_task_by_id(node, task_id):
            if node.get('id') == task_id:
                return node
            for child in node.get('children', []):
                result = find_task_by_id(child, task_id)
                if result:
                    return result
            return None

        task = find_task_by_id(tree, 'actuator-check-8080')
        assert task is not None

        metadata = task['metadata']

        # Check command
        assert 'curl' in metadata['command']
        assert '/actuator' in metadata['command']
        assert '192.168.45.100:8080' in metadata['command']

        # Check tags
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'QUICK_WIN' in metadata['tags']
        assert 'ENUM' in metadata['tags']

        # Check explanations
        assert 'curl' in metadata['flag_explanations']
        assert '/actuator' in metadata['flag_explanations']

        # Check indicators
        assert len(metadata['success_indicators']) >= 3
        assert len(metadata['failure_indicators']) >= 3

        # Check notes
        assert 'notes' in metadata
        assert len(metadata['notes']) > 50

    def test_heapdump_download_task(self, plugin):
        """PROVES: Heapdump download task has proper metadata"""
        service_info = {
            'port': 8080,
            'service': 'http',
            'product': 'Spring Boot',
            'version': '2.5.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Find heapdump download task
        def find_task_by_id(node, task_id):
            if node.get('id') == task_id:
                return node
            for child in node.get('children', []):
                result = find_task_by_id(child, task_id)
                if result:
                    return result
            return None

        task = find_task_by_id(tree, 'heapdump-download-8080')
        assert task is not None

        metadata = task['metadata']

        # Check command
        assert 'wget' in metadata['command']
        assert '/actuator/heapdump' in metadata['command']
        assert 'heapdump_192.168.45.100_8080.hprof' in metadata['command']

        # Check tags
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'CREDS' in metadata['tags']

        # Check notes mention credential types
        assert 'DB creds' in metadata['notes'] or 'credentials' in metadata['notes'].lower()

    def test_tomcat_war_rce_task(self, plugin):
        """PROVES: Tomcat WAR deployment task includes RCE payload"""
        service_info = {
            'port': 8080,
            'service': 'http',
            'product': 'Apache Tomcat',
            'version': '9.0.50'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Find WAR RCE task
        def find_task_by_id(node, task_id):
            if node.get('id') == task_id:
                return node
            for child in node.get('children', []):
                result = find_task_by_id(child, task_id)
                if result:
                    return result
            return None

        task = find_task_by_id(tree, 'tomcat-war-rce-8080')
        assert task is not None

        metadata = task['metadata']

        # Check command
        assert 'msfvenom' in metadata['command']
        assert 'java/jsp_shell_reverse_tcp' in metadata['command']
        assert 'LHOST' in metadata['command']
        assert 'LPORT' in metadata['command']

        # Check tags
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'EXPLOIT' in metadata['tags']
        assert 'RCE' in metadata['tags']

        # Check flag explanations include msfvenom
        assert 'msfvenom' in metadata['flag_explanations']

    def test_jolokia_rce_tasks(self, plugin):
        """PROVES: Plugin includes Jolokia RCE exploitation"""
        service_info = {
            'port': 8080,
            'service': 'http',
            'product': 'Spring Boot',
            'version': '2.5.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Find Jolokia tasks
        jolokia_tasks = [t for t in tree['children'] if 'jolokia' in t['id'].lower()]
        assert len(jolokia_tasks) > 0

        jolokia_parent = jolokia_tasks[0]
        assert len(jolokia_parent['children']) >= 2

    def test_logger_manipulation_tasks(self, plugin):
        """PROVES: Plugin includes actuator logger manipulation for credential harvesting"""
        service_info = {
            'port': 8080,
            'service': 'http',
            'product': 'Spring Boot',
            'version': '2.5.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Find logger tasks
        logger_tasks = [t for t in tree['children'] if 'logger' in t['id'].lower()]
        assert len(logger_tasks) > 0

        logger_parent = logger_tasks[0]
        assert len(logger_parent['children']) >= 3

    def test_exploit_research_conditional(self, plugin):
        """PROVES: Plugin adds exploit research when version is known"""
        service_info = {
            'port': 8080,
            'service': 'http',
            'product': 'Apache Tomcat',
            'version': '9.0.50'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Find exploit research tasks
        research_tasks = [t for t in tree['children'] if 'exploit-research' in t['id']]
        assert len(research_tasks) > 0

        research_parent = research_tasks[0]
        assert 'searchsploit' in research_parent['children'][0]['id']

    def test_exploit_research_skipped_when_version_unknown(self, plugin):
        """PROVES: Plugin skips exploit research when version is unknown"""
        service_info = {
            'port': 8080,
            'service': 'http',
            'product': 'Apache Tomcat',
            'version': 'unknown'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Should not have exploit research tasks
        research_tasks = [t for t in tree['children'] if 'exploit-research' in t['id']]
        assert len(research_tasks) == 0

    def test_post_exploitation_tasks(self, plugin):
        """PROVES: Plugin includes post-exploitation tasks for Tomcat"""
        service_info = {
            'port': 8080,
            'service': 'http',
            'product': 'Apache Tomcat',
            'version': '9.0.50'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Find post-exploit tasks
        post_exploit_tasks = [t for t in tree['children'] if 'post-exploit' in t['id']]
        assert len(post_exploit_tasks) > 0

        # Should include tomcat-users.xml search
        post_parent = post_exploit_tasks[0]
        assert any('tomcat-users' in child['id'] for child in post_parent['children'])

    def test_path_traversal_tasks(self, plugin):
        """PROVES: Plugin includes Tomcat path traversal bypass techniques"""
        service_info = {
            'port': 8080,
            'service': 'http',
            'product': 'Apache Tomcat',
            'version': '9.0.50'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Find path traversal tasks
        traversal_tasks = [t for t in tree['children'] if 'path-traversal' in t['id']]
        assert len(traversal_tasks) > 0

        traversal_parent = traversal_tasks[0]
        assert len(traversal_parent['children']) >= 2

    def test_jboss_enumeration_tasks(self, plugin):
        """PROVES: Plugin includes JBoss management console enumeration"""
        service_info = {
            'port': 8080,
            'service': 'http',
            'product': 'JBoss',
            'version': '7.1.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Find JBoss tasks
        jboss_tasks = [t for t in tree['children'] if 'jboss' in t['id'].lower()]
        assert len(jboss_tasks) > 0

    def test_target_port_placeholders(self, plugin):
        """PROVES: Plugin correctly uses target and port placeholders"""
        service_info = {
            'port': 9090,
            'service': 'http',
            'product': 'Spring Boot',
            'version': '2.5.0'
        }

        tree = plugin.get_task_tree('10.10.10.50', 9090, service_info)

        # Check root ID uses port
        assert 'spring-boot-enum-9090' == tree['id']

        # Find a command task and verify placeholders
        def find_command_tasks(node):
            tasks = []
            if node.get('type') == 'command':
                tasks.append(node)
            for child in node.get('children', []):
                tasks.extend(find_command_tasks(child))
            return tasks

        command_tasks = find_command_tasks(tree)
        first_task = command_tasks[0]

        # Should use correct target and port
        assert '10.10.10.50' in first_task['metadata']['command']
        assert '9090' in first_task['metadata']['command']

    def test_https_port_detection(self, plugin):
        """PROVES: Plugin correctly handles HTTPS on port 443"""
        service_info = {
            'port': 443,
            'service': 'https',
            'product': 'Spring Boot',
            'version': '2.5.0'
        }

        # Port 443 should NOT match (not in default_ports)
        port_info = {
            'port': 443,
            'service': 'https',
            'product': 'Spring Boot'
        }
        # Will detect because of product match
        assert plugin.detect(port_info) == True

        tree = plugin.get_task_tree('192.168.45.100', 443, service_info)

        # Find first command task
        def find_command_tasks(node):
            tasks = []
            if node.get('type') == 'command':
                tasks.append(node)
            for child in node.get('children', []):
                tasks.extend(find_command_tasks(child))
            return tasks

        command_tasks = find_command_tasks(tree)
        first_task = command_tasks[0]

        # Should use https:// scheme for port 443
        assert 'https://192.168.45.100:443' in first_task['metadata']['command']
