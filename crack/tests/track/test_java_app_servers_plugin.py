"""
Tests for Java Application Server plugin (Tomcat, JBoss, etc.)

PROVES: Java server detection and comprehensive enumeration task generation
"""

import pytest
from crack.track.services.java_app_servers import JavaAppServerPlugin


class TestJavaAppServerPlugin:
    """Test suite for Java Application Server plugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return JavaAppServerPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "java-app-server"

    def test_default_ports(self, plugin):
        """PROVES: Plugin defines common Java server ports"""
        assert 8080 in plugin.default_ports
        assert 8443 in plugin.default_ports
        assert 8009 in plugin.default_ports  # AJP
        assert 8180 in plugin.default_ports  # JBoss

    def test_service_names(self, plugin):
        """PROVES: Plugin recognizes Java server service names"""
        assert 'tomcat' in plugin.service_names
        assert 'jboss' in plugin.service_names
        assert 'ajp' in plugin.service_names
        assert 'java-rmi' in plugin.service_names

    # === DETECTION TESTS ===

    def test_detect_tomcat_by_service(self, plugin):
        """PROVES: Plugin detects Tomcat by service name"""
        port_info = {
            'port': 8080,
            'service': 'http-proxy',
            'product': 'Apache Tomcat/Coyote JSP engine',
            'version': '1.1'
        }
        assert plugin.detect(port_info) == True

    def test_detect_tomcat_by_product(self, plugin):
        """PROVES: Plugin detects Tomcat by product name"""
        port_info = {
            'port': 8080,
            'service': 'http',
            'product': 'Apache Tomcat',
            'version': '9.0.50'
        }
        assert plugin.detect(port_info) == True

    def test_detect_jboss_by_service(self, plugin):
        """PROVES: Plugin detects JBoss by service name"""
        port_info = {
            'port': 8080,
            'service': 'jboss',
            'product': '',
            'version': ''
        }
        assert plugin.detect(port_info) == True

    def test_detect_ajp_by_port(self, plugin):
        """PROVES: Plugin detects AJP on port 8009"""
        port_info = {
            'port': 8009,
            'service': 'ajp13',
            'product': '',
            'version': ''
        }
        assert plugin.detect(port_info) == True

    def test_detect_rmi_by_service(self, plugin):
        """PROVES: Plugin detects Java RMI"""
        port_info = {
            'port': 1099,
            'service': 'java-rmi',
            'product': 'Java RMI',
            'version': ''
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_common_port(self, plugin):
        """PROVES: Plugin detects by common port as fallback"""
        port_info = {
            'port': 8080,
            'service': 'unknown',
            'product': '',
            'version': ''
        }
        assert plugin.detect(port_info) == True

    def test_detect_negative(self, plugin):
        """PROVES: Plugin rejects non-Java services"""
        port_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.41'
        }
        assert plugin.detect(port_info) == False

    # === TASK TREE STRUCTURE TESTS ===

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid structure"""
        service_info = {
            'port': 8080,
            'service': 'http-proxy',
            'product': 'Apache Tomcat',
            'version': '9.0.50'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Root structure
        assert tree['id'] == 'java-app-server-enum-8080'
        assert tree['type'] == 'parent'
        assert 'children' in tree
        assert len(tree['children']) > 0

    def test_version_identification_tasks(self, plugin):
        """PROVES: Version identification tasks included"""
        service_info = {
            'port': 8080,
            'service': 'http-proxy',
            'product': 'Apache Tomcat',
            'version': '9.0.50'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Find version identification task
        version_tasks = [t for t in tree['children'] if 'version' in t['id'].lower()]
        assert len(version_tasks) > 0

        version_task = version_tasks[0]
        assert version_task['type'] == 'parent'
        assert 'children' in version_task

    def test_manager_discovery_tasks(self, plugin):
        """PROVES: Manager interface discovery tasks included"""
        service_info = {
            'port': 8080,
            'service': 'http-proxy',
            'product': 'Apache Tomcat',
            'version': '9.0.50'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Find manager discovery tasks
        manager_tasks = [t for t in tree['children'] if 'manager' in t['id'].lower()]
        assert len(manager_tasks) > 0

    def test_default_credentials_tasks(self, plugin):
        """PROVES: Default credential testing tasks included"""
        service_info = {
            'port': 8080,
            'service': 'http-proxy',
            'product': 'Apache Tomcat',
            'version': '9.0.50'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Find default creds tasks
        creds_tasks = [t for t in tree['children'] if 'cred' in t['id'].lower()]
        assert len(creds_tasks) > 0

    def test_vulnerability_testing_tasks(self, plugin):
        """PROVES: Vulnerability testing tasks included"""
        service_info = {
            'port': 8080,
            'service': 'http-proxy',
            'product': 'Apache Tomcat',
            'version': '9.0.50'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Find vulnerability tasks
        vuln_tasks = [t for t in tree['children'] if 'vuln' in t['id'].lower()]
        assert len(vuln_tasks) > 0

    def test_war_deployment_tasks(self, plugin):
        """PROVES: WAR deployment (RCE) tasks included for Tomcat"""
        service_info = {
            'port': 8080,
            'service': 'http-proxy',
            'product': 'Apache Tomcat',
            'version': '9.0.50'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Find WAR deployment tasks
        war_tasks = [t for t in tree['children'] if 'war' in t['id'].lower()]
        assert len(war_tasks) > 0

        war_task = war_tasks[0]
        assert war_task['type'] == 'parent'
        assert 'children' in war_task

        # Verify includes msfvenom, curl, metasploit methods
        war_children = war_task['children']
        child_ids = [c['id'] for c in war_children]
        assert any('msfvenom' in cid for cid in child_ids)
        assert any('curl' in cid for cid in child_ids)

    def test_exploit_research_tasks(self, plugin):
        """PROVES: Exploit research tasks included when version known"""
        service_info = {
            'port': 8080,
            'service': 'http-proxy',
            'product': 'Apache Tomcat',
            'version': '9.0.50'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Find exploit research tasks
        exploit_tasks = [t for t in tree['children'] if 'exploit-research' in t['id']]
        assert len(exploit_tasks) > 0

        exploit_task = exploit_tasks[0]
        assert 'children' in exploit_task

        # Verify searchsploit and CVE lookup included
        exploit_children = exploit_task['children']
        child_ids = [c['id'] for c in exploit_children]
        assert any('searchsploit' in cid for cid in child_ids)
        assert any('cve' in cid for cid in child_ids)

    # === METADATA COMPLETENESS TESTS ===

    def test_command_metadata_completeness(self, plugin):
        """PROVES: Command tasks have complete OSCP metadata"""
        service_info = {
            'port': 8080,
            'service': 'http-proxy',
            'product': 'Apache Tomcat',
            'version': '9.0.50'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Collect all command tasks recursively
        def collect_command_tasks(node, tasks=[]):
            if node.get('type') == 'command':
                tasks.append(node)
            if 'children' in node:
                for child in node['children']:
                    collect_command_tasks(child, tasks)
            return tasks

        command_tasks = collect_command_tasks(tree)
        assert len(command_tasks) > 0

        # Check first few command tasks
        for task in command_tasks[:5]:
            metadata = task.get('metadata', {})

            # Required fields
            assert 'command' in metadata, f"Task {task['id']} missing command"
            assert 'description' in metadata, f"Task {task['id']} missing description"

            # OSCP educational fields
            assert 'tags' in metadata, f"Task {task['id']} missing tags"
            assert len(metadata['tags']) > 0, f"Task {task['id']} has empty tags"

            # At least one of: flag_explanations, alternatives, success_indicators
            has_educational = (
                'flag_explanations' in metadata or
                'alternatives' in metadata or
                'success_indicators' in metadata
            )
            assert has_educational, f"Task {task['id']} missing educational metadata"

    def test_flag_explanations_present(self, plugin):
        """PROVES: Command tasks explain all flags"""
        service_info = {
            'port': 8080,
            'service': 'http-proxy',
            'product': 'Apache Tomcat',
            'version': '9.0.50'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Find curl server header task
        def find_task_by_id(node, task_id):
            if node.get('id') == task_id:
                return node
            if 'children' in node:
                for child in node['children']:
                    result = find_task_by_id(child, task_id)
                    if result:
                        return result
            return None

        curl_task = find_task_by_id(tree, 'curl-server-header-8080')
        assert curl_task is not None

        metadata = curl_task['metadata']
        assert 'flag_explanations' in metadata
        assert '-I' in metadata['flag_explanations']

    def test_alternatives_present(self, plugin):
        """PROVES: Tasks provide manual alternatives"""
        service_info = {
            'port': 8080,
            'service': 'http-proxy',
            'product': 'Apache Tomcat',
            'version': '9.0.50'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Collect command tasks with alternatives
        def collect_with_alternatives(node, tasks=[]):
            if node.get('type') == 'command':
                metadata = node.get('metadata', {})
                if 'alternatives' in metadata:
                    tasks.append(node)
            if 'children' in node:
                for child in node['children']:
                    collect_with_alternatives(child, tasks)
            return tasks

        tasks_with_alternatives = collect_with_alternatives(tree)
        assert len(tasks_with_alternatives) > 0

    def test_oscp_tags_present(self, plugin):
        """PROVES: Tasks tagged with OSCP relevance"""
        service_info = {
            'port': 8080,
            'service': 'http-proxy',
            'product': 'Apache Tomcat',
            'version': '9.0.50'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Collect all tasks with tags
        def collect_tags(node, all_tags=set()):
            metadata = node.get('metadata', {})
            if 'tags' in metadata:
                all_tags.update(metadata['tags'])
            if 'children' in node:
                for child in node['children']:
                    collect_tags(child, all_tags)
            return all_tags

        all_tags = collect_tags(tree)

        # Verify OSCP tags present
        oscp_tags = [t for t in all_tags if 'OSCP:' in t]
        assert len(oscp_tags) > 0
        assert any('OSCP:HIGH' in t for t in all_tags)

    # === SERVER TYPE DETECTION TESTS ===

    def test_detect_tomcat_type(self, plugin):
        """PROVES: Correctly identifies Tomcat server type"""
        server_type = plugin._detect_server_type('http-proxy', 'Apache Tomcat', '9.0.50')
        assert server_type == 'Tomcat'

    def test_detect_jboss_type(self, plugin):
        """PROVES: Correctly identifies JBoss server type"""
        server_type = plugin._detect_server_type('jboss', '', '')
        assert server_type == 'JBoss/WildFly'

    def test_detect_wildfly_type(self, plugin):
        """PROVES: Correctly identifies WildFly server type"""
        server_type = plugin._detect_server_type('wildfly', 'WildFly', '20.0.0')
        assert server_type == 'JBoss/WildFly'

    def test_detect_weblogic_type(self, plugin):
        """PROVES: Correctly identifies WebLogic server type"""
        server_type = plugin._detect_server_type('', 'WebLogic Server', '12.2.1')
        assert server_type == 'WebLogic'

    def test_detect_glassfish_type(self, plugin):
        """PROVES: Correctly identifies GlassFish server type"""
        server_type = plugin._detect_server_type('', 'GlassFish', '5.0')
        assert server_type == 'GlassFish'

    # === JAVA-SPECIFIC PROTOCOL TESTS ===

    def test_java_rmi_tasks_on_1099(self, plugin):
        """PROVES: Java RMI tasks generated for port 1099"""
        service_info = {
            'port': 1099,
            'service': 'java-rmi',
            'product': 'Java RMI',
            'version': ''
        }

        tree = plugin.get_task_tree('192.168.45.100', 1099, service_info)

        # Find Java protocol tasks
        java_tasks = [t for t in tree['children'] if 'java-protocols' in t['id']]
        assert len(java_tasks) > 0

        # Verify RMI enumeration included
        java_task = java_tasks[0]
        assert 'children' in java_task

        rmi_tasks = [c for c in java_task['children'] if 'rmi' in c['id']]
        assert len(rmi_tasks) > 0

    def test_jdwp_tasks_on_8000(self, plugin):
        """PROVES: JDWP exploitation tasks generated for port 8000"""
        service_info = {
            'port': 8000,
            'service': 'jdwp',
            'product': 'Java Debug Wire Protocol',
            'version': ''
        }

        tree = plugin.get_task_tree('192.168.45.100', 8000, service_info)

        # Find Java protocol tasks
        java_tasks = [t for t in tree['children'] if 'java-protocols' in t['id']]
        assert len(java_tasks) > 0

        # Verify JDWP exploitation included
        def find_jdwp_tasks(node):
            if 'jdwp' in node.get('id', ''):
                return True
            if 'children' in node:
                return any(find_jdwp_tasks(c) for c in node['children'])
            return False

        assert find_jdwp_tasks(tree)

    def test_ajp_tasks_on_8009(self, plugin):
        """PROVES: AJP enumeration tasks generated for port 8009"""
        service_info = {
            'port': 8009,
            'service': 'ajp13',
            'product': '',
            'version': ''
        }

        tree = plugin.get_task_tree('192.168.45.100', 8009, service_info)

        # Find Java protocol tasks
        java_tasks = [t for t in tree['children'] if 'java-protocols' in t['id']]
        assert len(java_tasks) > 0

        # Verify AJP enumeration included
        def find_ajp_tasks(node):
            if 'ajp' in node.get('id', ''):
                return True
            if 'children' in node:
                return any(find_ajp_tasks(c) for c in node['children'])
            return False

        assert find_ajp_tasks(tree)

    # === TOMCAT-SPECIFIC VULNERABILITY TESTS ===

    def test_tomcat_path_traversal_tasks(self, plugin):
        """PROVES: Tomcat path traversal tests included"""
        service_info = {
            'port': 8080,
            'service': 'http-proxy',
            'product': 'Apache Tomcat',
            'version': '7.0.88'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Find path traversal tasks
        def find_path_traversal(node):
            if 'path-traversal' in node.get('id', ''):
                return True
            if 'children' in node:
                return any(find_path_traversal(c) for c in node['children'])
            return False

        assert find_path_traversal(tree)

    def test_ghostcat_tasks_for_ajp(self, plugin):
        """PROVES: Ghostcat vulnerability test included for AJP port"""
        service_info = {
            'port': 8009,
            'service': 'ajp13',
            'product': 'Apache Tomcat',
            'version': '9.0.30'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8009, service_info)

        # Find Ghostcat task
        def find_ghostcat(node):
            if 'ghostcat' in node.get('id', ''):
                return True
            if 'children' in node:
                return any(find_ghostcat(c) for c in node['children'])
            return False

        assert find_ghostcat(tree)

    # === JBOSS-SPECIFIC TESTS ===

    def test_jboss_specific_tasks(self, plugin):
        """PROVES: JBoss-specific enumeration tasks generated"""
        service_info = {
            'port': 8080,
            'service': 'jboss',
            'product': 'JBoss',
            'version': '7.0.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # JBoss should have vulnerability scanning
        def find_jboss_vuln_scan(node):
            if 'jboss-vuln-scan' in node.get('id', ''):
                return True
            if 'children' in node:
                return any(find_jboss_vuln_scan(c) for c in node['children'])
            return False

        assert find_jboss_vuln_scan(tree)

    # === PROTOCOL DETECTION TESTS ===

    def test_https_protocol_detection(self, plugin):
        """PROVES: HTTPS protocol correctly detected for secure ports"""
        service_info = {
            'port': 8443,
            'service': 'https',
            'product': 'Apache Tomcat',
            'version': '9.0.50'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8443, service_info)

        # Find a command task and verify HTTPS in URL
        def find_https_url(node):
            metadata = node.get('metadata', {})
            command = metadata.get('command', '')
            if 'https://192.168.45.100:8443' in command:
                return True
            if 'children' in node:
                return any(find_https_url(c) for c in node['children'])
            return False

        assert find_https_url(tree)

    # === COMPREHENSIVE COVERAGE TEST ===

    def test_comprehensive_coverage(self, plugin):
        """PROVES: Plugin generates comprehensive enumeration coverage"""
        service_info = {
            'port': 8080,
            'service': 'http-proxy',
            'product': 'Apache Tomcat',
            'version': '9.0.50'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Count total tasks
        def count_tasks(node):
            count = 1
            if 'children' in node:
                for child in node['children']:
                    count += count_tasks(child)
            return count

        total_tasks = count_tasks(tree)

        # Should have substantial coverage (25+ tasks for comprehensive enumeration)
        assert total_tasks >= 25, f"Only {total_tasks} tasks generated, expected 25+"

    def test_post_exploitation_tasks(self, plugin):
        """PROVES: Post-exploitation tasks included"""
        service_info = {
            'port': 8080,
            'service': 'http-proxy',
            'product': 'Apache Tomcat',
            'version': '9.0.50'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Find post-exploitation tasks
        post_exploit_tasks = [t for t in tree['children'] if 'post-exploit' in t['id']]
        assert len(post_exploit_tasks) > 0
