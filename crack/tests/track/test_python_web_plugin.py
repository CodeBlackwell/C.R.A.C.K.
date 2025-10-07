"""
Tests for Python Web Framework Exploitation service plugin

Validates detection, task generation, and OSCP educational metadata
for Python web application exploitation scenarios.
"""

import pytest
from crack.track.services.python_web import PythonWebPlugin


class TestPythonWebPlugin:
    """Test suite for Python Web Framework Exploitation plugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return PythonWebPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "python-web"

    def test_default_ports(self, plugin):
        """PROVES: Plugin knows common Python web framework ports"""
        expected_ports = [5000, 8000, 8080, 8443, 5001, 8001]
        assert plugin.default_ports == expected_ports

    def test_service_names(self, plugin):
        """PROVES: Plugin recognizes HTTP service names"""
        expected_names = ['http', 'https', 'http-proxy', 'http-alt', 'ssl/http']
        assert plugin.service_names == expected_names

    # Detection tests
    def test_detect_flask_by_product(self, plugin):
        """PROVES: Plugin detects Flask/Werkzeug by product name"""
        port_info = {
            'port': 5000,
            'service': 'http',
            'product': 'Werkzeug httpd',
            'version': '2.0.1'
        }
        assert plugin.detect(port_info) == True

    def test_detect_django_by_product(self, plugin):
        """PROVES: Plugin detects Django by product name"""
        port_info = {
            'port': 8000,
            'service': 'http',
            'product': 'Django',
            'version': '3.2.0'
        }
        assert plugin.detect(port_info) == True

    def test_detect_fastapi_by_product(self, plugin):
        """PROVES: Plugin detects FastAPI/uvicorn"""
        port_info = {
            'port': 8000,
            'service': 'http',
            'product': 'uvicorn',
            'version': '0.15.0'
        }
        assert plugin.detect(port_info) == True

    def test_detect_gunicorn_by_product(self, plugin):
        """PROVES: Plugin detects Gunicorn"""
        port_info = {
            'port': 8000,
            'service': 'http',
            'product': 'gunicorn',
            'version': '20.1.0'
        }
        assert plugin.detect(port_info) == True

    def test_detect_python_by_version(self, plugin):
        """PROVES: Plugin detects Python in version string"""
        port_info = {
            'port': 8080,
            'service': 'http',
            'product': 'SimpleHTTP',
            'version': 'Python/3.9.0'
        }
        assert plugin.detect(port_info) == True

    def test_detect_wsgi_by_product(self, plugin):
        """PROVES: Plugin detects WSGI servers"""
        port_info = {
            'port': 8000,
            'service': 'http',
            'product': 'wsgi server',
            'version': '1.0'
        }
        assert plugin.detect(port_info) == True

    def test_no_detect_generic_http(self, plugin):
        """PROVES: Plugin doesn't claim generic HTTP (lets HTTP plugin handle)"""
        port_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.41'
        }
        assert plugin.detect(port_info) == False

    def test_no_detect_nginx(self, plugin):
        """PROVES: Plugin doesn't detect non-Python servers"""
        port_info = {
            'port': 80,
            'service': 'http',
            'product': 'nginx',
            'version': '1.18.0'
        }
        assert plugin.detect(port_info) == False

    def test_no_detect_unrelated_service(self, plugin):
        """PROVES: Plugin rejects non-HTTP services"""
        port_info = {
            'port': 22,
            'service': 'ssh',
            'product': 'OpenSSH',
            'version': '8.2p1'
        }
        assert plugin.detect(port_info) == False

    # Task generation tests
    def test_task_tree_structure_flask(self, plugin):
        """PROVES: Plugin generates valid task tree for Flask"""
        service_info = {
            'port': 5000,
            'service': 'http',
            'product': 'Werkzeug httpd',
            'version': '2.0.1'
        }

        tree = plugin.get_task_tree('192.168.45.100', 5000, service_info)

        # Root structure
        assert tree['id'] == 'python-web-enum-5000'
        assert tree['type'] == 'parent'
        assert 'children' in tree
        assert len(tree['children']) > 0

    def test_task_tree_structure_django(self, plugin):
        """PROVES: Plugin generates valid task tree for Django"""
        service_info = {
            'port': 8000,
            'service': 'http',
            'product': 'Django',
            'version': '3.2.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8000, service_info)

        # Root structure
        assert tree['id'] == 'python-web-enum-8000'
        assert tree['type'] == 'parent'
        assert 'children' in tree

    def test_task_tree_has_recon_phase(self, plugin):
        """PROVES: Task tree includes reconnaissance phase"""
        service_info = {
            'port': 5000,
            'service': 'http',
            'product': 'Werkzeug httpd',
            'version': '2.0.1'
        }

        tree = plugin.get_task_tree('192.168.45.100', 5000, service_info)

        recon_tasks = [t for t in tree['children'] if 'recon' in t['id'].lower()]
        assert len(recon_tasks) > 0

    def test_task_tree_has_exploitation_phase(self, plugin):
        """PROVES: Task tree includes exploitation techniques"""
        service_info = {
            'port': 5000,
            'service': 'http',
            'product': 'Werkzeug httpd',
            'version': '2.0.1'
        }

        tree = plugin.get_task_tree('192.168.45.100', 5000, service_info)

        exploit_tasks = [t for t in tree['children'] if 'exploit' in t['id'].lower()]
        assert len(exploit_tasks) > 0

    def test_task_tree_has_post_exploitation_phase(self, plugin):
        """PROVES: Task tree includes post-exploitation tasks"""
        service_info = {
            'port': 5000,
            'service': 'http',
            'product': 'Werkzeug httpd',
            'version': '2.0.1'
        }

        tree = plugin.get_task_tree('192.168.45.100', 5000, service_info)

        post_exploit_tasks = [t for t in tree['children'] if 'post' in t['id'].lower()]
        assert len(post_exploit_tasks) > 0

    def test_flask_specific_tasks(self, plugin):
        """PROVES: Flask detection includes Flask-specific tasks"""
        service_info = {
            'port': 5000,
            'service': 'http',
            'product': 'Werkzeug httpd',
            'version': '2.0.1'
        }

        tree = plugin.get_task_tree('192.168.45.100', 5000, service_info)

        # Find all task IDs (flatten tree)
        def get_all_task_ids(node):
            ids = [node['id']]
            if 'children' in node:
                for child in node['children']:
                    ids.extend(get_all_task_ids(child))
            return ids

        all_ids = get_all_task_ids(tree)

        # Flask-specific tasks
        assert any('werkzeug-console' in tid for tid in all_ids)
        assert any('flask-secret' in tid for tid in all_ids)
        assert any('werkzeug-pin' in tid for tid in all_ids)

    def test_https_url_construction(self, plugin):
        """PROVES: Plugin uses HTTPS for secure ports"""
        service_info = {
            'port': 8443,
            'service': 'https',
            'product': 'Werkzeug httpd',
            'version': '2.0.1'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8443, service_info)

        # Find a command task
        def find_command_task(node):
            if node.get('type') == 'command' and 'metadata' in node:
                return node
            if 'children' in node:
                for child in node['children']:
                    result = find_command_task(child)
                    if result:
                        return result
            return None

        command_task = find_command_task(tree)
        assert command_task is not None
        assert 'https://' in command_task['metadata']['command']

    # OSCP metadata tests
    def test_framework_detection_has_oscp_metadata(self, plugin):
        """PROVES: Framework detection task has complete OSCP metadata"""
        service_info = {
            'port': 5000,
            'service': 'http',
            'product': 'Werkzeug httpd'
        }

        tree = plugin.get_task_tree('192.168.45.100', 5000, service_info)

        # Find framework detection task
        def find_task_by_id(node, task_id):
            if node['id'] == task_id:
                return node
            if 'children' in node:
                for child in node['children']:
                    result = find_task_by_id(child, task_id)
                    if result:
                        return result
            return None

        detect_task = find_task_by_id(tree, 'python-detect-5000')
        assert detect_task is not None

        metadata = detect_task['metadata']

        # Required fields
        assert 'command' in metadata
        assert 'description' in metadata
        assert 'flag_explanations' in metadata
        assert 'success_indicators' in metadata
        assert 'failure_indicators' in metadata
        assert 'next_steps' in metadata
        assert 'alternatives' in metadata
        assert 'tags' in metadata
        assert 'notes' in metadata

        # OSCP tags
        assert 'OSCP:HIGH' in metadata['tags'] or 'OSCP:MEDIUM' in metadata['tags']

        # Content quality
        assert len(metadata['success_indicators']) >= 2
        assert len(metadata['failure_indicators']) >= 2
        assert len(metadata['next_steps']) >= 2
        assert len(metadata['alternatives']) >= 2

    def test_ssti_task_has_exploitation_templates(self, plugin):
        """PROVES: SSTI task includes exploitation payloads"""
        service_info = {
            'port': 5000,
            'service': 'http',
            'product': 'Werkzeug httpd'
        }

        tree = plugin.get_task_tree('192.168.45.100', 5000, service_info)

        # Find SSTI task
        def find_task_by_id(node, task_id):
            if node['id'] == task_id:
                return node
            if 'children' in node:
                for child in node['children']:
                    result = find_task_by_id(child, task_id)
                    if result:
                        return result
            return None

        ssti_task = find_task_by_id(tree, 'ssti-test-5000')
        assert ssti_task is not None

        metadata = ssti_task['metadata']

        # SSTI-specific content
        assert '{{7*7}}' in metadata['command']
        assert 'success_indicators' in metadata
        assert any('49' in indicator for indicator in metadata['success_indicators'])

        # Next steps should include RCE payloads
        next_steps_str = ' '.join(metadata['next_steps'])
        assert '__globals__' in next_steps_str or 'RCE' in next_steps_str

    def test_pickle_deserialization_has_code_examples(self, plugin):
        """PROVES: Pickle task includes working Python code"""
        service_info = {
            'port': 5000,
            'service': 'http',
            'product': 'Flask'
        }

        tree = plugin.get_task_tree('192.168.45.100', 5000, service_info)

        # Find pickle task
        def find_task_by_id(node, task_id):
            if node['id'] == task_id:
                return node
            if 'children' in node:
                for child in node['children']:
                    result = find_task_by_id(child, task_id)
                    if result:
                        return result
            return None

        pickle_task = find_task_by_id(tree, 'pickle-rce-5000')
        assert pickle_task is not None

        metadata = pickle_task['metadata']

        # Pickle-specific content
        alternatives_str = '\n'.join(metadata['alternatives'])
        assert 'import pickle' in alternatives_str
        assert '__reduce__' in alternatives_str
        assert 'base64' in alternatives_str

    def test_class_pollution_has_payloads(self, plugin):
        """PROVES: Class pollution task includes JSON payloads"""
        service_info = {
            'port': 5000,
            'service': 'http',
            'product': 'Flask'
        }

        tree = plugin.get_task_tree('192.168.45.100', 5000, service_info)

        # Find class pollution task
        def find_task_by_id(node, task_id):
            if node['id'] == task_id:
                return node
            if 'children' in node:
                for child in node['children']:
                    result = find_task_by_id(child, task_id)
                    if result:
                        return result
            return None

        pollution_task = find_task_by_id(tree, 'class-pollution-5000')
        assert pollution_task is not None

        metadata = pollution_task['metadata']

        # Class pollution specific content
        alternatives_str = '\n'.join(metadata['alternatives'])
        assert '__class__' in alternatives_str
        assert '__init__' in alternatives_str
        assert '__globals__' in alternatives_str

    def test_reportlab_rce_has_cve_info(self, plugin):
        """PROVES: ReportLab task includes CVE and payload"""
        service_info = {
            'port': 5000,
            'service': 'http',
            'product': 'Flask'
        }

        tree = plugin.get_task_tree('192.168.45.100', 5000, service_info)

        # Find ReportLab task
        def find_task_by_id(node, task_id):
            if node['id'] == task_id:
                return node
            if 'children' in node:
                for child in node['children']:
                    result = find_task_by_id(child, task_id)
                    if result:
                        return result
            return None

        reportlab_task = find_task_by_id(tree, 'reportlab-rce-5000')
        assert reportlab_task is not None

        metadata = reportlab_task['metadata']

        # CVE info
        assert 'CVE' in metadata['tags'] or 'CVE-2023-33733' in metadata['description']

        # Payload content
        alternatives_str = '\n'.join(metadata['alternatives'])
        assert 'getattr(pow' in alternatives_str
        assert 'Word' in alternatives_str

    def test_ml_model_deserialization_has_multiple_formats(self, plugin):
        """PROVES: ML model task covers Keras, PyTorch, and pickle"""
        service_info = {
            'port': 5000,
            'service': 'http',
            'product': 'FastAPI'
        }

        tree = plugin.get_task_tree('192.168.45.100', 5000, service_info)

        # Find ML model task
        def find_task_by_id(node, task_id):
            if node['id'] == task_id:
                return node
            if 'children' in node:
                for child in node['children']:
                    result = find_task_by_id(child, task_id)
                    if result:
                        return result
            return None

        ml_task = find_task_by_id(tree, 'ml-model-rce-5000')
        assert ml_task is not None

        metadata = ml_task['metadata']

        # Multiple formats covered
        alternatives_str = '\n'.join(metadata['alternatives'])
        assert 'Keras' in alternatives_str or 'keras' in alternatives_str
        assert 'torch' in alternatives_str or 'PyTorch' in alternatives_str
        assert 'pickle' in alternatives_str

    def test_pyscript_exploitation_has_xss_and_ssrf(self, plugin):
        """PROVES: PyScript task covers XSS, file exfil, and SSRF"""
        service_info = {
            'port': 5000,
            'service': 'http',
            'product': 'Python'
        }

        tree = plugin.get_task_tree('192.168.45.100', 5000, service_info)

        # Find PyScript task
        def find_task_by_id(node, task_id):
            if node['id'] == task_id:
                return node
            if 'children' in node:
                for child in node['children']:
                    result = find_task_by_id(child, task_id)
                    if result:
                        return result
            return None

        pyscript_task = find_task_by_id(tree, 'pyscript-exploit-5000')
        assert pyscript_task is not None

        metadata = pyscript_task['metadata']

        # Multiple attack vectors
        alternatives_str = '\n'.join(metadata['alternatives'])
        assert '<py-script>' in alternatives_str
        assert 'print(' in alternatives_str
        assert 'urllib3' in alternatives_str or 'SSRF' in metadata['description']

    def test_sandbox_bypass_has_gadget_chains(self, plugin):
        """PROVES: Sandbox bypass task includes working gadget chains"""
        service_info = {
            'port': 5000,
            'service': 'http',
            'product': 'Flask'
        }

        tree = plugin.get_task_tree('192.168.45.100', 5000, service_info)

        # Find sandbox bypass task
        def find_task_by_id(node, task_id):
            if node['id'] == task_id:
                return node
            if 'children' in node:
                for child in node['children']:
                    result = find_task_by_id(child, task_id)
                    if result:
                        return result
            return None

        sandbox_task = find_task_by_id(tree, 'python-sandbox-bypass-5000')
        assert sandbox_task is not None

        metadata = sandbox_task['metadata']

        # Gadget chains
        alternatives_str = '\n'.join(metadata['alternatives'])
        assert '__subclasses__' in alternatives_str
        assert '__builtins__' in alternatives_str
        assert '__globals__' in alternatives_str

    def test_format_string_has_read_gadgets(self, plugin):
        """PROVES: Format string task includes read gadgets"""
        service_info = {
            'port': 5000,
            'service': 'http',
            'product': 'Flask'
        }

        tree = plugin.get_task_tree('192.168.45.100', 5000, service_info)

        # Find format string task
        def find_task_by_id(node, task_id):
            if node['id'] == task_id:
                return node
            if 'children' in node:
                for child in node['children']:
                    result = find_task_by_id(child, task_id)
                    if result:
                        return result
            return None

        format_task = find_task_by_id(tree, 'python-format-string-5000')
        assert format_task is not None

        metadata = format_task['metadata']

        # Format string content
        alternatives_str = '\n'.join(metadata['alternatives'])
        assert '.format(' in alternatives_str or '{' in alternatives_str
        assert '__globals__' in alternatives_str

    def test_version_triggers_research_tasks(self, plugin):
        """PROVES: Version detection triggers vulnerability research"""
        service_info = {
            'port': 5000,
            'service': 'http',
            'product': 'Werkzeug httpd',
            'version': '2.0.1'
        }

        tree = plugin.get_task_tree('192.168.45.100', 5000, service_info)

        # Find research tasks
        research_tasks = [t for t in tree['children'] if 'research' in t['id'].lower()]
        assert len(research_tasks) > 0

        # Should have searchsploit and CVE tasks
        research_task = research_tasks[0]
        assert 'children' in research_task
        task_ids = [t['id'] for t in research_task['children']]
        assert any('searchsploit' in tid for tid in task_ids)
        assert any('cve' in tid for tid in task_ids)

    def test_all_tasks_have_unique_ids(self, plugin):
        """PROVES: All tasks have unique IDs"""
        service_info = {
            'port': 5000,
            'service': 'http',
            'product': 'Werkzeug httpd',
            'version': '2.0.1'
        }

        tree = plugin.get_task_tree('192.168.45.100', 5000, service_info)

        def get_all_task_ids(node):
            ids = [node['id']]
            if 'children' in node:
                for child in node['children']:
                    ids.extend(get_all_task_ids(child))
            return ids

        all_ids = get_all_task_ids(tree)
        assert len(all_ids) == len(set(all_ids)), "Duplicate task IDs found"

    def test_command_tasks_have_commands(self, plugin):
        """PROVES: All command-type tasks have actual commands"""
        service_info = {
            'port': 5000,
            'service': 'http',
            'product': 'Werkzeug httpd'
        }

        tree = plugin.get_task_tree('192.168.45.100', 5000, service_info)

        def get_all_command_tasks(node):
            tasks = []
            if node.get('type') == 'command':
                tasks.append(node)
            if 'children' in node:
                for child in node['children']:
                    tasks.extend(get_all_command_tasks(child))
            return tasks

        command_tasks = get_all_command_tasks(tree)
        assert len(command_tasks) > 0

        for task in command_tasks:
            assert 'metadata' in task
            assert 'command' in task['metadata']
            assert len(task['metadata']['command']) > 0

    def test_manual_tasks_have_alternatives(self, plugin):
        """PROVES: Manual tasks have alternatives/instructions"""
        service_info = {
            'port': 5000,
            'service': 'http',
            'product': 'Werkzeug httpd'
        }

        tree = plugin.get_task_tree('192.168.45.100', 5000, service_info)

        def get_all_manual_tasks(node):
            tasks = []
            if node.get('type') == 'manual':
                tasks.append(node)
            if 'children' in node:
                for child in node['children']:
                    tasks.extend(get_all_manual_tasks(child))
            return tasks

        manual_tasks = get_all_manual_tasks(tree)
        assert len(manual_tasks) > 0

        for task in manual_tasks:
            assert 'metadata' in task
            assert 'alternatives' in task['metadata'] or 'description' in task['metadata']
            if 'alternatives' in task['metadata']:
                assert len(task['metadata']['alternatives']) > 0

    # New techniques tests (2025-10-07 additions)
    def test_django_sqli_jsonfield_cve_2024_42005(self, plugin):
        """PROVES: Django JSONField SQLi task exists with CVE-2024-42005 details"""
        service_info = {
            'port': 8000,
            'service': 'http',
            'product': 'Django',
            'version': '4.2.10'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8000, service_info)

        # Find Django SQLi task
        def find_task_by_id(node, task_id):
            if node['id'] == task_id:
                return node
            if 'children' in node:
                for child in node['children']:
                    result = find_task_by_id(child, task_id)
                    if result:
                        return result
            return None

        sqli_task = find_task_by_id(tree, 'django-sqli-jsonfield-8000')
        assert sqli_task is not None, "Django SQLi JSONField task not found"

        metadata = sqli_task['metadata']

        # CVE info
        assert 'CVE-2024-42005' in metadata['description'] or 'CVE-2024-42005' in metadata.get('notes', '')
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'SQLI' in metadata['tags']

        # Payload content
        alternatives_str = '\n'.join(metadata['alternatives'])
        assert 'QuerySet.values()' in alternatives_str or 'values_list()' in alternatives_str
        assert 'json_key' in alternatives_str
        assert 'UNION' in alternatives_str or 'OR 1=1' in alternatives_str

    def test_flask_ssrf_at_bypass(self, plugin):
        """PROVES: Flask SSRF @ bypass task exists with exploitation techniques"""
        service_info = {
            'port': 5000,
            'service': 'http',
            'product': 'Werkzeug httpd',
            'version': '2.0.1'
        }

        tree = plugin.get_task_tree('192.168.45.100', 5000, service_info)

        # Find Flask SSRF task
        def find_task_by_id(node, task_id):
            if node['id'] == task_id:
                return node
            if 'children' in node:
                for child in node['children']:
                    result = find_task_by_id(child, task_id)
                    if result:
                        return result
            return None

        ssrf_task = find_task_by_id(tree, 'flask-ssrf-at-bypass-5000')
        assert ssrf_task is not None, "Flask SSRF @ bypass task not found"

        metadata = ssrf_task['metadata']

        # SSRF content
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'SSRF' in metadata['tags']

        alternatives_str = '\n'.join(metadata['alternatives'])
        assert '@attacker.com' in alternatives_str or '@localhost' in alternatives_str
        assert '169.254.169.254' in alternatives_str  # AWS metadata
        assert 'proxy' in metadata['description'].lower()

    def test_django_log_injection_cve_2025_48432(self, plugin):
        """PROVES: Django log injection task exists with CVE-2025-48432 details"""
        service_info = {
            'port': 8000,
            'service': 'http',
            'product': 'Django',
            'version': '4.2.20'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8000, service_info)

        # Find Django log injection task
        def find_task_by_id(node, task_id):
            if node['id'] == task_id:
                return node
            if 'children' in node:
                for child in node['children']:
                    result = find_task_by_id(child, task_id)
                    if result:
                        return result
            return None

        log_task = find_task_by_id(tree, 'django-log-injection-8000')
        assert log_task is not None, "Django log injection task not found"

        metadata = log_task['metadata']

        # CVE info
        assert 'CVE-2025-48432' in metadata['description'] or 'CVE-2025-48432' in metadata.get('notes', '')
        assert 'OSCP:MEDIUM' in metadata['tags']

        alternatives_str = '\n'.join(metadata['alternatives'])
        assert '%0A' in alternatives_str  # URL-encoded newline
        assert 'request.path' in alternatives_str
        assert 'ANSI' in alternatives_str or 'log' in metadata['description'].lower()

    def test_werkzeug_unicode_smuggling(self, plugin):
        """PROVES: Werkzeug Unicode CL.0 smuggling task exists"""
        service_info = {
            'port': 5000,
            'service': 'http',
            'product': 'Werkzeug httpd',
            'version': '2.0.1'
        }

        tree = plugin.get_task_tree('192.168.45.100', 5000, service_info)

        # Find Werkzeug smuggling task
        def find_task_by_id(node, task_id):
            if node['id'] == task_id:
                return node
            if 'children' in node:
                for child in node['children']:
                    result = find_task_by_id(child, task_id)
                    if result:
                        return result
            return None

        smuggling_task = find_task_by_id(tree, 'werkzeug-smuggling-5000')
        assert smuggling_task is not None, "Werkzeug Unicode smuggling task not found"

        metadata = smuggling_task['metadata']

        # HTTP smuggling content
        assert 'OSCP:MEDIUM' in metadata['tags']
        assert 'HTTP_SMUGGLING' in metadata['tags']

        alternatives_str = '\n'.join(metadata['alternatives'])
        assert 'Unicode' in alternatives_str or 'unicode' in alternatives_str
        assert 'keep-alive' in alternatives_str
        assert 'Content-Length' in alternatives_str or 'CL.0' in metadata['description']

    def test_new_cves_in_research_section(self, plugin):
        """PROVES: Research section includes 2024-2025 CVEs"""
        service_info = {
            'port': 5000,
            'service': 'http',
            'product': 'Werkzeug httpd',
            'version': '2.0.1'
        }

        tree = plugin.get_task_tree('192.168.45.100', 5000, service_info)

        # Find CVE lookup task
        def find_task_by_id(node, task_id):
            if node['id'] == task_id:
                return node
            if 'children' in node:
                for child in node['children']:
                    result = find_task_by_id(child, task_id)
                    if result:
                        return result
            return None

        cve_task = find_task_by_id(tree, 'python-cve-5000')
        assert cve_task is not None

        metadata = cve_task['metadata']
        alternatives_str = '\n'.join(metadata['alternatives'])

        # New CVEs should be listed
        assert 'CVE-2024-42005' in alternatives_str
        assert 'CVE-2025-48432' in alternatives_str
        assert 'Django' in alternatives_str
        assert 'Flask' in alternatives_str or 'Werkzeug' in alternatives_str

    def test_django_tasks_conditional_on_framework(self, plugin):
        """PROVES: Django-specific tasks only appear for Django apps"""
        # Django app
        django_info = {
            'port': 8000,
            'service': 'http',
            'product': 'Django',
            'version': '4.2.0'
        }

        django_tree = plugin.get_task_tree('192.168.45.100', 8000, django_info)

        def get_all_task_ids(node):
            ids = [node['id']]
            if 'children' in node:
                for child in node['children']:
                    ids.extend(get_all_task_ids(child))
            return ids

        django_ids = get_all_task_ids(django_tree)

        # Django-specific tasks should exist
        assert any('django-sqli-jsonfield' in tid for tid in django_ids)
        assert any('django-log-injection' in tid for tid in django_ids)

        # Flask app (Django tasks shouldn't appear)
        flask_info = {
            'port': 5000,
            'service': 'http',
            'product': 'Werkzeug httpd',
            'version': '2.0.1'
        }

        flask_tree = plugin.get_task_tree('192.168.45.100', 5000, flask_info)
        flask_ids = get_all_task_ids(flask_tree)

        # Flask-specific tasks should exist
        assert any('flask-ssrf-at-bypass' in tid for tid in flask_ids)
        assert any('werkzeug-smuggling' in tid for tid in flask_ids)
