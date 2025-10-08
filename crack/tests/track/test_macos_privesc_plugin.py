"""
Test suite for macOS Privilege Escalation plugin

Validates:
- Service detection logic
- Task tree generation
- OSCP-required metadata completeness
- Educational content quality
"""

import pytest
from crack.track.services.macos_privesc import MacOSPrivEscPlugin


class TestMacOSPrivEscPlugin:
    """Test macOS privilege escalation plugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return MacOSPrivEscPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "macos-privesc"

    def test_default_ports(self, plugin):
        """PROVES: Plugin defines macOS-relevant ports"""
        assert isinstance(plugin.default_ports, list)
        assert len(plugin.default_ports) > 0
        assert 22 in plugin.default_ports  # SSH
        assert 548 in plugin.default_ports  # AFP
        assert 5900 in plugin.default_ports  # VNC

    def test_service_names(self, plugin):
        """PROVES: Plugin recognizes macOS service names"""
        assert isinstance(plugin.service_names, list)
        assert 'ssh' in plugin.service_names
        assert 'afp' in plugin.service_names
        assert 'vnc' in plugin.service_names

    # Detection Tests
    def test_detect_ssh_service(self, plugin):
        """PROVES: Plugin detects SSH (common macOS access)"""
        port_info = {
            'port': 22,
            'service': 'ssh',
            'product': 'OpenSSH'
        }
        assert plugin.detect(port_info) == True

    def test_detect_afp_service(self, plugin):
        """PROVES: Plugin detects AFP (Apple Filing Protocol)"""
        port_info = {
            'port': 548,
            'service': 'afp',
            'product': 'Apple AFP'
        }
        assert plugin.detect(port_info) == True

    def test_detect_vnc_service(self, plugin):
        """PROVES: Plugin detects VNC (Screen Sharing)"""
        port_info = {
            'port': 5900,
            'service': 'vnc',
            'product': 'Apple VNC'
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_port_afp(self, plugin):
        """PROVES: Plugin detects AFP by port number"""
        port_info = {
            'port': 548,
            'service': 'unknown'
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_port_vnc(self, plugin):
        """PROVES: Plugin detects VNC by port number"""
        port_info = {
            'port': 5900,
            'service': 'unknown'
        }
        assert plugin.detect(port_info) == True

    def test_detect_apple_product(self, plugin):
        """PROVES: Plugin detects macOS by product name"""
        port_info = {
            'port': 445,
            'service': 'smb',
            'product': 'Apple SMB'
        }
        assert plugin.detect(port_info) == True

    def test_detect_negative_unrelated_service(self, plugin):
        """PROVES: Plugin rejects non-macOS services"""
        port_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache'
        }
        assert plugin.detect(port_info) == False

    # Task Tree Structure Tests
    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid root structure"""
        service_info = {
            'port': 22,
            'service': 'ssh',
            'version': '8.1',
            'product': 'OpenSSH'
        }
        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        # Root structure validation
        assert 'id' in tree
        assert tree['id'] == 'macos-privesc-22'
        assert 'name' in tree
        assert 'macOS Privilege Escalation' in tree['name']
        assert 'type' in tree
        assert tree['type'] == 'parent'
        assert 'children' in tree
        assert isinstance(tree['children'], list)
        assert len(tree['children']) > 0

    def test_task_tree_phases(self, plugin):
        """PROVES: Task tree contains all major privesc phases"""
        service_info = {
            'port': 22,
            'service': 'ssh',
            'version': '8.1'
        }
        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        # Extract phase names
        phase_names = [child['name'] for child in tree['children']]

        # Verify key phases present
        assert any('Reconnaissance' in name for name in phase_names), "Missing initial recon phase"
        assert any('Password' in name or 'Credential' in name for name in phase_names), "Missing password extraction"
        assert any('TCC' in name for name in phase_names), "Missing TCC enumeration"
        assert any('Sensitive' in name for name in phase_names), "Missing sensitive locations"
        assert any('Persistence' in name for name in phase_names), "Missing persistence mechanisms"
        assert any('User Interaction' in name for name in phase_names), "Missing user interaction attacks"
        assert any('Application' in name for name in phase_names), "Missing application abuse"

    def test_task_tree_includes_exploit_research(self, plugin):
        """PROVES: Exploit research phase added when version known"""
        service_info = {
            'port': 22,
            'service': 'ssh',
            'version': '13.4',
            'product': 'macOS'
        }
        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        phase_names = [child['name'] for child in tree['children']]
        assert any('Exploit Research' in name for name in phase_names), "Missing exploit research for known version"

    # Initial Recon Phase Tests
    def test_initial_recon_tasks(self, plugin):
        """PROVES: Initial reconnaissance includes critical enumeration"""
        service_info = {'port': 22, 'service': 'ssh'}
        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        # Find initial recon phase
        recon_phase = next((child for child in tree['children'] if 'Reconnaissance' in child['name']), None)
        assert recon_phase is not None, "Initial recon phase not found"
        assert recon_phase['type'] == 'parent'
        assert len(recon_phase['children']) > 0

        # Check for key recon tasks
        task_ids = [task['id'] for task in recon_phase['children']]
        assert 'macos-version-check' in task_ids, "Version check missing"
        assert 'macos-sip-check' in task_ids, "SIP check missing"
        assert 'macos-user-enum' in task_ids, "User enumeration missing"

    def test_version_check_metadata(self, plugin):
        """PROVES: Version check has complete OSCP metadata"""
        service_info = {'port': 22, 'service': 'ssh'}
        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        recon_phase = next((child for child in tree['children'] if 'Reconnaissance' in child['name']), None)
        version_check = next((task for task in recon_phase['children'] if task['id'] == 'macos-version-check'), None)

        assert version_check is not None
        metadata = version_check['metadata']

        # Required OSCP fields
        assert 'command' in metadata
        assert metadata['command'] == 'sw_vers'
        assert 'description' in metadata
        assert 'flag_explanations' in metadata
        assert 'success_indicators' in metadata
        assert len(metadata['success_indicators']) >= 2
        assert 'failure_indicators' in metadata
        assert len(metadata['failure_indicators']) >= 1
        assert 'next_steps' in metadata
        assert len(metadata['next_steps']) >= 2
        assert 'alternatives' in metadata
        assert len(metadata['alternatives']) >= 2
        assert 'tags' in metadata
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'QUICK_WIN' in metadata['tags']

    # Password Extraction Phase Tests
    def test_password_extraction_tasks(self, plugin):
        """PROVES: Password extraction includes all major techniques"""
        service_info = {'port': 22, 'service': 'ssh'}
        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        password_phase = next((child for child in tree['children']
                               if 'Password' in child['name'] or 'Credential' in child['name']), None)
        assert password_phase is not None
        assert password_phase['type'] == 'parent'

        task_ids = [task['id'] for task in password_phase['children']]
        assert 'macos-shadow-dump' in task_ids, "Shadow password dump missing"
        assert 'macos-kcpassword-check' in task_ids, "kcpassword check missing"
        assert 'macos-keychain-dump' in task_ids, "Keychain dump missing"
        assert 'macos-ssh-keys' in task_ids, "SSH key search missing"
        assert 'macos-bash-history' in task_ids, "Bash history search missing"

    def test_shadow_dump_command(self, plugin):
        """PROVES: Shadow dump command is comprehensive"""
        service_info = {'port': 22, 'service': 'ssh'}
        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        password_phase = next((child for child in tree['children'] if 'Password' in child['name']), None)
        shadow_dump = next((task for task in password_phase['children'] if task['id'] == 'macos-shadow-dump'), None)

        assert shadow_dump is not None
        metadata = shadow_dump['metadata']
        assert 'command' in metadata
        assert '/var/db/dslocal/nodes/Default/users' in metadata['command']
        assert 'SALTED-SHA512-PBKDF2' in metadata['command']
        assert 'hashcat' in metadata['description'].lower()

    def test_kcpassword_metadata(self, plugin):
        """PROVES: kcpassword task explains XOR decryption"""
        service_info = {'port': 22, 'service': 'ssh'}
        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        password_phase = next((child for child in tree['children'] if 'Password' in child['name']), None)
        kcpassword_task = next((task for task in password_phase['children']
                                if task['id'] == 'macos-kcpassword-check'), None)

        assert kcpassword_task is not None
        metadata = kcpassword_task['metadata']
        assert '/etc/kcpassword' in metadata['command']
        assert 'xor' in metadata['description'].lower()
        # Check for XOR key in flag explanations (either in keys or values)
        flag_text = ' '.join(str(k) + ' ' + str(v) for k, v in metadata['flag_explanations'].items())
        assert '0x7D' in flag_text or 'XOR' in flag_text.upper()

    # TCC Enumeration Phase Tests
    def test_tcc_enumeration_tasks(self, plugin):
        """PROVES: TCC enumeration includes database queries and bypasses"""
        service_info = {'port': 22, 'service': 'ssh'}
        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        tcc_phase = next((child for child in tree['children'] if 'TCC' in child['name']), None)
        assert tcc_phase is not None
        assert tcc_phase['type'] == 'parent'

        task_ids = [task['id'] for task in tcc_phase['children']]
        assert 'macos-tcc-user-db' in task_ids, "User TCC DB query missing"
        assert 'macos-tcc-fda-apps' in task_ids, "FDA apps enumeration missing"

    def test_tcc_bypass_techniques(self, plugin):
        """PROVES: TCC bypass techniques are documented"""
        service_info = {'port': 22, 'service': 'ssh'}
        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        tcc_phase = next((child for child in tree['children'] if 'TCC' in child['name']), None)
        task_ids = [task['id'] for task in tcc_phase['children']]

        # Check for bypass techniques
        assert any('bypass' in task_id for task_id in task_ids), "No TCC bypass techniques found"
        assert 'macos-tcc-bypass-terminal' in task_ids, "Terminal TCC bypass missing"
        assert 'macos-tcc-bypass-dot-terminal' in task_ids, ".terminal file bypass missing"

    def test_fda_apps_query(self, plugin):
        """PROVES: FDA apps query targets Full Disk Access permissions"""
        service_info = {'port': 22, 'service': 'ssh'}
        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        tcc_phase = next((child for child in tree['children'] if 'TCC' in child['name']), None)
        fda_task = next((task for task in tcc_phase['children'] if task['id'] == 'macos-tcc-fda-apps'), None)

        assert fda_task is not None
        metadata = fda_task['metadata']
        assert 'kTCCServiceSystemPolicyAllFiles' in metadata['command']
        assert 'Full Disk Access' in metadata['description']

    # Sensitive Locations Phase Tests
    def test_sensitive_locations_tasks(self, plugin):
        """PROVES: Sensitive locations include key databases and files"""
        service_info = {'port': 22, 'service': 'ssh'}
        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        sensitive_phase = next((child for child in tree['children'] if 'Sensitive' in child['name']), None)
        assert sensitive_phase is not None

        task_ids = [task['id'] for task in sensitive_phase['children']]
        assert 'macos-messages-db' in task_ids, "Messages DB extraction missing"
        assert 'macos-notes-db' in task_ids, "Notes DB extraction missing"
        assert 'macos-notifications-db' in task_ids, "Notifications DB missing"
        assert 'macos-config-files' in task_ids, "Config file search missing"

    def test_messages_db_command(self, plugin):
        """PROVES: Messages database query is properly formatted"""
        service_info = {'port': 22, 'service': 'ssh'}
        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        sensitive_phase = next((child for child in tree['children'] if 'Sensitive' in child['name']), None)
        messages_task = next((task for task in sensitive_phase['children']
                              if task['id'] == 'macos-messages-db'), None)

        assert messages_task is not None
        metadata = messages_task['metadata']
        assert 'Library/Messages/chat.db' in metadata['command']
        assert 'sqlite3' in metadata['command']

    # Persistence Phase Tests
    def test_persistence_mechanisms(self, plugin):
        """PROVES: Persistence includes LaunchAgents, shell, and other methods"""
        service_info = {'port': 22, 'service': 'ssh'}
        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        persistence_phase = next((child for child in tree['children'] if 'Persistence' in child['name']), None)
        assert persistence_phase is not None

        task_ids = [task['id'] for task in persistence_phase['children']]
        assert 'macos-launchagents-enum' in task_ids, "LaunchAgents enum missing"
        assert 'macos-create-launchagent' in task_ids, "LaunchAgent creation missing"
        assert 'macos-shell-persistence' in task_ids, "Shell startup persistence missing"

    def test_launchagent_example_plist(self, plugin):
        """PROVES: LaunchAgent task includes example plist"""
        service_info = {'port': 22, 'service': 'ssh'}
        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        persistence_phase = next((child for child in tree['children'] if 'Persistence' in child['name']), None)
        launchagent_task = next((task for task in persistence_phase['children']
                                 if task['id'] == 'macos-create-launchagent'), None)

        assert launchagent_task is not None
        metadata = launchagent_task['metadata']
        assert 'notes' in metadata
        assert '<?xml' in metadata['notes']
        assert 'plist' in metadata['notes']
        assert 'Label' in metadata['notes']
        assert 'RunAtLoad' in metadata['notes']

    # User Interaction Phase Tests
    def test_user_interaction_attacks(self, plugin):
        """PROVES: User interaction attacks include social engineering"""
        service_info = {'port': 22, 'service': 'ssh'}
        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        user_phase = next((child for child in tree['children'] if 'User Interaction' in child['name']), None)
        assert user_phase is not None

        task_ids = [task['id'] for task in user_phase['children']]
        assert 'macos-sudo-hijack' in task_ids, "Sudo hijacking missing"
        assert 'macos-dock-impersonation' in task_ids, "Dock impersonation missing"
        assert 'macos-fake-update-prompt' in task_ids, "Fake prompt missing"

    def test_sudo_hijack_explanation(self, plugin):
        """PROVES: Sudo hijack explains PATH preservation"""
        service_info = {'port': 22, 'service': 'ssh'}
        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        user_phase = next((child for child in tree['children'] if 'User Interaction' in child['name']), None)
        sudo_task = next((task for task in user_phase['children'] if task['id'] == 'macos-sudo-hijack'), None)

        assert sudo_task is not None
        metadata = sudo_task['metadata']
        assert 'notes' in metadata
        assert 'PATH' in metadata['notes']
        assert '/opt/homebrew/bin' in metadata['notes']

    # Application Abuse Phase Tests
    def test_application_abuse_tasks(self, plugin):
        """PROVES: Application abuse includes Terminal and preference manipulation"""
        service_info = {'port': 22, 'service': 'ssh'}
        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        app_phase = next((child for child in tree['children'] if 'Application' in child['name']), None)
        assert app_phase is not None

        task_ids = [task['id'] for task in app_phase['children']]
        assert 'macos-terminal-startup' in task_ids, "Terminal startup abuse missing"

    # Exploit Research Tests
    def test_exploit_research_structure(self, plugin):
        """PROVES: Exploit research includes searchsploit and CVE lookup"""
        service_info = {
            'port': 22,
            'service': 'ssh',
            'version': '13.4',
            'product': 'macOS'
        }
        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        exploit_phase = next((child for child in tree['children'] if 'Exploit Research' in child['name']), None)
        assert exploit_phase is not None
        assert exploit_phase['type'] == 'parent'

        task_ids = [task['id'] for task in exploit_phase['children']]
        assert any('searchsploit' in task_id for task_id in task_ids)
        assert any('cve' in task_id for task_id in task_ids)
        assert any('github' in task_id for task_id in task_ids)

    # OSCP Metadata Quality Tests
    def test_all_command_tasks_have_required_metadata(self, plugin):
        """PROVES: All command tasks have complete OSCP metadata"""
        service_info = {'port': 22, 'service': 'ssh', 'version': '13.4'}
        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        def check_command_tasks(node):
            """Recursively check all command tasks"""
            issues = []

            if node.get('type') == 'command':
                metadata = node.get('metadata', {})

                # Required fields
                if 'command' not in metadata:
                    issues.append(f"Task {node['id']}: Missing 'command'")
                if 'description' not in metadata:
                    issues.append(f"Task {node['id']}: Missing 'description'")
                if 'flag_explanations' not in metadata:
                    issues.append(f"Task {node['id']}: Missing 'flag_explanations'")
                if 'alternatives' not in metadata:
                    issues.append(f"Task {node['id']}: Missing 'alternatives'")
                if 'tags' not in metadata:
                    issues.append(f"Task {node['id']}: Missing 'tags'")

                # Quality checks
                if metadata.get('alternatives') and len(metadata['alternatives']) < 1:
                    issues.append(f"Task {node['id']}: Need at least 1 alternative")

            # Recurse into children
            if 'children' in node:
                for child in node['children']:
                    issues.extend(check_command_tasks(child))

            return issues

        issues = check_command_tasks(tree)
        assert len(issues) == 0, f"Metadata issues found:\n" + "\n".join(issues)

    def test_tags_are_consistent(self, plugin):
        """PROVES: Tags use consistent naming convention"""
        service_info = {'port': 22, 'service': 'ssh', 'version': '13.4'}
        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        valid_tag_prefixes = [
            'OSCP:', 'QUICK_WIN', 'MANUAL', 'AUTOMATED', 'NOISY', 'STEALTH',
            'RECON', 'ENUM', 'EXPLOIT', 'PRIVESC', 'POST_EXPLOIT',
            'RESEARCH', 'BRUTE_FORCE', 'VULN_SCAN', 'TCC', 'PERSISTENCE',
            'USER_INTERACTION', 'SOCIAL_ENGINEERING', 'APP_ABUSE', 'SENSITIVE',
            'REQUIRES_ROOT', 'ADVANCED'
        ]

        def check_tags(node):
            """Recursively check tag validity"""
            invalid_tags = []

            if 'metadata' in node and 'tags' in node['metadata']:
                for tag in node['metadata']['tags']:
                    if not any(tag.startswith(prefix) or tag == prefix for prefix in valid_tag_prefixes):
                        invalid_tags.append(f"Task {node['id']}: Invalid tag '{tag}'")

            if 'children' in node:
                for child in node['children']:
                    invalid_tags.extend(check_tags(child))

            return invalid_tags

        invalid = check_tags(tree)
        assert len(invalid) == 0, f"Invalid tags found:\n" + "\n".join(invalid)

    def test_high_value_tasks_marked_correctly(self, plugin):
        """PROVES: High-value tasks have OSCP:HIGH or QUICK_WIN tags"""
        service_info = {'port': 22, 'service': 'ssh'}
        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        # Find high-value tasks by ID
        high_value_task_ids = [
            'macos-version-check',
            'macos-sip-check',
            'macos-shadow-dump',
            'macos-kcpassword-check',
            'macos-tcc-fda-apps',
            'macos-ssh-keys'
        ]

        def find_task_by_id(node, task_id):
            """Recursively find task by ID"""
            if node.get('id') == task_id:
                return node
            if 'children' in node:
                for child in node['children']:
                    result = find_task_by_id(child, task_id)
                    if result:
                        return result
            return None

        for task_id in high_value_task_ids:
            task = find_task_by_id(tree, task_id)
            if task and 'metadata' in task and 'tags' in task['metadata']:
                tags = task['metadata']['tags']
                assert any(tag in ['OSCP:HIGH', 'QUICK_WIN'] for tag in tags), \
                    f"High-value task {task_id} should have OSCP:HIGH or QUICK_WIN tag"

    def test_plugin_comprehensive_coverage(self, plugin):
        """PROVES: Plugin provides comprehensive macOS privesc coverage"""
        service_info = {'port': 22, 'service': 'ssh', 'version': '13.4'}
        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        # Count total tasks
        def count_tasks(node):
            count = 1  # Count current node
            if 'children' in node:
                for child in node['children']:
                    count += count_tasks(child)
            return count

        total_tasks = count_tasks(tree)

        # Should have substantial task coverage
        assert total_tasks >= 30, f"Expected at least 30 tasks for comprehensive coverage, got {total_tasks}"

        # Should have multiple phases
        assert len(tree['children']) >= 7, "Expected at least 7 major phases"

    def test_educational_quality(self, plugin):
        """PROVES: Plugin provides educational value for OSCP preparation"""
        service_info = {'port': 22, 'service': 'ssh'}
        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        # Check for educational notes
        def check_educational_content(node):
            """Check for educational metadata"""
            has_education = False

            if 'metadata' in node:
                metadata = node['metadata']
                # Educational indicators
                if any(key in metadata for key in ['notes', 'next_steps', 'success_indicators', 'failure_indicators']):
                    has_education = True

            return has_education

        # Sample some tasks
        recon_phase = tree['children'][0]
        if 'children' in recon_phase and len(recon_phase['children']) > 0:
            first_task = recon_phase['children'][0]
            assert check_educational_content(first_task), "Tasks should have educational content"
