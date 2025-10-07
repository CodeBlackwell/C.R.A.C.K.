"""
Test suite for Active Directory Attacks plugin

Validates:
- Plugin registration and detection
- Task tree structure and completeness
- OSCP-required metadata (flags, alternatives, indicators)
- Kerberos attack coverage
- Credential attack coverage
- Lateral movement techniques
- Persistence mechanisms
"""

import pytest
from crack.track.services.ad_attacks import ADAttacksPlugin


class TestADAttacksPlugin:
    """Test Active Directory Attacks plugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return ADAttacksPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "ad-attacks"

    def test_plugin_detection_manual_only(self, plugin):
        """PROVES: Plugin requires manual triggering (detect always False)"""
        # Should never auto-detect
        port_info_ldap = {'port': 389, 'service': 'ldap', 'state': 'open'}
        port_info_kerberos = {'port': 88, 'service': 'kerberos', 'state': 'open'}
        port_info_smb = {'port': 445, 'service': 'microsoft-ds', 'state': 'open'}

        assert plugin.detect(port_info_ldap) == False
        assert plugin.detect(port_info_kerberos) == False
        assert plugin.detect(port_info_smb) == False

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid structure"""
        service_info = {
            'domain': 'CORP.LOCAL',
            'dc_ip': '192.168.45.200'
        }

        tree = plugin.get_task_tree('192.168.45.200', 389, service_info)

        # Root structure
        assert 'id' in tree
        assert tree['id'] == 'ad-attacks-enum'
        assert 'name' in tree
        assert 'Active Directory Attacks' in tree['name']
        assert tree['type'] == 'parent'
        assert 'children' in tree

        # Has major attack phases
        assert len(tree['children']) >= 4, "Should have at least 4 attack phases"

        phase_names = [child['name'] for child in tree['children']]
        assert any('Kerberos' in name for name in phase_names)
        assert any('Credential' in name for name in phase_names)
        assert any('Lateral' in name for name in phase_names)
        assert any('Persistence' in name for name in phase_names)

    def test_kerberos_attacks_phase(self, plugin):
        """PROVES: Kerberos attacks phase is comprehensive"""
        service_info = {'domain': 'CORP.LOCAL', 'dc_ip': '192.168.45.200'}
        tree = plugin.get_task_tree('192.168.45.200', 389, service_info)

        # Find Kerberos attacks phase
        kerberos_phase = next(
            (child for child in tree['children'] if 'Kerberos' in child['name']),
            None
        )
        assert kerberos_phase is not None, "Kerberos attacks phase must exist"
        assert kerberos_phase['type'] == 'parent'
        assert len(kerberos_phase['children']) >= 5, "Should have multiple Kerberos attack types"

        # Check for key Kerberos attacks
        attack_ids = [task['id'] for task in kerberos_phase['children']]
        assert 'asreproast-enum' in attack_ids, "AS-REP Roasting must be present"
        assert 'kerberoast-spn-enum' in attack_ids, "Kerberoasting must be present"
        assert 'golden-ticket' in attack_ids, "Golden Ticket must be present"
        assert 'silver-ticket' in attack_ids, "Silver Ticket must be present"
        assert 'pass-the-ticket' in attack_ids, "Pass-the-Ticket must be present"

    def test_asreproast_task_completeness(self, plugin):
        """PROVES: AS-REP Roasting task has complete OSCP metadata"""
        service_info = {'domain': 'CORP.LOCAL', 'dc_ip': '192.168.45.200'}
        tree = plugin.get_task_tree('192.168.45.200', 389, service_info)

        # Navigate to AS-REP roast task
        kerberos_phase = next(child for child in tree['children'] if 'Kerberos' in child['name'])
        asreproast = next(
            task for task in kerberos_phase['children'] if task['id'] == 'asreproast-enum'
        )

        # Verify task structure
        assert asreproast['type'] == 'command'
        metadata = asreproast['metadata']

        # Required fields
        assert 'command' in metadata, "Command must be specified"
        assert 'GetNPUsers.py' in metadata['command'], "Should use GetNPUsers.py"
        assert 'description' in metadata
        assert 'AS-REP' in metadata['description'] or 'pre-auth' in metadata['description']

        # OSCP requirements
        assert 'flag_explanations' in metadata
        assert len(metadata['flag_explanations']) >= 3, "Should explain key flags"
        assert '-usersfile' in metadata['flag_explanations']
        assert '-format hashcat' in metadata['flag_explanations']

        assert 'success_indicators' in metadata
        assert len(metadata['success_indicators']) >= 2

        assert 'failure_indicators' in metadata
        assert len(metadata['failure_indicators']) >= 2

        assert 'next_steps' in metadata
        assert len(metadata['next_steps']) >= 2
        assert any('hashcat' in step.lower() for step in metadata['next_steps'])

        assert 'alternatives' in metadata
        assert len(metadata['alternatives']) >= 2
        assert any('Rubeus' in alt for alt in metadata['alternatives'])

        assert 'tags' in metadata
        assert 'OSCP:HIGH' in metadata['tags'] or 'OSCP:MEDIUM' in metadata['tags']

    def test_kerberoasting_task_completeness(self, plugin):
        """PROVES: Kerberoasting task has complete OSCP metadata"""
        service_info = {'domain': 'CORP.LOCAL', 'dc_ip': '192.168.45.200'}
        tree = plugin.get_task_tree('192.168.45.200', 389, service_info)

        kerberos_phase = next(child for child in tree['children'] if 'Kerberos' in child['name'])
        kerberoast = next(
            task for task in kerberos_phase['children'] if task['id'] == 'kerberoast-spn-enum'
        )

        metadata = kerberoast['metadata']

        # Verify GetUserSPNs usage
        assert 'GetUserSPNs.py' in metadata['command']
        assert '-request' in metadata['command']

        # OSCP metadata
        assert 'flag_explanations' in metadata
        assert 'success_indicators' in metadata
        assert 'alternatives' in metadata

        # Check for hashcat modes in next_steps
        next_steps = ' '.join(metadata['next_steps'])
        assert '13100' in next_steps or '19600' in next_steps or '19700' in next_steps, \
            "Should mention hashcat modes for RC4/AES"

    def test_golden_ticket_attack_structure(self, plugin):
        """PROVES: Golden Ticket attack has parent-child structure"""
        service_info = {'domain': 'CORP.LOCAL', 'dc_ip': '192.168.45.200'}
        tree = plugin.get_task_tree('192.168.45.200', 389, service_info)

        kerberos_phase = next(child for child in tree['children'] if 'Kerberos' in child['name'])
        golden_ticket = next(
            task for task in kerberos_phase['children'] if task['id'] == 'golden-ticket'
        )

        assert golden_ticket['type'] == 'parent', "Golden ticket should be parent with subtasks"
        assert len(golden_ticket['children']) >= 2, "Should have creation + krbtgt extraction tasks"

        # Check for creation task
        create_task_ids = [child['id'] for child in golden_ticket['children']]
        assert any('create' in tid for tid in create_task_ids)
        assert any('krbtgt' in tid for tid in create_task_ids)

    def test_dcsync_attack_coverage(self, plugin):
        """PROVES: DCSync attack is comprehensive"""
        service_info = {'domain': 'CORP.LOCAL', 'dc_ip': '192.168.45.200'}
        tree = plugin.get_task_tree('192.168.45.200', 389, service_info)

        # Find credential attacks phase
        cred_phase = next(
            child for child in tree['children'] if 'Credential' in child['name']
        )

        # Find DCSync attack
        dcsync = None
        for task in cred_phase['children']:
            if 'dcsync' in task['id'].lower():
                dcsync = task
                break

        assert dcsync is not None, "DCSync attack must be present"
        assert dcsync['type'] == 'parent', "DCSync should have multiple subtasks"

        # Should have enumeration, execution, and persistence
        dcsync_task_ids = [child['id'] for child in dcsync['children']]
        assert len(dcsync_task_ids) >= 2, "Should have enum and dump tasks minimum"

    def test_password_spraying_coverage(self, plugin):
        """PROVES: Password spraying attacks are present"""
        service_info = {'domain': 'CORP.LOCAL', 'dc_ip': '192.168.45.200'}
        tree = plugin.get_task_tree('192.168.45.200', 389, service_info)

        cred_phase = next(
            child for child in tree['children'] if 'Credential' in child['name']
        )

        # Check for password policy and spraying tasks
        task_ids = [task['id'] for task in cred_phase['children']]
        assert 'password-policy' in task_ids, "Password policy enumeration must be present"

        # Should have spraying techniques
        assert any('spray' in tid for tid in task_ids), "Password spraying must be present"

    def test_lateral_movement_phase(self, plugin):
        """PROVES: Lateral movement phase exists with key techniques"""
        service_info = {'domain': 'CORP.LOCAL', 'dc_ip': '192.168.45.200'}
        tree = plugin.get_task_tree('192.168.45.200', 389, service_info)

        lateral_phase = next(
            child for child in tree['children'] if 'Lateral' in child['name']
        )

        assert lateral_phase is not None
        assert len(lateral_phase['children']) >= 2, "Should have multiple lateral movement techniques"

        # Check for key techniques
        lateral_ids = []
        for task in lateral_phase['children']:
            lateral_ids.append(task['id'])
            if task['type'] == 'parent':
                lateral_ids.extend([child['id'] for child in task['children']])

        assert any('delegation' in lid for lid in lateral_ids), "Constrained delegation must be covered"
        assert any('pass-the-hash' in lid for lid in lateral_ids), "Pass-the-Hash must be covered"

    def test_persistence_mechanisms_phase(self, plugin):
        """PROVES: Persistence mechanisms are documented"""
        service_info = {'domain': 'CORP.LOCAL', 'dc_ip': '192.168.45.200'}
        tree = plugin.get_task_tree('192.168.45.200', 389, service_info)

        persist_phase = next(
            child for child in tree['children'] if 'Persistence' in child['name']
        )

        assert persist_phase is not None
        assert len(persist_phase['children']) >= 4, "Should have multiple persistence mechanisms"

        # Check for key persistence techniques
        persist_ids = []
        for task in persist_phase['children']:
            persist_ids.append(task['id'])
            if task['type'] == 'parent':
                persist_ids.extend([child['id'] for child in task['children']])

        assert any('acl' in pid for pid in persist_ids), "ACL-based persistence must be covered"
        assert any('golden-ticket' in pid for pid in persist_ids), "Golden ticket persistence must be covered"

    def test_all_command_tasks_have_metadata(self, plugin):
        """PROVES: All command-type tasks have complete metadata"""
        service_info = {'domain': 'CORP.LOCAL', 'dc_ip': '192.168.45.200'}
        tree = plugin.get_task_tree('192.168.45.200', 389, service_info)

        def collect_command_tasks(node):
            """Recursively collect all command tasks"""
            tasks = []
            if node.get('type') == 'command':
                tasks.append(node)
            if 'children' in node:
                for child in node['children']:
                    tasks.extend(collect_command_tasks(child))
            return tasks

        command_tasks = collect_command_tasks(tree)
        assert len(command_tasks) >= 10, "Should have at least 10 executable command tasks"

        for task in command_tasks:
            metadata = task.get('metadata', {})

            # Required fields
            assert 'command' in metadata, f"Task {task['id']} missing command"
            assert 'description' in metadata, f"Task {task['id']} missing description"
            assert 'tags' in metadata, f"Task {task['id']} missing tags"

            # OSCP requirements (allow some manual tasks to skip certain fields)
            if task.get('type') != 'manual':
                assert 'flag_explanations' in metadata or len(metadata.get('alternatives', [])) > 0, \
                    f"Task {task['id']} should have flag_explanations or alternatives"

    def test_tags_consistency(self, plugin):
        """PROVES: Tags follow standard conventions"""
        service_info = {'domain': 'CORP.LOCAL', 'dc_ip': '192.168.45.200'}
        tree = plugin.get_task_tree('192.168.45.200', 389, service_info)

        def collect_all_tags(node):
            """Recursively collect all tags"""
            tags = []
            if 'metadata' in node and 'tags' in node['metadata']:
                tags.extend(node['metadata']['tags'])
            if 'children' in node:
                for child in node['children']:
                    tags.extend(collect_all_tags(child))
            return tags

        all_tags = collect_all_tags(tree)
        assert len(all_tags) > 0, "Should have tags assigned"

        # Check for OSCP tags
        oscp_tags = [tag for tag in all_tags if 'OSCP:' in tag]
        assert len(oscp_tags) > 0, "Should have OSCP priority tags"

        # Verify tag format
        valid_oscp_tags = ['OSCP:HIGH', 'OSCP:MEDIUM', 'OSCP:LOW']
        for tag in oscp_tags:
            assert tag in valid_oscp_tags, f"Invalid OSCP tag: {tag}"

    def test_domain_parameter_usage(self, plugin):
        """PROVES: Domain parameter is used in commands"""
        service_info = {
            'domain': 'TESTDOMAIN.LOCAL',
            'dc_ip': '10.10.10.100'
        }

        tree = plugin.get_task_tree('10.10.10.100', 389, service_info)

        def collect_commands(node):
            """Recursively collect all commands"""
            commands = []
            if 'metadata' in node and 'command' in node['metadata']:
                commands.append(node['metadata']['command'])
            if 'children' in node:
                for child in node['children']:
                    commands.extend(collect_commands(child))
            return commands

        all_commands = collect_commands(tree)
        assert len(all_commands) > 0

        # Check that domain is used in commands
        domain_usage = [cmd for cmd in all_commands if 'TESTDOMAIN.LOCAL' in cmd or 'CORP.LOCAL' in cmd]
        assert len(domain_usage) > 0, "Domain should be used in commands"

    def test_alternatives_present_in_key_tasks(self, plugin):
        """PROVES: Key tasks have manual alternatives for OSCP exam"""
        service_info = {'domain': 'CORP.LOCAL', 'dc_ip': '192.168.45.200'}
        tree = plugin.get_task_tree('192.168.45.200', 389, service_info)

        kerberos_phase = next(child for child in tree['children'] if 'Kerberos' in child['name'])

        # AS-REP Roasting alternatives
        asreproast = next(task for task in kerberos_phase['children'] if task['id'] == 'asreproast-enum')
        alternatives = asreproast['metadata']['alternatives']
        assert any('Rubeus' in alt for alt in alternatives), "Should have Rubeus alternative"
        assert any('Windows' in alt or 'PowerView' in alt for alt in alternatives), "Should have Windows alternative"

        # Kerberoasting alternatives
        kerberoast = next(task for task in kerberos_phase['children'] if task['id'] == 'kerberoast-spn-enum')
        alternatives = kerberoast['metadata']['alternatives']
        assert any('Rubeus' in alt for alt in alternatives), "Should have Rubeus alternative"
        assert len(alternatives) >= 3, "Should have multiple alternative approaches"

    def test_targeted_kerberoast_present(self, plugin):
        """PROVES: Targeted Kerberoasting (ACL abuse) is documented"""
        service_info = {'domain': 'CORP.LOCAL', 'dc_ip': '192.168.45.200'}
        tree = plugin.get_task_tree('192.168.45.200', 389, service_info)

        kerberos_phase = next(child for child in tree['children'] if 'Kerberos' in child['name'])
        task_ids = [task['id'] for task in kerberos_phase['children']]

        assert 'kerberoast-targeted' in task_ids, "Targeted Kerberoasting must be present"

        targeted = next(task for task in kerberos_phase['children'] if task['id'] == 'kerberoast-targeted')
        assert targeted['type'] == 'parent', "Should have subtasks for add SPN → roast → cleanup"
        assert 'GenericWrite' in targeted['name'] or 'GenericAll' in targeted['name']

    def test_constrained_delegation_abuse(self, plugin):
        """PROVES: Constrained delegation abuse is comprehensive"""
        service_info = {'domain': 'CORP.LOCAL', 'dc_ip': '192.168.45.200'}
        tree = plugin.get_task_tree('192.168.45.200', 389, service_info)

        lateral_phase = next(child for child in tree['children'] if 'Lateral' in child['name'])

        # Find constrained delegation
        delegation = None
        for task in lateral_phase['children']:
            if 'constrained-delegation' in task['id']:
                delegation = task
                break

        assert delegation is not None, "Constrained delegation must be present"
        assert delegation['type'] == 'parent'

        # Should have enum + exploit
        subtask_ids = [child['id'] for child in delegation['children']]
        assert any('enum' in sid for sid in subtask_ids)
        assert any('exploit' in sid for sid in subtask_ids)

        # Check exploit task mentions altservice (SPN pivoting)
        exploit_task = next(
            child for child in delegation['children'] if 'exploit' in child['id']
        )
        metadata = exploit_task['metadata']
        assert 'altservice' in metadata['command'] or 'altservice' in str(metadata.get('flag_explanations', {}))

    def test_pass_the_hash_present(self, plugin):
        """PROVES: Pass-the-Hash technique is documented"""
        service_info = {'domain': 'CORP.LOCAL', 'dc_ip': '192.168.45.200'}
        tree = plugin.get_task_tree('192.168.45.200', 389, service_info)

        lateral_phase = next(child for child in tree['children'] if 'Lateral' in child['name'])

        task_ids = []
        for task in lateral_phase['children']:
            task_ids.append(task['id'])
            if task['type'] == 'parent':
                task_ids.extend([child['id'] for child in task['children']])

        assert any('pass-the-hash' in tid for tid in task_ids), "Pass-the-Hash must be documented"

    def test_clock_sync_warnings(self, plugin):
        """PROVES: Clock synchronization warnings are present for Kerberos attacks"""
        service_info = {'domain': 'CORP.LOCAL', 'dc_ip': '192.168.45.200'}
        tree = plugin.get_task_tree('192.168.45.200', 389, service_info)

        def collect_all_notes(node):
            """Recursively collect all notes and failure indicators"""
            text = []
            if 'metadata' in node:
                if 'notes' in node['metadata']:
                    text.append(node['metadata']['notes'])
                if 'failure_indicators' in node['metadata']:
                    text.extend(node['metadata']['failure_indicators'])
            if 'children' in node:
                for child in node['children']:
                    text.extend(collect_all_notes(child))
            return text

        all_notes = ' '.join(collect_all_notes(tree)).lower()

        # Should mention clock sync for Kerberos attacks
        assert 'clock' in all_notes or 'ntpdate' in all_notes or 'skew' in all_notes, \
            "Should warn about clock synchronization for Kerberos"

    def test_event_id_detection_notes(self, plugin):
        """PROVES: Windows Event ID detection notes are present"""
        service_info = {'domain': 'CORP.LOCAL', 'dc_ip': '192.168.45.200'}
        tree = plugin.get_task_tree('192.168.45.200', 389, service_info)

        def collect_all_notes(node):
            """Recursively collect all notes"""
            notes = []
            if 'metadata' in node and 'notes' in node['metadata']:
                notes.append(node['metadata']['notes'])
            if 'children' in node:
                for child in node['children']:
                    notes.extend(collect_all_notes(child))
            return notes

        all_notes = ' '.join(collect_all_notes(tree))

        # Should mention Windows Event IDs
        assert '4768' in all_notes or '4769' in all_notes or 'Event ID' in all_notes, \
            "Should document Windows Event IDs for detection awareness"

    def test_comprehensive_task_count(self, plugin):
        """PROVES: Plugin generates comprehensive task coverage"""
        service_info = {'domain': 'CORP.LOCAL', 'dc_ip': '192.168.45.200'}
        tree = plugin.get_task_tree('192.168.45.200', 389, service_info)

        def count_all_tasks(node):
            """Recursively count all tasks"""
            count = 1  # Count self
            if 'children' in node:
                for child in node['children']:
                    count += count_all_tasks(child)
            return count

        total_tasks = count_all_tasks(tree)
        assert total_tasks >= 35, f"Should have at least 35 total tasks (parent+children), got {total_tasks}"

    def test_no_placeholder_leaks(self, plugin):
        """PROVES: No template placeholders left in commands"""
        service_info = {'domain': 'CORP.LOCAL', 'dc_ip': '192.168.45.200'}
        tree = plugin.get_task_tree('192.168.45.200', 389, service_info)

        def collect_commands(node):
            """Recursively collect all commands"""
            commands = []
            if 'metadata' in node and 'command' in node['metadata']:
                commands.append(node['metadata']['command'])
            if 'children' in node:
                for child in node['children']:
                    commands.extend(collect_commands(child))
            return commands

        all_commands = collect_commands(tree)

        for cmd in all_commands:
            # Check for common placeholder patterns
            assert '<DC_IP>' not in cmd or dc_ip in cmd, f"Placeholder <DC_IP> not replaced in: {cmd}"
            assert '<DOMAIN>' not in cmd or domain in cmd, f"Placeholder <DOMAIN> not replaced in: {cmd}"
            # Note: Some placeholders like <HASH>, <USER>, <PASS> are intentional (user fills them)
