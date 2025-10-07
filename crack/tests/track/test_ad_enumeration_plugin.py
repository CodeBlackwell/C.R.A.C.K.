"""
Test suite for AD Enumeration Plugin

Tests comprehensive Active Directory enumeration task generation
including user enumeration, password attacks, BloodHound, ADWS, and post-compromise
"""

import pytest
from crack.track.services.ad_enumeration import ADEnumerationPlugin


class TestADEnumerationPlugin:
    """Test AD enumeration plugin functionality"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return ADEnumerationPlugin()

    @pytest.fixture
    def ad_service_info(self):
        """Mock AD service information"""
        return {
            'port': 88,
            'service': 'kerberos',
            'version': 'Microsoft Windows Kerberos',
            'domain': 'corp.local'
        }

    def test_plugin_registration(self, plugin):
        """PROVES: Plugin registers correctly"""
        assert plugin.name == "ad-enumeration"
        assert isinstance(plugin.default_ports, list)
        assert 88 in plugin.default_ports
        assert 389 in plugin.default_ports
        assert 9389 in plugin.default_ports  # ADWS

    def test_service_names(self, plugin):
        """PROVES: Plugin recognizes AD service names"""
        service_names = plugin.service_names
        assert 'kerberos' in service_names
        assert 'ldap' in service_names
        assert 'active-directory' in service_names

    def test_detect_method_returns_false(self, plugin, ad_service_info):
        """PROVES: Plugin requires manual trigger (complex enumeration)"""
        # AD enumeration should be manually triggered
        result = plugin.detect({'port': 88, 'service': 'kerberos'})
        assert result is False

    def test_task_tree_structure(self, plugin, ad_service_info):
        """PROVES: Task tree has proper hierarchical structure"""
        task_tree = plugin.get_task_tree('10.10.10.10', 88, ad_service_info)

        # Verify root structure
        assert task_tree['type'] == 'parent'
        assert 'children' in task_tree
        assert len(task_tree['children']) > 0

        # Verify main phases exist
        phase_names = [child['name'] for child in task_tree['children']]
        assert any('Phase 1' in name for name in phase_names)
        assert any('Phase 2' in name for name in phase_names)
        assert any('Phase 3' in name for name in phase_names)

    def test_phase1_recon_no_creds(self, plugin, ad_service_info):
        """PROVES: Phase 1 contains recon tasks without credentials"""
        task_tree = plugin.get_task_tree('10.10.10.10', 88, ad_service_info)

        # Find Phase 1
        phase1 = next((c for c in task_tree['children'] if 'Phase 1' in c['name']), None)
        assert phase1 is not None
        assert phase1['type'] == 'parent'

        # Check for key tasks
        task_ids = [t['id'] for t in phase1['children']]
        assert any('dns-enum' in tid for tid in task_ids)
        assert any('ldap-anon' in tid for tid in task_ids)
        assert any('smb-null' in tid for tid in task_ids)
        assert any('responder' in tid for tid in task_ids)

    def test_dns_enumeration_task(self, plugin, ad_service_info):
        """PROVES: DNS enumeration task has complete metadata"""
        task_tree = plugin.get_task_tree('10.10.10.10', 88, ad_service_info)
        phase1 = next((c for c in task_tree['children'] if 'Phase 1' in c['name']), None)

        dns_task = next((t for t in phase1['children'] if 'dns-enum' in t['id']), None)
        assert dns_task is not None

        # Verify metadata completeness
        metadata = dns_task['metadata']
        assert 'command' in metadata
        assert 'gobuster dns' in metadata['command']
        assert 'description' in metadata
        assert 'tags' in metadata
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'flag_explanations' in metadata
        assert len(metadata['flag_explanations']) > 0
        assert 'success_indicators' in metadata
        assert len(metadata['success_indicators']) >= 2
        assert 'failure_indicators' in metadata
        assert 'next_steps' in metadata
        assert 'alternatives' in metadata

    def test_phase2_user_enumeration(self, plugin, ad_service_info):
        """PROVES: Phase 2 contains user enumeration tasks"""
        task_tree = plugin.get_task_tree('10.10.10.10', 88, ad_service_info)

        phase2 = next((c for c in task_tree['children'] if 'Phase 2' in c['name']), None)
        assert phase2 is not None

        # Check for Kerbrute and RID cycling
        task_ids = [t['id'] for t in phase2['children']]
        assert any('kerbrute' in tid for tid in task_ids)
        assert any('rid-cycling' in tid for tid in task_ids)

    def test_kerbrute_task_complete(self, plugin, ad_service_info):
        """PROVES: Kerbrute task has all OSCP metadata"""
        task_tree = plugin.get_task_tree('10.10.10.10', 88, ad_service_info)
        phase2 = next((c for c in task_tree['children'] if 'Phase 2' in c['name']), None)

        kerbrute_task = next((t for t in phase2['children'] if 'kerbrute' in t['id']), None)
        assert kerbrute_task is not None

        metadata = kerbrute_task['metadata']
        assert 'kerbrute userenum' in metadata['command']
        assert '-d' in metadata['flag_explanations']
        assert '--dc' in metadata['flag_explanations']
        assert 'QUICK_WIN' in metadata['tags']
        assert len(metadata['success_indicators']) >= 2
        assert len(metadata['alternatives']) >= 2

    def test_phase3_password_attacks(self, plugin, ad_service_info):
        """PROVES: Phase 3 contains password attack tasks"""
        task_tree = plugin.get_task_tree('10.10.10.10', 88, ad_service_info)

        phase3 = next((c for c in task_tree['children'] if 'Phase 3' in c['name']), None)
        assert phase3 is not None

        task_ids = [t['id'] for t in phase3['children']]
        assert any('asreproast' in tid for tid in task_ids)
        assert any('password-spray' in tid for tid in task_ids)
        assert any('password-policy' in tid for tid in task_ids)

    def test_asreproast_task_complete(self, plugin, ad_service_info):
        """PROVES: ASREPRoast task has comprehensive metadata"""
        task_tree = plugin.get_task_tree('10.10.10.10', 88, ad_service_info)
        phase3 = next((c for c in task_tree['children'] if 'Phase 3' in c['name']), None)

        asrep_task = next((t for t in phase3['children'] if 'asreproast' in t['id']), None)
        assert asrep_task is not None

        metadata = asrep_task['metadata']
        assert 'GetNPUsers.py' in metadata['command']
        assert '-usersfile' in metadata['flag_explanations']
        assert '-format hashcat' in metadata['flag_explanations']
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'EXPLOIT' in metadata['tags']
        assert 'No credentials needed' in metadata['notes'] or 'no credentials' in metadata['notes'].lower()

    def test_password_spray_safety_notes(self, plugin, ad_service_info):
        """PROVES: Password spray task includes lockout safety warnings"""
        task_tree = plugin.get_task_tree('10.10.10.10', 88, ad_service_info)
        phase3 = next((c for c in task_tree['children'] if 'Phase 3' in c['name']), None)

        spray_task = next((t for t in phase3['children'] if 'password-spray' in t['id']), None)
        assert spray_task is not None

        metadata = spray_task['metadata']
        notes_lower = metadata['notes'].lower()
        assert 'lockout' in notes_lower or 'policy' in notes_lower
        assert 'NOISY' in metadata['tags']

    def test_phase4_authenticated_enumeration(self, plugin, ad_service_info):
        """PROVES: Phase 4 contains authenticated enumeration tasks"""
        task_tree = plugin.get_task_tree('10.10.10.10', 88, ad_service_info)

        phase4 = next((c for c in task_tree['children'] if 'Phase 4' in c['name']), None)
        assert phase4 is not None

        task_ids = [t['id'] for t in phase4['children']]
        assert any('bloodhound' in tid for tid in task_ids)
        assert any('kerberoast' in tid for tid in task_ids)
        assert any('soapy' in tid for tid in task_ids)  # ADWS
        assert any('printer' in tid for tid in task_ids)

    def test_bloodhound_task_complete(self, plugin, ad_service_info):
        """PROVES: BloodHound task has complete metadata"""
        task_tree = plugin.get_task_tree('10.10.10.10', 88, ad_service_info)
        phase4 = next((c for c in task_tree['children'] if 'Phase 4' in c['name']), None)

        bh_task = next((t for t in phase4['children'] if 'bloodhound' in t['id']), None)
        assert bh_task is not None

        metadata = bh_task['metadata']
        assert 'bloodhound-python' in metadata['command']
        assert '-c All' in metadata['command']
        assert '--zip' in metadata['command']
        assert 'NOISY' in metadata['tags']
        assert len(metadata['next_steps']) >= 3

    def test_adws_soapy_task(self, plugin, ad_service_info):
        """PROVES: ADWS/SoaPy task present for stealth enumeration"""
        task_tree = plugin.get_task_tree('10.10.10.10', 88, ad_service_info)
        phase4 = next((c for c in task_tree['children'] if 'Phase 4' in c['name']), None)

        soapy_task = next((t for t in phase4['children'] if 'soapy' in t['id']), None)
        assert soapy_task is not None

        metadata = soapy_task['metadata']
        assert 'soapy' in metadata['command']
        assert 'STEALTH' in metadata['tags']
        assert 'port 9389' in metadata['notes'] or 'ADWS' in metadata['notes']

    def test_kerberoast_task_complete(self, plugin, ad_service_info):
        """PROVES: Kerberoast task has complete metadata"""
        task_tree = plugin.get_task_tree('10.10.10.10', 88, ad_service_info)
        phase4 = next((c for c in task_tree['children'] if 'Phase 4' in c['name']), None)

        kerb_task = next((t for t in phase4['children'] if 'kerberoast' in t['id']), None)
        assert kerb_task is not None

        metadata = kerb_task['metadata']
        assert 'GetUserSPNs.py' in metadata['command']
        assert '-request' in metadata['flag_explanations']
        assert 'hashcat -m 13100' in ' '.join(metadata['next_steps'])

    def test_printer_exploitation_task(self, plugin, ad_service_info):
        """PROVES: Printer pass-back attack task included"""
        task_tree = plugin.get_task_tree('10.10.10.10', 88, ad_service_info)
        phase4 = next((c for c in task_tree['children'] if 'Phase 4' in c['name']), None)

        printer_task = next((t for t in phase4['children'] if 'printer' in t['id']), None)
        assert printer_task is not None
        assert printer_task['type'] == 'manual'

        metadata = printer_task['metadata']
        assert 'LDAP' in metadata['description'] or 'pass-back' in metadata['description'].lower()
        assert 'commands' in metadata
        assert len(metadata['commands']) >= 5

    def test_phase5_post_compromise(self, plugin, ad_service_info):
        """PROVES: Phase 5 contains post-compromise tasks"""
        task_tree = plugin.get_task_tree('10.10.10.10', 88, ad_service_info)

        phase5 = next((c for c in task_tree['children'] if 'Phase 5' in c['name']), None)
        assert phase5 is not None

        task_ids = [t['id'] for t in phase5['children']]
        assert any('share-enum' in tid for tid in task_ids)
        assert any('trust-enum' in tid for tid in task_ids)
        assert any('acl-enum' in tid for tid in task_ids)

    def test_all_tasks_have_tags(self, plugin, ad_service_info):
        """PROVES: All tasks have proper OSCP tags"""
        task_tree = plugin.get_task_tree('10.10.10.10', 88, ad_service_info)

        def check_tags_recursive(node):
            if node['type'] == 'parent':
                for child in node.get('children', []):
                    check_tags_recursive(child)
            else:
                # Leaf task must have metadata with tags
                if 'metadata' in node:
                    assert 'tags' in node['metadata']
                    assert len(node['metadata']['tags']) > 0
                    # Check for OSCP relevance tag
                    tags_str = ' '.join(node['metadata']['tags'])
                    assert 'OSCP:' in tags_str or 'ENUM' in tags_str or 'EXPLOIT' in tags_str

        check_tags_recursive(task_tree)

    def test_all_command_tasks_have_flag_explanations(self, plugin, ad_service_info):
        """PROVES: All command tasks explain their flags"""
        task_tree = plugin.get_task_tree('10.10.10.10', 88, ad_service_info)

        def check_flags_recursive(node):
            if node['type'] == 'parent':
                for child in node.get('children', []):
                    check_flags_recursive(child)
            elif node['type'] == 'command':
                metadata = node['metadata']
                assert 'flag_explanations' in metadata
                # Should have at least 2 flags explained
                assert len(metadata['flag_explanations']) >= 2

        check_flags_recursive(task_tree)

    def test_all_tasks_have_success_failure_indicators(self, plugin, ad_service_info):
        """PROVES: All tasks have success and failure indicators"""
        task_tree = plugin.get_task_tree('10.10.10.10', 88, ad_service_info)

        def check_indicators_recursive(node):
            if node['type'] == 'parent':
                for child in node.get('children', []):
                    check_indicators_recursive(child)
            elif 'metadata' in node and node['type'] != 'manual':
                metadata = node['metadata']
                assert 'success_indicators' in metadata
                assert len(metadata['success_indicators']) >= 1
                if 'failure_indicators' in metadata:  # Optional but recommended
                    assert len(metadata['failure_indicators']) >= 1

        check_indicators_recursive(task_tree)

    def test_on_task_complete_asreproast(self, plugin):
        """PROVES: ASREPRoast completion spawns cracking task"""
        result = "$krb5asrep$23$user@DOMAIN.LOCAL:hash_data_here"
        new_tasks = plugin.on_task_complete('asreproast-10.10.10.10', result, '10.10.10.10')

        assert len(new_tasks) > 0
        crack_task = next((t for t in new_tasks if 'crack' in t['id']), None)
        assert crack_task is not None
        assert 'hashcat -m 18200' in crack_task['metadata']['command']

    def test_on_task_complete_kerberoast(self, plugin):
        """PROVES: Kerberoast completion spawns cracking task"""
        result = "$krb5tgs$23$*user$realm$service*$hash_data"
        new_tasks = plugin.on_task_complete('kerberoast-10.10.10.10', result, '10.10.10.10')

        assert len(new_tasks) > 0
        crack_task = next((t for t in new_tasks if 'crack' in t['id']), None)
        assert crack_task is not None
        assert 'hashcat -m 13100' in crack_task['metadata']['command']

    def test_on_task_complete_password_spray_success(self, plugin):
        """PROVES: Successful password spray spawns BloodHound task"""
        result = "[+] CORP.LOCAL\\jdoe:Password123! (Pwn3d!)"
        new_tasks = plugin.on_task_complete('password-spray-10.10.10.10', result, '10.10.10.10')

        assert len(new_tasks) > 0
        bh_task = next((t for t in new_tasks if 'bloodhound' in t['id']), None)
        assert bh_task is not None

    def test_on_task_complete_bloodhound_spawns_analysis(self, plugin):
        """PROVES: BloodHound collection spawns analysis reminder"""
        result = "Compressing output into 20250107_bloodhound.zip"
        new_tasks = plugin.on_task_complete('bloodhound-10.10.10.10', result, '10.10.10.10')

        assert len(new_tasks) > 0
        analysis_task = next((t for t in new_tasks if 'analysis' in t['id']), None)
        assert analysis_task is not None
        assert analysis_task['type'] == 'manual'

    def test_manual_alternatives_provided(self, plugin):
        """PROVES: Manual alternatives available for key tools"""
        # Test key task types
        alternatives_kerbrute = plugin.get_manual_alternatives('kerbrute-10.10.10.10')
        assert len(alternatives_kerbrute) >= 2

        alternatives_asrep = plugin.get_manual_alternatives('asreproast-10.10.10.10')
        assert len(alternatives_asrep) >= 2

        alternatives_kerb = plugin.get_manual_alternatives('kerberoast-10.10.10.10')
        assert len(alternatives_kerb) >= 2

        alternatives_bh = plugin.get_manual_alternatives('bloodhound-10.10.10.10')
        assert len(alternatives_bh) >= 2

    def test_task_count_comprehensive(self, plugin, ad_service_info):
        """PROVES: Plugin generates comprehensive task coverage (20+ tasks)"""
        task_tree = plugin.get_task_tree('10.10.10.10', 88, ad_service_info)

        def count_leaf_tasks(node):
            if node['type'] == 'parent':
                return sum(count_leaf_tasks(child) for child in node.get('children', []))
            else:
                return 1

        total_tasks = count_leaf_tasks(task_tree)
        assert total_tasks >= 20, f"Expected 20+ tasks, got {total_tasks}"

    def test_domain_placeholder_usage(self, plugin):
        """PROVES: Domain parameter properly used in commands"""
        service_info = {'domain': 'contoso.local'}
        task_tree = plugin.get_task_tree('10.10.10.10', 88, service_info)

        # Check DNS task uses domain
        phase1 = next((c for c in task_tree['children'] if 'Phase 1' in c['name']), None)
        dns_task = next((t for t in phase1['children'] if 'dns-enum' in t['id']), None)
        assert 'contoso.local' in dns_task['metadata']['command']

    def test_educational_notes_quality(self, plugin, ad_service_info):
        """PROVES: Tasks include educational notes for OSCP learning"""
        task_tree = plugin.get_task_tree('10.10.10.10', 88, ad_service_info)

        def check_notes_recursive(node):
            if node['type'] == 'parent':
                for child in node.get('children', []):
                    check_notes_recursive(child)
            elif 'metadata' in node:
                metadata = node['metadata']
                # Should have notes field
                if 'notes' in metadata:
                    assert len(metadata['notes']) > 20  # Meaningful note

        check_notes_recursive(task_tree)

    def test_quick_win_tasks_present(self, plugin, ad_service_info):
        """PROVES: Plugin includes QUICK_WIN tasks for rapid assessment"""
        task_tree = plugin.get_task_tree('10.10.10.10', 88, ad_service_info)

        def find_quick_wins(node):
            quick_wins = []
            if node['type'] == 'parent':
                for child in node.get('children', []):
                    quick_wins.extend(find_quick_wins(child))
            elif 'metadata' in node and 'tags' in node['metadata']:
                if 'QUICK_WIN' in node['metadata']['tags']:
                    quick_wins.append(node['name'])
            return quick_wins

        quick_win_tasks = find_quick_wins(task_tree)
        assert len(quick_win_tasks) >= 5, "Should have multiple quick win tasks"

    def test_stealth_vs_noisy_tasks_tagged(self, plugin, ad_service_info):
        """PROVES: Tasks properly tagged as NOISY or STEALTH"""
        task_tree = plugin.get_task_tree('10.10.10.10', 88, ad_service_info)

        def find_noisy_and_stealth(node):
            noisy = []
            stealth = []
            if node['type'] == 'parent':
                for child in node.get('children', []):
                    n, s = find_noisy_and_stealth(child)
                    noisy.extend(n)
                    stealth.extend(s)
            elif 'metadata' in node and 'tags' in node['metadata']:
                if 'NOISY' in node['metadata']['tags']:
                    noisy.append(node['name'])
                if 'STEALTH' in node['metadata']['tags']:
                    stealth.append(node['name'])
            return noisy, stealth

        noisy_tasks, stealth_tasks = find_noisy_and_stealth(task_tree)

        # BloodHound and Responder should be noisy
        assert len(noisy_tasks) >= 2
        # ADWS/SoaPy should be stealthy
        assert len(stealth_tasks) >= 1


class TestADEnumerationIntegration:
    """Integration tests for AD enumeration workflow"""

    def test_complete_workflow_no_creds_to_domain_admin(self):
        """PROVES: Plugin supports complete OSCP workflow from no creds to DA"""
        plugin = ADEnumerationPlugin()
        service_info = {'domain': 'htb.local'}
        task_tree = plugin.get_task_tree('10.10.10.10', 88, service_info)

        # Workflow phases should be present in order
        phase_names = [child['name'] for child in task_tree['children']]

        assert any('Phase 1' in name for name in phase_names)  # No creds recon
        assert any('Phase 2' in name for name in phase_names)  # User enum
        assert any('Phase 3' in name for name in phase_names)  # Password attacks
        assert any('Phase 4' in name for name in phase_names)  # Authenticated enum
        assert any('Phase 5' in name for name in phase_names)  # Post-compromise

    def test_realistic_oscp_exam_scenario(self):
        """PROVES: Tasks align with OSCP exam AD methodology"""
        plugin = ADEnumerationPlugin()
        service_info = {'domain': 'exam.local'}
        task_tree = plugin.get_task_tree('192.168.45.100', 88, service_info)

        # Should have critical OSCP tasks
        def find_task_by_keyword(node, keyword):
            if node['type'] == 'parent':
                for child in node.get('children', []):
                    result = find_task_by_keyword(child, keyword)
                    if result:
                        return result
            elif keyword.lower() in node['id'].lower():
                return node
            return None

        # Critical OSCP tools should be present
        assert find_task_by_keyword(task_tree, 'kerbrute') is not None
        assert find_task_by_keyword(task_tree, 'asreproast') is not None
        assert find_task_by_keyword(task_tree, 'kerberoast') is not None
        assert find_task_by_keyword(task_tree, 'bloodhound') is not None
        assert find_task_by_keyword(task_tree, 'password-spray') is not None
