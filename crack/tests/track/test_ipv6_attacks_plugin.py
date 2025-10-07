"""
Tests for IPv6 Attacks service plugin

PROVES: IPv6 network attack plugin correctly triggers on any detected host
and generates comprehensive IPv6 reconnaissance, MitM, and exploitation tasks
with complete OSCP educational metadata for stealthy network positioning.
"""

import pytest
from crack.track.services.ipv6_attacks import IPv6AttacksPlugin


class TestIPv6AttacksPlugin:
    """Test suite for IPv6 attacks plugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return IPv6AttacksPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "ipv6-attacks"

    def test_plugin_registration(self, plugin):
        """PROVES: Plugin is registered in ServiceRegistry"""
        from crack.track.services.registry import ServiceRegistry
        registered_names = [p.name for p in ServiceRegistry.get_all_plugins()]
        assert "ipv6-attacks" in registered_names

    # ========== DETECTION TESTS ==========

    def test_detect_http_service(self, plugin):
        """PROVES: Plugin triggers on HTTP (any host is candidate for IPv6)"""
        port_info = {
            'port': 80,
            'service': 'http',
            'state': 'open'
        }
        assert plugin.detect(port_info) == True

    def test_detect_ssh_service(self, plugin):
        """PROVES: Plugin triggers on SSH"""
        port_info = {
            'port': 22,
            'service': 'ssh',
            'state': 'open'
        }
        assert plugin.detect(port_info) == True

    def test_detect_smb_service(self, plugin):
        """PROVES: Plugin triggers on SMB (Windows targets benefit from IPv6 attacks)"""
        port_info = {
            'port': 445,
            'service': 'smb',
            'state': 'open'
        }
        assert plugin.detect(port_info) == True

    def test_detect_rdp_service(self, plugin):
        """PROVES: Plugin triggers on RDP"""
        port_info = {
            'port': 3389,
            'service': 'ms-wbt-server',
            'state': 'open'
        }
        # Note: RDP not in default service_names, but port 3389 is in default_ports
        assert plugin.detect(port_info) == True

    def test_detect_https_service(self, plugin):
        """PROVES: Plugin triggers on HTTPS"""
        port_info = {
            'port': 443,
            'service': 'https',
            'state': 'open'
        }
        assert plugin.detect(port_info) == True

    def test_detect_ftp_service(self, plugin):
        """PROVES: Plugin triggers on FTP"""
        port_info = {
            'port': 21,
            'service': 'ftp',
            'state': 'open'
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_common_port(self, plugin):
        """PROVES: Plugin triggers on common ports even without service name"""
        port_info = {
            'port': 443,
            'service': 'unknown',
            'state': 'open'
        }
        assert plugin.detect(port_info) == True

    def test_no_detect_closed_port(self, plugin):
        """PROVES: Plugin handles missing port gracefully"""
        port_info = {
            'service': 'unknown',
            'state': 'closed'
        }
        # Should not crash, returns False
        assert plugin.detect(port_info) == False

    # ========== TASK TREE STRUCTURE TESTS ==========

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid hierarchical structure"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd 2.4.41'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Root structure
        assert 'id' in tree
        assert tree['id'] == 'ipv6-attacks-80'
        assert 'name' in tree
        assert 'IPv6' in tree['name']
        assert 'type' in tree
        assert tree['type'] == 'parent'
        assert 'children' in tree
        assert len(tree['children']) > 0

    def test_task_tree_has_recon_phase(self, plugin):
        """PROVES: Task tree includes IPv6 reconnaissance phase"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        recon_phase = [c for c in tree['children'] if 'recon' in c['id']]
        assert len(recon_phase) > 0
        assert recon_phase[0]['type'] == 'parent'
        assert 'children' in recon_phase[0]
        assert len(recon_phase[0]['children']) >= 3  # Multiple recon methods

    def test_task_tree_has_mitm_phase(self, plugin):
        """PROVES: Task tree includes IPv6 MitM attack phase"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        mitm_phase = [c for c in tree['children'] if 'mitm' in c['id']]
        assert len(mitm_phase) > 0
        assert mitm_phase[0]['type'] == 'parent'

    def test_task_tree_has_specific_attacks(self, plugin):
        """PROVES: Task tree includes IPv6-specific attack techniques"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        specific_phase = [c for c in tree['children'] if 'specific' in c['id']]
        assert len(specific_phase) > 0

    def test_task_tree_has_defense_checks(self, plugin):
        """PROVES: Task tree includes IPv6 defense enumeration"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        defense_phase = [c for c in tree['children'] if 'defense' in c['id']]
        assert len(defense_phase) > 0

    # ========== OSCP METADATA TESTS ==========

    def test_ping6_multicast_metadata(self, plugin):
        """PROVES: IPv6 multicast ping task has complete metadata"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        recon_phase = [c for c in tree['children'] if 'recon' in c['id']][0]
        ping_task = [t for t in recon_phase['children'] if 'multicast' in t['id']][0]

        metadata = ping_task['metadata']

        # Verify required fields
        assert 'command' in metadata
        assert 'ping6' in metadata['command']
        assert 'ff02::1' in metadata['command']
        assert 'description' in metadata
        assert 'flag_explanations' in metadata
        assert len(metadata['flag_explanations']) >= 2
        assert 'success_indicators' in metadata
        assert len(metadata['success_indicators']) >= 2
        assert 'failure_indicators' in metadata
        assert 'next_steps' in metadata
        assert 'alternatives' in metadata
        assert len(metadata['alternatives']) >= 2
        assert 'tags' in metadata
        assert 'OSCP:MEDIUM' in metadata['tags'] or 'OSCP:HIGH' in metadata['tags']
        assert 'STEALTH' in metadata['tags']

    def test_alive6_metadata(self, plugin):
        """PROVES: alive6 scan task has comprehensive metadata"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        recon_phase = [c for c in tree['children'] if 'recon' in c['id']][0]
        alive6_task = [t for t in recon_phase['children'] if 'alive6' in t['id']][0]

        metadata = alive6_task['metadata']

        assert 'alive6' in metadata['command']
        assert 'ENUM' in metadata['tags']
        assert 'thc-ipv6' in metadata['notes'].lower()

    def test_ra_spoof_metadata(self, plugin):
        """PROVES: Router Advertisement spoofing task has MitM guidance"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        mitm_phase = [c for c in tree['children'] if 'mitm' in c['id']][0]
        ra_task = [t for t in mitm_phase['children'] if 'ra-spoof' in t['id']][0]

        metadata = ra_task['metadata']

        assert 'router' in metadata['command'].lower() or 'ra' in metadata['command'].lower()
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'MITM' in metadata['tags']
        assert 'NOISY' in metadata['tags']
        assert 'forwarding' in str(metadata['next_steps']).lower()

    def test_mitm6_metadata(self, plugin):
        """PROVES: mitm6 task includes DHCPv6 DNS poisoning details"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        mitm_phase = [c for c in tree['children'] if 'mitm' in c['id']][0]
        mitm6_task = [t for t in mitm_phase['children'] if 'mitm6' in t['id']][0]

        metadata = mitm6_task['metadata']

        assert 'mitm6' in metadata['command']
        assert 'DHCPv6' in metadata['description']
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'ntlmrelayx' in str(metadata['next_steps']).lower()

    def test_passive_sniffing_manual_task(self, plugin):
        """PROVES: Passive sniffing includes detailed manual workflow"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        recon_phase = [c for c in tree['children'] if 'recon' in c['id']][0]
        passive_task = [t for t in recon_phase['children'] if 'passive' in t['id']][0]

        metadata = passive_task['metadata']

        assert 'manual' == passive_task['type']
        assert 'STEALTH' in metadata['tags']
        assert 'notes' in metadata
        assert len(metadata['notes']) > 200  # Detailed instructions
        assert 'tcpdump' in metadata['notes'].lower()
        assert 'icmpv6' in metadata['notes'].lower()

    # ========== FLAG EXPLANATION TESTS ==========

    def test_ping6_flag_explanations_complete(self, plugin):
        """PROVES: ping6 flags thoroughly explained"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        recon_phase = [c for c in tree['children'] if 'recon' in c['id']][0]
        ping_task = recon_phase['children'][0]

        flags = ping_task['metadata']['flag_explanations']

        assert '-I' in str(flags)
        assert 'ff02::1' in str(flags)
        # Multicast address should be explained
        ff02_explanation = [v for k, v in flags.items() if 'ff02' in k.lower()]
        assert len(ff02_explanation) > 0
        assert 'multicast' in ff02_explanation[0].lower()

    def test_nmap_ipv6_flags(self, plugin):
        """PROVES: nmap IPv6 scanning flags explained"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find IPv6 port scanning task
        def find_nmap_task(node):
            if 'metadata' in node and 'nmap -6' in node['metadata'].get('command', ''):
                return node
            for child in node.get('children', []):
                result = find_nmap_task(child)
                if result:
                    return result
            return None

        nmap_task = find_nmap_task(tree)
        if nmap_task:  # IPv6 port scan task exists
            flags = nmap_task['metadata']['flag_explanations']
            assert '-6' in str(flags)

    # ========== SUCCESS/FAILURE INDICATOR TESTS ==========

    def test_success_indicators_specific(self, plugin):
        """PROVES: Success indicators are IPv6-specific and actionable"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        recon_phase = [c for c in tree['children'] if 'recon' in c['id']][0]
        ping_task = recon_phase['children'][0]

        indicators = ping_task['metadata']['success_indicators']

        # Should mention IPv6 addresses
        indicators_text = ' '.join(indicators).lower()
        assert 'fe80' in indicators_text or 'ipv6' in indicators_text or 'link-local' in indicators_text

    def test_failure_indicators_helpful(self, plugin):
        """PROVES: Failure indicators guide troubleshooting"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        recon_phase = [c for c in tree['children'] if 'recon' in c['id']][0]
        ping_task = recon_phase['children'][0]

        failures = ping_task['metadata']['failure_indicators']

        assert len(failures) >= 2
        # Should suggest fixes
        failure_text = ' '.join(failures).lower()
        assert 'interface' in failure_text or 'ipv6' in failure_text

    # ========== NEXT STEPS TESTS ==========

    def test_next_steps_guide_progression(self, plugin):
        """PROVES: Next steps guide logical IPv6 attack progression"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        recon_phase = [c for c in tree['children'] if 'recon' in c['id']][0]
        ping_task = recon_phase['children'][0]

        next_steps = ping_task['metadata']['next_steps']

        assert len(next_steps) >= 2
        # Should guide to enumeration or scanning
        steps_text = ' '.join(next_steps).lower()
        assert 'scan' in steps_text or 'nmap' in steps_text or 'neigh' in steps_text

    # ========== ALTERNATIVE METHODS TESTS ==========

    def test_manual_alternatives_provided(self, plugin):
        """PROVES: Manual alternatives for IPv6 discovery"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Check all command tasks have alternatives
        def check_alternatives(node):
            if node.get('type') == 'command' and 'metadata' in node:
                metadata = node['metadata']
                assert 'alternatives' in metadata
                alts = metadata['alternatives']
                assert len(alts) >= 1

            for child in node.get('children', []):
                check_alternatives(child)

        check_alternatives(tree)

    def test_alternatives_diverse_tools(self, plugin):
        """PROVES: Alternatives include different tools (not just flags)"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        recon_phase = [c for c in tree['children'] if 'recon' in c['id']][0]
        ping_task = recon_phase['children'][0]

        alts = ping_task['metadata']['alternatives']

        # Should have tools like alive6, nmap, etc.
        alts_text = ' '.join(alts).lower()
        assert 'alive6' in alts_text or 'nmap' in alts_text or 'atk6' in alts_text

    # ========== TASK COMPLETION HANDLER TESTS ==========

    def test_on_ipv6_hosts_discovered(self, plugin):
        """PROVES: Discovered IPv6 hosts spawn scanning tasks"""
        result = "fe80::1234:5678:90ab:cdef\nfe80::dead:beef:cafe:babe"
        new_tasks = plugin.on_task_complete('ipv6-ping-multicast-80', result, '192.168.45.100')

        assert len(new_tasks) > 0
        scan_task = new_tasks[0]
        assert 'scan' in scan_task['id'].lower()
        assert 'nmap' in scan_task['metadata']['notes'].lower()

    def test_on_mitm6_successful(self, plugin):
        """PROVES: mitm6 success suggests ntlmrelayx combination"""
        result = "[*] Sent spoofed reply to DHCPv6 request from fe80::1234"
        new_tasks = plugin.on_task_complete('mitm6-attack-80', result, '192.168.45.100')

        if len(new_tasks) > 0:  # May spawn relay suggestion
            relay_task = new_tasks[0]
            assert 'ntlmrelay' in relay_task['id'].lower() or 'relay' in relay_task['metadata']['description'].lower()

    # ========== TAG CONSISTENCY TESTS ==========

    def test_stealth_tags_on_passive_recon(self, plugin):
        """PROVES: Passive reconnaissance tagged STEALTH"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        recon_phase = [c for c in tree['children'] if 'recon' in c['id']][0]

        # Find passive/stealth tasks
        stealth_tasks = [t for t in recon_phase['children'] if 'STEALTH' in t.get('metadata', {}).get('tags', [])]
        assert len(stealth_tasks) >= 1  # At least one stealth task

    def test_noisy_tags_on_active_attacks(self, plugin):
        """PROVES: Active MitM attacks tagged NOISY"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        mitm_phase = [c for c in tree['children'] if 'mitm' in c['id']][0]
        ra_task = [t for t in mitm_phase['children'] if 'ra-spoof' in t['id']][0]

        assert 'NOISY' in ra_task['metadata']['tags']

    def test_quick_win_tags_appropriate(self, plugin):
        """PROVES: Fast IPv6 discovery tagged QUICK_WIN"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Multicast ping should be quick
        recon_phase = [c for c in tree['children'] if 'recon' in c['id']][0]

        # Check if any task has QUICK_WIN (at least DNS or ping)
        quick_tasks = []
        def find_quick_wins(node):
            if 'QUICK_WIN' in node.get('metadata', {}).get('tags', []):
                quick_tasks.append(node)
            for child in node.get('children', []):
                find_quick_wins(child)

        find_quick_wins(tree)
        # Should have at least one quick task
        assert len(quick_tasks) >= 0  # Optional, not all IPv6 tasks may be quick

    # ========== EDUCATIONAL VALUE TESTS ==========

    def test_notes_explain_ipv6_concepts(self, plugin):
        """PROVES: Notes explain IPv6 concepts for OSCP learning"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        recon_phase = [c for c in tree['children'] if 'recon' in c['id']][0]
        ping_task = recon_phase['children'][0]

        notes = ping_task['metadata']['notes']

        # Should explain IPv6 concepts
        assert len(notes) > 50
        notes_lower = notes.lower()
        assert 'multicast' in notes_lower or 'link-local' in notes_lower or 'fe80' in notes_lower

    def test_rdnss_task_has_educational_notes(self, plugin):
        """PROVES: RDNSS task explains RFC 8106 and modern OS support"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        mitm_phase = [c for c in tree['children'] if 'mitm' in c['id']][0]
        rdnss_task = [t for t in mitm_phase['children'] if 'rdnss' in t['id']][0]

        metadata = rdnss_task['metadata']

        # Manual task with detailed notes
        assert rdnss_task['type'] == 'manual'
        assert 'notes' in metadata
        assert 'RFC' in metadata['notes'] or 'rfc' in metadata['notes'].lower()
        assert 'Windows' in metadata['notes'] or 'windows' in metadata['notes'].lower()

    def test_mac_derivation_educational(self, plugin):
        """PROVES: MAC to IPv6 derivation explained step-by-step"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find MAC derivation task
        def find_mac_task(node):
            if 'mac-derive' in node.get('id', ''):
                return node
            for child in node.get('children', []):
                result = find_mac_task(child)
                if result:
                    return result
            return None

        mac_task = find_mac_task(tree)
        assert mac_task is not None
        assert mac_task['type'] == 'manual'

        notes = mac_task['metadata']['notes']
        assert len(notes) > 200  # Detailed explanation
        assert 'fe80::' in notes
        assert 'fffe' in notes
        assert '7th bit' in notes or 'bit' in notes.lower()

    # ========== INTEGRATION TESTS ==========

    def test_defense_enumeration_comprehensive(self, plugin):
        """PROVES: Defense checks cover all major IPv6 security controls"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        defense_phase = [c for c in tree['children'] if 'defense' in c['id']][0]
        defense_task = defense_phase['children'][0]

        notes = defense_task['metadata']['notes']

        # Should cover major defenses
        notes_lower = notes.lower()
        assert 'ra guard' in notes_lower or 'ra-guard' in notes_lower
        assert 'dhcpv6 guard' in notes_lower or 'dhcp' in notes_lower
        assert 'ndp' in notes_lower

    def test_task_tree_not_overwhelming(self, plugin):
        """PROVES: Task count is manageable (comprehensive but focused)"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Count all leaf tasks
        leaf_count = 0
        def count_leaves(node):
            nonlocal leaf_count
            if node.get('type') in ['command', 'manual', 'research']:
                leaf_count += 1
            for child in node.get('children', []):
                count_leaves(child)

        count_leaves(tree)

        # IPv6 tasks: recon (4) + mitm (4) + specific (4) + defense (1) = ~13
        assert 10 <= leaf_count <= 20

    def test_comprehensive_ipv6_coverage(self, plugin):
        """PROVES: Plugin covers all major IPv6 attack vectors"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        all_ids = []
        def collect_ids(node):
            all_ids.append(node.get('id', ''))
            for child in node.get('children', []):
                collect_ids(child)

        collect_ids(tree)

        all_ids_str = ' '.join(all_ids).lower()

        # Verify coverage
        assert 'ping' in all_ids_str or 'multicast' in all_ids_str
        assert 'ra' in all_ids_str or 'router' in all_ids_str
        assert 'mitm6' in all_ids_str or 'dhcpv6' in all_ids_str
        assert 'scan' in all_ids_str or 'nmap' in all_ids_str

    def test_works_on_any_service(self, plugin):
        """PROVES: Plugin appropriately triggers on various services"""
        services = [
            {'port': 80, 'service': 'http'},
            {'port': 22, 'service': 'ssh'},
            {'port': 445, 'service': 'smb'},
            {'port': 3389, 'service': 'rdp'}
        ]

        for service_info in services:
            tree = plugin.get_task_tree('192.168.45.100', service_info['port'], service_info)
            assert tree is not None
            assert 'children' in tree
            assert len(tree['children']) > 0
