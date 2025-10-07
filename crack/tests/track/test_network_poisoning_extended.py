"""
Tests for extended NetworkPoisoningPlugin (VLAN/Routing/SSDP attacks)

Validates:
- VLAN hopping attacks (DTP, double-tagging, voice VLAN)
- Routing protocol attacks (EIGRP, GLBP, HSRP)
- SSDP/UPnP spoofing attacks
- Complete OSCP metadata (flags, indicators, alternatives)
"""

import pytest
from crack.track.services.network_poisoning import NetworkPoisoningPlugin


class TestVLANHoppingAttacks:
    """Test VLAN hopping attack task generation"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return NetworkPoisoningPlugin()

    @pytest.fixture
    def smb_service(self):
        """SMB service that triggers network poisoning plugin"""
        return {
            'port': 445,
            'service': 'microsoft-ds',
            'product': 'Windows Server 2019',
            'version': '10.0'
        }

    def test_vlan_hopping_phase_exists(self, plugin, smb_service):
        """PROVES: Plugin includes VLAN hopping attack phase"""
        tree = plugin.get_task_tree('192.168.45.100', 445, smb_service)

        # Find VLAN hopping phase
        vlan_phase = None
        for child in tree['children']:
            if 'vlan-hopping' in child['id']:
                vlan_phase = child
                break

        assert vlan_phase is not None, "VLAN hopping phase missing"
        assert vlan_phase['type'] == 'parent'
        assert 'VLAN Hopping' in vlan_phase['name']
        assert len(vlan_phase['children']) >= 4, "Should have DTP, double-tag, voice VLAN, trunk reconfig"

    def test_dtp_spoofing_task(self, plugin, smb_service):
        """PROVES: DTP switch spoofing task includes complete OSCP metadata"""
        tree = plugin.get_task_tree('192.168.45.100', 445, smb_service)

        # Find DTP task
        dtp_task = None
        for phase in tree['children']:
            if 'vlan-hopping' in phase.get('id', ''):
                for task in phase['children']:
                    if 'dtp-spoof' in task['id']:
                        dtp_task = task
                        break

        assert dtp_task is not None
        assert dtp_task['name'] == 'DTP Switch Spoofing (Auto-Trunk Negotiation)'
        assert dtp_task['type'] == 'command'

        metadata = dtp_task['metadata']
        assert 'yersinia' in metadata['command']
        assert 'Negotiate trunk port via DTP' in metadata['description']

        # Verify OSCP metadata
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'EXPLOIT' in metadata['tags']
        assert 'VLAN' in metadata['tags']

        assert 'yersinia' in metadata['flag_explanations']
        assert '-G' in metadata['flag_explanations']

        assert len(metadata['success_indicators']) >= 3
        assert len(metadata['failure_indicators']) >= 3
        assert len(metadata['next_steps']) >= 4
        assert len(metadata['alternatives']) >= 3

        # Check educational content
        assert 'DTP' in metadata['notes']
        assert 'trunk' in metadata['notes'].lower()

    def test_double_tagging_attack(self, plugin, smb_service):
        """PROVES: Double-tagging attack includes native VLAN exploitation"""
        tree = plugin.get_task_tree('192.168.45.100', 445, smb_service)

        # Find double-tagging task
        double_tag_task = None
        for phase in tree['children']:
            if 'vlan-hopping' in phase.get('id', ''):
                for task in phase['children']:
                    if 'double-tag' in task['id']:
                        double_tag_task = task
                        break

        assert double_tag_task is not None
        metadata = double_tag_task['metadata']

        assert 'DoubleTagging.py' in metadata['command']
        assert '--nativevlan' in metadata['command']
        assert '--targetvlan' in metadata['command']

        # Verify flag explanations
        assert '--nativevlan 1' in metadata['flag_explanations']
        assert '--targetvlan 20' in metadata['flag_explanations']
        assert '--victim' in metadata['flag_explanations']

        # Check attack constraints documented
        assert 'native vlan' in metadata['notes'].lower()
        assert 'one-way' in metadata['notes'].lower()

        assert 'OSCP:MEDIUM' in metadata['tags']

    def test_voice_vlan_hijacking(self, plugin, smb_service):
        """PROVES: Voice VLAN hijacking via IP phone spoofing"""
        tree = plugin.get_task_tree('192.168.45.100', 445, smb_service)

        # Find voice VLAN task
        voice_task = None
        for phase in tree['children']:
            if 'vlan-hopping' in phase.get('id', ''):
                for task in phase['children']:
                    if 'voice-vlan-hijack' in task['id']:
                        voice_task = task
                        break

        assert voice_task is not None
        metadata = voice_task['metadata']

        assert 'voiphopper' in metadata['command']
        assert '-i eth0' in metadata['command']
        assert '-f cisco-7940' in metadata['command']

        # Check VOIP relevance
        assert 'VOIP' in metadata['tags']
        assert 'CDP' in metadata['notes'] or 'LLDP' in metadata['notes']

        # Verify next steps include VoIP enumeration
        next_steps_text = ' '.join(metadata['next_steps'])
        assert 'sip' in next_steps_text.lower() or '5060' in next_steps_text

        assert 'OSCP:HIGH' in metadata['tags']

    def test_manual_trunk_reconfiguration(self, plugin, smb_service):
        """PROVES: Manual trunk reconfiguration task is comprehensive"""
        tree = plugin.get_task_tree('192.168.45.100', 445, smb_service)

        # Find trunk reconfig task
        trunk_task = None
        for phase in tree['children']:
            if 'vlan-hopping' in phase.get('id', ''):
                for task in phase['children']:
                    if 'trunk-reconfig' in task['id']:
                        trunk_task = task
                        break

        assert trunk_task is not None
        assert trunk_task['type'] == 'manual'

        metadata = trunk_task['metadata']
        notes = metadata['notes']

        # Verify comprehensive manual workflow
        assert 'STEP 1' in notes
        assert 'STEP 2' in notes
        assert 'show vlan brief' in notes
        assert 'switchport mode trunk' in notes
        assert 'ip link add' in notes
        assert 'dhclient' in notes

        # Check both modern and legacy methods documented
        assert 'modprobe 8021q' in notes
        assert 'vconfig' in notes


class TestRoutingProtocolAttacks:
    """Test routing protocol attack task generation"""

    @pytest.fixture
    def plugin(self):
        return NetworkPoisoningPlugin()

    @pytest.fixture
    def ldap_service(self):
        """LDAP service that triggers network poisoning"""
        return {
            'port': 389,
            'service': 'ldap',
            'product': 'OpenLDAP',
            'version': '2.4'
        }

    def test_routing_attacks_phase_exists(self, plugin, ldap_service):
        """PROVES: Routing protocol attacks phase exists"""
        tree = plugin.get_task_tree('192.168.45.100', 389, ldap_service)

        routing_phase = None
        for child in tree['children']:
            if 'routing-attacks' in child['id']:
                routing_phase = child
                break

        assert routing_phase is not None
        assert 'EIGRP/GLBP/HSRP' in routing_phase['name']
        assert len(routing_phase['children']) >= 4, "Should have EIGRP hello, EIGRP inject, GLBP, HSRP"

    def test_eigrp_hello_flooding(self, plugin, ldap_service):
        """PROVES: EIGRP hello flooding DoS attack"""
        tree = plugin.get_task_tree('192.168.45.100', 389, ldap_service)

        eigrp_flood = None
        for phase in tree['children']:
            if 'routing-attacks' in phase.get('id', ''):
                for task in phase['children']:
                    if 'eigrp-hello-flood' in task['id']:
                        eigrp_flood = task
                        break

        assert eigrp_flood is not None
        metadata = eigrp_flood['metadata']

        assert 'helloflooding.py' in metadata['command']
        assert '--interface' in metadata['command']
        assert '--as' in metadata['command']
        assert '--subnet' in metadata['command']

        # Check DoS nature documented
        assert 'DOS' in metadata['tags'] or 'DoS' in metadata['description']
        assert 'OSCP:LOW' in metadata['tags'], "DoS attacks less relevant for OSCP"

        # Verify educational content
        assert 'EIGRP' in metadata['notes']
        assert '224.0.0.10' in metadata['notes'], "EIGRP multicast address"

    def test_eigrp_route_injection(self, plugin, ldap_service):
        """PROVES: EIGRP route injection for MITM"""
        tree = plugin.get_task_tree('192.168.45.100', 389, ldap_service)

        eigrp_inject = None
        for phase in tree['children']:
            if 'routing-attacks' in phase.get('id', ''):
                for task in phase['children']:
                    if 'eigrp-route-inject' in task['id']:
                        eigrp_inject = task
                        break

        assert eigrp_inject is not None
        metadata = eigrp_inject['metadata']

        assert 'routeinject.py' in metadata['command']
        assert '--src' in metadata['command']
        assert '--dst' in metadata['command']
        assert '--prefix' in metadata['command']

        assert 'MITM' in metadata['tags']
        assert 'OSCP:MEDIUM' in metadata['tags']

        # Verify MITM setup documented
        next_steps_text = ' '.join(metadata['next_steps'])
        assert 'ip_forward' in next_steps_text
        assert 'iptables' in next_steps_text

    def test_glbp_hijacking(self, plugin, ldap_service):
        """PROVES: GLBP AVG hijacking manual workflow"""
        tree = plugin.get_task_tree('192.168.45.100', 389, ldap_service)

        glbp_task = None
        for phase in tree['children']:
            if 'routing-attacks' in phase.get('id', ''):
                for task in phase['children']:
                    if 'glbp-hijack' in task['id']:
                        glbp_task = task
                        break

        assert glbp_task is not None
        assert glbp_task['type'] == 'manual'

        metadata = glbp_task['metadata']
        notes = metadata['notes']

        # Verify GLBP-specific details
        assert 'GLBP' in notes
        assert 'UDP 3222' in notes
        assert '224.0.0.102' in notes
        assert 'AVG' in notes  # Active Virtual Gateway
        assert 'priority' in notes.lower()
        assert '255' in notes  # Maximum priority

        # Check Loki tool referenced
        assert 'Loki' in notes or 'loki' in notes
        assert 'github' in notes.lower()

    def test_hsrp_hijacking(self, plugin, ldap_service):
        """PROVES: HSRP hijacking with authentication bypass"""
        tree = plugin.get_task_tree('192.168.45.100', 389, ldap_service)

        hsrp_task = None
        for phase in tree['children']:
            if 'routing-attacks' in phase.get('id', ''):
                for task in phase['children']:
                    if 'hsrp-hijack' in task['id']:
                        hsrp_task = task
                        break

        assert hsrp_task is not None
        metadata = hsrp_task['metadata']
        notes = metadata['notes']

        # Verify HSRP specifics
        assert 'HSRP' in notes
        assert 'UDP 1985' in notes
        assert 'hsrp2john' in notes  # Auth bypass tool
        assert 'john' in notes.lower()

        # Check version differences documented
        assert 'HSRPv1' in notes or 'v1' in notes
        assert 'HSRPv2' in notes or 'v2' in notes

        assert 'OSCP:MEDIUM' in metadata['tags']


class TestSSDPUPnPAttacks:
    """Test SSDP/UPnP spoofing attack tasks"""

    @pytest.fixture
    def plugin(self):
        return NetworkPoisoningPlugin()

    @pytest.fixture
    def smb_service(self):
        return {
            'port': 445,
            'service': 'microsoft-ds',
            'product': 'Windows 10',
            'version': 'unknown'
        }

    def test_ssdp_upnp_phase_exists(self, plugin, smb_service):
        """PROVES: SSDP/UPnP spoofing phase exists"""
        tree = plugin.get_task_tree('192.168.45.100', 445, smb_service)

        ssdp_phase = None
        for child in tree['children']:
            if 'ssdp-upnp' in child['id']:
                ssdp_phase = child
                break

        assert ssdp_phase is not None
        assert 'SSDP/UPnP' in ssdp_phase['name']
        assert len(ssdp_phase['children']) >= 2, "Should have Evil SSDP and UPnP IGD"

    def test_evil_ssdp_phishing(self, plugin, smb_service):
        """PROVES: Evil SSDP fake device phishing attack"""
        tree = plugin.get_task_tree('192.168.45.100', 445, smb_service)

        evil_ssdp = None
        for phase in tree['children']:
            if 'ssdp-upnp' in phase.get('id', ''):
                for task in phase['children']:
                    if 'evil-ssdp' in task['id']:
                        evil_ssdp = task
                        break

        assert evil_ssdp is not None
        metadata = evil_ssdp['metadata']

        assert 'evil_ssdp.py' in metadata['command']
        assert '-t office365' in metadata['command']

        # Check phishing nature
        assert 'PHISHING' in metadata['tags']
        assert 'IOT' in metadata['tags']
        assert 'OSCP:LOW' in metadata['tags']

        # Verify templates mentioned
        assert 'template' in metadata['notes'].lower()
        assert '1900' in metadata['notes']  # SSDP port

    def test_upnp_igd_exploitation(self, plugin, smb_service):
        """PROVES: UPnP IGD port mapping abuse"""
        tree = plugin.get_task_tree('192.168.45.100', 445, smb_service)

        upnp_igd = None
        for phase in tree['children']:
            if 'ssdp-upnp' in phase.get('id', ''):
                for task in phase['children']:
                    if 'upnp-igd' in task['id']:
                        upnp_igd = task
                        break

        assert upnp_igd is not None
        assert upnp_igd['type'] == 'manual'

        metadata = upnp_igd['metadata']
        notes = metadata['notes']

        # Verify IGD concepts
        assert 'IGD' in notes
        assert 'miranda' in notes.lower()
        assert 'port mapping' in notes.lower() or 'port forwarding' in notes.lower()
        assert 'SOAP' in notes

        # Check tools documented
        assert 'miranda' in notes.lower()
        assert 'nmap' in notes


class TestOSCPCompliance:
    """Test OSCP-specific requirements across all new phases"""

    @pytest.fixture
    def plugin(self):
        return NetworkPoisoningPlugin()

    @pytest.fixture
    def test_service(self):
        return {
            'port': 445,
            'service': 'microsoft-ds',
            'product': 'Windows Server 2019',
            'version': '10.0'
        }

    def test_all_command_tasks_have_flag_explanations(self, plugin, test_service):
        """PROVES: All command tasks explain their flags"""
        tree = plugin.get_task_tree('192.168.45.100', 445, test_service)

        command_tasks = self._collect_command_tasks(tree)
        assert len(command_tasks) > 0

        for task in command_tasks:
            metadata = task['metadata']
            assert 'flag_explanations' in metadata, f"Task {task['id']} missing flag_explanations"
            assert len(metadata['flag_explanations']) > 0, f"Task {task['id']} has empty flag_explanations"

    def test_all_tasks_have_success_failure_indicators(self, plugin, test_service):
        """PROVES: All tasks include success and failure indicators"""
        tree = plugin.get_task_tree('192.168.45.100', 445, test_service)

        all_tasks = self._collect_all_leaf_tasks(tree)

        for task in all_tasks:
            if task['type'] == 'manual':
                # Manual tasks may have indicators in notes
                continue

            metadata = task['metadata']
            assert 'success_indicators' in metadata, f"Task {task['id']} missing success_indicators"
            assert 'failure_indicators' in metadata, f"Task {task['id']} missing failure_indicators"
            assert len(metadata['success_indicators']) >= 2, f"Task {task['id']} needs more success indicators"
            assert len(metadata['failure_indicators']) >= 2, f"Task {task['id']} needs more failure indicators"

    def test_all_tasks_have_alternatives(self, plugin, test_service):
        """PROVES: All tasks provide manual alternatives"""
        tree = plugin.get_task_tree('192.168.45.100', 445, test_service)

        all_tasks = self._collect_all_leaf_tasks(tree)

        for task in all_tasks:
            metadata = task['metadata']
            assert 'alternatives' in metadata, f"Task {task['id']} missing alternatives"
            assert len(metadata['alternatives']) >= 1, f"Task {task['id']} needs alternatives"

    def test_all_tasks_have_next_steps(self, plugin, test_service):
        """PROVES: All tasks guide the attack chain"""
        tree = plugin.get_task_tree('192.168.45.100', 445, test_service)

        command_tasks = self._collect_command_tasks(tree)

        for task in command_tasks:
            metadata = task['metadata']
            assert 'next_steps' in metadata, f"Task {task['id']} missing next_steps"
            assert len(metadata['next_steps']) >= 2, f"Task {task['id']} needs more next_steps"

    def test_all_tasks_have_oscp_tags(self, plugin, test_service):
        """PROVES: All tasks tagged with OSCP relevance"""
        tree = plugin.get_task_tree('192.168.45.100', 445, test_service)

        all_tasks = self._collect_all_leaf_tasks(tree)

        for task in all_tasks:
            metadata = task['metadata']
            tags = metadata.get('tags', [])

            # Check for OSCP relevance tag
            oscp_tags = [t for t in tags if t.startswith('OSCP:')]
            assert len(oscp_tags) >= 1, f"Task {task['id']} missing OSCP relevance tag"

    def test_all_tasks_have_educational_notes(self, plugin, test_service):
        """PROVES: All tasks include educational context"""
        tree = plugin.get_task_tree('192.168.45.100', 445, test_service)

        all_tasks = self._collect_all_leaf_tasks(tree)

        for task in all_tasks:
            metadata = task['metadata']
            assert 'notes' in metadata, f"Task {task['id']} missing notes"
            assert len(metadata['notes']) > 50, f"Task {task['id']} notes too brief"

    # Helper methods
    def _collect_command_tasks(self, node):
        """Recursively collect all command-type tasks"""
        tasks = []
        if node.get('type') == 'command':
            tasks.append(node)
        for child in node.get('children', []):
            tasks.extend(self._collect_command_tasks(child))
        return tasks

    def _collect_all_leaf_tasks(self, node):
        """Recursively collect all leaf tasks (command, manual, research)"""
        tasks = []
        if node.get('type') in ['command', 'manual', 'research']:
            tasks.append(node)
        for child in node.get('children', []):
            tasks.extend(self._collect_all_leaf_tasks(child))
        return tasks


class TestPluginIntegration:
    """Test complete plugin integration"""

    def test_plugin_generates_valid_tree_structure(self):
        """PROVES: Extended plugin generates valid hierarchical tree"""
        plugin = NetworkPoisoningPlugin()
        service = {
            'port': 445,
            'service': 'microsoft-ds',
            'product': 'Windows Server 2019',
            'version': '10.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 445, service)

        # Verify root structure
        assert tree['id'] == 'net-poison-445'
        assert tree['type'] == 'parent'
        assert 'children' in tree

        # Count phases
        phase_count = len(tree['children'])
        assert phase_count >= 8, f"Expected at least 8 phases (Responder, NTLM relay, Kerberos, Coercion, Mitigation, VLAN, Routing, SSDP), got {phase_count}"

        # Verify all phases are parent types
        for phase in tree['children']:
            assert phase['type'] == 'parent', f"Phase {phase['id']} should be parent type"
            assert 'children' in phase
            assert len(phase['children']) > 0, f"Phase {phase['id']} has no tasks"

    def test_total_task_count_increased(self):
        """PROVES: Extended plugin has significantly more tasks"""
        plugin = NetworkPoisoningPlugin()
        service = {'port': 445, 'service': 'microsoft-ds'}

        tree = plugin.get_task_tree('192.168.45.100', 445, service)

        # Count all leaf tasks
        def count_tasks(node):
            if node.get('type') in ['command', 'manual', 'research']:
                return 1
            return sum(count_tasks(child) for child in node.get('children', []))

        total_tasks = count_tasks(tree)
        assert total_tasks >= 20, f"Expected at least 20 tasks with extensions, got {total_tasks}"

    def test_new_phases_properly_integrated(self):
        """PROVES: New phases integrate with existing phases"""
        plugin = NetworkPoisoningPlugin()
        service = {'port': 445, 'service': 'microsoft-ds'}

        tree = plugin.get_task_tree('192.168.45.100', 445, service)

        phase_ids = [child['id'] for child in tree['children']]

        # Verify new phases present
        assert any('vlan-hopping' in pid for pid in phase_ids)
        assert any('routing-attacks' in pid for pid in phase_ids)
        assert any('ssdp-upnp' in pid for pid in phase_ids)

        # Verify original phases still present
        assert any('responder' in pid for pid in phase_ids)
        assert any('ntlm-relay' in pid for pid in phase_ids)
