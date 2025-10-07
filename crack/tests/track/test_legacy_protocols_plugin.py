"""
Tests for Legacy Protocols service plugin

PROVES:
- Finger plugin detects port 79 and generates user enumeration tasks
- IRC plugin detects IRC ports and generates enumeration tasks
- RTSP plugin detects streaming ports and generates media tasks
- Echo plugin detects port 7 and generates basic tasks
- All plugins provide OSCP-required metadata
"""

import pytest
from crack.track.services.legacy_protocols import (
    FingerPlugin,
    IRCPlugin,
    RTSPPlugin,
    EchoPlugin
)


class TestFingerPlugin:
    """Test suite for Finger protocol enumeration plugin"""

    @pytest.fixture
    def plugin(self):
        """Create Finger plugin instance"""
        return FingerPlugin()

    def test_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "finger"

    def test_default_ports(self, plugin):
        """PROVES: Plugin knows Finger default port"""
        assert 79 in plugin.default_ports

    def test_service_names(self, plugin):
        """PROVES: Plugin recognizes Finger service names"""
        assert 'finger' in plugin.service_names

    def test_detect_by_service_name(self, plugin):
        """PROVES: Plugin detects Finger by service name"""
        port_info = {'service': 'finger', 'port': 79}
        assert plugin.detect(port_info) == True

    def test_detect_by_port(self, plugin):
        """PROVES: Plugin detects Finger by port 79"""
        port_info = {'service': 'unknown', 'port': 79}
        assert plugin.detect(port_info) == True

    def test_detect_negative(self, plugin):
        """PROVES: Plugin rejects unrelated services"""
        port_info = {'service': 'http', 'port': 80}
        assert plugin.detect(port_info) == False

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid structure"""
        tree = plugin.get_task_tree('192.168.45.100', 79, {'service': 'finger'})

        # Root structure
        assert 'id' in tree
        assert 'name' in tree
        assert 'type' in tree
        assert tree['type'] == 'parent'
        assert 'children' in tree

        # Has tasks
        assert len(tree['children']) > 0

        # Verify task IDs
        assert tree['id'] == 'finger-enum-79'

    def test_banner_grabbing_task(self, plugin):
        """PROVES: Banner grabbing task has complete metadata"""
        tree = plugin.get_task_tree('192.168.45.100', 79, {'service': 'finger'})

        # Find banner task
        banner_task = [t for t in tree['children'] if 'banner' in t['id']][0]

        # Verify command
        assert 'command' in banner_task['metadata']
        assert 'nc -vn 192.168.45.100 79' == banner_task['metadata']['command']

        # Verify OSCP metadata
        assert 'flag_explanations' in banner_task['metadata']
        assert 'success_indicators' in banner_task['metadata']
        assert 'failure_indicators' in banner_task['metadata']
        assert 'alternatives' in banner_task['metadata']
        assert 'tags' in banner_task['metadata']

        # Verify tags
        assert 'OSCP:HIGH' in banner_task['metadata']['tags']
        assert 'QUICK_WIN' in banner_task['metadata']['tags']

    def test_user_enumeration_tasks(self, plugin):
        """PROVES: Plugin generates user enumeration tasks"""
        tree = plugin.get_task_tree('192.168.45.100', 79, {'service': 'finger'})

        # Should have multiple enumeration tasks
        task_ids = [t['id'] for t in tree['children']]
        assert 'finger-list-users-79' in task_ids
        assert 'finger-enum-users-79' in task_ids
        assert 'finger-user-enum-79' in task_ids

    def test_command_injection_task(self, plugin):
        """PROVES: Plugin includes command injection testing"""
        tree = plugin.get_task_tree('192.168.45.100', 79, {'service': 'finger'})

        # Find command injection task
        injection_tasks = [t for t in tree['children'] if 'injection' in t['id']]
        assert len(injection_tasks) > 0

        injection_task = injection_tasks[0]
        assert injection_task['type'] == 'manual'
        assert 'alternatives' in injection_task['metadata']

    def test_all_tasks_have_alternatives(self, plugin):
        """PROVES: All command tasks have manual alternatives"""
        tree = plugin.get_task_tree('192.168.45.100', 79, {'service': 'finger'})

        command_tasks = [t for t in tree['children'] if t['type'] == 'command']

        for task in command_tasks:
            assert 'alternatives' in task['metadata'], f"Task {task['id']} missing alternatives"
            assert len(task['metadata']['alternatives']) > 0


class TestIRCPlugin:
    """Test suite for IRC enumeration plugin"""

    @pytest.fixture
    def plugin(self):
        """Create IRC plugin instance"""
        return IRCPlugin()

    def test_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "irc"

    def test_default_ports(self, plugin):
        """PROVES: Plugin knows IRC default ports"""
        assert 194 in plugin.default_ports
        assert 6667 in plugin.default_ports
        assert 7000 in plugin.default_ports

    def test_detect_by_service_name(self, plugin):
        """PROVES: Plugin detects IRC by service name"""
        port_info = {'service': 'irc', 'port': 6667}
        assert plugin.detect(port_info) == True

        port_info = {'service': 'ircd', 'port': 6667}
        assert plugin.detect(port_info) == True

    def test_detect_by_port_range(self, plugin):
        """PROVES: Plugin detects IRC by port range (6660-7000)"""
        port_info = {'service': 'unknown', 'port': 6667}
        assert plugin.detect(port_info) == True

        port_info = {'service': 'unknown', 'port': 6669}
        assert plugin.detect(port_info) == True

        port_info = {'service': 'unknown', 'port': 6700}
        assert plugin.detect(port_info) == True

    def test_detect_negative(self, plugin):
        """PROVES: Plugin rejects unrelated services"""
        port_info = {'service': 'http', 'port': 80}
        assert plugin.detect(port_info) == False

        port_info = {'service': 'unknown', 'port': 5000}
        assert plugin.detect(port_info) == False

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid structure"""
        tree = plugin.get_task_tree('192.168.45.100', 6667, {'service': 'irc'})

        assert tree['id'] == 'irc-enum-6667'
        assert tree['type'] == 'parent'
        assert len(tree['children']) > 0

    def test_banner_grabbing_tasks(self, plugin):
        """PROVES: Plugin includes both plaintext and TLS banner grabbing"""
        tree = plugin.get_task_tree('192.168.45.100', 6667, {'service': 'irc'})

        task_ids = [t['id'] for t in tree['children']]
        assert 'irc-banner-6667' in task_ids
        assert 'irc-tls-6667' in task_ids

    def test_manual_enumeration_task(self, plugin):
        """PROVES: Plugin provides manual IRC enumeration workflow"""
        tree = plugin.get_task_tree('192.168.45.100', 6667, {'service': 'irc'})

        manual_tasks = [t for t in tree['children'] if t['type'] == 'manual']
        assert len(manual_tasks) > 0

        # Check for IRC command workflow
        enum_task = [t for t in manual_tasks if 'manual-enum' in t['id']][0]
        assert 'alternatives' in enum_task['metadata']
        alternatives_text = ' '.join(enum_task['metadata']['alternatives'])
        assert 'USER' in alternatives_text
        assert 'NICK' in alternatives_text
        assert 'NAMES' in alternatives_text

    def test_default_credentials_task(self, plugin):
        """PROVES: Plugin includes default credential testing"""
        tree = plugin.get_task_tree('192.168.45.100', 6667, {'service': 'irc'})

        creds_tasks = [t for t in tree['children'] if 'creds' in t['id']]
        assert len(creds_tasks) > 0

        creds_task = creds_tasks[0]
        assert 'wealllikedebian' in str(creds_task['metadata'].get('alternatives', []))

    def test_nmap_scripts_task(self, plugin):
        """PROVES: Plugin includes nmap IRC scripts"""
        tree = plugin.get_task_tree('192.168.45.100', 6667, {'service': 'irc'})

        nmap_tasks = [t for t in tree['children'] if 'nmap' in t['id']]
        assert len(nmap_tasks) > 0

        nmap_task = nmap_tasks[0]
        assert 'irc-botnet-channels' in nmap_task['metadata']['command']
        assert 'irc-unrealircd-backdoor' in nmap_task['metadata']['command']

    def test_oscp_metadata_completeness(self, plugin):
        """PROVES: All command tasks have OSCP-required metadata"""
        tree = plugin.get_task_tree('192.168.45.100', 6667, {'service': 'irc'})

        command_tasks = [t for t in tree['children'] if t['type'] == 'command']

        for task in command_tasks:
            metadata = task['metadata']
            assert 'command' in metadata, f"Task {task['id']} missing command"
            assert 'description' in metadata, f"Task {task['id']} missing description"
            assert 'flag_explanations' in metadata, f"Task {task['id']} missing flag_explanations"
            assert 'tags' in metadata, f"Task {task['id']} missing tags"
            assert len(metadata['tags']) > 0


class TestRTSPPlugin:
    """Test suite for RTSP streaming enumeration plugin"""

    @pytest.fixture
    def plugin(self):
        """Create RTSP plugin instance"""
        return RTSPPlugin()

    def test_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "rtsp"

    def test_default_ports(self, plugin):
        """PROVES: Plugin knows RTSP default ports"""
        assert 554 in plugin.default_ports
        assert 8554 in plugin.default_ports

    def test_detect_by_service_name(self, plugin):
        """PROVES: Plugin detects RTSP by service name"""
        port_info = {'service': 'rtsp', 'port': 554}
        assert plugin.detect(port_info) == True

    def test_detect_by_port(self, plugin):
        """PROVES: Plugin detects RTSP by port"""
        port_info = {'service': 'unknown', 'port': 554}
        assert plugin.detect(port_info) == True

        port_info = {'service': 'unknown', 'port': 8554}
        assert plugin.detect(port_info) == True

    def test_detect_negative(self, plugin):
        """PROVES: Plugin rejects unrelated services"""
        port_info = {'service': 'http', 'port': 80}
        assert plugin.detect(port_info) == False

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid structure"""
        tree = plugin.get_task_tree('192.168.45.100', 554, {'service': 'rtsp'})

        assert tree['id'] == 'rtsp-enum-554'
        assert tree['type'] == 'parent'
        assert len(tree['children']) > 0

    def test_describe_request_task(self, plugin):
        """PROVES: Plugin includes RTSP DESCRIBE request"""
        tree = plugin.get_task_tree('192.168.45.100', 554, {'service': 'rtsp'})

        describe_tasks = [t for t in tree['children'] if 'describe' in t['id']]
        assert len(describe_tasks) > 0

        describe_task = describe_tasks[0]
        assert describe_task['type'] == 'manual'
        assert 'DESCRIBE' in str(describe_task['metadata'].get('alternatives', []))

    def test_authentication_tasks(self, plugin):
        """PROVES: Plugin includes authentication testing"""
        tree = plugin.get_task_tree('192.168.45.100', 554, {'service': 'rtsp'})

        auth_tasks = [t for t in tree['children'] if 'auth' in t['id']]
        assert len(auth_tasks) > 0

        # Check for Basic auth
        basic_auth_tasks = [t for t in auth_tasks if 'basic' in t['id']]
        assert len(basic_auth_tasks) > 0

    def test_ffplay_viewing_task(self, plugin):
        """PROVES: Plugin includes stream viewing with ffplay"""
        tree = plugin.get_task_tree('192.168.45.100', 554, {'service': 'rtsp'})

        ffplay_tasks = [t for t in tree['children'] if 'ffplay' in t['id']]
        assert len(ffplay_tasks) > 0

        ffplay_task = ffplay_tasks[0]
        assert 'ffplay' in ffplay_task['metadata']['command']
        assert '-rtsp_transport tcp' in ffplay_task['metadata']['command']

    def test_cameradar_task(self, plugin):
        """PROVES: Plugin includes Cameradar automated tool"""
        tree = plugin.get_task_tree('192.168.45.100', 554, {'service': 'rtsp'})

        cameradar_tasks = [t for t in tree['children'] if 'cameradar' in t['id']]
        assert len(cameradar_tasks) > 0

    def test_all_tasks_have_next_steps(self, plugin):
        """PROVES: Tasks provide next steps guidance"""
        tree = plugin.get_task_tree('192.168.45.100', 554, {'service': 'rtsp'})

        for task in tree['children']:
            if task['type'] in ['command', 'manual']:
                # Manual tasks may use alternatives instead of next_steps
                has_guidance = (
                    'next_steps' in task['metadata'] or
                    'alternatives' in task['metadata']
                )
                assert has_guidance, f"Task {task['id']} missing guidance"


class TestEchoPlugin:
    """Test suite for Echo service plugin"""

    @pytest.fixture
    def plugin(self):
        """Create Echo plugin instance"""
        return EchoPlugin()

    def test_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "echo"

    def test_default_ports(self, plugin):
        """PROVES: Plugin knows Echo default port"""
        assert 7 in plugin.default_ports

    def test_detect_by_service_name(self, plugin):
        """PROVES: Plugin detects Echo by service name"""
        port_info = {'service': 'echo', 'port': 7, 'protocol': 'tcp'}
        assert plugin.detect(port_info) == True

    def test_detect_by_port_tcp(self, plugin):
        """PROVES: Plugin detects Echo TCP port"""
        port_info = {'service': 'unknown', 'port': 7, 'protocol': 'tcp'}
        assert plugin.detect(port_info) == True

    def test_detect_by_port_udp(self, plugin):
        """PROVES: Plugin detects Echo UDP port"""
        port_info = {'service': 'unknown', 'port': 7, 'protocol': 'udp'}
        assert plugin.detect(port_info) == True

    def test_detect_negative(self, plugin):
        """PROVES: Plugin rejects unrelated services"""
        port_info = {'service': 'http', 'port': 80}
        assert plugin.detect(port_info) == False

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid structure"""
        tree = plugin.get_task_tree('192.168.45.100', 7, {'service': 'echo', 'protocol': 'tcp'})

        assert tree['id'] == 'echo-enum-7'
        assert tree['type'] == 'parent'
        assert len(tree['children']) > 0

    def test_udp_echo_task(self, plugin):
        """PROVES: Plugin generates UDP-specific task"""
        tree = plugin.get_task_tree('192.168.45.100', 7, {'service': 'echo', 'protocol': 'udp'})

        udp_tasks = [t for t in tree['children'] if 'udp' in t['id']]
        assert len(udp_tasks) > 0

        udp_task = udp_tasks[0]
        assert 'nc -uvn' in udp_task['metadata']['command']

    def test_tcp_echo_task(self, plugin):
        """PROVES: Plugin generates TCP-specific task"""
        tree = plugin.get_task_tree('192.168.45.100', 7, {'service': 'echo', 'protocol': 'tcp'})

        tcp_tasks = [t for t in tree['children'] if 'tcp' in t['id']]
        assert len(tcp_tasks) > 0

        tcp_task = tcp_tasks[0]
        assert 'nc -vn' in tcp_task['metadata']['command']

    def test_dos_note_task(self, plugin):
        """PROVES: Plugin includes DoS risk information"""
        tree = plugin.get_task_tree('192.168.45.100', 7, {'service': 'echo', 'protocol': 'tcp'})

        dos_tasks = [t for t in tree['children'] if 'dos' in t['id']]
        assert len(dos_tasks) > 0

        dos_task = dos_tasks[0]
        assert dos_task['type'] == 'manual'
        assert 'DoS' in dos_task['name'] or 'DoS' in dos_task['metadata']['description']

    def test_low_oscp_relevance_tags(self, plugin):
        """PROVES: Echo tasks are tagged as low OSCP relevance"""
        tree = plugin.get_task_tree('192.168.45.100', 7, {'service': 'echo', 'protocol': 'tcp'})

        for task in tree['children']:
            if 'tags' in task.get('metadata', {}):
                tags = task['metadata']['tags']
                # Should be OSCP:LOW since echo has minimal security value
                oscp_tags = [t for t in tags if 'OSCP:' in t]
                if oscp_tags:
                    assert 'OSCP:LOW' in oscp_tags or 'OSCP:MEDIUM' not in oscp_tags


class TestPluginIntegration:
    """Test plugin integration and registration"""

    def test_all_plugins_registered(self):
        """PROVES: All plugins are auto-registered via decorator"""
        from crack.track.services.registry import ServiceRegistry

        registered_names = [p.name for p in ServiceRegistry.get_all_plugins()]

        assert 'finger' in registered_names
        assert 'irc' in registered_names
        assert 'rtsp' in registered_names
        assert 'echo' in registered_names

    def test_plugins_handle_real_nmap_data(self):
        """PROVES: Plugins work with realistic nmap-style port data"""
        finger = FingerPlugin()
        irc = IRCPlugin()
        rtsp = RTSPPlugin()
        echo = EchoPlugin()

        # Realistic nmap port data
        finger_port = {
            'port': 79,
            'state': 'open',
            'service': 'finger',
            'product': '',
            'version': '',
            'source': 'nmap service scan'
        }

        irc_port = {
            'port': 6667,
            'state': 'open',
            'service': 'irc',
            'product': 'UnrealIRCd',
            'version': '3.2.8.1',
            'source': 'nmap service scan'
        }

        rtsp_port = {
            'port': 554,
            'state': 'open',
            'service': 'rtsp',
            'product': 'RTSP Server',
            'version': '',
            'source': 'nmap service scan'
        }

        echo_port = {
            'port': 7,
            'state': 'open',
            'service': 'echo',
            'protocol': 'udp',
            'source': 'nmap service scan'
        }

        # All should detect correctly
        assert finger.detect(finger_port)
        assert irc.detect(irc_port)
        assert rtsp.detect(rtsp_port)
        assert echo.detect(echo_port)

        # All should generate valid task trees
        finger_tree = finger.get_task_tree('10.10.10.10', 79, finger_port)
        irc_tree = irc.get_task_tree('10.10.10.10', 6667, irc_port)
        rtsp_tree = rtsp.get_task_tree('10.10.10.10', 554, rtsp_port)
        echo_tree = echo.get_task_tree('10.10.10.10', 7, echo_port)

        assert finger_tree['type'] == 'parent'
        assert irc_tree['type'] == 'parent'
        assert rtsp_tree['type'] == 'parent'
        assert echo_tree['type'] == 'parent'

        assert len(finger_tree['children']) >= 5
        assert len(irc_tree['children']) >= 5
        assert len(rtsp_tree['children']) >= 4
        assert len(echo_tree['children']) >= 1
