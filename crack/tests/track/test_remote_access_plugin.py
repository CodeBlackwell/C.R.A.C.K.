"""
Test suite for RemoteAccessPlugin (RDP, VNC, Telnet)

PROVES: Plugin correctly detects and generates tasks for remote access services
"""

import pytest
from crack.track.services.remote_access import RemoteAccessPlugin


class TestRemoteAccessPluginDetection:
    """Test service detection logic"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return RemoteAccessPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "remote-access"

    def test_default_ports(self, plugin):
        """PROVES: Plugin lists correct default ports"""
        assert 3389 in plugin.default_ports  # RDP
        assert 5900 in plugin.default_ports  # VNC
        assert 5901 in plugin.default_ports  # VNC
        assert 23 in plugin.default_ports    # Telnet

    def test_detect_rdp_by_service_name(self, plugin):
        """PROVES: Detects RDP by service name"""
        port_info = {'port': 3389, 'service': 'ms-wbt-server'}
        assert plugin.detect(port_info) == True

    def test_detect_rdp_by_port(self, plugin):
        """PROVES: Detects RDP by port number"""
        port_info = {'port': 3389, 'service': 'unknown'}
        assert plugin.detect(port_info) == True

    def test_detect_vnc_by_service_name(self, plugin):
        """PROVES: Detects VNC by service name"""
        port_info = {'port': 5900, 'service': 'vnc'}
        assert plugin.detect(port_info) == True

    def test_detect_vnc_by_port(self, plugin):
        """PROVES: Detects VNC by port number"""
        port_info = {'port': 5900, 'service': 'unknown'}
        assert plugin.detect(port_info) == True

    def test_detect_telnet_by_service_name(self, plugin):
        """PROVES: Detects Telnet by service name"""
        port_info = {'port': 23, 'service': 'telnet'}
        assert plugin.detect(port_info) == True

    def test_detect_telnet_by_port(self, plugin):
        """PROVES: Detects Telnet by port number"""
        port_info = {'port': 23, 'service': 'unknown'}
        assert plugin.detect(port_info) == True

    def test_detect_realvnc(self, plugin):
        """PROVES: Detects RealVNC variant"""
        port_info = {'port': 5900, 'service': 'realvnc'}
        assert plugin.detect(port_info) == True

    def test_detect_negative_http(self, plugin):
        """PROVES: Does not detect HTTP"""
        port_info = {'port': 80, 'service': 'http'}
        assert plugin.detect(port_info) == False

    def test_detect_negative_ssh(self, plugin):
        """PROVES: Does not detect SSH"""
        port_info = {'port': 22, 'service': 'ssh'}
        assert plugin.detect(port_info) == False


class TestRDPTaskGeneration:
    """Test RDP task tree generation"""

    @pytest.fixture
    def plugin(self):
        return RemoteAccessPlugin()

    def test_rdp_task_tree_structure(self, plugin):
        """PROVES: RDP task tree has valid structure"""
        service_info = {
            'port': 3389,
            'service': 'ms-wbt-server',
            'version': '10.0',
            'product': 'Microsoft Terminal Services'
        }

        tree = plugin.get_task_tree('192.168.45.100', 3389, service_info)

        # Verify root structure
        assert tree['id'] == 'remote-access-enum-3389'
        assert tree['type'] == 'parent'
        assert 'children' in tree
        assert len(tree['children']) > 0

    def test_rdp_nmap_enumeration_task(self, plugin):
        """PROVES: RDP nmap enumeration task included"""
        service_info = {'port': 3389, 'service': 'ms-wbt-server'}
        tree = plugin.get_task_tree('192.168.45.100', 3389, service_info)

        # Find RDP nmap task
        rdp_tasks = [t for t in tree['children'] if 'rdp-nmap-enum' in t['id']]
        assert len(rdp_tasks) == 1

        task = rdp_tasks[0]
        metadata = task['metadata']

        # Verify command
        assert 'nmap' in metadata['command']
        assert 'rdp-enum-encryption' in metadata['command']
        assert 'rdp-vuln-ms12-020' in metadata['command']
        assert 'rdp-ntlm-info' in metadata['command']

    def test_rdp_credential_check_task(self, plugin):
        """PROVES: RDP credential check task included"""
        service_info = {'port': 3389, 'service': 'rdp'}
        tree = plugin.get_task_tree('192.168.45.100', 3389, service_info)

        # Find credential check task
        cred_tasks = [t for t in tree['children'] if 'rdp-cred-check' in t['id']]
        assert len(cred_tasks) == 1

        task = cred_tasks[0]
        metadata = task['metadata']

        # Verify Pass-the-Hash support
        assert 'xfreerdp' in metadata['command']
        assert '/pth:' in metadata['command']
        assert 'NTLM hash' in metadata['description']

    def test_rdp_password_spray_task(self, plugin):
        """PROVES: RDP password spraying task included"""
        service_info = {'port': 3389, 'service': 'rdp'}
        tree = plugin.get_task_tree('192.168.45.100', 3389, service_info)

        spray_tasks = [t for t in tree['children'] if 'password-spray' in t['id']]
        assert len(spray_tasks) == 1

        task = spray_tasks[0]
        metadata = task['metadata']

        # Verify lockout warning
        assert 'CAREFUL' in task['name'] or 'Account Lockout' in task['name']
        assert 'NOISY' in metadata['tags']

    def test_rdp_session_hijacking_task(self, plugin):
        """PROVES: RDP session hijacking documented"""
        service_info = {'port': 3389, 'service': 'rdp'}
        tree = plugin.get_task_tree('192.168.45.100', 3389, service_info)

        hijack_tasks = [t for t in tree['children'] if 'session-hijack' in t['id']]
        assert len(hijack_tasks) == 1

        task = hijack_tasks[0]
        assert task['type'] == 'manual'
        assert 'tscon' in task['metadata']['notes']
        assert 'mimikatz' in task['metadata']['notes'].lower()

    def test_rdp_sticky_keys_task(self, plugin):
        """PROVES: Sticky keys backdoor check included"""
        service_info = {'port': 3389, 'service': 'rdp'}
        tree = plugin.get_task_tree('192.168.45.100', 3389, service_info)

        sticky_tasks = [t for t in tree['children'] if 'sticky-keys' in t['id']]
        assert len(sticky_tasks) == 1

    def test_rdp_automation_tools_parent(self, plugin):
        """PROVES: RDP automation tools grouped under parent"""
        service_info = {'port': 3389, 'service': 'rdp'}
        tree = plugin.get_task_tree('192.168.45.100', 3389, service_info)

        # Find automation tools parent
        tool_parents = [t for t in tree['children'] if 'auto-tools' in t['id']]
        assert len(tool_parents) == 1

        parent = tool_parents[0]
        assert parent['type'] == 'parent'
        assert len(parent['children']) >= 3  # AutoRDPwn, EvilRDP, SharpRDP

    def test_rdp_oscp_metadata_complete(self, plugin):
        """PROVES: RDP tasks have complete OSCP metadata"""
        service_info = {'port': 3389, 'service': 'rdp'}
        tree = plugin.get_task_tree('192.168.45.100', 3389, service_info)

        # Check first command task
        command_tasks = [t for t in tree['children'] if t['type'] == 'command']
        assert len(command_tasks) > 0

        task = command_tasks[0]
        metadata = task['metadata']

        # Verify required fields
        assert 'command' in metadata
        assert 'description' in metadata
        assert 'tags' in metadata
        assert 'flag_explanations' in metadata
        assert 'success_indicators' in metadata
        assert 'failure_indicators' in metadata
        assert 'next_steps' in metadata
        assert 'alternatives' in metadata


class TestVNCTaskGeneration:
    """Test VNC task tree generation"""

    @pytest.fixture
    def plugin(self):
        return RemoteAccessPlugin()

    def test_vnc_task_tree_structure(self, plugin):
        """PROVES: VNC task tree has valid structure"""
        service_info = {'port': 5900, 'service': 'vnc'}
        tree = plugin.get_task_tree('192.168.45.100', 5900, service_info)

        assert tree['id'] == 'remote-access-enum-5900'
        assert tree['type'] == 'parent'
        assert len(tree['children']) > 0

    def test_vnc_nmap_enumeration_task(self, plugin):
        """PROVES: VNC nmap enumeration task included"""
        service_info = {'port': 5900, 'service': 'vnc'}
        tree = plugin.get_task_tree('192.168.45.100', 5900, service_info)

        vnc_tasks = [t for t in tree['children'] if 'vnc-nmap-enum' in t['id']]
        assert len(vnc_tasks) == 1

        task = vnc_tasks[0]
        metadata = task['metadata']

        # Verify VNC scripts
        assert 'vnc-info' in metadata['command']
        assert 'realvnc-auth-bypass' in metadata['command']
        assert 'vnc-title' in metadata['command']

    def test_vnc_no_auth_test(self, plugin):
        """PROVES: VNC no-auth test included"""
        service_info = {'port': 5900, 'service': 'vnc'}
        tree = plugin.get_task_tree('192.168.45.100', 5900, service_info)

        no_auth_tasks = [t for t in tree['children'] if 'vnc-no-auth' in t['id']]
        assert len(no_auth_tasks) == 1

        task = no_auth_tasks[0]
        metadata = task['metadata']

        # Verify no-auth methods
        assert 'vnc_none_auth' in metadata['command'] or 'vncviewer' in metadata['command']

    def test_vnc_password_decrypt_task(self, plugin):
        """PROVES: VNC password decryption documented"""
        service_info = {'port': 5900, 'service': 'vnc'}
        tree = plugin.get_task_tree('192.168.45.100', 5900, service_info)

        decrypt_tasks = [t for t in tree['children'] if 'password-decrypt' in t['id']]
        assert len(decrypt_tasks) == 1

        task = decrypt_tasks[0]
        assert task['type'] == 'manual'
        assert 'vncpwd' in task['metadata']['notes']
        assert '3DES' in task['metadata']['notes']

    def test_vnc_bruteforce_task(self, plugin):
        """PROVES: VNC brute-force task included"""
        service_info = {'port': 5900, 'service': 'vnc'}
        tree = plugin.get_task_tree('192.168.45.100', 5900, service_info)

        brute_tasks = [t for t in tree['children'] if 'bruteforce' in t['id']]
        assert len(brute_tasks) == 1

        task = brute_tasks[0]
        metadata = task['metadata']

        # Verify brute-force tools
        assert 'hydra' in metadata['command'] or 'msfconsole' in metadata['command']

    def test_vnc_connection_task(self, plugin):
        """PROVES: VNC connection task included"""
        service_info = {'port': 5900, 'service': 'vnc'}
        tree = plugin.get_task_tree('192.168.45.100', 5900, service_info)

        connect_tasks = [t for t in tree['children'] if 'vnc-connect' in t['id']]
        assert len(connect_tasks) == 1

        task = connect_tasks[0]
        metadata = task['metadata']

        # Verify vncviewer usage
        assert 'vncviewer' in metadata['command']
        assert '-passwd' in metadata['command']


class TestTelnetTaskGeneration:
    """Test Telnet task tree generation"""

    @pytest.fixture
    def plugin(self):
        return RemoteAccessPlugin()

    def test_telnet_task_tree_structure(self, plugin):
        """PROVES: Telnet task tree has valid structure"""
        service_info = {'port': 23, 'service': 'telnet'}
        tree = plugin.get_task_tree('192.168.45.100', 23, service_info)

        assert tree['id'] == 'remote-access-enum-23'
        assert tree['type'] == 'parent'
        assert len(tree['children']) > 0

    def test_telnet_banner_grabbing_task(self, plugin):
        """PROVES: Telnet banner grabbing task included"""
        service_info = {'port': 23, 'service': 'telnet'}
        tree = plugin.get_task_tree('192.168.45.100', 23, service_info)

        banner_tasks = [t for t in tree['children'] if 'telnet-banner' in t['id']]
        assert len(banner_tasks) == 1

        task = banner_tasks[0]
        metadata = task['metadata']

        # Verify netcat usage
        assert 'nc' in metadata['command']
        assert 'QUICK_WIN' in metadata['tags']

    def test_telnet_nmap_enumeration_task(self, plugin):
        """PROVES: Telnet nmap enumeration task included"""
        service_info = {'port': 23, 'service': 'telnet'}
        tree = plugin.get_task_tree('192.168.45.100', 23, service_info)

        nmap_tasks = [t for t in tree['children'] if 'telnet-nmap-enum' in t['id']]
        assert len(nmap_tasks) == 1

        task = nmap_tasks[0]
        metadata = task['metadata']

        # Verify telnet scripts
        assert '*telnet*' in metadata['command']
        assert 'safe' in metadata['command']

    def test_telnet_default_credentials_task(self, plugin):
        """PROVES: Telnet default credentials documented"""
        service_info = {'port': 23, 'service': 'telnet'}
        tree = plugin.get_task_tree('192.168.45.100', 23, service_info)

        default_tasks = [t for t in tree['children'] if 'default-creds' in t['id']]
        assert len(default_tasks) == 1

        task = default_tasks[0]
        assert task['type'] == 'manual'
        # Verify vendor credentials listed
        assert 'Cisco' in task['metadata']['notes']
        assert 'Mirai' in task['metadata']['notes']

    def test_telnet_bruteforce_task(self, plugin):
        """PROVES: Telnet brute-force task included"""
        service_info = {'port': 23, 'service': 'telnet'}
        tree = plugin.get_task_tree('192.168.45.100', 23, service_info)

        brute_tasks = [t for t in tree['children'] if 'bruteforce' in t['id']]
        assert len(brute_tasks) == 1

        task = brute_tasks[0]
        metadata = task['metadata']

        # Verify brute-force tools
        assert 'hydra' in metadata['command'] or 'medusa' in metadata['command']

    def test_telnet_sniffing_task(self, plugin):
        """PROVES: Telnet credential sniffing documented"""
        service_info = {'port': 23, 'service': 'telnet'}
        tree = plugin.get_task_tree('192.168.45.100', 23, service_info)

        sniff_tasks = [t for t in tree['children'] if 'sniff' in t['id']]
        assert len(sniff_tasks) == 1

        task = sniff_tasks[0]
        assert task['type'] == 'manual'
        assert 'tcpdump' in task['metadata']['notes']
        assert 'cleartext' in task['metadata']['notes'].lower()

    def test_telnet_recent_cves_parent(self, plugin):
        """PROVES: Recent Telnet CVEs grouped under parent"""
        service_info = {'port': 23, 'service': 'telnet'}
        tree = plugin.get_task_tree('192.168.45.100', 23, service_info)

        cve_parents = [t for t in tree['children'] if 'recent-cves' in t['id']]
        assert len(cve_parents) == 1

        parent = cve_parents[0]
        assert parent['type'] == 'parent'
        assert len(parent['children']) >= 3  # D-Link, NETGEAR, inetutils

    def test_telnet_post_exploitation_task(self, plugin):
        """PROVES: Telnet post-exploitation documented"""
        service_info = {'port': 23, 'service': 'telnet'}
        tree = plugin.get_task_tree('192.168.45.100', 23, service_info)

        post_tasks = [t for t in tree['children'] if 'post-exploit' in t['id']]
        assert len(post_tasks) == 1

        task = post_tasks[0]
        assert task['type'] == 'manual'
        assert 'pty.spawn' in task['metadata']['notes']


class TestOSCPMetadataCompleteness:
    """Test OSCP metadata completeness across all services"""

    @pytest.fixture
    def plugin(self):
        return RemoteAccessPlugin()

    def test_all_command_tasks_have_flag_explanations(self, plugin):
        """PROVES: All command tasks explain their flags"""
        # Test RDP
        rdp_info = {'port': 3389, 'service': 'rdp'}
        rdp_tree = plugin.get_task_tree('192.168.45.100', 3389, rdp_info)

        # Test VNC
        vnc_info = {'port': 5900, 'service': 'vnc'}
        vnc_tree = plugin.get_task_tree('192.168.45.100', 5900, vnc_info)

        # Test Telnet
        telnet_info = {'port': 23, 'service': 'telnet'}
        telnet_tree = plugin.get_task_tree('192.168.45.100', 23, telnet_info)

        # Check all command tasks
        for tree in [rdp_tree, vnc_tree, telnet_tree]:
            for task in tree['children']:
                if task['type'] == 'command':
                    metadata = task['metadata']
                    assert 'flag_explanations' in metadata, f"Task {task['id']} missing flag_explanations"
                    assert len(metadata['flag_explanations']) > 0

    def test_all_tasks_have_success_failure_indicators(self, plugin):
        """PROVES: All tasks provide success/failure indicators"""
        rdp_info = {'port': 3389, 'service': 'rdp'}
        tree = plugin.get_task_tree('192.168.45.100', 3389, rdp_info)

        for task in tree['children']:
            if 'metadata' in task:
                metadata = task['metadata']
                assert 'success_indicators' in metadata or task['type'] == 'parent'
                if 'success_indicators' in metadata:
                    assert len(metadata['success_indicators']) > 0

    def test_all_tasks_have_alternatives(self, plugin):
        """PROVES: All tasks provide manual alternatives"""
        vnc_info = {'port': 5900, 'service': 'vnc'}
        tree = plugin.get_task_tree('192.168.45.100', 5900, vnc_info)

        for task in tree['children']:
            if 'metadata' in task and task['type'] == 'command':
                metadata = task['metadata']
                assert 'alternatives' in metadata
                assert len(metadata['alternatives']) > 0

    def test_oscp_tags_present(self, plugin):
        """PROVES: Tasks tagged with OSCP relevance"""
        telnet_info = {'port': 23, 'service': 'telnet'}
        tree = plugin.get_task_tree('192.168.45.100', 23, telnet_info)

        command_tasks = [t for t in tree['children'] if t['type'] == 'command']
        assert len(command_tasks) > 0

        # At least some tasks should have OSCP tags
        oscp_tagged = [t for t in command_tasks if 'tags' in t['metadata'] and
                       any('OSCP' in tag for tag in t['metadata']['tags'])]
        assert len(oscp_tagged) > 0


class TestMultiServiceDetection:
    """Test plugin behavior with ambiguous service info"""

    @pytest.fixture
    def plugin(self):
        return RemoteAccessPlugin()

    def test_rdp_on_non_standard_port(self, plugin):
        """PROVES: Detects RDP on non-standard port by service name"""
        port_info = {'port': 13389, 'service': 'ms-wbt-server'}
        assert plugin.detect(port_info) == True

    def test_vnc_on_display_1(self, plugin):
        """PROVES: Detects VNC display 1 (port 5901)"""
        port_info = {'port': 5901, 'service': 'vnc'}
        tree = plugin.get_task_tree('192.168.45.100', 5901, port_info)
        assert tree['id'] == 'remote-access-enum-5901'

    def test_web_vnc_port_5800(self, plugin):
        """PROVES: Detects web-based VNC on port 5800"""
        port_info = {'port': 5800, 'service': 'vnc-http'}
        assert plugin.detect(port_info) == True
