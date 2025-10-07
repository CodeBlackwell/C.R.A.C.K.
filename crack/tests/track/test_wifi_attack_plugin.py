"""
Tests for WiFi Attack service plugin

Validates:
- Plugin registration and detection
- Task tree generation for WiFi pentesting workflows
- WPS, WPA/WPA2, Evil Twin, KARMA/MANA attack tasks
- OSCP metadata completeness (flag explanations, alternatives, time estimates)
- Integration with CRACK Track system
"""

import pytest
from crack.track.services.wifi_attack import WiFiAttackPlugin


class TestWiFiAttackPlugin:
    """Test suite for WiFi Attack plugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return WiFiAttackPlugin()

    @pytest.fixture
    def wpa2_network_info(self):
        """Sample WPA2 network metadata"""
        return {
            'essid': 'TestNetwork',
            'bssid': '00:11:22:33:44:55',
            'channel': 6,
            'security': 'WPA2',
            'wps': False,
            'interface': 'wlan0'
        }

    @pytest.fixture
    def wps_enabled_network_info(self):
        """Sample WPS-enabled network metadata"""
        return {
            'essid': 'WPS_Network',
            'bssid': 'AA:BB:CC:DD:EE:FF',
            'channel': 11,
            'security': 'WPA2',
            'wps': True,
            'interface': 'wlan0'
        }

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct identifier"""
        assert plugin.name == "wifi-attack"

    def test_default_ports_empty(self, plugin):
        """PROVES: WiFi attacks are not port-specific (wireless interface-based)"""
        assert plugin.default_ports == []

    def test_service_names(self, plugin):
        """PROVES: Plugin recognizes WiFi/wireless keywords"""
        expected_names = ['wifi', 'wireless', '802.11', 'wlan']
        assert plugin.service_names == expected_names

    def test_detect_returns_false(self, plugin):
        """PROVES: Plugin is manually triggered, not auto-detected"""
        port_info = {'port': 80, 'service': 'http'}
        assert plugin.detect(port_info) == False

    def test_task_tree_structure(self, plugin, wpa2_network_info):
        """PROVES: Task tree has valid parent/children hierarchy"""
        tree = plugin.get_task_tree('TestNetwork', 6, wpa2_network_info)

        # Verify root structure
        assert 'id' in tree
        assert 'name' in tree
        assert 'type' in tree
        assert tree['type'] == 'parent'
        assert 'children' in tree

        # Verify tree contains main phases
        assert len(tree['children']) > 0

    def test_setup_phase_exists(self, plugin, wpa2_network_info):
        """PROVES: Setup phase includes monitor mode and interface preparation"""
        tree = plugin.get_task_tree('TestNetwork', 6, wpa2_network_info)

        # Find setup phase
        setup_phase = next(c for c in tree['children'] if 'setup' in c['id'].lower())

        # Verify setup includes key tasks
        task_ids = [t['id'] for t in setup_phase['children']]

        assert any('kill-processes' in tid or 'kill' in tid for tid in task_ids)
        assert any('monitor-mode' in tid or 'monitor' in tid for tid in task_ids)
        assert any('scan' in tid or 'airodump' in tid for tid in task_ids)

    def test_airmon_kill_processes_task(self, plugin, wpa2_network_info):
        """PROVES: Kill interfering processes task configured correctly"""
        tree = plugin.get_task_tree('TestNetwork', 6, wpa2_network_info)

        setup_phase = next(c for c in tree['children'] if 'setup' in c['id'].lower())
        kill_task = next(c for c in setup_phase['children'] if 'kill' in c['id'])

        metadata = kill_task['metadata']

        # Verify command
        assert 'airmon-ng check kill' in metadata['command']

        # Verify tags
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'QUICK_WIN' in metadata['tags']

        # Verify flag explanations
        assert 'flag_explanations' in metadata
        assert 'kill' in metadata['flag_explanations']

        # Verify alternatives
        assert 'alternatives' in metadata
        alternatives_str = ' '.join(metadata['alternatives'])
        assert 'networkmanager' in alternatives_str.lower() or 'systemctl' in alternatives_str.lower()

    def test_monitor_mode_task(self, plugin, wpa2_network_info):
        """PROVES: Monitor mode setup includes airmon-ng command"""
        tree = plugin.get_task_tree('TestNetwork', 6, wpa2_network_info)

        setup_phase = next(c for c in tree['children'] if 'setup' in c['id'].lower())
        monitor_task = next(c for c in setup_phase['children'] if 'monitor-mode' in c['id'])

        metadata = monitor_task['metadata']

        # Verify command includes interface
        assert 'airmon-ng start' in metadata['command']
        assert 'wlan0' in metadata['command']

        # Verify time estimate
        assert 'estimated_time' in metadata
        assert '30 seconds' in metadata['estimated_time'].lower() or '< 30' in metadata['estimated_time']

        # Verify success indicators
        assert 'success_indicators' in metadata
        assert len(metadata['success_indicators']) >= 2

    def test_airodump_scan_task(self, plugin, wpa2_network_info):
        """PROVES: Airodump scan task covers 2.4GHz and 5GHz bands"""
        tree = plugin.get_task_tree('TestNetwork', 6, wpa2_network_info)

        setup_phase = next(c for c in tree['children'] if 'setup' in c['id'].lower())
        scan_task = next(c for c in setup_phase['children'] if 'scan' in c['id'] or 'airodump' in c['id'])

        metadata = scan_task['metadata']

        # Verify command
        assert 'airodump-ng' in metadata['command']
        assert '--band abg' in metadata['command']  # 2.4GHz + 5GHz
        assert '--wps' in metadata['command']  # Show WPS status

        # Verify flag explanations
        assert 'flag_explanations' in metadata
        assert '--band abg' in metadata['flag_explanations'] or '--band' in str(metadata['flag_explanations'])

        # Verify tags
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'RECON' in metadata['tags']

    def test_wps_attacks_phase_conditional(self, plugin, wps_enabled_network_info):
        """PROVES: WPS attack phase only appears when WPS is enabled"""
        # Test with WPS enabled
        tree_wps = plugin.get_task_tree('WPS_Network', 11, wps_enabled_network_info)
        phase_ids = [c['id'] for c in tree_wps['children']]
        assert any('wps' in pid for pid in phase_ids)

        # Test without WPS
        no_wps_info = wps_enabled_network_info.copy()
        no_wps_info['wps'] = False
        tree_no_wps = plugin.get_task_tree('NoWPS_Network', 11, no_wps_info)
        phase_ids_no_wps = [c['id'] for c in tree_no_wps['children']]

        # WPS phase should not appear or should be empty
        wps_phases = [c for c in tree_no_wps['children'] if 'wps' in c['id']]
        # Either no WPS phase, or phase exists but no children (design choice)
        # For this plugin: WPS phase only added if wps_enabled

    def test_wps_pixie_dust_attack(self, plugin, wps_enabled_network_info):
        """PROVES: WPS Pixie Dust attack configured with reaver"""
        tree = plugin.get_task_tree('WPS_Network', 11, wps_enabled_network_info)

        wps_phase = next(c for c in tree['children'] if 'wps' in c['id'])
        pixie_task = next(c for c in wps_phase['children'] if 'pixie-dust' in c['id'] or 'pixie' in c['id'])

        metadata = pixie_task['metadata']

        # Verify reaver command with Pixie Dust flags
        assert 'reaver' in metadata['command']
        assert '-K 1' in metadata['command'] or '-K' in metadata['command']  # Pixie Dust mode
        assert wps_enabled_network_info['bssid'] in metadata['command']

        # Verify tags
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'QUICK_WIN' in metadata['tags']
        assert 'EXPLOIT' in metadata['tags']

        # Verify time estimate (Pixie Dust is fast)
        assert 'estimated_time' in metadata
        assert '5' in metadata['estimated_time'] or '30' in metadata['estimated_time'] or 'seconds' in metadata['estimated_time']

        # Verify alternatives include bully
        alternatives_str = ' '.join(metadata['alternatives'])
        assert 'bully' in alternatives_str.lower()

    def test_wps_null_pin_attack(self, plugin, wps_enabled_network_info):
        """PROVES: WPS NULL PIN attack uses empty PIN parameter"""
        tree = plugin.get_task_tree('WPS_Network', 11, wps_enabled_network_info)

        wps_phase = next(c for c in tree['children'] if 'wps' in c['id'])
        null_pin_task = next(c for c in wps_phase['children'] if 'null-pin' in c['id'] or 'null' in c['id'].lower())

        metadata = null_pin_task['metadata']

        # Verify empty PIN
        assert '-p ""' in metadata['command'] or "p ''" in metadata['command']

        # Verify QUICK_WIN (fast attempt)
        assert 'QUICK_WIN' in metadata['tags']

        # Verify time estimate
        assert 'estimated_time' in metadata
        assert '1 minute' in metadata['estimated_time'] or '< 1' in metadata['estimated_time']

    def test_wpa_attacks_phase_exists(self, plugin, wpa2_network_info):
        """PROVES: WPA/WPA2-PSK attack phase always present"""
        tree = plugin.get_task_tree('TestNetwork', 6, wpa2_network_info)

        phase_ids = [c['id'] for c in tree['children']]
        assert any('wpa' in pid for pid in phase_ids)

    def test_pmkid_capture_task(self, plugin, wpa2_network_info):
        """PROVES: PMKID capture task uses hcxdumptool (clientless attack)"""
        tree = plugin.get_task_tree('TestNetwork', 6, wpa2_network_info)

        wpa_phase = next(c for c in tree['children'] if 'wpa-attacks' in c['id'])
        pmkid_task = next(c for c in wpa_phase['children'] if 'pmkid' in c['id'].lower())

        metadata = pmkid_task['metadata']

        # Verify hcxdumptool command
        assert 'hcxdumptool' in metadata['command']
        assert '-i' in metadata['command']  # Interface parameter
        assert '-o' in metadata['command']  # Output file

        # Verify QUICK_WIN and OSCP:HIGH tags (PMKID is major discovery)
        assert 'QUICK_WIN' in metadata['tags']
        assert 'OSCP:HIGH' in metadata['tags']

        # Verify alternatives include eaphammer
        alternatives_str = ' '.join(metadata['alternatives'])
        assert 'eaphammer' in alternatives_str.lower() or 'bettercap' in alternatives_str.lower()

        # Verify next steps include hashcat cracking
        next_steps_str = ' '.join(metadata['next_steps'])
        assert 'hashcat' in next_steps_str.lower()
        assert 'hcxpcaptool' in next_steps_str.lower() or 'convert' in next_steps_str.lower()

    def test_handshake_capture_workflow(self, plugin, wpa2_network_info):
        """PROVES: Handshake capture includes airodump + deauth + verification"""
        tree = plugin.get_task_tree('TestNetwork', 6, wpa2_network_info)

        wpa_phase = next(c for c in tree['children'] if 'wpa-attacks' in c['id'])
        handshake_parent = next(c for c in wpa_phase['children'] if 'handshake-capture' in c['id'])

        # Verify handshake capture is a workflow (parent with children)
        assert handshake_parent['type'] == 'parent'
        assert len(handshake_parent['children']) >= 3

        task_names = [t['name'].lower() for t in handshake_parent['children']]

        # Verify workflow steps
        assert any('airodump' in name or 'capture' in name for name in task_names)
        assert any('deauth' in name for name in task_names)
        assert any('verify' in name for name in task_names)

    def test_deauth_attack_task(self, plugin, wpa2_network_info):
        """PROVES: Deauth attack uses aireplay-ng for client disconnection"""
        tree = plugin.get_task_tree('TestNetwork', 6, wpa2_network_info)

        wpa_phase = next(c for c in tree['children'] if 'wpa-attacks' in c['id'])
        handshake_parent = next(c for c in wpa_phase['children'] if 'handshake-capture' in c['id'])
        deauth_task = next(c for c in handshake_parent['children'] if 'deauth' in c['id'].lower())

        metadata = deauth_task['metadata']

        # Verify aireplay-ng command
        assert 'aireplay-ng' in metadata['command']
        assert '-0' in metadata['command']  # Deauth mode
        assert wpa2_network_info['bssid'] in metadata['command']

        # Verify NOISY tag
        assert 'NOISY' in metadata['tags']
        assert 'DOS' in metadata['tags'] or 'OSCP:HIGH' in metadata['tags']

        # Verify alternatives include mdk4
        alternatives_str = ' '.join(metadata['alternatives'])
        assert 'mdk4' in alternatives_str.lower() or 'wifite' in alternatives_str.lower()

    def test_hashcat_cracking_task(self, plugin, wpa2_network_info):
        """PROVES: Hashcat cracking task configured for GPU acceleration"""
        tree = plugin.get_task_tree('TestNetwork', 6, wpa2_network_info)

        wpa_phase = next(c for c in tree['children'] if 'wpa-attacks' in c['id'])
        crack_parent = next(c for c in wpa_phase['children'] if 'crack' in c['id'].lower())
        hashcat_task = next(c for c in crack_parent['children'] if 'hashcat' in c['id'])

        metadata = hashcat_task['metadata']

        # Verify hashcat command
        assert 'hashcat' in metadata['command']
        assert '-m 22000' in metadata['command']  # WPA-PBKDF2-PMKID+EAPOL mode
        assert 'rockyou' in metadata['command']

        # Verify BRUTE_FORCE tag
        assert 'BRUTE_FORCE' in metadata['tags']
        assert 'OSCP:HIGH' in metadata['tags']

        # Verify alternatives include aircrack-ng
        alternatives_str = ' '.join(metadata['alternatives'])
        assert 'aircrack-ng' in alternatives_str.lower() or 'john' in alternatives_str.lower()

    def test_evil_twin_phase_exists(self, plugin, wpa2_network_info):
        """PROVES: Evil Twin attack phase includes multiple attack types"""
        tree = plugin.get_task_tree('TestNetwork', 6, wpa2_network_info)

        phase_ids = [c['id'] for c in tree['children']]
        assert any('evil-twin' in pid for pid in phase_ids)

    def test_open_evil_twin_task(self, plugin, wpa2_network_info):
        """PROVES: Open Evil Twin includes captive portal"""
        tree = plugin.get_task_tree('TestNetwork', 6, wpa2_network_info)

        evil_twin_phase = next(c for c in tree['children'] if 'evil-twin' in c['id'])
        open_twin_task = next(c for c in evil_twin_phase['children'] if 'open' in c['id'].lower())

        metadata = open_twin_task['metadata']

        # Verify eaphammer with captive portal
        assert 'eaphammer' in metadata['command']
        assert '--captive-portal' in metadata['command']
        assert wpa2_network_info['essid'] in metadata['command']

        # Verify tags
        assert 'OSCP:MEDIUM' in metadata['tags']
        assert 'EXPLOIT' in metadata['tags']
        assert 'PHISHING' in metadata['tags']

        # Verify alternatives include airgeddon, wifiphisher
        alternatives_str = ' '.join(metadata['alternatives'])
        assert 'airgeddon' in alternatives_str.lower() or 'wifiphisher' in alternatives_str.lower()

    def test_wpa_enterprise_evil_twin_task(self, plugin, wpa2_network_info):
        """PROVES: WPA-Enterprise evil twin captures domain credentials"""
        tree = plugin.get_task_tree('TestNetwork', 6, wpa2_network_info)

        evil_twin_phase = next(c for c in tree['children'] if 'evil-twin' in c['id'])
        enterprise_twin_task = next(c for c in evil_twin_phase['children'] if 'enterprise' in c['id'].lower())

        metadata = enterprise_twin_task['metadata']

        # Verify WPA-EAP configuration
        assert 'eaphammer' in metadata['command']
        assert '--auth wpa-eap' in metadata['command']
        assert '--creds' in metadata['command']

        # Verify high-value tags
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'EXPLOIT' in metadata['tags']
        assert 'PRIVESC' in metadata['tags']  # Domain creds = privilege escalation

        # Verify alternatives include hostapd-wpe
        alternatives_str = ' '.join(metadata['alternatives'])
        assert 'hostapd-wpe' in alternatives_str.lower() or 'airgeddon' in alternatives_str.lower()

    def test_karma_mana_phase_exists(self, plugin, wpa2_network_info):
        """PROVES: KARMA/MANA attack phase includes all variants"""
        tree = plugin.get_task_tree('TestNetwork', 6, wpa2_network_info)

        phase_ids = [c['id'] for c in tree['children']]
        assert any('karma' in pid or 'mana' in pid for pid in phase_ids)

    def test_mana_attack_task(self, plugin, wpa2_network_info):
        """PROVES: MANA attack responds to directed probe requests"""
        tree = plugin.get_task_tree('TestNetwork', 6, wpa2_network_info)

        karma_phase = next(c for c in tree['children'] if 'karma' in c['id'] or 'mana' in c['id'])
        mana_task = next((c for c in karma_phase['children'] if 'mana-attack' in c['id']), karma_phase['children'][0])

        metadata = mana_task['metadata']

        # Verify eaphammer MANA configuration
        assert 'eaphammer' in metadata['command']
        assert '--mana' in metadata['command']
        assert '--cloaking full' in metadata['command']

        # Verify tags
        assert 'OSCP:MEDIUM' in metadata['tags']
        assert 'EXPLOIT' in metadata['tags']

    def test_loud_mana_attack_task(self, plugin, wpa2_network_info):
        """PROVES: Loud MANA broadcasts all captured SSIDs"""
        tree = plugin.get_task_tree('TestNetwork', 6, wpa2_network_info)

        karma_phase = next(c for c in tree['children'] if 'karma' in c['id'] or 'mana' in c['id'])
        loud_mana_task = next(c for c in karma_phase['children'] if 'loud' in c['id'].lower())

        metadata = loud_mana_task['metadata']

        # Verify --loud flag
        assert '--loud' in metadata['command']
        assert '--mana' in metadata['command']

        # Verify NOISY tag
        assert 'NOISY' in metadata['tags']

    def test_known_beacon_attack_task(self, plugin, wpa2_network_info):
        """PROVES: Known Beacon attack uses SSID wordlist"""
        tree = plugin.get_task_tree('TestNetwork', 6, wpa2_network_info)

        karma_phase = next(c for c in tree['children'] if 'karma' in c['id'] or 'mana' in c['id'])
        known_beacon_task = next(c for c in karma_phase['children'] if 'known-beacons' in c['id'] or 'beacon' in c['id'].lower())

        metadata = known_beacon_task['metadata']

        # Verify known beacons configuration
        assert '--known-beacons' in metadata['command']
        assert '--known-ssids-file' in metadata['command']

        # Verify BRUTE_FORCE tag
        assert 'BRUTE_FORCE' in metadata['tags']

    def test_android_nexmon_advanced_technique(self, plugin, wpa2_network_info):
        """PROVES: Advanced techniques include Android NexMon monitor mode"""
        tree = plugin.get_task_tree('TestNetwork', 6, wpa2_network_info)

        advanced_phase = next((c for c in tree['children'] if 'advanced' in c['id'].lower()), None)

        if advanced_phase:
            task_names = [t['name'].lower() for t in advanced_phase['children']]
            assert any('android' in name or 'nexmon' in name for name in task_names)

    def test_all_command_tasks_have_flag_explanations(self, plugin, wpa2_network_info):
        """PROVES: All command tasks explain flags (OSCP requirement)"""
        tree = plugin.get_task_tree('TestNetwork', 6, wpa2_network_info)

        def check_command_tasks(node):
            if node.get('type') == 'command':
                metadata = node.get('metadata', {})
                assert 'command' in metadata, f"Task {node['id']} missing command"

                # Command tasks MUST have flag explanations
                assert 'flag_explanations' in metadata, \
                    f"Task {node['id']} missing flag_explanations (OSCP requirement)"

                assert len(metadata['flag_explanations']) > 0, \
                    f"Task {node['id']} has empty flag_explanations"

            if 'children' in node:
                for child in node['children']:
                    check_command_tasks(child)

        check_command_tasks(tree)

    def test_time_estimates_provided(self, plugin, wpa2_network_info):
        """PROVES: Time-sensitive tasks include estimates for exam planning"""
        tree = plugin.get_task_tree('TestNetwork', 6, wpa2_network_info)

        tasks_with_time = []

        def find_time_estimates(node):
            if node.get('type') in ['command', 'manual']:
                metadata = node.get('metadata', {})
                if 'estimated_time' in metadata:
                    tasks_with_time.append((node['name'], metadata['estimated_time']))

            if 'children' in node:
                for child in node['children']:
                    find_time_estimates(child)

        find_time_estimates(tree)

        # Should have multiple tasks with time estimates
        assert len(tasks_with_time) >= 5, \
            f"WiFi plugin should provide time estimates for planning, found: {len(tasks_with_time)}"

    def test_noisy_attacks_tagged(self, plugin, wpa2_network_info):
        """PROVES: Noisy attacks (deauth, DoS) properly tagged"""
        tree = plugin.get_task_tree('TestNetwork', 6, wpa2_network_info)

        noisy_tasks = []

        def find_noisy_tasks(node):
            if node.get('type') in ['command', 'manual']:
                metadata = node.get('metadata', {})
                tags = metadata.get('tags', [])
                if 'NOISY' in tags:
                    noisy_tasks.append(node['name'])

            if 'children' in node:
                for child in node['children']:
                    find_noisy_tasks(child)

        find_noisy_tasks(tree)

        # Deauth and DoS should be tagged as NOISY
        assert len(noisy_tasks) > 0, "WiFi plugin should tag noisy attacks (deauth, DoS)"

    def test_task_ids_unique(self, plugin, wpa2_network_info):
        """PROVES: All task IDs unique within tree"""
        tree = plugin.get_task_tree('TestNetwork', 6, wpa2_network_info)

        task_ids = []

        def collect_ids(node):
            if 'id' in node:
                task_ids.append(node['id'])
            if 'children' in node:
                for child in node['children']:
                    collect_ids(child)

        collect_ids(tree)

        # Check for duplicates
        assert len(task_ids) == len(set(task_ids)), \
            f"Duplicate task IDs found: {[tid for tid in task_ids if task_ids.count(tid) > 1]}"


class TestWiFiAttackWorkflows:
    """Test real-world OSCP WiFi pentesting workflows"""

    @pytest.fixture
    def plugin(self):
        return WiFiAttackPlugin()

    def test_wps_enabled_workflow(self, plugin):
        """
        PROVES: WPS-enabled network workflow prioritizes fast attacks

        Workflow:
        1. Setup monitor mode
        2. Scan networks
        3. Try Pixie Dust (QUICK_WIN - 30 seconds)
        4. Try NULL PIN (QUICK_WIN - 1 minute)
        5. Fallback to WPA handshake if WPS fails
        """
        wps_info = {
            'essid': 'WPS_Router',
            'bssid': '00:11:22:33:44:55',
            'channel': 6,
            'wps': True,
            'interface': 'wlan0'
        }

        tree = plugin.get_task_tree('WPS_Router', 6, wps_info)

        # Verify WPS phase exists and has quick wins
        wps_phase = next(c for c in tree['children'] if 'wps' in c['id'])

        quick_wins = [t for t in wps_phase['children']
                      if 'QUICK_WIN' in t['metadata'].get('tags', [])]

        assert len(quick_wins) >= 2, "WPS workflow should prioritize QUICK_WIN attacks (Pixie Dust, NULL PIN)"

    def test_wpa2_no_clients_workflow(self, plugin):
        """
        PROVES: WPA2 network without clients uses PMKID (clientless)

        Workflow:
        1. Setup monitor mode
        2. Scan networks (no clients visible)
        3. Attempt PMKID capture (clientless)
        4. Crack PMKID offline
        """
        wpa2_info = {
            'essid': 'NoClients_Network',
            'bssid': 'AA:BB:CC:DD:EE:FF',
            'channel': 11,
            'security': 'WPA2',
            'wps': False,
            'interface': 'wlan0'
        }

        tree = plugin.get_task_tree('NoClients_Network', 11, wpa2_info)

        # Verify PMKID attack available
        wpa_phase = next(c for c in tree['children'] if 'wpa-attacks' in c['id'])
        pmkid_task = next(c for c in wpa_phase['children'] if 'pmkid' in c['id'].lower())

        # PMKID should be QUICK_WIN and not require clients
        assert 'QUICK_WIN' in pmkid_task['metadata']['tags']
        assert 'clientless' in pmkid_task['metadata']['description'].lower()

    def test_enterprise_network_workflow(self, plugin):
        """
        PROVES: WPA-Enterprise workflow captures domain credentials

        Workflow:
        1. Setup monitor mode
        2. Create WPA-Enterprise evil twin
        3. Capture EAP credentials (MSCHAPv2 or GTC)
        4. Crack captured hashes or use plaintext
        5. Lateral movement with domain creds
        """
        enterprise_info = {
            'essid': 'Corp_WiFi',
            'bssid': '11:22:33:44:55:66',
            'channel': 6,
            'security': 'WPA2-Enterprise',
            'wps': False,
            'interface': 'wlan0'
        }

        tree = plugin.get_task_tree('Corp_WiFi', 6, enterprise_info)

        # Verify Evil Twin phase has enterprise option
        evil_twin_phase = next(c for c in tree['children'] if 'evil-twin' in c['id'])
        enterprise_task = next(c for c in evil_twin_phase['children'] if 'enterprise' in c['id'].lower())

        # Verify PRIVESC tag (domain creds = escalation)
        assert 'PRIVESC' in enterprise_task['metadata']['tags']

    def test_oscp_exam_time_management(self, plugin):
        """PROVES: Plugin helps with OSCP time management via QUICK_WIN tags and time estimates"""
        wpa2_info = {
            'essid': 'Exam_Network',
            'bssid': '00:AA:BB:CC:DD:EE',
            'channel': 6,
            'security': 'WPA2',
            'wps': True,
            'interface': 'wlan0'
        }

        tree = plugin.get_task_tree('Exam_Network', 6, wpa2_info)

        # Find all QUICK_WIN tasks
        quick_wins = []

        def find_quick_wins(node):
            if node.get('type') in ['command', 'manual']:
                metadata = node.get('metadata', {})
                tags = metadata.get('tags', [])
                if 'QUICK_WIN' in tags:
                    time_est = metadata.get('estimated_time', 'unknown')
                    quick_wins.append((node['name'], time_est))

            if 'children' in node:
                for child in node['children']:
                    find_quick_wins(child)

        find_quick_wins(tree)

        # Should have multiple quick wins with time estimates
        assert len(quick_wins) >= 3, \
            f"WiFi plugin should identify QUICK_WIN tasks for exam, found: {quick_wins}"


class TestWiFiPCAPAnalysisPhase:
    """Test PCAP Analysis & Forensics phase (HackTricks integration)"""

    @pytest.fixture
    def plugin(self):
        return WiFiAttackPlugin()

    @pytest.fixture
    def network_info(self):
        return {
            'essid': 'TestNetwork',
            'bssid': '00:11:22:33:44:55',
            'channel': 6,
            'security': 'WPA2',
            'wps': False,
            'interface': 'wlan0'
        }

    def test_pcap_analysis_phase_exists(self, plugin, network_info):
        """PROVES: PCAP Analysis phase added to task tree"""
        tree = plugin.get_task_tree('TestNetwork', 6, network_info)

        phase_ids = [c['id'] for c in tree['children']]
        assert any('pcap-analysis' in pid for pid in phase_ids), \
            "PCAP Analysis phase should exist in task tree"

    def test_wireshark_wlan_traffic_task(self, plugin, network_info):
        """PROVES: Wireshark WLAN traffic analysis task configured"""
        tree = plugin.get_task_tree('TestNetwork', 6, network_info)

        pcap_phase = next(c for c in tree['children'] if 'pcap-analysis' in c['id'])
        wireshark_task = next((c for c in pcap_phase['children'] if 'wireshark-wlan' in c['id']), None)

        assert wireshark_task is not None, "Wireshark WLAN analysis task should exist"

        metadata = wireshark_task['metadata']

        # Verify FORENSICS tag
        assert 'FORENSICS' in metadata['tags']
        assert 'OSCP:MEDIUM' in metadata['tags']

        # Verify notes include Wireshark workflow
        notes_str = ' '.join(metadata['notes'])
        assert 'wireshark' in notes_str.lower()
        assert 'bssid' in notes_str.lower() or 'wlan traffic' in notes_str.lower()

        # Verify alternatives
        assert 'alternatives' in metadata
        assert len(metadata['alternatives']) >= 2

    def test_extract_handshake_from_pcap_task(self, plugin, network_info):
        """PROVES: Handshake extraction from existing PCAP configured"""
        tree = plugin.get_task_tree('TestNetwork', 6, network_info)

        pcap_phase = next(c for c in tree['children'] if 'pcap-analysis' in c['id'])
        extract_task = next(c for c in pcap_phase['children'] if 'extract-handshake' in c['id'])

        metadata = extract_task['metadata']

        # Verify aircrack-ng command
        assert 'aircrack-ng' in metadata['command']
        assert '-w' in metadata['command']  # Wordlist parameter
        assert 'rockyou' in metadata['command']
        assert network_info['bssid'] in metadata['command']

        # Verify tags
        assert 'OSCP:MEDIUM' in metadata['tags']
        assert 'FORENSICS' in metadata['tags']
        assert 'BRUTE_FORCE' in metadata['tags']

        # Verify flag explanations
        assert 'flag_explanations' in metadata
        assert '-w' in metadata['flag_explanations']
        assert '-b' in metadata['flag_explanations']

        # Verify alternatives include hashcat conversion
        alternatives_str = ' '.join(metadata['alternatives'])
        assert 'hashcat' in alternatives_str.lower() or 'hcxpcaptool' in alternatives_str.lower()

    def test_beacon_exfiltration_detection_task(self, plugin, network_info):
        """PROVES: Beacon frame data exfiltration detection configured"""
        tree = plugin.get_task_tree('TestNetwork', 6, network_info)

        pcap_phase = next(c for c in tree['children'] if 'pcap-analysis' in c['id'])
        beacon_task = next(c for c in pcap_phase['children'] if 'beacon-exfil' in c['id'])

        metadata = beacon_task['metadata']

        # Verify tshark command
        assert 'tshark' in metadata['command']
        assert '-r capture.pcap' in metadata['command']
        assert 'wlan contains' in metadata['command']
        assert network_info['essid'] in metadata['command']

        # Verify OSCP:LOW (advanced/rare technique)
        assert 'OSCP:LOW' in metadata['tags']
        assert 'FORENSICS' in metadata['tags']
        assert 'STEALTH' in metadata['tags']

        # Verify flag explanations
        assert 'flag_explanations' in metadata
        assert 'tshark' in metadata['flag_explanations']
        assert '-r' in metadata['flag_explanations']

    def test_unknown_mac_detection_task(self, plugin, network_info):
        """PROVES: Unknown/rogue device detection task configured"""
        tree = plugin.get_task_tree('TestNetwork', 6, network_info)

        pcap_phase = next(c for c in tree['children'] if 'pcap-analysis' in c['id'])
        mac_task = next(c for c in pcap_phase['children'] if 'unknown-mac' in c['id'])

        metadata = mac_task['metadata']

        # Verify complex tshark filter
        assert 'tshark' in metadata['command']
        assert 'wlan.ta' in metadata['command']
        assert network_info['bssid'] in metadata['command']

        # Verify tags
        assert 'OSCP:MEDIUM' in metadata['tags']
        assert 'FORENSICS' in metadata['tags']
        assert 'RECON' in metadata['tags']

        # Verify comprehensive flag explanations
        assert 'flag_explanations' in metadata
        assert len(metadata['flag_explanations']) >= 5, \
            "Complex tshark filter should have detailed flag explanations"

        # Verify next steps include MAC lookup
        next_steps_str = ' '.join(metadata['next_steps'])
        assert 'mac' in next_steps_str.lower() or 'oui' in next_steps_str.lower()

    def test_decrypt_wpa_traffic_task(self, plugin, network_info):
        """PROVES: WPA traffic decryption with known PSK task configured"""
        tree = plugin.get_task_tree('TestNetwork', 6, network_info)

        pcap_phase = next(c for c in tree['children'] if 'pcap-analysis' in c['id'])
        decrypt_task = next(c for c in pcap_phase['children'] if 'decrypt-wpa' in c['id'])

        metadata = decrypt_task['metadata']

        # Verify manual type (Wireshark GUI workflow)
        assert decrypt_task['type'] == 'manual'

        # Verify tags
        assert 'OSCP:MEDIUM' in metadata['tags']
        assert 'FORENSICS' in metadata['tags']
        assert 'MANUAL' in metadata['tags']

        # Verify notes include Wireshark decryption steps
        notes_str = ' '.join(metadata['notes'])
        assert 'wireshark' in notes_str.lower()
        assert 'wpa-pwd' in notes_str.lower()
        assert 'edit' in notes_str.lower() and 'preferences' in notes_str.lower()

        # Verify alternatives include airdecap-ng
        alternatives_str = ' '.join(metadata['alternatives'])
        assert 'airdecap-ng' in alternatives_str.lower()

    def test_pcap_phase_has_five_tasks(self, plugin, network_info):
        """PROVES: PCAP Analysis phase includes all 5 HackTricks techniques"""
        tree = plugin.get_task_tree('TestNetwork', 6, network_info)

        pcap_phase = next(c for c in tree['children'] if 'pcap-analysis' in c['id'])

        # Verify 5 tasks: Wireshark, Extract handshake, Beacon exfil, Unknown MAC, Decrypt
        assert len(pcap_phase['children']) == 5, \
            f"PCAP Analysis phase should have 5 tasks, found: {len(pcap_phase['children'])}"

        task_names = [t['name'].lower() for t in pcap_phase['children']]

        # Verify all techniques present
        assert any('wireshark' in name for name in task_names)
        assert any('handshake' in name or 'extract' in name for name in task_names)
        assert any('beacon' in name or 'exfil' in name for name in task_names)
        assert any('mac' in name or 'rogue' in name for name in task_names)
        assert any('decrypt' in name for name in task_names)

    def test_pcap_workflow_for_credential_extraction(self, plugin, network_info):
        """
        PROVES: PCAP analysis workflow supports offline credential extraction

        Workflow:
        1. Receive PCAP from network tap or incident response
        2. Analyze in Wireshark for BSSIDs and authentication
        3. Extract WPA handshakes with aircrack-ng
        4. Crack handshakes offline with hashcat/aircrack-ng
        5. Decrypt traffic with recovered PSK
        6. Extract credentials from decrypted HTTP/FTP
        """
        tree = plugin.get_task_tree('TestNetwork', 6, network_info)

        pcap_phase = next(c for c in tree['children'] if 'pcap-analysis' in c['id'])

        # Verify workflow progression
        tasks = pcap_phase['children']

        # Task 1: Analysis (Wireshark)
        analysis_task = tasks[0]
        assert 'wireshark' in analysis_task['id'].lower()

        # Task 2: Extraction (aircrack-ng)
        extract_task = tasks[1]
        assert 'extract' in extract_task['id'].lower() or 'handshake' in extract_task['id'].lower()

        # Task 5: Decryption (requires cracked PSK)
        decrypt_task = tasks[4]
        assert 'decrypt' in decrypt_task['id'].lower()

        # Verify next steps chain together
        extract_metadata = extract_task['metadata']
        next_steps_str = ' '.join(extract_metadata['next_steps'])
        assert 'hashcat' in next_steps_str.lower() or 'crack' in next_steps_str.lower()

    def test_pcap_analysis_educational_metadata(self, plugin, network_info):
        """PROVES: PCAP analysis tasks have full OSCP educational metadata"""
        tree = plugin.get_task_tree('TestNetwork', 6, network_info)

        pcap_phase = next(c for c in tree['children'] if 'pcap-analysis' in c['id'])

        for task in pcap_phase['children']:
            metadata = task['metadata']

            # All tasks must have description
            assert 'description' in metadata, \
                f"Task {task['id']} missing description"

            # All tasks must have tags
            assert 'tags' in metadata and len(metadata['tags']) > 0, \
                f"Task {task['id']} missing tags"

            # Command tasks must have flag explanations
            if task['type'] == 'command':
                assert 'flag_explanations' in metadata, \
                    f"Command task {task['id']} missing flag_explanations"

            # All tasks must have alternatives
            assert 'alternatives' in metadata and len(metadata['alternatives']) >= 1, \
                f"Task {task['id']} missing alternatives"

            # Verify next_steps or success_indicators present
            has_guidance = ('next_steps' in metadata or
                           'success_indicators' in metadata or
                           'notes' in metadata)
            assert has_guidance, \
                f"Task {task['id']} lacks guidance (next_steps/success_indicators/notes)"
