"""
Tests for Port Lookup (pl) Tool

Validates:
- Port reference data structure
- Lookup by port number
- Search by service name
- List all ports
- Port info completeness
- Shortcut integration
- Display formatting
"""

import pytest
from crack.track.interactive.port_reference import PortReference, PortInfo


class TestPortInfoStructure:
    """Test PortInfo data structure"""

    def test_port_info_initialization(self):
        """PROVES: PortInfo stores port data correctly"""
        port_info = PortInfo(
            port=80,
            service="HTTP",
            description="Hypertext Transfer Protocol",
            enum_commands=["gobuster dir -u http://<TARGET>"],
            quick_wins=["Check robots.txt"],
            common_vulns=["SQL injection"]
        )

        assert port_info.port == 80
        assert port_info.service == "HTTP"
        assert port_info.description == "Hypertext Transfer Protocol"
        assert len(port_info.enum_commands) == 1
        assert len(port_info.quick_wins) == 1
        assert len(port_info.common_vulns) == 1

    def test_port_info_optional_fields(self):
        """PROVES: Optional fields default to empty lists"""
        port_info = PortInfo(
            port=22,
            service="SSH",
            description="Secure Shell",
            enum_commands=["ssh <TARGET>"]
        )

        assert port_info.quick_wins == []
        assert port_info.common_vulns == []


class TestPortReference:
    """Test PortReference registry"""

    def test_register_port(self):
        """PROVES: Can register and retrieve port information"""
        # Clear existing registrations for test
        original_ports = PortReference._ports.copy()
        PortReference._ports = {}

        try:
            port_info = PortInfo(
                port=9999,
                service="TEST",
                description="Test service",
                enum_commands=["test_command"]
            )

            PortReference.register(port_info)

            retrieved = PortReference.lookup(9999)
            assert retrieved is not None
            assert retrieved.port == 9999
            assert retrieved.service == "TEST"

        finally:
            # Restore original registrations
            PortReference._ports = original_ports

    def test_lookup_existing_port(self):
        """PROVES: Can lookup common OSCP ports"""
        # Test common ports that should be registered
        common_ports = [21, 22, 80, 443, 445, 3306, 3389]

        for port in common_ports:
            port_info = PortReference.lookup(port)
            assert port_info is not None, f"Port {port} should be registered"
            assert port_info.port == port
            assert port_info.service != ""
            assert len(port_info.enum_commands) > 0

    def test_lookup_nonexistent_port(self):
        """PROVES: Returns None for unregistered ports"""
        port_info = PortReference.lookup(99999)
        assert port_info is None

    def test_search_by_service_name(self):
        """PROVES: Can search ports by service name"""
        # Search for HTTP
        results = PortReference.search_by_service("http")
        assert len(results) > 0

        # Should find both HTTP (80) and HTTPS (443)
        port_numbers = [p.port for p in results]
        assert 80 in port_numbers
        assert 443 in port_numbers

    def test_search_case_insensitive(self):
        """PROVES: Service search is case-insensitive"""
        results_lower = PortReference.search_by_service("ssh")
        results_upper = PortReference.search_by_service("SSH")
        results_mixed = PortReference.search_by_service("Ssh")

        assert len(results_lower) > 0
        assert len(results_upper) == len(results_lower)
        assert len(results_mixed) == len(results_lower)

    def test_search_partial_match(self):
        """PROVES: Service search supports partial matching"""
        # Search for "sql" should find MySQL, MSSQL, PostgreSQL
        results = PortReference.search_by_service("sql")
        assert len(results) >= 2  # At least MySQL and MSSQL

        port_numbers = [p.port for p in results]
        assert 3306 in port_numbers  # MySQL
        assert 1433 in port_numbers  # MSSQL

    def test_search_no_results(self):
        """PROVES: Returns empty list for no matches"""
        results = PortReference.search_by_service("nonexistent_service_xyz")
        assert results == []

    def test_list_all_ports(self):
        """PROVES: Can list all registered ports"""
        all_ports = PortReference.list_all()

        assert len(all_ports) > 0
        assert isinstance(all_ports, list)

        # Verify sorting by port number
        port_numbers = [p.port for p in all_ports]
        assert port_numbers == sorted(port_numbers)

    def test_list_all_includes_common_ports(self):
        """PROVES: All common OSCP ports are registered"""
        all_ports = PortReference.list_all()
        port_numbers = [p.port for p in all_ports]

        # Essential OSCP ports
        essential_ports = [21, 22, 80, 443, 445, 3306, 3389]
        for port in essential_ports:
            assert port in port_numbers, f"Port {port} should be registered"


class TestPortDataCompleteness:
    """Test registered port data quality"""

    def test_all_ports_have_enumeration_commands(self):
        """PROVES: Every registered port has enumeration commands"""
        all_ports = PortReference.list_all()

        for port_info in all_ports:
            assert len(port_info.enum_commands) > 0, \
                f"Port {port_info.port} missing enumeration commands"

    def test_all_ports_have_descriptions(self):
        """PROVES: Every registered port has a description"""
        all_ports = PortReference.list_all()

        for port_info in all_ports:
            assert port_info.description != "", \
                f"Port {port_info.port} missing description"
            assert port_info.service != "", \
                f"Port {port_info.port} missing service name"

    def test_high_value_ports_have_quick_wins(self):
        """PROVES: Common OSCP ports have quick win checks"""
        high_value_ports = [21, 80, 443, 445, 3306]  # FTP, HTTP, HTTPS, SMB, MySQL

        for port_num in high_value_ports:
            port_info = PortReference.lookup(port_num)
            assert port_info is not None
            assert len(port_info.quick_wins) > 0, \
                f"Port {port_num} should have quick win checks"

    def test_high_value_ports_have_common_vulns(self):
        """PROVES: Common OSCP ports list common vulnerabilities"""
        high_value_ports = [21, 80, 443, 445, 3306, 3389]

        for port_num in high_value_ports:
            port_info = PortReference.lookup(port_num)
            assert port_info is not None
            assert len(port_info.common_vulns) > 0, \
                f"Port {port_num} should list common vulnerabilities"

    def test_commands_use_placeholder_format(self):
        """PROVES: Commands use <TARGET> placeholder"""
        all_ports = PortReference.list_all()

        for port_info in all_ports:
            # Most commands should contain <TARGET> placeholder
            has_target = any('<TARGET>' in cmd for cmd in port_info.enum_commands)
            # Some commands might not need target (like manual commands)
            # But at least ONE command per port should use it
            if len(port_info.enum_commands) > 1:
                assert has_target, \
                    f"Port {port_info.port} commands should use <TARGET> placeholder"


class TestShortcutIntegration:
    """Test 'pl' shortcut registration"""

    def test_shortcut_registered_in_shortcuts_py(self):
        """PROVES: 'pl' shortcut is registered"""
        from crack.track.interactive.shortcuts import ShortcutHandler
        from unittest.mock import Mock

        mock_session = Mock()
        mock_session.target = "192.168.45.100"
        mock_session.profile = Mock()

        handler = ShortcutHandler(mock_session)

        assert 'pl' in handler.shortcuts
        assert handler.shortcuts['pl'][0] == 'Port lookup reference'
        assert handler.shortcuts['pl'][1] == 'port_lookup'

    def test_shortcut_handler_exists(self):
        """PROVES: port_lookup handler method exists"""
        from crack.track.interactive.shortcuts import ShortcutHandler
        from unittest.mock import Mock

        mock_session = Mock()
        handler = ShortcutHandler(mock_session)

        assert hasattr(handler, 'port_lookup')
        assert callable(handler.port_lookup)

    def test_shortcut_recognized_in_input_processor(self):
        """PROVES: 'pl' is recognized as valid shortcut"""
        from crack.track.interactive.input_handler import InputProcessor

        assert 'pl' in InputProcessor.SHORTCUTS

    def test_help_text_includes_port_lookup(self):
        """PROVES: Help text documents 'pl' shortcut"""
        from crack.track.interactive.prompts import PromptBuilder

        help_text = PromptBuilder.build_help_text()

        assert 'pl' in help_text
        assert 'Port lookup' in help_text or 'port lookup' in help_text


class TestDisplayFormatting:
    """Test port information display"""

    def test_display_includes_target_substitution(self):
        """PROVES: Display replaces <TARGET> with actual target"""
        from crack.track.interactive.session import InteractiveSession
        from unittest.mock import Mock, patch
        import io
        import sys

        # Create mock session with target
        with patch('crack.track.interactive.session.TargetProfile') as MockProfile:
            MockProfile.exists.return_value = False
            mock_profile_instance = Mock()
            mock_profile_instance.target = "192.168.45.100"
            mock_profile_instance.phase = "discovery"
            mock_profile_instance.metadata = {}
            MockProfile.return_value = mock_profile_instance

            session = InteractiveSession("192.168.45.100")

            # Get port info
            port_info = PortReference.lookup(80)
            assert port_info is not None

            # Capture display output
            captured_output = io.StringIO()
            sys.stdout = captured_output

            try:
                session._display_port_info(port_info)
                output = captured_output.getvalue()

                # Verify target is substituted
                assert "192.168.45.100" in output
                assert "<TARGET>" not in output  # Placeholder should be replaced

            finally:
                sys.stdout = sys.__stdout__

    def test_display_shows_all_sections(self):
        """PROVES: Display shows commands, quick wins, and vulnerabilities"""
        from crack.track.interactive.session import InteractiveSession
        from unittest.mock import Mock, patch
        import io
        import sys

        with patch('crack.track.interactive.session.TargetProfile') as MockProfile:
            MockProfile.exists.return_value = False
            mock_profile_instance = Mock()
            mock_profile_instance.target = "192.168.45.100"
            mock_profile_instance.phase = "discovery"
            mock_profile_instance.metadata = {}
            MockProfile.return_value = mock_profile_instance

            session = InteractiveSession("192.168.45.100")
            port_info = PortReference.lookup(445)  # SMB has all sections

            captured_output = io.StringIO()
            sys.stdout = captured_output

            try:
                session._display_port_info(port_info)
                output = captured_output.getvalue()

                # Verify all sections present
                assert "Enumeration Commands:" in output
                assert "Quick Wins:" in output
                assert "Common Vulnerabilities:" in output

            finally:
                sys.stdout = sys.__stdout__


class TestSpecificPorts:
    """Test specific port data accuracy"""

    def test_http_port_80(self):
        """PROVES: HTTP port 80 data is complete and accurate"""
        port_info = PortReference.lookup(80)

        assert port_info is not None
        assert port_info.service == "HTTP"
        # Check description contains some HTTP-related term
        desc_lower = port_info.description.lower()
        assert "http" in desc_lower or "web" in desc_lower or "hypertext" in desc_lower

        # Should have web enumeration commands
        commands_str = ' '.join(port_info.enum_commands).lower()
        assert 'gobuster' in commands_str or 'dirb' in commands_str or 'nikto' in commands_str

    def test_smb_port_445(self):
        """PROVES: SMB port 445 includes EternalBlue"""
        port_info = PortReference.lookup(445)

        assert port_info is not None
        assert port_info.service == "SMB"

        # Should mention EternalBlue
        vulns_str = ' '.join(port_info.common_vulns)
        assert 'EternalBlue' in vulns_str or 'MS17-010' in vulns_str

    def test_mysql_port_3306(self):
        """PROVES: MySQL port 3306 suggests default credential check"""
        port_info = PortReference.lookup(3306)

        assert port_info is not None
        assert port_info.service == "MySQL"

        # Should mention trying root with no password
        quick_wins_str = ' '.join(port_info.quick_wins).lower()
        assert 'root' in quick_wins_str or 'default' in quick_wins_str

    def test_rdp_port_3389(self):
        """PROVES: RDP port 3389 mentions BlueKeep"""
        port_info = PortReference.lookup(3389)

        assert port_info is not None
        assert port_info.service == "RDP"

        # Should mention BlueKeep
        vulns_str = ' '.join(port_info.common_vulns)
        assert 'BlueKeep' in vulns_str or 'CVE-2019-0708' in vulns_str
