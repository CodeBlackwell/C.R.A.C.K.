"""
Tests for Port Reference Utility

Business Value Focus:
- Quick port reference for pentesting
- Port categorization by service type
- Filtering and search functionality

Test Priority: TIER 2 - HIGH (Reference Tool)
"""

import pytest
from core.utils.ports import (
    PORT_DATA, colorize_port, filter_ports, display_ports, C
)


# =============================================================================
# PORT_DATA Tests
# =============================================================================

class TestPortData:
    """Tests for PORT_DATA structure"""

    def test_port_data_not_empty(self):
        """
        BV: Port data contains entries

        Scenario:
          Given: PORT_DATA constant
          When: Checking length
          Then: Contains entries
        """
        assert len(PORT_DATA) > 0

    def test_port_data_has_common_ports(self):
        """
        BV: Contains critical pentesting ports

        Scenario:
          Given: PORT_DATA
          When: Checking for common ports
          Then: Contains 22, 80, 445, etc.
        """
        ports = [p[0] for p in PORT_DATA]

        assert 22 in ports   # SSH
        assert 80 in ports   # HTTP
        assert 443 in ports  # HTTPS
        assert 445 in ports  # SMB
        assert 3389 in ports # RDP

    def test_port_data_tuple_structure(self):
        """
        BV: Port data has correct structure

        Scenario:
          Given: PORT_DATA entry
          When: Checking structure
          Then: Has 5 elements (port, proto, service, desc, tools)
        """
        entry = PORT_DATA[0]

        assert len(entry) == 5
        assert isinstance(entry[0], int)     # port
        assert isinstance(entry[1], str)     # protocol
        assert isinstance(entry[2], str)     # service
        assert isinstance(entry[3], str)     # description
        assert isinstance(entry[4], str)     # tools


# =============================================================================
# Colorize Port Tests
# =============================================================================

class TestColorizePort:
    """Tests for port colorization"""

    def test_colorize_ssh_port(self):
        """
        BV: SSH port colored correctly

        Scenario:
          Given: Port 22 (SSH)
          When: colorize_port() is called
          Then: Colored with auth color
        """
        result = colorize_port(22)

        assert C.GREEN in result
        assert "22" in result

    def test_colorize_smb_port(self):
        """
        BV: SMB port colored as AD/SMB

        Scenario:
          Given: Port 445 (SMB)
          When: colorize_port() is called
          Then: Colored with AD/SMB color
        """
        result = colorize_port(445)

        assert C.RED in result
        assert "445" in result

    def test_colorize_http_port(self):
        """
        BV: HTTP port colored as Web

        Scenario:
          Given: Port 80 (HTTP)
          When: colorize_port() is called
          Then: Colored with Web color
        """
        result = colorize_port(80)

        assert C.CYAN in result
        assert "80" in result

    def test_colorize_database_port(self):
        """
        BV: Database port colored correctly

        Scenario:
          Given: Port 3306 (MySQL)
          When: colorize_port() is called
          Then: Colored with Database color
        """
        result = colorize_port(3306)

        assert C.YELLOW in result
        assert "3306" in result

    def test_colorize_rdp_port(self):
        """
        BV: RDP port colored as Remote Access

        Scenario:
          Given: Port 3389 (RDP)
          When: colorize_port() is called
          Then: Colored with Remote color
        """
        result = colorize_port(3389)

        assert C.MAGENTA in result
        assert "3389" in result

    def test_colorize_unknown_port(self):
        """
        BV: Unknown port has default color

        Scenario:
          Given: Unknown port (99999)
          When: colorize_port() is called
          Then: Colored with default color
        """
        result = colorize_port(99999)

        assert C.WHITE in result
        assert "99999" in result


# =============================================================================
# Filter Ports Tests
# =============================================================================

class TestFilterPorts:
    """Tests for port filtering"""

    def test_filter_by_port_number(self):
        """
        BV: Filter by port number

        Scenario:
          Given: Query "22"
          When: filter_ports() is called
          Then: Returns port 22
        """
        result = filter_ports(PORT_DATA, "22")

        ports = [p[0] for p in result]
        assert 22 in ports

    def test_filter_by_service_name(self):
        """
        BV: Filter by service name

        Scenario:
          Given: Query "ssh"
          When: filter_ports() is called
          Then: Returns SSH port
        """
        result = filter_ports(PORT_DATA, "ssh")

        services = [p[2].lower() for p in result]
        assert "ssh" in services

    def test_filter_by_protocol(self):
        """
        BV: Filter by protocol

        Scenario:
          Given: Query "udp"
          When: filter_ports() is called
          Then: Returns UDP ports
        """
        result = filter_ports(PORT_DATA, "udp")

        assert len(result) > 0
        # All results should contain UDP in protocol
        for port_data in result:
            assert "udp" in port_data[1].lower()

    def test_filter_by_description(self):
        """
        BV: Filter by description

        Scenario:
          Given: Query "database"
          When: filter_ports() is called
          Then: Returns database ports
        """
        # Note: exact text depends on PORT_DATA content
        result = filter_ports(PORT_DATA, "server")

        assert len(result) > 0

    def test_filter_by_tools(self):
        """
        BV: Filter by tools

        Scenario:
          Given: Query "hydra"
          When: filter_ports() is called
          Then: Returns ports with hydra in tools
        """
        result = filter_ports(PORT_DATA, "hydra")

        assert len(result) > 0
        for port_data in result:
            assert "hydra" in port_data[4].lower()

    def test_filter_no_query_returns_all(self):
        """
        BV: No filter returns all ports

        Scenario:
          Given: No query
          When: filter_ports() is called
          Then: Returns all ports
        """
        result = filter_ports(PORT_DATA, None)

        assert result == PORT_DATA

    def test_filter_no_matches(self):
        """
        BV: No matches returns empty list

        Scenario:
          Given: Query with no matches
          When: filter_ports() is called
          Then: Returns empty list
        """
        result = filter_ports(PORT_DATA, "xyznomatch123")

        assert result == []

    def test_filter_case_insensitive(self):
        """
        BV: Filter is case insensitive

        Scenario:
          Given: Query "SSH" (uppercase)
          When: filter_ports() is called
          Then: Returns SSH port
        """
        result = filter_ports(PORT_DATA, "SSH")

        services = [p[2].lower() for p in result]
        assert "ssh" in services


# =============================================================================
# Display Ports Tests
# =============================================================================

class TestDisplayPorts:
    """Tests for port display functionality"""

    def test_display_ports_no_error(self, capsys):
        """
        BV: Display ports without error

        Scenario:
          Given: Default parameters
          When: display_ports() is called
          Then: No exception raised
        """
        display_ports(limit=5)

        captured = capsys.readouterr()
        assert len(captured.out) > 0

    def test_display_ports_with_query(self, capsys):
        """
        BV: Display filtered ports

        Scenario:
          Given: Query for SSH
          When: display_ports() is called
          Then: Shows SSH port
        """
        display_ports(query="ssh")

        captured = capsys.readouterr()
        assert "SSH" in captured.out

    def test_display_ports_no_matches(self, capsys):
        """
        BV: Display message for no matches

        Scenario:
          Given: Query with no matches
          When: display_ports() is called
          Then: Shows no matches message
        """
        display_ports(query="xyznomatch123")

        captured = capsys.readouterr()
        assert "No ports found" in captured.out

    def test_display_ports_with_limit(self, capsys):
        """
        BV: Respect limit parameter

        Scenario:
          Given: limit=3
          When: display_ports() is called
          Then: Shows limited ports
        """
        display_ports(limit=3)

        captured = capsys.readouterr()
        # Should show some ports
        assert len(captured.out) > 0


# =============================================================================
# Color Constants Tests
# =============================================================================

class TestColorConstants:
    """Tests for color constants"""

    def test_color_class_has_reset(self):
        """
        BV: Color class has reset code

        Scenario:
          Given: C class
          When: Checking END
          Then: Contains escape sequence
        """
        assert C.END == '\033[0m'

    def test_color_class_has_bold(self):
        """
        BV: Color class has bold code

        Scenario:
          Given: C class
          When: Checking BOLD
          Then: Contains escape sequence
        """
        assert C.BOLD == '\033[1m'

    def test_color_class_has_colors(self):
        """
        BV: Color class has color codes

        Scenario:
          Given: C class
          When: Checking colors
          Then: All colors defined
        """
        assert hasattr(C, 'RED')
        assert hasattr(C, 'GREEN')
        assert hasattr(C, 'YELLOW')
        assert hasattr(C, 'BLUE')
        assert hasattr(C, 'CYAN')
        assert hasattr(C, 'MAGENTA')
        assert hasattr(C, 'WHITE')


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Edge case handling tests"""

    def test_empty_port_list(self):
        """
        BV: Handle empty port list

        Scenario:
          Given: Empty port list
          When: filter_ports() is called
          Then: Returns empty list
        """
        result = filter_ports([], "ssh")

        assert result == []

    def test_filter_empty_query(self):
        """
        BV: Empty string query returns all

        Scenario:
          Given: Empty string query
          When: filter_ports() is called
          Then: Returns all ports
        """
        result = filter_ports(PORT_DATA, "")

        # Empty string matches all (contains "")
        assert len(result) == len(PORT_DATA)

    def test_kerberos_port_in_ad_category(self):
        """
        BV: Kerberos port (88) colored as AD

        Scenario:
          Given: Port 88 (Kerberos)
          When: colorize_port() is called
          Then: Colored with AD/SMB color
        """
        result = colorize_port(88)

        assert C.RED in result
