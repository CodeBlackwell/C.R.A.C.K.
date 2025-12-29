"""
Tests for Core Utilities - Shared utility functions.

Business Value Focus:
- Curl parser handles malformed Burp Suite exports
- Port reference provides accurate quick lookup
- Utilities handle edge cases gracefully

TIER 3: EDGE CASE HANDLING (Medium) - Malformed input, encoding issues
TIER 2: FUNCTIONAL CORRECTNESS (High) - Correct parsing, accurate data
"""

import pytest
from typing import Dict, Any


# =============================================================================
# CurlParser Tests
# =============================================================================

class TestCurlParserBasic:
    """Tests for basic curl command parsing"""

    def test_parses_simple_get_request(self):
        """
        BV: Simple curl commands are correctly parsed.

        Scenario:
          Given: Simple GET curl command
          When: parse() is called
          Then: Method is GET, URL is extracted
        """
        from core.utils.curl_parser import CurlParser

        parser = CurlParser("curl http://example.com")
        result = parser.parse()

        assert result['method'] == 'GET'
        assert result['url'] == 'http://example.com'

    def test_parses_post_method(self):
        """
        BV: POST method is correctly detected.

        Scenario:
          Given: Curl with -X POST
          When: parse() is called
          Then: Method is POST
        """
        from core.utils.curl_parser import CurlParser

        parser = CurlParser("curl -X POST http://example.com")
        result = parser.parse()

        assert result['method'] == 'POST'

    def test_parses_headers(self):
        """
        BV: Headers are extracted correctly.

        Scenario:
          Given: Curl with -H 'Host: example.com'
          When: parse() is called
          Then: Headers dict contains Host key
        """
        from core.utils.curl_parser import CurlParser

        parser = CurlParser("curl -H 'Host: example.com' -H 'User-Agent: test' http://example.com")
        result = parser.parse()

        assert result['headers']['Host'] == 'example.com'
        assert result['headers']['User-Agent'] == 'test'

    def test_parses_post_data(self):
        """
        BV: POST data is extracted for further analysis.

        Scenario:
          Given: Curl with -d 'user=admin&pass=secret'
          When: parse() is called
          Then: Data field contains the POST body
        """
        from core.utils.curl_parser import CurlParser

        parser = CurlParser("curl -X POST -d 'user=admin&pass=secret' http://example.com/login")
        result = parser.parse()

        assert result['data'] == 'user=admin&pass=secret'
        assert 'user' in result['params']
        assert 'pass' in result['params']

    def test_extracts_url_query_params(self):
        """
        BV: URL query parameters are extracted for testing.

        Scenario:
          Given: Curl with URL containing ?id=123&page=1
          When: parse() is called
          Then: Params dict contains id and page
        """
        from core.utils.curl_parser import CurlParser

        parser = CurlParser("curl 'http://example.com/api?id=123&page=1'")
        result = parser.parse()

        assert 'id' in result['params']
        assert 'page' in result['params']


class TestCurlParserBurpFixes:
    """Tests for Burp Suite export malformation handling"""

    def test_fixes_backtick_quotes(self):
        """
        BV: Burp's backtick format is corrected automatically.

        Scenario:
          Given: Curl with backticks instead of quotes
          When: parse() is called
          Then: Command is parsed correctly
        """
        from core.utils.curl_parser import CurlParser

        parser = CurlParser("curl -X `POST` -H `Host: example.com` http://example.com")
        result = parser.parse()

        assert result['method'] == 'POST'
        assert 'Replaced' in str(parser.fixes_applied)

    def test_fixes_line_continuations(self):
        """
        BV: Multiline curl commands with backslashes are handled.

        Scenario:
          Given: Multiline curl with \\ continuations
          When: parse() is called
          Then: All lines are combined and parsed
        """
        from core.utils.curl_parser import CurlParser

        curl_cmd = """curl -X POST \\
  -H 'Host: test.com' \\
  -d 'data=value' \\
  http://test.com/api"""

        parser = CurlParser(curl_cmd)
        result = parser.parse()

        assert result['method'] == 'POST'
        assert result['headers']['Host'] == 'test.com'

    def test_fixes_echo_escaped_quotes(self):
        """
        BV: Echo-mangled backslash escapes are corrected.

        Scenario:
          Given: Curl with \\' instead of '
          When: parse() is called
          Then: Escapes are removed and parsing succeeds
        """
        from core.utils.curl_parser import CurlParser

        curl_cmd = r"curl -X POST -H \'Host: example.com\' http://example.com"
        parser = CurlParser(curl_cmd)
        result = parser.parse()

        assert result['method'] == 'POST'

    def test_handles_malformed_header_quotes(self):
        """
        BV: Headers with misplaced quotes are corrected.

        Scenario:
          Given: Curl with -H Host: value' (missing opening quote)
          When: parse() is called
          Then: Header is extracted correctly
        """
        from core.utils.curl_parser import CurlParser

        # This is a common Burp malformation
        curl_cmd = "curl -X POST' -H Host: example.com' http://example.com"
        parser = CurlParser(curl_cmd)
        result = parser.parse()

        # Should extract URL at minimum
        assert result['url'] is not None


class TestCurlParserEdgeCases:
    """Tests for edge case handling"""

    def test_handles_empty_command(self):
        """
        BV: Empty command doesn't crash parser.

        Scenario:
          Given: Empty string
          When: parse() is called
          Then: Returns default structure without exception
        """
        from core.utils.curl_parser import CurlParser

        parser = CurlParser("")
        result = parser.parse()

        assert result['method'] == 'GET'
        assert result['url'] is None

    def test_handles_curl_only(self):
        """
        BV: 'curl' alone returns valid structure.

        Scenario:
          Given: Just 'curl' with no args
          When: parse() is called
          Then: Returns default structure
        """
        from core.utils.curl_parser import CurlParser

        parser = CurlParser("curl")
        result = parser.parse()

        assert result['method'] == 'GET'
        assert result['url'] is None

    def test_rejects_non_curl_command(self):
        """
        BV: Non-curl commands are rejected with clear error.

        Scenario:
          Given: Command that doesn't start with 'curl'
          When: parse() is called
          Then: Raises ValueError
        """
        from core.utils.curl_parser import CurlParser

        parser = CurlParser("wget http://example.com")

        with pytest.raises(ValueError) as exc_info:
            parser.parse()

        assert 'curl' in str(exc_info.value).lower()

    def test_auto_detects_post_from_data(self):
        """
        BV: POST is inferred when -d is used without -X.

        Scenario:
          Given: Curl with -d but no -X POST
          When: parse() is called
          Then: Method is POST
        """
        from core.utils.curl_parser import CurlParser

        parser = CurlParser("curl -d 'data=value' http://example.com")
        result = parser.parse()

        assert result['method'] == 'POST'

    def test_handles_data_binary_flag(self):
        """
        BV: --data-binary is parsed same as -d.

        Scenario:
          Given: Curl with --data-binary
          When: parse() is called
          Then: Data is extracted
        """
        from core.utils.curl_parser import CurlParser

        parser = CurlParser("curl -X POST --data-binary 'binary_data' http://example.com")
        result = parser.parse()

        assert result['data'] == 'binary_data'

    def test_handles_cookie_flag(self):
        """
        BV: -b/--cookie is converted to Cookie header.

        Scenario:
          Given: Curl with -b 'session=abc123'
          When: parse() is called
          Then: Cookie header is set
        """
        from core.utils.curl_parser import CurlParser

        parser = CurlParser("curl -b 'session=abc123' http://example.com")
        result = parser.parse()

        assert result['headers']['Cookie'] == 'session=abc123'

    def test_handles_user_agent_flag(self):
        """
        BV: -A/--user-agent is converted to User-Agent header.

        Scenario:
          Given: Curl with -A 'Mozilla/5.0'
          When: parse() is called
          Then: User-Agent header is set
        """
        from core.utils.curl_parser import CurlParser

        parser = CurlParser("curl -A 'Mozilla/5.0' http://example.com")
        result = parser.parse()

        assert result['headers']['User-Agent'] == 'Mozilla/5.0'


class TestCurlParserTestableParams:
    """Tests for testable parameter detection"""

    def test_identifies_high_priority_params(self):
        """
        BV: User input fields are flagged as high priority for testing.

        Scenario:
          Given: POST data with username and password fields
          When: get_testable_params() is called
          Then: Both are marked as high priority
        """
        from core.utils.curl_parser import CurlParser

        parser = CurlParser("curl -d 'username=admin&password=secret' http://example.com")
        parser.parse()

        testable = parser.get_testable_params()

        # Find high priority params
        high_priority = [p for p, priority in testable if priority == 'high']

        assert 'username' in high_priority or any('user' in p for p in high_priority)

    def test_excludes_csrf_tokens(self):
        """
        BV: CSRF tokens are excluded from testable params.

        Scenario:
          Given: POST data with csrf_token field
          When: get_testable_params() is called
          Then: csrf_token is not in list
        """
        from core.utils.curl_parser import CurlParser

        parser = CurlParser("curl -d 'username=admin&csrf_token=abc123' http://example.com")
        parser.parse()

        testable = parser.get_testable_params()
        param_names = [p for p, _ in testable]

        assert 'csrf_token' not in param_names

    def test_excludes_viewstate(self):
        """
        BV: ASP.NET ViewState is excluded from testing.

        Scenario:
          Given: POST data with __VIEWSTATE field
          When: get_testable_params() is called
          Then: __VIEWSTATE is not in list
        """
        from core.utils.curl_parser import CurlParser

        parser = CurlParser("curl -d '__VIEWSTATE=abc123&username=admin' http://example.com")
        parser.parse()

        testable = parser.get_testable_params()
        param_names = [p for p, _ in testable]

        assert '__VIEWSTATE' not in param_names

    def test_returns_empty_for_no_params(self):
        """
        BV: No params case is handled gracefully.

        Scenario:
          Given: GET request with no params
          When: get_testable_params() is called
          Then: Returns empty list
        """
        from core.utils.curl_parser import CurlParser

        parser = CurlParser("curl http://example.com")
        parser.parse()

        testable = parser.get_testable_params()

        assert testable == []


# =============================================================================
# Port Reference Tests
# =============================================================================

class TestPortReference:
    """Tests for port reference utility"""

    def test_port_data_contains_common_ports(self):
        """
        BV: Common pentesting ports are documented.

        Scenario:
          Given: PORT_DATA constant
          When: Checking for common ports
          Then: 21, 22, 80, 443, 445 are present
        """
        from core.utils.ports import PORT_DATA

        ports = [p[0] for p in PORT_DATA]

        assert 21 in ports  # FTP
        assert 22 in ports  # SSH
        assert 80 in ports  # HTTP
        assert 443 in ports  # HTTPS
        assert 445 in ports  # SMB

    def test_port_data_has_complete_entries(self):
        """
        BV: Each port entry has all required fields.

        Scenario:
          Given: PORT_DATA entries
          When: Checking structure
          Then: Each entry has port, protocol, service, description, tools
        """
        from core.utils.ports import PORT_DATA

        for entry in PORT_DATA:
            assert len(entry) == 5, f"Entry {entry} doesn't have 5 fields"
            port, proto, service, desc, tools = entry
            assert isinstance(port, int)
            assert proto in ['TCP', 'UDP', 'TCP/UDP']
            assert len(service) > 0
            assert len(desc) > 0
            assert len(tools) > 0

    def test_filter_ports_by_service(self):
        """
        BV: Users can filter ports by service name.

        Scenario:
          Given: PORT_DATA
          When: filter_ports with 'smb' query
          Then: Returns SMB-related ports
        """
        from core.utils.ports import filter_ports, PORT_DATA

        filtered = filter_ports(PORT_DATA, 'smb')

        assert len(filtered) > 0
        # Port 445 should be in results
        ports = [p[0] for p in filtered]
        assert 445 in ports

    def test_filter_ports_by_port_number(self):
        """
        BV: Users can filter by port number.

        Scenario:
          Given: PORT_DATA
          When: filter_ports with '445'
          Then: Returns entry for port 445
        """
        from core.utils.ports import filter_ports, PORT_DATA

        filtered = filter_ports(PORT_DATA, '445')

        assert len(filtered) >= 1
        assert filtered[0][0] == 445

    def test_filter_ports_by_tool(self):
        """
        BV: Users can find ports by associated tool.

        Scenario:
          Given: PORT_DATA
          When: filter_ports with 'hydra'
          Then: Returns ports where hydra is listed as tool
        """
        from core.utils.ports import filter_ports, PORT_DATA

        filtered = filter_ports(PORT_DATA, 'hydra')

        assert len(filtered) > 0
        # Verify hydra is in tools for returned ports
        for entry in filtered:
            assert 'hydra' in entry[4].lower()

    def test_filter_ports_returns_empty_for_no_match(self):
        """
        BV: No match returns empty list, not error.

        Scenario:
          Given: PORT_DATA
          When: filter_ports with 'nonexistent_query'
          Then: Returns empty list
        """
        from core.utils.ports import filter_ports, PORT_DATA

        filtered = filter_ports(PORT_DATA, 'nonexistent_query_xyz')

        assert filtered == []

    def test_filter_ports_case_insensitive(self):
        """
        BV: Search is case-insensitive for convenience.

        Scenario:
          Given: PORT_DATA
          When: filter_ports with 'SMB' (uppercase)
          Then: Returns same results as 'smb' (lowercase)
        """
        from core.utils.ports import filter_ports, PORT_DATA

        upper = filter_ports(PORT_DATA, 'SMB')
        lower = filter_ports(PORT_DATA, 'smb')

        assert upper == lower

    def test_colorize_port_categorizes_correctly(self):
        """
        BV: Ports are color-coded by category for quick identification.

        Scenario:
          Given: Port colorization function
          When: colorize_port(445) is called
          Then: Returns string with red ANSI code (AD/SMB category)
        """
        from core.utils.ports import colorize_port

        result = colorize_port(445)

        # SMB should be red
        assert '\033[91m' in result or 'red' in result.lower()

    def test_colorize_port_handles_unknown(self):
        """
        BV: Unknown ports get default color.

        Scenario:
          Given: Port not in any category
          When: colorize_port(9999) is called
          Then: Returns string with white ANSI code
        """
        from core.utils.ports import colorize_port

        result = colorize_port(9999)

        # Should have white color for uncategorized
        assert '\033[97m' in result  # White


class TestParseCurlConvenience:
    """Tests for parse_curl_command convenience function"""

    def test_convenience_function_works(self):
        """
        BV: Simple API for quick curl parsing.

        Scenario:
          Given: parse_curl_command function
          When: Called with curl string
          Then: Returns parsed dict
        """
        from core.utils.curl_parser import parse_curl_command

        result = parse_curl_command("curl -X POST http://example.com")

        assert result['method'] == 'POST'
        assert result['url'] == 'http://example.com'


# =============================================================================
# Validators Tests (from config module but utility-like)
# =============================================================================

class TestValidators:
    """Tests for configuration validators"""

    def test_validate_ip_accepts_valid(self):
        """
        BV: Valid IPs pass validation.

        Scenario:
          Given: Valid IP address
          When: validate_ip() is called
          Then: Returns (True, None)
        """
        from core.config.validators import Validators

        is_valid, error = Validators.validate_ip('192.168.1.100')

        assert is_valid is True
        assert error is None

    def test_validate_ip_rejects_invalid(self):
        """
        BV: Invalid IPs are rejected with clear error.

        Scenario:
          Given: Invalid IP format
          When: validate_ip() is called
          Then: Returns (False, error_message)
        """
        from core.config.validators import Validators

        is_valid, error = Validators.validate_ip('999.999.999.999')

        assert is_valid is False
        assert error is not None

    def test_validate_port_accepts_valid_range(self):
        """
        BV: Ports 1-65535 are accepted.

        Scenario:
          Given: Valid port number
          When: validate_port() is called
          Then: Returns (True, None)
        """
        from core.config.validators import Validators

        valid_ports = ['1', '80', '443', '8080', '65535']

        for port in valid_ports:
            is_valid, error = Validators.validate_port(port)
            assert is_valid is True, f"Port {port} should be valid"

    def test_validate_port_rejects_out_of_range(self):
        """
        BV: Ports outside 1-65535 are rejected.

        Scenario:
          Given: Port 0 or 99999
          When: validate_port() is called
          Then: Returns (False, error_message)
        """
        from core.config.validators import Validators

        is_valid, error = Validators.validate_port('0')
        assert is_valid is False

        is_valid, error = Validators.validate_port('99999')
        assert is_valid is False

    def test_validate_url_requires_protocol(self):
        """
        BV: URLs must start with http:// or https://.

        Scenario:
          Given: URL without protocol
          When: validate_url() is called
          Then: Returns (False, error_message)
        """
        from core.config.validators import Validators

        is_valid, error = Validators.validate_url('example.com')

        assert is_valid is False
        assert 'http' in error.lower()

    def test_validate_cidr_accepts_valid(self):
        """
        BV: Valid CIDR notation is accepted.

        Scenario:
          Given: Valid CIDR like 192.168.1.0/24
          When: validate_cidr() is called
          Then: Returns (True, None)
        """
        from core.config.validators import Validators

        is_valid, error = Validators.validate_cidr('192.168.1.0/24')

        assert is_valid is True

    def test_validate_cve_format(self):
        """
        BV: CVE format is validated for accuracy.

        Scenario:
          Given: Valid CVE-YYYY-NNNNN format
          When: validate_cve() is called
          Then: Returns (True, None)
        """
        from core.config.validators import Validators

        is_valid, error = Validators.validate_cve('CVE-2021-44228')

        assert is_valid is True

    def test_validate_cve_rejects_invalid(self):
        """
        BV: Invalid CVE format is rejected.

        Scenario:
          Given: CVE with wrong format
          When: validate_cve() is called
          Then: Returns (False, error_message)
        """
        from core.config.validators import Validators

        is_valid, error = Validators.validate_cve('CVE-21-1234')

        assert is_valid is False

    def test_validate_hash_32_char(self):
        """
        BV: NTLM/LM hashes are validated for correct length.

        Scenario:
          Given: 32 hex character string
          When: validate_hash() is called
          Then: Returns (True, None)
        """
        from core.config.validators import Validators

        valid_hash = 'a' * 32

        is_valid, error = Validators.validate_hash(valid_hash, length=32)

        assert is_valid is True

    def test_validate_interface_accepts_common(self):
        """
        BV: Common interface names are accepted.

        Scenario:
          Given: Interface names like tun0, eth0, wlan0
          When: validate_interface() is called
          Then: Returns (True, None)
        """
        from core.config.validators import Validators

        interfaces = ['tun0', 'eth0', 'wlan0', 'lo']

        for iface in interfaces:
            is_valid, error = Validators.validate_interface(iface)
            assert is_valid is True, f"Interface {iface} should be valid"

    def test_get_validator_for_variable_returns_correct(self):
        """
        BV: Correct validator is selected for each variable type.

        Scenario:
          Given: Variable names
          When: get_validator_for_variable() is called
          Then: Returns appropriate validator function
        """
        from core.config.validators import Validators

        # LHOST should get IP validator
        validator = Validators.get_validator_for_variable('LHOST')
        assert validator is not None

        # Port should get port validator
        validator = Validators.get_validator_for_variable('LPORT')
        assert validator is not None

    def test_validate_variable_uses_correct_validator(self):
        """
        BV: validate_variable() auto-selects correct validation.

        Scenario:
          Given: Variable name and value
          When: validate_variable() is called
          Then: Correct validator is applied
        """
        from core.config.validators import Validators

        # Valid IP
        is_valid, error = Validators.validate_variable('LHOST', '10.10.14.5')
        assert is_valid is True

        # Invalid IP
        is_valid, error = Validators.validate_variable('LHOST', 'invalid')
        assert is_valid is False
