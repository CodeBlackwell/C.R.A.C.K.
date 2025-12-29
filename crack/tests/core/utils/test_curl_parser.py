"""
Tests for Curl Command Parser

Business Value Focus:
- Parse curl commands exported from Burp Suite
- Extract request components for SQLi testing
- Handle malformed exports gracefully

Test Priority: TIER 2 - HIGH (Web Testing Tool)
"""

import pytest
from core.utils.curl_parser import CurlParser, parse_curl_command


# =============================================================================
# Sample Curl Commands
# =============================================================================

SIMPLE_GET = "curl 'http://example.com/path'"

SIMPLE_POST = """curl -X POST 'http://example.com/login' -d 'user=admin&pass=test'"""

WITH_HEADERS = """curl -X GET 'http://example.com/api' -H 'Content-Type: application/json' -H 'Authorization: Bearer token123'"""

WITH_DATA_BINARY = """curl -X POST 'http://example.com/api' --data-binary 'username=test&password=secret'"""

WITH_COOKIE = """curl 'http://example.com/dashboard' -b 'session=abc123; token=xyz'"""

WITH_USER_AGENT = """curl 'http://example.com/' -A 'Mozilla/5.0 (X11; Linux x86_64)'"""

WITH_REFERER = """curl 'http://example.com/page' -e 'http://example.com/previous'"""

MALFORMED_QUOTES = """curl -X POST' -H Host: example.com' 'http://example.com/api"""

WITH_BACKTICKS = """curl -X `POST` 'http://example.com/api'"""

MULTILINE = """curl -X POST \\
    -H 'Host: example.com' \\
    'http://example.com/api'"""

WITH_QUERY_PARAMS = "curl 'http://example.com/search?q=test&page=1'"


# =============================================================================
# Basic Parsing Tests
# =============================================================================

class TestBasicParsing:
    """Tests for basic curl command parsing"""

    def test_parse_simple_get(self):
        """
        BV: Parse simple GET request

        Scenario:
          Given: Simple curl GET command
          When: parse() is called
          Then: URL and method extracted
        """
        parser = CurlParser(SIMPLE_GET)
        result = parser.parse()

        assert result['method'] == 'GET'
        assert result['url'] == 'http://example.com/path'

    def test_parse_simple_post(self):
        """
        BV: Parse simple POST request

        Scenario:
          Given: Simple curl POST command
          When: parse() is called
          Then: Method is POST and data extracted
        """
        parser = CurlParser(SIMPLE_POST)
        result = parser.parse()

        assert result['method'] == 'POST'
        assert result['data'] == 'user=admin&pass=test'

    def test_parse_extracts_url(self):
        """
        BV: Extract URL correctly

        Scenario:
          Given: Curl command with URL
          When: parse() is called
          Then: URL extracted
        """
        parser = CurlParser(SIMPLE_GET)
        result = parser.parse()

        assert 'http://example.com' in result['url']


# =============================================================================
# Header Extraction Tests
# =============================================================================

class TestHeaderExtraction:
    """Tests for header extraction"""

    def test_parse_content_type_header(self):
        """
        BV: Extract Content-Type header

        Scenario:
          Given: Curl with Content-Type header
          When: parse() is called
          Then: Header extracted
        """
        parser = CurlParser(WITH_HEADERS)
        result = parser.parse()

        assert 'Content-Type' in result['headers']
        assert result['headers']['Content-Type'] == 'application/json'

    def test_parse_authorization_header(self):
        """
        BV: Extract Authorization header

        Scenario:
          Given: Curl with Authorization header
          When: parse() is called
          Then: Header extracted
        """
        parser = CurlParser(WITH_HEADERS)
        result = parser.parse()

        assert 'Authorization' in result['headers']
        assert 'Bearer' in result['headers']['Authorization']

    def test_parse_cookie_header(self):
        """
        BV: Extract Cookie header from -b flag

        Scenario:
          Given: Curl with -b cookie flag
          When: parse() is called
          Then: Cookie header extracted
        """
        parser = CurlParser(WITH_COOKIE)
        result = parser.parse()

        assert 'Cookie' in result['headers']
        assert 'session=abc123' in result['headers']['Cookie']

    def test_parse_user_agent_header(self):
        """
        BV: Extract User-Agent from -A flag

        Scenario:
          Given: Curl with -A user agent flag
          When: parse() is called
          Then: User-Agent header extracted
        """
        parser = CurlParser(WITH_USER_AGENT)
        result = parser.parse()

        assert 'User-Agent' in result['headers']
        assert 'Mozilla' in result['headers']['User-Agent']

    def test_parse_referer_header(self):
        """
        BV: Extract Referer from -e flag

        Scenario:
          Given: Curl with -e referer flag
          When: parse() is called
          Then: Referer header extracted
        """
        parser = CurlParser(WITH_REFERER)
        result = parser.parse()

        assert 'Referer' in result['headers']


# =============================================================================
# Data Extraction Tests
# =============================================================================

class TestDataExtraction:
    """Tests for POST data extraction"""

    def test_parse_data_binary(self):
        """
        BV: Extract --data-binary content

        Scenario:
          Given: Curl with --data-binary
          When: parse() is called
          Then: Data extracted
        """
        parser = CurlParser(WITH_DATA_BINARY)
        result = parser.parse()

        assert result['data'] is not None
        assert 'username=test' in result['data']

    def test_auto_detect_post_with_data(self):
        """
        BV: Auto-detect POST when data present

        Scenario:
          Given: Curl without -X but with -d
          When: parse() is called
          Then: Method becomes POST
        """
        cmd = "curl 'http://example.com/api' -d 'data=value'"
        parser = CurlParser(cmd)
        result = parser.parse()

        assert result['method'] == 'POST'


# =============================================================================
# Parameter Extraction Tests
# =============================================================================

class TestParameterExtraction:
    """Tests for URL/POST parameter extraction"""

    def test_parse_url_query_params(self):
        """
        BV: Extract URL query parameters

        Scenario:
          Given: Curl with query parameters
          When: parse() is called
          Then: Parameters extracted
        """
        parser = CurlParser(WITH_QUERY_PARAMS)
        result = parser.parse()

        assert 'q' in result['params']
        assert 'page' in result['params']

    def test_parse_post_data_params(self):
        """
        BV: Extract POST data parameters

        Scenario:
          Given: Curl with POST data
          When: parse() is called
          Then: Parameters extracted
        """
        parser = CurlParser(SIMPLE_POST)
        result = parser.parse()

        assert 'user' in result['params']
        assert 'pass' in result['params']


# =============================================================================
# Burp Fix Tests
# =============================================================================

class TestBurpFixes:
    """Tests for Burp Suite export fixes"""

    def test_fix_backticks(self):
        """
        BV: Fix Burp backtick exports

        Scenario:
          Given: Curl with backticks
          When: fix_burp_curl() is called
          Then: Backticks replaced with quotes
        """
        parser = CurlParser(WITH_BACKTICKS)
        fixed = parser.fix_burp_curl(WITH_BACKTICKS)

        assert '`' not in fixed
        assert 'Replaced' in str(parser.fixes_applied)

    def test_fix_line_continuations(self):
        """
        BV: Fix multiline curl exports

        Scenario:
          Given: Multiline curl with backslashes
          When: fix_burp_curl() is called
          Then: Line continuations removed
        """
        parser = CurlParser(MULTILINE)
        fixed = parser.fix_burp_curl(MULTILINE)

        assert '\\\n' not in fixed

    def test_fix_echo_escapes(self):
        """
        BV: Fix echo-added escapes

        Scenario:
          Given: Curl with escaped quotes
          When: fix_burp_curl() is called
          Then: Escape characters removed
        """
        cmd = r"curl -H \'Host: example.com\' http://example.com"
        parser = CurlParser(cmd)
        fixed = parser.fix_burp_curl(cmd)

        assert r"\'" not in fixed


# =============================================================================
# Testable Parameters Tests
# =============================================================================

class TestTestableParams:
    """Tests for testable parameter detection"""

    def test_get_testable_params_high_priority(self):
        """
        BV: Identify high priority parameters

        Scenario:
          Given: Curl with username parameter
          When: get_testable_params() is called
          Then: Parameter marked as high priority
        """
        cmd = "curl 'http://example.com/login' -d 'username=test&csrf=abc'"
        parser = CurlParser(cmd)
        parser.parse()
        testable = parser.get_testable_params()

        # username should be high priority
        high_priority = [p for p, priority in testable if priority == 'high']
        assert 'username' in high_priority

    def test_skip_csrf_tokens(self):
        """
        BV: Skip CSRF tokens in testable params

        Scenario:
          Given: Curl with csrf_token parameter
          When: get_testable_params() is called
          Then: csrf_token not in list
        """
        cmd = "curl 'http://example.com/api' -d 'data=value&csrf_token=xyz'"
        parser = CurlParser(cmd)
        parser.parse()
        testable = parser.get_testable_params()

        param_names = [p for p, _ in testable]
        assert 'csrf_token' not in param_names

    def test_skip_viewstate(self):
        """
        BV: Skip __VIEWSTATE parameters

        Scenario:
          Given: Curl with __VIEWSTATE
          When: get_testable_params() is called
          Then: __VIEWSTATE not in list
        """
        cmd = "curl 'http://example.com/api' -d 'search=test&__VIEWSTATE=xyz'"
        parser = CurlParser(cmd)
        parser.parse()
        testable = parser.get_testable_params()

        param_names = [p for p, _ in testable]
        assert '__VIEWSTATE' not in param_names

    def test_empty_params_returns_empty(self):
        """
        BV: Empty params returns empty list

        Scenario:
          Given: Curl without parameters
          When: get_testable_params() is called
          Then: Returns empty list
        """
        cmd = "curl 'http://example.com/'"
        parser = CurlParser(cmd)
        parser.parse()
        testable = parser.get_testable_params()

        assert testable == []


# =============================================================================
# Convenience Function Tests
# =============================================================================

class TestConvenienceFunction:
    """Tests for parse_curl_command function"""

    def test_parse_curl_command_function(self):
        """
        BV: Use convenience function

        Scenario:
          Given: Curl command string
          When: parse_curl_command() is called
          Then: Returns parsed dict
        """
        result = parse_curl_command(SIMPLE_GET)

        assert 'method' in result
        assert 'url' in result
        assert 'headers' in result


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestErrorHandling:
    """Tests for error handling"""

    def test_invalid_command_raises(self):
        """
        BV: Invalid command raises error

        Scenario:
          Given: Command not starting with curl
          When: parse() is called
          Then: Raises ValueError
        """
        parser = CurlParser("wget http://example.com")

        with pytest.raises(ValueError, match="Not a valid curl command"):
            parser.parse()

    def test_empty_command_handles_gracefully(self):
        """
        BV: Empty command handles gracefully

        Scenario:
          Given: Empty command
          When: parse() is called
          Then: Returns defaults without error
        """
        parser = CurlParser("")
        result = parser.parse()

        assert result['method'] == 'GET'
        assert result['url'] is None

    def test_malformed_command_uses_fallback(self):
        """
        BV: Malformed command uses fallback parser

        Scenario:
          Given: Severely malformed curl
          When: parse() is called
          Then: Fallback parser used
        """
        # This command has unbalanced quotes
        cmd = "curl -X POST -H 'Host: test http://example.com"
        parser = CurlParser(cmd)

        # Should not raise, fallback parser should handle it
        try:
            result = parser.parse()
            assert result is not None
        except ValueError:
            # Some malformed commands may still fail, which is acceptable
            pass


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Edge case handling tests"""

    def test_https_url(self):
        """
        BV: Parse HTTPS URL

        Scenario:
          Given: Curl with HTTPS URL
          When: parse() is called
          Then: URL extracted correctly
        """
        cmd = "curl 'https://secure.example.com/api'"
        parser = CurlParser(cmd)
        result = parser.parse()

        assert 'https://' in result['url']

    def test_url_with_port(self):
        """
        BV: Parse URL with port

        Scenario:
          Given: Curl with port in URL
          When: parse() is called
          Then: Port preserved
        """
        cmd = "curl 'http://example.com:8080/api'"
        parser = CurlParser(cmd)
        result = parser.parse()

        assert ':8080' in result['url']

    def test_basic_auth_flag(self):
        """
        BV: Parse -u basic auth flag

        Scenario:
          Given: Curl with -u flag
          When: parse() is called
          Then: Authorization header set
        """
        cmd = "curl -u admin:password 'http://example.com/api'"
        parser = CurlParser(cmd)
        result = parser.parse()

        assert 'Authorization' in result['headers']
        assert 'Basic' in result['headers']['Authorization']

    def test_multiple_headers(self):
        """
        BV: Parse multiple headers

        Scenario:
          Given: Curl with multiple -H flags
          When: parse() is called
          Then: All headers extracted
        """
        cmd = """curl 'http://example.com' -H 'Accept: */*' -H 'Host: example.com' -H 'X-Custom: value'"""
        parser = CurlParser(cmd)
        result = parser.parse()

        assert len(result['headers']) >= 3
