#!/usr/bin/env python3
"""
Unit tests for CurlParser utility
Tests parsing of curl commands, especially from Burp Suite exports
"""

import pytest
from crack.utils.curl_parser import CurlParser


class TestCurlParser:
    """Test CurlParser functionality"""

    @pytest.mark.unit
    @pytest.mark.fast
    def test_init(self, clean_curl_command):
        """Test CurlParser initialization"""
        parser = CurlParser(clean_curl_command)

        assert parser.curl_command == clean_curl_command.strip()
        assert parser.method == 'GET'  # Default
        assert parser.url is None
        assert parser.headers == {}
        assert parser.data is None
        assert parser.params == {}
        assert parser.fixes_applied == []

    @pytest.mark.unit
    def test_fix_burp_backticks(self):
        """Test fixing Burp Suite backtick formatting"""
        curl_with_backticks = "curl -X `POST` -H `Content-Type: application/json` `http://test.com`"
        parser = CurlParser(curl_with_backticks)

        fixed = parser.fix_burp_curl(curl_with_backticks)

        assert '`' not in fixed
        assert "'" in fixed
        assert "-X 'POST'" in fixed
        assert "'Content-Type: application/json'" in fixed
        assert "'http://test.com'" in fixed
        assert "Replaced 6 backtick(s) with single quotes" in parser.fixes_applied

    @pytest.mark.unit
    def test_fix_line_continuations(self):
        """Test fixing multi-line curl commands with backslashes"""
        multiline_curl = """curl -X POST \\
            -H 'Content-Type: application/json' \\
            -H 'Authorization: Bearer token' \\
            --data '{"key": "value"}' \\
            http://test.com/api"""

        parser = CurlParser(multiline_curl)
        fixed = parser.fix_burp_curl(multiline_curl)

        # Should be on single line
        assert '\\\n' not in fixed
        assert '\n' not in fixed
        # All components should be present
        assert "-X POST" in fixed
        assert "Content-Type: application/json" in fixed
        assert "Authorization: Bearer token" in fixed

    @pytest.mark.unit
    def test_parse_simple_get(self):
        """Test parsing simple GET request"""
        curl_cmd = "curl http://test.com/page"
        parser = CurlParser(curl_cmd)
        parser.parse()

        assert parser.url == "http://test.com/page"
        assert parser.method == "GET"
        assert parser.data is None

    @pytest.mark.unit
    def test_parse_post_with_data(self):
        """Test parsing POST request with data"""
        curl_cmd = "curl -X POST --data 'username=admin&password=pass' http://test.com/login"
        parser = CurlParser(curl_cmd)
        parser.parse()

        assert parser.url == "http://test.com/login"
        assert parser.method == "POST"
        assert parser.data == "username=admin&password=pass"
        assert parser.params == {'username': ['admin'], 'password': ['pass']}

    @pytest.mark.unit
    def test_parse_headers(self):
        """Test parsing headers"""
        curl_cmd = """curl -H 'Content-Type: application/json' \
                          -H 'Authorization: Bearer token123' \
                          -H 'X-Custom: value' \
                          http://test.com/api"""
        parser = CurlParser(curl_cmd)
        parser.parse()

        assert parser.headers['Content-Type'] == 'application/json'
        assert parser.headers['Authorization'] == 'Bearer token123'
        assert parser.headers['X-Custom'] == 'value'

    @pytest.mark.unit
    def test_parse_data_binary(self):
        """Test parsing --data-binary flag"""
        curl_cmd = "curl -X POST --data-binary '{\"json\": \"data\"}' http://test.com/api"
        parser = CurlParser(curl_cmd)
        parser.parse()

        assert parser.method == "POST"
        assert parser.data == '{"json": "data"}'

    @pytest.mark.unit
    def test_parse_data_raw(self):
        """Test parsing --data-raw flag"""
        curl_cmd = "curl -X POST --data-raw 'raw=data&test=value' http://test.com/api"
        parser = CurlParser(curl_cmd)
        parser.parse()

        assert parser.method == "POST"
        assert parser.data == "raw=data&test=value"

    @pytest.mark.unit
    def test_parse_method_flags(self):
        """Test parsing different HTTP method flags"""
        test_cases = [
            ("curl -X PUT http://test.com", "PUT"),
            ("curl -X DELETE http://test.com", "DELETE"),
            ("curl -X PATCH http://test.com", "PATCH"),
            ("curl --request POST http://test.com", "POST"),
        ]

        for curl_cmd, expected_method in test_cases:
            parser = CurlParser(curl_cmd)
            parser.parse()
            assert parser.method == expected_method

    @pytest.mark.unit
    def test_parse_url_with_query_params(self):
        """Test parsing URL with query parameters"""
        curl_cmd = "curl 'http://test.com/search?q=test&page=1&limit=10'"
        parser = CurlParser(curl_cmd)
        parser.parse()

        assert parser.url == "http://test.com/search?q=test&page=1&limit=10"
        # Parameters should be parsed from URL
        assert 'q' in parser.params
        assert parser.params['q'] == ['test']
        assert parser.params['page'] == ['1']
        assert parser.params['limit'] == ['10']

    @pytest.mark.unit
    def test_parse_burp_export(self, burp_curl_command):
        """Test parsing actual Burp Suite export format"""
        parser = CurlParser(burp_curl_command)

        # Fix and parse
        fixed = parser.fix_burp_curl(burp_curl_command)
        parser.curl_command = fixed
        parser.parse()

        assert parser.url == "http://192.168.45.100/login.php"
        assert parser.method == "POST"
        assert parser.headers['Host'] == '192.168.45.100'
        assert parser.headers['Content-Type'] == 'application/x-www-form-urlencoded'
        assert 'username=admin' in parser.data
        assert 'password=password123' in parser.data

    @pytest.mark.unit
    def test_parse_compressed_flag(self):
        """Test parsing with compression flags"""
        curl_cmd = "curl --compressed -H 'Accept-Encoding: gzip, deflate' http://test.com"
        parser = CurlParser(curl_cmd)
        parser.parse()

        assert parser.headers['Accept-Encoding'] == 'gzip, deflate'

    @pytest.mark.unit
    def test_parse_user_agent(self):
        """Test parsing user agent"""
        curl_cmd = "curl -A 'Mozilla/5.0' http://test.com"
        parser = CurlParser(curl_cmd)
        parser.parse()

        assert parser.headers.get('User-Agent') == 'Mozilla/5.0'

        # Alternative format
        curl_cmd2 = "curl --user-agent 'Custom Agent' http://test.com"
        parser2 = CurlParser(curl_cmd2)
        parser2.parse()

        assert parser2.headers.get('User-Agent') == 'Custom Agent'

    @pytest.mark.unit
    def test_parse_cookie_header(self):
        """Test parsing cookie headers"""
        curl_cmd = "curl -H 'Cookie: session=abc123; user=admin' http://test.com"
        parser = CurlParser(curl_cmd)
        parser.parse()

        assert parser.headers['Cookie'] == 'session=abc123; user=admin'

    @pytest.mark.unit
    @pytest.mark.fast
    def test_empty_curl_command(self):
        """Test parsing empty curl command"""
        parser = CurlParser("")
        parser.parse()

        assert parser.url is None
        assert parser.method == "GET"
        assert parser.data is None

    @pytest.mark.unit
    def test_url_encoding_preservation(self):
        """Test that URL encoding is preserved"""
        curl_cmd = "curl 'http://test.com/page?param=%20test%20&special=%3D%26'"
        parser = CurlParser(curl_cmd)
        parser.parse()

        # URL encoding should be preserved
        assert '%20' in parser.url or ' test ' in str(parser.params)

    @pytest.mark.unit
    def test_multiple_data_flags(self):
        """Test handling multiple data flags"""
        curl_cmd = "curl -d 'field1=value1' -d 'field2=value2' http://test.com"
        parser = CurlParser(curl_cmd)
        parser.parse()

        # Multiple -d flags should be concatenated
        assert parser.data is not None
        assert 'field1=value1' in parser.data or 'field2=value2' in parser.data

    @pytest.mark.unit
    def test_json_data_parsing(self):
        """Test parsing JSON data"""
        curl_cmd = '''curl -X POST -H 'Content-Type: application/json' \
                      --data '{"username": "admin", "password": "pass"}' \
                      http://test.com/api/login'''
        parser = CurlParser(curl_cmd)
        parser.parse()

        assert parser.headers['Content-Type'] == 'application/json'
        assert '"username"' in parser.data
        assert '"admin"' in parser.data

    @pytest.mark.unit
    def test_insecure_flag(self):
        """Test parsing -k/--insecure flag"""
        curl_cmd = "curl -k https://test.com"
        parser = CurlParser(curl_cmd)
        parser.parse()

        # Should recognize the URL even with -k flag
        assert parser.url == "https://test.com"

    @pytest.mark.unit
    def test_location_flag(self):
        """Test parsing -L/--location flag"""
        curl_cmd = "curl -L http://test.com/redirect"
        parser = CurlParser(curl_cmd)
        parser.parse()

        assert parser.url == "http://test.com/redirect"

    @pytest.mark.unit
    def test_fixes_applied_tracking(self):
        """Test that all fixes are tracked"""
        curl_cmd = "curl -X `POST` \\\n    -H `Host: test.com` \\\n    `http://test.com`"
        parser = CurlParser(curl_cmd)
        fixed = parser.fix_burp_curl(curl_cmd)

        # Should track both types of fixes
        assert any('backtick' in fix for fix in parser.fixes_applied)
        assert any('line continuation' in fix for fix in parser.fixes_applied)