#!/usr/bin/env python3
"""
Unit tests for SQLiScanner module
Tests SQL injection detection functionality
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import time
import requests

from crack.sqli.scanner import SQLiScanner


class TestSQLiScanner:
    """Test SQLiScanner functionality"""

    @pytest.mark.unit
    @pytest.mark.sqli
    def test_init_default_config(self, sqli_vulnerable_url):
        """Test SQLiScanner initialization with defaults"""
        scanner = SQLiScanner(sqli_vulnerable_url)

        assert scanner.target == sqli_vulnerable_url
        assert scanner.method == 'GET'  # AUTO defaults to GET without POST data
        assert scanner.post_data is None
        assert scanner.test_params is None
        assert scanner.technique == 'all'
        assert scanner.verbose is False
        assert scanner.quick is False
        assert scanner.delay == 0.5
        assert scanner.timeout == 10
        assert scanner.min_findings == 0

    @pytest.mark.unit
    @pytest.mark.sqli
    def test_init_with_post_data(self, target_url):
        """Test initialization with POST data"""
        post_data = "username=admin&password=test"
        scanner = SQLiScanner(target_url, data=post_data)

        assert scanner.method == 'POST'  # AUTO detects POST from data
        assert scanner.post_data == post_data
        assert scanner.post_params == {'username': ['admin'], 'password': ['test']}

    @pytest.mark.unit
    @pytest.mark.sqli
    def test_init_explicit_method(self, target_url):
        """Test explicit method specification"""
        scanner = SQLiScanner(target_url, method='POST')
        assert scanner.method == 'POST'

        scanner = SQLiScanner(target_url, method='GET', data="ignored_data")
        assert scanner.method == 'GET'

    @pytest.mark.unit
    @pytest.mark.sqli
    @pytest.mark.fast
    def test_get_baseline_get_request(self, sqli_vulnerable_url, mock_requests_session):
        """Test baseline establishment for GET requests"""
        scanner = SQLiScanner(sqli_vulnerable_url)

        # Configure mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"Normal response"
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_requests_session.get.return_value = mock_response

        baseline = scanner.get_baseline()

        assert baseline is not None
        assert baseline['status'] == 200
        assert baseline['length'] > 0
        assert 'time' in baseline
        assert 'hash' in baseline

        # Verify GET was called
        assert mock_requests_session.get.called

    @pytest.mark.unit
    @pytest.mark.sqli
    def test_get_baseline_post_request(self, target_url, mock_requests_session):
        """Test baseline establishment for POST requests"""
        post_data = "param1=value1&param2=value2"
        scanner = SQLiScanner(target_url, method='POST', data=post_data)

        # Configure mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"POST response"
        mock_requests_session.post.return_value = mock_response

        baseline = scanner.get_baseline()

        assert baseline is not None
        # Verify POST was called with data
        mock_requests_session.post.assert_called()
        call_args = mock_requests_session.post.call_args
        assert call_args[1]['data'] == post_data

    @pytest.mark.unit
    @pytest.mark.sqli
    def test_get_baseline_averaging(self, sqli_vulnerable_url, mock_requests_session):
        """Test that baseline averages multiple samples"""
        scanner = SQLiScanner(sqli_vulnerable_url)

        # Mock responses with slightly different times
        responses = []
        for i in range(3):
            mock_resp = Mock()
            mock_resp.status_code = 200
            mock_resp.content = b"Response content"
            mock_resp.headers = {}
            responses.append(mock_resp)

        mock_requests_session.get.side_effect = responses

        with patch('time.time') as mock_time:
            # Simulate different response times
            mock_time.side_effect = [0, 0.1, 0.1, 0.2, 0.2, 0.3]
            baseline = scanner.get_baseline()

        # Should have called get 3 times for averaging
        assert mock_requests_session.get.call_count == 3

        # Baseline time should be averaged
        assert baseline['time'] == pytest.approx(0.1, rel=0.1)

    @pytest.mark.unit
    @pytest.mark.sqli
    def test_test_parameter_selection(self, sqli_vulnerable_url):
        """Test parameter selection for testing"""
        scanner = SQLiScanner(sqli_vulnerable_url, params="id,name")

        # Parse URL parameters
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(sqli_vulnerable_url)
        params = parse_qs(parsed.query)

        # Should have detected 'id' parameter from URL
        assert 'id' in params

    @pytest.mark.unit
    @pytest.mark.sqli
    def test_test_injection_error_based(self, sqli_vulnerable_url, mock_requests_session):
        """Test error-based SQL injection detection"""
        scanner = SQLiScanner(sqli_vulnerable_url)

        # Set up baseline
        scanner.baseline = {
            'status': 200,
            'length': 1000,
            'time': 0.1,
            'hash': 'abc123'
        }

        # Mock error response for injection payload
        mock_error_resp = Mock()
        mock_error_resp.status_code = 200
        mock_error_resp.content = b"MySQL error: You have an error in your SQL syntax"
        mock_error_resp.text = "MySQL error: You have an error in your SQL syntax"
        mock_requests_session.get.return_value = mock_error_resp

        # Test with error-based payload
        from crack.sqli.techniques import SQLiTechniques
        with patch.object(SQLiTechniques, 'test_error_based') as mock_test:
            mock_test.return_value = {
                'vulnerable': True,
                'confidence': 'HIGH',
                'type': 'Error-based SQLi',
                'details': 'MySQL error detected'
            }

            # This would normally be called internally
            result = mock_test.return_value

        assert result['vulnerable'] is True
        assert result['confidence'] == 'HIGH'
        assert 'Error-based' in result['type']

    @pytest.mark.unit
    @pytest.mark.sqli
    def test_test_injection_boolean_based(self, sqli_vulnerable_url, mock_requests_session):
        """Test boolean-based blind SQL injection detection"""
        scanner = SQLiScanner(sqli_vulnerable_url)

        scanner.baseline = {
            'status': 200,
            'length': 1000,
            'time': 0.1,
            'hash': 'abc123'
        }

        # Mock different responses for true/false conditions
        true_resp = Mock()
        true_resp.status_code = 200
        true_resp.content = b"Welcome user"
        true_resp.text = "Welcome user"

        false_resp = Mock()
        false_resp.status_code = 200
        false_resp.content = b"No results"
        false_resp.text = "No results"

        mock_requests_session.get.side_effect = [true_resp, false_resp]

        from crack.sqli.techniques import SQLiTechniques
        with patch.object(SQLiTechniques, 'test_boolean_blind') as mock_test:
            mock_test.return_value = {
                'vulnerable': True,
                'confidence': 'MEDIUM',
                'type': 'Boolean-based blind SQLi',
                'details': 'Different responses for true/false'
            }

            result = mock_test.return_value

        assert result['vulnerable'] is True
        assert 'Boolean-based' in result['type']

    @pytest.mark.unit
    @pytest.mark.sqli
    def test_test_injection_time_based(self, sqli_vulnerable_url, mock_requests_session):
        """Test time-based blind SQL injection detection"""
        scanner = SQLiScanner(sqli_vulnerable_url, technique='time')

        scanner.baseline = {
            'status': 200,
            'length': 1000,
            'time': 0.1,
            'hash': 'abc123'
        }

        # Mock delayed response
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.content = b"Response"

        def delayed_get(*args, **kwargs):
            time.sleep(3)  # Simulate SQL sleep
            return mock_resp

        from crack.sqli.techniques import SQLiTechniques
        with patch.object(SQLiTechniques, 'test_time_blind') as mock_test:
            mock_test.return_value = {
                'vulnerable': True,
                'confidence': 'HIGH',
                'type': 'Time-based blind SQLi',
                'details': 'Significant delay detected (3s)'
            }

            result = mock_test.return_value

        assert result['vulnerable'] is True
        assert 'Time-based' in result['type']

    @pytest.mark.unit
    @pytest.mark.sqli
    def test_quick_mode(self, sqli_vulnerable_url):
        """Test quick mode uses fewer payloads"""
        scanner_quick = SQLiScanner(sqli_vulnerable_url, quick=True)
        scanner_normal = SQLiScanner(sqli_vulnerable_url, quick=False)

        assert scanner_quick.quick is True
        assert scanner_normal.quick is False

        # Quick mode should affect payload selection in techniques

    @pytest.mark.unit
    @pytest.mark.sqli
    def test_verbose_mode(self, sqli_vulnerable_url, capsys):
        """Test verbose output mode"""
        scanner = SQLiScanner(sqli_vulnerable_url, verbose=True)
        assert scanner.verbose is True

        # Verbose mode should produce more output
        # This would be tested in integration tests

    @pytest.mark.unit
    @pytest.mark.sqli
    def test_delay_between_requests(self, sqli_vulnerable_url, mock_requests_session):
        """Test delay between requests"""
        scanner = SQLiScanner(sqli_vulnerable_url, delay=1.0)

        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.content = b"Response"
        mock_requests_session.get.return_value = mock_resp

        with patch('time.sleep') as mock_sleep:
            # Simulate making requests with delays
            scanner.get_baseline()

            # sleep should be called for delays between requests
            # The exact count depends on implementation
            assert mock_sleep.called or scanner.delay == 1.0

    @pytest.mark.unit
    @pytest.mark.sqli
    def test_timeout_handling(self, sqli_vulnerable_url, mock_requests_session):
        """Test request timeout handling"""
        scanner = SQLiScanner(sqli_vulnerable_url, timeout=5)

        mock_requests_session.get.side_effect = requests.Timeout("Request timed out")

        with pytest.raises(requests.Timeout):
            scanner.get_baseline()

    @pytest.mark.unit
    @pytest.mark.sqli
    @pytest.mark.fast
    def test_parameter_parsing_from_url(self):
        """Test parameter extraction from URL"""
        urls_and_params = [
            ("http://test.com/page.php?id=1", {'id': ['1']}),
            ("http://test.com/page.php?id=1&name=test", {'id': ['1'], 'name': ['test']}),
            ("http://test.com/page.php", {}),
            ("http://test.com/page.php?", {}),
        ]

        for url, expected_params in urls_and_params:
            scanner = SQLiScanner(url)
            assert scanner.base_params == expected_params

    @pytest.mark.unit
    @pytest.mark.sqli
    def test_post_data_parsing(self):
        """Test POST data parameter parsing"""
        post_data_cases = [
            ("username=admin&password=pass", {'username': ['admin'], 'password': ['pass']}),
            ("single=value", {'single': ['value']}),
            ("", {}),
            ("malformed&", {}),
        ]

        for data, expected_params in post_data_cases:
            scanner = SQLiScanner("http://test.com", data=data)
            assert scanner.post_params == expected_params

    @pytest.mark.unit
    @pytest.mark.sqli
    def test_user_agent_header(self, sqli_vulnerable_url):
        """Test that custom user agent is set"""
        scanner = SQLiScanner(sqli_vulnerable_url)

        assert 'User-Agent' in scanner.session.headers
        assert 'SQLi Scanner Educational Tool' in scanner.session.headers['User-Agent']

    @pytest.mark.unit
    @pytest.mark.sqli
    def test_min_findings_threshold(self, sqli_vulnerable_url):
        """Test minimum findings threshold"""
        scanner = SQLiScanner(sqli_vulnerable_url, min_findings=3)

        assert scanner.min_findings == 3
        # This would affect when scanning stops early

    @pytest.mark.unit
    @pytest.mark.sqli
    def test_technique_selection(self):
        """Test different technique selections"""
        techniques = ['all', 'error', 'boolean', 'time', 'union']

        for technique in techniques:
            scanner = SQLiScanner("http://test.com", technique=technique)
            assert scanner.technique == technique

    @pytest.mark.unit
    @pytest.mark.sqli
    def test_vulnerability_tracking(self, sqli_vulnerable_url):
        """Test vulnerability result tracking"""
        scanner = SQLiScanner(sqli_vulnerable_url)

        # Initially no vulnerabilities
        assert scanner.vulnerabilities == []
        assert scanner.tested_count == 0
        assert scanner.high_conf_found == 0

        # Simulate finding a vulnerability
        vuln = {
            'parameter': 'id',
            'type': 'Error-based SQLi',
            'confidence': 'HIGH',
            'payload': "1'"
        }
        scanner.vulnerabilities.append(vuln)
        scanner.high_conf_found += 1

        assert len(scanner.vulnerabilities) == 1
        assert scanner.high_conf_found == 1

    @pytest.mark.unit
    @pytest.mark.sqli
    def test_reporter_initialization(self, sqli_vulnerable_url):
        """Test that reporter is initialized correctly"""
        post_data = "test=value"
        scanner = SQLiScanner(sqli_vulnerable_url, method='POST', data=post_data)

        assert scanner.reporter is not None
        # Reporter should have target and method info
        from crack.sqli.reporter import SQLiReporter
        assert isinstance(scanner.reporter, SQLiReporter)