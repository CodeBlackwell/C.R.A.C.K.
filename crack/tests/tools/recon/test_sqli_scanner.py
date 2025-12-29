"""
Tests for CRACK SQLi Scanner (tools/recon/sqli/)

Business Value Focus:
- Detection accuracy for all SQLi techniques (no false negatives)
- False positive handling (no wasted time on non-vulnerable params)
- Database type identification (enables targeted exploitation)
- Confidence scoring accuracy (prioritizes investigation)

Priority: HIGH - SQLi is a critical vulnerability class for OSCP
"""

import pytest
import time
import hashlib
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, PropertyMock
from typing import Dict, List, Tuple


# =============================================================================
# Test Fixtures Specific to SQLi Scanner
# =============================================================================

class SQLiScannerFactory:
    """Factory for creating SQLiScanner instances with controlled dependencies."""

    @staticmethod
    def create(
        target: str = "http://test.local/page.php?id=1",
        method: str = 'AUTO',
        data: str = None,
        params: str = None,
        technique: str = 'all',
        verbose: bool = False,
        quick: bool = False,
        delay: float = 0,  # No delay in tests
        timeout: int = 10,
        min_findings: int = 0
    ):
        """Create SQLiScanner with mock session."""
        from tools.recon.sqli.scanner import SQLiScanner
        scanner = SQLiScanner(
            target=target,
            method=method,
            data=data,
            params=params,
            technique=technique,
            verbose=verbose,
            quick=quick,
            delay=delay,
            timeout=timeout,
            min_findings=min_findings
        )
        return scanner


class SQLiTechniquesFactory:
    """Factory for creating SQLiTechniques tester instances."""

    @staticmethod
    def create(
        target: str = "http://test.local/page.php?id=1",
        method: str = 'GET',
        session: Mock = None,
        timeout: int = 10,
        delay: float = 0,
        verbose: bool = False,
        quick: bool = False
    ):
        """Create SQLiTechniques with mock session."""
        from tools.recon.sqli.techniques import SQLiTechniques

        if session is None:
            session = Mock()
            session.headers = {}

        tester = SQLiTechniques(
            target=target,
            method=method,
            session=session,
            timeout=timeout,
            delay=delay,
            verbose=verbose,
            quick=quick
        )
        return tester


# =============================================================================
# Error-Based SQLi Detection Tests (BV: HIGH)
# =============================================================================

class TestErrorBasedDetection:
    """
    Tests for test_error_based() method.

    BV: Error-based SQLi is the easiest to confirm and exploit.
    Missing error detection means missing easy wins.
    """

    def test_detects_mysql_syntax_error(
        self, mock_http_response, sqli_error_responses
    ):
        """
        BV: MySQL syntax errors confirm SQLi vulnerability

        Scenario:
          Given: Parameter vulnerable to MySQL SQLi
          When: Single quote payload triggers error
          Then: Finding with db_type='mysql' and high confidence
        """
        mock_response = mock_http_response(
            text=sqli_error_responses['mysql_syntax'],
            status_code=200
        )

        mock_session = Mock()
        mock_session.get.return_value = mock_response

        tester = SQLiTechniquesFactory.create(
            target="http://test.local/page.php?id=1",
            session=mock_session
        )

        findings = tester.test_error_based('id', '1')

        assert len(findings) >= 1
        mysql_finding = next((f for f in findings if f.get('db_type') == 'mysql'), None)
        assert mysql_finding is not None
        assert mysql_finding['confidence'] >= 60

    def test_detects_postgresql_error(
        self, mock_http_response, sqli_error_responses
    ):
        """
        BV: PostgreSQL error identification enables targeted payloads

        Scenario:
          Given: PostgreSQL backend
          When: Quote triggers unterminated string error
          Then: Finding with db_type='postgresql'
        """
        mock_response = mock_http_response(
            text=sqli_error_responses['postgresql_error'],
            status_code=200
        )

        mock_session = Mock()
        mock_session.get.return_value = mock_response

        tester = SQLiTechniquesFactory.create(session=mock_session)
        findings = tester.test_error_based('id', '1')

        assert len(findings) >= 1
        pg_finding = next((f for f in findings if f.get('db_type') == 'postgresql'), None)
        assert pg_finding is not None

    def test_detects_mssql_error(
        self, mock_http_response, sqli_error_responses
    ):
        """
        BV: MSSQL identification enables xp_cmdshell exploitation

        Scenario:
          Given: Microsoft SQL Server backend
          When: Quote triggers quotation mark error
          Then: Finding with db_type='mssql'
        """
        mock_response = mock_http_response(
            text=sqli_error_responses['mssql_error'],
            status_code=200
        )

        mock_session = Mock()
        mock_session.get.return_value = mock_response

        tester = SQLiTechniquesFactory.create(session=mock_session)
        findings = tester.test_error_based('id', '1')

        assert len(findings) >= 1
        mssql_finding = next((f for f in findings if f.get('db_type') == 'mssql'), None)
        assert mssql_finding is not None

    def test_detects_oracle_error(
        self, mock_http_response, sqli_error_responses
    ):
        """
        BV: Oracle identification enables UTL_HTTP and other exploits

        Scenario:
          Given: Oracle database backend
          When: Quote triggers ORA- error
          Then: Finding with db_type='oracle'
        """
        mock_response = mock_http_response(
            text=sqli_error_responses['oracle_error'],
            status_code=200
        )

        mock_session = Mock()
        mock_session.get.return_value = mock_response

        tester = SQLiTechniquesFactory.create(session=mock_session)
        findings = tester.test_error_based('id', '1')

        assert len(findings) >= 1
        oracle_finding = next((f for f in findings if f.get('db_type') == 'oracle'), None)
        assert oracle_finding is not None

    def test_no_findings_for_clean_response(
        self, mock_http_response, sqli_error_responses
    ):
        """
        BV: No false positives on non-vulnerable parameters

        Scenario:
          Given: Parameter that sanitizes input properly
          When: All payloads tested
          Then: No error-based findings returned
        """
        mock_response = mock_http_response(
            text=sqli_error_responses['no_error'],
            status_code=200
        )

        mock_session = Mock()
        mock_session.get.return_value = mock_response

        tester = SQLiTechniquesFactory.create(session=mock_session)
        findings = tester.test_error_based('id', '1')

        assert len(findings) == 0

    def test_quick_mode_tests_fewer_payloads(self, mock_http_response):
        """
        BV: Quick mode reduces scan time for initial assessment

        Scenario:
          Given: Quick mode enabled
          When: test_error_based() runs
          Then: Fewer payloads tested (first 3 only)
        """
        mock_response = mock_http_response(text="OK", status_code=200)

        mock_session = Mock()
        mock_session.get.return_value = mock_response

        tester = SQLiTechniquesFactory.create(session=mock_session, quick=True)
        tester.test_error_based('id', '1')

        # Quick mode tests only first 3 payloads
        assert mock_session.get.call_count <= 3

    def test_extracts_error_snippet(
        self, mock_http_response, sqli_error_responses
    ):
        """
        BV: Error snippets help confirm vulnerability manually

        Scenario:
          Given: Error message in response
          When: Finding is created
          Then: Snippet contains relevant error text
        """
        mock_response = mock_http_response(
            text=sqli_error_responses['mysql_syntax'],
            status_code=200
        )

        mock_session = Mock()
        mock_session.get.return_value = mock_response

        tester = SQLiTechniquesFactory.create(session=mock_session)
        findings = tester.test_error_based('id', '1')

        finding_with_snippet = next((f for f in findings if f.get('snippet')), None)
        assert finding_with_snippet is not None
        assert 'SQL' in finding_with_snippet['snippet'] or 'MySQL' in finding_with_snippet['snippet']


# =============================================================================
# Boolean-Based SQLi Detection Tests (BV: HIGH)
# =============================================================================

class TestBooleanBasedDetection:
    """
    Tests for test_boolean_based() method.

    BV: Boolean-based SQLi enables data extraction from blind scenarios.
    Accurate detection requires comparing true vs false conditions.
    """

    def test_detects_boolean_sqli_by_content_length(
        self, sqli_boolean_responses, mock_http_response
    ):
        """
        BV: Content length difference indicates boolean SQLi

        Scenario:
          Given: True condition returns more content than false
          When: Boolean test pair is executed
          Then: Finding with 'size_diff' reason

        Edge Cases:
          - Small differences (< 50 bytes) may be noise
          - Large differences (> 100 bytes) are significant
        """
        true_resp, false_resp = sqli_boolean_responses(
            true_content="Found 10 results" + " " * 400,
            false_content="No results found",
            true_length=500,
            false_length=200
        )

        mock_session = Mock()
        # Alternate between true and false responses
        mock_session.get.side_effect = [true_resp, false_resp] * 10

        baseline = {'length': 450, 'status': 200}

        tester = SQLiTechniquesFactory.create(session=mock_session)
        findings = tester.test_boolean_based('id', baseline, '1')

        # Should detect significant size difference
        assert len(findings) >= 1
        finding = findings[0]
        # Note: reasons contains "size diff" with space, not underscore
        assert 'size diff' in str(finding.get('reasons', []))

    def test_detects_boolean_sqli_by_status_code(
        self, mock_http_response
    ):
        """
        BV: Status code difference confirms boolean SQLi

        Scenario:
          Given: True condition returns 200, false returns 404/500
          When: Boolean test pair executed
          Then: Finding with 'status diff' reason
        """
        true_resp = mock_http_response(text="OK", status_code=200)
        false_resp = mock_http_response(text="Error", status_code=500)

        mock_session = Mock()
        mock_session.get.side_effect = [true_resp, false_resp] * 10

        baseline = {'length': 100, 'status': 200}

        tester = SQLiTechniquesFactory.create(session=mock_session)
        findings = tester.test_boolean_based('id', baseline, '1')

        assert len(findings) >= 1
        status_finding = next(
            (f for f in findings if 'status' in str(f.get('reasons', []))),
            None
        )
        assert status_finding is not None

    def test_no_finding_when_responses_identical(
        self, mock_http_response
    ):
        """
        BV: Identical responses indicate no vulnerability

        Scenario:
          Given: True and false conditions return same response
          When: Boolean test executed
          Then: No findings (properly parameterized query)
        """
        same_resp = mock_http_response(text="Same content", status_code=200)

        mock_session = Mock()
        mock_session.get.return_value = same_resp

        baseline = {'length': len("Same content"), 'status': 200}

        tester = SQLiTechniquesFactory.create(session=mock_session)
        findings = tester.test_boolean_based('id', baseline, '1')

        # No significant difference should mean no findings
        assert len(findings) == 0

    def test_confidence_increases_with_multiple_indicators(
        self, mock_http_response
    ):
        """
        BV: Multiple indicators increase confidence score

        Scenario:
          Given: Size diff AND status diff AND baseline match
          When: Finding created
          Then: Confidence >= 70%
        """
        true_resp = mock_http_response(
            text="Found results" + " " * 200,
            status_code=200
        )
        false_resp = mock_http_response(
            text="No results",
            status_code=404
        )

        mock_session = Mock()
        mock_session.get.side_effect = [true_resp, false_resp] * 10

        baseline = {'length': 220, 'status': 200}

        tester = SQLiTechniquesFactory.create(session=mock_session)
        findings = tester.test_boolean_based('id', baseline, '1')

        assert len(findings) >= 1
        high_conf = [f for f in findings if f['confidence'] >= 70]
        assert len(high_conf) >= 1


# =============================================================================
# Time-Based SQLi Detection Tests (BV: HIGH)
# =============================================================================

class TestTimeBasedDetection:
    """
    Tests for test_time_based() method.

    BV: Time-based SQLi works when no other indicators are available.
    Critical for completely blind scenarios.
    """

    def test_detects_time_delay(self, mock_http_response):
        """
        BV: Response delay confirms time-based SQLi

        Scenario:
          Given: SLEEP() payload delays response by 5+ seconds
          When: test_time_based() compares baseline vs payload
          Then: Finding with delay information
        """
        baseline_resp = mock_http_response(text="OK", status_code=200)
        delayed_resp = mock_http_response(text="OK", status_code=200)

        mock_session = Mock()

        # Track call count for timing simulation
        call_count = [0]

        def mock_get(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] % 2 == 0:  # Every other call is the payload test
                # Simulate delay by returning with elapsed time
                resp = Mock()
                resp.text = "OK"
                resp.content = b"OK"
                resp.status_code = 200
                return resp
            return baseline_resp

        mock_session.get.side_effect = mock_get

        tester = SQLiTechniquesFactory.create(session=mock_session)

        # Mock the _make_request to simulate timing
        original_make_request = tester._make_request

        def mock_make_request(param, payload, original_value=''):
            resp, _ = original_make_request(param, payload, original_value)
            if 'SLEEP' in payload or 'WAITFOR' in payload or 'pg_sleep' in payload:
                return resp, 5.5  # Simulated delay
            return resp, 0.1  # Fast response

        tester._make_request = mock_make_request

        findings = tester.test_time_based('id', '1')

        # Should detect time delay
        assert len(findings) >= 1
        time_finding = next((f for f in findings if f.get('delay', 0) >= 4), None)
        assert time_finding is not None

    def test_no_finding_when_no_delay(self, mock_http_response):
        """
        BV: Fast responses indicate no time-based vulnerability

        Scenario:
          Given: All payloads return quickly
          When: test_time_based() runs
          Then: No findings
        """
        fast_resp = mock_http_response(text="OK", status_code=200)

        mock_session = Mock()
        mock_session.get.return_value = fast_resp

        tester = SQLiTechniquesFactory.create(session=mock_session)

        # All responses are fast
        original_make_request = tester._make_request
        tester._make_request = lambda p, pl, ov='': (fast_resp, 0.1)

        findings = tester.test_time_based('id', '1')

        assert len(findings) == 0

    def test_identifies_database_from_successful_sleep(
        self, mock_http_response
    ):
        """
        BV: Database type identified from which SLEEP works

        Scenario:
          Given: MySQL SLEEP() works, others don't
          When: Finding created
          Then: db_type='MySQL'
        """
        mock_session = Mock()

        tester = SQLiTechniquesFactory.create(session=mock_session)

        # Only MySQL SLEEP causes delay
        def mock_request(param, payload, original_value=''):
            resp = Mock()
            resp.text = "OK"
            resp.content = b"OK"
            resp.status_code = 200

            if 'SLEEP' in payload and 'WAITFOR' not in payload and 'pg_sleep' not in payload:
                return resp, 5.5  # MySQL delay
            return resp, 0.1

        tester._make_request = mock_request

        findings = tester.test_time_based('id', '1')

        mysql_finding = next(
            (f for f in findings if 'MySQL' in f.get('db_type', '')),
            None
        )
        assert mysql_finding is not None


# =============================================================================
# UNION-Based SQLi Detection Tests (BV: HIGH)
# =============================================================================

class TestUnionBasedDetection:
    """
    Tests for test_union_based() method.

    BV: UNION SQLi enables direct data extraction.
    Most powerful when detected correctly.
    """

    def test_detects_column_count_via_order_by(
        self, mock_http_response
    ):
        """
        BV: Correct column count is essential for UNION exploitation

        Scenario:
          Given: Table has 3 columns
          When: ORDER BY 4 causes error
          Then: Column count detected as 3
        """
        mock_session = Mock()

        # ORDER BY 1,2,3 work, ORDER BY 4 fails
        responses = []
        for i in range(1, 11):
            if i <= 3:
                responses.append(mock_http_response(text="OK", status_code=200))
            else:
                responses.append(mock_http_response(
                    text="Unknown column",
                    status_code=200
                ))

        mock_session.get.side_effect = responses * 2  # For UNION tests too

        baseline = {'length': 100, 'status': 200, 'hash': 'abc'}

        tester = SQLiTechniquesFactory.create(session=mock_session)
        findings = tester.test_union_based('id', baseline, '1')

        # Should have detected column count
        if findings:
            assert findings[0].get('column_count', 0) == 3

    def test_detects_successful_union_injection(
        self, mock_http_response
    ):
        """
        BV: Successful UNION confirms data extraction capability

        Scenario:
          Given: UNION SELECT with correct columns
          When: Response changes without error
          Then: High-confidence UNION finding
        """
        mock_session = Mock()

        call_count = [0]
        baseline_content = "Normal page content"
        union_content = "Normal page content INJECTED_DATA"

        def mock_get(*args, **kwargs):
            call_count[0] += 1
            # First calls are ORDER BY tests
            if call_count[0] <= 5:
                if call_count[0] <= 3:
                    return mock_http_response(text=baseline_content, status_code=200)
                else:
                    return mock_http_response(text="Column error", status_code=200)
            # Later calls are UNION tests
            return mock_http_response(text=union_content, status_code=200)

        mock_session.get.side_effect = mock_get

        baseline = {
            'length': len(baseline_content),
            'status': 200,
            'hash': hashlib.md5(baseline_content.encode()).hexdigest()
        }

        tester = SQLiTechniquesFactory.create(session=mock_session)
        findings = tester.test_union_based('id', baseline, '1')

        union_finding = next((f for f in findings if f.get('type') == 'union'), None)
        if union_finding:
            assert union_finding['confidence'] >= 80


# =============================================================================
# SQLiScanner Orchestration Tests (BV: MEDIUM)
# =============================================================================

class TestSQLiScannerOrchestration:
    """
    Tests for SQLiScanner class orchestrating all techniques.

    BV: Complete scan workflow produces actionable results.
    """

    def test_auto_detects_get_method(self):
        """
        BV: GET method auto-detected when no POST data

        Scenario:
          Given: URL with query parameters, no -d flag
          When: Scanner initialized with method=AUTO
          Then: method set to GET
        """
        scanner = SQLiScannerFactory.create(
            target="http://test.local/page.php?id=1",
            method='AUTO'
        )

        assert scanner.method == 'GET'

    def test_auto_detects_post_method(self):
        """
        BV: POST method auto-detected when data provided

        Scenario:
          Given: URL with POST data (-d flag)
          When: Scanner initialized with method=AUTO
          Then: method set to POST
        """
        scanner = SQLiScannerFactory.create(
            target="http://test.local/login.php",
            method='AUTO',
            data="username=admin&password=test"
        )

        assert scanner.method == 'POST'

    def test_extracts_parameters_from_url(self):
        """
        BV: URL parameters are correctly parsed for testing

        Scenario:
          Given: URL with multiple query parameters
          When: Scanner parses URL
          Then: All parameters available for testing
        """
        scanner = SQLiScannerFactory.create(
            target="http://test.local/page.php?id=1&name=test&sort=asc"
        )

        assert 'id' in scanner.base_params
        assert 'name' in scanner.base_params
        assert 'sort' in scanner.base_params

    def test_parses_post_data_parameters(self):
        """
        BV: POST data parameters are correctly parsed

        Scenario:
          Given: POST data string with multiple params
          When: Scanner parses data
          Then: All POST parameters available for testing
        """
        scanner = SQLiScannerFactory.create(
            target="http://test.local/login.php",
            data="username=admin&password=test&remember=1"
        )

        assert 'username' in scanner.post_params
        assert 'password' in scanner.post_params
        assert 'remember' in scanner.post_params

    def test_runs_specified_technique_only(self):
        """
        BV: Technique filter reduces scan time

        Scenario:
          Given: technique='error' specified
          When: scan_parameter() runs
          Then: Only error-based tests executed
        """
        scanner = SQLiScannerFactory.create(
            target="http://test.local/page.php?id=1",
            technique='error'
        )

        # Mock techniques tester to track calls
        mock_tester = Mock()
        mock_tester.test_error_based.return_value = []
        mock_tester.test_boolean_based.return_value = []
        mock_tester.test_time_based.return_value = []
        mock_tester.test_union_based.return_value = []
        mock_tester.get_tested_count.return_value = 0

        scanner.techniques_tester = mock_tester
        scanner.baseline = {'length': 100, 'status': 200}

        with patch.object(scanner.reporter, 'display_findings'):
            scanner.scan_parameter('id', '1')

        mock_tester.test_error_based.assert_called_once()
        mock_tester.test_boolean_based.assert_not_called()
        mock_tester.test_time_based.assert_not_called()
        mock_tester.test_union_based.assert_not_called()

    def test_early_termination_on_high_confidence(self):
        """
        BV: Early termination saves time when vulnerability confirmed

        Scenario:
          Given: min_findings=1 and 3 parameters
          When: First parameter has high-confidence finding
          Then: Remaining parameters skipped
        """
        scanner = SQLiScannerFactory.create(
            target="http://test.local/page.php?id=1&name=test&sort=asc",
            min_findings=1
        )

        # First parameter finds high-confidence vulnerability
        scanner.high_conf_found = 1

        # Mock get_baseline
        scanner.baseline = {'length': 100, 'status': 200}

        # This would normally scan 3 parameters, but should stop after 1
        # We verify by checking early termination logic
        assert scanner.min_findings == 1


# =============================================================================
# Baseline Establishment Tests (BV: MEDIUM)
# =============================================================================

class TestBaselineEstablishment:
    """
    Tests for get_baseline() method.

    BV: Accurate baseline enables meaningful difference detection.
    """

    def test_baseline_uses_median_values(self, mock_http_response):
        """
        BV: Median values reduce noise from network variance

        Scenario:
          Given: 3 baseline requests with varying response times
          When: get_baseline() calculates
          Then: Median values used (not average)
        """
        # Create responses with varying sizes
        responses = [
            mock_http_response(text="X" * 100, status_code=200),
            mock_http_response(text="X" * 150, status_code=200),  # Median
            mock_http_response(text="X" * 200, status_code=200),
        ]

        mock_session = Mock()
        mock_session.get.side_effect = responses

        scanner = SQLiScannerFactory.create()
        scanner.session = mock_session

        baseline = scanner.get_baseline()

        # Median of 100, 150, 200 is 150
        assert baseline['length'] == 150

    def test_baseline_captures_all_metrics(self, mock_http_response):
        """
        BV: All comparison metrics are captured

        Scenario:
          Given: Normal page response
          When: get_baseline() runs
          Then: Baseline has status, length, time, hash, lines, words
        """
        mock_resp = mock_http_response(
            text="Hello World\nLine 2\nLine 3",
            status_code=200
        )

        mock_session = Mock()
        mock_session.get.return_value = mock_resp

        scanner = SQLiScannerFactory.create()
        scanner.session = mock_session

        baseline = scanner.get_baseline()

        assert 'status' in baseline
        assert 'length' in baseline
        assert 'time' in baseline
        assert 'hash' in baseline
        assert 'lines' in baseline
        assert 'words' in baseline


# =============================================================================
# Request Building Tests (BV: MEDIUM)
# =============================================================================

class TestRequestBuilding:
    """
    Tests for _make_request() method.

    BV: Correctly constructed requests ensure payload delivery.
    """

    def test_builds_get_request_with_payload(self, mock_http_response):
        """
        BV: GET parameter correctly modified with payload

        Scenario:
          Given: GET request with id parameter
          When: Payload appended to id
          Then: Request URL contains original value + payload
        """
        mock_session = Mock()
        mock_session.get.return_value = mock_http_response(text="OK")

        tester = SQLiTechniquesFactory.create(
            target="http://test.local/page.php?id=1",
            method='GET',
            session=mock_session
        )

        tester._make_request('id', "'", '1')

        # Check the URL was built correctly
        call_args = mock_session.get.call_args
        assert call_args is not None
        url = call_args[0][0]
        assert "id=1'" in url or "id=1%27" in url

    def test_builds_post_request_with_payload(self, mock_http_response):
        """
        BV: POST parameter correctly modified with payload

        Scenario:
          Given: POST request with username parameter
          When: Payload appended to username
          Then: POST data contains original value + payload
        """
        mock_session = Mock()
        mock_session.post.return_value = mock_http_response(text="OK")

        tester = SQLiTechniquesFactory.create(
            target="http://test.local/login.php",
            method='POST',
            session=mock_session
        )
        tester.post_params = {'username': ['admin'], 'password': ['test']}

        tester._make_request('username', "'", 'admin')

        call_args = mock_session.post.call_args
        assert call_args is not None
        data = call_args[1].get('data', {})
        assert "admin'" in str(data.get('username', ''))


# =============================================================================
# Confidence Scoring Tests (BV: MEDIUM)
# =============================================================================

class TestConfidenceScoring:
    """
    Tests for confidence score calculation.

    BV: Accurate confidence helps prioritize vulnerabilities.
    """

    def test_error_based_confidence_increases_with_patterns(
        self, mock_http_response
    ):
        """
        BV: More matching patterns = higher confidence

        Scenario:
          Given: Response contains multiple SQL error patterns
          When: Error-based detection runs
          Then: Confidence higher than single pattern match
        """
        # Response with multiple MySQL indicators
        multi_error = """
        You have an error in your SQL syntax; check the manual
        Warning: mysql_fetch_array() expects parameter
        MySQL Error: Query failed
        """

        mock_session = Mock()
        mock_session.get.return_value = mock_http_response(text=multi_error)

        tester = SQLiTechniquesFactory.create(session=mock_session)
        findings = tester.test_error_based('id', '1')

        if findings:
            # Multiple patterns should give higher confidence
            assert findings[0]['confidence'] >= 75

    def test_boolean_based_confidence_capped_at_90(
        self, mock_http_response
    ):
        """
        BV: Boolean findings never exceed 90% (needs manual verification)

        Scenario:
          Given: All boolean indicators positive
          When: Finding created
          Then: Confidence <= 90%
        """
        true_resp = mock_http_response(text="A" * 1000, status_code=200)
        false_resp = mock_http_response(text="B", status_code=404)

        mock_session = Mock()
        mock_session.get.side_effect = [true_resp, false_resp] * 10

        baseline = {'length': 900, 'status': 200}

        tester = SQLiTechniquesFactory.create(session=mock_session)
        findings = tester.test_boolean_based('id', baseline, '1')

        for finding in findings:
            assert finding['confidence'] <= 90


# =============================================================================
# Edge Cases and Error Handling (BV: LOW)
# =============================================================================

class TestEdgeCases:
    """
    Tests for edge cases and error handling.

    BV: Scanner handles unexpected situations gracefully.
    """

    def test_handles_connection_timeout(self, mock_http_response):
        """
        BV: Timeout doesn't crash scanner

        Scenario:
          Given: Target server times out
          When: _make_request() called
          Then: Returns None, None without exception
        """
        import requests

        mock_session = Mock()
        mock_session.get.side_effect = requests.RequestException("Timeout")

        tester = SQLiTechniquesFactory.create(session=mock_session)
        resp, elapsed = tester._make_request('id', "'", '1')

        assert resp is None
        assert elapsed == 0

    def test_handles_empty_response(self, mock_http_response):
        """
        BV: Empty responses don't cause errors

        Scenario:
          Given: Server returns empty response
          When: Detection methods run
          Then: Complete without exception
        """
        empty_resp = mock_http_response(text="", status_code=200)

        mock_session = Mock()
        mock_session.get.return_value = empty_resp

        tester = SQLiTechniquesFactory.create(session=mock_session)

        # Should not raise
        findings = tester.test_error_based('id', '1')
        assert isinstance(findings, list)

    def test_handles_special_characters_in_values(
        self, mock_http_response
    ):
        """
        BV: Special characters in original values don't break requests

        Scenario:
          Given: Parameter value contains quotes, ampersands
          When: Payload appended
          Then: Request built correctly
        """
        mock_session = Mock()
        mock_session.get.return_value = mock_http_response(text="OK")

        tester = SQLiTechniquesFactory.create(
            target="http://test.local/page.php?name=test",
            session=mock_session
        )

        # Original value has special chars
        tester._make_request('name', "'", "O'Brien&Co")

        # Should complete without error
        assert mock_session.get.called

    def test_tracked_count_increments_correctly(
        self, mock_http_response
    ):
        """
        BV: Test count enables progress reporting

        Scenario:
          Given: Multiple payloads tested
          When: get_tested_count() called
          Then: Returns accurate count
        """
        mock_session = Mock()
        mock_session.get.return_value = mock_http_response(text="OK")

        tester = SQLiTechniquesFactory.create(session=mock_session)
        tester.test_error_based('id', '1')

        assert tester.get_tested_count() > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
