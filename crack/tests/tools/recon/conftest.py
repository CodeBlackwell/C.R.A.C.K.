"""
Shared fixtures for recon scanner tests.

Business Value Focus:
- Isolated subprocess mocking for port scanner tests
- HTTP response mocking for web and SQLi scanners
- Sample output fixtures for parsing accuracy tests
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from pathlib import Path
import tempfile
from typing import Dict, Any, List, Optional


# =============================================================================
# Sample Nmap Output Fixtures
# =============================================================================

NMAP_GNMAP_SAMPLE_WITH_PORTS = """# Nmap 7.94 scan initiated Sat Dec 21 10:00:00 2024
Host: 192.168.1.100 () Status: Up
Host: 192.168.1.100 () Ports: 22/open/tcp//ssh//OpenSSH 8.2p1/, 80/open/tcp//http//Apache httpd 2.4.41/, 443/open/tcp//ssl|https//nginx 1.18.0/
# Nmap done at Sat Dec 21 10:00:30 2024 -- 1 IP address (1 host up)
"""

NMAP_GNMAP_NO_PORTS = """# Nmap 7.94 scan initiated Sat Dec 21 10:00:00 2024
Host: 192.168.1.100 () Status: Up
Host: 192.168.1.100 () Ports:
# Nmap done at Sat Dec 21 10:00:30 2024 -- 1 IP address (1 host up)
"""

NMAP_GNMAP_MANY_PORTS = """# Nmap 7.94 scan initiated Sat Dec 21 10:00:00 2024
Host: 192.168.1.100 () Status: Up
Host: 192.168.1.100 () Ports: 21/open/tcp//ftp//vsftpd 3.0.3/, 22/open/tcp//ssh//OpenSSH 8.2p1/, 25/open/tcp//smtp//Postfix smtpd/, 80/open/tcp//http//Apache httpd 2.4.41/, 110/open/tcp//pop3//Dovecot pop3d/, 139/open/tcp//netbios-ssn//Samba smbd 4.6.2/, 143/open/tcp//imap//Dovecot imapd/, 443/open/tcp//ssl|https//nginx 1.18.0/, 445/open/tcp//microsoft-ds//Samba smbd 4.6.2/, 993/open/tcp//ssl|imaps//Dovecot imapd/, 995/open/tcp//ssl|pop3s//Dovecot pop3d/, 3306/open/tcp//mysql//MySQL 5.7.32/, 5432/open/tcp//postgresql//PostgreSQL DB 13.1/, 8080/open/tcp//http-proxy//Squid http proxy 4.13/, 8443/open/tcp//ssl|https-alt//Apache Tomcat/
# Nmap done at Sat Dec 21 10:01:00 2024 -- 1 IP address (1 host up)
"""

NMAP_SERVICE_SCAN_OUTPUT = """# Nmap 7.94 scan initiated Sat Dec 21 10:01:00 2024
Nmap scan report for 192.168.1.100
Host is up (0.0015s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3
80/tcp  open  http     Apache httpd 2.4.41 ((Ubuntu))
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
3306/tcp open mysql    MySQL 5.7.32-0ubuntu0.18.04.1

Service detection performed.
# Nmap done at Sat Dec 21 10:03:00 2024 -- 1 IP address (1 host up)
"""


# =============================================================================
# Sample HTML Fixtures for Web Scanner
# =============================================================================

HTML_FORM_LOGIN = """<!DOCTYPE html>
<html>
<head><title>Login Page</title></head>
<body>
<form action="/login" method="POST" id="loginForm">
    <input type="hidden" name="csrf_token" value="abc123xyz789">
    <input type="text" name="username" id="user">
    <input type="password" name="password" id="pass">
    <input type="submit" value="Login">
</form>
</body>
</html>
"""

HTML_FORM_ASPNET = """<!DOCTYPE html>
<html>
<head><title>ASP.NET Form</title></head>
<body>
<form action="/Default.aspx" method="POST">
    <input type="hidden" name="__VIEWSTATE" value="dDwtMTc0MjI2ODMxO3Q8O2w8aTwxPjs+O2w8dDw7bDxpPDA+O2k8MT47aTwyPjs+">
    <input type="hidden" name="__VIEWSTATEGENERATOR" value="CA0B0334">
    <input type="hidden" name="__EVENTVALIDATION" value="abc123">
    <input type="text" name="txtUsername">
    <input type="password" name="txtPassword">
    <input type="submit" name="btnLogin" value="Login">
</form>
</body>
</html>
"""

HTML_FORM_MULTIPART = """<!DOCTYPE html>
<html>
<head><title>Upload Form</title></head>
<body>
<form action="/upload" method="POST" enctype="multipart/form-data">
    <input type="hidden" name="_token" value="secret_token_value">
    <input type="text" name="title">
    <textarea name="description"></textarea>
    <input type="file" name="document">
    <select name="category">
        <option value="reports">Reports</option>
        <option value="images" selected>Images</option>
    </select>
    <input type="submit" value="Upload">
</form>
</body>
</html>
"""

HTML_WITH_COMMENTS = """<!DOCTYPE html>
<html>
<head><title>Page with Comments</title></head>
<body>
<!-- TODO: Fix SQL injection in search -->
<!-- DEBUG: admin credentials temp password: admin123 -->
<form action="/search" method="GET">
    <input type="text" name="q">
    <input type="submit" value="Search">
</form>
<script>
// API endpoint for user data
var apiUrl = '/api/users/search';
// TODO: Remove this debug endpoint
var debugUrl = '/api/debug/info';
/*
  Multi-line comment
  Contains sensitive info: backup at /backups/db.sql
*/
</script>
</body>
</html>
"""

HTML_NO_FORMS = """<!DOCTYPE html>
<html>
<head><title>Static Page</title></head>
<body>
<h1>Welcome</h1>
<p>No forms here.</p>
<a href="/about">About</a>
<a href="/contact">Contact</a>
</body>
</html>
"""

HTML_MULTIPLE_FORMS = """<!DOCTYPE html>
<html>
<head><title>Multiple Forms</title></head>
<body>
<form action="/search" method="GET" id="searchForm">
    <input type="text" name="q" placeholder="Search">
    <input type="submit" value="Search">
</form>
<form action="/newsletter" method="POST" id="newsletterForm">
    <input type="email" name="email">
    <input type="submit" value="Subscribe">
</form>
<form action="/feedback" method="POST" id="feedbackForm">
    <input type="hidden" name="csrf" value="token123">
    <input type="text" name="name">
    <textarea name="message"></textarea>
    <input type="submit" value="Send">
</form>
</body>
</html>
"""


# =============================================================================
# Pytest Fixtures
# =============================================================================

@pytest.fixture
def nmap_gnmap_file(tmp_path: Path) -> Path:
    """
    Create a temporary gnmap file with port discovery output.

    BV: Tests can parse realistic nmap greppable output.
    """
    gnmap_file = tmp_path / "ports_discovery.gnmap"
    gnmap_file.write_text(NMAP_GNMAP_SAMPLE_WITH_PORTS)
    return gnmap_file


@pytest.fixture
def nmap_gnmap_empty_file(tmp_path: Path) -> Path:
    """
    Create a temporary gnmap file with no open ports.

    BV: Scanner handles target with no open ports gracefully.
    """
    gnmap_file = tmp_path / "ports_discovery.gnmap"
    gnmap_file.write_text(NMAP_GNMAP_NO_PORTS)
    return gnmap_file


@pytest.fixture
def nmap_service_file(tmp_path: Path) -> Path:
    """
    Create a temporary nmap service scan output file.

    BV: Service parsing extracts version information correctly.
    """
    nmap_file = tmp_path / "service_scan.nmap"
    nmap_file.write_text(NMAP_SERVICE_SCAN_OUTPUT)
    return nmap_file


@pytest.fixture
def mock_subprocess_run():
    """
    Factory fixture for mocking subprocess.run with configurable output.

    BV: Port scanner tests don't require actual nmap execution.
    """
    def _factory(
        stdout: str = "",
        stderr: str = "",
        returncode: int = 0,
        timeout: bool = False
    ):
        mock = Mock()
        if timeout:
            import subprocess
            mock.side_effect = subprocess.TimeoutExpired("nmap", 120)
        else:
            mock.return_value = Mock(
                stdout=stdout,
                stderr=stderr,
                returncode=returncode
            )
        return mock

    return _factory


@pytest.fixture
def mock_http_response():
    """
    Factory fixture for creating mock HTTP responses.

    BV: Web scanner tests don't require network access.
    """
    def _factory(
        text: str = "",
        status_code: int = 200,
        headers: Dict[str, str] = None,
        elapsed_seconds: float = 0.1
    ):
        mock = Mock()
        mock.text = text
        mock.content = text.encode('utf-8')
        mock.status_code = status_code
        mock.headers = headers or {'Content-Type': 'text/html'}
        mock.elapsed = Mock()
        mock.elapsed.total_seconds.return_value = elapsed_seconds
        mock.raise_for_status = Mock()
        return mock

    return _factory


@pytest.fixture
def mock_requests_session(mock_http_response):
    """
    Mock requests.Session with configurable responses.

    BV: SQLi scanner tests are isolated from network.
    """
    def _factory(responses: List[Mock] = None, default_response: Mock = None):
        session = Mock()
        if responses:
            session.get.side_effect = responses
            session.post.side_effect = responses
        elif default_response:
            session.get.return_value = default_response
            session.post.return_value = default_response
        else:
            # Create a default response
            default = mock_http_response(text="OK", status_code=200)
            session.get.return_value = default
            session.post.return_value = default

        session.headers = {}
        return session

    return _factory


@pytest.fixture
def sample_form_html():
    """
    Provides sample HTML content for form extraction tests.

    BV: Consistent HTML fixtures across all web scanner tests.
    """
    return {
        'login': HTML_FORM_LOGIN,
        'aspnet': HTML_FORM_ASPNET,
        'multipart': HTML_FORM_MULTIPART,
        'comments': HTML_WITH_COMMENTS,
        'no_forms': HTML_NO_FORMS,
        'multiple': HTML_MULTIPLE_FORMS,
    }


@pytest.fixture
def sample_nmap_outputs():
    """
    Provides sample nmap output strings for parsing tests.

    BV: Consistent nmap output fixtures across all port scanner tests.
    """
    return {
        'gnmap_with_ports': NMAP_GNMAP_SAMPLE_WITH_PORTS,
        'gnmap_no_ports': NMAP_GNMAP_NO_PORTS,
        'gnmap_many_ports': NMAP_GNMAP_MANY_PORTS,
        'service_scan': NMAP_SERVICE_SCAN_OUTPUT,
    }


# =============================================================================
# SQLi-Specific Fixtures
# =============================================================================

SQLI_ERROR_RESPONSES = {
    'mysql_syntax': """<html><body>
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version
</body></html>""",

    'mysql_warning': """<html><body>
Warning: mysql_fetch_array() expects parameter 1 to be resource
</body></html>""",

    'postgresql_error': """<html><body>
ERROR:  unterminated quoted string at or near "'"
</body></html>""",

    'mssql_error': """<html><body>
Unclosed quotation mark after the character string ''
Microsoft OLE DB Provider for SQL Server
</body></html>""",

    'oracle_error': """<html><body>
ORA-01756: quoted string not properly terminated
</body></html>""",

    'generic_error': """<html><body>
Database error: syntax error in query
</body></html>""",

    'no_error': """<html><body>
<h1>Welcome</h1>
<p>Search results for: test</p>
</body></html>""",
}


@pytest.fixture
def sqli_error_responses():
    """
    Sample SQL error responses for error-based SQLi detection tests.

    BV: Tests cover all major database error message patterns.
    """
    return SQLI_ERROR_RESPONSES


@pytest.fixture
def sqli_boolean_responses(mock_http_response):
    """
    Factory for boolean-based SQLi test responses.

    BV: Boolean detection tests have predictable true/false pairs.
    """
    def _factory(
        true_content: str = "Found 1 result",
        false_content: str = "No results found",
        true_length: int = 500,
        false_length: int = 200
    ):
        true_resp = mock_http_response(
            text=true_content + " " * (true_length - len(true_content)),
            status_code=200
        )
        false_resp = mock_http_response(
            text=false_content + " " * (false_length - len(false_content)),
            status_code=200
        )
        return true_resp, false_resp

    return _factory
