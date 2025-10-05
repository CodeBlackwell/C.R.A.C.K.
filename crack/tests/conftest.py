#!/usr/bin/env python3
"""
Shared fixtures and configuration for CRACK library tests
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch
import subprocess
import requests


# ============================================================================
# FILE SYSTEM FIXTURES
# ============================================================================

@pytest.fixture
def temp_output_dir():
    """Create a temporary directory for test outputs"""
    temp_dir = tempfile.mkdtemp(prefix="crack_test_")
    yield Path(temp_dir)
    # Cleanup after test
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def sample_files_dir():
    """Get the path to test fixture files"""
    return Path(__file__).parent / "fixtures"


# ============================================================================
# NMAP OUTPUT FIXTURES
# ============================================================================

@pytest.fixture
def nmap_greppable_output():
    """Sample nmap greppable output with open ports"""
    return """# Nmap 7.94 scan initiated Mon Oct 1 10:00:00 2024 as: nmap -p- --min-rate=5000 -oG ports.gnmap 192.168.45.100
Host: 192.168.45.100 ()	Status: Up
Host: 192.168.45.100 ()	Ports: 22/open/tcp//ssh///, 80/open/tcp//http///, 443/open/tcp//https///, 3306/open/tcp//mysql///, 8080/open/tcp//http-proxy///
# Nmap done at Mon Oct 1 10:00:30 2024 -- 1 IP address (1 host up) scanned in 30.00 seconds"""


@pytest.fixture
def nmap_service_output():
    """Sample nmap service detection output"""
    return """Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.45.100
Host is up (0.050s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http        Apache httpd 2.4.52 ((Ubuntu))
443/tcp  open  ssl/http    Apache httpd 2.4.52 ((Ubuntu))
3306/tcp open  mysql       MySQL 8.0.35
8080/tcp open  http        Apache Tomcat 9.0.82

Service detection performed.
Nmap done: 1 IP address (1 host up) scanned in 10.50 seconds"""


@pytest.fixture
def nmap_no_ports_output():
    """Sample nmap output with no open ports"""
    return """# Nmap 7.94 scan initiated Mon Oct 1 10:00:00 2024
Host: 192.168.45.100 ()	Status: Up
Host: 192.168.45.100 ()	Ports:
# Nmap done at Mon Oct 1 10:00:30 2024 -- 1 IP address (1 host up) scanned"""


# ============================================================================
# SEARCHSPLOIT OUTPUT FIXTURES
# ============================================================================

@pytest.fixture
def searchsploit_output():
    """Sample searchsploit output with exploits"""
    return """-------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                            |  Path
-------------------------------------------------------------------------- ---------------------------------
Apache 2.4.49/2.4.50 - Path Traversal & Remote Code Execution            | linux/webapps/50383.sh
Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution       | multiple/webapps/50512.py
Apache HTTP Server 2.4.50 - Remote Code Execution                        | linux/webapps/50539.sh
MySQL 8.0 - Authentication Bypass                                        | multiple/local/49765.txt
-------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results"""


@pytest.fixture
def searchsploit_no_results():
    """Sample searchsploit output with no results"""
    return """-------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                            |  Path
-------------------------------------------------------------------------- ---------------------------------
-------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results"""


# ============================================================================
# HTML CONTENT FIXTURES
# ============================================================================

@pytest.fixture
def sample_html_with_forms():
    """HTML content with various form types for testing"""
    return """<!DOCTYPE html>
<html>
<head><title>Test Page</title></head>
<body>
    <!-- Login form with password field -->
    <form action="/login.php" method="POST">
        <input type="text" name="username" value="">
        <input type="password" name="password">
        <input type="hidden" name="csrf_token" value="abc123def456">
        <input type="submit" value="Login">
    </form>

    <!-- File upload form -->
    <form action="/upload.php" method="POST" enctype="multipart/form-data">
        <input type="file" name="upload_file">
        <input type="submit" value="Upload">
    </form>

    <!-- Search form -->
    <form action="/search.php" method="GET">
        <input type="text" name="q" placeholder="Search...">
        <select name="category">
            <option value="all">All</option>
            <option value="products">Products</option>
        </select>
        <input type="submit" value="Search">
    </form>

    <!-- AJAX endpoints in JavaScript -->
    <script>
        var apiEndpoint = '/api/v1/users';
        fetch('/ajax/data.json');
        $.ajax({url: '/ajax/validate.php'});
    </script>

    <!-- HTML comments -->
    <!-- TODO: Fix SQL injection in search.php -->
    <!-- DEBUG: admin password is admin123 -->

    <!-- Links -->
    <a href="/admin.php">Admin Panel</a>
    <a href="http://external.com">External Link</a>
</body>
</html>"""


@pytest.fixture
def sample_html_minimal():
    """Minimal HTML for edge case testing"""
    return """<!DOCTYPE html>
<html>
<head><title>Minimal</title></head>
<body>
    <p>Simple page with no forms</p>
</body>
</html>"""


# ============================================================================
# CURL COMMAND FIXTURES
# ============================================================================

@pytest.fixture
def burp_curl_command():
    """Sample curl command exported from Burp Suite with common issues"""
    return """curl -i -s -k -X `POST` \
    -H `Host: 192.168.45.100` \
    -H `Content-Type: application/x-www-form-urlencoded` \
    -H `Content-Length: 50` \
    --data-binary `username=admin&password=password123` \
    `http://192.168.45.100/login.php`"""


@pytest.fixture
def clean_curl_command():
    """Clean curl command for comparison"""
    return """curl -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data 'username=admin&password=password123' \
    http://192.168.45.100/login.php"""


# ============================================================================
# MOCK FIXTURES FOR EXTERNAL COMMANDS
# ============================================================================

@pytest.fixture
def mock_subprocess_run(monkeypatch):
    """Mock subprocess.run for nmap and searchsploit commands"""
    def mock_run(cmd, **kwargs):
        result = Mock(spec=subprocess.CompletedProcess)
        result.returncode = 0
        result.stdout = ""
        result.stderr = ""

        # Determine what command is being run
        if 'nmap' in cmd:
            if '-p-' in cmd:  # Stage 1 fast discovery
                result.stdout = """Host: 192.168.45.100 ()	Ports: 22/open/tcp//ssh///, 80/open/tcp//http///"""
            elif '-sV' in cmd:  # Stage 2 service detection
                result.stdout = """22/tcp   open  ssh         OpenSSH 8.9p1
80/tcp   open  http        Apache httpd 2.4.52"""

        elif 'searchsploit' in cmd:
            result.stdout = """Apache 2.4.52 - Path Traversal | linux/webapps/50383.sh"""

        elif 'nikto' in cmd:
            result.stdout = """+ Server: Apache/2.4.52
+ OSVDB-3092: /admin/: This might be interesting..."""

        elif 'enum4linux' in cmd:
            result.stdout = """[+] Got domain/workgroup name: WORKGROUP
[+] Shares: print$, IPC$"""

        elif 'whatweb' in cmd:
            result.stdout = """http://192.168.45.100 [200 OK] Apache[2.4.52], PHP[7.4.33]"""

        return result

    mock = Mock(side_effect=mock_run)
    monkeypatch.setattr(subprocess, 'run', mock)
    return mock


@pytest.fixture
def mock_requests_session(monkeypatch):
    """Mock requests.Session for HTTP testing"""
    mock_session = MagicMock(spec=requests.Session)

    # Mock response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.content = b"<html><body>Test response</body></html>"
    mock_response.text = "<html><body>Test response</body></html>"
    mock_response.headers = {'Content-Type': 'text/html'}

    # Configure session methods
    mock_session.get.return_value = mock_response
    mock_session.post.return_value = mock_response

    # Mock Session class
    def mock_session_class():
        return mock_session

    monkeypatch.setattr(requests, 'Session', mock_session_class)
    return mock_session


@pytest.fixture
def mock_requests_get(monkeypatch):
    """Mock requests.get for simple HTTP testing"""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.content = b"<html><body>Test page</body></html>"
    mock_response.text = "<html><body>Test page</body></html>"
    mock_response.headers = {'Content-Type': 'text/html'}

    mock_get = Mock(return_value=mock_response)
    monkeypatch.setattr(requests, 'get', mock_get)
    return mock_get


# ============================================================================
# UTILITY FIXTURES
# ============================================================================

@pytest.fixture
def target_ip():
    """Standard target IP for testing"""
    return "192.168.45.100"


@pytest.fixture
def target_url():
    """Standard target URL for testing"""
    return "http://192.168.45.100"


@pytest.fixture
def sqli_vulnerable_url():
    """URL with SQLi vulnerable parameter"""
    return "http://192.168.45.100/page.php?id=1"