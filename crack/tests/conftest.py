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
# SERVICE REGISTRY FIXTURES (Test Isolation)
# ============================================================================

@pytest.fixture(scope="module", autouse=True)
def clear_event_bus_and_plugin_state():
    """Clear EventBus and plugin resolution state before each module for test isolation

    This ensures:
    - EventBus handlers don't accumulate across tests (each TargetProfile registers handlers)
    - ServiceRegistry plugin conflict resolution resets (_resolved_ports, _plugin_claims)
    - ServiceRegistry re-registers event handlers (by resetting _initialized flag)
    - Service plugins themselves remain registered (avoiding Python import cache issues)
    - Plugins are re-initialized after state clearing (ensures registry is populated)
    - Plugin registry is saved/restored (allows tests to clear plugins for isolation)
    """
    from crack.track.services.registry import ServiceRegistry
    from crack.track.core.events import EventBus

    # SAVE current plugin state (protects against tests that clear plugins)
    saved_plugins = ServiceRegistry._plugins.copy()

    # Clear EventBus handlers (prevents duplicate handlers from multiple TargetProfiles)
    EventBus.clear()

    # Reset ServiceRegistry initialization flag to force handler re-registration
    ServiceRegistry._initialized = False

    # Clear plugin resolution state (allows ports to be re-resolved in new tests)
    if hasattr(ServiceRegistry, '_plugin_claims'):
        ServiceRegistry._plugin_claims.clear()
    if hasattr(ServiceRegistry, '_resolved_ports'):
        ServiceRegistry._resolved_ports.clear()

    # Re-initialize plugins to ensure registry is populated
    # This loads all plugin modules and re-registers event handlers
    ServiceRegistry.initialize_plugins()

    yield

    # RESTORE plugin registry (ensures next test starts with full registry)
    # This fixes the issue where test_core_improvements.py clears plugins
    ServiceRegistry._plugins = saved_plugins
    ServiceRegistry._initialized = True  # Mark as initialized since we restored plugins

    # Cleanup after test
    EventBus.clear()
    if hasattr(ServiceRegistry, '_plugin_claims'):
        ServiceRegistry._plugin_claims.clear()
    if hasattr(ServiceRegistry, '_resolved_ports'):
        ServiceRegistry._resolved_ports.clear()


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

    # IMPORTANT: Set up headers as a real dict, not a Mock
    mock_session.headers = {}

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


# ============================================================================
# REFERENCE SYSTEM FIXTURES
# ============================================================================

@pytest.fixture
def sample_command_data():
    """Sample command object for testing"""
    return {
        "id": "test-command",
        "name": "Test Command",
        "category": "test",
        "command": "echo <MESSAGE>",
        "description": "A test command for unit testing",
        "subcategory": "unit",
        "variables": [
            {
                "name": "<MESSAGE>",
                "description": "Message to echo",
                "example": "Hello World",
                "required": True
            }
        ],
        "flag_explanations": {
            "echo": "Print message to stdout"
        },
        "tags": ["TEST", "OSCP:HIGH", "QUICK_WIN"],
        "oscp_relevance": "high",
        "success_indicators": ["Message displayed"],
        "failure_indicators": ["Command not found"],
        "next_steps": ["Verify output"],
        "alternatives": ["printf <MESSAGE>"],
        "notes": "Test command only"
    }


@pytest.fixture
def sample_commands_json(temp_output_dir):
    """Create sample command JSON file for testing"""
    commands_data = {
        "category": "test",
        "description": "Test commands",
        "commands": [
            {
                "id": "test-nmap",
                "name": "Test Nmap Scan",
                "category": "test",
                "command": "nmap -sV <TARGET>",
                "description": "Test service scan",
                "variables": [
                    {
                        "name": "<TARGET>",
                        "description": "Target IP",
                        "example": "192.168.1.100",
                        "required": True
                    }
                ],
                "tags": ["OSCP:HIGH", "ENUM"],
                "oscp_relevance": "high"
            },
            {
                "id": "test-curl",
                "name": "Test Curl Request",
                "category": "test",
                "command": "curl http://<TARGET>",
                "description": "Test HTTP request",
                "variables": [
                    {
                        "name": "<TARGET>",
                        "description": "Target host",
                        "example": "example.com",
                        "required": True
                    }
                ],
                "tags": ["OSCP:MEDIUM", "QUICK_WIN"],
                "oscp_relevance": "medium"
            }
        ]
    }

    json_file = temp_output_dir / "test_commands.json"
    import json
    with open(json_file, 'w') as f:
        json.dump(commands_data, f, indent=2)

    return json_file


@pytest.fixture
def sample_subcategory_commands(temp_output_dir):
    """Create subdirectory structure with commands"""
    # Create category directory
    category_dir = temp_output_dir / "test-category"
    category_dir.mkdir()

    # Create subcategory JSON
    subcat_data = {
        "category": "test-category",
        "subcategory": "subcat",
        "commands": [
            {
                "id": "test-subcat-cmd",
                "name": "Test Subcategory Command",
                "category": "test-category",
                "subcategory": "subcat",
                "command": "echo 'subcategory test'",
                "description": "Test subcategory command",
                "tags": ["TEST"],
                "oscp_relevance": "low"
            }
        ]
    }

    json_file = category_dir / "subcat.json"
    import json
    with open(json_file, 'w') as f:
        json.dump(subcat_data, f, indent=2)

    return temp_output_dir


@pytest.fixture
def mock_config_file(temp_output_dir):
    """Create mock config.json for testing"""
    config_data = {
        "variables": {
            "LHOST": {
                "value": "10.10.14.5",
                "description": "Local IP",
                "source": "manual",
                "updated": "2024-10-07T12:00:00"
            },
            "LPORT": {
                "value": "4444",
                "description": "Local port",
                "source": "default",
                "updated": None
            },
            "TARGET": {
                "value": "192.168.45.100",
                "description": "Target IP",
                "source": "manual",
                "updated": "2024-10-07T12:00:00"
            }
        },
        "sessions": {},
        "settings": {
            "auto_detect_interface": True,
            "auto_detect_ip": True
        }
    }

    config_file = temp_output_dir / "config.json"
    import json
    with open(config_file, 'w') as f:
        json.dump(config_data, f, indent=2)

    return config_file


@pytest.fixture
def reference_registry(temp_output_dir, sample_commands_json):
    """Pre-configured HybridCommandRegistry for testing"""
    from crack.reference.core.registry import HybridCommandRegistry

    # Create commands directory structure
    commands_dir = temp_output_dir / "data" / "commands"
    commands_dir.mkdir(parents=True)

    # Copy sample commands
    import shutil
    shutil.copy(sample_commands_json, commands_dir / "test.json")

    # Initialize registry with test data
    registry = HybridCommandRegistry(base_path=temp_output_dir)

    return registry


@pytest.fixture
def mock_network_interfaces(monkeypatch):
    """Mock network interface detection for config tests"""
    def mock_run(cmd, **kwargs):
        result = Mock()
        result.returncode = 0

        if 'ip' in cmd or 'ifconfig' in cmd:
            # Mock interface list
            result.stdout = """
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP
3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP
    inet 10.10.14.5/23 brd 10.10.15.255 scope global tun0
"""
        return result

    mock = Mock(side_effect=mock_run)
    monkeypatch.setattr(subprocess, 'run', mock)
    return mock


@pytest.fixture
def mock_ip_detection(monkeypatch):
    """Mock IP address auto-detection (also handles interface detection)"""
    def mock_run(cmd, **kwargs):
        result = Mock()
        result.returncode = 0

        if 'ip' in cmd and 'link' in cmd:
            # Mock interface list for auto_detect_interface
            result.stdout = """
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP
3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP
    inet 10.10.14.5/23 brd 10.10.15.255 scope global tun0
"""
        elif 'ip' in cmd and 'addr' in cmd:
            # Mock ip addr show output
            result.stdout = """
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
    inet 127.0.0.1/8 scope host lo
3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP
    inet 10.10.14.5/23 brd 10.10.15.255 scope global tun0
"""
        elif 'hostname' in cmd:
            result.stdout = "10.10.14.5"

        return result

    mock = Mock(side_effect=mock_run)
    monkeypatch.setattr(subprocess, 'run', mock)
    return mock


@pytest.fixture
def invalid_command_json(temp_output_dir):
    """Create invalid command JSON for validation testing"""
    invalid_data = {
        "category": "invalid",
        "commands": [
            {
                "id": "missing-required-fields",
                # Missing: name, command, description
                "category": "invalid"
            }
        ]
    }

    json_file = temp_output_dir / "invalid.json"
    import json
    with open(json_file, 'w') as f:
        json.dump(invalid_data, f, indent=2)

    return json_file


# ============================================================================
# VALIDATOR FIXTURES
# ============================================================================

@pytest.fixture
def valid_command_dict():
    """Well-formed command dictionary for validation testing"""
    return {
        "id": "valid-test-cmd",
        "name": "Valid Test Command",
        "category": "recon",
        "command": "nmap -sV <TARGET> -p <PORTS>",
        "description": "A valid command with all required fields and proper formatting",
        "variables": [
            {
                "name": "<TARGET>",
                "description": "Target IP address",
                "example": "192.168.1.100",
                "required": True
            },
            {
                "name": "<PORTS>",
                "description": "Ports to scan",
                "example": "80,443",
                "required": True
            }
        ],
        "flag_explanations": {
            "-sV": "Service version detection",
            "-p": "Specify ports"
        },
        "tags": ["OSCP:HIGH", "ENUM", "NOISY"],
        "oscp_relevance": "high",
        "success_indicators": ["Open ports listed", "Service versions shown"],
        "failure_indicators": ["Connection timeout", "Host appears down"],
        "next_steps": ["Run targeted scripts", "Research service versions"],
        "alternatives": ["nc -zv <TARGET> <PORTS>"],
        "notes": "Requires nmap installed"
    }


@pytest.fixture
def invalid_command_dict():
    """Command dictionary missing required fields"""
    return {
        "id": "invalid-cmd",
        # Missing: name, command, description
        "category": "recon",
        "tags": ["TEST"]
    }


@pytest.fixture
def dangerous_command_dict():
    """Command with dangerous patterns"""
    return {
        "id": "dangerous-cmd",
        "name": "Dangerous Command",
        "category": "exploitation",
        "command": "rm -rf /tmp/*",
        "description": "Contains dangerous pattern"
    }


@pytest.fixture
def command_with_bad_formatting():
    """Command with formatting issues"""
    return {
        "id": "Bad_Format_123",  # Should be lowercase kebab-case
        "name": "Bad Format",
        "category": "invalid_category",  # Invalid category
        "command": "echo <UNDEFINED>",  # Placeholder not defined in variables
        "description": "Bad",  # Description too short
        "tags": ["lowercase_tag", "Mixed_Case"],  # Tags should be uppercase
        "oscp_relevance": "invalid",  # Should be high/medium/low
        "variables": [
            {
                "name": "<UNUSED>",
                "description": "Not used in command",
                "example": "test",
                "required": True
            }
        ]
    }


@pytest.fixture
def duplicate_commands_json(temp_output_dir):
    """JSON file with duplicate command IDs"""
    import json

    data = {
        "category": "test",
        "commands": [
            {
                "id": "duplicate-id",
                "name": "First Command",
                "category": "test",
                "command": "echo first",
                "description": "First command"
            },
            {
                "id": "duplicate-id",  # Duplicate!
                "name": "Second Command",
                "category": "test",
                "command": "echo second",
                "description": "Second command"
            }
        ]
    }

    json_file = temp_output_dir / "duplicates.json"
    with open(json_file, 'w') as f:
        json.dump(data, f, indent=2)

    return json_file


@pytest.fixture
def command_schema_file(temp_output_dir):
    """Create a minimal command schema for validation testing"""
    import json

    schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["category", "commands"],
        "properties": {
            "category": {"type": "string"},
            "commands": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["id", "name", "category", "command", "description"],
                    "properties": {
                        "id": {"type": "string"},
                        "name": {"type": "string"},
                        "category": {"type": "string"},
                        "command": {"type": "string"},
                        "description": {"type": "string"}
                    }
                }
            }
        }
    }

    # Create schemas directory
    schemas_dir = temp_output_dir / "data" / "schemas"
    schemas_dir.mkdir(parents=True, exist_ok=True)

    schema_file = schemas_dir / "command.schema.json"
    with open(schema_file, 'w') as f:
        json.dump(schema, f, indent=2)

    return schema_file


# ============================================================================
# PARSER FIXTURES
# ============================================================================

@pytest.fixture
def sample_markdown_with_commands():
    """Markdown content with bash commands for parser testing"""
    return """# Reconnaissance Commands

## Port Scanning

Use nmap to scan for open ports:

```bash
nmap -sV -sC <TARGET> -oA scan_results
```

You can also use a faster scan:

```sh
nmap -p- --min-rate=5000 <TARGET>
```

## Web Enumeration

For directory enumeration:

```shell
gobuster dir -u http://<TARGET> -w <WORDLIST>
```

## Notes

This is just documentation text, not a command.

```python
# This is Python code, should be skipped
print("Not a shell command")
```

## Alternative Methods

```bash
# This is a comment and should be skipped
curl http://<TARGET>
wget http://<TARGET>/file.txt
```
"""


@pytest.fixture
def sample_markdown_no_commands():
    """Markdown without any extractable commands"""
    return """# Documentation

This is just documentation with no code blocks.

## Section 1

Some text here.

## Section 2

More text without commands.
"""


@pytest.fixture
def sample_command_for_export(valid_command_dict):
    """Command object ready for markdown export"""
    from crack.reference.core.registry import Command

    # Create Command directly from dict - from_dict handles variable conversion
    return Command.from_dict(valid_command_dict)


@pytest.fixture
def markdown_file_with_commands(temp_output_dir, sample_markdown_with_commands):
    """Actual markdown file on disk for parser testing"""
    md_file = temp_output_dir / "test_commands.md"
    md_file.write_text(sample_markdown_with_commands)
    return md_file


@pytest.fixture
def markdown_directory_structure(temp_output_dir):
    """Directory structure with categorized markdown files"""
    docs_dir = temp_output_dir / "docs"

    # Create category directories
    (docs_dir / "01-recon").mkdir(parents=True)
    (docs_dir / "02-web").mkdir(parents=True)
    (docs_dir / "03-exploitation").mkdir(parents=True)

    # Create markdown files with commands
    recon_md = docs_dir / "01-recon" / "scanning.md"
    recon_md.write_text("""# Scanning
```bash
nmap -sV <TARGET>
```
""")

    web_md = docs_dir / "02-web" / "enumeration.md"
    web_md.write_text("""# Web Enum
```bash
gobuster dir -u <URL> -w <WORDLIST>
```
""")

    return docs_dir