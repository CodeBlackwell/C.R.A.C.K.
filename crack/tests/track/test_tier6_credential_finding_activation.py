"""
Tests for Tier 6 credential & access plugin finding-based activation

These plugins activate when credentials are discovered or RCE opportunities arise:
- credential_theft.py: Activates on credential findings
- reverse_shells.py: Activates on RCE detection
- c2_operations.py: Suggests on high-privilege shells (lower confidence)
- phishing.py: Activates on email access
"""

import pytest
from crack.track.services.credential_theft import CredentialTheftPlugin
from crack.track.services.reverse_shells import ReverseShellPlugin
from crack.track.services.c2_operations import C2OperationsPlugin
from crack.track.services.phishing import PhishingPlugin
from crack.track.core.constants import FindingTypes


# ===== CREDENTIAL THEFT PLUGIN TESTS =====

def test_credential_theft_activates_on_password_found():
    """Credential theft activates when password found"""
    plugin = CredentialTheftPlugin()

    finding = {
        'type': FindingTypes.PASSWORD_FOUND,
        'description': 'Found password in config file: admin:password123',
        'source': 'manual'
    }

    confidence = plugin.detect_from_finding(finding)

    assert confidence == 100, "Should have perfect confidence for password found"


def test_credential_theft_activates_on_api_key():
    """Credential theft activates on API key"""
    plugin = CredentialTheftPlugin()

    finding = {
        'type': FindingTypes.API_KEY_FOUND,
        'description': 'API key exposed in .env file',
        'source': 'file_enum'
    }

    confidence = plugin.detect_from_finding(finding)

    assert confidence == 100, "Should have perfect confidence for API key"


def test_credential_theft_activates_on_ssh_credential():
    """Credential theft activates on SSH credential"""
    plugin = CredentialTheftPlugin()

    finding = {
        'type': FindingTypes.SSH_CREDENTIAL,
        'description': 'SSH key found in /home/user/.ssh/id_rsa',
        'source': 'linpeas'
    }

    confidence = plugin.detect_from_finding(finding)

    assert confidence == 95, "Should have high confidence for SSH credential"


def test_credential_theft_activates_on_database_access():
    """Credential theft activates on database access (medium confidence)"""
    plugin = CredentialTheftPlugin()

    finding = {
        'type': FindingTypes.DATABASE_ACCESS,
        'description': 'Database access via SQLi',
        'source': 'sqlmap'
    }

    confidence = plugin.detect_from_finding(finding)

    assert confidence == 70, "Should have medium confidence for database access"


# ===== REVERSE SHELLS PLUGIN TESTS =====

def test_reverse_shells_activates_on_rce():
    """Reverse shells activates on RCE detection"""
    plugin = ReverseShellPlugin()

    finding = {
        'type': FindingTypes.REMOTE_CODE_EXECUTION,
        'description': 'CVE-2021-44228 Log4Shell RCE',
        'source': 'exploit'
    }

    confidence = plugin.detect_from_finding(finding)

    assert confidence == 100, "Should have perfect confidence for RCE"


def test_reverse_shells_activates_on_command_injection():
    """Reverse shells activates on command injection"""
    plugin = ReverseShellPlugin()

    finding = {
        'type': FindingTypes.COMMAND_INJECTION,
        'description': 'Command injection in ping parameter',
        'source': 'burp'
    }

    confidence = plugin.detect_from_finding(finding)

    assert confidence == 95, "Should have high confidence for command injection"


def test_reverse_shells_activates_on_rce_description():
    """Reverse shells activates on RCE indicators in description"""
    plugin = ReverseShellPlugin()

    finding = {
        'type': FindingTypes.VULNERABILITY_FOUND,
        'description': 'Vulnerable to RCE via deserialization',
        'source': 'manual'
    }

    confidence = plugin.detect_from_finding(finding)

    assert confidence == 90, "Should have high confidence for RCE in description"


def test_reverse_shells_activates_on_deserialization():
    """Reverse shells activates on deserialization (medium confidence)"""
    plugin = ReverseShellPlugin()

    finding = {
        'type': FindingTypes.DESERIALIZATION_VULN,
        'description': 'Insecure deserialization detected',
        'source': 'ysoserial'
    }

    confidence = plugin.detect_from_finding(finding)

    assert confidence == 75, "Should have medium confidence for deserialization"


# ===== C2 OPERATIONS PLUGIN TESTS =====

def test_c2_operations_suggests_on_root_shell():
    """C2 operations suggests on root shell (medium confidence - user decision)"""
    plugin = C2OperationsPlugin()

    finding = {
        'type': FindingTypes.ROOT_SHELL,
        'description': 'Root shell obtained',
        'source': 'privesc'
    }

    confidence = plugin.detect_from_finding(finding)

    assert confidence == 60, "Should have medium confidence (user decides if C2 needed)"


def test_c2_operations_suggests_on_system_shell():
    """C2 operations suggests on SYSTEM shell"""
    plugin = C2OperationsPlugin()

    finding = {
        'type': FindingTypes.SYSTEM_SHELL,
        'description': 'NT AUTHORITY\\SYSTEM shell',
        'source': 'exploit'
    }

    confidence = plugin.detect_from_finding(finding)

    assert confidence == 60, "Should have medium confidence for SYSTEM shell"


def test_c2_operations_suggests_on_persistence_need():
    """C2 operations suggests when persistence mentioned"""
    plugin = C2OperationsPlugin()

    finding = {
        'type': FindingTypes.ACCESS_GAINED,
        'description': 'Need to maintain persistence on target',
        'source': 'manual'
    }

    confidence = plugin.detect_from_finding(finding)

    assert confidence == 50, "Should have low-medium confidence for persistence"


# ===== PHISHING PLUGIN TESTS =====

def test_phishing_activates_on_email_access():
    """Phishing activates on email access"""
    plugin = PhishingPlugin()

    finding = {
        'type': FindingTypes.EMAIL_ACCESS,
        'description': 'Access to email server gained',
        'source': 'credential'
    }

    confidence = plugin.detect_from_finding(finding)

    assert confidence == 80, "Should have high confidence for email access (matches 'email' + 'access')"


def test_phishing_activates_on_smtp_credential():
    """Phishing activates on SMTP credentials"""
    plugin = PhishingPlugin()

    finding = {
        'type': FindingTypes.CREDENTIAL_FOUND,
        'description': 'SMTP server credential found: smtp.example.com',
        'source': 'config_file'
    }

    confidence = plugin.detect_from_finding(finding)

    assert confidence == 80, "Should have high confidence for SMTP credential (matches 'smtp' + 'credential')"


def test_phishing_activates_on_exchange_access():
    """Phishing activates on Exchange server access"""
    plugin = PhishingPlugin()

    finding = {
        'type': FindingTypes.ACCESS_GAINED,
        'description': 'Exchange server access gained with admin credential',
        'source': 'phishing'
    }

    confidence = plugin.detect_from_finding(finding)

    assert confidence == 80, "Should have high confidence for Exchange access"


# ===== NEGATIVE TESTS (Should NOT activate) =====

def test_credential_theft_no_activation_on_irrelevant():
    """Credential theft should not activate on irrelevant findings"""
    plugin = CredentialTheftPlugin()

    finding = {
        'type': FindingTypes.DIRECTORY_FOUND,
        'description': '/images directory found',
        'source': 'gobuster'
    }

    confidence = plugin.detect_from_finding(finding)

    assert confidence == 0, "Should not activate on directory finding"


def test_reverse_shells_no_activation_on_sqli():
    """Reverse shells should not activate on SQLi (not RCE)"""
    plugin = ReverseShellPlugin()

    finding = {
        'type': FindingTypes.SQL_INJECTION,
        'description': 'SQL injection in login form',
        'source': 'sqlmap'
    }

    confidence = plugin.detect_from_finding(finding)

    assert confidence == 0, "Should not activate on SQLi without RCE"


def test_c2_operations_no_activation_on_low_priv():
    """C2 operations should not activate on low privilege shell"""
    plugin = C2OperationsPlugin()

    finding = {
        'type': FindingTypes.LOW_PRIVILEGE_SHELL,
        'description': 'www-data shell obtained',
        'source': 'exploit'
    }

    confidence = plugin.detect_from_finding(finding)

    assert confidence == 0, "Should not activate on low privilege shell"


def test_phishing_no_activation_on_web_credential():
    """Phishing should not activate on generic web credential"""
    plugin = PhishingPlugin()

    finding = {
        'type': FindingTypes.WEB_CREDENTIAL,
        'description': 'Web admin credential: admin:password',
        'source': 'brute'
    }

    confidence = plugin.detect_from_finding(finding)

    assert confidence == 0, "Should not activate on non-email web credential"
