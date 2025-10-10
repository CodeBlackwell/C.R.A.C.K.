"""
Test Tier 4 AD Plugin Finding-Based Activation

Tests finding-based activation for Active Directory plugins:
- ad_enumeration.py
- ad_attacks.py
- ad_persistence.py
- ad_certificates.py
- lateral_movement.py
"""

import pytest
from crack.track.services.ad_enumeration import ADEnumerationPlugin
from crack.track.services.ad_attacks import ADAttacksPlugin
from crack.track.services.ad_persistence import ADPersistencePlugin
from crack.track.services.ad_certificates import ADCertificatesPlugin
from crack.track.services.lateral_movement import LateralMovementPlugin
from crack.track.core.constants import FindingTypes


# ============================================
# AD Enumeration Plugin Tests
# ============================================

def test_ad_enumeration_activates_on_domain_joined():
    """AD enumeration activates when domain detected"""
    plugin = ADEnumerationPlugin()

    finding = {
        'type': FindingTypes.DOMAIN_JOINED,
        'description': 'Target is domain-joined: CORPORATE.LOCAL'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 100, "Perfect match: domain_joined should return 100"


def test_ad_enumeration_activates_on_ad_detected():
    """AD enumeration activates on AD_DETECTED finding"""
    plugin = ADEnumerationPlugin()

    finding = {
        'type': FindingTypes.AD_DETECTED,
        'description': 'Active Directory environment detected'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 100, "Perfect match: AD_DETECTED should return 100"


def test_ad_enumeration_activates_on_domain_controller_found():
    """AD enumeration activates when domain controller found"""
    plugin = ADEnumerationPlugin()

    finding = {
        'type': FindingTypes.DOMAIN_CONTROLLER_FOUND,
        'description': 'Domain Controller: DC01.corporate.local'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 100, "Perfect match: DC found should return 100"


def test_ad_enumeration_activates_on_ad_indicators():
    """AD enumeration activates on AD-related keywords"""
    plugin = ADEnumerationPlugin()

    finding = {
        'type': 'service_detected',
        'description': 'LDAP service running on domain controller'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 90, "High confidence: LDAP + domain controller should return 90"


def test_ad_enumeration_activates_on_windows_domain_hints():
    """AD enumeration activates on Windows with domain hints"""
    plugin = ADEnumerationPlugin()

    finding = {
        'type': FindingTypes.OS_WINDOWS,
        'description': 'Windows Server 2019 - domain member'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 70, "Medium confidence: Windows + domain hint should return 70"


def test_ad_enumeration_ignores_unrelated_findings():
    """AD enumeration does not activate on unrelated findings"""
    plugin = ADEnumerationPlugin()

    finding = {
        'type': FindingTypes.OS_LINUX,
        'description': 'Ubuntu 22.04 LTS'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 0, "No match: Linux should return 0"


# ============================================
# AD Attacks Plugin Tests
# ============================================

def test_ad_attacks_activates_on_kerberoastable():
    """AD attacks activates on Kerberoastable user"""
    plugin = ADAttacksPlugin()

    finding = {
        'type': FindingTypes.KERBEROASTABLE_USER,
        'description': 'svc_sql has SPN and is Kerberoastable'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 100, "Perfect match: Kerberoastable should return 100"


def test_ad_attacks_activates_on_asreproastable():
    """AD attacks activates on AS-REP roastable user"""
    plugin = ADAttacksPlugin()

    finding = {
        'type': FindingTypes.AS_REP_ROASTABLE,
        'description': 'User has DONT_REQ_PREAUTH set'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 100, "Perfect match: AS-REP roastable should return 100"


def test_ad_attacks_activates_on_ad_admin_found():
    """AD attacks activates when AD admin found"""
    plugin = ADAttacksPlugin()

    finding = {
        'type': FindingTypes.AD_ADMIN_FOUND,
        'description': 'Domain Admins member: Administrator'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 95, "Very high: AD admin should return 95"


def test_ad_attacks_activates_on_ad_user_found():
    """AD attacks activates when AD user found"""
    plugin = ADAttacksPlugin()

    finding = {
        'type': FindingTypes.AD_USER_FOUND,
        'description': 'Domain user: jsmith'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 85, "High: AD user should return 85"


def test_ad_attacks_activates_on_domain_joined():
    """AD attacks activates on domain membership"""
    plugin = ADAttacksPlugin()

    finding = {
        'type': FindingTypes.DOMAIN_JOINED,
        'description': 'Host is domain member'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 75, "Medium: domain joined should return 75"


def test_ad_attacks_ignores_unrelated_findings():
    """AD attacks does not activate on unrelated findings"""
    plugin = ADAttacksPlugin()

    finding = {
        'type': FindingTypes.FILE_FOUND,
        'description': 'backup.zip found'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 0, "No match: file finding should return 0"


# ============================================
# AD Persistence Plugin Tests
# ============================================

def test_ad_persistence_activates_on_domain_admin_obtained():
    """AD persistence activates when DA obtained"""
    plugin = ADPersistencePlugin()

    finding = {
        'type': FindingTypes.DOMAIN_ADMIN_OBTAINED,
        'description': 'Domain Admin credentials obtained via Kerberoast'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 100, "Perfect match: DA obtained should return 100"


def test_ad_persistence_activates_on_domain_admin_compromised():
    """AD persistence activates on compromised DA"""
    plugin = ADPersistencePlugin()

    finding = {
        'type': FindingTypes.DOMAIN_ADMIN_OBTAINED,
        'description': 'Administrator account compromised'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 100, "Perfect match: DA compromised should return 100"


def test_ad_persistence_activates_on_da_credential():
    """AD persistence activates on DA credential found"""
    plugin = ADPersistencePlugin()

    finding = {
        'type': FindingTypes.CREDENTIAL_FOUND,
        'description': 'Credential for domain admin: administrator:P@ssw0rd'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 90, "High: DA credential should return 90"


def test_ad_persistence_activates_on_administrator_credential():
    """AD persistence activates on administrator credential"""
    plugin = ADPersistencePlugin()

    finding = {
        'type': FindingTypes.CREDENTIAL_FOUND,
        'description': 'Found administrator password in config file'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 90, "High: administrator credential should return 90"


def test_ad_persistence_ignores_low_privilege_credential():
    """AD persistence does not activate on low-privilege credential"""
    plugin = ADPersistencePlugin()

    finding = {
        'type': FindingTypes.CREDENTIAL_FOUND,
        'description': 'User credential: jsmith:password123'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 0, "No match: regular user credential should return 0"


def test_ad_persistence_ignores_unrelated_findings():
    """AD persistence does not activate on unrelated findings"""
    plugin = ADPersistencePlugin()

    finding = {
        'type': FindingTypes.DIRECTORY_FOUND,
        'description': '/admin directory found'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 0, "No match: directory finding should return 0"


# ============================================
# AD Certificates Plugin Tests
# ============================================

def test_adcs_plugin_activates_on_certificate_services():
    """ADCS plugin activates on certificate services detection"""
    plugin = ADCertificatesPlugin()

    finding = {
        'type': FindingTypes.ADCS_DETECTED,
        'description': 'Active Directory Certificate Services detected'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 100, "Perfect match: ADCS detected should return 100"


def test_adcs_plugin_activates_on_certificate_authority():
    """ADCS plugin activates on Certificate Authority found"""
    plugin = ADCertificatesPlugin()

    finding = {
        'type': 'service_detected',
        'description': 'Certificate Authority running on DC01'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 90, "High: CA indicator should return 90"


def test_adcs_plugin_activates_on_pki_indicator():
    """ADCS plugin activates on PKI keywords"""
    plugin = ADCertificatesPlugin()

    finding = {
        'type': 'misconfiguration',
        'description': 'PKI infrastructure detected with vulnerable templates'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 90, "High: PKI indicator should return 90"


def test_adcs_plugin_activates_on_adcs_keyword():
    """ADCS plugin activates on ADCS keyword"""
    plugin = ADCertificatesPlugin()

    finding = {
        'type': 'service_detected',
        'description': 'ADCS enrollment endpoint accessible'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 90, "High: ADCS keyword should return 90"


def test_adcs_plugin_ignores_unrelated_findings():
    """ADCS plugin does not activate on unrelated findings"""
    plugin = ADCertificatesPlugin()

    finding = {
        'type': FindingTypes.AD_USER_FOUND,
        'description': 'Domain user enumerated'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 0, "No match: user finding should return 0"


# ============================================
# Lateral Movement Plugin Tests
# ============================================

def test_lateral_movement_activates_on_credentials():
    """Lateral movement activates on credential found"""
    plugin = LateralMovementPlugin()

    finding = {
        'type': FindingTypes.CREDENTIAL_FOUND,
        'description': 'Valid domain credentials: user:password'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 90, "Very high: credential should return 90"


def test_lateral_movement_activates_on_ssh_credential():
    """Lateral movement activates on SSH credential"""
    plugin = LateralMovementPlugin()

    finding = {
        'type': FindingTypes.SSH_CREDENTIAL,
        'description': 'SSH key found in /home/user/.ssh/id_rsa'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 90, "Very high: SSH credential should return 90"


def test_lateral_movement_activates_on_database_credential():
    """Lateral movement activates on database credential"""
    plugin = LateralMovementPlugin()

    finding = {
        'type': FindingTypes.DATABASE_CREDENTIAL,
        'description': 'MySQL credentials in config.php'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 90, "Very high: DB credential should return 90"


def test_lateral_movement_activates_on_pivot_opportunity():
    """Lateral movement activates on pivot opportunity"""
    plugin = LateralMovementPlugin()

    finding = {
        'type': FindingTypes.PIVOT_OPPORTUNITY,
        'description': 'Multiple network segments accessible from compromised host'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 100, "Perfect match: pivot should return 100"


def test_lateral_movement_activates_on_network_share():
    """Lateral movement activates on network share found"""
    plugin = LateralMovementPlugin()

    finding = {
        'type': FindingTypes.NETWORK_SHARE_FOUND,
        'description': 'SMB share found: \\\\server\\data'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 85, "High: network share should return 85"


def test_lateral_movement_activates_on_writable_share():
    """Lateral movement activates on writable share"""
    plugin = LateralMovementPlugin()

    finding = {
        'type': FindingTypes.WRITABLE_SHARE,
        'description': 'Writable share: \\\\server\\public (Everyone:FULL)'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 85, "High: writable share should return 85"


def test_lateral_movement_activates_on_domain_joined():
    """Lateral movement activates on domain membership"""
    plugin = LateralMovementPlugin()

    finding = {
        'type': FindingTypes.DOMAIN_JOINED,
        'description': 'Host is domain member - potential lateral movement'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 70, "Medium: domain joined should return 70"


def test_lateral_movement_ignores_unrelated_findings():
    """Lateral movement does not activate on unrelated findings"""
    plugin = LateralMovementPlugin()

    finding = {
        'type': FindingTypes.CVE_FOUND,
        'description': 'CVE-2024-1234 found'
    }

    score = plugin.detect_from_finding(finding)
    assert score == 0, "No match: CVE finding should return 0"


# ============================================
# Integration Tests
# ============================================

def test_all_ad_plugins_have_detect_from_finding():
    """All AD plugins implement detect_from_finding method"""
    plugins = [
        ADEnumerationPlugin(),
        ADAttacksPlugin(),
        ADPersistencePlugin(),
        ADCertificatesPlugin(),
        LateralMovementPlugin()
    ]

    for plugin in plugins:
        assert hasattr(plugin, 'detect_from_finding'), \
            f"{plugin.name} missing detect_from_finding method"

        # Test method signature
        test_finding = {'type': 'test', 'description': 'test'}
        result = plugin.detect_from_finding(test_finding)
        assert isinstance(result, (int, float)), \
            f"{plugin.name}.detect_from_finding must return numeric score"
        assert 0 <= result <= 100, \
            f"{plugin.name}.detect_from_finding must return score 0-100"


def test_ad_plugins_return_zero_for_empty_finding():
    """All AD plugins return 0 for empty finding"""
    plugins = [
        ADEnumerationPlugin(),
        ADAttacksPlugin(),
        ADPersistencePlugin(),
        ADCertificatesPlugin(),
        LateralMovementPlugin()
    ]

    empty_finding = {'type': '', 'description': ''}

    for plugin in plugins:
        score = plugin.detect_from_finding(empty_finding)
        assert score == 0, f"{plugin.name} should return 0 for empty finding"


def test_ad_plugins_handle_missing_description():
    """All AD plugins handle missing description gracefully"""
    plugins = [
        ADEnumerationPlugin(),
        ADAttacksPlugin(),
        ADPersistencePlugin(),
        ADCertificatesPlugin(),
        LateralMovementPlugin()
    ]

    finding_no_desc = {'type': 'test'}

    for plugin in plugins:
        # Should not crash
        score = plugin.detect_from_finding(finding_no_desc)
        assert isinstance(score, (int, float)), \
            f"{plugin.name} should handle missing description"


def test_ad_plugins_case_insensitive_matching():
    """All AD plugins perform case-insensitive matching"""
    plugin = ADEnumerationPlugin()

    finding_upper = {
        'type': 'DOMAIN_JOINED',
        'description': 'DOMAIN DETECTED'
    }

    finding_lower = {
        'type': 'domain_joined',
        'description': 'domain detected'
    }

    score_upper = plugin.detect_from_finding(finding_upper)
    score_lower = plugin.detect_from_finding(finding_lower)

    assert score_upper == score_lower, \
        "Case should not affect matching"


# ============================================
# Confidence Score Validation Tests
# ============================================

def test_confidence_scores_follow_pattern():
    """Confidence scores follow expected pattern (100, 90, 85, 75, 70, 0)"""
    # AD Enumeration expected scores
    plugin = ADEnumerationPlugin()

    # Perfect match: 100
    assert plugin.detect_from_finding({
        'type': FindingTypes.DOMAIN_JOINED,
        'description': 'test'
    }) == 100

    # High: 90
    assert plugin.detect_from_finding({
        'type': 'other',
        'description': 'active directory detected'
    }) == 90

    # Medium: 70
    assert plugin.detect_from_finding({
        'type': FindingTypes.OS_WINDOWS,
        'description': 'Windows with domain hints'
    }) == 70

    # No match: 0
    assert plugin.detect_from_finding({
        'type': 'unrelated',
        'description': 'nothing relevant'
    }) == 0


def test_lateral_movement_confidence_scores():
    """Lateral movement plugin uses full confidence range"""
    plugin = LateralMovementPlugin()

    # Perfect match: 100
    assert plugin.detect_from_finding({
        'type': FindingTypes.PIVOT_OPPORTUNITY,
        'description': 'test'
    }) == 100

    # Very high: 90
    assert plugin.detect_from_finding({
        'type': FindingTypes.CREDENTIAL_FOUND,
        'description': 'test'
    }) == 90

    # High: 85
    assert plugin.detect_from_finding({
        'type': FindingTypes.NETWORK_SHARE_FOUND,
        'description': 'test'
    }) == 85

    # Medium: 70
    assert plugin.detect_from_finding({
        'type': FindingTypes.DOMAIN_JOINED,
        'description': 'test'
    }) == 70

    # No match: 0
    assert plugin.detect_from_finding({
        'type': 'unrelated',
        'description': 'test'
    }) == 0
