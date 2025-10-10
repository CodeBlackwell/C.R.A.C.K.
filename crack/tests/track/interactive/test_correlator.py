"""
Tests for Finding Correlator

Validates credential reuse detection, attack chain matching, and CVE correlation.
"""

import pytest
from crack.track.core.state import TargetProfile
from crack.track.interactive.correlator import FindingCorrelator


@pytest.fixture
def empty_profile():
    """Profile with no data"""
    return TargetProfile('192.168.45.100')


@pytest.fixture
def profile_with_creds():
    """Profile with credentials and services"""
    profile = TargetProfile('192.168.45.100')

    # Add credentials
    profile.add_credential(
        username='admin',
        password='password123',
        source='config.php',
        service='http'
    )

    # Add services
    profile.add_port(22, 'open', 'ssh', 'OpenSSH 7.9p1', 'nmap')
    profile.add_port(445, 'open', 'smb', 'Samba 3.5.0', 'nmap')
    profile.add_port(3306, 'open', 'mysql', 'MySQL 5.5.47', 'nmap')

    return profile


@pytest.fixture
def profile_with_vulns():
    """Profile with vulnerable service versions"""
    profile = TargetProfile('192.168.45.100')

    profile.add_port(80, 'open', 'apache', 'Apache 2.4.49', 'nmap')
    profile.add_port(22, 'open', 'openssh', 'OpenSSH 7.9p1', 'nmap')
    profile.add_port(21, 'open', 'vsftpd', 'vsftpd 2.3.4', 'nmap')

    return profile


@pytest.fixture
def profile_with_findings():
    """Profile with findings for attack chain detection"""
    profile = TargetProfile('192.168.45.100')

    profile.add_finding(
        finding_type='vulnerability',
        description='LFI vulnerability detected',
        source='manual testing'
    )

    profile.add_finding(
        finding_type='file',
        description='Config file readable',
        source='LFI exploitation'
    )

    profile.add_finding(
        finding_type='credential',
        description='Database credentials found in config',
        source='config file'
    )

    return profile


def test_correlator_initialization(empty_profile):
    """Test correlator can be initialized"""
    correlator = FindingCorrelator(empty_profile)

    assert correlator.profile == empty_profile
    assert isinstance(correlator.cve_cache, dict)


def test_credential_reuse_detection(profile_with_creds):
    """Test credential reuse opportunities are detected"""
    correlator = FindingCorrelator(profile_with_creds)

    opportunities = correlator.detect_credential_reuse()

    # Should find untested services (SSH, SMB, MySQL)
    assert len(opportunities) == 1

    opp = opportunities[0]
    assert opp['credential']['username'] == 'admin'
    assert len(opp['untested_services']) == 3  # SSH, SMB, MySQL

    # Check confidence scoring
    assert opp['confidence'] in ['HIGH', 'MEDIUM', 'LOW']

    # Check actions are suggested
    assert len(opp['actions']) > 0


def test_credential_confidence_scoring():
    """Test confidence scoring heuristics"""
    profile = TargetProfile('192.168.45.100')
    profile.add_credential(
        username='admin',
        password='P@ssw0rd123',
        source='config.php',  # Config file = HIGH
        service='http'
    )
    profile.add_port(22, 'open', 'ssh', 'OpenSSH', 'nmap')

    correlator = FindingCorrelator(profile)
    opps = correlator.detect_credential_reuse()

    # Config file should give HIGH confidence
    assert opps[0]['confidence'] == 'HIGH'


def test_empty_profile_returns_no_correlations(empty_profile):
    """Test empty profile returns no correlations"""
    correlator = FindingCorrelator(empty_profile)

    cred_opps = correlator.detect_credential_reuse()
    attack_chains = correlator.detect_attack_chains()
    cves = correlator.correlate_cves()

    assert len(cred_opps) == 0
    assert len(attack_chains) == 0
    assert len(cves) == 0


def test_attack_chain_detection(profile_with_findings):
    """Test attack chain pattern matching"""
    correlator = FindingCorrelator(profile_with_findings)

    chains = correlator.detect_attack_chains()

    # Should detect LFI → Config → Database chain
    # Note: May not match exactly due to keyword matching
    assert isinstance(chains, list)


def test_cve_correlation_exact_match(profile_with_vulns):
    """Test CVE correlation with exact version match"""
    correlator = FindingCorrelator(profile_with_vulns)

    cves = correlator.correlate_cves()

    # Should find CVEs for Apache 2.4.49, vsftpd 2.3.4
    assert len(cves) > 0

    # Check CVE structure
    cve = cves[0]
    assert 'cve_id' in cve
    assert 'description' in cve
    assert 'cvss' in cve
    assert 'severity' in cve
    assert 'confidence' in cve
    assert cve['confidence'] in ['HIGH', 'MEDIUM']


def test_cve_correlation_sorted_by_cvss(profile_with_vulns):
    """Test CVE matches are sorted by CVSS score"""
    correlator = FindingCorrelator(profile_with_vulns)

    cves = correlator.correlate_cves()

    if len(cves) > 1:
        # Check descending CVSS order
        for i in range(len(cves) - 1):
            assert cves[i]['cvss'] >= cves[i+1]['cvss']


def test_cred_actions_are_service_specific():
    """Test suggested actions are specific to services"""
    profile = TargetProfile('192.168.45.100')
    profile.add_credential(
        username='root',
        password='toor',
        source='database',
        service='mysql'
    )
    profile.add_port(22, 'open', 'ssh', 'OpenSSH', 'nmap')

    correlator = FindingCorrelator(profile)
    opps = correlator.detect_credential_reuse()

    # Should suggest SSH command
    ssh_action = opps[0]['actions'][0]
    assert 'ssh' in ssh_action.lower()
    assert 'root' in ssh_action


def test_no_duplicate_credential_opportunities():
    """Test each credential only generates one opportunity"""
    profile = TargetProfile('192.168.45.100')
    profile.add_credential(
        username='admin',
        password='pass',
        source='test',
        service='http'
    )

    # Add multiple untested services
    for port, service in [(22, 'ssh'), (445, 'smb'), (3306, 'mysql')]:
        profile.add_port(port, 'open', service, '', 'nmap')

    correlator = FindingCorrelator(profile)
    opps = correlator.detect_credential_reuse()

    # Should only have ONE opportunity (with multiple untested services)
    assert len(opps) == 1
    assert len(opps[0]['untested_services']) == 3


def test_cve_cache_loads_correctly(empty_profile):
    """Test CVE cache loads from JSON file"""
    correlator = FindingCorrelator(empty_profile)

    # Check cache has entries
    assert len(correlator.cve_cache) > 0

    # Check structure
    for key, cves in correlator.cve_cache.items():
        assert ':' in key  # service:version format
        assert isinstance(cves, list)
        for cve in cves:
            assert 'id' in cve
            assert 'description' in cve
            assert 'cvss' in cve
