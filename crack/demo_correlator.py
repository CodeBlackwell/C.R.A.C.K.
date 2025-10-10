#!/usr/bin/env python
"""
Demo script for Finding Correlator

Creates test profile with sample data to show correlations.
"""

from crack.track.core.state import TargetProfile
from crack.track.interactive.correlator import FindingCorrelator


def main():
    print("=" * 70)
    print("Finding Correlator Demo")
    print("=" * 70)
    print()

    # Create profile with sample data
    profile = TargetProfile('192.168.45.100')

    # Add credentials
    profile.add_credential(
        username='admin',
        password='password123',
        source='config.php',
        service='http'
    )

    # Add vulnerable services
    profile.add_port(22, 'open', 'openssh', 'OpenSSH 7.9p1', 'nmap')
    profile.add_port(80, 'open', 'apache', 'Apache 2.4.49', 'nmap')
    profile.add_port(445, 'open', 'smb', 'Samba 3.5.0', 'nmap')
    profile.add_port(3306, 'open', 'mysql', 'MySQL 5.5.47', 'nmap')

    # Add findings
    profile.add_finding(
        finding_type='vulnerability',
        description='LFI vulnerability detected in page.php',
        source='manual testing'
    )

    profile.add_finding(
        finding_type='file',
        description='Config file readable via LFI',
        source='exploitation'
    )

    # Initialize correlator
    correlator = FindingCorrelator(profile)

    # 1. Credential Reuse
    print("🔑 CREDENTIAL REUSE OPPORTUNITIES")
    print("=" * 70)
    print()

    cred_opps = correlator.detect_credential_reuse()
    for opp in cred_opps:
        cred = opp['credential']
        print(f"{opp['confidence']} CONFIDENCE:")
        print(f"  {cred.get('username')}:{cred.get('password')} (from {cred.get('source')})")

        services = [f"{s.get('service')} ({s.get('port')})" for s in opp['untested_services'][:3]]
        print(f"  → Untested: {', '.join(services)}")

        print(f"  → Actions:")
        for action in opp['actions'][:2]:
            print(f"     - {action}")
        print()

    # 2. Attack Chains
    print()
    print("🔗 ATTACK CHAINS")
    print("=" * 70)
    print()

    chains = correlator.detect_attack_chains()
    for chain in chains:
        print(f"Path: {chain['name']}")
        print(f"  {chain['description']}")
        print(f"  Confidence: {chain['confidence']}")
        print()

    # 3. CVE Matches
    print()
    print("🔍 CVE MATCHES")
    print("=" * 70)
    print()

    cves = correlator.correlate_cves()
    for cve in cves[:5]:
        severity_icon = {
            'Critical': '🔴',
            'High': '🟠',
            'Medium': '🟡',
            'Low': '🟢'
        }.get(cve['severity'], '⚪')

        print(f"{cve['service']} {cve['version']} (Port {cve['port']}):")
        print(f"  {severity_icon} {cve['cve_id']} - {cve['description']}")
        print(f"     Severity: {cve['severity']} (CVSS {cve['cvss']})")
        if cve.get('exploit_url'):
            print(f"     Exploit: {cve['exploit_url']}")
        print(f"     Confidence: {cve['confidence']}")
        print()

    print()
    print("=" * 70)
    print("Demo complete! Use 'fc' shortcut in TUI for interactive mode.")
    print("=" * 70)


if __name__ == '__main__':
    main()
