#!/usr/bin/env python3
"""
Manual visual test for FindingsPanel component

Run this script to see the panel rendering in different states:
- Empty state
- With findings (all types)
- Filtered view
- Paginated view

Usage: python3 manual_test_findings_panel.py
"""

from datetime import datetime, timedelta
from crack.track.core.state import TargetProfile
from crack.track.interactive.panels.findings_panel import FindingsPanel
from rich.console import Console


def create_test_profile_empty():
    """Create profile with no findings"""
    profile = TargetProfile('192.168.1.100')
    return profile


def create_test_profile_with_findings():
    """Create profile with sample findings"""
    profile = TargetProfile('192.168.1.100')

    # Add various types of findings
    profile.add_finding(
        finding_type='vulnerability',
        description='SQL injection in login form (parameter: username)',
        source='sqlmap -u http://192.168.1.100/login.php --forms --batch',
        data={'severity': 'high', 'port': 80, 'parameter': 'username'}
    )

    profile.add_finding(
        finding_type='directory',
        description='/admin - Admin panel discovered (Status: 200)',
        source='gobuster dir -u http://192.168.1.100 -w /usr/share/wordlists/dirb/common.txt',
        data={'status_code': 200, 'port': 80, 'path': '/admin'}
    )

    profile.add_finding(
        finding_type='directory',
        description='/backup - Backup directory with file listing enabled',
        source='nikto -h 192.168.1.100',
        data={'status_code': 200, 'port': 80, 'listing': True}
    )

    profile.add_finding(
        finding_type='credential',
        description='admin:password123',
        source='hydra -l admin -P rockyou.txt ssh://192.168.1.100',
        data={'service': 'ssh', 'port': 22, 'username': 'admin'}
    )

    profile.add_finding(
        finding_type='user',
        description='User: john (uid=1001, shell=/bin/bash)',
        source='enum4linux -U 192.168.1.100',
        data={'port': 445, 'uid': 1001, 'shell': '/bin/bash'}
    )

    profile.add_finding(
        finding_type='user',
        description='User: sarah (uid=1002, shell=/bin/bash)',
        source='enum4linux -U 192.168.1.100',
        data={'port': 445, 'uid': 1002, 'shell': '/bin/bash'}
    )

    profile.add_finding(
        finding_type='note',
        description='Apache 2.4.41 - potential CVE-2021-41773 path traversal',
        source='manual analysis - whatweb output',
        data={'research_needed': True, 'cve': 'CVE-2021-41773'}
    )

    profile.add_finding(
        finding_type='vulnerability',
        description='Anonymous FTP login enabled',
        source='nmap -sV -p 21 192.168.1.100',
        data={'severity': 'medium', 'port': 21, 'service': 'ftp'}
    )

    return profile


def create_test_profile_many_findings():
    """Create profile with 25 findings for pagination test"""
    profile = TargetProfile('192.168.1.100')

    finding_types = ['vulnerability', 'directory', 'credential', 'user', 'note']

    for i in range(25):
        finding_type = finding_types[i % len(finding_types)]
        profile.add_finding(
            finding_type=finding_type,
            description=f'Finding #{i+1} - {finding_type} discovered during enumeration phase',
            source=f'automated-scanner-{i+1}',
            data={'test_index': i}
        )

    return profile


def main():
    """Run visual tests for all panel states"""
    console = Console()

    # Test 1: Empty state
    console.print("\n[bold cyan]═══ Test 1: Empty State ═══[/]\n")
    profile_empty = create_test_profile_empty()
    panel, choices = FindingsPanel.render(profile_empty)
    console.print(panel)
    console.print(f"\n[dim]Choices generated: {len(choices)}[/]")
    input("\nPress ENTER to continue...")

    # Test 2: With findings (all types)
    console.print("\n[bold cyan]═══ Test 2: With Findings (All Types) ═══[/]\n")
    profile_findings = create_test_profile_with_findings()
    panel, choices = FindingsPanel.render(profile_findings, filter_type='all', page=1)
    console.print(panel)
    console.print(f"\n[dim]Choices generated: {len(choices)}[/]")
    console.print(f"[dim]Selection choices: {[c['id'] for c in choices if c['id'].isdigit()]}[/]")
    input("\nPress ENTER to continue...")

    # Test 3: Filtered by vulnerability
    console.print("\n[bold cyan]═══ Test 3: Filtered by Vulnerability ═══[/]\n")
    panel, choices = FindingsPanel.render(profile_findings, filter_type='vulnerability', page=1)
    console.print(panel)
    console.print(f"\n[dim]Choices generated: {len(choices)}[/]")
    input("\nPress ENTER to continue...")

    # Test 4: Filtered by directory
    console.print("\n[bold cyan]═══ Test 4: Filtered by Directory ═══[/]\n")
    panel, choices = FindingsPanel.render(profile_findings, filter_type='directory', page=1)
    console.print(panel)
    console.print(f"\n[dim]Choices generated: {len(choices)}[/]")
    input("\nPress ENTER to continue...")

    # Test 5: Pagination (page 1)
    console.print("\n[bold cyan]═══ Test 5: Pagination - Page 1 of 3 ═══[/]\n")
    profile_many = create_test_profile_many_findings()
    panel, choices = FindingsPanel.render(profile_many, filter_type='all', page=1)
    console.print(panel)
    console.print(f"\n[dim]Choices generated: {len(choices)}[/]")
    console.print(f"[dim]Has next page: {'n' in [c['id'] for c in choices]}[/]")
    console.print(f"[dim]Has prev page: {'p' in [c['id'] for c in choices]}[/]")
    input("\nPress ENTER to continue...")

    # Test 6: Pagination (page 2)
    console.print("\n[bold cyan]═══ Test 6: Pagination - Page 2 of 3 ═══[/]\n")
    panel, choices = FindingsPanel.render(profile_many, filter_type='all', page=2)
    console.print(panel)
    console.print(f"\n[dim]Choices generated: {len(choices)}[/]")
    console.print(f"[dim]Has next page: {'n' in [c['id'] for c in choices]}[/]")
    console.print(f"[dim]Has prev page: {'p' in [c['id'] for c in choices]}[/]")
    input("\nPress ENTER to continue...")

    # Test 7: Pagination (page 3 - last)
    console.print("\n[bold cyan]═══ Test 7: Pagination - Page 3 of 3 (Last) ═══[/]\n")
    panel, choices = FindingsPanel.render(profile_many, filter_type='all', page=3)
    console.print(panel)
    console.print(f"\n[dim]Choices generated: {len(choices)}[/]")
    console.print(f"[dim]Has next page: {'n' in [c['id'] for c in choices]}[/]")
    console.print(f"[dim]Has prev page: {'p' in [c['id'] for c in choices]}[/]")
    input("\nPress ENTER to continue...")

    console.print("\n[bold green]✓ All visual tests complete![/]\n")


if __name__ == '__main__':
    main()
