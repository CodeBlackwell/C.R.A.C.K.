"""
Engagement CLI Commands

Provides CLI interface for engagement tracking:
- Client management (create, list, show)
- Engagement management (create, list, activate, status)
- Target management (add, list, show, services)
- Finding management (add, list, link)
"""

import sys
from typing import Optional, List

from crack.core.themes import Colors
from crack.tools.engagement.adapter import EngagementAdapter
from crack.tools.engagement.models import (
    FindingSeverity,
    EngagementStatus,
    TargetStatus,
)
from crack.tools.engagement.storage import (
    get_active_engagement_id,
    clear_active_engagement,
)


# =============================================================================
# Client Commands
# =============================================================================

def client_create(args: List[str]) -> int:
    """Create a new client"""
    if not args:
        print(f"{Colors.RED}Error:{Colors.END} Client name required")
        print("Usage: crack engagement client create <name> [--org <organization>]")
        return 1

    name = args[0]
    organization = ""

    # Parse --org flag
    if '--org' in args:
        idx = args.index('--org')
        if idx + 1 < len(args):
            organization = args[idx + 1]

    adapter = EngagementAdapter()
    try:
        client_id = adapter.create_client(name, organization=organization)
        print(f"{Colors.GREEN}✓{Colors.END} Created client: {Colors.CYAN}{name}{Colors.END}")
        print(f"  ID: {Colors.YELLOW}{client_id}{Colors.END}")
        if organization:
            print(f"  Organization: {organization}")
        return 0
    except Exception as e:
        print(f"{Colors.RED}✗ Error:{Colors.END} {e}")
        return 1


def client_list(args: List[str]) -> int:
    """List all clients"""
    adapter = EngagementAdapter()
    try:
        clients = adapter.list_clients()

        if not clients:
            print(f"{Colors.YELLOW}No clients found{Colors.END}")
            print("Create one with: crack engagement client create <name>")
            return 0

        print(f"\n{Colors.CYAN}{'=' * 60}{Colors.END}")
        print(f"{Colors.BOLD}CLIENTS ({len(clients)}){Colors.END}")
        print(f"{Colors.CYAN}{'=' * 60}{Colors.END}\n")

        for client in clients:
            print(f"  {Colors.CYAN}•{Colors.END} {Colors.BOLD}{client.name}{Colors.END}")
            print(f"    ID: {Colors.YELLOW}{client.id}{Colors.END}")
            if client.organization:
                print(f"    Org: {client.organization}")
            print()

        return 0
    except Exception as e:
        print(f"{Colors.RED}✗ Error:{Colors.END} {e}")
        return 1


def client_show(args: List[str]) -> int:
    """Show client details"""
    if not args:
        print(f"{Colors.RED}Error:{Colors.END} Client ID required")
        print("Usage: crack engagement client show <client_id>")
        return 1

    client_id = args[0]
    adapter = EngagementAdapter()

    try:
        client = adapter.get_client(client_id)

        if not client:
            print(f"{Colors.RED}✗ Client not found:{Colors.END} {client_id}")
            return 1

        print(f"\n{Colors.CYAN}{'=' * 60}{Colors.END}")
        print(f"{Colors.BOLD}CLIENT: {client.name}{Colors.END}")
        print(f"{Colors.CYAN}{'=' * 60}{Colors.END}\n")

        print(f"  ID:           {Colors.YELLOW}{client.id}{Colors.END}")
        print(f"  Name:         {client.name}")
        print(f"  Organization: {client.organization or '(not set)'}")
        print(f"  Contact:      {client.contact_email or '(not set)'}")
        print(f"  Industry:     {client.industry or '(not set)'}")
        print(f"  Created:      {client.created_at}")

        if client.notes:
            print(f"\n  Notes: {client.notes}")

        # List engagements for this client
        engagements = adapter.list_engagements(client_id=client_id)
        if engagements:
            print(f"\n  {Colors.CYAN}Engagements ({len(engagements)}):{Colors.END}")
            for eng in engagements:
                status_color = Colors.GREEN if eng.status == EngagementStatus.ACTIVE else Colors.YELLOW
                print(f"    • {eng.name} [{status_color}{eng.status.value}{Colors.END}]")

        print()
        return 0
    except Exception as e:
        print(f"{Colors.RED}✗ Error:{Colors.END} {e}")
        return 1


# =============================================================================
# Engagement Commands
# =============================================================================

def engagement_create(args: List[str]) -> int:
    """Create a new engagement"""
    if not args:
        print(f"{Colors.RED}Error:{Colors.END} Engagement name required")
        print("Usage: crack engagement create <name> --client <client_id> [--scope <type>]")
        return 1

    name = args[0]
    client_id = None
    scope_type = ""

    # Parse flags
    if '--client' in args:
        idx = args.index('--client')
        if idx + 1 < len(args):
            client_id = args[idx + 1]

    if '--scope' in args:
        idx = args.index('--scope')
        if idx + 1 < len(args):
            scope_type = args[idx + 1]

    if not client_id:
        print(f"{Colors.RED}Error:{Colors.END} --client <client_id> is required")
        print("Use 'crack engagement client list' to see available clients")
        return 1

    adapter = EngagementAdapter()
    try:
        eng_id = adapter.create_engagement(name, client_id, scope_type=scope_type)
        print(f"{Colors.GREEN}✓{Colors.END} Created engagement: {Colors.CYAN}{name}{Colors.END}")
        print(f"  ID: {Colors.YELLOW}{eng_id}{Colors.END}")
        print(f"\nTo activate: crack engagement activate {eng_id}")
        return 0
    except Exception as e:
        print(f"{Colors.RED}✗ Error:{Colors.END} {e}")
        return 1


def engagement_list(args: List[str]) -> int:
    """List engagements"""
    client_id = None

    # Parse --client flag
    if '--client' in args:
        idx = args.index('--client')
        if idx + 1 < len(args):
            client_id = args[idx + 1]

    adapter = EngagementAdapter()
    active_id = get_active_engagement_id()

    try:
        engagements = adapter.list_engagements(client_id=client_id)

        if not engagements:
            print(f"{Colors.YELLOW}No engagements found{Colors.END}")
            print("Create one with: crack engagement create <name> --client <client_id>")
            return 0

        print(f"\n{Colors.CYAN}{'=' * 70}{Colors.END}")
        print(f"{Colors.BOLD}ENGAGEMENTS ({len(engagements)}){Colors.END}")
        print(f"{Colors.CYAN}{'=' * 70}{Colors.END}\n")

        for eng in engagements:
            is_active = eng.id == active_id
            status_color = Colors.GREEN if eng.status == EngagementStatus.ACTIVE else Colors.YELLOW

            active_marker = f" {Colors.GREEN}[ACTIVE]{Colors.END}" if is_active else ""
            print(f"  {Colors.CYAN}•{Colors.END} {Colors.BOLD}{eng.name}{Colors.END}{active_marker}")
            print(f"    ID: {Colors.YELLOW}{eng.id}{Colors.END}")
            print(f"    Status: [{status_color}{eng.status.value}{Colors.END}]")
            print(f"    Started: {eng.start_date or '(not set)'}")
            if eng.scope_type:
                print(f"    Scope: {eng.scope_type}")
            print()

        return 0
    except Exception as e:
        print(f"{Colors.RED}✗ Error:{Colors.END} {e}")
        return 1


def engagement_activate(args: List[str]) -> int:
    """Activate an engagement"""
    if not args:
        print(f"{Colors.RED}Error:{Colors.END} Engagement ID required")
        print("Usage: crack engagement activate <engagement_id>")
        print("\nUse 'crack engagement list' to see available engagements")
        return 1

    eng_id = args[0]
    adapter = EngagementAdapter()

    try:
        adapter.set_active_engagement(eng_id)
        eng = adapter.get_engagement(eng_id)

        if eng:
            print(f"{Colors.GREEN}✓{Colors.END} Activated engagement: {Colors.CYAN}{eng.name}{Colors.END}")
            print(f"  ID: {Colors.YELLOW}{eng_id}{Colors.END}")
        else:
            print(f"{Colors.GREEN}✓{Colors.END} Activated engagement: {Colors.YELLOW}{eng_id}{Colors.END}")

        print(f"\nAll tool output will now be logged to this engagement.")
        return 0
    except Exception as e:
        print(f"{Colors.RED}✗ Error:{Colors.END} {e}")
        return 1


def engagement_deactivate(args: List[str]) -> int:
    """Deactivate current engagement"""
    clear_active_engagement()
    print(f"{Colors.GREEN}✓{Colors.END} Engagement deactivated")
    print("Tool output will no longer be logged to an engagement.")
    return 0


def engagement_status(args: List[str]) -> int:
    """Show current engagement status"""
    adapter = EngagementAdapter()
    active_id = get_active_engagement_id()

    if not active_id:
        print(f"{Colors.YELLOW}No active engagement{Colors.END}")
        print("Use 'crack engagement activate <id>' to set one")
        return 0

    try:
        eng = adapter.get_engagement(active_id)

        if not eng:
            print(f"{Colors.RED}✗ Active engagement not found:{Colors.END} {active_id}")
            print("Consider clearing with: crack engagement deactivate")
            return 1

        print(f"\n{Colors.CYAN}{'=' * 70}{Colors.END}")
        print(f"{Colors.BOLD}ACTIVE ENGAGEMENT: {eng.name}{Colors.END}")
        print(f"{Colors.CYAN}{'=' * 70}{Colors.END}\n")

        print(f"  ID:         {Colors.YELLOW}{eng.id}{Colors.END}")
        print(f"  Status:     [{Colors.GREEN}{eng.status.value}{Colors.END}]")
        print(f"  Started:    {eng.start_date or '(not set)'}")
        print(f"  Scope Type: {eng.scope_type or '(not set)'}")

        if eng.scope_text:
            print(f"\n  Scope:\n    {eng.scope_text}")

        # Get stats
        stats = adapter.get_engagement_stats(active_id)
        if stats:
            print(f"\n  {Colors.CYAN}Statistics:{Colors.END}")
            print(f"    Targets:  {stats.get('targets', 0)}")
            print(f"    Services: {stats.get('services', 0)}")
            print(f"    Findings: {stats.get('findings', 0)}")

        print()
        return 0
    except Exception as e:
        print(f"{Colors.RED}✗ Error:{Colors.END} {e}")
        return 1


def engagement_scope(args: List[str]) -> int:
    """Manage engagement scope"""
    if not args or args[0] not in ['add', 'show']:
        print(f"{Colors.CYAN}Engagement Scope Management{Colors.END}\n")
        print("Usage:")
        print("  crack engagement scope add <ip_or_cidr>  - Add target to scope")
        print("  crack engagement scope show              - Show current scope")
        return 1

    action = args[0]
    adapter = EngagementAdapter()
    active_id = get_active_engagement_id()

    if not active_id:
        print(f"{Colors.RED}Error:{Colors.END} No active engagement")
        print("Use 'crack engagement activate <id>' first")
        return 1

    if action == 'add':
        if len(args) < 2:
            print(f"{Colors.RED}Error:{Colors.END} Target IP or CIDR required")
            return 1

        ip_or_cidr = args[1]
        try:
            target_id = adapter.add_target(active_id, ip_or_cidr)
            print(f"{Colors.GREEN}✓{Colors.END} Added to scope: {Colors.CYAN}{ip_or_cidr}{Colors.END}")
            print(f"  Target ID: {Colors.YELLOW}{target_id}{Colors.END}")
            return 0
        except Exception as e:
            print(f"{Colors.RED}✗ Error:{Colors.END} {e}")
            return 1

    elif action == 'show':
        try:
            eng = adapter.get_engagement(active_id)
            if eng and eng.scope_text:
                print(f"\n{Colors.CYAN}Scope for: {eng.name}{Colors.END}\n")
                print(eng.scope_text)
            else:
                print(f"{Colors.YELLOW}No scope defined{Colors.END}")

            # Also show targets
            targets = adapter.get_targets(active_id)
            if targets:
                print(f"\n{Colors.CYAN}Targets ({len(targets)}):{Colors.END}")
                for t in targets:
                    print(f"  • {t.display_name}")

            return 0
        except Exception as e:
            print(f"{Colors.RED}✗ Error:{Colors.END} {e}")
            return 1

    return 0


# =============================================================================
# Target Commands
# =============================================================================

def target_add(args: List[str]) -> int:
    """Add a target to active engagement"""
    if not args:
        print(f"{Colors.RED}Error:{Colors.END} Target IP or hostname required")
        print("Usage: crack target add <ip_or_hostname> [--hostname <name>] [--os <guess>]")
        return 1

    ip_or_hostname = args[0]
    hostname = ""
    os_guess = ""

    # Parse flags
    if '--hostname' in args:
        idx = args.index('--hostname')
        if idx + 1 < len(args):
            hostname = args[idx + 1]

    if '--os' in args:
        idx = args.index('--os')
        if idx + 1 < len(args):
            os_guess = args[idx + 1]

    adapter = EngagementAdapter()
    active_id = get_active_engagement_id()

    if not active_id:
        print(f"{Colors.RED}Error:{Colors.END} No active engagement")
        print("Use 'crack engagement activate <id>' first")
        return 1

    try:
        target_id = adapter.add_target(
            active_id, ip_or_hostname,
            hostname=hostname, os_guess=os_guess
        )
        print(f"{Colors.GREEN}✓{Colors.END} Added target: {Colors.CYAN}{ip_or_hostname}{Colors.END}")
        print(f"  ID: {Colors.YELLOW}{target_id}{Colors.END}")
        return 0
    except Exception as e:
        print(f"{Colors.RED}✗ Error:{Colors.END} {e}")
        return 1


def target_list(args: List[str]) -> int:
    """List targets in active engagement"""
    adapter = EngagementAdapter()
    active_id = get_active_engagement_id()

    if not active_id:
        print(f"{Colors.RED}Error:{Colors.END} No active engagement")
        print("Use 'crack engagement activate <id>' first")
        return 1

    try:
        targets = adapter.get_targets(active_id)

        if not targets:
            print(f"{Colors.YELLOW}No targets in engagement{Colors.END}")
            print("Add one with: crack target add <ip_or_hostname>")
            return 0

        print(f"\n{Colors.CYAN}{'=' * 60}{Colors.END}")
        print(f"{Colors.BOLD}TARGETS ({len(targets)}){Colors.END}")
        print(f"{Colors.CYAN}{'=' * 60}{Colors.END}\n")

        for target in targets:
            status_color = {
                TargetStatus.NEW: Colors.BRIGHT_BLACK,
                TargetStatus.SCANNING: Colors.YELLOW,
                TargetStatus.ENUMERATED: Colors.CYAN,
                TargetStatus.EXPLOITED: Colors.RED,
                TargetStatus.COMPLETED: Colors.GREEN,
            }.get(target.status, Colors.BRIGHT_BLACK)

            print(f"  {Colors.CYAN}•{Colors.END} {Colors.BOLD}{target.display_name}{Colors.END}")
            print(f"    ID: {Colors.YELLOW}{target.id}{Colors.END}")
            print(f"    Status: [{status_color}{target.status.value}{Colors.END}]")
            if target.os_guess:
                print(f"    OS: {target.os_guess}")

            # Get services
            services = adapter.get_services(target.id)
            if services:
                print(f"    Services: {len(services)}")
            print()

        return 0
    except Exception as e:
        print(f"{Colors.RED}✗ Error:{Colors.END} {e}")
        return 1


def target_show(args: List[str]) -> int:
    """Show target details"""
    if not args:
        print(f"{Colors.RED}Error:{Colors.END} Target ID required")
        print("Usage: crack target show <target_id>")
        return 1

    target_id = args[0]
    adapter = EngagementAdapter()

    try:
        target = adapter.get_target(target_id)

        if not target:
            print(f"{Colors.RED}✗ Target not found:{Colors.END} {target_id}")
            return 1

        print(f"\n{Colors.CYAN}{'=' * 60}{Colors.END}")
        print(f"{Colors.BOLD}TARGET: {target.display_name}{Colors.END}")
        print(f"{Colors.CYAN}{'=' * 60}{Colors.END}\n")

        print(f"  ID:         {Colors.YELLOW}{target.id}{Colors.END}")
        print(f"  IP:         {target.ip_address or '(not set)'}")
        print(f"  Hostname:   {target.hostname or '(not set)'}")
        print(f"  OS:         {target.os_guess or '(not set)'}")
        print(f"  Status:     {target.status.value}")
        print(f"  First Seen: {target.first_seen}")

        if target.notes:
            print(f"\n  Notes: {target.notes}")

        # List services
        services = adapter.get_services(target_id)
        if services:
            print(f"\n  {Colors.CYAN}Services ({len(services)}):{Colors.END}")
            for svc in services:
                print(f"    • {svc.display_name}")

        print()
        return 0
    except Exception as e:
        print(f"{Colors.RED}✗ Error:{Colors.END} {e}")
        return 1


def target_services(args: List[str]) -> int:
    """List services on a target"""
    if not args:
        print(f"{Colors.RED}Error:{Colors.END} Target ID required")
        print("Usage: crack target services <target_id>")
        return 1

    target_id = args[0]
    adapter = EngagementAdapter()

    try:
        services = adapter.get_services(target_id)

        if not services:
            print(f"{Colors.YELLOW}No services found for target{Colors.END}")
            return 0

        print(f"\n{Colors.CYAN}SERVICES ({len(services)}){Colors.END}\n")

        for svc in services:
            state_color = Colors.GREEN if svc.state == 'open' else Colors.YELLOW
            print(f"  {Colors.CYAN}•{Colors.END} {Colors.BOLD}{svc.display_name}{Colors.END}")
            print(f"    State: [{state_color}{svc.state}{Colors.END}]")
            if svc.banner:
                print(f"    Banner: {svc.banner[:60]}...")
            print()

        return 0
    except Exception as e:
        print(f"{Colors.RED}✗ Error:{Colors.END} {e}")
        return 1


def target_service_add(args: List[str]) -> int:
    """Add service to target"""
    if len(args) < 2:
        print(f"{Colors.RED}Error:{Colors.END} Target ID and port required")
        print("Usage: crack target service-add <target_id> <port> [--name <service>] [--version <ver>]")
        return 1

    target_id = args[0]
    try:
        port = int(args[1])
    except ValueError:
        print(f"{Colors.RED}Error:{Colors.END} Port must be a number")
        return 1

    service_name = ""
    version = ""

    # Parse flags
    if '--name' in args:
        idx = args.index('--name')
        if idx + 1 < len(args):
            service_name = args[idx + 1]

    if '--version' in args:
        idx = args.index('--version')
        if idx + 1 < len(args):
            version = args[idx + 1]

    adapter = EngagementAdapter()

    try:
        svc_id = adapter.add_service(target_id, port, service_name=service_name, version=version)
        print(f"{Colors.GREEN}✓{Colors.END} Added service: {Colors.CYAN}{port}/tcp{Colors.END}")
        print(f"  ID: {Colors.YELLOW}{svc_id}{Colors.END}")
        return 0
    except Exception as e:
        print(f"{Colors.RED}✗ Error:{Colors.END} {e}")
        return 1


# =============================================================================
# Finding Commands
# =============================================================================

def finding_add(args: List[str]) -> int:
    """Add a finding to active engagement"""
    if not args:
        print(f"{Colors.RED}Error:{Colors.END} Finding title required")
        print("Usage: crack finding add <title> --severity <level> [--cve <CVE-ID>]")
        print("\nSeverity levels: critical, high, medium, low, info")
        return 1

    title = args[0]
    severity = "medium"
    cve_id = ""
    description = ""

    # Parse flags
    if '--severity' in args:
        idx = args.index('--severity')
        if idx + 1 < len(args):
            severity = args[idx + 1].lower()

    if '--cve' in args:
        idx = args.index('--cve')
        if idx + 1 < len(args):
            cve_id = args[idx + 1]

    if '--description' in args:
        idx = args.index('--description')
        if idx + 1 < len(args):
            description = args[idx + 1]

    # Validate severity
    valid_severities = ['critical', 'high', 'medium', 'low', 'info']
    if severity not in valid_severities:
        print(f"{Colors.RED}Error:{Colors.END} Invalid severity: {severity}")
        print(f"Valid options: {', '.join(valid_severities)}")
        return 1

    adapter = EngagementAdapter()
    active_id = get_active_engagement_id()

    if not active_id:
        print(f"{Colors.RED}Error:{Colors.END} No active engagement")
        print("Use 'crack engagement activate <id>' first")
        return 1

    try:
        finding_id = adapter.add_finding(
            active_id, title,
            severity=severity,
            cve_id=cve_id,
            description=description
        )

        severity_color = {
            'critical': Colors.RED,
            'high': Colors.RED,
            'medium': Colors.YELLOW,
            'low': Colors.CYAN,
            'info': Colors.BRIGHT_BLACK,
        }.get(severity, Colors.BRIGHT_BLACK)

        print(f"{Colors.GREEN}✓{Colors.END} Added finding: {Colors.CYAN}{title}{Colors.END}")
        print(f"  ID: {Colors.YELLOW}{finding_id}{Colors.END}")
        print(f"  Severity: [{severity_color}{severity.upper()}{Colors.END}]")
        if cve_id:
            print(f"  CVE: {cve_id}")
        return 0
    except Exception as e:
        print(f"{Colors.RED}✗ Error:{Colors.END} {e}")
        return 1


def finding_list(args: List[str]) -> int:
    """List findings in active engagement"""
    severity_filter = None

    # Parse --severity flag
    if '--severity' in args:
        idx = args.index('--severity')
        if idx + 1 < len(args):
            severity_filter = args[idx + 1].lower()

    adapter = EngagementAdapter()
    active_id = get_active_engagement_id()

    if not active_id:
        print(f"{Colors.RED}Error:{Colors.END} No active engagement")
        print("Use 'crack engagement activate <id>' first")
        return 1

    try:
        findings = adapter.get_findings(active_id)

        # Filter by severity if specified
        if severity_filter:
            findings = [f for f in findings if f.severity.value == severity_filter]

        if not findings:
            print(f"{Colors.YELLOW}No findings in engagement{Colors.END}")
            print("Add one with: crack finding add <title> --severity <level>")
            return 0

        print(f"\n{Colors.CYAN}{'=' * 70}{Colors.END}")
        print(f"{Colors.BOLD}FINDINGS ({len(findings)}){Colors.END}")
        print(f"{Colors.CYAN}{'=' * 70}{Colors.END}\n")

        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        findings.sort(key=lambda f: severity_order.get(f.severity.value, 5))

        for finding in findings:
            severity_color = {
                FindingSeverity.CRITICAL: Colors.RED,
                FindingSeverity.HIGH: Colors.RED,
                FindingSeverity.MEDIUM: Colors.YELLOW,
                FindingSeverity.LOW: Colors.CYAN,
                FindingSeverity.INFO: Colors.BRIGHT_BLACK,
            }.get(finding.severity, Colors.BRIGHT_BLACK)

            print(f"  [{severity_color}{finding.severity.value.upper():8}{Colors.END}] "
                  f"{Colors.BOLD}{finding.title}{Colors.END}")
            print(f"    ID: {Colors.YELLOW}{finding.id}{Colors.END}")
            if finding.cve_id:
                print(f"    CVE: {finding.cve_id}")
            print()

        return 0
    except Exception as e:
        print(f"{Colors.RED}✗ Error:{Colors.END} {e}")
        return 1


def finding_link(args: List[str]) -> int:
    """Link a finding to a target"""
    if not args:
        print(f"{Colors.RED}Error:{Colors.END} Finding ID required")
        print("Usage: crack finding link <finding_id> --target <target_id>")
        return 1

    finding_id = args[0]
    target_id = None

    # Parse --target flag
    if '--target' in args:
        idx = args.index('--target')
        if idx + 1 < len(args):
            target_id = args[idx + 1]

    if not target_id:
        print(f"{Colors.RED}Error:{Colors.END} --target <target_id> is required")
        return 1

    adapter = EngagementAdapter()

    try:
        adapter.link_finding_to_target(finding_id, target_id)
        print(f"{Colors.GREEN}✓{Colors.END} Linked finding to target")
        print(f"  Finding: {Colors.YELLOW}{finding_id}{Colors.END}")
        print(f"  Target:  {Colors.YELLOW}{target_id}{Colors.END}")
        return 0
    except Exception as e:
        print(f"{Colors.RED}✗ Error:{Colors.END} {e}")
        return 1


def finding_show(args: List[str]) -> int:
    """Show finding details"""
    if not args:
        print(f"{Colors.RED}Error:{Colors.END} Finding ID required")
        print("Usage: crack finding show <finding_id>")
        return 1

    finding_id = args[0]
    adapter = EngagementAdapter()

    try:
        finding = adapter.get_finding(finding_id)

        if not finding:
            print(f"{Colors.RED}✗ Finding not found:{Colors.END} {finding_id}")
            return 1

        severity_color = {
            FindingSeverity.CRITICAL: Colors.RED,
            FindingSeverity.HIGH: Colors.RED,
            FindingSeverity.MEDIUM: Colors.YELLOW,
            FindingSeverity.LOW: Colors.CYAN,
            FindingSeverity.INFO: Colors.BRIGHT_BLACK,
        }.get(finding.severity, Colors.BRIGHT_BLACK)

        print(f"\n{Colors.CYAN}{'=' * 70}{Colors.END}")
        print(f"{Colors.BOLD}FINDING: {finding.title}{Colors.END}")
        print(f"{Colors.CYAN}{'=' * 70}{Colors.END}\n")

        print(f"  ID:         {Colors.YELLOW}{finding.id}{Colors.END}")
        print(f"  Severity:   [{severity_color}{finding.severity.value.upper()}{Colors.END}]")
        if finding.cvss_score:
            print(f"  CVSS:       {finding.cvss_score}")
        if finding.cve_id:
            print(f"  CVE:        {finding.cve_id}")
        print(f"  Status:     {finding.status.value}")
        print(f"  Found:      {finding.found_at}")

        if finding.description:
            print(f"\n  Description:\n    {finding.description}")

        if finding.impact:
            print(f"\n  Impact:\n    {finding.impact}")

        if finding.remediation:
            print(f"\n  Remediation:\n    {finding.remediation}")

        if finding.evidence:
            print(f"\n  Evidence:\n    {finding.evidence[:200]}...")

        print()
        return 0
    except Exception as e:
        print(f"{Colors.RED}✗ Error:{Colors.END} {e}")
        return 1


# =============================================================================
# Main Command Dispatchers
# =============================================================================

def engagement_command(args: List[str]) -> int:
    """Main engagement command dispatcher"""
    if not args:
        print(f"{Colors.CYAN}CRACK Engagement Tracking{Colors.END}\n")
        print(f"{Colors.YELLOW}Usage:{Colors.END}")
        print("  crack engagement client <action>     - Manage clients")
        print("  crack engagement create <name>       - Create engagement")
        print("  crack engagement list                - List engagements")
        print("  crack engagement activate <id>       - Activate engagement")
        print("  crack engagement deactivate          - Deactivate engagement")
        print("  crack engagement status              - Show active engagement")
        print("  crack engagement scope <action>      - Manage scope")
        print(f"\n{Colors.YELLOW}Client Actions:{Colors.END}")
        print("  crack engagement client create <name> [--org <org>]")
        print("  crack engagement client list")
        print("  crack engagement client show <id>")
        print(f"\n{Colors.YELLOW}Examples:{Colors.END}")
        print("  crack engagement client create 'ACME Corp' --org 'ACME Corporation'")
        print("  crack engagement create 'Q4 Pentest' --client client-abc123")
        print("  crack engagement activate eng-xyz789")
        return 0

    subcommand = args[0]
    subargs = args[1:]

    # Client subcommands
    if subcommand == 'client':
        if not subargs:
            print(f"{Colors.CYAN}Client Management{Colors.END}\n")
            print("Usage:")
            print("  crack engagement client create <name> [--org <organization>]")
            print("  crack engagement client list")
            print("  crack engagement client show <client_id>")
            return 0

        action = subargs[0]
        action_args = subargs[1:]

        if action == 'create':
            return client_create(action_args)
        elif action == 'list':
            return client_list(action_args)
        elif action == 'show':
            return client_show(action_args)
        else:
            print(f"{Colors.RED}Error:{Colors.END} Unknown client action: {action}")
            return 1

    # Engagement subcommands
    elif subcommand == 'create':
        return engagement_create(subargs)
    elif subcommand == 'list':
        return engagement_list(subargs)
    elif subcommand == 'activate':
        return engagement_activate(subargs)
    elif subcommand == 'deactivate':
        return engagement_deactivate(subargs)
    elif subcommand == 'status':
        return engagement_status(subargs)
    elif subcommand == 'scope':
        return engagement_scope(subargs)
    else:
        print(f"{Colors.RED}Error:{Colors.END} Unknown subcommand: {subcommand}")
        print("Use 'crack engagement' to see available commands")
        return 1


def target_command(args: List[str]) -> int:
    """Main target command dispatcher"""
    if not args:
        print(f"{Colors.CYAN}CRACK Target Management{Colors.END}\n")
        print(f"{Colors.YELLOW}Usage:{Colors.END}")
        print("  crack target add <ip_or_hostname>     - Add target to engagement")
        print("  crack target list                     - List targets")
        print("  crack target show <id>                - Show target details")
        print("  crack target services <id>            - List services on target")
        print("  crack target service-add <id> <port>  - Add service to target")
        print(f"\n{Colors.YELLOW}Examples:{Colors.END}")
        print("  crack target add 192.168.1.100 --hostname web01.local")
        print("  crack target service-add target-abc123 80 --name http")
        return 0

    subcommand = args[0]
    subargs = args[1:]

    if subcommand == 'add':
        return target_add(subargs)
    elif subcommand == 'list':
        return target_list(subargs)
    elif subcommand == 'show':
        return target_show(subargs)
    elif subcommand == 'services':
        return target_services(subargs)
    elif subcommand == 'service-add':
        return target_service_add(subargs)
    else:
        print(f"{Colors.RED}Error:{Colors.END} Unknown subcommand: {subcommand}")
        print("Use 'crack target' to see available commands")
        return 1


def finding_command(args: List[str]) -> int:
    """Main finding command dispatcher"""
    if not args:
        print(f"{Colors.CYAN}CRACK Finding Management{Colors.END}\n")
        print(f"{Colors.YELLOW}Usage:{Colors.END}")
        print("  crack finding add <title>             - Add finding")
        print("  crack finding list                    - List findings")
        print("  crack finding show <id>               - Show finding details")
        print("  crack finding link <id> --target <id> - Link to target")
        print(f"\n{Colors.YELLOW}Severity Levels:{Colors.END}")
        print("  critical, high, medium, low, info")
        print(f"\n{Colors.YELLOW}Examples:{Colors.END}")
        print("  crack finding add 'SQL Injection' --severity critical --cve CVE-2024-1234")
        print("  crack finding list --severity critical")
        print("  crack finding link finding-abc123 --target target-xyz789")
        return 0

    subcommand = args[0]
    subargs = args[1:]

    if subcommand == 'add':
        return finding_add(subargs)
    elif subcommand == 'list':
        return finding_list(subargs)
    elif subcommand == 'show':
        return finding_show(subargs)
    elif subcommand == 'link':
        return finding_link(subargs)
    else:
        print(f"{Colors.RED}Error:{Colors.END} Unknown subcommand: {subcommand}")
        print("Use 'crack finding' to see available commands")
        return 1


if __name__ == '__main__':
    # Test CLI
    print("Testing engagement CLI...")
    engagement_command([])
