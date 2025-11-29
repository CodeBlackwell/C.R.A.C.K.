"""
Blood-trail DRY Command Display

Tabular display functions for attack command suggestions.
Shows template ONCE, then lists targets in compact table format.
"""

from typing import List, Dict, Optional
from .command_suggester import CommandTable, TargetEntry, AttackSequence
from .command_mappings import ACCESS_TYPE_PHASES


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


def print_command_tables(
    tables: List[CommandTable],
    use_colors: bool = True,
    max_targets: int = 20
) -> None:
    """
    Print DRY tabular output for command tables.

    Each command shows:
    - Name + access type badge
    - Template (shown ONCE)
    - Variables needed (if any)
    - Table of targets with ready-to-run commands

    Args:
        tables: List of CommandTable objects
        use_colors: Enable ANSI colors
        max_targets: Maximum targets to show per table
    """
    c = Colors if use_colors else _NoColors

    for table in tables:
        if not table.targets:
            continue

        # Access type badge
        badge = f"[{table.access_type}]" if table.access_type else ""

        # Header: Command name + badge
        print(f"\n{c.BOLD}{table.name}{c.RESET} {c.CYAN}{badge}{c.RESET}")

        # Objective (what the command achieves)
        if table.objective:
            print(f"Objective: {table.objective}")

        # Rewards (practical application)
        if table.rewards:
            print(f"Rewards:   {c.YELLOW}{table.rewards}{c.RESET}")

        # Template (shown ONCE)
        print(f"{c.DIM}Template:  {table.template}{c.RESET}")

        # Example (if available and different from template)
        if table.example and table.example != table.template:
            print(f"{c.GREEN}Example:   {table.example}{c.RESET}")

        # Variables needed
        if table.variables_needed:
            print(f"{c.YELLOW}Need: {', '.join(table.variables_needed)}{c.RESET}")

        # Permissions required (new field)
        if table.permissions_required:
            print(f"{c.CYAN}Requires: {table.permissions_required}{c.RESET}")

        # Table header - adjust columns for discovery commands
        if table.is_discovery:
            # Discovery commands find targets, attacker provides their own creds
            print(f"\n  {'Discovered':<25} {'Domain':<20} {'Info':<40} {'Ready Command'}")
        else:
            print(f"\n  {'User':<25} {'Target':<20} {'Reason':<40} {'Ready Command'}")
        print(f"  {'-'*25} {'-'*20} {'-'*40} {'-'*50}")

        # Target rows
        displayed = 0
        for entry in table.targets[:max_targets]:
            user_short = _truncate(entry.user, 23)
            target_short = _truncate(entry.target, 18)

            # Build reason with warnings prefix
            warning_str = " ".join(entry.warnings) if entry.warnings else ""
            if warning_str:
                reason_display = f"{c.RED}{warning_str}{c.RESET} {entry.reason}"
                reason_short = _truncate(f"{warning_str} {entry.reason}", 38)
            else:
                reason_display = entry.reason
                reason_short = _truncate(entry.reason, 38) if entry.reason else ""

            # Color reason yellow, but warnings are red (handled above)
            if warning_str:
                print(f"  {user_short:<25} {target_short:<20} {c.RED}{_truncate(warning_str, 15):<16}{c.RESET}{c.YELLOW}{_truncate(entry.reason, 22):<24}{c.RESET} {c.GREEN}{entry.ready_command}{c.RESET}")
            else:
                print(f"  {user_short:<25} {target_short:<20} {c.YELLOW}{reason_short:<40}{c.RESET} {c.GREEN}{entry.ready_command}{c.RESET}")
            displayed += 1

        # Show truncation notice
        if len(table.targets) > max_targets:
            remaining = len(table.targets) - max_targets
            print(f"  {c.DIM}... and {remaining} more targets{c.RESET}")

        print()  # Spacing between tables


def print_command_tables_by_phase(
    tables: List[CommandTable],
    use_colors: bool = True
) -> None:
    """
    Print command tables grouped by attack phase.

    Phases:
    - Quick Wins
    - Lateral Movement
    - Privilege Escalation
    """
    c = Colors if use_colors else _NoColors

    # Group by phase
    phases = {
        "Quick Wins": [],
        "Lateral Movement": [],
        "Privilege Escalation": [],
        "Other": [],
    }

    for table in tables:
        if not table.targets:
            continue
        phase = table.phase
        if phase not in phases:
            phase = "Other"
        phases[phase].append(table)

    # Print each phase
    for phase_name, phase_tables in phases.items():
        if not phase_tables:
            continue

        # Phase header
        print(f"\n{c.BOLD}{c.CYAN}{'='*70}")
        print(f"  {phase_name.upper()}")
        print(f"{'='*70}{c.RESET}")

        print_command_tables(phase_tables, use_colors)


def print_domain_level_table(
    table: CommandTable,
    principals: List[str],
    use_colors: bool = True
) -> None:
    """
    Print domain-level command (DCSync, etc.) with both formats:
    1. Single ready command template
    2. Expandable list of principals with this right

    Args:
        table: CommandTable for domain-level command
        principals: List of principals with this right (not groups)
        use_colors: Enable ANSI colors
    """
    c = Colors if use_colors else _NoColors

    print(f"\n{c.BOLD}{table.name}{c.RESET} {c.CYAN}[{table.access_type}]{c.RESET}")

    # Objective (what the command achieves)
    if table.objective:
        print(f"Objective: {table.objective}")

    # Rewards (practical application)
    if table.rewards:
        print(f"Rewards:   {c.YELLOW}{table.rewards}{c.RESET}")

    print(f"{c.DIM}Template:  {table.template}{c.RESET}")

    # Example (if available and different from template)
    if table.example and table.example != table.template:
        print(f"{c.GREEN}Example:   {table.example}{c.RESET}")

    if table.variables_needed:
        print(f"{c.YELLOW}Need: {', '.join(table.variables_needed)}{c.RESET}")

    print(f"{c.DIM}Access: Domain-level{c.RESET}")

    # Single ready command (example)
    if table.targets:
        print(f"\n  {c.GREEN}Ready: {table.targets[0].ready_command}{c.RESET}")

    # Principals with this right
    if principals:
        print(f"\n  Principals with DCSync rights:")
        print(f"  {c.DIM}{'+'*40}{c.RESET}")
        for p in principals[:10]:
            print(f"  {c.DIM}|{c.RESET} {p}")
        if len(principals) > 10:
            print(f"  {c.DIM}| ... and {len(principals) - 10} more{c.RESET}")
        print(f"  {c.DIM}{'+'*40}{c.RESET}")

    print()


def format_table_markdown(table: CommandTable) -> str:
    """
    Format CommandTable as markdown for report output.

    Returns:
        Markdown string
    """
    lines = []

    badge = f"[{table.access_type}]" if table.access_type else ""
    lines.append(f"### {table.name} {badge}")
    lines.append("")

    if table.objective:
        lines.append(f"**Objective:** {table.objective}")

    if table.rewards:
        lines.append(f"**Rewards:** {table.rewards}")

    lines.append(f"**Template:** `{table.template}`")

    if table.example and table.example != table.template:
        lines.append(f"**Example:** `{table.example}`")

    if table.variables_needed:
        lines.append(f"**Need:** {', '.join(table.variables_needed)}")

    if table.permissions_required:
        lines.append(f"**Requires:** {table.permissions_required}")

    lines.append("")
    # Adjust column headers for discovery commands
    if table.is_discovery:
        lines.append("| Discovered | Domain | Warnings | Info | Ready Command |")
    else:
        lines.append("| User | Target | Warnings | Reason | Ready Command |")
    lines.append("|------|--------|----------|--------|---------------|")

    for entry in table.targets[:20]:
        user_safe = entry.user.replace("|", "\\|")
        target_safe = entry.target.replace("|", "\\|")
        warnings_safe = " ".join(entry.warnings).replace("|", "\\|") if entry.warnings else ""
        reason_safe = (entry.reason or "").replace("|", "\\|")
        cmd_safe = entry.ready_command.replace("|", "\\|")
        lines.append(f"| {user_safe} | {target_safe} | {warnings_safe} | {reason_safe} | `{cmd_safe}` |")

    if len(table.targets) > 20:
        lines.append(f"| ... | ... | ... | ... | *{len(table.targets) - 20} more* |")

    lines.append("")
    return "\n".join(lines)


def format_tables_markdown(tables: List[CommandTable]) -> str:
    """Format all command tables as markdown grouped by phase"""
    lines = ["## Attack Commands", ""]

    # Group by phase
    phases = {"Quick Wins": [], "Lateral Movement": [], "Privilege Escalation": [], "Other": []}
    for table in tables:
        if table.targets:
            phase = table.phase if table.phase in phases else "Other"
            phases[phase].append(table)

    for phase_name, phase_tables in phases.items():
        if not phase_tables:
            continue
        lines.append(f"### {phase_name}")
        lines.append("")
        for table in phase_tables:
            lines.append(format_table_markdown(table))

    return "\n".join(lines)


def get_table_stats(tables: List[CommandTable]) -> Dict:
    """Get statistics about command tables"""
    total_commands = len(tables)
    total_targets = sum(len(t.targets) for t in tables)

    by_phase = {}
    for table in tables:
        phase = table.phase
        if phase not in by_phase:
            by_phase[phase] = {"commands": 0, "targets": 0}
        by_phase[phase]["commands"] += 1
        by_phase[phase]["targets"] += len(table.targets)

    return {
        "total_commands": total_commands,
        "total_targets": total_targets,
        "by_phase": by_phase,
    }


def print_stats(tables: List[CommandTable], use_colors: bool = True) -> None:
    """Print summary statistics"""
    c = Colors if use_colors else _NoColors
    stats = get_table_stats(tables)

    print(f"{c.DIM}Commands: {stats['total_commands']} | Targets: {stats['total_targets']}{c.RESET}")

    for phase, data in stats["by_phase"].items():
        print(f"  {phase}: {data['commands']} commands, {data['targets']} targets")


# =============================================================================
# POST-SUCCESS SUGGESTIONS
# =============================================================================

def print_post_success(
    post_success: List[Dict],
    domain: str = "",
    dc_ip: str = "<DC_IP>",
    use_colors: bool = True
) -> None:
    """
    Print post-success suggestions after command tables.

    Shows "When You Succeed" next steps for discovery commands
    like Kerberoasting, AS-REP roasting, etc.

    Args:
        post_success: List of {"description": str, "command": str|None}
        domain: Domain for placeholder replacement
        dc_ip: DC IP for placeholder replacement
        use_colors: Enable ANSI colors
    """
    if not post_success:
        return

    c = Colors if use_colors else _NoColors

    print(f"\n  {c.DIM}─── When You Succeed ───────────────────────────────{c.RESET}")

    for i, step in enumerate(post_success, 1):
        desc = step.get("description", "")
        cmd = step.get("command")

        print(f"  {c.CYAN}{i}.{c.RESET} {desc}")
        if cmd:
            # Fill domain/DC placeholders
            cmd = cmd.replace("<DOMAIN>", domain.lower() if domain else "<DOMAIN>")
            cmd = cmd.replace("<DC_IP>", dc_ip)
            print(f"     {c.GREEN}{cmd}{c.RESET}")

    print()


# =============================================================================
# PWNED USER DISPLAY FUNCTIONS
# =============================================================================

def print_pwned_followup_commands(
    user_name: str,
    cred_type: str,
    cred_value: str,
    access: List,  # List[MachineAccess]
    domain_level_access: str = None,
    use_colors: bool = True
) -> None:
    """
    Print follow-up commands after marking a user as pwned.

    Commands are auto-filled with the stored credential value.
    Grouped by privilege level (local-admin, user-level).

    Args:
        user_name: User UPN (USER@DOMAIN.COM)
        cred_type: password, ntlm-hash, kerberos-ticket, certificate
        cred_value: The actual credential value
        access: List of MachineAccess objects
        domain_level_access: 'domain-admin' if user has DA-level rights
        use_colors: Enable ANSI colors
    """
    from .command_mappings import CRED_TYPE_TEMPLATES, fill_pwned_command, infer_dc_hostname

    c = Colors if use_colors else _NoColors

    # Extract username and domain
    if "@" in user_name:
        username, domain = user_name.split("@")
    else:
        username = user_name
        domain = ""

    # Header
    print()
    print(f"{c.BOLD}{'='*70}{c.RESET}")
    print(f"  {c.CYAN}FOLLOW-UP COMMANDS{c.RESET} ({c.BOLD}{user_name}{c.RESET})")
    print(f"{'='*70}")
    print(f"  Credential: {c.YELLOW}{cred_type}{c.RESET} (stored - auto-filled)")
    print()

    # Domain-level access (DCSync)
    if domain_level_access == "domain-admin":
        print(f"{c.RED}{c.BOLD}DOMAIN ADMIN ACCESS{c.RESET} [DCSync] ⚡")
        print()
        print(f"  {'Attack':<22} {'Reason':<40} {'Ready Command'}")
        print(f"  {'-'*22} {'-'*40} {'-'*60}")
        template = CRED_TYPE_TEMPLATES.get(cred_type, {}).get("DCSync")
        if template:
            cmd = fill_pwned_command(
                template,
                username=username,
                domain=domain,
                target=infer_dc_hostname(domain),
                cred_value=cred_value
            )
            print(
                f"  {c.BOLD}{'DCSync':<22}{c.RESET} "
                f"{c.YELLOW}{'Member of Domain Admins':<40}{c.RESET} "
                f"{c.GREEN}{cmd}{c.RESET}"
            )
        print()

    # Group access by privilege level
    admin_access = [a for a in access if a.privilege_level == "local-admin"]
    user_access = [a for a in access if a.privilege_level == "user-level"]
    dcom_access = [a for a in access if a.privilege_level == "dcom-exec"]

    # Local Admin access
    if admin_access:
        print(f"{c.RED}{c.BOLD}LOCAL ADMIN ACCESS{c.RESET} ({len(admin_access)} machines)")
        print()
        print(f"  {'Target':<25} {'Access Path':<35} {'Ready Command'}")
        print(f"  {'-'*25} {'-'*35} {'-'*60}")

        priority_targets = []

        for ma in admin_access[:10]:  # Limit to first 10
            access_path = "direct AdminTo"
            template = CRED_TYPE_TEMPLATES.get(cred_type, {}).get("AdminTo")
            if template:
                cmd = fill_pwned_command(
                    template,
                    username=username,
                    domain=domain,
                    target=ma.computer,
                    cred_value=cred_value
                )
                target_display = _truncate(ma.computer, 23)
                path_display = _truncate(access_path, 33)
                print(
                    f"  {c.BOLD}{target_display:<25}{c.RESET} "
                    f"{c.YELLOW}{path_display:<35}{c.RESET} "
                    f"{c.GREEN}{cmd}{c.RESET}"
                )

            # Track priority targets with sessions
            if ma.sessions:
                priority_targets.append((ma, ma.sessions))

        if len(admin_access) > 10:
            print(f"  {c.DIM}... and {len(admin_access) - 10} more machines{c.RESET}")

        # Priority targets with sessions (secretsdump)
        if priority_targets:
            print()
            print(f"  {c.YELLOW}⚠ PRIORITY TARGETS (privileged sessions detected){c.RESET}")
            print(f"  {'Target':<25} {'Sessions':<35} {'SecretsDump Command'}")
            print(f"  {'-'*25} {'-'*35} {'-'*60}")

            for ma, sessions in priority_targets[:5]:
                sessions_str = ", ".join(sessions[:2])
                sd_template = CRED_TYPE_TEMPLATES.get(cred_type, {}).get("secretsdump")
                if sd_template:
                    sd_cmd = fill_pwned_command(
                        sd_template,
                        username=username,
                        domain=domain,
                        target=ma.computer,
                        cred_value=cred_value
                    )
                    target_display = _truncate(ma.computer, 23)
                    sessions_display = _truncate(sessions_str, 33)
                    print(
                        f"  {c.BOLD}{target_display:<25}{c.RESET} "
                        f"{c.YELLOW}{sessions_display:<35}{c.RESET} "
                        f"{c.GREEN}{sd_cmd}{c.RESET}"
                    )
        print()

    # User-level access (RDP, PSRemote)
    if user_access:
        print(f"{c.BLUE}{c.BOLD}USER-LEVEL ACCESS{c.RESET} ({len(user_access)} machines)")
        print()
        print(f"  {'Target':<25} {'Access Type':<20} {'Ready Command'}")
        print(f"  {'-'*25} {'-'*20} {'-'*60}")

        for ma in user_access[:10]:
            # Determine template based on access type
            if "CanRDP" in ma.access_types:
                template = CRED_TYPE_TEMPLATES.get(cred_type, {}).get("CanRDP")
                access_type = "RDP"
            elif "CanPSRemote" in ma.access_types:
                template = CRED_TYPE_TEMPLATES.get(cred_type, {}).get("CanPSRemote")
                access_type = "WinRM"
            else:
                template = None
                access_type = ", ".join(ma.access_types)

            if template:
                cmd = fill_pwned_command(
                    template,
                    username=username,
                    domain=domain,
                    target=ma.computer,
                    cred_value=cred_value
                )
                target_display = _truncate(ma.computer, 23)
                print(
                    f"  {c.BOLD}{target_display:<25}{c.RESET} "
                    f"{c.YELLOW}{access_type:<20}{c.RESET} "
                    f"{c.GREEN}{cmd}{c.RESET}"
                )

        if len(user_access) > 10:
            print(f"  {c.DIM}... and {len(user_access) - 10} more machines{c.RESET}")
        print()

    # DCOM access
    if dcom_access:
        print(f"{c.BLUE}{c.BOLD}DCOM ACCESS{c.RESET} ({len(dcom_access)} machines)")
        print()
        print(f"  {'Target':<25} {'Access Type':<20} {'Ready Command'}")
        print(f"  {'-'*25} {'-'*20} {'-'*60}")

        for ma in dcom_access[:5]:
            template = CRED_TYPE_TEMPLATES.get(cred_type, {}).get("ExecuteDCOM")
            if template:
                cmd = fill_pwned_command(
                    template,
                    username=username,
                    domain=domain,
                    target=ma.computer,
                    cred_value=cred_value
                )
                target_display = _truncate(ma.computer, 23)
                print(
                    f"  {c.BOLD}{target_display:<25}{c.RESET} "
                    f"{c.YELLOW}{'DCOM':<20}{c.RESET} "
                    f"{c.GREEN}{cmd}{c.RESET}"
                )
            else:
                print(f"  {c.DIM}{ma.computer:<25} DCOM{c.RESET}")
        print()

    # ALWAYS show authenticated user attacks (regardless of edges)
    # Any domain user can run AS-REP Roasting, Kerberoasting, enumeration, etc.
    auth_console, _ = _generate_authenticated_attacks(
        username=username,
        domain=domain,
        cred_type=cred_type,
        cred_value=cred_value,
        use_colors=use_colors
    )
    for line in auth_console:
        print(line)

    # No edge-based access found
    if not admin_access and not user_access and not dcom_access and not domain_level_access:
        print(f"  {c.DIM}No direct machine access via AdminTo/CanRDP/CanPSRemote edges.{c.RESET}")
        print()

    print(f"{'='*70}")
    print()


def print_pwned_users_table(
    users: List,  # List[PwnedUser]
    use_colors: bool = True
) -> None:
    """
    Print a table of all pwned users with their access summary.

    Args:
        users: List of PwnedUser objects
        use_colors: Enable ANSI colors
    """
    c = Colors if use_colors else _NoColors

    if not users:
        print(f"{c.DIM}No pwned users tracked.{c.RESET}")
        print(f"{c.DIM}Mark a user as pwned: bloodtrail --pwn USER@DOMAIN.COM --cred-type password --cred-value 'secret'{c.RESET}")
        return

    # Header
    print()
    print(f"{c.BOLD}{'='*90}{c.RESET}")
    print(f"  {c.CYAN}PWNED USERS{c.RESET} ({len(users)} total)")
    print(f"{'='*90}")
    print()

    # Table header
    print(f"  {'User':<30} {'Cred Type':<15} {'Admin On':<10} {'User On':<10} {'Domain?':<8} {'Pwned At'}")
    print(f"  {'-'*30} {'-'*15} {'-'*10} {'-'*10} {'-'*8} {'-'*20}")

    for user in users:
        # Count access by type
        admin_count = sum(1 for a in user.access if a.privilege_level == "local-admin")
        user_count = sum(1 for a in user.access if a.privilege_level == "user-level")
        domain_marker = "YES" if user.domain_level_access == "domain-admin" else "-"

        # Format timestamp
        pwned_at_str = user.pwned_at.strftime("%Y-%m-%d %H:%M")

        # Color based on privilege level
        if user.domain_level_access == "domain-admin":
            name_color = c.RED
        elif admin_count > 0:
            name_color = c.YELLOW
        else:
            name_color = c.RESET

        print(f"  {name_color}{user.name:<30}{c.RESET} {user.cred_type:<15} {admin_count:<10} {user_count:<10} {domain_marker:<8} {pwned_at_str}")

    print()
    print(f"{c.DIM}Run: bloodtrail --pwn USER -v  to see detailed access for a user{c.RESET}")
    print()


def print_cred_harvest_targets(
    targets: List[Dict],
    use_colors: bool = True
) -> None:
    """
    Print high-priority credential harvest targets.

    These are machines where pwned users have admin AND privileged users have sessions.

    Args:
        targets: List of dicts with pwned_user, target, privileged_sessions
        use_colors: Enable ANSI colors
    """
    from .command_mappings import CRED_TYPE_TEMPLATES, fill_pwned_command

    c = Colors if use_colors else _NoColors

    if not targets:
        print(f"{c.DIM}No high-priority credential harvest targets found.{c.RESET}")
        return

    print()
    print(f"{c.RED}{c.BOLD}{'='*70}{c.RESET}")
    print(f"  {c.RED}PRIORITY CREDENTIAL HARVEST TARGETS{c.RESET}")
    print(f"{c.RED}{'='*70}{c.RESET}")
    print()

    for t in targets[:10]:
        user = t["pwned_user"]
        target = t["target"]
        sessions = t["privileged_sessions"]
        cred_type = t.get("cred_type", "password")
        cred_value = t.get("cred_value", "<PASSWORD>")

        # Extract username/domain
        if "@" in user:
            username, domain = user.split("@")
        else:
            username, domain = user, ""

        print(f"  {c.BOLD}{target}{c.RESET}")
        print(f"    {c.DIM}Pwned user:{c.RESET} {user} ({cred_type})")
        print(f"    {c.YELLOW}High-value sessions:{c.RESET} {', '.join(sessions[:5])}")

        # Secretsdump command
        template = CRED_TYPE_TEMPLATES.get(cred_type, {}).get("secretsdump")
        if template:
            cmd = fill_pwned_command(
                template,
                username=username,
                domain=domain,
                target=target,
                cred_value=cred_value
            )
            print(f"    {c.GREEN}{cmd}{c.RESET}")
        print()

    if len(targets) > 10:
        print(f"  {c.DIM}... and {len(targets) - 10} more targets{c.RESET}")

    print()


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _truncate(s: str, max_len: int) -> str:
    """Truncate string with '..' indicator"""
    if len(s) > max_len:
        return s[:max_len-2] + ".."
    return s


class _NoColors:
    """Dummy colors class for non-colored output"""
    HEADER = ''
    BLUE = ''
    CYAN = ''
    GREEN = ''
    YELLOW = ''
    RED = ''
    BOLD = ''
    DIM = ''
    RESET = ''


# =============================================================================
# PWNED USER ATTACK PATHS (for run_all_queries report)
# =============================================================================

def generate_pwned_attack_paths(driver, use_colors: bool = True) -> tuple:
    """
    Generate Pwned User Attack Paths section for the report.

    Queries Neo4j for pwned users and their access paths, generates
    credential-type-aware commands based on each user's specific privileges.

    Args:
        driver: Neo4j driver instance
        use_colors: Enable ANSI colors for console output

    Returns:
        Tuple of (console_output: str, markdown_output: str)
        Returns ("", "") if no pwned users
    """
    from .command_mappings import CRED_TYPE_TEMPLATES, fill_pwned_command, infer_dc_hostname

    c = Colors if use_colors else _NoColors

    # 1. Fetch all pwned users with credentials
    pwned_users = _fetch_pwned_users(driver)
    if not pwned_users:
        return "", ""

    console_lines = []
    markdown_lines = []

    # Header
    console_lines.append("")
    console_lines.append(f"{c.CYAN}{c.BOLD}╔══════════════════════════════════════════════════════════════════════╗{c.RESET}")
    console_lines.append(f"{c.CYAN}{c.BOLD}║{c.RESET}   {c.YELLOW}🎯{c.RESET} {c.BOLD}Pwned User Attack Paths{c.RESET}                                      {c.CYAN}{c.BOLD}║{c.RESET}")
    console_lines.append(f"{c.CYAN}{c.BOLD}╚══════════════════════════════════════════════════════════════════════╝{c.RESET}")
    console_lines.append("")

    markdown_lines.append("## 🎯 Pwned User Attack Paths")
    markdown_lines.append("")

    for user in pwned_users:
        user_name = user["name"]
        cred_type = user.get("cred_type", "password")
        cred_value = user.get("cred_value", "")

        # Extract username and domain from UPN
        if "@" in user_name:
            username, domain = user_name.split("@")
        else:
            username = user_name
            domain = ""

        # 2. Fetch access paths for this user
        access_by_priv = _fetch_user_access(driver, user_name)

        # 3. Check domain-level access
        domain_access = _check_domain_access(driver, user_name)

        # User header
        console_lines.append(f"{c.BOLD}{c.CYAN}{'═'*70}{c.RESET}")
        console_lines.append(f"{c.BOLD}{user_name}{c.RESET}")
        console_lines.append(f"{c.DIM}Credential:{c.RESET} {c.YELLOW}{cred_type}{c.RESET}")
        console_lines.append(f"{c.CYAN}{'─'*70}{c.RESET}")

        markdown_lines.append(f"### {user_name}")
        markdown_lines.append(f"**Credential:** {cred_type}")
        markdown_lines.append("")

        # Domain-level access (DCSync / DomainAdmin)
        if domain_access in ("DCSync", "DomainAdmin", "GenericAll"):
            console_lines.append("")
            access_label = "DOMAIN ADMIN" if domain_access == "DomainAdmin" else domain_access
            console_lines.append(f"{c.RED}{c.BOLD}DOMAIN ADMIN ACCESS{c.RESET} [{access_label}] ⚡")
            console_lines.append("")
            console_lines.append(f"  {'Attack':<22} {'Reason':<40} {'Ready Command'}")
            console_lines.append(f"  {'-'*22} {'-'*40} {'-'*60}")

            template = CRED_TYPE_TEMPLATES.get(cred_type, {}).get("DCSync")
            if template and cred_value:
                cmd = fill_pwned_command(template, username, domain, infer_dc_hostname(domain), cred_value)
                reason = "Member of Domain Admins" if domain_access == "DomainAdmin" else "GetChanges+GetChangesAll"
                console_lines.append(
                    f"  {c.BOLD}{'DCSync':<22}{c.RESET} "
                    f"{c.YELLOW}{_truncate(reason, 38):<40}{c.RESET} "
                    f"{c.GREEN}{cmd}{c.RESET}"
                )

            markdown_lines.append(f"#### DCSync - Dump Domain Credentials ⚡")
            markdown_lines.append(f"| Attack | Reason | Command |")
            markdown_lines.append(f"|--------|--------|---------|")
            if template and cred_value:
                cmd = fill_pwned_command(template, username, domain, infer_dc_hostname(domain), cred_value)
                reason = "Member of Domain Admins" if domain_access == "DomainAdmin" else "GetChanges+GetChangesAll"
                markdown_lines.append(f"| DCSync | {reason} | `{cmd}` |")
            markdown_lines.append("")

        # Local Admin access
        admin_machines = access_by_priv.get("local-admin", [])
        if admin_machines:
            console_lines.append("")
            console_lines.append(f"{c.RED}{c.BOLD}LOCAL ADMIN ACCESS{c.RESET} ({len(admin_machines)} machines)")
            console_lines.append("")
            console_lines.append(f"  {'Target':<25} {'Access Path':<35} {'Ready Command'}")
            console_lines.append(f"  {'-'*25} {'-'*35} {'-'*60}")

            markdown_lines.append(f"#### Local Admin Access ({len(admin_machines)} machines)")
            markdown_lines.append(f"| Target | Access Path | Command |")
            markdown_lines.append(f"|--------|-------------|---------|")

            priority_targets = []

            for ma in admin_machines[:10]:
                has_sessions = bool(ma.get("privileged_sessions"))
                inherited_from = ma.get("inherited_from")
                access_path = f"via {inherited_from}" if inherited_from else "direct AdminTo"

                template = CRED_TYPE_TEMPLATES.get(cred_type, {}).get("AdminTo")
                if template and cred_value:
                    cmd = fill_pwned_command(template, username, domain, ma['computer'], cred_value)
                    target_display = _truncate(ma['computer'], 23)
                    path_display = _truncate(access_path, 33)
                    console_lines.append(
                        f"  {c.BOLD}{target_display:<25}{c.RESET} "
                        f"{c.YELLOW}{path_display:<35}{c.RESET} "
                        f"{c.GREEN}{cmd}{c.RESET}"
                    )
                    markdown_lines.append(f"| {ma['computer']} | {access_path} | `{cmd}` |")

                # Track priority targets for separate display
                if has_sessions:
                    priority_targets.append((ma, ma.get("privileged_sessions", [])))

            if len(admin_machines) > 10:
                console_lines.append(f"  {c.DIM}... and {len(admin_machines) - 10} more machines{c.RESET}")

            markdown_lines.append("")

            # Priority targets with sessions (secretsdump)
            if priority_targets:
                console_lines.append("")
                console_lines.append(f"  {c.YELLOW}⚠ PRIORITY TARGETS (privileged sessions detected){c.RESET}")
                console_lines.append(f"  {'Target':<25} {'Sessions':<35} {'SecretsDump Command'}")
                console_lines.append(f"  {'-'*25} {'-'*35} {'-'*60}")

                markdown_lines.append(f"**Priority Targets (Active Sessions)**")
                markdown_lines.append(f"| Target | Sessions | SecretsDump Command |")
                markdown_lines.append(f"|--------|----------|---------------------|")

                for ma, sessions in priority_targets[:5]:
                    sessions_str = ", ".join(sessions[:2])
                    sd_template = CRED_TYPE_TEMPLATES.get(cred_type, {}).get("secretsdump")
                    if sd_template and cred_value:
                        sd_cmd = fill_pwned_command(sd_template, username, domain, ma['computer'], cred_value)
                        target_display = _truncate(ma['computer'], 23)
                        sessions_display = _truncate(sessions_str, 33)
                        console_lines.append(
                            f"  {c.BOLD}{target_display:<25}{c.RESET} "
                            f"{c.YELLOW}{sessions_display:<35}{c.RESET} "
                            f"{c.GREEN}{sd_cmd}{c.RESET}"
                        )
                        markdown_lines.append(f"| {ma['computer']} | {sessions_str} | `{sd_cmd}` |")

                markdown_lines.append("")

        # User-level access (RDP, WinRM)
        user_machines = access_by_priv.get("user-level", [])
        if user_machines:
            console_lines.append("")
            console_lines.append(f"{c.BLUE}{c.BOLD}USER-LEVEL ACCESS{c.RESET} ({len(user_machines)} machines)")
            console_lines.append("")
            console_lines.append(f"  {'Target':<25} {'Access Type':<20} {'Ready Command'}")
            console_lines.append(f"  {'-'*25} {'-'*20} {'-'*60}")

            markdown_lines.append(f"#### User-Level Access ({len(user_machines)} machines)")
            markdown_lines.append(f"| Target | Access Type | Command |")
            markdown_lines.append(f"|--------|-------------|---------|")

            for ma in user_machines[:5]:
                access_types = ma.get("access_types", [])

                if "CanRDP" in access_types:
                    template = CRED_TYPE_TEMPLATES.get(cred_type, {}).get("CanRDP")
                    if template and cred_value:
                        cmd = fill_pwned_command(template, username, domain, ma['computer'], cred_value)
                        target_display = _truncate(ma['computer'], 23)
                        console_lines.append(
                            f"  {c.BOLD}{target_display:<25}{c.RESET} "
                            f"{c.YELLOW}{'RDP':<20}{c.RESET} "
                            f"{c.GREEN}{cmd}{c.RESET}"
                        )
                        markdown_lines.append(f"| {ma['computer']} | RDP | `{cmd}` |")

                elif "CanPSRemote" in access_types:
                    template = CRED_TYPE_TEMPLATES.get(cred_type, {}).get("CanPSRemote")
                    if template and cred_value:
                        cmd = fill_pwned_command(template, username, domain, ma['computer'], cred_value)
                        target_display = _truncate(ma['computer'], 23)
                        console_lines.append(
                            f"  {c.BOLD}{target_display:<25}{c.RESET} "
                            f"{c.YELLOW}{'WinRM':<20}{c.RESET} "
                            f"{c.GREEN}{cmd}{c.RESET}"
                        )
                        markdown_lines.append(f"| {ma['computer']} | WinRM | `{cmd}` |")

            markdown_lines.append("")

        # DCOM access
        dcom_machines = access_by_priv.get("dcom-exec", [])
        if dcom_machines:
            console_lines.append("")
            console_lines.append(f"{c.BLUE}{c.BOLD}DCOM ACCESS{c.RESET} ({len(dcom_machines)} machines)")
            console_lines.append("")
            console_lines.append(f"  {'Target':<25} {'Access Type':<20} {'Ready Command'}")
            console_lines.append(f"  {'-'*25} {'-'*20} {'-'*60}")

            markdown_lines.append(f"#### DCOM Access ({len(dcom_machines)} machines)")
            markdown_lines.append(f"| Target | Access Type | Command |")
            markdown_lines.append(f"|--------|-------------|---------|")

            for ma in dcom_machines[:3]:
                template = CRED_TYPE_TEMPLATES.get(cred_type, {}).get("ExecuteDCOM")
                if template and cred_value:
                    cmd = fill_pwned_command(template, username, domain, ma['computer'], cred_value)
                    target_display = _truncate(ma['computer'], 23)
                    console_lines.append(
                        f"  {c.BOLD}{target_display:<25}{c.RESET} "
                        f"{c.YELLOW}{'DCOM':<20}{c.RESET} "
                        f"{c.GREEN}{cmd}{c.RESET}"
                    )
                    markdown_lines.append(f"| {ma['computer']} | DCOM | `{cmd}` |")
                else:
                    console_lines.append(f"  {c.DIM}{ma['computer']:<25} DCOM{c.RESET}")
                    markdown_lines.append(f"| {ma['computer']} | DCOM | - |")

            markdown_lines.append("")

        # ALWAYS show authenticated user attacks (regardless of edges)
        auth_console, auth_markdown = _generate_authenticated_attacks(
            username=username,
            domain=domain,
            cred_type=cred_type,
            cred_value=cred_value,
            use_colors=use_colors
        )
        console_lines.extend(auth_console)
        markdown_lines.extend(auth_markdown)

        # No edge-based access found
        if not admin_machines and not user_machines and not dcom_machines and not domain_access:
            console_lines.append(f"{c.DIM}No direct machine access via AdminTo/CanRDP/CanPSRemote edges.{c.RESET}")
            markdown_lines.append("_No direct machine access via BloodHound edges_")
            markdown_lines.append("")

        console_lines.append("")

    return "\n".join(console_lines), "\n".join(markdown_lines)


def _fetch_pwned_users(driver) -> list:
    """Fetch all pwned users with their credentials from Neo4j."""
    try:
        with driver.session() as session:
            result = session.run("""
                MATCH (u:User)
                WHERE u.pwned = true
                RETURN u.name AS name,
                       u.pwned_cred_type AS cred_type,
                       u.pwned_cred_value AS cred_value,
                       u.pwned_source_machine AS source_machine
                ORDER BY u.pwned_at DESC
            """)
            return [dict(r) for r in result]
    except Exception:
        return []


def _fetch_user_access(driver, user_name: str) -> dict:
    """
    Fetch user's access paths grouped by privilege level.

    Includes both direct access AND inherited access through group membership
    (e.g., DOMAIN ADMINS members have AdminTo on all computers).

    Returns:
        Dict with keys: 'local-admin', 'user-level', 'dcom-exec'
        Each value is a list of dicts with 'computer', 'access_types', 'privileged_sessions', 'inherited_from'
    """
    try:
        with driver.session() as session:
            # Query for BOTH direct access AND inherited access through groups
            result = session.run("""
                // Direct access
                MATCH (u:User {name: $user_name})-[r:AdminTo|CanRDP|CanPSRemote|ExecuteDCOM]->(c:Computer)
                OPTIONAL MATCH (c)<-[:HasSession]-(priv:User)
                WHERE priv.admincount = true AND priv.name <> u.name
                WITH c, type(r) AS access_type, null AS inherited_from, collect(DISTINCT priv.name) AS priv_sessions
                RETURN c.name AS computer,
                       collect(DISTINCT access_type) AS access_types,
                       inherited_from,
                       priv_sessions AS privileged_sessions

                UNION

                // Inherited access through group membership
                MATCH (u:User {name: $user_name})-[:MemberOf*1..]->(g:Group)-[r:AdminTo|CanRDP|CanPSRemote|ExecuteDCOM]->(c:Computer)
                OPTIONAL MATCH (c)<-[:HasSession]-(priv:User)
                WHERE priv.admincount = true AND priv.name <> u.name
                WITH c, type(r) AS access_type, g.name AS inherited_from, collect(DISTINCT priv.name) AS priv_sessions
                RETURN c.name AS computer,
                       collect(DISTINCT access_type) AS access_types,
                       inherited_from,
                       priv_sessions AS privileged_sessions
            """, {"user_name": user_name})

            # Group by privilege level, deduplicating by computer
            access_by_priv = {
                "local-admin": [],
                "user-level": [],
                "dcom-exec": [],
            }
            seen_computers = {}  # Track to avoid duplicates

            for record in result:
                computer = record["computer"]
                access_types = record["access_types"]
                inherited_from = record["inherited_from"]

                # Skip if we've seen this computer with same or better access
                if computer in seen_computers:
                    # Merge access types if same computer
                    existing = seen_computers[computer]
                    existing["access_types"] = list(set(existing["access_types"]) | set(access_types))
                    if inherited_from and not existing.get("inherited_from"):
                        existing["inherited_from"] = inherited_from
                    continue

                entry = {
                    "computer": computer,
                    "access_types": access_types,
                    "privileged_sessions": [s for s in record["privileged_sessions"] if s],
                    "inherited_from": inherited_from,
                }
                seen_computers[computer] = entry

                # Categorize by highest privilege
                if "AdminTo" in access_types:
                    access_by_priv["local-admin"].append(entry)
                elif "ExecuteDCOM" in access_types:
                    access_by_priv["dcom-exec"].append(entry)
                elif access_types:  # CanRDP, CanPSRemote
                    access_by_priv["user-level"].append(entry)

            return access_by_priv

    except Exception:
        return {"local-admin": [], "user-level": [], "dcom-exec": []}


def _check_domain_access(driver, user_name: str) -> str:
    """
    Check if user has domain-level privileges (direct or inherited through groups).

    Checks:
    1. Direct DCSync rights (GetChanges + GetChangesAll)
    2. Inherited DCSync through group membership (e.g., DOMAIN ADMINS)
    3. GenericAll on Domain
    4. Membership in high-privilege groups (Domain Admins, Enterprise Admins, Backup Operators)

    Returns:
        'DCSync' if user has GetChanges+GetChangesAll (direct or inherited)
        'DomainAdmin' if user is member of Domain Admins
        'GenericAll' if user has GenericAll on domain
        None otherwise
    """
    try:
        with driver.session() as session:
            # Check direct DCSync
            result = session.run("""
                MATCH (u:User {name: $user_name})-[r:GetChanges|GetChangesAll]->(d:Domain)
                WITH u, d, collect(DISTINCT type(r)) AS rights
                WHERE 'GetChanges' IN rights AND 'GetChangesAll' IN rights
                RETURN 'DCSync' AS access
            """, {"user_name": user_name})

            if result.single():
                return "DCSync"

            # Check inherited DCSync through group membership
            result = session.run("""
                MATCH (u:User {name: $user_name})-[:MemberOf*1..]->(g:Group)-[r:GetChanges|GetChangesAll]->(d:Domain)
                WITH g, d, collect(DISTINCT type(r)) AS rights
                WHERE 'GetChanges' IN rights AND 'GetChangesAll' IN rights
                RETURN 'DCSync' AS access, g.name AS via_group
            """, {"user_name": user_name})

            record = result.single()
            if record:
                return "DCSync"

            # Check membership in Domain Admins / Enterprise Admins (implicit DCSync)
            result = session.run("""
                MATCH (u:User {name: $user_name})-[:MemberOf*1..]->(g:Group)
                WHERE g.name STARTS WITH 'DOMAIN ADMINS@'
                   OR g.name STARTS WITH 'ENTERPRISE ADMINS@'
                   OR g.objectid ENDS WITH '-512'
                   OR g.objectid ENDS WITH '-519'
                RETURN g.name AS admin_group
                LIMIT 1
            """, {"user_name": user_name})

            record = result.single()
            if record:
                return "DomainAdmin"

            # Check direct GenericAll on Domain
            result = session.run("""
                MATCH (u:User {name: $user_name})-[:GenericAll]->(d:Domain)
                RETURN 'GenericAll' AS access
            """, {"user_name": user_name})

            if result.single():
                return "GenericAll"

            # Check inherited GenericAll through group
            result = session.run("""
                MATCH (u:User {name: $user_name})-[:MemberOf*1..]->(g:Group)-[:GenericAll]->(d:Domain)
                RETURN 'GenericAll' AS access
            """, {"user_name": user_name})

            if result.single():
                return "GenericAll"

            return None

    except Exception:
        return None


# =============================================================================
# AUTHENTICATED USER ATTACKS (any domain user can run)
# =============================================================================

def _generate_authenticated_attacks(
    username: str,
    domain: str,
    cred_type: str,
    cred_value: str,
    dc_ip: str = None,
    use_colors: bool = True
) -> tuple:
    """
    Generate authenticated user attack commands.

    These attacks work for ANY authenticated domain user,
    regardless of BloodHound edges.

    Args:
        username: Username (without domain)
        domain: Domain name
        cred_type: password, ntlm-hash, kerberos-ticket
        cred_value: The credential value
        dc_ip: DC IP/hostname (optional, inferred from domain if not provided)
        use_colors: Enable ANSI colors

    Returns:
        Tuple of (console_lines: List[str], markdown_lines: List[str])
    """
    from .command_mappings import (
        AUTHENTICATED_USER_TEMPLATES,
        AUTHENTICATED_ATTACKS,
        fill_pwned_command,
        infer_dc_hostname,
    )

    c = Colors if use_colors else _NoColors

    # Get templates for this cred type
    templates = AUTHENTICATED_USER_TEMPLATES.get(cred_type, {})
    if not templates:
        return [], []

    dc = dc_ip or infer_dc_hostname(domain)

    console_lines = []
    markdown_lines = []

    # Section header
    console_lines.append("")
    console_lines.append(f"{c.CYAN}{c.BOLD}AUTHENTICATED USER ATTACKS{c.RESET} (Any domain user can run these)")
    console_lines.append("")

    # Table header (DRY format matching other command tables)
    console_lines.append(f"  {'Attack':<25} {'Objective':<45} {'Ready Command'}")
    console_lines.append(f"  {'-'*25} {'-'*45} {'-'*60}")

    markdown_lines.append("#### Authenticated User Attacks")
    markdown_lines.append("| Attack | Objective | Command |")
    markdown_lines.append("|--------|-----------|---------|")

    for attack in AUTHENTICATED_ATTACKS:
        template = templates.get(attack["id"])
        if not template:
            continue

        # Fill the command template
        cmd = fill_pwned_command(template, username, domain, dc, cred_value, dc)

        # Priority indicator
        priority = attack.get("priority", "medium")
        priority_indicator = " ⚡" if priority == "high" else ""

        # Truncate for table display
        name_display = _truncate(attack['name'] + priority_indicator, 23)
        objective_display = _truncate(attack['objective'], 43)

        # Console: tabular row
        console_lines.append(
            f"  {c.BOLD}{name_display:<25}{c.RESET} "
            f"{c.YELLOW}{objective_display:<45}{c.RESET} "
            f"{c.GREEN}{cmd}{c.RESET}"
        )

        # Markdown
        markdown_lines.append(f"| {attack['name']}{priority_indicator} | {attack['objective']} | `{cmd}` |")

    console_lines.append("")
    markdown_lines.append("")

    return console_lines, markdown_lines
