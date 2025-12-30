"""
PRISM Rich Display Formatter

Colorized console output using the rich library.
"""

from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from ..models import ParsedSummary, Credential, CredentialType, KerberosTicket
from ..models import NmapScanSummary, NmapHost, NmapPort
from ..models import LdapSummary, LdapUser, LdapComputer, LdapGroup


class PrismFormatter:
    """Rich library formatter for PRISM output"""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def render_summary(self, summary: ParsedSummary, verbose: bool = False) -> None:
        """Render complete summary to console

        Args:
            summary: ParsedSummary to render
            verbose: If True, show all credentials including service accounts
        """
        # Header panel
        self._render_header(summary)

        # Cleartext credentials (HIGH VALUE)
        cleartext = [c for c in summary.cleartext_creds
                     if verbose or not c.is_service_account]
        if cleartext:
            self._render_cleartext_table(cleartext)

        # NTLM hashes
        ntlm = summary.ntlm_hashes
        if not verbose:
            # Filter out duplicates where we show NTLM for same user
            ntlm = [c for c in ntlm if not c.is_service_account or c.is_machine_account]
        if ntlm:
            self._render_ntlm_table(ntlm, verbose)

        # SHA1 hashes (optional, usually less useful)
        if verbose and summary.sha1_hashes:
            self._render_sha1_table(summary.sha1_hashes)

        # TGT tickets
        if summary.tgt_tickets:
            self._render_tgt_table(summary.tgt_tickets)

        # TGS tickets
        if summary.tgs_tickets:
            self._render_tgs_table(summary.tgs_tickets)

        # Summary stats
        self._render_stats(summary)

    def _render_header(self, summary: ParsedSummary) -> None:
        """Render summary header panel"""
        hostname = summary.source_hostname or "Unknown Host"
        domain = summary.source_domain or ""

        if domain:
            source_str = f"[bold cyan]{hostname}[/].{domain}"
        else:
            source_str = f"[bold cyan]{hostname}[/]"

        stats = summary.stats
        header_text = (
            f"Source: {source_str}\n"
            f"Sessions: [bold]{stats['sessions']}[/] | "
            f"Unique Creds: [bold]{stats['total_creds']}[/] | "
            f"High Value: [bold yellow]{stats['high_value']}[/]"
        )

        panel = Panel(
            header_text,
            title="[bold white]PRISM - Mimikatz Credential Summary[/]",
            border_style="cyan",
            box=box.ROUNDED
        )
        self.console.print(panel)

    def _render_cleartext_table(self, creds: list) -> None:
        """Render cleartext credentials with HIGH VALUE emphasis"""
        self.console.print(
            "\n[bold yellow]CLEARTEXT CREDENTIALS (HIGH VALUE)[/]\n"
        )

        table = Table(box=box.ROUNDED, border_style="yellow")
        table.add_column("Username", style="bold white")
        table.add_column("Domain", style="cyan")
        table.add_column("Password", style="bold green")
        table.add_column("Source", style="dim")

        for cred in creds:
            source = cred.session_type or ""
            table.add_row(
                cred.username,
                cred.domain,
                cred.value,
                source
            )

        self.console.print(table)

    def _render_ntlm_table(self, creds: list, verbose: bool = False) -> None:
        """Render NTLM hashes table"""
        self.console.print("\n[bold blue]NTLM HASHES[/]\n")

        table = Table(box=box.ROUNDED, border_style="blue")
        table.add_column("Username", style="bold white")
        table.add_column("Domain", style="cyan")
        table.add_column("NTLM", style="yellow")
        table.add_column("Type", style="dim")

        for cred in creds:
            if cred.is_machine_account:
                cred_type = "Machine"
                style = "dim"
            elif cred.is_service_account:
                cred_type = "Service"
                style = "dim"
            else:
                cred_type = "User"
                style = "bold"

            # Skip service accounts unless verbose
            if cred.is_service_account and not cred.is_machine_account and not verbose:
                continue

            table.add_row(
                f"[{style}]{cred.username}[/]",
                cred.domain,
                cred.value,
                cred_type
            )

        self.console.print(table)

    def _render_sha1_table(self, creds: list) -> None:
        """Render SHA1 hashes table (verbose mode)"""
        self.console.print("\n[bold magenta]SHA1 HASHES[/]\n")

        table = Table(box=box.ROUNDED, border_style="magenta")
        table.add_column("Username", style="bold white")
        table.add_column("Domain", style="cyan")
        table.add_column("SHA1", style="yellow")

        for cred in creds:
            table.add_row(cred.username, cred.domain, cred.value)

        self.console.print(table)

    def _render_tgt_table(self, tickets: list) -> None:
        """Render TGT tickets table"""
        self.console.print("\n[bold magenta]KERBEROS TICKETS (TGT)[/]\n")

        table = Table(box=box.ROUNDED, border_style="magenta")
        table.add_column("Client", style="bold white")
        table.add_column("Realm", style="cyan")
        table.add_column("Valid Until", style="yellow")
        table.add_column("Remaining", style="green")
        table.add_column("Saved", style="dim")

        for ticket in tickets:
            # Format end time
            if ticket.end_time:
                end_str = ticket.end_time.strftime('%m/%d %H:%M')
            else:
                end_str = "N/A"

            # Time remaining
            remaining = ticket.time_remaining or "N/A"
            if remaining == "EXPIRED":
                remaining = "[red]EXPIRED[/]"

            # Saved indicator
            saved = "[green]Yes[/]" if ticket.saved_path else "[dim]No[/]"

            table.add_row(
                ticket.client_name,
                ticket.client_realm,
                end_str,
                remaining,
                saved
            )

        self.console.print(table)

    def _render_tgs_table(self, tickets: list) -> None:
        """Render TGS tickets table"""
        self.console.print("\n[bold cyan]KERBEROS TICKETS (TGS)[/]\n")

        table = Table(box=box.ROUNDED, border_style="cyan")
        table.add_column("Client", style="bold white")
        table.add_column("Service", style="yellow")
        table.add_column("Target", style="cyan")
        table.add_column("Valid Until", style="dim")
        table.add_column("Saved", style="dim")

        for ticket in tickets:
            # Format end time
            if ticket.end_time:
                end_str = ticket.end_time.strftime('%m/%d %H:%M')
            else:
                end_str = "N/A"

            # Saved indicator
            saved = "[green]Yes[/]" if ticket.saved_path else "[dim]No[/]"

            # Service display
            service = ticket.service_type
            target = ticket.service_target or ticket.service_realm

            table.add_row(
                ticket.client_name,
                service,
                target,
                end_str,
                saved
            )

        self.console.print(table)

    def _render_stats(self, summary: ParsedSummary) -> None:
        """Render quick statistics"""
        stats = summary.stats
        domains = summary.unique_domains

        self.console.print("\n[dim]---[/]")

        stats_line = (
            f"[dim]Parsed {summary.lines_parsed} lines | "
            f"{stats['sessions']} sessions | "
            f"{stats['cleartext']} cleartext | "
            f"{stats['ntlm']} NTLM | "
            f"{stats['tgt_tickets']} TGT | "
            f"{stats['tgs_tickets']} TGS[/]"
        )
        self.console.print(stats_line)

        if domains:
            self.console.print(f"[dim]Domains: {', '.join(domains)}[/]")


class JSONFormatter:
    """JSON output formatter"""

    def format(self, summary: ParsedSummary) -> str:
        """Format summary as JSON"""
        import json
        return json.dumps(summary.to_dict(), indent=2, default=str)


class MarkdownFormatter:
    """Markdown output formatter"""

    def format(self, summary: ParsedSummary) -> str:
        """Format summary as Markdown"""
        lines = [
            f"# PRISM - {summary.source_tool.title()} Summary",
            "",
            f"**Source:** {summary.source_hostname or 'Unknown'}",
            f"**Domain:** {summary.source_domain or 'Unknown'}",
            f"**Parsed:** {summary.parse_time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
        ]

        # Cleartext
        if summary.cleartext_creds:
            lines.append("## Cleartext Credentials")
            lines.append("")
            lines.append("| Username | Domain | Password |")
            lines.append("|----------|--------|----------|")
            for c in summary.cleartext_creds:
                lines.append(f"| {c.username} | {c.domain} | `{c.value}` |")
            lines.append("")

        # NTLM
        if summary.ntlm_hashes:
            lines.append("## NTLM Hashes")
            lines.append("")
            lines.append("| Username | Domain | NTLM |")
            lines.append("|----------|--------|------|")
            for c in summary.ntlm_hashes:
                lines.append(f"| {c.username} | {c.domain} | `{c.value}` |")
            lines.append("")

        # TGT
        if summary.tgt_tickets:
            lines.append("## TGT Tickets")
            lines.append("")
            lines.append("| Client | Realm | Expires |")
            lines.append("|--------|-------|---------|")
            for t in summary.tgt_tickets:
                exp = t.end_time.strftime('%Y-%m-%d %H:%M') if t.end_time else "N/A"
                lines.append(f"| {t.client_name} | {t.client_realm} | {exp} |")
            lines.append("")

        # TGS
        if summary.tgs_tickets:
            lines.append("## TGS Tickets")
            lines.append("")
            lines.append("| Client | Service | Target |")
            lines.append("|--------|---------|--------|")
            for t in summary.tgs_tickets:
                lines.append(f"| {t.client_name} | {t.service_type} | {t.service_target} |")
            lines.append("")

        return "\n".join(lines)


class NmapFormatter:
    """Rich library formatter for Nmap output"""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def render_summary(self, summary: NmapScanSummary, verbose: bool = False) -> None:
        """Render nmap scan summary to console

        Args:
            summary: NmapScanSummary to render
            verbose: If True, show all hosts including down hosts
        """
        # Header panel
        self._render_header(summary)

        # Domain Controllers (HIGH VALUE)
        if summary.domain_controllers:
            self._render_dc_table(summary.domain_controllers)

        # All hosts table
        if summary.hosts_up:
            self._render_hosts_table(summary.hosts_up, verbose)

        # Port summary
        if summary.all_open_ports:
            self._render_port_summary(summary)

        # Stats footer
        self._render_stats(summary)

    def _render_header(self, summary: NmapScanSummary) -> None:
        """Render scan info header panel"""
        stats = summary.stats

        # Build header text
        lines = [
            f"[bold cyan]Scan File:[/] {summary.source_file}",
        ]

        if summary.nmap_command:
            # Truncate long commands
            cmd = summary.nmap_command
            if len(cmd) > 80:
                cmd = cmd[:77] + "..."
            lines.append(f"[dim]Command:[/] {cmd}")

        if summary.scan_start:
            lines.append(f"[dim]Time:[/] {summary.scan_start.strftime('%Y-%m-%d %H:%M')}")

        if summary.scan_duration:
            lines.append(f"[dim]Duration:[/] {summary.scan_duration:.1f}s")

        lines.append("")
        lines.append(
            f"Hosts: [bold green]{stats['hosts_up']}[/] up / "
            f"[dim]{stats['hosts_down']}[/] down | "
            f"DCs: [bold yellow]{stats['domain_controllers']}[/] | "
            f"Ports: [bold]{stats['unique_open_ports']}[/] unique"
        )

        if summary.unique_domains:
            lines.append(f"Domains: [cyan]{', '.join(summary.unique_domains)}[/]")

        panel = Panel(
            "\n".join(lines),
            title="[bold white]PRISM - Nmap Scan Summary[/]",
            border_style="cyan",
            box=box.ROUNDED
        )
        self.console.print(panel)

    def _render_dc_table(self, dcs: list) -> None:
        """Render domain controllers table (HIGH VALUE)"""
        self.console.print(
            "\n[bold yellow]DOMAIN CONTROLLERS (HIGH VALUE)[/]\n"
        )

        table = Table(box=box.ROUNDED, border_style="yellow")
        table.add_column("IP", style="bold white")
        table.add_column("Hostname", style="cyan")
        table.add_column("OS", style="dim")
        table.add_column("Domain", style="green")
        table.add_column("Key Ports", style="yellow")

        for host in dcs:
            # Get key DC ports
            key_ports = []
            if host.has_kerberos:
                key_ports.append("88")
            if host.has_ldap:
                key_ports.append("389")
            if host.has_dns:
                key_ports.append("53")
            if host.has_smb:
                key_ports.append("445")

            table.add_row(
                host.ip,
                host.hostname or "-",
                host.os_display,
                host.domain or host.dns_domain or "-",
                ", ".join(key_ports),
            )

        self.console.print(table)

    def _render_hosts_table(self, hosts: list, verbose: bool = False) -> None:
        """Render all hosts table"""
        self.console.print("\n[bold blue]HOSTS[/]\n")

        table = Table(box=box.ROUNDED, border_style="blue")
        table.add_column("IP", style="bold white")
        table.add_column("Hostname", style="cyan")
        table.add_column("OS", style="dim")
        table.add_column("Open Ports", style="yellow")
        table.add_column("Services", style="green")

        for host in hosts:
            # Skip if already shown as DC unless verbose
            if host.is_domain_controller and not verbose:
                continue

            # Format ports (show first 8)
            ports = host.open_port_numbers[:8]
            port_str = ", ".join(str(p) for p in ports)
            if len(host.open_port_numbers) > 8:
                port_str += f" (+{len(host.open_port_numbers) - 8})"

            # Key services
            services = []
            if host.has_smb:
                services.append("SMB")
            if host.has_rdp:
                services.append("RDP")
            if host.has_winrm:
                services.append("WinRM")
            if host.has_ssh:
                services.append("SSH")
            if host.has_web:
                services.append("HTTP")
            if host.has_mssql:
                services.append("MSSQL")
            if host.has_mysql:
                services.append("MySQL")

            # Style based on type
            ip_style = "bold white"
            if host.is_windows:
                ip_style = "bold cyan"
            elif host.is_linux:
                ip_style = "bold green"

            table.add_row(
                f"[{ip_style}]{host.ip}[/]",
                host.hostname or "-",
                host.os_display,
                port_str,
                ", ".join(services) if services else "-",
            )

        self.console.print(table)

    def _render_port_summary(self, summary: NmapScanSummary) -> None:
        """Render port frequency summary"""
        self.console.print("\n[bold magenta]PORT SUMMARY[/]\n")

        # Show most common ports
        port_counts = summary.all_open_ports
        if not port_counts:
            return

        table = Table(box=box.SIMPLE, border_style="magenta")
        table.add_column("Port", style="yellow")
        table.add_column("Count", style="bold")
        table.add_column("Sample Service", style="dim")

        # Sort by count descending, take top 15
        sorted_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:15]

        for port, count in sorted_ports:
            # Find sample service for this port
            sample_service = ""
            for host in summary.hosts_up:
                p = host.get_port(port)
                if p and p.service:
                    sample_service = p.service_version
                    break

            table.add_row(str(port), str(count), sample_service)

        self.console.print(table)

    def _render_stats(self, summary: NmapScanSummary) -> None:
        """Render statistics footer"""
        stats = summary.stats

        self.console.print("\n[dim]---[/]")

        stats_line = (
            f"[dim]Parsed {summary.lines_parsed} lines | "
            f"{stats['hosts_up']} hosts up | "
            f"{stats['windows_hosts']} Windows | "
            f"{stats['linux_hosts']} Linux | "
            f"{stats['total_open_ports']} total ports[/]"
        )
        self.console.print(stats_line)

        # Service breakdown
        service_stats = (
            f"[dim]SMB: {stats['hosts_with_smb']} | "
            f"RDP: {stats['hosts_with_rdp']} | "
            f"WinRM: {stats['hosts_with_winrm']} | "
            f"SSH: {stats['hosts_with_ssh']} | "
            f"HTTP: {stats['hosts_with_web']}[/]"
        )
        self.console.print(service_stats)


class NmapJSONFormatter:
    """JSON output formatter for Nmap"""

    def format(self, summary: NmapScanSummary) -> str:
        """Format nmap summary as JSON"""
        import json
        return json.dumps(summary.to_dict(), indent=2, default=str)


class NmapMarkdownFormatter:
    """Markdown output formatter for Nmap"""

    def format(self, summary: NmapScanSummary) -> str:
        """Format nmap summary as Markdown"""
        lines = [
            "# Nmap Scan Summary",
            "",
            f"**Source:** {summary.source_file}",
            f"**Command:** `{summary.nmap_command}`" if summary.nmap_command else "",
            f"**Duration:** {summary.scan_duration:.1f}s" if summary.scan_duration else "",
            "",
            f"## Statistics",
            "",
            f"- **Hosts Up:** {len(summary.hosts_up)}",
            f"- **Hosts Down:** {len(summary.hosts_down)}",
            f"- **Domain Controllers:** {len(summary.domain_controllers)}",
            f"- **Total Open Ports:** {sum(len(h.open_ports) for h in summary.hosts_up)}",
            "",
        ]

        # Domain Controllers
        if summary.domain_controllers:
            lines.append("## Domain Controllers")
            lines.append("")
            lines.append("| IP | Hostname | Domain | OS |")
            lines.append("|-----|----------|--------|-----|")
            for dc in summary.domain_controllers:
                lines.append(
                    f"| {dc.ip} | {dc.hostname or '-'} | "
                    f"{dc.domain or dc.dns_domain or '-'} | {dc.os_display} |"
                )
            lines.append("")

        # All hosts
        if summary.hosts_up:
            lines.append("## Hosts")
            lines.append("")
            lines.append("| IP | Hostname | OS | Open Ports |")
            lines.append("|-----|----------|-----|------------|")
            for host in summary.hosts_up:
                ports = ", ".join(str(p) for p in host.open_port_numbers[:6])
                if len(host.open_port_numbers) > 6:
                    ports += "..."
                lines.append(
                    f"| {host.ip} | {host.hostname or '-'} | "
                    f"{host.os_display} | {ports} |"
                )
            lines.append("")

        # Port summary
        if summary.all_open_ports:
            lines.append("## Common Ports")
            lines.append("")
            lines.append("| Port | Host Count |")
            lines.append("|------|------------|")
            sorted_ports = sorted(
                summary.all_open_ports.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
            for port, count in sorted_ports:
                lines.append(f"| {port} | {count} |")
            lines.append("")

        return "\n".join(lines)


class LdapFormatter:
    """Rich library formatter for LDAP output"""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def render_summary(self, summary: LdapSummary, verbose: bool = False) -> None:
        """Render LDAP summary to console

        Args:
            summary: LdapSummary to render
            verbose: If True, show all entries including disabled accounts
        """
        # Header panel
        self._render_header(summary)

        # Domain info / Password Policy
        if summary.domain_info:
            self._render_domain_info(summary.domain_info)

        # Kerberoastable users (HIGH VALUE)
        if summary.kerberoastable_users:
            self._render_kerberoastable_table(summary.kerberoastable_users)

        # AS-REP roastable users (HIGH VALUE)
        if summary.asrep_roastable_users:
            self._render_asrep_table(summary.asrep_roastable_users)

        # Users with descriptions (potential password hints)
        if summary.users_with_descriptions:
            self._render_description_table(summary.users_with_descriptions)

        # Admin users
        if summary.admin_users:
            self._render_admin_table(summary.admin_users)

        # All users (verbose mode)
        if verbose and summary.enabled_users:
            self._render_all_users_table(summary.enabled_users)

        # Domain Controllers
        if summary.domain_controllers:
            self._render_dc_table(summary.domain_controllers)

        # High-value groups
        if summary.high_value_groups:
            self._render_groups_table(summary.high_value_groups)

        # Stats footer
        self._render_stats(summary)

    def _render_header(self, summary: LdapSummary) -> None:
        """Render summary header panel"""
        domain = summary.domain_name or "Unknown Domain"
        stats = summary.stats

        header_text = (
            f"Domain: [bold cyan]{domain}[/]\n"
            f"Users: [bold]{stats['enabled_users']}[/] enabled / "
            f"[dim]{stats['disabled_users']}[/] disabled | "
            f"Computers: [bold]{stats['computers']}[/] | "
            f"Groups: [bold]{stats['groups']}[/]"
        )

        # High-value summary
        high_value_line = (
            f"[bold yellow]Attack Targets:[/] "
            f"Kerberoast: {stats['kerberoastable']} | "
            f"AS-REP: {stats['asrep_roastable']} | "
            f"Descriptions: {stats['with_descriptions']} | "
            f"Admins: {stats['admin_users']}"
        )

        panel = Panel(
            f"{header_text}\n{high_value_line}",
            title="[bold white]PRISM - LDAP Enumeration Summary[/]",
            border_style="cyan",
            box=box.ROUNDED
        )
        self.console.print(panel)

    def _render_domain_info(self, domain_info) -> None:
        """Render domain and password policy info"""
        self.console.print("\n[bold blue]DOMAIN INFORMATION[/]\n")

        # Policy table
        table = Table(box=box.SIMPLE, border_style="blue", show_header=False)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Domain", domain_info.dns_name or domain_info.domain_name)
        table.add_row("Functional Level", domain_info.functional_level_name)
        table.add_row("Machine Account Quota", str(domain_info.machine_account_quota))

        self.console.print(table)

        # Password policy
        self.console.print("\n[bold magenta]PASSWORD POLICY[/]\n")

        policy_table = Table(box=box.SIMPLE, border_style="magenta", show_header=False)
        policy_table.add_column("Property", style="cyan")
        policy_table.add_column("Value", style="white")
        policy_table.add_column("Notes", style="dim")

        # Min length with weakness check
        min_len = domain_info.min_pwd_length
        min_note = "[red]WEAK[/]" if min_len < 8 else ""
        policy_table.add_row("Min Password Length", str(min_len), min_note)

        # Complexity
        complexity = "Required" if domain_info.pwd_complexity_required else "Not Required"
        complexity_note = "[red]WEAK[/]" if not domain_info.pwd_complexity_required else ""
        policy_table.add_row("Complexity", complexity, complexity_note)

        # Lockout
        lockout = domain_info.lockout_threshold
        if lockout == 0:
            lockout_str = "Disabled"
            lockout_note = "[red]NO LOCKOUT[/]"
        else:
            lockout_str = f"{lockout} attempts"
            lockout_note = "[red]HIGH[/]" if lockout > 10 else ""
        policy_table.add_row("Lockout Threshold", lockout_str, lockout_note)

        if domain_info.lockout_duration:
            policy_table.add_row("Lockout Duration", f"{domain_info.lockout_duration_minutes} min", "")

        policy_table.add_row("Password History", str(domain_info.pwd_history_length), "")
        policy_table.add_row("Max Password Age", f"{domain_info.max_pwd_age_days} days", "")

        self.console.print(policy_table)

        if domain_info.is_weak_policy:
            self.console.print("\n[bold red]WARNING: Weak password policy detected![/]")

    def _render_kerberoastable_table(self, users: list) -> None:
        """Render Kerberoastable users (HIGH VALUE)"""
        self.console.print(
            "\n[bold yellow]KERBEROASTABLE USERS (HIGH VALUE)[/]\n"
        )

        table = Table(box=box.ROUNDED, border_style="yellow")
        table.add_column("Username", style="bold white")
        table.add_column("Display Name", style="cyan")
        table.add_column("SPNs", style="yellow")
        table.add_column("Admin", style="red")

        for user in users:
            spns = user.service_principal_names
            spn_display = spns[0] if spns else ""
            if len(spns) > 1:
                spn_display += f" (+{len(spns)-1})"

            admin = "[red]Yes[/]" if user.admin_count else ""

            table.add_row(
                user.sam_account_name,
                user.display_name,
                spn_display,
                admin
            )

        self.console.print(table)
        self.console.print(
            "[dim]Attack: GetUserSPNs.py DOMAIN/user:pass -dc-ip DC_IP -request[/]"
        )

    def _render_asrep_table(self, users: list) -> None:
        """Render AS-REP roastable users (HIGH VALUE)"""
        self.console.print(
            "\n[bold red]AS-REP ROASTABLE USERS (HIGH VALUE)[/]\n"
        )

        table = Table(box=box.ROUNDED, border_style="red")
        table.add_column("Username", style="bold white")
        table.add_column("Display Name", style="cyan")
        table.add_column("Admin", style="red")

        for user in users:
            admin = "[red]Yes[/]" if user.admin_count else ""
            table.add_row(
                user.sam_account_name,
                user.display_name,
                admin
            )

        self.console.print(table)
        self.console.print(
            "[dim]Attack: GetNPUsers.py DOMAIN/ -usersfile users.txt -dc-ip DC_IP -format hashcat[/]"
        )

    def _render_description_table(self, users: list) -> None:
        """Render users with descriptions (potential password hints)"""
        self.console.print(
            "\n[bold green]USERS WITH DESCRIPTIONS (CHECK FOR PASSWORDS!)[/]\n"
        )

        table = Table(box=box.ROUNDED, border_style="green")
        table.add_column("Username", style="bold white")
        table.add_column("Description", style="green")

        for user in users:
            desc = user.description or ""
            # Truncate long descriptions
            if len(desc) > 60:
                desc = desc[:57] + "..."
            table.add_row(user.sam_account_name, desc)

        self.console.print(table)

    def _render_admin_table(self, users: list) -> None:
        """Render admin/privileged users"""
        self.console.print("\n[bold red]ADMIN USERS (adminCount=1)[/]\n")

        table = Table(box=box.ROUNDED, border_style="red")
        table.add_column("Username", style="bold white")
        table.add_column("Display Name", style="cyan")
        table.add_column("Attack Paths", style="yellow")

        for user in users:
            paths = ", ".join(user.attack_paths) if user.attack_paths else "-"
            table.add_row(
                user.sam_account_name,
                user.display_name,
                paths
            )

        self.console.print(table)

    def _render_all_users_table(self, users: list) -> None:
        """Render all enabled users (verbose mode)"""
        self.console.print("\n[bold blue]ALL ENABLED USERS[/]\n")

        table = Table(box=box.ROUNDED, border_style="blue")
        table.add_column("Username", style="bold white")
        table.add_column("Display Name", style="cyan")
        table.add_column("Flags", style="dim")

        for user in users[:50]:  # Limit to 50
            flags = []
            if user.admin_count:
                flags.append("Admin")
            if user.is_kerberoastable:
                flags.append("SPN")
            if user.dont_require_preauth:
                flags.append("NoPreAuth")
            if user.password_never_expires:
                flags.append("NoPwdExpire")

            table.add_row(
                user.sam_account_name,
                user.display_name,
                ", ".join(flags) if flags else "-"
            )

        if len(users) > 50:
            self.console.print(f"[dim]... and {len(users) - 50} more users[/]")

        self.console.print(table)

    def _render_dc_table(self, dcs: list) -> None:
        """Render domain controllers"""
        self.console.print("\n[bold cyan]DOMAIN CONTROLLERS[/]\n")

        table = Table(box=box.ROUNDED, border_style="cyan")
        table.add_column("Name", style="bold white")
        table.add_column("DNS Hostname", style="cyan")
        table.add_column("OS", style="dim")

        for dc in dcs:
            table.add_row(
                dc.sam_account_name.rstrip('$'),
                dc.dns_hostname or "-",
                dc.os_display
            )

        self.console.print(table)

    def _render_groups_table(self, groups: list) -> None:
        """Render high-value groups"""
        self.console.print("\n[bold magenta]HIGH-VALUE GROUPS[/]\n")

        table = Table(box=box.ROUNDED, border_style="magenta")
        table.add_column("Group", style="bold white")
        table.add_column("Members", style="cyan")
        table.add_column("Description", style="dim")

        for group in groups:
            members = group.members
            member_str = str(len(members)) if members else "0"

            desc = group.description or ""
            if len(desc) > 40:
                desc = desc[:37] + "..."

            table.add_row(
                group.sam_account_name,
                member_str,
                desc
            )

        self.console.print(table)

    def _render_stats(self, summary: LdapSummary) -> None:
        """Render statistics footer"""
        stats = summary.stats

        self.console.print("\n[dim]---[/]")

        stats_line = (
            f"[dim]Parsed {summary.lines_parsed} lines | "
            f"{stats['total_entries']} entries | "
            f"{stats['users']} users | "
            f"{stats['computers']} computers | "
            f"{stats['groups']} groups[/]"
        )
        self.console.print(stats_line)


class LdapJSONFormatter:
    """JSON output formatter for LDAP"""

    def format(self, summary: LdapSummary) -> str:
        """Format LDAP summary as JSON"""
        import json
        return json.dumps(summary.to_dict(), indent=2, default=str)


class LdapMarkdownFormatter:
    """Markdown output formatter for LDAP"""

    def format(self, summary: LdapSummary) -> str:
        """Format LDAP summary as Markdown"""
        lines = [
            "# LDAP Enumeration Summary",
            "",
            f"**Domain:** {summary.domain_name}",
            f"**Source:** {summary.source_file}",
            "",
            "## Statistics",
            "",
            f"- **Users:** {len(summary.users)} ({len(summary.enabled_users)} enabled)",
            f"- **Computers:** {len(summary.computers)}",
            f"- **Groups:** {len(summary.groups)}",
            f"- **Domain Controllers:** {len(summary.domain_controllers)}",
            "",
        ]

        # Password Policy
        if summary.domain_info:
            di = summary.domain_info
            lines.extend([
                "## Password Policy",
                "",
                f"- **Min Length:** {di.min_pwd_length}",
                f"- **Complexity:** {'Required' if di.pwd_complexity_required else 'Not Required'}",
                f"- **Lockout Threshold:** {di.lockout_threshold or 'Disabled'}",
                f"- **Max Age:** {di.max_pwd_age_days} days",
                "",
            ])

        # Kerberoastable
        if summary.kerberoastable_users:
            lines.extend([
                "## Kerberoastable Users",
                "",
                "| Username | SPNs |",
                "|----------|------|",
            ])
            for u in summary.kerberoastable_users:
                spns = "; ".join(u.service_principal_names[:2])
                if len(u.service_principal_names) > 2:
                    spns += "..."
                lines.append(f"| {u.sam_account_name} | {spns} |")
            lines.append("")

        # AS-REP Roastable
        if summary.asrep_roastable_users:
            lines.extend([
                "## AS-REP Roastable Users",
                "",
                "| Username | Display Name |",
                "|----------|--------------|",
            ])
            for u in summary.asrep_roastable_users:
                lines.append(f"| {u.sam_account_name} | {u.display_name} |")
            lines.append("")

        # Descriptions
        if summary.users_with_descriptions:
            lines.extend([
                "## Users with Descriptions",
                "",
                "| Username | Description |",
                "|----------|-------------|",
            ])
            for u in summary.users_with_descriptions:
                desc = u.description or ""
                if len(desc) > 50:
                    desc = desc[:47] + "..."
                lines.append(f"| {u.sam_account_name} | {desc} |")
            lines.append("")

        return "\n".join(lines)
