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
