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
from ..models import SmbmapSummary, SmbShare, SmbPermission


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

        # GPP credentials (HIGH VALUE)
        gpp = summary.gpp_creds
        if gpp:
            self._render_gpp_table(gpp)

        # Kerberoast hashes
        kerberoast = summary.kerberoast_hashes
        if kerberoast:
            self._render_kerberoast_table(kerberoast)

        # Cleartext credentials (HIGH VALUE)
        cleartext = [c for c in summary.cleartext_creds
                     if verbose or not c.is_service_account]
        if cleartext:
            self._render_cleartext_table(cleartext)

        # Cracked passwords from potfiles (HIGH VALUE)
        cracked = summary.cracked_passwords
        if cracked:
            self._render_cracked_table(cracked)

        # Connection string credentials (HIGH VALUE)
        connstrings = summary.connection_strings
        if connstrings:
            self._render_connstring_table(connstrings)

        # NTLM hashes
        ntlm = summary.ntlm_hashes
        if not verbose:
            # Filter out duplicates where we show NTLM for same user
            ntlm = [c for c in ntlm if not c.is_service_account or c.is_machine_account]
        if ntlm:
            self._render_ntlm_table(ntlm, verbose)

        # NTDS hashes (from secretsdump)
        ntds = summary.ntds_hashes
        if ntds:
            self._render_ntds_table(ntds, verbose)

        # NetNTLM hashes (from Responder)
        netntlm = summary.netntlm_hashes
        if netntlm:
            self._render_netntlm_table(netntlm)

        # Linux shadow hashes
        linux = summary.linux_hashes
        if linux:
            self._render_linux_table(linux)

        # SSH keys
        ssh = summary.ssh_keys
        if ssh:
            self._render_ssh_table(ssh)

        # htpasswd hashes
        htpasswd = summary.htpasswd_hashes
        if htpasswd:
            self._render_htpasswd_table(htpasswd)

        # AWS keys
        aws = summary.aws_keys
        if aws:
            self._render_aws_table(aws)

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
        hostname = summary.display_hostname
        domain = summary.source_domain or ""

        # Don't append domain if hostname already contains it
        if domain and domain.upper() not in hostname.upper():
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

        # Dynamic title based on source tool
        tool_titles = {
            'mimikatz': 'Mimikatz Credential Summary',
            'gpp': 'GPP Password Summary',
            'kerberoast': 'Kerberoast Hash Summary',
            'secretsdump': 'Secretsdump Hash Summary',
            'nmap': 'Nmap Scan Summary',
            'ldap': 'LDAP Enumeration Summary',
        }
        title_suffix = tool_titles.get(summary.source_tool, 'Credential Summary')

        panel = Panel(
            header_text,
            title=f"[bold white]PRISM - {title_suffix}[/]",
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

    def _render_gpp_table(self, creds: list) -> None:
        """Render GPP credentials table (HIGH VALUE)"""
        self.console.print(
            "\n[bold yellow]GPP CREDENTIALS (HIGH VALUE)[/]\n"
        )

        table = Table(box=box.ROUNDED, border_style="yellow")
        table.add_column("Username", style="bold white")
        table.add_column("Domain", style="cyan")
        table.add_column("Password", style="bold green")
        table.add_column("Type", style="dim")

        for cred in creds:
            cred_type = "Decrypted" if cred.cred_type == CredentialType.GPP_PASSWORD else "Encrypted"
            table.add_row(
                cred.username,
                cred.domain,
                cred.value,
                cred_type
            )

        self.console.print(table)

    def _render_kerberoast_table(self, creds: list) -> None:
        """Render Kerberoast/AS-REP hashes table"""
        self.console.print("\n[bold magenta]KERBEROAST HASHES[/]\n")

        table = Table(box=box.ROUNDED, border_style="magenta")
        table.add_column("Username", style="bold white")
        table.add_column("Domain", style="cyan")
        table.add_column("Hash Type", style="yellow")
        table.add_column("Hash (truncated)", style="dim", max_width=50)

        for cred in creds:
            hash_type = "TGS" if cred.cred_type == CredentialType.KRB5TGS else "AS-REP"
            # Truncate long hashes for display
            hash_display = cred.value[:47] + "..." if len(cred.value) > 50 else cred.value

            table.add_row(
                cred.username,
                cred.domain,
                hash_type,
                hash_display
            )

        self.console.print(table)

        self.console.print(
            "[dim]Full hashes saved. Crack with: hashcat -m 13100 (TGS) / 18200 (AS-REP)[/]"
        )

    def _render_ntds_table(self, creds: list, verbose: bool = False) -> None:
        """Render NTDS/SAM hashes table"""
        self.console.print("\n[bold blue]NTDS/SAM HASHES[/]\n")

        table = Table(box=box.ROUNDED, border_style="blue")
        table.add_column("Username", style="bold white")
        table.add_column("Domain", style="cyan")
        table.add_column("NTLM Hash", style="yellow")
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

            if cred.is_service_account and not cred.is_machine_account and not verbose:
                continue

            table.add_row(
                f"[{style}]{cred.username}[/]",
                cred.domain,
                cred.value,
                cred_type
            )

        self.console.print(table)
        self.console.print("[dim]Crack with: hashcat -m 1000[/]")

    def _render_netntlm_table(self, creds: list) -> None:
        """Render NetNTLM hashes table (Responder captures)"""
        self.console.print("\n[bold red]NETNTLM HASHES (Relay/Crack)[/]\n")

        table = Table(box=box.ROUNDED, border_style="red")
        table.add_column("Username", style="bold white")
        table.add_column("Domain", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Hash (truncated)", style="dim", max_width=40)

        for cred in creds:
            hash_type = "NTLMv1" if cred.cred_type == CredentialType.NET_NTLMV1 else "NTLMv2"
            hash_display = cred.value[:37] + "..." if len(cred.value) > 40 else cred.value

            table.add_row(
                cred.username,
                cred.domain,
                hash_type,
                hash_display
            )

        self.console.print(table)
        self.console.print("[dim]Crack: hashcat -m 5500 (NTLMv1) / -m 5600 (NTLMv2)[/]")

    def _render_linux_table(self, creds: list) -> None:
        """Render Linux shadow hashes table"""
        self.console.print("\n[bold green]LINUX SHADOW HASHES[/]\n")

        table = Table(box=box.ROUNDED, border_style="green")
        table.add_column("Username", style="bold white")
        table.add_column("Hash Type", style="cyan")
        table.add_column("Hash (truncated)", style="yellow", max_width=50)

        for cred in creds:
            # Detect hash type from prefix
            if cred.value.startswith('$6$'):
                hash_type = "SHA512"
            elif cred.value.startswith('$5$'):
                hash_type = "SHA256"
            elif cred.value.startswith('$1$'):
                hash_type = "MD5"
            elif cred.value.startswith('$y$'):
                hash_type = "yescrypt"
            else:
                hash_type = "Unknown"

            hash_display = cred.value[:47] + "..." if len(cred.value) > 50 else cred.value
            table.add_row(cred.username, hash_type, hash_display)

        self.console.print(table)
        self.console.print("[dim]Crack: hashcat -m 1800 (SHA512) / -m 500 (MD5)[/]")

    def _render_cracked_table(self, creds: list) -> None:
        """Render cracked passwords from potfile (HIGH VALUE)"""
        self.console.print("\n[bold yellow]CRACKED PASSWORDS (HIGH VALUE)[/]\n")

        table = Table(box=box.ROUNDED, border_style="yellow")
        table.add_column("Hash", style="dim", max_width=35)
        table.add_column("Password", style="bold green")

        for cred in creds:
            hash_display = cred.username[:32] + "..." if len(cred.username) > 35 else cred.username
            table.add_row(hash_display, cred.value)

        self.console.print(table)

    def _render_connstring_table(self, creds: list) -> None:
        """Render connection string credentials (HIGH VALUE)"""
        self.console.print("\n[bold yellow]DATABASE CREDENTIALS (HIGH VALUE)[/]\n")

        table = Table(box=box.ROUNDED, border_style="yellow")
        table.add_column("Username", style="bold white")
        table.add_column("Server/Database", style="cyan")
        table.add_column("Password", style="bold green")

        for cred in creds:
            table.add_row(cred.username, cred.domain, cred.value)

        self.console.print(table)

    def _render_ssh_table(self, creds: list) -> None:
        """Render SSH private keys"""
        self.console.print("\n[bold magenta]SSH PRIVATE KEYS[/]\n")

        table = Table(box=box.ROUNDED, border_style="magenta")
        table.add_column("File/User", style="bold white")
        table.add_column("Key Type", style="cyan")
        table.add_column("Encrypted", style="yellow")

        for cred in creds:
            # Parse key info from value or domain
            encrypted = "Yes" if "ENCRYPTED" in cred.value.upper() else "No"
            key_type = "RSA" if "RSA" in cred.value.upper() else "Unknown"
            table.add_row(cred.username, key_type, encrypted)

        self.console.print(table)
        self.console.print("[dim]Use ssh -i <key> user@target[/]")

    def _render_htpasswd_table(self, creds: list) -> None:
        """Render htpasswd hashes"""
        self.console.print("\n[bold blue]HTPASSWD HASHES[/]\n")

        table = Table(box=box.ROUNDED, border_style="blue")
        table.add_column("Username", style="bold white")
        table.add_column("Hash (truncated)", style="yellow", max_width=40)

        for cred in creds:
            hash_display = cred.value[:37] + "..." if len(cred.value) > 40 else cred.value
            table.add_row(cred.username, hash_display)

        self.console.print(table)
        self.console.print("[dim]Crack: hashcat -m 1600 (APR1) / -m 3200 (bcrypt)[/]")

    def _render_aws_table(self, creds: list) -> None:
        """Render AWS access keys (HIGH VALUE)"""
        self.console.print("\n[bold yellow]AWS ACCESS KEYS (HIGH VALUE)[/]\n")

        table = Table(box=box.ROUNDED, border_style="yellow")
        table.add_column("Access Key ID", style="bold white")
        table.add_column("Secret Key (truncated)", style="bold green", max_width=30)
        table.add_column("Profile", style="cyan")

        for cred in creds:
            secret_display = cred.value[:10] + "..." if len(cred.value) > 10 else cred.value
            table.add_row(cred.username, secret_display, cred.domain or "default")

        self.console.print(table)
        self.console.print("[dim]Use: aws configure --profile <name>[/]")

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

        # Build dynamic stats line based on what's present
        parts = [f"Parsed {summary.lines_parsed} lines"]

        if stats['sessions']:
            parts.append(f"{stats['sessions']} sessions")
        if stats.get('gpp', 0):
            parts.append(f"{stats['gpp']} GPP")
        if stats.get('kerberoast', 0):
            parts.append(f"{stats['kerberoast']} kerberoast")
        if stats['cleartext']:
            parts.append(f"{stats['cleartext']} cleartext")
        if stats['ntlm']:
            parts.append(f"{stats['ntlm']} NTLM")
        if stats['tgt_tickets']:
            parts.append(f"{stats['tgt_tickets']} TGT")
        if stats['tgs_tickets']:
            parts.append(f"{stats['tgs_tickets']} TGS")

        stats_line = "[dim]" + " | ".join(parts) + "[/]"
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


class SmbmapFormatter:
    """Rich library formatter for SMBMap output"""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def render_summary(self, summary: SmbmapSummary, verbose: bool = False) -> None:
        """Render smbmap scan summary to console

        Args:
            summary: SmbmapSummary to render
            verbose: If True, show all entries including default shares
        """
        # Header panel
        self._render_header(summary)

        # High-value files (CRITICAL - show first!)
        if summary.high_value_files:
            self._render_high_value_files(summary)

        # Writable shares (attack vectors)
        if summary.writable_shares:
            self._render_writable_shares(summary)

        # All shares table
        self._render_shares_table(summary, verbose)

        # Stats footer
        self._render_stats(summary)

    def _render_header(self, summary: SmbmapSummary) -> None:
        """Render scan info header panel"""
        stats = summary.stats

        lines = [
            f"[bold cyan]Source:[/] {summary.source_file}",
        ]

        if summary.target_ip:
            lines.append(f"[dim]Target:[/] {summary.target_ip}:{summary.target_port}")
        if summary.target_hostname:
            lines.append(f"[dim]Hostname:[/] {summary.target_hostname}")
        if summary.username:
            domain = f"{summary.domain}\\" if summary.domain else ""
            lines.append(f"[dim]Auth:[/] {domain}{summary.username} ({summary.auth_status})")

        lines.append("")
        lines.append(
            f"Shares: [bold]{stats['total_shares']}[/] total | "
            f"[bold green]{stats['readable_shares']}[/] readable | "
            f"[bold yellow]{stats['writable_shares']}[/] writable"
        )
        lines.append(
            f"Files: [bold]{stats['total_files']}[/] total | "
            f"[bold red]{stats['high_value_files']}[/] high-value"
        )

        panel = Panel(
            "\n".join(lines),
            title="[bold white]PRISM - SMBMap Summary[/]",
            border_style="blue",
            box=box.ROUNDED
        )
        self.console.print(panel)

    def _render_high_value_files(self, summary: SmbmapSummary) -> None:
        """Render high-value files table (CRITICAL for pentesting)"""
        self.console.print(
            "\n[bold red]HIGH-VALUE FILES (CHECK IMMEDIATELY)[/]\n"
        )

        table = Table(box=box.ROUNDED, border_style="red")
        table.add_column("File", style="bold white")
        table.add_column("Path", style="cyan")
        table.add_column("Size", style="dim", justify="right")
        table.add_column("Why High-Value", style="yellow")

        for entry in summary.high_value_files[:10]:  # Limit to 10
            # Determine why it's high-value
            reason = self._get_high_value_reason(entry.name)
            size_str = self._format_size(entry.size)

            table.add_row(
                entry.name,
                entry.path or "(root)",
                size_str,
                reason
            )

        self.console.print(table)

        if len(summary.high_value_files) > 10:
            self.console.print(
                f"[dim]... and {len(summary.high_value_files) - 10} more high-value files[/]"
            )

    def _render_writable_shares(self, summary: SmbmapSummary) -> None:
        """Render writable shares (potential attack vectors)"""
        self.console.print(
            "\n[bold yellow]WRITABLE SHARES (POTENTIAL ATTACK VECTORS)[/]\n"
        )

        table = Table(box=box.ROUNDED, border_style="yellow")
        table.add_column("Share", style="bold white")
        table.add_column("Comment", style="dim")
        table.add_column("Files", style="cyan", justify="right")
        table.add_column("Attack Ideas", style="green")

        for share in summary.writable_shares:
            attack_ideas = self._get_attack_ideas(share)
            table.add_row(
                share.name,
                share.comment or "-",
                str(len(share.files)),
                attack_ideas
            )

        self.console.print(table)

    def _render_shares_table(self, summary: SmbmapSummary, verbose: bool) -> None:
        """Render all shares table"""
        self.console.print("\n[bold]ALL SHARES[/]\n")

        table = Table(box=box.ROUNDED, border_style="blue")
        table.add_column("Share", style="bold white")
        table.add_column("Permission", style="cyan")
        table.add_column("Comment", style="dim")
        table.add_column("Entries", justify="right")
        table.add_column("Files", justify="right")

        shares_to_show = summary.shares if verbose else summary.non_default_shares
        if not shares_to_show:
            shares_to_show = summary.shares  # Show default shares if nothing else

        for share in shares_to_show:
            # Color-code permission
            perm = share.permission.value
            if share.permission == SmbPermission.READ_WRITE:
                perm_style = "bold yellow"
            elif share.permission == SmbPermission.READ_ONLY:
                perm_style = "green"
            elif share.permission == SmbPermission.NO_ACCESS:
                perm_style = "dim red"
            else:
                perm_style = "dim"

            table.add_row(
                share.name,
                f"[{perm_style}]{perm}[/]",
                share.comment or "-",
                str(len(share.entries)),
                str(len(share.files))
            )

        self.console.print(table)

        if not verbose and len(summary.shares) > len(shares_to_show):
            self.console.print(
                f"[dim]({len(summary.shares) - len(shares_to_show)} default shares hidden, use --verbose to show)[/]"
            )

    def _render_stats(self, summary: SmbmapSummary) -> None:
        """Render statistics footer"""
        stats = summary.stats

        self.console.print("\n[dim]" + "─" * 60 + "[/]")
        self.console.print(
            f"[dim]Parsed {summary.lines_parsed} lines | "
            f"{stats['total_shares']} shares | "
            f"{stats['total_files']} files | "
            f"{stats['high_value_files']} high-value[/]"
        )

        if summary.warnings:
            for warning in summary.warnings:
                self.console.print(f"[yellow]Warning: {warning}[/]")

    def _format_size(self, size: int) -> str:
        """Format file size for display"""
        if size < 1024:
            return f"{size}B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f}KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024):.1f}MB"
        else:
            return f"{size / (1024 * 1024 * 1024):.1f}GB"

    def _get_high_value_reason(self, filename: str) -> str:
        """Get reason why a file is high-value"""
        name_lower = filename.lower()

        # GPP files
        if name_lower in ('groups.xml', 'services.xml', 'scheduledtasks.xml'):
            return "GPP cpassword (auto-decrypt!)"
        if name_lower in ('datasources.xml', 'printers.xml', 'drives.xml'):
            return "GPP credentials"

        # Registry backups
        if name_lower in ('sam', 'sam.bak', 'system', 'system.bak', 'security', 'security.bak'):
            return "Registry hive (hash extraction)"
        if name_lower == 'ntds.dit':
            return "AD database (all hashes!)"

        # Config files
        if name_lower in ('web.config', 'applicationhost.config'):
            return "Connection strings"
        if 'password' in name_lower or 'cred' in name_lower:
            return "Potential credentials"

        # Keys
        if name_lower.startswith('id_') or name_lower.endswith('.pem'):
            return "SSH private key"
        if name_lower.endswith(('.pfx', '.p12', '.kdbx')):
            return "Certificate/KeyPass"

        # Flags
        if name_lower in ('flag.txt', 'root.txt', 'user.txt'):
            return "CTF flag!"

        return "Sensitive file"

    def _get_attack_ideas(self, share: SmbShare) -> str:
        """Get attack ideas for a writable share"""
        ideas = []

        name_lower = share.name.lower()

        if 'web' in name_lower or 'www' in name_lower:
            ideas.append("Web shell")
        if 'script' in name_lower or 'deploy' in name_lower:
            ideas.append("Script injection")
        if name_lower == 'sysvol':
            ideas.append("GPO abuse")
        if 'backup' in name_lower:
            ideas.append("Backup poisoning")

        if not ideas:
            ideas.append("File drop")

        return ", ".join(ideas)


class SmbmapJSONFormatter:
    """JSON output formatter for SMBMap"""

    def format(self, summary: SmbmapSummary) -> str:
        """Format smbmap summary as JSON"""
        import json
        return json.dumps(summary.to_dict(), indent=2, default=str)


class SmbmapMarkdownFormatter:
    """Markdown output formatter for SMBMap"""

    def format(self, summary: SmbmapSummary) -> str:
        """Format smbmap summary as Markdown"""
        lines = [
            "# SMBMap Summary",
            "",
            f"**Source:** {summary.source_file}",
            f"**Target:** {summary.target_ip}:{summary.target_port}" if summary.target_ip else "",
            f"**Hostname:** {summary.target_hostname}" if summary.target_hostname else "",
            f"**Auth:** {summary.domain}\\{summary.username} ({summary.auth_status})" if summary.username else "",
            "",
            "## Statistics",
            "",
            f"- **Total Shares:** {summary.stats['total_shares']}",
            f"- **Readable Shares:** {summary.stats['readable_shares']}",
            f"- **Writable Shares:** {summary.stats['writable_shares']}",
            f"- **Total Files:** {summary.stats['total_files']}",
            f"- **High-Value Files:** {summary.stats['high_value_files']}",
            "",
        ]

        # High-value files
        if summary.high_value_files:
            lines.append("## High-Value Files")
            lines.append("")
            lines.append("| File | Path | Size |")
            lines.append("|------|------|------|")
            for f in summary.high_value_files:
                lines.append(f"| {f.name} | {f.path or '(root)'} | {f.size} |")
            lines.append("")

        # Shares
        lines.append("## Shares")
        lines.append("")
        lines.append("| Share | Permission | Comment |")
        lines.append("|-------|------------|---------|")
        for share in summary.shares:
            lines.append(f"| {share.name} | {share.permission.value} | {share.comment or '-'} |")
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

        # CRITICAL: Users with legacy passwords (INSTANT WIN - show first!)
        if summary.users_with_legacy_passwords:
            self._render_legacy_password_table(summary.users_with_legacy_passwords)

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

        # Domain Controllers
        if summary.domain_controllers:
            self._render_dc_table(summary.domain_controllers)

        # High-value groups
        if summary.high_value_groups:
            self._render_groups_table(summary.high_value_groups)

        # Partial entries (user hints from anonymous LDAP)
        if summary.user_hints:
            self._render_user_hints(summary)

        # Verbose mode: Additional detailed sections
        if verbose:
            # Delegation analysis (critical attack path)
            self._render_delegation_analysis(summary)

            # Full UAC flag breakdown for high-value users
            high_value = [u for u in summary.enabled_users if u.high_value]
            if high_value:
                self._render_uac_analysis(high_value)

            # Group membership details
            self._render_group_members(summary)

            # Stale/suspicious accounts
            self._render_stale_accounts(summary)

            # Enhanced all-users table
            if summary.enabled_users:
                self._render_all_users_verbose(summary.enabled_users)

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

        # High-value summary - include legacy passwords!
        legacy_count = stats.get('with_legacy_passwords', 0)
        legacy_part = f"[bold red]LegacyPwd: {legacy_count}[/] | " if legacy_count else ""
        high_value_line = (
            f"[bold yellow]Attack Targets:[/] "
            f"{legacy_part}"
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

    def _render_legacy_password_table(self, users: list) -> None:
        """Render users with legacy passwords (CRITICAL - INSTANT WIN!)"""
        self.console.print(
            "\n[bold red]🔓 LEGACY PASSWORDS FOUND (CRITICAL - TEST IMMEDIATELY!)[/]\n"
        )

        table = Table(box=box.DOUBLE, border_style="red")
        table.add_column("Username", style="bold white")
        table.add_column("Attribute", style="yellow")
        table.add_column("Decoded Password", style="bold green")
        table.add_column("Groups", style="dim")

        for user in users:
            groups = len(user.member_of)
            group_str = str(groups) if groups else "0"

            table.add_row(
                user.sam_account_name,
                user.legacy_password_attr or "unknown",
                user.legacy_password_decoded or user.legacy_password_raw or "",
                group_str
            )

        self.console.print(table)

        # Show test commands
        self.console.print("\n[bold]TEST THESE CREDENTIALS:[/]")
        for user in users:
            pwd = user.legacy_password_decoded or user.legacy_password_raw
            self.console.print(
                f"  [cyan]$ crackmapexec smb DC_IP -u '{user.sam_account_name}' -p '{pwd}'[/]"
            )
            self.console.print(
                f"  [cyan]$ evil-winrm -i DC_IP -u '{user.sam_account_name}' -p '{pwd}'[/]"
            )
        self.console.print()

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

    def _render_delegation_analysis(self, summary: LdapSummary) -> None:
        """Render delegation targets (verbose mode) - CRITICAL for attack paths"""
        # Find users and computers with delegation
        delegation_targets = []

        for user in summary.enabled_users:
            if user.trusted_for_delegation:
                delegation_targets.append({
                    'account': user.sam_account_name,
                    'type': 'User',
                    'delegation': 'Unconstrained',
                    'admin': user.admin_count
                })

        for computer in summary.computers:
            if computer.trusted_for_delegation:
                delegation_targets.append({
                    'account': computer.sam_account_name,
                    'type': 'DC' if computer.is_domain_controller else 'Computer',
                    'delegation': 'Unconstrained',
                    'admin': False
                })

        if not delegation_targets:
            return

        self.console.print(
            "\n[bold red]DELEGATION TARGETS (CRITICAL)[/]\n"
        )

        table = Table(box=box.ROUNDED, border_style="red")
        table.add_column("Account", style="bold white")
        table.add_column("Type", style="cyan")
        table.add_column("Delegation", style="yellow")
        table.add_column("Admin", style="red")

        for target in delegation_targets:
            admin_str = "[red]Yes[/]" if target['admin'] else ""
            table.add_row(
                target['account'],
                target['type'],
                target['delegation'],
                admin_str
            )

        self.console.print(table)
        self.console.print(
            "[dim]Attack: Unconstrained delegation allows TGT capture. "
            "Use Rubeus monitor or printer bug.[/]"
        )

    def _render_uac_analysis(self, users: list) -> None:
        """Render full UAC flag breakdown for high-value users (verbose mode)"""
        if not users:
            return

        self.console.print("\n[bold magenta]UAC FLAG ANALYSIS[/]\n")

        table = Table(box=box.ROUNDED, border_style="magenta")
        table.add_column("Username", style="bold white")
        table.add_column("UAC Value", style="cyan")
        table.add_column("Flags", style="yellow", max_width=50)

        for user in users:
            uac_hex = f"0x{user.user_account_control:06X}"
            flags = ", ".join(sorted(user.uac_flags)) if user.uac_flags else "-"

            table.add_row(
                user.sam_account_name,
                uac_hex,
                flags
            )

        self.console.print(table)

    def _render_group_members(self, summary: LdapSummary) -> None:
        """Render members of high-value groups (verbose mode)"""
        high_value_groups = summary.high_value_groups
        if not high_value_groups:
            return

        self.console.print("\n[bold green]HIGH-VALUE GROUP MEMBERS[/]\n")

        for group in high_value_groups:
            members = group.members
            if not members:
                continue

            # Extract CN from DN for member names
            member_names = []
            for member_dn in members[:10]:  # Limit to 10
                # Extract CN from "CN=Name,OU=..."
                import re
                match = re.match(r'CN=([^,]+)', member_dn, re.IGNORECASE)
                if match:
                    member_names.append(match.group(1))
                else:
                    member_names.append(member_dn[:30])

            count = len(members)
            self.console.print(
                f"[bold cyan]{group.sam_account_name}[/] ({count} member{'s' if count != 1 else ''}):"
            )
            for name in member_names:
                self.console.print(f"  [dim]-[/] {name}")

            if len(members) > 10:
                self.console.print(f"  [dim]... and {len(members) - 10} more[/]")

            self.console.print()

    def _render_stale_accounts(self, summary: LdapSummary) -> None:
        """Render accounts with old passwords or no recent activity (verbose mode)"""
        from datetime import datetime

        stale_users = []
        for user in summary.enabled_users:
            # Check for indicators of stale accounts
            pwd_last_set = user.pwd_last_set
            last_logon = user.last_logon

            # These are often stored as Windows FILETIME or string dates
            # For now, just check if they exist and look old
            is_stale = False
            stale_reason = []

            if pwd_last_set:
                # If pwdLastSet is 0 or very old, flag it
                try:
                    if pwd_last_set == '0' or int(pwd_last_set) == 0:
                        is_stale = True
                        stale_reason.append("Password never set")
                except (ValueError, TypeError):
                    pass

            if last_logon:
                try:
                    if last_logon == '0' or int(last_logon) == 0:
                        is_stale = True
                        stale_reason.append("Never logged on")
                except (ValueError, TypeError):
                    pass

            if is_stale:
                stale_users.append({
                    'username': user.sam_account_name,
                    'display': user.display_name,
                    'reason': ", ".join(stale_reason)
                })

        if not stale_users:
            return

        self.console.print(
            "\n[bold yellow]STALE/SUSPICIOUS ACCOUNTS[/]\n"
        )

        table = Table(box=box.ROUNDED, border_style="yellow")
        table.add_column("Username", style="bold white")
        table.add_column("Display Name", style="cyan")
        table.add_column("Issue", style="yellow")

        for user in stale_users[:20]:  # Limit to 20
            table.add_row(
                user['username'],
                user['display'],
                user['reason']
            )

        self.console.print(table)

        if len(stale_users) > 20:
            self.console.print(f"[dim]... and {len(stale_users) - 20} more[/]")

    def _render_all_users_verbose(self, users: list) -> None:
        """Render all enabled users with detailed info (verbose mode)"""
        self.console.print("\n[bold blue]ALL ENABLED USERS (DETAILED)[/]\n")

        table = Table(box=box.ROUNDED, border_style="blue")
        table.add_column("Username", style="bold white")
        table.add_column("Display Name", style="cyan", max_width=20)
        table.add_column("Groups", style="dim")
        table.add_column("UAC", style="dim")
        table.add_column("Flags", style="yellow", max_width=30)

        for user in users[:100]:  # Limit to 100
            # Count groups
            groups = len(user.member_of)
            group_str = str(groups) if groups else "0"

            # UAC hex
            uac_hex = f"0x{user.user_account_control:04X}"

            # Important flags only
            flags = []
            if user.admin_count:
                flags.append("[red]Admin[/]")
            if user.is_kerberoastable:
                flags.append("[yellow]SPN[/]")
            if user.dont_require_preauth:
                flags.append("[red]NoPreAuth[/]")
            if user.trusted_for_delegation:
                flags.append("[red]Deleg[/]")
            if user.password_never_expires:
                flags.append("NoPwdExp")
            if user.is_locked:
                flags.append("[dim]Locked[/]")

            table.add_row(
                user.sam_account_name,
                user.display_name[:20] if user.display_name else "-",
                group_str,
                uac_hex,
                ", ".join(flags) if flags else "-"
            )

        self.console.print(table)

        if len(users) > 100:
            self.console.print(f"[dim]... and {len(users) - 100} more users[/]")

    def _render_user_hints(self, summary: LdapSummary) -> None:
        """Render possible users from partial LDAP entries (anonymous bind)"""
        user_hints = summary.user_hints

        self.console.print("\n[bold yellow]POSSIBLE USERS (Anonymous LDAP - unconfirmed)[/]\n")
        self.console.print(
            "[dim]These entries have DN but no objectClass (common with anonymous bind).[/]\n"
            "[dim]Verify with: kerbrute userenum or GetNPUsers.py[/]\n"
        )

        table = Table(box=box.ROUNDED, border_style="yellow")
        table.add_column("CN (Display Name)", style="white")
        table.add_column("Username Guesses", style="cyan")

        for hint in user_hints[:20]:  # Limit to first 20
            guesses = ", ".join(hint.username_guesses[:4])  # First 4 guesses
            if len(hint.username_guesses) > 4:
                guesses += f" (+{len(hint.username_guesses) - 4})"
            table.add_row(hint.cn, guesses)

        self.console.print(table)

        if len(user_hints) > 20:
            self.console.print(f"[dim]... and {len(user_hints) - 20} more hints[/]")

        # All username guesses for easy copy
        all_guesses = summary.all_username_guesses
        if all_guesses:
            self.console.print(f"\n[bold]Username Wordlist:[/] [cyan]{', '.join(all_guesses)}[/]")
            self.console.print(
                "\n[dim]Save to file: crack prism <file> -f json | jq -r '.username_guesses[]' > users.txt[/]"
            )

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


class DomainReportFormatter:
    """Rich library formatter for Domain Report from Neo4j"""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def render_report(
        self,
        report: dict,
        section: str = 'all',
        verbose: bool = False
    ) -> None:
        """Render domain report to console

        Args:
            report: Dict from adapter.query_domain_report()
            section: 'all', 'policy', 'users', 'computers', 'credentials', 'groups', 'tickets'
            verbose: If True, show additional details
        """
        if not report or not report.get('domain'):
            self.console.print("[red]No domain data found[/]")
            return

        # Header
        self._render_header(report['domain'])

        # Sections based on filter
        if section in ('all', 'policy') and report.get('policy'):
            self._render_password_policy(report['policy'])

        if section in ('all', 'users') and report.get('users'):
            self._render_attack_targets(report['users'])
            self._render_users_table(report['users'], verbose)

        if section in ('all', 'groups') and report.get('groups'):
            self._render_groups_table(report['groups'])

        if section in ('all', 'computers') and report.get('computers'):
            self._render_computers_table(report['computers'])

        if section in ('all', 'credentials') and report.get('credentials'):
            self._render_credentials_table(report['credentials'])

        if section in ('all', 'tickets') and report.get('tickets'):
            self._render_tickets_table(report['tickets'])

        # Stats summary
        if section == 'all' and report.get('stats'):
            self._render_stats_summary(report['stats'])

    def _render_header(self, domain: dict) -> None:
        """Render domain header panel"""
        name = domain.get('name', 'Unknown')
        dns_name = domain.get('dns_name', '')
        level = domain.get('functional_level_name', '')
        source = domain.get('source', '')

        header_lines = [f"[bold cyan]{name}[/]"]
        if dns_name:
            header_lines.append(f"DNS: {dns_name}")
        if level:
            header_lines.append(f"Functional Level: {level}")
        if source:
            header_lines.append(f"[dim]Source: {source}[/]")

        panel = Panel(
            "\n".join(header_lines),
            title="[bold white]PRISM Domain Report[/]",
            border_style="cyan",
            box=box.DOUBLE
        )
        self.console.print(panel)

    def _render_password_policy(self, policy: dict) -> None:
        """Render password policy with weakness indicators"""
        self.console.print("\n[bold magenta]PASSWORD POLICY[/]\n")

        table = Table(box=box.ROUNDED, border_style="magenta")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="white")
        table.add_column("Status", style="dim")

        # Min length
        min_len = policy.get('min_length', 0)
        status = "[red]WEAK[/]" if min_len < 8 else "[green]OK[/]"
        table.add_row("Min Length", str(min_len), status)

        # Complexity
        complexity = policy.get('complexity', False)
        status = "[green]OK[/]" if complexity else "[red]WEAK[/]"
        table.add_row("Complexity", "Yes" if complexity else "No", status)

        # Lockout
        lockout = policy.get('lockout_threshold', 0)
        if lockout == 0:
            status = "[red]NO LOCKOUT[/]"
            lockout_str = "Disabled"
        else:
            status = "[green]OK[/]" if lockout <= 5 else "[yellow]HIGH[/]"
            lockout_str = f"{lockout} attempts"
        table.add_row("Lockout", lockout_str, status)

        # Lockout duration
        duration = policy.get('lockout_duration', 0)
        if duration and lockout:
            table.add_row("Lockout Duration", f"{duration} min", "")

        # Max age
        max_age = policy.get('max_pwd_age', 0)
        if max_age:
            status = "[yellow]LONG[/]" if max_age > 90 else ""
            table.add_row("Max Password Age", f"{max_age} days", status)

        # History
        history = policy.get('history_length', 0)
        if history:
            table.add_row("Password History", str(history), "")

        self.console.print(table)

        # Weak policy warning
        if policy.get('is_weak'):
            self.console.print("\n[bold red]WARNING: Weak password policy detected![/]")

    def _render_attack_targets(self, users: list) -> None:
        """Render high-value attack targets"""
        targets = [u for u in users if (
            u.get('is_kerberoastable') or
            u.get('is_asrep_roastable') or
            u.get('description') or
            u.get('admin_count') or
            u.get('trusted_for_delegation')
        )]

        if not targets:
            return

        self.console.print("\n[bold yellow]ATTACK TARGETS (High Value)[/]\n")

        table = Table(box=box.ROUNDED, border_style="yellow")
        table.add_column("Username", style="bold white")
        table.add_column("Attack Path", style="red")
        table.add_column("Description", style="green", max_width=30)
        table.add_column("SPNs", style="cyan", max_width=30)

        for user in targets[:15]:  # Limit to 15
            # Determine attack path
            paths = []
            if user.get('is_kerberoastable'):
                paths.append("Kerberoast")
            if user.get('is_asrep_roastable'):
                paths.append("AS-REP")
            if user.get('description'):
                paths.append("Description")
            if user.get('admin_count'):
                paths.append("Admin")
            if user.get('trusted_for_delegation'):
                paths.append("Delegation")

            path_str = ", ".join(paths)

            # Description
            desc = user.get('description', '') or ''
            if len(desc) > 30:
                desc = desc[:27] + "..."

            # SPNs
            spns = user.get('spns') or []
            spn_str = spns[0] if spns else ""
            if len(spns) > 1:
                spn_str += f" (+{len(spns)-1})"

            table.add_row(
                user.get('name', ''),
                path_str,
                desc,
                spn_str
            )

        self.console.print(table)

        if len(targets) > 15:
            self.console.print(f"[dim]... and {len(targets) - 15} more targets[/]")

    def _render_users_table(self, users: list, verbose: bool = False) -> None:
        """Render all users table"""
        self.console.print(f"\n[bold blue]ALL USERS ({len(users)} total)[/]\n")

        table = Table(box=box.ROUNDED, border_style="blue")
        table.add_column("Username", style="bold white")
        table.add_column("Display Name", style="cyan", max_width=20)
        table.add_column("Enabled", style="dim")
        table.add_column("Admin", style="red")
        table.add_column("Flags", style="yellow", max_width=25)

        limit = 50 if verbose else 20
        for user in users[:limit]:
            enabled = "[green]Y[/]" if user.get('is_enabled') else "[red]N[/]"
            admin = "[red]Y[/]" if user.get('admin_count') else ""

            # Build flags
            flags = []
            if user.get('is_kerberoastable'):
                flags.append("KERB")
            if user.get('is_asrep_roastable'):
                flags.append("ASREP")
            if user.get('trusted_for_delegation'):
                flags.append("DELEG")
            if user.get('high_value'):
                flags.append("HV")

            table.add_row(
                user.get('name', ''),
                (user.get('display_name', '') or '')[:20],
                enabled,
                admin,
                ", ".join(flags) if flags else "-"
            )

        self.console.print(table)

        if len(users) > limit:
            self.console.print(f"[dim]... and {len(users) - limit} more users[/]")

    def _render_groups_table(self, groups: list) -> None:
        """Render groups table"""
        if not groups:
            return

        self.console.print(f"\n[bold magenta]GROUPS ({len(groups)} total)[/]\n")

        # Separate high-value groups
        high_value = [g for g in groups if g.get('is_high_value') or g.get('admin_count')]

        if high_value:
            self.console.print("[bold yellow]High-Value Groups:[/]\n")
            table = Table(box=box.ROUNDED, border_style="yellow")
            table.add_column("Group", style="bold white")
            table.add_column("Members", style="cyan")
            table.add_column("Description", style="dim", max_width=40)

            for group in high_value:
                desc = group.get('description', '') or ''
                if len(desc) > 40:
                    desc = desc[:37] + "..."

                table.add_row(
                    group.get('name', ''),
                    str(group.get('member_count', 0)),
                    desc
                )

            self.console.print(table)

        # Other groups (show count only)
        other = [g for g in groups if g not in high_value]
        if other:
            self.console.print(f"\n[dim]Other groups: {len(other)}[/]")

    def _render_computers_table(self, computers: list) -> None:
        """Render computers table"""
        if not computers:
            return

        self.console.print(f"\n[bold cyan]COMPUTERS ({len(computers)} total)[/]\n")

        table = Table(box=box.ROUNDED, border_style="cyan")
        table.add_column("Name", style="bold white")
        table.add_column("DNS Hostname", style="cyan", max_width=35)
        table.add_column("OS", style="dim", max_width=25)
        table.add_column("IP", style="yellow")
        table.add_column("DC", style="red")
        table.add_column("Deleg", style="yellow")

        for computer in computers[:20]:
            is_dc = "[red]Y[/]" if computer.get('is_dc') else ""
            deleg = "[yellow]Y[/]" if computer.get('trusted_for_delegation') else ""

            os_info = computer.get('os', '') or ''
            if len(os_info) > 25:
                os_info = os_info[:22] + "..."

            table.add_row(
                computer.get('name', ''),
                (computer.get('dns_hostname', '') or '')[:35],
                os_info,
                computer.get('ip', '') or '',
                is_dc,
                deleg
            )

        self.console.print(table)

        if len(computers) > 20:
            self.console.print(f"[dim]... and {len(computers) - 20} more computers[/]")

    def _render_credentials_table(self, credentials: list) -> None:
        """Render credentials table"""
        if not credentials:
            return

        self.console.print(f"\n[bold green]CREDENTIALS ({len(credentials)} total)[/]\n")

        table = Table(box=box.ROUNDED, border_style="green")
        table.add_column("Username", style="bold white")
        table.add_column("Type", style="cyan")
        table.add_column("Value", style="yellow", max_width=45)
        table.add_column("Source", style="dim")
        table.add_column("HV", style="red")

        for cred in credentials[:30]:
            cred_type = cred.get('cred_type', '')
            value = cred.get('value', '')

            # Mask or truncate value
            if cred_type in ('cleartext', 'CLEARTEXT'):
                # Show cleartext passwords fully (they're valuable)
                style = "bold green"
            else:
                # Truncate hashes
                if len(value) > 45:
                    value = value[:42] + "..."
                style = "yellow"

            hv = "[red]Y[/]" if cred.get('high_value') else ""

            table.add_row(
                cred.get('username', ''),
                cred_type,
                f"[{style}]{value}[/]",
                cred.get('source_tool', '') or '',
                hv
            )

        self.console.print(table)

        if len(credentials) > 30:
            self.console.print(f"[dim]... and {len(credentials) - 30} more credentials[/]")

    def _render_tickets_table(self, tickets: list) -> None:
        """Render Kerberos tickets table"""
        if not tickets:
            return

        self.console.print(f"\n[bold magenta]KERBEROS TICKETS ({len(tickets)} total)[/]\n")

        table = Table(box=box.ROUNDED, border_style="magenta")
        table.add_column("Client", style="bold white")
        table.add_column("Type", style="cyan")
        table.add_column("Service", style="yellow", max_width=35)
        table.add_column("Expires", style="dim")
        table.add_column("Saved", style="green")

        for ticket in tickets[:20]:
            ticket_type = "TGT" if ticket.get('is_tgt') else "TGS"

            service = ticket.get('service_target', '') or ticket.get('service_type', '')
            if len(service) > 35:
                service = service[:32] + "..."

            end_time = ticket.get('end_time', '')
            if end_time and len(end_time) > 16:
                end_time = end_time[:16]

            saved = "[green]Y[/]" if ticket.get('saved_path') else ""

            table.add_row(
                ticket.get('client_name', ''),
                ticket_type,
                service,
                end_time,
                saved
            )

        self.console.print(table)

        if len(tickets) > 20:
            self.console.print(f"[dim]... and {len(tickets) - 20} more tickets[/]")

    def _render_stats_summary(self, stats: dict) -> None:
        """Render statistics summary line"""
        self.console.print("\n" + "─" * 70)

        parts = []
        if stats.get('total_users'):
            parts.append(f"{stats['total_users']} users")
        if stats.get('total_computers'):
            parts.append(f"{stats['total_computers']} computers")
        if stats.get('total_credentials'):
            parts.append(f"{stats['total_credentials']} creds")
        if stats.get('total_tickets'):
            parts.append(f"{stats['total_tickets']} tickets")
        if stats.get('kerberoastable'):
            parts.append(f"[yellow]{stats['kerberoastable']} kerberoastable[/]")
        if stats.get('asrep_roastable'):
            parts.append(f"[red]{stats['asrep_roastable']} asrep[/]")
        if stats.get('domain_controllers'):
            parts.append(f"{stats['domain_controllers']} DCs")

        self.console.print(f"[bold]Summary:[/] {' | '.join(parts)}")

    def format_json(self, report: dict) -> str:
        """Format report as JSON"""
        import json
        return json.dumps(report, indent=2, default=str)

    def format_markdown(self, report: dict) -> str:
        """Format report as Markdown"""
        lines = [
            f"# Domain Report: {report.get('domain', {}).get('name', 'Unknown')}",
            "",
            f"**DNS:** {report.get('domain', {}).get('dns_name', '')}",
            f"**Source:** {report.get('domain', {}).get('source', '')}",
            "",
        ]

        # Policy
        policy = report.get('policy', {})
        if policy:
            lines.extend([
                "## Password Policy",
                "",
                f"- **Min Length:** {policy.get('min_length', 'N/A')}",
                f"- **Complexity:** {'Yes' if policy.get('complexity') else 'No'}",
                f"- **Lockout:** {policy.get('lockout_threshold', 0) or 'Disabled'}",
                "",
            ])

        # Users
        users = report.get('users', [])
        if users:
            lines.extend([
                f"## Users ({len(users)})",
                "",
                "| Username | Display Name | Enabled | Flags |",
                "|----------|--------------|---------|-------|",
            ])
            for u in users[:30]:
                flags = []
                if u.get('is_kerberoastable'): flags.append("KERB")
                if u.get('is_asrep_roastable'): flags.append("ASREP")
                if u.get('admin_count'): flags.append("ADMIN")
                enabled = "Y" if u.get('is_enabled') else "N"
                lines.append(f"| {u.get('name', '')} | {u.get('display_name', '')} | {enabled} | {', '.join(flags)} |")
            lines.append("")

        # Credentials
        creds = report.get('credentials', [])
        if creds:
            lines.extend([
                f"## Credentials ({len(creds)})",
                "",
                "| Username | Type | Source |",
                "|----------|------|--------|",
            ])
            for c in creds[:20]:
                lines.append(f"| {c.get('username', '')} | {c.get('cred_type', '')} | {c.get('source_tool', '')} |")
            lines.append("")

        # Stats
        stats = report.get('stats', {})
        if stats:
            lines.extend([
                "## Summary",
                "",
                f"- **Users:** {stats.get('total_users', 0)} ({stats.get('enabled_users', 0)} enabled)",
                f"- **Computers:** {stats.get('total_computers', 0)} ({stats.get('domain_controllers', 0)} DCs)",
                f"- **Credentials:** {stats.get('total_credentials', 0)}",
                f"- **Kerberoastable:** {stats.get('kerberoastable', 0)}",
                f"- **AS-REP Roastable:** {stats.get('asrep_roastable', 0)}",
            ])

        return "\n".join(lines)

    def format_markdown_full(self, report: dict) -> str:
        """Format report as full Markdown with timestamps and source tracking"""
        from datetime import datetime
        from collections import Counter

        domain_info = report.get('domain', {})
        lines = [
            f"# Domain Report: {domain_info.get('name', 'Unknown')}",
            "",
            "## Report Metadata",
            "",
            f"- **Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"- **Domain:** {domain_info.get('name', '')}",
            f"- **DNS:** {domain_info.get('dns_name', '')}",
            f"- **Source:** {domain_info.get('source', '')}",
            "",
        ]

        # Password Policy
        policy = report.get('policy', {})
        if policy:
            lines.extend([
                "## Password Policy",
                "",
                f"- **Min Length:** {policy.get('min_length', 'N/A')}",
                f"- **Complexity Required:** {'Yes' if policy.get('complexity') else 'No'}",
                f"- **Lockout Threshold:** {policy.get('lockout_threshold', 0) or 'Disabled'}",
                f"- **Max Password Age:** {policy.get('max_pwd_age', 'N/A')}",
                "",
            ])

        # Source Summary (credentials by tool)
        creds = report.get('credentials', [])
        if creds:
            source_counts = Counter(c.get('source_tool', 'unknown') for c in creds)
            lines.extend([
                "## Source Summary",
                "",
                "| Source Tool | Credential Count |",
                "|-------------|------------------|",
            ])
            for source, count in sorted(source_counts.items(), key=lambda x: -x[1]):
                lines.append(f"| {source or 'unknown'} | {count} |")
            lines.append("")

        # Duplicates section (credentials seen multiple times)
        duplicates = [c for c in creds if c.get('occurrences', 1) > 1]
        if duplicates:
            lines.extend([
                "## Duplicate Credentials",
                "",
                "| Username | Type | Occurrences | First Seen | Last Seen |",
                "|----------|------|-------------|------------|-----------|",
            ])
            for c in sorted(duplicates, key=lambda x: -x.get('occurrences', 1)):
                first_seen = self._format_datetime(c.get('first_seen'))
                last_seen = self._format_datetime(c.get('last_seen'))
                lines.append(
                    f"| {c.get('username', '')} | {c.get('cred_type', '')} | "
                    f"{c.get('occurrences', 1)} | {first_seen} | {last_seen} |"
                )
            lines.append("")

        # Full Users table (no truncation)
        users = report.get('users', [])
        if users:
            lines.extend([
                f"## Users ({len(users)})",
                "",
                "| Username | Display Name | Enabled | Flags | First Seen | Last Seen |",
                "|----------|--------------|---------|-------|------------|-----------|",
            ])
            for u in users:  # No truncation
                flags = []
                if u.get('is_kerberoastable'): flags.append("KERB")
                if u.get('is_asrep_roastable'): flags.append("ASREP")
                if u.get('admin_count'): flags.append("ADMIN")
                if u.get('trusted_for_delegation'): flags.append("DELEG")
                if u.get('high_value'): flags.append("HV")
                enabled = "Y" if u.get('is_enabled') else "N"
                first_seen = self._format_datetime(u.get('first_seen'))
                last_seen = self._format_datetime(u.get('last_seen'))
                lines.append(
                    f"| {u.get('name', '')} | {u.get('display_name', '') or '-'} | "
                    f"{enabled} | {', '.join(flags) or '-'} | {first_seen} | {last_seen} |"
                )
            lines.append("")

        # Full Computers table (no truncation)
        computers = report.get('computers', [])
        if computers:
            lines.extend([
                f"## Computers ({len(computers)})",
                "",
                "| Name | DNS Hostname | OS | DC | First Seen | Last Seen |",
                "|------|--------------|----|----|------------|-----------|",
            ])
            for c in computers:  # No truncation
                is_dc = "Yes" if c.get('is_dc') else "No"
                os_info = c.get('os', '') or '-'
                first_seen = self._format_datetime(c.get('first_seen'))
                last_seen = self._format_datetime(c.get('last_seen'))
                lines.append(
                    f"| {c.get('name', '')} | {c.get('dns_hostname', '') or '-'} | "
                    f"{os_info} | {is_dc} | {first_seen} | {last_seen} |"
                )
            lines.append("")

        # Full Credentials table (no truncation)
        if creds:
            lines.extend([
                f"## Credentials ({len(creds)})",
                "",
                "| Username | Type | Source | High Value | Occurrences | First Seen | Last Seen |",
                "|----------|------|--------|------------|-------------|------------|-----------|",
            ])
            for c in creds:  # No truncation
                hv = "Yes" if c.get('high_value') else "No"
                first_seen = self._format_datetime(c.get('first_seen'))
                last_seen = self._format_datetime(c.get('last_seen'))
                lines.append(
                    f"| {c.get('username', '')} | {c.get('cred_type', '')} | "
                    f"{c.get('source_tool', '')} | {hv} | {c.get('occurrences', 1)} | "
                    f"{first_seen} | {last_seen} |"
                )
            lines.append("")

        # Groups table
        groups = report.get('groups', [])
        if groups:
            lines.extend([
                f"## Groups ({len(groups)})",
                "",
                "| Name | High Value | Admin Count | Members |",
                "|------|------------|-------------|---------|",
            ])
            for g in groups:
                hv = "Yes" if g.get('is_high_value') else "No"
                lines.append(
                    f"| {g.get('name', '')} | {hv} | "
                    f"{g.get('admin_count', 0) or '-'} | {g.get('member_count', 0) or '-'} |"
                )
            lines.append("")

        # Tickets table
        tickets = report.get('tickets', [])
        if tickets:
            lines.extend([
                f"## Kerberos Tickets ({len(tickets)})",
                "",
                "| Client | Type | Service | Expires |",
                "|--------|------|---------|---------|",
            ])
            for t in tickets:
                ticket_type = "TGT" if t.get('is_tgt') else "TGS"
                end_time = self._format_datetime(t.get('end_time'))
                lines.append(
                    f"| {t.get('client_name', '')} | {ticket_type} | "
                    f"{t.get('service_target', '') or '-'} | {end_time} |"
                )
            lines.append("")

        # Stats Summary
        stats = report.get('stats', {})
        if stats:
            lines.extend([
                "## Summary Statistics",
                "",
                f"- **Total Users:** {stats.get('total_users', 0)} ({stats.get('enabled_users', 0)} enabled)",
                f"- **Total Computers:** {stats.get('total_computers', 0)} ({stats.get('domain_controllers', 0)} DCs)",
                f"- **Total Credentials:** {stats.get('total_credentials', 0)}",
                f"- **Total Groups:** {stats.get('total_groups', 0)} ({stats.get('high_value_groups', 0)} high-value)",
                f"- **Total Tickets:** {stats.get('total_tickets', 0)}",
                "",
                "### Attack Surface",
                "",
                f"- **Kerberoastable Users:** {stats.get('kerberoastable', 0)}",
                f"- **AS-REP Roastable Users:** {stats.get('asrep_roastable', 0)}",
                f"- **High-Value Users:** {stats.get('high_value_users', 0)}",
            ])

        return "\n".join(lines)

    def _format_datetime(self, dt) -> str:
        """Format datetime for display, handling various input types"""
        if dt is None:
            return "-"
        if isinstance(dt, str):
            return dt[:19] if len(dt) > 19 else dt
        try:
            return dt.strftime('%Y-%m-%d %H:%M')
        except (AttributeError, TypeError):
            return str(dt)[:19] if dt else "-"

    def format_json_full(self, report: dict) -> str:
        """Format report as full JSON with metadata and source grouping"""
        import json
        from datetime import datetime
        from collections import defaultdict

        # Add metadata
        enhanced_report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'domain': report.get('domain', {}).get('name', ''),
                'dns_name': report.get('domain', {}).get('dns_name', ''),
            },
            'domain': report.get('domain', {}),
            'policy': report.get('policy', {}),
            'stats': report.get('stats', {}),
            'users': report.get('users', []),
            'computers': report.get('computers', []),
            'groups': report.get('groups', []),
            'tickets': report.get('tickets', []),
        }

        # Group credentials by source
        creds = report.get('credentials', [])
        creds_by_source = defaultdict(list)
        for c in creds:
            source = c.get('source_tool', 'unknown') or 'unknown'
            creds_by_source[source].append(c)

        enhanced_report['credentials'] = creds
        enhanced_report['credentials_by_source'] = dict(creds_by_source)

        # Extract duplicates
        duplicates = [
            {
                'username': c.get('username'),
                'cred_type': c.get('cred_type'),
                'occurrences': c.get('occurrences', 1),
                'source_tool': c.get('source_tool'),
            }
            for c in creds if c.get('occurrences', 1) > 1
        ]
        enhanced_report['duplicates'] = duplicates

        return json.dumps(enhanced_report, indent=2, default=str)


class DomainListFormatter:
    """Formatter for listing available domains"""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def render_domains(self, domains: list) -> None:
        """Render available domains table"""
        if not domains:
            self.console.print("[yellow]No domains found in database[/]")
            return

        self.console.print("\n[bold cyan]AVAILABLE DOMAINS[/]\n")

        table = Table(box=box.ROUNDED, border_style="cyan")
        table.add_column("Domain", style="bold white")
        table.add_column("DNS Name", style="cyan")
        table.add_column("Users", style="yellow")
        table.add_column("Computers", style="green")
        table.add_column("Credentials", style="red")
        table.add_column("Source", style="dim")

        for domain in domains:
            table.add_row(
                domain.get('name', ''),
                domain.get('dns_name', '') or '',
                str(domain.get('user_count', 0)),
                str(domain.get('computer_count', 0)),
                str(domain.get('credential_count', 0)),
                domain.get('source', '') or ''
            )

        self.console.print(table)
        self.console.print(
            "\n[dim]Usage: crack prism report --domain DOMAIN_NAME[/]"
        )
