"""
PRISM CLI - Command-line interface for parsing security tool output

Usage:
    crack prism <file>                          # Auto-detect and parse
    crack prism <file> -f json                  # JSON output
    crack prism <file> --neo4j                  # Import to neo4j
    crack prism --list-parsers                  # Show available parsers
    crack prism report --domain DOMAIN          # Generate domain report from Neo4j
    crack prism report --list-domains           # List available domains
    crack prism crawl <directory>               # Recursively parse all files
    crack prism crawl <directory> --depth 3     # Limit recursion depth
    crack prism crawl <directory> --dry-run     # Preview without parsing
"""

import argparse
import os
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from rich.console import Console
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = None

from .parsers.registry import PrismParserRegistry
from .display.formatter import (
    PrismFormatter, JSONFormatter, MarkdownFormatter,
    NmapFormatter, NmapJSONFormatter, NmapMarkdownFormatter,
    SmbmapFormatter, SmbmapJSONFormatter, SmbmapMarkdownFormatter,
    LdapFormatter, LdapJSONFormatter, LdapMarkdownFormatter,
    DomainReportFormatter, DomainListFormatter
)
from .models import LdapSummary, NmapScanSummary, SmbmapSummary


def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser"""
    parser = argparse.ArgumentParser(
        prog="crack prism",
        description="PRISM - Parse and distill security tool output",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    crack prism mimikatz.txt                    # Parse, display, import to neo4j
    crack prism mimikatz.txt -o creds.json      # Also save to file
    crack prism mimikatz.txt --no-neo4j         # Skip neo4j import
    crack prism mimikatz.txt -f json            # JSON to stdout (for piping)
    crack prism --list-parsers                  # Show available parsers

Default behavior:
    - Display colorized table to console
    - Import credentials to Neo4j (if available)
        """
    )

    parser.add_argument(
        "file",
        type=Path,
        nargs="?",
        help="File to parse (mimikatz output, etc.)"
    )

    parser.add_argument(
        "-f", "--format",
        choices=["table", "json", "markdown"],
        default="table",
        help="Output format (default: table)"
    )

    parser.add_argument(
        "--host", "--hostname",
        type=str,
        dest="hostname",
        help="Source hostname (auto-detected if not provided)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show all credentials including service accounts"
    )

    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Save output to file (format auto-detected from extension: .json, .md, .txt)"
    )

    parser.add_argument(
        "--no-neo4j",
        action="store_true",
        help="Skip Neo4j import (imports by default if available)"
    )

    parser.add_argument(
        "--list-parsers",
        action="store_true",
        help="List available parsers"
    )

    parser.add_argument(
        "--parser",
        type=str,
        help="Force specific parser (bypass auto-detection)"
    )

    parser.add_argument(
        "--no-dedup",
        action="store_true",
        help="Disable credential deduplication"
    )

    parser.add_argument(
        "--stats-only",
        action="store_true",
        help="Show statistics only (no credential details)"
    )

    return parser


def print_error(msg: str, console: Optional['Console'] = None) -> None:
    """Print error message"""
    if console and RICH_AVAILABLE:
        console.print(f"[bold red]Error:[/] {msg}")
    else:
        print(f"Error: {msg}", file=sys.stderr)


def print_info(msg: str, console: Optional['Console'] = None) -> None:
    """Print info message"""
    if console and RICH_AVAILABLE:
        console.print(f"[dim]{msg}[/]")
    else:
        print(msg)


def cleanup_temp_file(temp_path: Optional[str]) -> None:
    """Remove temp file if it exists"""
    if temp_path and Path(temp_path).exists():
        try:
            os.unlink(temp_path)
        except OSError:
            pass


def list_parsers(console: Optional['Console'] = None) -> int:
    """List available parsers"""
    parsers = PrismParserRegistry.get_all_parsers()

    if console and RICH_AVAILABLE:
        console.print("[bold]Available PRISM Parsers:[/]\n")
        for p in parsers:
            console.print(f"  [cyan]{p.name}[/] - {p.description}")
    else:
        print("Available PRISM Parsers:\n")
        for p in parsers:
            print(f"  {p.name} - {p.description}")

    return 0


# ============================================================================
# CRAWL FEATURE - Recursive directory parsing
# ============================================================================

# Binary file extensions to skip (not worth reading)
BINARY_EXTENSIONS = frozenset({
    '.exe', '.dll', '.so', '.bin', '.dat', '.db', '.sqlite', '.evtx',
    '.zip', '.gz', '.tar', '.7z', '.rar', '.bz2', '.xz',
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.webp',
    '.pdf', '.docx', '.xlsx', '.pptx', '.vsdx', '.odt',
    '.pol', '.lnk', '.msi', '.cab', '.sys', '.drv',
    '.mp3', '.mp4', '.avi', '.mkv', '.wav', '.flac'
})

# Max file size to attempt parsing (10MB)
MAX_PARSE_SIZE = 10 * 1024 * 1024


def is_binary_file(filepath: str) -> bool:
    """Check if file appears to be binary (not text-parseable)

    Args:
        filepath: Path to file

    Returns:
        True if file should be skipped as binary
    """
    # Fast path: check extension
    ext = Path(filepath).suffix.lower()
    if ext in BINARY_EXTENSIONS:
        return True

    # Check for null bytes in first 8KB (indicates binary)
    try:
        with open(filepath, 'rb') as f:
            chunk = f.read(8192)
            return b'\x00' in chunk
    except (IOError, OSError):
        return True  # Can't read = skip


def _guess_content_type(filepath: str) -> str:
    """Guess potential content type based on filename/path for unparsed files

    Args:
        filepath: Relative path to file

    Returns:
        Human-readable hint about what the file might contain
    """
    path_lower = filepath.lower()
    name = Path(filepath).name.lower()
    ext = Path(filepath).suffix.lower()

    # Registry hives
    if any(h in name for h in ['sam', 'security', 'system', 'software', 'ntuser.dat']):
        if '.bak' in name or 'config' in path_lower:
            return "Registry hive backup (use secretsdump)"

    # Event logs
    if 'evtx' in name or 'logs' in path_lower:
        return "Event log (parse with evtxexport)"

    # SQL logs
    if 'errorlog' in name or 'sql' in path_lower:
        return "SQL Server log (check for creds)"

    # Credential-related files
    if any(c in name for c in ['cred', 'pass', 'secret', 'auth', 'login']):
        return "May contain credentials (review manually)"

    # Notes and documentation
    if 'note' in name or 'readme' in name or name.endswith('.txt'):
        return "Notes/text (review for sensitive info)"

    # Backup files
    if '.bak' in name or 'backup' in path_lower:
        return "Backup file (may contain sensitive data)"

    # Config files
    if ext in ['.conf', '.cfg', '.ini', '.config']:
        return "Config file (check for hardcoded creds)"

    # Log files
    if ext == '.log' or 'log' in path_lower:
        return "Log file (check for sensitive data)"

    # Temp files
    if 'temp' in path_lower or name.startswith('~') or '.tmp' in name:
        return "Temp file (usually not interesting)"

    return "Unknown (review manually)"


def walk_with_depth(directory: str, max_depth: int = -1):
    """Walk directory tree with optional depth limit

    Args:
        directory: Root directory to walk
        max_depth: Maximum recursion depth (-1 = unlimited)

    Yields:
        Full file paths
    """
    base_depth = directory.rstrip(os.sep).count(os.sep)

    for root, dirs, files in os.walk(directory):
        current_depth = root.count(os.sep) - base_depth

        # Stop descending if at max depth
        if max_depth >= 0 and current_depth >= max_depth:
            dirs.clear()

        # Sort for consistent ordering
        dirs.sort()
        files.sort()

        for filename in files:
            yield os.path.join(root, filename)


def discover_parseable_files(
    directory: str,
    max_depth: int = -1,
    verbose: bool = False
) -> Tuple[List[Tuple[str, 'PrismParser']], Dict[str, List[str]]]:
    """Discover which files in directory can be parsed

    Args:
        directory: Root directory to scan
        max_depth: Maximum recursion depth (-1 = unlimited)
        verbose: Include detailed skip reasons

    Returns:
        Tuple of (parseable_files, skipped_files)
        - parseable_files: List of (filepath, parser) tuples
        - skipped_files: Dict mapping skip_reason -> list of filepaths
    """
    parseable = []
    skipped = defaultdict(list)

    for filepath in walk_with_depth(directory, max_depth):
        try:
            filesize = os.path.getsize(filepath)
        except OSError:
            skipped['unreadable'].append(filepath)
            continue

        # Skip empty files
        if filesize == 0:
            skipped['empty'].append(filepath)
            continue

        # Skip oversized files
        if filesize > MAX_PARSE_SIZE:
            skipped['too_large'].append(filepath)
            continue

        # Skip binary files
        if is_binary_file(filepath):
            skipped['binary'].append(filepath)
            continue

        # Try auto-detection
        parser = PrismParserRegistry.get_parser(filepath)
        if parser:
            parseable.append((filepath, parser))
        else:
            skipped['no_parser'].append(filepath)

    return parseable, dict(skipped)


def print_crawl_discovery(
    directory: str,
    parseable: List[Tuple[str, 'PrismParser']],
    skipped: Dict[str, List[str]],
    max_depth: int,
    verbose: bool,
    console: Optional['Console'] = None
) -> None:
    """Print discovery phase summary

    Args:
        directory: Root directory scanned
        parseable: List of (filepath, parser) tuples
        skipped: Dict of skip_reason -> filepaths
        max_depth: Depth limit used
        verbose: Show detailed skip info
        console: Rich console for formatted output
    """
    total_files = len(parseable) + sum(len(v) for v in skipped.values())
    total_skipped = sum(len(v) for v in skipped.values())

    if console and RICH_AVAILABLE:
        from rich.table import Table
        from rich.panel import Panel
        from rich import box

        # Header panel
        depth_str = "unlimited" if max_depth < 0 else str(max_depth)
        console.print(Panel(
            f"[bold]Directory:[/] {directory}\n[bold]Depth:[/] {depth_str}",
            title="PRISM CRAWL",
            border_style="cyan"
        ))

        # Discovery stats
        console.print("\n[bold cyan]DISCOVERY[/]")
        console.print(f"  Files scanned:  {total_files}")

        if parseable:
            pct = len(parseable) * 100 // total_files if total_files else 0
            console.print(f"  [green]Parseable:[/]      {len(parseable)}  ({pct}%)")
        else:
            console.print(f"  [yellow]Parseable:[/]      0")

        console.print(f"  Skipped:        {total_skipped}")

        # Skip breakdown
        for reason, files in sorted(skipped.items()):
            if files:
                console.print(f"    - {reason}: {len(files)}")

        # Parseable files by parser
        if parseable:
            console.print("\n[bold cyan]PARSEABLE FILES[/]")

            # Group by parser
            by_parser = defaultdict(list)
            for filepath, parser in parseable:
                by_parser[parser.name].append(filepath)

            table = Table(show_header=True)
            table.add_column("Parser", style="cyan")
            table.add_column("Count", justify="right")
            table.add_column("Files", style="dim")

            for parser_name, files in sorted(by_parser.items()):
                # Show relative paths, truncate list
                rel_files = [os.path.relpath(f, directory) for f in files]
                display = ", ".join(rel_files[:3])
                if len(rel_files) > 3:
                    display += f", ... (+{len(rel_files) - 3})"
                table.add_row(parser_name, str(len(files)), display)

            console.print(table)

        # Always show unparsed files section
        if skipped.get('no_parser'):
            console.print("\n[bold cyan]UNPARSED FILES[/]")

            unparsed_table = Table(show_header=True, box=box.ROUNDED, border_style="dim")
            unparsed_table.add_column("File", style="dim")
            unparsed_table.add_column("Potential Content", style="yellow")

            unparsed_files = skipped['no_parser']
            display_limit = len(unparsed_files) if verbose else min(10, len(unparsed_files))

            for f in unparsed_files[:display_limit]:
                rel_path = os.path.relpath(f, directory)
                # Guess potential content type based on filename
                hint = _guess_content_type(rel_path)
                unparsed_table.add_row(rel_path, hint)

            console.print(unparsed_table)

            if not verbose and len(unparsed_files) > 10:
                console.print(f"  [dim]... and {len(unparsed_files) - 10} more (use -v to see all)[/]")

    else:
        # Plain text output
        depth_str = "unlimited" if max_depth < 0 else str(max_depth)
        print(f"\n{'='*60}")
        print(f"PRISM CRAWL")
        print(f"{'='*60}")
        print(f"Directory: {directory}")
        print(f"Depth: {depth_str}")
        print(f"\nDISCOVERY")
        print(f"  Files scanned:  {total_files}")
        print(f"  Parseable:      {len(parseable)}")
        print(f"  Skipped:        {total_skipped}")

        for reason, files in sorted(skipped.items()):
            if files:
                print(f"    - {reason}: {len(files)}")

        if parseable:
            print(f"\nPARSEABLE FILES")
            by_parser = defaultdict(list)
            for filepath, parser in parseable:
                by_parser[parser.name].append(filepath)

            for parser_name, files in sorted(by_parser.items()):
                print(f"  {parser_name}: {len(files)} files")


def aggregate_crawl_results(
    results: List[Tuple[str, str, any]],
    console: Optional['Console'] = None
) -> Dict:
    """Aggregate parsed results across all files

    Args:
        results: List of (filepath, parser_name, summary) tuples
        console: Rich console for output

    Returns:
        Aggregated statistics dict
    """
    from .models import LdapSummary, NmapScanSummary, SmbmapSummary

    stats = {
        'files_parsed': len(results),
        'files_with_findings': 0,
        'total_credentials': 0,
        'cleartext': 0,
        'ntlm_hashes': 0,
        'kerberos_tickets': 0,
        'high_value': 0,
        'unique_accounts': set(),
        'domains': set(),
        'hosts': 0,
        'ports': 0,
        'shares': 0,
    }

    for filepath, parser_name, summary in results:
        has_findings = False

        if isinstance(summary, LdapSummary):
            if summary.users:
                has_findings = True
                stats['unique_accounts'].update(u.sam_account_name for u in summary.users if u.sam_account_name)
            if summary.domain_info and summary.domain_info.domain_name:
                stats['domains'].add(summary.domain_info.domain_name)

        elif isinstance(summary, NmapScanSummary):
            if summary.hosts:
                has_findings = True
                stats['hosts'] += len(summary.hosts)
                for host in summary.hosts:
                    stats['ports'] += len(host.ports)

        elif isinstance(summary, SmbmapSummary):
            if summary.shares:
                has_findings = True
                stats['shares'] += len(summary.shares)

        else:
            # Credential-based summaries (mimikatz, secretsdump, kerberoast, gpp)
            if hasattr(summary, 'credentials') and summary.credentials:
                has_findings = True
                for cred in summary.credentials:
                    stats['total_credentials'] += 1
                    stats['unique_accounts'].add(cred.username)

                    if cred.domain:
                        stats['domains'].add(cred.domain)

                    cred_type_raw = getattr(cred, 'cred_type', '')
                    # Handle CredentialType enum or string
                    cred_type = cred_type_raw.value if hasattr(cred_type_raw, 'value') else str(cred_type_raw)
                    if cred_type == 'cleartext':
                        stats['cleartext'] += 1
                    elif cred_type == 'ntlm':
                        stats['ntlm_hashes'] += 1

                    if getattr(cred, 'high_value', False):
                        stats['high_value'] += 1

            if hasattr(summary, 'tickets') and summary.tickets:
                has_findings = True
                stats['kerberos_tickets'] += len(summary.tickets)

        if has_findings:
            stats['files_with_findings'] += 1

    # Convert sets to counts for JSON serialization
    stats['unique_accounts'] = len(stats['unique_accounts'])
    stats['domains'] = len(stats['domains'])

    return stats


def display_crawl_results(
    results: List[Tuple[str, str, any]],
    directory: str,
    output_format: str,
    verbose: bool,
    console: Optional['Console'] = None
) -> None:
    """Display parsed results from crawl

    Args:
        results: List of (filepath, parser_name, summary) tuples
        directory: Root directory for relative paths
        output_format: 'table', 'json', or 'markdown'
        verbose: Show detailed output
        console: Rich console
    """
    if output_format == 'json':
        import json
        from .models import LdapSummary, NmapScanSummary, SmbmapSummary

        output = {
            'directory': directory,
            'files': [],
            'aggregate': aggregate_crawl_results(results, console)
        }

        for filepath, parser_name, summary in results:
            file_data = {
                'path': os.path.relpath(filepath, directory),
                'parser': parser_name,
            }

            # Add summary data based on type
            if hasattr(summary, 'to_dict'):
                file_data['data'] = summary.to_dict()
            elif hasattr(summary, 'stats'):
                file_data['stats'] = summary.stats

            output['files'].append(file_data)

        print(json.dumps(output, indent=2, default=str))
        return

    if not console or not RICH_AVAILABLE:
        # Plain text fallback
        print(f"\n{'='*60}")
        print("CRAWL RESULTS")
        print(f"{'='*60}")
        for filepath, parser_name, summary in results:
            rel_path = os.path.relpath(filepath, directory)
            print(f"\n[{parser_name}] {rel_path}")
            if hasattr(summary, 'stats'):
                for k, v in summary.stats.items():
                    print(f"  {k}: {v}")
        return

    # Rich table output
    from rich.panel import Panel
    from rich.table import Table

    console.print("\n")
    console.print(Panel("[bold]PARSING RESULTS[/]", border_style="green"))

    for i, (filepath, parser_name, summary) in enumerate(results, 1):
        rel_path = os.path.relpath(filepath, directory)
        console.print(f"\n[cyan][{i}/{len(results)}][/] [bold]{parser_name}[/]: {rel_path}")

        # Display based on summary type
        if hasattr(summary, 'credentials') and summary.credentials:
            table = Table(show_header=True, box=None)
            table.add_column("Username", style="yellow")
            table.add_column("Type", style="cyan")
            table.add_column("Value", style="dim", max_width=40)

            for cred in summary.credentials[:10]:  # Limit display
                cred_type_raw = getattr(cred, 'cred_type', 'unknown')
                # Handle CredentialType enum or string
                cred_type = cred_type_raw.value if hasattr(cred_type_raw, 'value') else str(cred_type_raw)

                # Get the credential value (stored in cred.value)
                value = cred.value or ''
                if value and len(value) > 40:
                    value = value[:37] + '...'
                value = value or '[dim]-[/]'

                # Highlight cleartext
                if cred_type == 'cleartext':
                    table.add_row(
                        f"[bold green]{cred.username}[/]",
                        f"[bold green]{cred_type}[/]",
                        f"[bold green]{value}[/]"
                    )
                else:
                    table.add_row(str(cred.username), str(cred_type), str(value))

            console.print(table)

            if len(summary.credentials) > 10:
                console.print(f"  [dim]... and {len(summary.credentials) - 10} more[/]")

        elif hasattr(summary, 'tickets') and summary.tickets:
            console.print(f"  [yellow]Kerberos Tickets:[/] {len(summary.tickets)}")

        elif hasattr(summary, 'stats'):
            for k, v in list(summary.stats.items())[:5]:
                console.print(f"  {k}: {v}")

    # Aggregate summary
    stats = aggregate_crawl_results(results, console)

    console.print("\n")
    console.print(Panel("[bold]AGGREGATE SUMMARY[/]", border_style="yellow"))

    summary_table = Table(show_header=False, box=None)
    summary_table.add_column("Metric", style="bold")
    summary_table.add_column("Value", justify="right")

    summary_table.add_row("Files with Findings", f"{stats['files_with_findings']}/{stats['files_parsed']}")

    if stats['total_credentials']:
        summary_table.add_row("Total Credentials", str(stats['total_credentials']))
        if stats['cleartext']:
            summary_table.add_row("  Cleartext", f"[bold green]{stats['cleartext']}[/] (HIGH VALUE)")
        if stats['ntlm_hashes']:
            summary_table.add_row("  NTLM Hashes", str(stats['ntlm_hashes']))
        if stats['high_value']:
            summary_table.add_row("  High Value Accounts", f"[bold yellow]{stats['high_value']}[/]")

    if stats['kerberos_tickets']:
        summary_table.add_row("Kerberos Tickets", str(stats['kerberos_tickets']))

    if stats['unique_accounts']:
        summary_table.add_row("Unique Accounts", str(stats['unique_accounts']))

    if stats['domains']:
        summary_table.add_row("Domains", str(stats['domains']))

    if stats['hosts']:
        summary_table.add_row("Hosts Discovered", str(stats['hosts']))

    if stats['ports']:
        summary_table.add_row("Open Ports", str(stats['ports']))

    if stats['shares']:
        summary_table.add_row("SMB Shares", str(stats['shares']))

    console.print(summary_table)


def handle_crawl_command(args: list, console: Optional['Console'] = None) -> int:
    """Handle the 'crawl' subcommand

    Usage:
        crack prism crawl <directory>
        crack prism crawl <directory> --depth 3
        crack prism crawl <directory> --dry-run
        crack prism crawl <directory> -v
    """
    crawl_parser = argparse.ArgumentParser(
        prog="crack prism crawl",
        description="Recursively parse all recognized files in a directory"
    )
    crawl_parser.add_argument(
        "directory",
        type=Path,
        help="Directory to crawl"
    )
    crawl_parser.add_argument(
        "--depth", "-d",
        type=int,
        default=-1,
        help="Max recursion depth (-1 = unlimited, default)"
    )
    crawl_parser.add_argument(
        "--dry-run", "-n",
        action="store_true",
        help="Preview what would be parsed without parsing"
    )
    crawl_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show skipped files and detailed progress"
    )
    crawl_parser.add_argument(
        "-f", "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)"
    )
    crawl_parser.add_argument(
        "--no-neo4j",
        action="store_true",
        help="Skip Neo4j import"
    )
    crawl_parser.add_argument(
        "--host", "--hostname",
        type=str,
        dest="hostname",
        help="Source hostname to associate with all parsed data"
    )

    parsed = crawl_parser.parse_args(args)

    # Validate directory
    directory = parsed.directory
    if not directory.exists():
        print_error(f"Directory not found: {directory}", console)
        return 1
    if not directory.is_dir():
        print_error(f"Not a directory: {directory}", console)
        return 1

    directory_str = str(directory.resolve())

    # Phase 1: Discovery
    if console and RICH_AVAILABLE:
        console.print("[cyan]Scanning directory...[/]")

    parseable, skipped = discover_parseable_files(
        directory_str,
        max_depth=parsed.depth,
        verbose=parsed.verbose
    )

    # Show discovery summary
    print_crawl_discovery(
        directory_str,
        parseable,
        skipped,
        parsed.depth,
        parsed.verbose,
        console
    )

    # Dry run stops here
    if parsed.dry_run:
        if console and RICH_AVAILABLE:
            console.print("\n[yellow]Dry run - no files parsed[/]")
        else:
            print("\nDry run - no files parsed")
        return 0

    # No parseable files
    if not parseable:
        if console and RICH_AVAILABLE:
            console.print("\n[yellow]No parseable files found[/]")
        else:
            print("\nNo parseable files found")
        return 0

    # Phase 2: Parse each file
    results = []
    errors = []

    if console and RICH_AVAILABLE:
        from rich.progress import Progress, SpinnerColumn, TextColumn

        console.print("\n")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Parsing files...", total=len(parseable))

            for filepath, parser in parseable:
                rel_path = os.path.relpath(filepath, directory_str)
                progress.update(task, description=f"Parsing: {rel_path[:50]}")

                try:
                    summary = parser.parse(filepath, hostname=parsed.hostname)
                    results.append((filepath, parser.name, summary))
                except Exception as e:
                    errors.append((filepath, str(e)))
                    if parsed.verbose:
                        console.print(f"[red]Error:[/] {rel_path}: {e}")

                progress.advance(task)
    else:
        for i, (filepath, parser) in enumerate(parseable, 1):
            rel_path = os.path.relpath(filepath, directory_str)
            print(f"[{i}/{len(parseable)}] Parsing: {rel_path}")

            try:
                summary = parser.parse(filepath, hostname=parsed.hostname)
                results.append((filepath, parser.name, summary))
            except Exception as e:
                errors.append((filepath, str(e)))
                if parsed.verbose:
                    print(f"  Error: {e}")

    # Phase 3: Display results
    if results:
        display_crawl_results(
            results,
            directory_str,
            parsed.format,
            parsed.verbose,
            console
        )

    # Show errors summary
    if errors and parsed.verbose:
        if console and RICH_AVAILABLE:
            console.print(f"\n[red]Parse errors: {len(errors)}[/]")
        else:
            print(f"\nParse errors: {len(errors)}")

    # Phase 4: Neo4j import
    if not parsed.no_neo4j and results:
        try:
            from .neo4j.adapter import PrismNeo4jAdapter
            adapter = PrismNeo4jAdapter()

            if adapter.connect():
                total_imported = {'credentials': 0, 'tickets': 0, 'users': 0, 'hosts': 0}

                for filepath, parser_name, summary in results:
                    try:
                        result = adapter.import_summary(summary)
                        for key in total_imported:
                            total_imported[key] += result.get(key, 0)
                    except Exception:
                        pass  # Silently skip import errors

                # Report totals
                parts = []
                if total_imported['credentials']:
                    parts.append(f"{total_imported['credentials']} credentials")
                if total_imported['tickets']:
                    parts.append(f"{total_imported['tickets']} tickets")
                if total_imported['users']:
                    parts.append(f"{total_imported['users']} users")
                if total_imported['hosts']:
                    parts.append(f"{total_imported['hosts']} hosts")

                if parts:
                    print_info(f"Neo4j: Imported {', '.join(parts)}", console)

        except ImportError:
            pass  # neo4j not installed
        except Exception as e:
            if parsed.verbose:
                print_info(f"Neo4j: {e}", console)

    return 0


def handle_report_command(args: list, console: Optional['Console'] = None) -> int:
    """Handle the 'report' subcommand

    Usage:
        crack prism report --domain DOMAIN
        crack prism report --list-domains
        crack prism report --domain DOMAIN --section users
        crack prism report --domain DOMAIN -f json
    """
    # Parse report-specific arguments
    report_parser = argparse.ArgumentParser(
        prog="crack prism report",
        description="Generate domain report from Neo4j"
    )
    report_parser.add_argument(
        "--domain", "-d",
        help="Domain name to report on"
    )
    report_parser.add_argument(
        "--list-domains", "-l",
        action="store_true",
        help="List available domains in Neo4j"
    )
    report_parser.add_argument(
        "--section", "-s",
        choices=["all", "policy", "users", "computers", "credentials", "groups", "tickets"],
        default="all",
        help="Report section to display (default: all)"
    )
    report_parser.add_argument(
        "-f", "--format",
        choices=["table", "json", "markdown"],
        default="table",
        help="Output format (default: table)"
    )
    report_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show additional details"
    )
    report_parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Save output to file"
    )

    parsed = report_parser.parse_args(args)

    # Require either --domain or --list-domains
    if not parsed.domain and not parsed.list_domains:
        report_parser.print_help()
        print_error("\nMust specify --domain or --list-domains", console)
        return 1

    # Connect to Neo4j
    try:
        from .neo4j.adapter import PrismNeo4jAdapter
        adapter = PrismNeo4jAdapter()

        if not adapter.connect():
            print_error("Failed to connect to Neo4j", console)
            print_info("Ensure Neo4j is running and NEO4J_URI/NEO4J_PASSWORD are set", console)
            return 1

    except ImportError:
        print_error("neo4j package not installed", console)
        print_info("Install with: pip install neo4j", console)
        return 1
    except Exception as e:
        print_error(f"Neo4j connection failed: {e}", console)
        return 1

    # Handle --list-domains
    if parsed.list_domains:
        domains = adapter.list_domains()
        if parsed.format == "json":
            import json
            print(json.dumps(domains, indent=2, default=str))
        else:
            formatter = DomainListFormatter(console)
            formatter.render_domains(domains)
        return 0

    # Handle --domain
    domain = parsed.domain

    # Query domain report
    try:
        report = adapter.query_domain_report(domain)
    except Exception as e:
        print_error(f"Query failed: {e}", console)
        return 1

    if not report or not report.get('domain'):
        print_error(f"No data found for domain: {domain}", console)
        print_info("Use --list-domains to see available domains", console)
        return 1

    # Format and output
    formatter = DomainReportFormatter(console)

    if parsed.format == "table":
        if not RICH_AVAILABLE:
            print_error("Rich library required for table output. Use -f json instead.", console)
            return 1
        formatter.render_report(report, section=parsed.section, verbose=parsed.verbose)

    elif parsed.format == "json":
        print(formatter.format_json(report))

    elif parsed.format == "markdown":
        print(formatter.format_markdown(report))

    # File output
    if parsed.output:
        # Single file output (backward compatible)
        output_path = parsed.output
        ext = output_path.suffix.lower()

        if ext == '.json':
            content = formatter.format_json_full(report)
        elif ext in ('.md', '.markdown'):
            content = formatter.format_markdown_full(report)
        else:
            content = formatter.format_json_full(report)

        try:
            output_path.write_text(content)
            print_info(f"Saved to: {output_path}", console)
        except Exception as e:
            print_error(f"Failed to write file: {e}", console)
    else:
        # Default: Create directory with both formats
        from datetime import datetime

        # Sanitize domain name for directory/file names
        safe_domain = domain.replace('.', '_').replace(' ', '_').replace('/', '_')
        output_dir = Path(f"prism-{safe_domain}")

        try:
            output_dir.mkdir(exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            json_path = output_dir / f"{safe_domain}_report_{timestamp}.json"
            md_path = output_dir / f"{safe_domain}_report_{timestamp}.md"

            # Generate full untruncated reports
            json_content = formatter.format_json_full(report)
            md_content = formatter.format_markdown_full(report)

            json_path.write_text(json_content)
            md_path.write_text(md_content)

            print_info(f"Report saved to: {output_dir}/", console)
            print_info(f"  - {json_path.name}", console)
            print_info(f"  - {md_path.name}", console)

        except Exception as e:
            print_error(f"Failed to create report directory: {e}", console)

    return 0


def handle_purge_command(args: list, console: Optional['Console'] = None) -> int:
    """Handle the 'purge' subcommand

    Usage:
        crack prism purge --domain CORP.LOCAL
        crack prism purge --all
        crack prism purge --domain CORP.LOCAL --dry-run
    """
    import argparse

    purge_parser = argparse.ArgumentParser(
        prog="crack prism purge",
        description="Remove PRISM data from Neo4j"
    )
    purge_parser.add_argument(
        "--domain", "-d",
        help="Domain to purge (e.g., CORP.LOCAL)"
    )
    purge_parser.add_argument(
        "--all", "-a",
        action="store_true",
        dest="purge_all",
        help="Purge ALL PRISM data from Neo4j"
    )
    purge_parser.add_argument(
        "--dry-run", "-n",
        action="store_true",
        help="Preview what would be deleted without deleting"
    )
    purge_parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Skip confirmation prompt"
    )

    parsed = purge_parser.parse_args(args)

    # Require either --domain or --all
    if not parsed.domain and not parsed.purge_all:
        purge_parser.print_help()
        print_error("\nMust specify --domain or --all", console)
        return 1

    # Can't use both
    if parsed.domain and parsed.purge_all:
        print_error("Cannot use both --domain and --all", console)
        return 1

    # Connect to Neo4j
    try:
        from .neo4j.adapter import PrismNeo4jAdapter
        adapter = PrismNeo4jAdapter()

        if not adapter.connect():
            print_error("Failed to connect to Neo4j", console)
            print_info("Ensure Neo4j is running and NEO4J_PASSWORD is set", console)
            return 1

    except ImportError:
        print_error("neo4j package not installed", console)
        return 1
    except Exception as e:
        print_error(f"Neo4j connection failed: {e}", console)
        return 1

    # Get preview counts
    if parsed.domain:
        preview = adapter.get_purge_preview(parsed.domain)
        target_desc = f"domain '{parsed.domain}'"
    else:
        preview = adapter.get_purge_preview()
        target_desc = "ALL PRISM data"

    # Show preview
    if console and RICH_AVAILABLE:
        from rich.table import Table
        table = Table(title=f"Purge Preview: {target_desc}")
        table.add_column("Type", style="cyan")
        table.add_column("Count", justify="right", style="yellow")

        total = 0
        for key, count in preview.items():
            if count > 0:
                table.add_row(key.replace('_', ' ').title(), str(count))
                total += count

        if total == 0:
            print_info(f"No data found for {target_desc}", console)
            return 0

        console.print(table)
        console.print(f"\n[bold]Total nodes to delete:[/] {total}")
    else:
        print(f"\nPurge Preview: {target_desc}")
        print("-" * 30)
        total = 0
        for key, count in preview.items():
            if count > 0:
                print(f"  {key}: {count}")
                total += count

        if total == 0:
            print(f"No data found for {target_desc}")
            return 0

        print(f"\nTotal nodes to delete: {total}")

    # Dry run stops here
    if parsed.dry_run:
        print_info("Dry run - no changes made", console)
        return 0

    # Confirmation
    if not parsed.force:
        if console and RICH_AVAILABLE:
            console.print(f"\n[bold red]WARNING:[/] This will permanently delete {target_desc}!")
            response = input("Type 'yes' to confirm: ")
        else:
            print(f"\nWARNING: This will permanently delete {target_desc}!")
            response = input("Type 'yes' to confirm: ")

        if response.lower() != 'yes':
            print_info("Purge cancelled", console)
            return 0

    # Execute purge
    try:
        if parsed.domain:
            result = adapter.purge_domain(parsed.domain)
        else:
            result = adapter.purge_all()

        # Show results
        deleted = sum(result.values())
        if console and RICH_AVAILABLE:
            console.print(f"\n[bold green]Purge complete![/] Deleted {deleted} nodes")
            for key, count in result.items():
                if count > 0:
                    console.print(f"  - {key}: {count}")
        else:
            print(f"\nPurge complete! Deleted {deleted} nodes")
            for key, count in result.items():
                if count > 0:
                    print(f"  - {key}: {count}")

        return 0

    except Exception as e:
        print_error(f"Purge failed: {e}", console)
        return 1


def main(args: Optional[list] = None) -> int:
    """Main CLI entry point"""
    # Initialize console early for error handling
    console = Console() if RICH_AVAILABLE else None

    # Get args list for subcommand detection
    if args is None:
        args = sys.argv[1:]

    # Check for subcommands
    if args and args[0] == 'report':
        return handle_report_command(args[1:], console)

    if args and args[0] == 'purge':
        return handle_purge_command(args[1:], console)

    if args and args[0] == 'crawl':
        return handle_crawl_command(args[1:], console)

    # Standard parsing for file-based operations
    parser = create_parser()
    parsed_args = parser.parse_args(args)

    # List parsers
    if parsed_args.list_parsers:
        return list_parsers(console)

    # Handle stdin pipe or require file argument
    stdin_temp_file = None
    if not parsed_args.file:
        if not sys.stdin.isatty():
            # Read from pipe, save to temp file for parser compatibility
            content = sys.stdin.read()
            if not content.strip():
                print_error("No input received from pipe", console)
                return 1

            # Create temp file
            fd, temp_path = tempfile.mkstemp(suffix='.txt', prefix='prism_')
            with os.fdopen(fd, 'w') as f:
                f.write(content)

            parsed_args.file = Path(temp_path)
            stdin_temp_file = temp_path
        else:
            # No file and no pipe - show help
            parser.print_help()
            return 1

    # Validate input file
    if not parsed_args.file.exists():
        print_error(f"File not found: {parsed_args.file}", console)
        return 1

    if not parsed_args.file.is_file():
        print_error(f"Not a file: {parsed_args.file}", console)
        return 1

    # Get parser (auto-detect or forced)
    filepath = str(parsed_args.file)

    if parsed_args.parser:
        selected_parser = PrismParserRegistry.get_parser_by_name(parsed_args.parser)
        if not selected_parser:
            print_error(f"Unknown parser: {parsed_args.parser}", console)
            print_info("Use --list-parsers to see available parsers", console)
            cleanup_temp_file(stdin_temp_file)
            return 1
    else:
        selected_parser = PrismParserRegistry.get_parser(filepath)
        if not selected_parser:
            print_error(f"No parser found for file: {parsed_args.file}", console)
            print_info("Use --list-parsers to see supported formats", console)
            cleanup_temp_file(stdin_temp_file)
            return 1

    # Only show parser info for table/verbose output (not for JSON/markdown piping)
    if parsed_args.format == "table":
        print_info(f"Using parser: {selected_parser.name}", console)

    # Parse file
    try:
        summary = selected_parser.parse(filepath, hostname=parsed_args.hostname)
    except Exception as e:
        print_error(f"Parse failed: {e}", console)
        cleanup_temp_file(stdin_temp_file)
        return 1

    # Determine formatter type based on summary
    is_ldap = isinstance(summary, LdapSummary)
    is_nmap = isinstance(summary, NmapScanSummary)
    is_smbmap = isinstance(summary, SmbmapSummary)

    # Stats only mode
    if parsed_args.stats_only:
        stats = summary.stats
        if is_ldap:
            if console and RICH_AVAILABLE:
                console.print(f"Users: {stats['users']} ({stats['enabled_users']} enabled)")
                console.print(f"Computers: {stats['computers']}")
                console.print(f"Groups: {stats['groups']}")
                console.print(f"Kerberoastable: {stats['kerberoastable']}")
                console.print(f"AS-REP Roastable: {stats['asrep_roastable']}")
                console.print(f"With Descriptions: {stats['with_descriptions']}")
            else:
                print(f"Users: {stats['users']} ({stats['enabled_users']} enabled)")
                print(f"Computers: {stats['computers']}")
                print(f"Groups: {stats['groups']}")
                print(f"Kerberoastable: {stats['kerberoastable']}")
                print(f"AS-REP Roastable: {stats['asrep_roastable']}")
        elif is_nmap:
            if console and RICH_AVAILABLE:
                console.print(f"Hosts Up: {stats['hosts_up']}")
                console.print(f"Hosts Down: {stats['hosts_down']}")
                console.print(f"Domain Controllers: {stats['domain_controllers']}")
                console.print(f"Unique Open Ports: {stats['unique_open_ports']}")
            else:
                print(f"Hosts Up: {stats['hosts_up']}")
                print(f"Hosts Down: {stats['hosts_down']}")
                print(f"Domain Controllers: {stats['domain_controllers']}")
                print(f"Unique Open Ports: {stats['unique_open_ports']}")
        elif is_smbmap:
            if console and RICH_AVAILABLE:
                console.print(f"Total Shares: {stats['total_shares']}")
                console.print(f"Readable Shares: {stats['readable_shares']}")
                console.print(f"Writable Shares: {stats['writable_shares']}")
                console.print(f"Total Files: {stats['total_files']}")
                console.print(f"High-Value Files: {stats['high_value_files']}")
            else:
                print(f"Total Shares: {stats['total_shares']}")
                print(f"Readable Shares: {stats['readable_shares']}")
                print(f"Writable Shares: {stats['writable_shares']}")
                print(f"Total Files: {stats['total_files']}")
                print(f"High-Value Files: {stats['high_value_files']}")
        else:
            if console and RICH_AVAILABLE:
                console.print(f"Sessions: {stats.get('sessions', 0)}")
                console.print(f"Credentials: {stats.get('total_creds', 0)}")
                console.print(f"  Cleartext: {stats.get('cleartext', 0)}")
                console.print(f"  NTLM: {stats.get('ntlm', 0)}")
                console.print(f"  High Value: {stats.get('high_value', 0)}")
                console.print(f"TGT Tickets: {stats.get('tgt_tickets', 0)}")
                console.print(f"TGS Tickets: {stats.get('tgs_tickets', 0)}")
            else:
                print(f"Sessions: {stats.get('sessions', 0)}")
                print(f"Credentials: {stats.get('total_creds', 0)}")
                print(f"  Cleartext: {stats.get('cleartext', 0)}")
                print(f"  NTLM: {stats.get('ntlm', 0)}")
                print(f"TGT Tickets: {stats.get('tgt_tickets', 0)}")
                print(f"TGS Tickets: {stats.get('tgs_tickets', 0)}")
        return 0

    # Console output based on format
    if parsed_args.format == "table":
        if not RICH_AVAILABLE:
            print_error("Rich library required for table output. Use -f json instead.", console)
            return 1
        if is_ldap:
            formatter = LdapFormatter(console)
        elif is_nmap:
            formatter = NmapFormatter(console)
        elif is_smbmap:
            formatter = SmbmapFormatter(console)
        else:
            formatter = PrismFormatter(console)
        formatter.render_summary(summary, verbose=parsed_args.verbose)

    elif parsed_args.format == "json":
        if is_ldap:
            formatter = LdapJSONFormatter()
        elif is_nmap:
            formatter = NmapJSONFormatter()
        elif is_smbmap:
            formatter = SmbmapJSONFormatter()
        else:
            formatter = JSONFormatter()
        print(formatter.format(summary))

    elif parsed_args.format == "markdown":
        if is_ldap:
            formatter = LdapMarkdownFormatter()
        elif is_nmap:
            formatter = NmapMarkdownFormatter()
        elif is_smbmap:
            formatter = SmbmapMarkdownFormatter()
        else:
            formatter = MarkdownFormatter()
        print(formatter.format(summary))

    # File output (optional)
    if parsed_args.output:
        output_path = parsed_args.output
        ext = output_path.suffix.lower()

        # Select appropriate formatter based on summary type
        def get_json_formatter():
            if is_ldap:
                return LdapJSONFormatter()
            elif is_nmap:
                return NmapJSONFormatter()
            elif is_smbmap:
                return SmbmapJSONFormatter()
            return JSONFormatter()

        def get_markdown_formatter():
            if is_ldap:
                return LdapMarkdownFormatter()
            elif is_nmap:
                return NmapMarkdownFormatter()
            elif is_smbmap:
                return SmbmapMarkdownFormatter()
            return MarkdownFormatter()

        # Auto-detect format from extension
        if ext == '.json':
            content = get_json_formatter().format(summary)
        elif ext in ('.md', '.markdown'):
            content = get_markdown_formatter().format(summary)
        else:
            # Default to JSON for unknown extensions
            content = get_json_formatter().format(summary)

        try:
            output_path.write_text(content)
            print_info(f"Saved to: {output_path}", console)
        except Exception as e:
            print_error(f"Failed to write file: {e}", console)

    # Neo4j import (default behavior - unless --no-neo4j)
    if not parsed_args.no_neo4j:
        try:
            from .neo4j.adapter import PrismNeo4jAdapter
            adapter = PrismNeo4jAdapter()

            if adapter.connect():
                result = adapter.import_summary(summary)
                # Format output based on what was imported
                parts = []
                if result.get('credentials'):
                    parts.append(f"{result['credentials']} credentials")
                if result.get('tickets'):
                    parts.append(f"{result['tickets']} tickets")
                if result.get('users'):
                    parts.append(f"{result['users']} users")
                if result.get('computers'):
                    parts.append(f"{result['computers']} computers")
                if result.get('groups'):
                    parts.append(f"{result['groups']} groups")
                if result.get('hosts'):
                    parts.append(f"{result['hosts']} hosts")
                if result.get('ports'):
                    parts.append(f"{result['ports']} ports")
                if result.get('domains'):
                    parts.append(f"{result['domains']} domain(s)")

                if parts:
                    print_info(f"Neo4j: Imported {', '.join(parts)}", console)
            else:
                # Silently skip if neo4j not available (not an error)
                print_info("Neo4j: Not connected (use --no-neo4j to suppress)", console)

        except ImportError:
            # neo4j package not installed - silently skip
            pass
        except Exception as e:
            # Log but don't fail - neo4j is optional
            print_info(f"Neo4j: {e}", console)

    # Cleanup temp file if created from stdin
    cleanup_temp_file(stdin_temp_file)

    return 0


if __name__ == "__main__":
    sys.exit(main())
