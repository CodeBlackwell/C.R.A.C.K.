"""
PRISM CLI - Command-line interface for parsing security tool output

Usage:
    crack prism <file>                          # Auto-detect and parse
    crack prism <file> -f json                  # JSON output
    crack prism <file> --neo4j                  # Import to neo4j
    crack prism --list-parsers                  # Show available parsers
    crack prism report --domain DOMAIN          # Generate domain report from Neo4j
    crack prism report --list-domains           # List available domains
"""

import argparse
import os
import sys
import tempfile
from pathlib import Path
from typing import Optional

try:
    from rich.console import Console
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = None

from .parsers.registry import PrismParserRegistry
from .display.formatter import (
    PrismFormatter, JSONFormatter, MarkdownFormatter,
    LdapFormatter, LdapJSONFormatter, LdapMarkdownFormatter,
    DomainReportFormatter, DomainListFormatter
)
from .models import LdapSummary


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

    # File output (optional)
    if parsed.output:
        output_path = parsed.output
        ext = output_path.suffix.lower()

        if ext == '.json':
            content = formatter.format_json(report)
        elif ext in ('.md', '.markdown'):
            content = formatter.format_markdown(report)
        else:
            content = formatter.format_json(report)

        try:
            output_path.write_text(content)
            print_info(f"Saved to: {output_path}", console)
        except Exception as e:
            print_error(f"Failed to write file: {e}", console)

    return 0


def main(args: Optional[list] = None) -> int:
    """Main CLI entry point"""
    # Initialize console early for error handling
    console = Console() if RICH_AVAILABLE else None

    # Get args list for subcommand detection
    if args is None:
        args = sys.argv[1:]

    # Check for 'report' subcommand
    if args and args[0] == 'report':
        return handle_report_command(args[1:], console)

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
        else:
            formatter = PrismFormatter(console)
        formatter.render_summary(summary, verbose=parsed_args.verbose)

    elif parsed_args.format == "json":
        if is_ldap:
            formatter = LdapJSONFormatter()
        else:
            formatter = JSONFormatter()
        print(formatter.format(summary))

    elif parsed_args.format == "markdown":
        if is_ldap:
            formatter = LdapMarkdownFormatter()
        else:
            formatter = MarkdownFormatter()
        print(formatter.format(summary))

    # File output (optional)
    if parsed_args.output:
        output_path = parsed_args.output
        ext = output_path.suffix.lower()

        # Auto-detect format from extension
        if ext == '.json':
            content = (LdapJSONFormatter() if is_ldap else JSONFormatter()).format(summary)
        elif ext in ('.md', '.markdown'):
            content = (LdapMarkdownFormatter() if is_ldap else MarkdownFormatter()).format(summary)
        else:
            # Default to JSON for unknown extensions
            content = (LdapJSONFormatter() if is_ldap else JSONFormatter()).format(summary)

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
