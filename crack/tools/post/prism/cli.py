"""
PRISM CLI - Command-line interface for parsing security tool output

Usage:
    crack prism <file>              # Auto-detect and parse
    crack prism <file> -f json      # JSON output
    crack prism <file> --neo4j      # Import to neo4j
    crack prism --list-parsers      # Show available parsers
"""

import argparse
import sys
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
    LdapFormatter, LdapJSONFormatter, LdapMarkdownFormatter
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


def main(args: Optional[list] = None) -> int:
    """Main CLI entry point"""
    parser = create_parser()
    parsed_args = parser.parse_args(args)

    # Initialize console
    console = Console() if RICH_AVAILABLE else None

    # List parsers
    if parsed_args.list_parsers:
        return list_parsers(console)

    # Require file argument for other operations
    if not parsed_args.file:
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
            return 1
    else:
        selected_parser = PrismParserRegistry.get_parser(filepath)
        if not selected_parser:
            print_error(f"No parser found for file: {parsed_args.file}", console)
            print_info("Use --list-parsers to see supported formats", console)
            return 1

    # Only show parser info for table/verbose output (not for JSON/markdown piping)
    if parsed_args.format == "table":
        print_info(f"Using parser: {selected_parser.name}", console)

    # Parse file
    try:
        summary = selected_parser.parse(filepath, hostname=parsed_args.hostname)
    except Exception as e:
        print_error(f"Parse failed: {e}", console)
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
                print_info(
                    f"Neo4j: Imported {result.get('credentials', 0)} credentials, "
                    f"{result.get('tickets', 0)} tickets",
                    console
                )
            else:
                # Silently skip if neo4j not available (not an error)
                print_info("Neo4j: Not connected (use --no-neo4j to suppress)", console)

        except ImportError:
            # neo4j package not installed - silently skip
            pass
        except Exception as e:
            # Log but don't fail - neo4j is optional
            print_info(f"Neo4j: {e}", console)

    return 0


if __name__ == "__main__":
    sys.exit(main())
