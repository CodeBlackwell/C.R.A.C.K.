#!/usr/bin/env python3
"""
BloodHound Trail - Command Line Interface

Usage:
    # Edge enhancement (directory or ZIP file)
    crack bloodtrail /path/to/bh/json/
    crack bloodtrail /path/to/sharphound_output.zip
    crack bloodtrail /path/to/bh/json/ --preset attack-paths
    crack bloodtrail /path/to/bh/json/ --dry-run --verbose

    # Query library
    crack bloodtrail --list-queries
    crack bloodtrail --list-queries --category lateral_movement
    crack bloodtrail --run-query lateral-adminto-nonpriv
    crack bloodtrail --run-query owned-what-can-access --var USER=PETE@CORP.COM
    crack bloodtrail --search-query DCSync
    crack bloodtrail --export-query lateral-adminto-nonpriv

Credentials (defaults):
    - Neo4j: neo4j / Neo4j123
    - BloodHound: admin / 1PlaySmarter*
"""

import argparse
import getpass
import json
import sys
from pathlib import Path

from neo4j import GraphDatabase

from .config import Neo4jConfig, ATTACK_PATH_EDGES, LHOST as CONFIG_LHOST, LPORT as CONFIG_LPORT
from .main import BHEnhancer
from .query_runner import (
    QueryRunner,
    print_query_info,
    export_to_bloodhound_customqueries,
    export_to_bloodhound_ce,
    run_all_queries,
)
from .data_source import is_valid_bloodhound_source, create_data_source
from .ip_resolver import IPResolver
from .pwned_tracker import (
    PwnedTracker,
    DiscoveryError,
    discover_dc_ip,
    discover_dc_hostname,
    update_etc_hosts,
)
from .display_commands import (
    print_pwned_followup_commands,
    print_pwned_users_table,
    print_cred_harvest_targets,
    print_post_exploit_commands,
    print_machines_ip_table,
)


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bloodtrail",
        description="BloodHound Trail - Edge enhancement and Neo4j query analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Import edges + auto-generate report with all queries (default)
  crack bloodtrail /path/to/bh/json/

  # Show commands in console (report still saved to file)
  crack bloodtrail /path/to/bh/json/ -c

  # Attack-path focused edges only (recommended)
  crack bloodtrail /path/to/bh/json/ --preset attack-paths

  # Dry run (validate without importing)
  crack bloodtrail /path/to/bh/json/ --dry-run --verbose

  # Skip report generation (edges only)
  crack bloodtrail /path/to/bh/json/ --no-report

  # Run queries against existing Neo4j data (no import)
  crack bloodtrail --run-all

  # Resume with existing Neo4j data (quick shortcut)
  crack bloodtrail -r
  crack bloodtrail --resume

Supported Edge Types:
  Computer Access: AdminTo, CanPSRemote, CanRDP, ExecuteDCOM, HasSession
  ACL Abuse:       GenericAll, GenericWrite, WriteDacl, WriteOwner, Owns
  DCSync:          GetChanges, GetChangesAll
  Membership:      MemberOf
  Delegation:      AllowedToDelegate, AllowedToAct
        """,
    )

    # Positional (optional for query commands)
    parser.add_argument(
        "bh_data_dir",
        type=Path,
        nargs="?",
        default=None,
        help="Directory or ZIP file containing BloodHound JSON exports. Auto-generates report with all queries.",
    )

    # Preset/Filter options
    filter_group = parser.add_mutually_exclusive_group()
    filter_group.add_argument(
        "--preset",
        choices=["attack-paths", "all"],
        default="attack-paths",
        help="Edge preset: 'attack-paths' (default) or 'all'",
    )
    filter_group.add_argument(
        "--edges",
        type=str,
        help="Comma-separated list of specific edge types to import",
    )

    # Resume mode - use existing Neo4j data
    parser.add_argument(
        "-r", "--resume",
        action="store_true",
        help="Resume from existing Neo4j data (skip edge import, auto-generate report)",
    )

    # Neo4j connection
    parser.add_argument(
        "--uri",
        default="bolt://localhost:7687",
        help="Neo4j URI (default: bolt://localhost:7687)",
    )
    parser.add_argument(
        "--user",
        default="neo4j",
        help="Neo4j username (default: neo4j)",
    )
    parser.add_argument(
        "--password",
        default="Neo4j123",
        help="Neo4j password (default: Neo4j123)",
    )

    # Behavior options
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Extract and validate without importing to Neo4j",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print detailed progress",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=500,
        help="Edges per batch (default: 500)",
    )
    parser.add_argument(
        "--dc-ip",
        type=str,
        metavar="IP",
        help="Set DC IP for DNS resolution and command auto-population. Can be used standalone (bt --dc-ip 192.168.50.70) or during import.",
    )

    # IP refresh mode options
    ip_refresh_group = parser.add_mutually_exclusive_group()
    ip_refresh_group.add_argument(
        "--clean",
        action="store_true",
        help="Clear all IPs before regenerating (default). Ensures fresh slate from DNS.",
    )
    ip_refresh_group.add_argument(
        "--update",
        action="store_true",
        help="Incremental update - keep existing IPs, only overwrite resolved computers.",
    )

    # Info options
    parser.add_argument(
        "--list-edges",
        action="store_true",
        help="List all supported edge types and exit",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate data and show summary without importing",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Skip automatic report generation (default: report auto-generated with all queries)",
    )

    # Query library options
    query_group = parser.add_argument_group("Query Library")
    query_group.add_argument(
        "--list-queries",
        action="store_true",
        help="List all available Cypher queries",
    )
    query_group.add_argument(
        "--category",
        type=str,
        choices=["lateral_movement", "quick_wins", "privilege_escalation",
                 "attack_chains", "operational", "owned_principal"],
        help="Filter queries by category",
    )
    query_group.add_argument(
        "--run-query",
        type=str,
        metavar="QUERY_ID",
        help="Run a specific query by ID (e.g., lateral-adminto-nonpriv)",
    )
    query_group.add_argument(
        "--var",
        type=str,
        action="append",
        metavar="NAME=VALUE",
        help="Set query variable (e.g., --var USER=PETE@CORP.COM)",
    )
    query_group.add_argument(
        "--search-query",
        type=str,
        metavar="KEYWORD",
        help="Search queries by keyword",
    )
    query_group.add_argument(
        "--export-query",
        type=str,
        metavar="QUERY_ID",
        help="Export query as raw Cypher for BloodHound paste",
    )
    query_group.add_argument(
        "--output-format",
        type=str,
        choices=["table", "json", "cypher"],
        default="table",
        help="Output format for query results (default: table)",
    )
    query_group.add_argument(
        "--install-queries",
        action="store_true",
        help="Install queries to BloodHound Legacy customqueries.json (~/.config/bloodhound/)",
    )
    query_group.add_argument(
        "--export-ce",
        action="store_true",
        help="Export queries as ZIP for BloodHound CE (drag-drop into Saved Queries)",
    )
    query_group.add_argument(
        "--export-ce-json",
        action="store_true",
        help="Export queries as JSON (not zipped) for BloodHound CE",
    )
    query_group.add_argument(
        "--install-path",
        type=Path,
        help="Custom output path for exported queries",
    )
    query_group.add_argument(
        "--oscp-high-only",
        action="store_true",
        help="Only export OSCP:HIGH relevance queries",
    )
    query_group.add_argument(
        "--run-all",
        action="store_true",
        help="Run all queries against existing Neo4j data (without importing new data). Report auto-generated when data path provided.",
    )
    query_group.add_argument(
        "--report-path",
        type=Path,
        help="Custom path for report output (default: ./bloodtrail.md)",
    )
    query_group.add_argument(
        "--commands", "-c",
        action="store_true",
        help="Only print command suggestions to console (report still generated)",
    )
    query_group.add_argument(
        "--data", "-d",
        action="store_true",
        help="Only print raw query data to console (report still generated)",
    )

    # Pwned user tracking options
    pwned_group = parser.add_argument_group("Pwned User Tracking")
    pwned_group.add_argument(
        "--pwn-interactive", "-pi",
        action="store_true",
        help="Interactively input credential information",
    )
    pwned_group.add_argument(
        "--pwn",
        type=str,
        metavar="USER",
        help="Mark user as pwned (e.g., PETE@CORP.COM)",
    )
    pwned_group.add_argument(
        "--unpwn",
        type=str,
        metavar="USER",
        help="Unmark user as pwned",
    )
    pwned_group.add_argument(
        "--list-pwned", "-lp",
        action="store_true",
        help="List all pwned users with access paths and credentials",
    )
    pwned_group.add_argument(
        "--cred-type",
        type=str,
        choices=["password", "ntlm-hash", "kerberos-ticket", "certificate"],
        help="Credential type for --pwn",
    )
    pwned_group.add_argument(
        "--cred-value",
        type=str,
        metavar="VALUE",
        help="Credential value for --pwn (password, hash, etc.)",
    )
    pwned_group.add_argument(
        "--source-machine",
        type=str,
        metavar="MACHINE",
        help="Machine where credential was obtained",
    )
    pwned_group.add_argument(
        "--pwn-notes",
        type=str,
        metavar="NOTES",
        help="Notes about compromise method",
    )
    pwned_group.add_argument(
        "--cred-targets",
        action="store_true",
        help="Show high-value credential harvest targets from pwned users",
    )
    pwned_group.add_argument(
        "--pwned-user",
        type=str,
        metavar="USER",
        help="Show details for specific pwned user",
    )
    pwned_group.add_argument(
        "--post-exploit", "-pe",
        action="store_true",
        help="Show post-exploitation (mimikatz) commands for all pwned users with local-admin access.",
    )
    pwned_group.add_argument(
        "--list-ip-addresses", "-lip",
        action="store_true",
        help="List all machines with their resolved IP addresses",
    )

    # Domain configuration options
    config_group = parser.add_argument_group("Domain Configuration")
    config_group.add_argument(
        "--set-dc-ip",
        type=str,
        metavar="IP",
        help="[DEPRECATED] Use --dc-ip during import instead. Store DC IP address for command auto-population (e.g., 192.168.50.70)",
    )
    config_group.add_argument(
        "--set-dc-hostname",
        type=str,
        metavar="HOSTNAME",
        help="Store DC hostname (optional, auto-detected from BloodHound)",
    )
    config_group.add_argument(
        "--domain-sid", "-ds",
        type=str,
        metavar="SID",
        help="Store Domain SID for Golden/Silver ticket auto-population (e.g., S-1-5-21-1987370270-658905905-1781884369)",
    )
    config_group.add_argument(
        "--show-config",
        action="store_true",
        help="Show stored domain configuration (domain, DC IP, DC hostname, SID)",
    )
    config_group.add_argument(
        "--clear-config",
        action="store_true",
        help="Clear stored domain configuration",
    )
    config_group.add_argument(
        "--purge",
        action="store_true",
        help="Purge ALL data from Neo4j database (nodes, edges, credentials). Use with caution!",
    )
    config_group.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Skip confirmation prompts (use with --purge)",
    )
    config_group.add_argument(
        "--discover-dc",
        nargs='*',
        metavar=('USER', 'PASSWORD'),
        help="Discover DC IP using BloodHound + crackmapexec. Usage: --discover-dc [USER PASSWORD]",
    )
    config_group.add_argument(
        "--lhost",
        type=str,
        metavar="IP",
        help="Attacker IP for reverse shell callbacks (stored in domain config)",
    )
    config_group.add_argument(
        "--lport",
        type=int,
        metavar="PORT",
        help="Attacker port for reverse shell callbacks (default: 443, stored in domain config)",
    )

    # Password Policy options
    policy_group = parser.add_argument_group("Password Policy")
    policy_group.add_argument(
        "--set-policy",
        nargs="?",
        const="-",  # stdin if no value
        metavar="FILE",
        help="Import password policy from 'net accounts' output. Use '-' for stdin, file path, or omit to paste interactively.",
    )
    policy_group.add_argument(
        "--show-policy",
        action="store_true",
        help="Show stored password policy and safe spray parameters",
    )
    policy_group.add_argument(
        "--clear-policy",
        action="store_true",
        help="Clear stored password policy",
    )

    # Password Spray options
    spray_group = parser.add_argument_group("Password Spraying")
    spray_group.add_argument(
        "--spray",
        action="store_true",
        help="Show password spray recommendations based on captured credentials",
    )
    spray_group.add_argument(
        "--spray-method",
        type=str,
        choices=["smb", "kerberos", "ldap", "all"],
        default="all",
        help="Filter spray methods to show (default: all)",
    )
    spray_group.add_argument(
        "--spray-tailored",
        action="store_true",
        help="Generate tailored spray commands based on BloodHound access data (user→machine mappings)",
    )
    spray_group.add_argument(
        "--spray-tailored-output",
        type=str,
        metavar="FILE",
        help="Output file for tailored spray report (default: spray_tailored.md in current dir)",
    )

    # Auto-spray arguments
    spray_group.add_argument(
        "--auto-spray",
        action="store_true",
        help="Generate auto-spray scripts (default) or execute with --execute flag",
    )
    spray_group.add_argument(
        "--execute",
        action="store_true",
        help="Execute spray commands automatically (requires --auto-spray). Default: generate scripts only",
    )
    spray_group.add_argument(
        "--spray-tool",
        type=str,
        choices=["kerbrute", "crackmapexec", "netexec", "hydra", "auto"],
        default="auto",
        help="Spray tool to use. 'auto' selects best available (default: auto)",
    )
    spray_group.add_argument(
        "--cred-source",
        type=str,
        action="append",
        choices=["neo4j", "potfile", "wordlist"],
        metavar="SOURCE",
        help="Credential sources: neo4j, potfile, wordlist (can specify multiple)",
    )
    spray_group.add_argument(
        "--wordlist",
        type=Path,
        metavar="FILE",
        help="Custom password wordlist file (use with --cred-source wordlist)",
    )
    spray_group.add_argument(
        "--potfile",
        type=Path,
        metavar="FILE",
        help="Custom potfile path (default: ~/.local/share/hashcat/hashcat.potfile)",
    )
    spray_group.add_argument(
        "--spray-users",
        type=str,
        choices=["all", "enabled", "non-pwned", "custom"],
        default="enabled",
        help="Users to target: 'all', 'enabled' (default), 'non-pwned', or 'custom' (with --user-file)",
    )
    spray_group.add_argument(
        "--user-file",
        type=Path,
        metavar="FILE",
        help="Custom user list file (use with --spray-users custom)",
    )
    spray_group.add_argument(
        "--targets-file",
        type=Path,
        metavar="FILE",
        help="Custom machine targets file (IPs/hostnames). Default: extract from Neo4j",
    )
    spray_group.add_argument(
        "--no-lockout-protection",
        action="store_true",
        help="Disable lockout protection (DANGEROUS - use only in lab environments)",
    )
    spray_group.add_argument(
        "--spray-output",
        type=Path,
        metavar="DIR",
        help="Output directory for spray scripts/results (default: ./spray_output/)",
    )

    return parser


def list_edge_types():
    """Print all supported edge types"""
    print("Supported Edge Types:")
    print()
    print("Computer Access:")
    for e in ["AdminTo", "CanPSRemote", "CanRDP", "ExecuteDCOM", "HasSession", "AllowedToAct"]:
        marker = "*" if e in ATTACK_PATH_EDGES else " "
        print(f"  {marker} {e}")
    print()
    print("ACL-Based:")
    for e in ["GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns",
              "ForceChangePassword", "AddKeyCredentialLink", "AllExtendedRights"]:
        marker = "*" if e in ATTACK_PATH_EDGES else " "
        print(f"  {marker} {e}")
    print()
    print("DCSync Rights:")
    for e in ["GetChanges", "GetChangesAll", "GetChangesInFilteredSet"]:
        marker = "*" if e in ATTACK_PATH_EDGES else " "
        print(f"  {marker} {e}")
    print()
    print("Membership:")
    for e in ["MemberOf"]:
        marker = "*" if e in ATTACK_PATH_EDGES else " "
        print(f"  {marker} {e}")
    print()
    print("Delegation:")
    for e in ["AllowedToDelegate"]:
        marker = "*" if e in ATTACK_PATH_EDGES else " "
        print(f"  {marker} {e}")
    print()
    print("* = Included in 'attack-paths' preset")


def parse_variables(var_list):
    """Parse --var arguments into a dict"""
    if not var_list:
        return {}
    variables = {}
    for var in var_list:
        if "=" in var:
            name, value = var.split("=", 1)
            variables[name] = value
        else:
            print(f"[!] Invalid variable format: {var} (expected NAME=VALUE)")
    return variables


# =============================================================================
# INTERACTIVE CREDENTIAL INPUT
# =============================================================================

def _fetch_neo4j_list(config: Neo4jConfig, query: str) -> list:
    """Fetch a list from Neo4j. Returns empty list on failure."""
    try:
        driver = GraphDatabase.driver(config.uri, auth=(config.user, config.password))
        with driver.session() as session:
            result = session.run(query)
            items = [r["name"] for r in result]
        driver.close()
        return items
    except Exception:
        return []


def _select_from_list(items: list, prompt: str, allow_manual: bool = True) -> str:
    """
    Present numbered list for selection.

    Args:
        items: List of items to choose from
        prompt: Header prompt to display
        allow_manual: If True, show [M] manual entry option

    Returns:
        Selected item or empty string if cancelled
    """
    if not items:
        if allow_manual:
            return input(f"{prompt} (manual): ").strip()
        return ""

    print(f"\n{prompt}:")
    for i, item in enumerate(items, 1):
        print(f"  [{i}] {item}")
    if allow_manual:
        print(f"  [M] Enter manually")

    choice = input("Choice: ").strip()

    if allow_manual and choice.upper() == "M":
        return input("  Enter value: ").strip()

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(items):
            return items[idx]
    except ValueError:
        pass

    # If invalid, treat as manual entry
    if choice:
        return choice.upper()
    return ""


def interactive_pwn(config: Neo4jConfig, prefill_user: str = None) -> dict:
    """
    Interactively collect credential information with selection menus.

    Args:
        config: Neo4j connection config for fetching users/computers
        prefill_user: Optional user to pre-fill (for "same user" loop)

    Returns:
        dict with keys: user, cred_type, cred_value, source_machine, notes
        Returns empty dict if user cancels (Ctrl+C)
    """
    CRED_TYPES = ["password", "ntlm-hash", "kerberos-ticket", "certificate"]

    print("\n🩸 Mark User as Pwned")

    try:
        # Fetch users and computers from Neo4j
        users = _fetch_neo4j_list(config, """
            MATCH (u:User)
            WHERE u.enabled = true AND NOT u.name STARTS WITH 'KRBTGT'
            RETURN u.name AS name
            ORDER BY u.name
            LIMIT 50
        """)

        computers = _fetch_neo4j_list(config, """
            MATCH (c:Computer)
            WHERE c.enabled = true
            RETURN c.name AS name
            ORDER BY c.name
            LIMIT 30
        """)

        # 1. User selection (required) - skip if pre-filled
        if prefill_user:
            print(f"\nUser: {prefill_user}")
            user = prefill_user
        else:
            user = _select_from_list(users, "Select user to mark as pwned")
        if not user:
            print("[!] User is required")
            return {}

        # 2. Credential type (required, with default)
        print("\nCredential type:")
        for i, ct in enumerate(CRED_TYPES, 1):
            print(f"  [{i}] {ct}")

        choice = input("Choice [1]: ").strip() or "1"
        try:
            cred_type = CRED_TYPES[int(choice) - 1]
        except (ValueError, IndexError):
            print("[!] Invalid choice, using 'password'")
            cred_type = "password"

        # 3. Credential value (required - always manual)
        cred_value = input(f"\n{cred_type.replace('-', ' ').title()}: ").strip()
        if not cred_value:
            print("[!] Credential value is required")
            return {}

        # 4. Source machine selection (optional)
        print("\nSource machine (where credential was obtained):")
        print("  [S] Skip")
        if computers:
            for i, comp in enumerate(computers, 1):
                print(f"  [{i}] {comp}")
        print("  [M] Enter manually")

        source_choice = input("Choice [S]: ").strip() or "S"
        source = None
        if source_choice.upper() == "M":
            source = input("  Enter machine: ").strip() or None
        elif source_choice.upper() != "S":
            try:
                idx = int(source_choice) - 1
                if 0 <= idx < len(computers):
                    source = computers[idx]
            except ValueError:
                if source_choice:
                    source = source_choice.upper()

        # 5. Notes (optional - always manual)
        notes = input("\nNotes (optional): ").strip() or None

        return {
            "user": user,
            "cred_type": cred_type,
            "cred_value": cred_value,
            "source_machine": source,
            "notes": notes,
        }

    except (KeyboardInterrupt, EOFError):
        print("\n[*] Cancelled")
        return {}


def handle_list_queries(args):
    """Handle --list-queries command"""
    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    runner = QueryRunner(config)

    queries = runner.list_queries(category=args.category)

    if not queries:
        print("[!] No queries found")
        return 1

    # Group by category
    by_category = {}
    for q in queries:
        if q.category not in by_category:
            by_category[q.category] = []
        by_category[q.category].append(q)

    print(f"\nBloodHound Cypher Query Library ({len(queries)} queries)")
    print("=" * 60)

    for cat, cat_queries in sorted(by_category.items()):
        print(f"\n[{cat.upper()}] ({len(cat_queries)} queries)")
        for q in cat_queries:
            oscp_marker = "*" if q.oscp_relevance == "high" else " "
            vars_marker = "(vars)" if q.has_variables() else ""
            print(f"  {oscp_marker} {q.id:40} {vars_marker}")

    print("\n* = OSCP:HIGH relevance")
    print("(vars) = requires --var arguments")
    print("\nRun: --run-query <id> to execute")
    return 0


def handle_search_queries(args):
    """Handle --search-query command"""
    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    runner = QueryRunner(config)

    queries = runner.search_queries(args.search_query)

    if not queries:
        print(f"[!] No queries found matching: {args.search_query}")
        return 1

    print(f"\nSearch Results for '{args.search_query}' ({len(queries)} matches)")
    print("=" * 60)

    for q in queries:
        print(f"\n{q.id}")
        print(f"  Name: {q.name}")
        print(f"  Category: {q.category} | OSCP: {q.oscp_relevance}")
        if q.has_variables():
            print(f"  Variables: {', '.join(q.variables.keys())}")

    return 0


def handle_run_query(args):
    """Handle --run-query command"""
    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    runner = QueryRunner(config)

    query = runner.get_query(args.run_query)
    if not query:
        print(f"[!] Query not found: {args.run_query}")
        return 1

    # Parse variables
    variables = parse_variables(args.var)

    # Check required variables
    if query.has_variables():
        missing = [v for v in query.get_required_variables() if v not in variables]
        if missing:
            print(f"[!] Missing required variables: {', '.join(missing)}")
            print(f"    Use: --var {missing[0]}=VALUE")
            for var_name, var_info in query.variables.items():
                print(f"    {var_name}: {var_info.get('description', '')} (e.g., {var_info.get('example', '')})")
            return 1

    print(f"[*] Running: {query.name}")
    print(f"[*] Category: {query.category} | OSCP: {query.oscp_relevance}")

    result = runner.run_query(args.run_query, variables)

    if not result.success:
        print(f"[!] Query failed: {result.error}")
        return 1

    # Format output
    if args.output_format == "json":
        print(json.dumps(result.records, indent=2, default=str))
    elif args.output_format == "cypher":
        print("\n# Executed Cypher:")
        print(result.cypher_executed)
    else:
        print(runner.format_results_table(result))

    # Suggest next steps
    if result.records and query.next_steps:
        print(f"\n[*] Suggested next queries: {', '.join(query.next_steps[:3])}")

    runner.close()
    return 0


def handle_export_query(args):
    """Handle --export-query command"""
    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    runner = QueryRunner(config)

    query = runner.get_query(args.export_query)
    if not query:
        print(f"[!] Query not found: {args.export_query}")
        return 1

    variables = parse_variables(args.var)
    cypher = runner.export_query(args.export_query, variables)

    print(f"// Query: {query.name}")
    print(f"// Category: {query.category}")
    print(f"// OSCP Relevance: {query.oscp_relevance}")
    if query.has_variables() and not variables:
        print(f"// Variables needed: {', '.join(query.variables.keys())}")
    print()
    print(cypher)

    return 0


def handle_install_queries(args):
    """Handle --install-queries command"""
    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    runner = QueryRunner(config)

    # Count queries before filtering
    all_queries = runner.list_queries(category=args.category)
    high_only = getattr(args, 'oscp_high_only', False)

    if high_only:
        filtered = [q for q in all_queries if q.oscp_relevance == "high"]
        print(f"[*] Installing {len(filtered)} OSCP:HIGH queries (filtered from {len(all_queries)})")
    else:
        filtered = all_queries
        print(f"[*] Installing {len(filtered)} queries")

    if args.category:
        print(f"[*] Category filter: {args.category}")

    # Export to BloodHound format
    output_path = export_to_bloodhound_customqueries(
        runner,
        output_path=args.install_path,
        category_filter=args.category,
        oscp_high_only=high_only
    )

    print(f"[+] Saved to: {output_path}")
    print()
    print("To use in BloodHound Legacy:")
    print("  1. Restart BloodHound")
    print("  2. Click 'Queries' tab (left sidebar)")
    print("  3. Look for '[CRACK] *' categories (sorted together)")
    print()
    print("Query categories installed:")
    category_display = {
        "lateral_movement": "Lateral Movement",
        "quick_wins": "Quick Wins",
        "privilege_escalation": "Privilege Escalation",
        "attack_chains": "Attack Chains",
        "operational": "Operational",
        "owned_principal": "Owned Principal",
    }
    categories = set(q.category for q in filtered)
    for cat in sorted(categories):
        count = sum(1 for q in filtered if q.category == cat)
        display = category_display.get(cat, cat.replace("_", " ").title())
        print(f"  - [CRACK] {display} ({count} queries)")

    return 0


def handle_run_all(args):
    """Handle --run-all command"""
    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    runner = QueryRunner(config)

    if not runner.connect():
        print("[!] Could not connect to Neo4j")
        print("    Ensure Neo4j is running: sudo neo4j start")
        return 1

    high_only = getattr(args, 'oscp_high_only', False)

    # Get stored DC IP from domain config (for <DC_IP> placeholder)
    dc_ip = None
    try:
        tracker = PwnedTracker(config)
        if tracker.connect():
            domain_config = tracker.get_domain_config()
            dc_ip = domain_config.get("dc_ip") if domain_config else None
            tracker.close()
    except Exception:
        pass  # Silently continue if DC IP not available

    try:
        stats = run_all_queries(
            runner,
            output_path=args.report_path,
            skip_variable_queries=True,
            oscp_high_only=high_only,
            show_commands=getattr(args, 'commands', False),
            show_data=getattr(args, 'data', False),
            dc_ip=dc_ip,
        )
    finally:
        runner.close()

    return 0 if stats["failed"] == 0 else 1


def handle_resume(args):
    """Handle --resume command - work with existing Neo4j data"""
    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)

    # Connect and verify data exists
    runner = QueryRunner(config)
    if not runner.connect():
        print("[!] Could not connect to Neo4j")
        print("    Ensure Neo4j is running: sudo neo4j start")
        return 1

    # Check if Neo4j has data
    try:
        with runner.driver.session() as session:
            result = session.run("MATCH (n) RETURN count(n) as total")
            total_nodes = result.single()["total"]

            if total_nodes == 0:
                print("[!] No data found in Neo4j database")
                print()
                print("    To import BloodHound data, run:")
                print("      crack bt /path/to/bloodhound/json/")
                print()
                runner.close()
                return 1
    except Exception as e:
        print(f"[!] Error checking Neo4j data: {e}")
        runner.close()
        return 1

    # Display nice banner
    C = "\033[96m"  # Cyan
    Y = "\033[93m"  # Yellow
    B = "\033[1m"   # Bold
    D = "\033[2m"   # Dim
    R = "\033[0m"   # Reset

    print()
    print(f"{C}{B}╔══════════════════════════════════════════════════════════════════════╗{R}")
    print(f"{C}{B}║{R}   {Y}🩸{R} {B}BloodHound Trail{R} - Resume Mode (Existing Data)              {C}{B}║{R}")
    print(f"{C}{B}╚══════════════════════════════════════════════════════════════════════╝{R}")
    print()
    print(f"  {D}Neo4j endpoint:{R}  {B}{args.uri}{R}")
    print(f"  {D}Nodes in DB:{R}     {B}{total_nodes}{R}")
    print()

    # Get stored DC IP from domain config
    dc_ip = None
    try:
        tracker = PwnedTracker(config)
        if tracker.connect():
            domain_config = tracker.get_domain_config()
            dc_ip = domain_config.get("dc_ip") if domain_config else None
            tracker.close()
    except Exception:
        pass

    # Run all queries (auto-generate report)
    high_only = getattr(args, 'oscp_high_only', False)

    try:
        stats = run_all_queries(
            runner,
            output_path=getattr(args, 'report_path', None),
            skip_variable_queries=True,
            oscp_high_only=high_only,
            show_commands=getattr(args, 'commands', False),
            show_data=getattr(args, 'data', False),
            dc_ip=dc_ip,
        )
    finally:
        runner.close()

    return 0 if stats["failed"] == 0 else 1


def handle_export_ce(args):
    """Handle --export-ce and --export-ce-json commands"""
    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    runner = QueryRunner(config)

    # Count queries
    all_queries = runner.list_queries(category=args.category)
    high_only = getattr(args, 'oscp_high_only', False)
    create_zip = args.export_ce  # True for --export-ce, False for --export-ce-json

    if high_only:
        filtered = [q for q in all_queries if q.oscp_relevance == "high"]
        print(f"[*] Exporting {len(filtered)} OSCP:HIGH queries (filtered from {len(all_queries)})")
    else:
        filtered = all_queries
        print(f"[*] Exporting {len(filtered)} queries")

    if args.category:
        print(f"[*] Category filter: {args.category}")

    # Export to BloodHound CE format
    output_path = export_to_bloodhound_ce(
        runner,
        output_path=args.install_path,
        category_filter=args.category,
        oscp_high_only=high_only,
        create_zip=create_zip
    )

    file_type = "ZIP" if create_zip else "JSON"
    print(f"[+] Saved {file_type}: {output_path}")
    print()
    print("To import into BloodHound CE:")
    print("  1. Open BloodHound CE in browser")
    print("  2. Navigate to: Explore > Cypher > Saved Queries")
    print("  3. Drag and drop the file into the Saved Queries panel")
    print("  4. BloodHound will validate and import the queries")
    print()
    print("Query categories:")
    category_display = {
        "lateral_movement": "CRACK - Lateral Movement",
        "quick_wins": "CRACK - Quick Wins",
        "privilege_escalation": "CRACK - Privilege Escalation",
        "attack_chains": "CRACK - Attack Chains",
        "operational": "CRACK - Operational",
        "owned_principal": "CRACK - Owned Principal",
    }
    categories = set(q.category for q in filtered)
    for cat in sorted(categories):
        count = sum(1 for q in filtered if q.category == cat)
        display = category_display.get(cat, f"CRACK - {cat.replace('_', ' ').title()}")
        print(f"  - {display} ({count} queries)")

    return 0


def handle_pwn_user(args):
    """Handle --pwn command"""
    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    tracker = PwnedTracker(config)

    if not tracker.connect():
        print("[!] Could not connect to Neo4j")
        return 1

    try:
        result = tracker.mark_pwned(
            user=args.pwn,
            cred_type=args.cred_type,
            cred_value=args.cred_value,
            source_machine=args.source_machine,
            notes=args.pwn_notes,
        )

        if not result.success:
            print(f"[!] Failed to mark {args.pwn} as pwned: {result.error}")
            return 1

        # Get domain config for DC IP and SID auto-population
        domain_config = tracker.get_domain_config()
        dc_ip = domain_config.get("dc_ip") if domain_config else None
        dc_hostname = domain_config.get("dc_hostname") if domain_config else None
        domain_sid = domain_config.get("domain_sid") if domain_config else None

        # Get user SPNs for manual enumeration suggestions
        user_spns = tracker.get_user_spns(result.user)

        # Show success with follow-up commands
        print_pwned_followup_commands(
            user_name=result.user,
            cred_type=args.cred_type,
            cred_value=args.cred_value,
            access=result.access,
            domain_level_access=result.domain_level_access,
            dc_ip=dc_ip,
            dc_hostname=dc_hostname,
            domain_sid=domain_sid,
            spns=user_spns,
        )
        return 0

    finally:
        tracker.close()


def handle_unpwn_user(args):
    """Handle --unpwn command"""
    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    tracker = PwnedTracker(config)

    if not tracker.connect():
        print("[!] Could not connect to Neo4j")
        return 1

    try:
        result = tracker.unmark_pwned(args.unpwn)

        if not result.success:
            print(f"[!] Failed to unmark {args.unpwn}: {result.error}")
            return 1

        print(f"[+] Removed pwned status from: {args.unpwn}")
        return 0

    finally:
        tracker.close()


def handle_list_pwned(args):
    """Handle --list-pwned command"""
    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    tracker = PwnedTracker(config)

    if not tracker.connect():
        print("[!] Could not connect to Neo4j")
        return 1

    try:
        pwned_users = tracker.list_pwned_users()

        if not pwned_users:
            print("[*] No pwned users found")
            return 0

        print_pwned_users_table(pwned_users)
        return 0

    finally:
        tracker.close()


def handle_pwned_user_detail(args):
    """Handle --pwned-user command"""
    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    tracker = PwnedTracker(config)

    if not tracker.connect():
        print("[!] Could not connect to Neo4j")
        return 1

    try:
        pwned_user = tracker.get_pwned_user(args.pwned_user)

        if not pwned_user:
            print(f"[!] User not found or not pwned: {args.pwned_user}")
            return 1

        machine_access = tracker.get_pwned_user_access(args.pwned_user)

        # Get domain config for DC IP, SID, and LHOST/LPORT auto-population
        domain_config = tracker.get_domain_config()
        dc_ip = domain_config.get("dc_ip") if domain_config else None
        dc_hostname = domain_config.get("dc_hostname") if domain_config else None
        domain_sid = domain_config.get("domain_sid") if domain_config else None
        lhost = domain_config.get("lhost") if domain_config else None
        lport = domain_config.get("lport") if domain_config else None

        # Override from CLI args if provided
        if getattr(args, 'lhost', None):
            lhost = args.lhost
        if getattr(args, 'lport', None):
            lport = args.lport

        # Fall back to config.py defaults if still not set
        if not lhost and CONFIG_LHOST:
            lhost = CONFIG_LHOST
        if not lport and CONFIG_LPORT:
            lport = CONFIG_LPORT

        # Get user SPNs for manual enumeration suggestions
        user_spns = tracker.get_user_spns(pwned_user.name)

        print_pwned_followup_commands(
            user_name=pwned_user.name,
            access=machine_access,
            domain_level_access=pwned_user.domain_level_access,
            cred_types=pwned_user.cred_types,
            cred_values=pwned_user.cred_values,
            dc_ip=dc_ip,
            dc_hostname=dc_hostname,
            domain_sid=domain_sid,
            lhost=lhost,
            lport=lport,
            spns=user_spns,
        )
        return 0

    finally:
        tracker.close()


def handle_cred_targets(args):
    """Handle --cred-targets command"""
    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    tracker = PwnedTracker(config)

    if not tracker.connect():
        print("[!] Could not connect to Neo4j")
        return 1

    try:
        targets = tracker.get_cred_harvest_targets()

        if not targets:
            print("[*] No credential harvest targets found")
            print("    Mark users as pwned first: --pwn USER@DOMAIN.COM")
            return 0

        print_cred_harvest_targets(targets)
        return 0

    finally:
        tracker.close()


def handle_post_exploit(args):
    """Handle --post-exploit flag - show mimikatz recommendations."""
    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    tracker = PwnedTracker(config)

    if not tracker.connect():
        print("[!] Could not connect to Neo4j")
        return 1

    try:
        # Get domain config for DC IP, SID, and LHOST/LPORT auto-population
        domain_config = tracker.get_domain_config()
        dc_ip = domain_config.get("dc_ip") if domain_config else None
        domain_sid = domain_config.get("domain_sid") if domain_config else None
        lhost = domain_config.get("lhost") if domain_config else None
        lport = domain_config.get("lport") if domain_config else None

        # Override from CLI args if provided
        if getattr(args, 'lhost', None):
            lhost = args.lhost
        if getattr(args, 'lport', None):
            lport = args.lport

        # Fall back to config.py defaults if still not set
        if not lhost and CONFIG_LHOST:
            lhost = CONFIG_LHOST
        if not lport and CONFIG_LPORT:
            lport = CONFIG_LPORT

        # Get all pwned users
        pwned_users = tracker.list_pwned_users()
        if not pwned_users:
            print("[*] No pwned users found")
            print("    Mark users as pwned first: --pwn USER@DOMAIN.COM")
            return 0

        shown_count = 0
        for user in pwned_users:
            machine_access = tracker.get_pwned_user_access(user.name)

            # Check if user has local-admin or domain-admin access
            has_local_admin = any(a.privilege_level == "local-admin" for a in machine_access)
            has_domain_admin = user.domain_level_access is not None

            if has_local_admin or has_domain_admin:
                print_post_exploit_commands(
                    user_name=user.name,
                    access=machine_access,
                    domain_level_access=user.domain_level_access,
                    cred_types=user.cred_types,
                    cred_values=user.cred_values,
                    dc_ip=dc_ip,
                    domain_sid=domain_sid,
                    lhost=lhost,
                    lport=lport,
                )
                shown_count += 1

        if shown_count == 0:
            print("[*] No pwned users with local-admin or domain-admin access found")
            print("    Post-exploitation commands require elevated access")

        return 0

    finally:
        tracker.close()


def handle_list_ip_addresses(args):
    """Handle --list-ip-addresses command - list all machines with IPs."""
    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    tracker = PwnedTracker(config)

    if not tracker.connect():
        print("[!] Could not connect to Neo4j")
        return 1

    try:
        machines = tracker.get_all_machines_with_ips()
        # Get DC IP from stored config for highlighting
        domain_config = tracker.get_domain_config()
        dc_ip = domain_config.get("dc_ip") if domain_config else None
        print_machines_ip_table(machines, dc_ip=dc_ip)
        return 0

    finally:
        tracker.close()


def handle_set_dc_ip(args):
    """Handle --set-dc-ip command"""
    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    tracker = PwnedTracker(config)

    if not tracker.connect():
        print("[!] Could not connect to Neo4j")
        return 1

    try:
        result = tracker.set_dc_ip(
            dc_ip=args.set_dc_ip,
            dc_hostname=getattr(args, 'set_dc_hostname', None)
        )

        if not result.success:
            print(f"[!] Failed to set DC IP: {result.error}")
            return 1

        print(f"[+] DC IP set: {args.set_dc_ip}")
        if args.set_dc_hostname:
            print(f"[+] DC hostname set: {args.set_dc_hostname}")

        # Show full config
        domain_config = tracker.get_domain_config()
        if domain_config:
            print()
            print(f"  Domain:      {domain_config['domain']}")
            print(f"  DC Hostname: {domain_config['dc_hostname'] or '(auto-detected)'}")
            print(f"  DC IP:       {domain_config['dc_ip']}")

        return 0

    finally:
        tracker.close()


def handle_dc_ip_standalone(args):
    """Handle --dc-ip as standalone config setter with IP resolution"""
    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    tracker = PwnedTracker(config)

    if not tracker.connect():
        print("[!] Could not connect to Neo4j")
        return 1

    try:
        # Set DC IP in config
        result = tracker.set_dc_ip(
            dc_ip=args.dc_ip,
            dc_hostname=getattr(args, 'set_dc_hostname', None)
        )

        if not result.success:
            print(f"[!] Failed to set DC IP: {result.error}")
            return 1

        print(f"[+] DC IP set: {args.dc_ip}")

        # Show domain config
        domain_config = tracker.get_domain_config()
        if domain_config:
            print(f"  Domain:      {domain_config['domain']}")

        # Fetch all computers from Neo4j
        driver = GraphDatabase.driver(args.uri, auth=(args.user, args.password))
        try:
            with driver.session() as session:
                result = session.run("""
                    MATCH (c:Computer)
                    RETURN c.name AS name
                    ORDER BY c.name
                """)
                computers = [record["name"] for record in result if record["name"]]

            # Filter out SIDs and invalid hostnames
            computers = [c for c in computers if c and 'S-1-5-' not in c and '.' in c]

            if not computers:
                print("\n[*] No computers found in Neo4j. Import BloodHound data first.")
                return 0

            print(f"\n[*] Resolving IPs for {len(computers)} computers using DC as DNS...")

            # Resolve IPs using DC as DNS server
            resolver = IPResolver(timeout=2.0, max_workers=20, dc_ip=args.dc_ip)
            ip_mappings = resolver.resolve_batch(computers)

            # Store resolved IPs in Neo4j
            resolved_count = 0
            with driver.session() as session:
                for fqdn, ip in ip_mappings.items():
                    if ip:
                        session.run("""
                            MATCH (c:Computer {name: $name})
                            SET c.bloodtrail_ip = $ip,
                                c.bloodtrail_ip_resolved_at = datetime()
                        """, name=fqdn, ip=ip)
                        resolved_count += 1

            # Print results table
            stats = resolver.get_stats()
            print(f"\n[+] Resolved: {stats['resolved']} | Failed: {stats['failed']}")
            print()
            print(f"{'COMPUTER':<45} {'IP ADDRESS':<15}")
            print("-" * 60)

            for fqdn in sorted(ip_mappings.keys()):
                ip = ip_mappings[fqdn]
                if ip:
                    print(f"{fqdn:<45} \033[92m{ip:<15}\033[0m")
                else:
                    print(f"{fqdn:<45} \033[91m(unresolved)\033[0m")

        finally:
            driver.close()

        return 0

    finally:
        tracker.close()


def handle_show_config(args):
    """Handle --show-config command"""
    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    tracker = PwnedTracker(config)

    if not tracker.connect():
        print("[!] Could not connect to Neo4j")
        return 1

    try:
        domain_config = tracker.get_domain_config()

        if not domain_config:
            print("[*] No domain found in BloodHound data")
            print("    Import BloodHound data first: crack bloodtrail /path/to/bh/json/")
            return 0

        print()
        print("🩸 Domain Configuration")
        print("=" * 40)
        print(f"  Domain:      {domain_config['domain']}")
        print(f"  DC Hostname: {domain_config['dc_hostname'] or '(not set)'}")
        print(f"  DC IP:       {domain_config['dc_ip'] or '(not set)'}")
        print(f"  Domain SID:  {domain_config['domain_sid'] or '(not set)'}")

        # Callback config
        lhost = domain_config.get('lhost')
        lport = domain_config.get('lport')
        if lhost or lport:
            print()
            print("📡 Callback Configuration")
            print("-" * 40)
            print(f"  LHOST:       {lhost or '(not set)'}")
            print(f"  LPORT:       {lport or '(not set)'}")

        print()

        if not domain_config['dc_ip']:
            print("  Set DC IP:   crack bloodtrail /path/to/bh/json/ --dc-ip 192.168.50.70")
        if not domain_config['domain_sid']:
            print("  Set SID:     crack bloodtrail -ds S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX")
        if not lhost:
            print("  Set LHOST:   crack bloodtrail --lhost 192.168.45.200 --lport 443")
        print()

        return 0

    finally:
        tracker.close()


def handle_clear_config(args):
    """Handle --clear-config command"""
    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    tracker = PwnedTracker(config)

    if not tracker.connect():
        print("[!] Could not connect to Neo4j")
        return 1

    try:
        result = tracker.clear_domain_config()

        if not result.success:
            print(f"[!] Failed to clear config: {result.error}")
            return 1

        print(f"[+] Domain configuration cleared")
        return 0

    finally:
        tracker.close()


def handle_purge(args):
    """Handle --purge command - completely clear Neo4j database"""
    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)

    # Connect to Neo4j
    try:
        driver = GraphDatabase.driver(config.uri, auth=(config.user, config.password))
        with driver.session() as session:
            session.run("RETURN 1")
    except Exception as e:
        print(f"[!] Could not connect to Neo4j: {e}")
        return 1

    # Get current database stats
    try:
        with driver.session() as session:
            # Count nodes and relationships
            result = session.run("""
                MATCH (n)
                WITH count(n) AS total_nodes
                MATCH ()-[r]->()
                WITH total_nodes, count(r) AS total_rels
                RETURN total_nodes, total_rels
            """)
            record = result.single()
            total_nodes = record["total_nodes"] if record else 0
            total_rels = record["total_rels"] if record else 0

            # Get node counts by label
            result = session.run("""
                MATCH (u:User) WITH count(u) AS users
                MATCH (c:Computer) WITH users, count(c) AS computers
                MATCH (g:Group) WITH users, computers, count(g) AS groups
                MATCH (d:Domain) WITH users, computers, groups, count(d) AS domains
                RETURN users, computers, groups, domains
            """)
            record = result.single()
            if record:
                users = record["users"]
                computers = record["computers"]
                groups = record["groups"]
                domains = record["domains"]
            else:
                users = computers = groups = domains = 0

    except Exception as e:
        print(f"[!] Error checking database: {e}")
        driver.close()
        return 1

    # Display what will be deleted
    print()
    print("\033[91m\033[1m╔══════════════════════════════════════════════════════════════════════╗\033[0m")
    print("\033[91m\033[1m║\033[0m   \033[91m⚠\033[0m  \033[1mWARNING: Database Purge\033[0m                                        \033[91m\033[1m║\033[0m")
    print("\033[91m\033[1m╚══════════════════════════════════════════════════════════════════════╝\033[0m")
    print()
    print("  This will permanently delete ALL data from Neo4j:")
    print()
    print(f"    \033[91m•\033[0m Users:         \033[1m{users}\033[0m")
    print(f"    \033[91m•\033[0m Computers:     \033[1m{computers}\033[0m")
    print(f"    \033[91m•\033[0m Groups:        \033[1m{groups}\033[0m")
    print(f"    \033[91m•\033[0m Domains:       \033[1m{domains}\033[0m")
    print(f"    \033[91m•\033[0m Total Nodes:   \033[1m{total_nodes}\033[0m")
    print(f"    \033[91m•\033[0m Relationships: \033[1m{total_rels}\033[0m")
    print()
    print("  \033[2mThis includes:\033[0m")
    print("    - All BloodHound Active Directory data")
    print("    - All pwned user credentials and tracking")
    print("    - Domain configuration (DC IP, SID, etc.)")
    print("    - Password policies")
    print()

    if total_nodes == 0:
        print("[*] Database is already empty.")
        driver.close()
        return 0

    # Confirm unless -y/--yes provided
    if not getattr(args, 'yes', False):
        confirm = input("  \033[1mType 'PURGE' to confirm:\033[0m ").strip()
        if confirm != "PURGE":
            print()
            print("[*] Aborted. No changes made.")
            driver.close()
            return 0

    # Execute purge
    print()
    print("[*] Purging database...")

    try:
        with driver.session() as session:
            # Delete all nodes and relationships
            result = session.run("MATCH (n) DETACH DELETE n RETURN count(n) AS deleted")
            record = result.single()
            deleted = record["deleted"] if record else 0

        print(f"\033[92m[+]\033[0m Purge complete: \033[1m{deleted}\033[0m nodes deleted")
        print()
        print("  To reimport BloodHound data:")
        print("    1. Import via BloodHound GUI (File > Upload Data)")
        print("    2. Run: crack bloodtrail /path/to/sharphound.zip")
        print()

    except Exception as e:
        print(f"[!] Purge failed: {e}")
        driver.close()
        return 1

    driver.close()
    return 0


def handle_domain_sid(args):
    """Handle --domain-sid command"""
    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    tracker = PwnedTracker(config)

    if not tracker.connect():
        print("[!] Could not connect to Neo4j")
        return 1

    try:
        result = tracker.set_domain_sid(args.domain_sid)

        if not result.success:
            print(f"[!] Failed to set Domain SID: {result.error}")
            return 1

        # Get the actual stored SID (may have been stripped of RID)
        domain_config = tracker.get_domain_config()
        stored_sid = domain_config.get("domain_sid") if domain_config else args.domain_sid
        print(f"[+] Domain SID set: {stored_sid}")

        # Show updated config
        domain_config = tracker.get_domain_config()
        if domain_config:
            print()
            print(f"  Domain:     {domain_config['domain']}")
            print(f"  Domain SID: {domain_config['domain_sid']}")

        return 0

    finally:
        tracker.close()


def handle_callback_config(args):
    """Handle --lhost/--lport flags - store callback configuration."""
    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    tracker = PwnedTracker(config)

    if not tracker.connect():
        print("[!] Could not connect to Neo4j")
        return 1

    try:
        lhost = args.lhost
        lport = args.lport or 443  # Default to 443

        result = tracker.set_callback_config(lhost, lport)

        if not result.success:
            print(f"[!] Failed to set callback config: {result.error}")
            return 1

        print(f"[+] Callback config set: LHOST={lhost} LPORT={lport}")
        return 0

    finally:
        tracker.close()


def handle_discover_dc(args):
    """Handle --discover-dc command - auto-discover DC IP using crackmapexec"""
    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    tracker = PwnedTracker(config)

    if not tracker.connect():
        print("[!] Could not connect to Neo4j")
        return 1

    try:
        # 1. Get domain from BloodHound
        domain_config = tracker.get_domain_config()

        if not domain_config or not domain_config.get('domain'):
            print("[!] No domain found in BloodHound data")
            print("    Import BloodHound data first: crack bloodtrail /path/to/bh/json/")
            return 1

        domain = domain_config['domain']

        # 2. Get credentials (from args or prompt)
        if args.discover_dc and len(args.discover_dc) >= 2:
            ad_user, ad_password = args.discover_dc[0], args.discover_dc[1]
        else:
            print(f"[*] Discovering DC for {domain}")
            ad_user = input("    Username: ").strip()
            ad_password = getpass.getpass("    Password: ")

        if not ad_user or not ad_password:
            print("[!] Username and password required")
            return 1

        # 3. Discover DC IP
        print(f"[*] Discovering DC for {domain}...")

        try:
            dc_ip = discover_dc_ip(domain, ad_user, ad_password)
            print(f"[+] DC IP:       {dc_ip}")
        except DiscoveryError as e:
            print(f"[!] {e}")
            return 1

        # 4. Discover DC hostname
        try:
            dc_hostname = discover_dc_hostname(dc_ip, ad_user, ad_password)
            print(f"[+] DC Hostname: {dc_hostname}")
        except DiscoveryError as e:
            print(f"[!] {e}")
            # Still store IP even if hostname discovery fails
            dc_hostname = None

        # 5. Store in Neo4j
        result = tracker.set_dc_ip(dc_ip, dc_hostname)
        if result.success:
            print(f"[+] Stored in Neo4j")
        else:
            print(f"[!] Failed to store: {result.error}")

        # 6. Ask user about /etc/hosts
        entry = f"{dc_ip} {dc_hostname.lower() if dc_hostname else 'dc'}.{domain.lower()} {dc_hostname.lower() if dc_hostname else 'dc'} {domain.lower()}"
        print()
        print(f"[?] Add to /etc/hosts?")
        print(f"    {entry}")
        response = input("    [Y/n]: ").strip().lower()

        if response != 'n':
            update_etc_hosts(entry)

        # 7. Print summary
        print()
        print(f"[+] DC discovery complete")
        print(f"    Domain:   {domain}")
        print(f"    DC:       {dc_hostname or '(unknown)'}")
        print(f"    IP:       {dc_ip}")

        return 0

    finally:
        tracker.close()


# =============================================================================
# PASSWORD POLICY HANDLERS
# =============================================================================

def handle_set_policy(args):
    """Handle --set-policy command - import password policy from net accounts output."""
    from .policy_parser import parse_net_accounts, format_policy_display

    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    tracker = PwnedTracker(config)

    if not tracker.connect():
        print("[!] Could not connect to Neo4j")
        return 1

    try:
        # Get policy text from stdin, file, or interactive
        policy_text = ""

        if args.set_policy == "-":
            # Read from stdin
            print("[*] Reading 'net accounts' output from stdin (Ctrl+D when done):")
            import sys
            policy_text = sys.stdin.read()
        elif args.set_policy and args.set_policy != "-":
            # Read from file if it exists
            import os
            if os.path.isfile(args.set_policy):
                with open(args.set_policy, 'r') as f:
                    policy_text = f.read()
                print(f"[*] Read policy from: {args.set_policy}")
            else:
                # Treat as the text itself (if someone passes the value directly)
                policy_text = args.set_policy
        else:
            # Interactive input
            print("[*] Paste 'net accounts' output (empty line to finish):")
            print()
            lines = []
            while True:
                try:
                    line = input()
                    if not line and lines:
                        break
                    lines.append(line)
                except EOFError:
                    break
            policy_text = "\n".join(lines)

        if not policy_text.strip():
            print("[!] No policy text provided")
            return 1

        # Parse the policy
        policy = parse_net_accounts(policy_text)

        # Store in Neo4j
        result = tracker.set_password_policy(policy)

        if not result.success:
            print(f"[!] Failed to store policy: {result.error}")
            return 1

        # Show what was stored
        print()
        print("[+] Password policy stored successfully!")
        print()
        print(format_policy_display(policy))

        return 0

    finally:
        tracker.close()


def handle_show_policy(args):
    """Handle --show-policy command - display stored password policy."""
    from .policy_parser import format_policy_display

    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    tracker = PwnedTracker(config)

    if not tracker.connect():
        print("[!] Could not connect to Neo4j")
        return 1

    try:
        policy = tracker.get_password_policy()

        if not policy:
            print("[*] No password policy stored")
            print("    Import with: crack bloodtrail --set-policy")
            return 0

        print()
        print(format_policy_display(policy))
        print()

        return 0

    finally:
        tracker.close()


def handle_clear_policy(args):
    """Handle --clear-policy command - clear stored password policy."""
    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    tracker = PwnedTracker(config)

    if not tracker.connect():
        print("[!] Could not connect to Neo4j")
        return 1

    try:
        result = tracker.clear_password_policy()

        if not result.success:
            print(f"[!] Failed to clear policy: {result.error}")
            return 1

        print("[+] Password policy cleared")
        return 0

    finally:
        tracker.close()


def handle_spray(args):
    """Handle --spray command - show password spray recommendations."""
    from .display_commands import print_spray_recommendations

    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    tracker = PwnedTracker(config)

    if not tracker.connect():
        print("[!] Could not connect to Neo4j")
        return 1

    try:
        # Get pwned users with credentials
        pwned_users = tracker.list_pwned_users()

        # Get password policy if stored
        policy = tracker.get_password_policy()

        # Get domain config
        domain_config = tracker.get_domain_config()
        domain = domain_config.get("domain", "") if domain_config else ""
        dc_ip = (domain_config.get("dc_ip") if domain_config else None) or "<DC_IP>"

        # Get all machine IPs for multi-target loops
        machines = tracker.get_all_machines_with_ips()
        all_ips = [m["ip"] for m in machines if m.get("ip")]

        # Show recommendations
        print_spray_recommendations(
            pwned_users=pwned_users,
            policy=policy,
            domain=domain,
            dc_ip=dc_ip,
            method_filter=getattr(args, 'spray_method', 'all'),
            all_ips=all_ips,
        )

        return 0

    finally:
        tracker.close()


def handle_spray_tailored(args):
    """Handle --spray-tailored command - generate tailored spray commands based on BloodHound access data."""
    from .display_commands import print_spray_tailored

    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    tracker = PwnedTracker(config)

    if not tracker.connect():
        print("[!] Could not connect to Neo4j")
        return 1

    try:
        # Get all user-to-machine access relationships
        access_data = tracker.get_all_users_with_access()

        if not access_data:
            print("[!] No user-to-machine access relationships found in Neo4j")
            print("    Make sure BloodHound data has been imported with edge collection")
            return 1

        # Get domain config
        domain_config = tracker.get_domain_config()
        domain = domain_config.get("domain", "") if domain_config else ""

        # Generate output
        console_output, markdown_output = print_spray_tailored(
            access_data=access_data,
            domain=domain,
            use_colors=True,
        )

        # Print to console (no truncation)
        print(console_output)

        # Write report file
        output_file = getattr(args, 'spray_tailored_output', None) or "spray_tailored.md"
        try:
            with open(output_file, "w") as f:
                f.write(markdown_output)
            print(f"[+] Report written to: {output_file}")
        except Exception as e:
            print(f"[!] Failed to write report: {e}")

        return 0

    finally:
        tracker.close()


def handle_auto_spray(args):
    """Handle --auto-spray command - generate or execute spray operations."""
    from .autospray import (
        SprayExecutor,
        CredentialManager,
        LockoutManager,
        ScriptGenerator,
        Neo4jCredentialSource,
        WordlistSource,
        PotfileSource,
        TargetManager,
        Neo4jUserSource,
        Neo4jMachineSource,
        FileTargetSource,
    )
    from .autospray.executor import SprayTool, ToolNotFoundError

    config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
    tracker = PwnedTracker(config)

    if not tracker.connect():
        print("[!] Could not connect to Neo4j")
        return 1

    try:
        # Get domain configuration
        domain_config = tracker.get_domain_config()
        domain = domain_config.get("domain", "") if domain_config else ""
        dc_ip = domain_config.get("dc_ip") if domain_config else None

        if not dc_ip:
            print("[!] DC IP not configured. Set it with: crack bt --dc-ip <IP>")
            return 1

        if not domain:
            print("[!] Domain not configured. Set it with: crack bt --domain <DOMAIN>")
            return 1

        print(f"[*] Domain: {domain}")
        print(f"[*] DC IP: {dc_ip}")
        print()

        # Initialize credential manager
        cred_manager = CredentialManager()

        # Add requested credential sources (default: neo4j)
        sources = args.cred_source or ["neo4j"]

        if "neo4j" in sources:
            cred_manager.add_source(Neo4jCredentialSource(config))
        if "wordlist" in sources:
            if not args.wordlist:
                print("[!] --wordlist required when using --cred-source wordlist")
                return 1
            cred_manager.add_source(WordlistSource(args.wordlist))
        if "potfile" in sources:
            cred_manager.add_source(PotfileSource(args.potfile))

        # Get passwords (optional - commands will use placeholders if empty)
        passwords = cred_manager.get_passwords_for_spray()

        if passwords:
            print(f"[+] Loaded {len(passwords)} passwords from {len(sources)} source(s)")
        else:
            print("[*] No passwords found - commands will use <PASSWORD> placeholders")
            stats = cred_manager.get_statistics()
            print(f"    Sources checked: {stats['sources_available'] or ['none']}")

        # Initialize target manager
        target_manager = TargetManager()

        # Add user sources
        user_filter = getattr(args, 'spray_users', 'enabled')
        if user_filter == "custom" and args.user_file:
            target_manager.add_user_source(FileTargetSource(args.user_file, "user"))
        else:
            target_manager.add_user_source(Neo4jUserSource(config, user_filter))

        # Add machine sources
        if args.targets_file:
            target_manager.add_machine_source(FileTargetSource(args.targets_file, "machine"))
        else:
            target_manager.add_machine_source(Neo4jMachineSource(config))

        # Get targets
        users = target_manager.get_users()
        machines = target_manager.get_machines()

        if not users:
            print("[!] No target users found")
            return 1

        print(f"[+] Targeting {len(users)} users")
        if machines:
            print(f"[+] Targeting {len(machines)} machines")
        print()

        # Get password policy
        policy = tracker.get_password_policy()

        # Initialize lockout manager
        lockout_mgr = LockoutManager(
            policy=policy,
            override_mode=args.no_lockout_protection,
        )

        # Display spray plan (only if we have passwords)
        if passwords:
            print(lockout_mgr.format_plan_display(passwords, len(users)))
            print()

        # Determine tool
        spray_tool = None
        if args.spray_tool and args.spray_tool != "auto":
            tool_map = {
                "kerbrute": SprayTool.KERBRUTE,
                "crackmapexec": SprayTool.CRACKMAPEXEC,
                "netexec": SprayTool.NETEXEC,
                "hydra": SprayTool.HYDRA,
            }
            spray_tool = tool_map.get(args.spray_tool)

        if args.execute:
            # Execute mode - run spray with real-time output
            return _execute_auto_spray(
                args, tracker, domain, dc_ip, users, passwords,
                lockout_mgr, spray_tool, machines
            )
        else:
            # Default: Generate scripts for review
            return _generate_spray_scripts(
                args, domain, dc_ip, users, passwords, lockout_mgr, machines
            )

    finally:
        tracker.close()


def _get_spray_users(tracker, args) -> list:
    """Get target users based on --spray-users option. (Deprecated - use TargetManager)"""
    user_mode = getattr(args, 'spray_users', 'enabled')

    if user_mode == "custom":
        if not args.user_file:
            print("[!] --user-file required when using --spray-users custom")
            return []
        try:
            with open(args.user_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Failed to read user file: {e}")
            return []

    elif user_mode == "all":
        return tracker.get_all_users()
    elif user_mode == "non-pwned":
        return tracker.get_non_pwned_users()
    else:  # enabled (default)
        return tracker.get_enabled_users()


def _execute_auto_spray(args, tracker, domain, dc_ip, users, passwords, lockout_mgr, spray_tool, machines=None):
    """Execute spray with real-time output."""
    from .autospray import SprayExecutor
    from .autospray.executor import ToolNotFoundError

    machines = machines or []

    # Confirmation prompt
    print("=" * 60)
    print("  AUTO-SPRAY EXECUTION CONFIRMATION")
    print("=" * 60)
    print()
    print(f"  Target Users:     {len(users)} accounts")
    print(f"  Target Machines:  {len(machines)} hosts" if machines else "  Target Machines:  DC only")
    print(f"  Passwords:        {len(passwords)} unique passwords")
    print(f"  DC Target:        {dc_ip}")
    print()

    if lockout_mgr.has_policy:
        print(f"  Lockout threshold: {lockout_mgr.lockout_threshold} attempts")
        print(f"  Safe per round:    {lockout_mgr.safe_attempts}")
    elif args.no_lockout_protection:
        print("  WARNING: Lockout protection DISABLED")
    else:
        print("  WARNING: No lockout policy detected")

    print()
    confirm = input("  Type 'SPRAY' to confirm: ")

    if confirm != "SPRAY":
        print("[!] Aborted")
        return 1

    print()
    print("[*] Starting spray...")
    print()

    try:
        with SprayExecutor(
            tool=spray_tool,
            domain=domain,
            dc_ip=dc_ip,
            verbose=True,
        ) as executor:
            tool_name = executor.get_tool().value
            print(f"[*] Using tool: {tool_name}")
            print()

            all_results = []

            def progress_cb(current, total, status):
                print(f"\r[{current}/{total}] {status}    ", end="", flush=True)

            def result_cb(result):
                if result.success:
                    for r in result.results:
                        admin = " [ADMIN]" if r.is_admin else ""
                        print(f"\n[+] VALID: {r.username}:{r.password}{admin}")

            results = executor.spray_with_plan(
                users=users,
                passwords=passwords,
                lockout_manager=lockout_mgr,
                progress_callback=progress_cb,
                result_callback=result_cb,
            )

            all_results.extend(results)

        # Summary
        print()
        print()
        print("=" * 60)
        print("  SPRAY COMPLETE")
        print("=" * 60)
        print()

        valid_creds = [r for result in all_results for r in result.results]
        admin_creds = [r for r in valid_creds if r.is_admin]

        print(f"  Valid credentials: {len(valid_creds)}")
        print(f"  Admin access:      {len(admin_creds)}")
        print()

        if valid_creds:
            print("  Credentials found:")
            for r in valid_creds:
                admin = " (ADMIN)" if r.is_admin else ""
                print(f"    {r.username}:{r.password}{admin}")
            print()

            # Mark pwned in Neo4j
            print("[*] Marking users as pwned in Neo4j...")
            marked = tracker.mark_pwned_batch([
                {"username": r.username, "password": r.password, "is_admin": r.is_admin}
                for r in valid_creds
            ])
            print(f"[+] Marked {marked} users as pwned")

        return 0

    except ToolNotFoundError as e:
        print(f"[!] {e}")
        return 1
    except Exception as e:
        print(f"[!] Spray failed: {e}")
        return 1


def _generate_spray_scripts(args, domain, dc_ip, users, passwords, lockout_mgr, machines=None):
    """Generate spray scripts for manual review."""
    from .autospray import ScriptGenerator

    machines = machines or []
    output_dir = args.spray_output or Path("./spray_output")
    tool = args.spray_tool if args.spray_tool != "auto" else "crackmapexec"

    generator = ScriptGenerator(
        domain=domain,
        dc_ip=dc_ip,
        output_dir=output_dir,
        tool=tool,
    )

    print(f"[*] Generating spray scripts with {tool}...")

    result = generator.generate_spray_script(
        users=users,
        passwords=passwords,
        lockout_manager=lockout_mgr,
        machines=machines,
    )

    # Print the commands file content to console
    commands_file = output_dir / "spray_commands.txt"
    if commands_file.exists():
        print()
        print(commands_file.read_text())

    # Show file locations
    print()
    print(f"[+] Files saved to: {output_dir}/")
    print(f"    users.txt      - {len(users)} target users")
    if machines:
        print(f"    targets.txt    - {len(machines)} target machines")
    if passwords:
        print(f"    passwords.txt  - {len(passwords)} passwords")
        print(f"    spray.sh       - Executable spray script")

    return 0


def main():
    parser = create_parser()
    args = parser.parse_args()

    # Handle --list-edges
    if args.list_edges:
        list_edge_types()
        return 0

    # Handle query library commands (don't require bh_data_dir)
    if args.list_queries:
        return handle_list_queries(args)

    if args.search_query:
        return handle_search_queries(args)

    if args.run_query:
        return handle_run_query(args)

    if args.export_query:
        return handle_export_query(args)

    if args.install_queries:
        return handle_install_queries(args)

    if args.export_ce or args.export_ce_json:
        return handle_export_ce(args)

    # Handle --resume
    if args.resume:
        # Error if filepath also provided
        if args.bh_data_dir is not None:
            print("[!] Cannot use --resume with a data path")
            print("    Use --resume alone to work with existing Neo4j data")
            print("    Or provide a path without --resume to import new data")
            return 1
        return handle_resume(args)

    if args.run_all:
        return handle_run_all(args)

    # Handle pwned user tracking commands
    if args.pwn_interactive:
        config = Neo4jConfig(uri=args.uri, user=args.user, password=args.password)
        prefill_user = None

        while True:
            creds = interactive_pwn(config, prefill_user=prefill_user)
            if not creds:
                return 0  # User cancelled

            # Populate args and mark user as pwned
            args.pwn = creds["user"]
            args.cred_type = creds["cred_type"]
            args.cred_value = creds["cred_value"]
            args.source_machine = creds["source_machine"]
            args.pwn_notes = creds["notes"]
            handle_pwn_user(args)

            # Ask to continue
            print("\nAdd another credential?")
            print("  [Enter] Done")
            print("  [1] Same user (different cred)")
            print("  [2] Different user")
            choice = input("Choice [Enter]: ").strip()

            if choice == "1":
                prefill_user = creds["user"]  # Pre-fill same user
            elif choice == "2":
                prefill_user = None  # Fresh selection
            else:
                break  # Done

        return 0

    if args.pwn:
        return handle_pwn_user(args)

    if args.unpwn:
        return handle_unpwn_user(args)

    if args.list_pwned:
        return handle_list_pwned(args)

    if args.pwned_user:
        return handle_pwned_user_detail(args)

    if args.cred_targets:
        return handle_cred_targets(args)

    if args.post_exploit:
        return handle_post_exploit(args)

    if args.list_ip_addresses:
        return handle_list_ip_addresses(args)

    # Handle domain configuration commands
    if args.set_dc_ip:
        return handle_set_dc_ip(args)

    if args.domain_sid:
        return handle_domain_sid(args)

    # Store LHOST/LPORT when provided with --lhost flag only (not during report)
    if args.lhost and not (args.run_all or args.post_exploit):
        return handle_callback_config(args)

    if args.show_config:
        return handle_show_config(args)

    if args.clear_config:
        return handle_clear_config(args)

    if args.purge:
        return handle_purge(args)

    if args.discover_dc is not None:
        return handle_discover_dc(args)

    # Handle password policy commands
    if args.set_policy is not None:
        return handle_set_policy(args)

    if args.show_policy:
        return handle_show_policy(args)

    if args.clear_policy:
        return handle_clear_policy(args)

    # Handle password spray command
    if args.spray:
        return handle_spray(args)

    # Handle tailored spray command
    if args.spray_tailored:
        return handle_spray_tailored(args)

    # Handle auto-spray command
    if args.auto_spray:
        return handle_auto_spray(args)

    # Handle --dc-ip as standalone config setter (when no data directory provided)
    if args.dc_ip and (not hasattr(args, 'bh_data_dir') or args.bh_data_dir is None):
        return handle_dc_ip_standalone(args)

    # Edge enhancement requires bh_data_dir
    if not hasattr(args, 'bh_data_dir') or args.bh_data_dir is None:
        parser.print_help()
        return 0

    # Validate data source (directory or ZIP file)
    is_valid, message = is_valid_bloodhound_source(args.bh_data_dir)
    if not is_valid:
        print(f"[!] {message}")
        return 1

    # Create data source to get file count for display
    try:
        data_source = create_data_source(args.bh_data_dir)
        json_files = data_source.list_json_files()
        source_type = data_source.source_type
    except Exception as e:
        print(f"[!] Failed to read data source: {e}")
        return 1

    # Create config
    config = Neo4jConfig(
        uri=args.uri,
        user=args.user,
        password=args.password,
        batch_size=args.batch_size,
    )

    # Create enhancer
    enhancer = BHEnhancer(args.bh_data_dir, config)

    # Handle --validate
    if args.validate:
        print(f"[*] Validating BloodHound data in {args.bh_data_dir}...")
        summary = enhancer.validate(verbose=args.verbose)

        if "error" in summary:
            print(f"[!] {summary['error']}")
            return 1

        print(f"\n=== Validation Summary ===")
        print(f"Total edges:     {summary['total_edges']}")
        print(f"Edge types:      {len(summary['edges_by_type'])}")
        print(f"SIDs resolved:   {summary['resolver_stats']['cache_size']}")
        print(f"SIDs unresolved: {summary['resolver_stats']['unresolved']}")

        if args.verbose:
            print(f"\nEdges by type:")
            for etype, count in sorted(summary['edges_by_type'].items()):
                print(f"  {etype}: {count}")

            if summary['resolver_stats']['unresolved_sids']:
                print(f"\nUnresolved SIDs (first 10):")
                for sid in summary['resolver_stats']['unresolved_sids']:
                    print(f"  {sid}")

        return 0

    # Determine edge filter
    edge_filter = None
    preset = None

    if args.edges:
        edge_filter = set(args.edges.split(","))
        print(f"[*] Filtering to edge types: {', '.join(edge_filter)}")
    elif args.preset == "attack-paths":
        preset = "attack-paths"
    # else: preset=None means all edges

    # Run enhancement with colorized banner
    C = "\033[96m"  # Cyan
    G = "\033[92m"  # Green
    Y = "\033[93m"  # Yellow
    B = "\033[1m"   # Bold
    D = "\033[2m"   # Dim
    R = "\033[0m"   # Reset

    print()
    print(f"{C}{B}╔══════════════════════════════════════════════════════════════════════╗{R}")
    print(f"{C}{B}║{R}   {Y}🩸{R} {B}BloodHound Trail{R} - Edge Enhancement & Attack Path Discovery   {C}{B}║{R}")
    print(f"{C}{B}╚══════════════════════════════════════════════════════════════════════╝{R}")
    print()
    source_label = "ZIP file:" if source_type == "zip" else "Data directory:"
    print(f"  {D}{source_label:16}{R} {B}{args.bh_data_dir}{R}")
    print(f"  {D}Neo4j endpoint:{R}  {B}{args.uri}{R}")
    print(f"  {D}JSON files:{R}      {B}{len(json_files)}{R} files found")
    print()

    stats = enhancer.run(
        preset=preset,
        edge_filter=edge_filter,
        dry_run=args.dry_run,
        verbose=args.verbose,
        dc_ip=getattr(args, 'dc_ip', None),
        clean_ips=not getattr(args, 'update', False),  # True if --clean (default), False if --update
    )

    # Check if we should run the report
    # Run if: edges were processed (new or existed), not dry-run, not --no-report
    total_processed = stats.edges_imported + stats.edges_already_existed
    should_run_report = (
        total_processed > 0
        and not args.dry_run
        and not args.no_report
        and not stats.errors
    )

    if should_run_report:
        # Generate report - run all queries against the enhanced Neo4j database
        print()
        print(f"{C}{B}╔══════════════════════════════════════════════════════════════════════╗{R}")
        print(f"{C}{B}║{R}   {Y}📊{R} {B}Running Attack Path Queries{R} - Generating Report              {C}{B}║{R}")
        print(f"{C}{B}╚══════════════════════════════════════════════════════════════════════╝{R}")
        print()

        runner = QueryRunner(config)
        if runner.connect():
            try:
                # For ZIP files, put report next to ZIP; for directories, inside
                if args.report_path:
                    report_path = args.report_path
                elif source_type == "zip":
                    report_path = args.bh_data_dir.parent / "bloodtrail.md"
                else:
                    report_path = args.bh_data_dir / "bloodtrail.md"

                # Get DC IP from args (if provided) or from stored domain config
                dc_ip_for_report = getattr(args, 'dc_ip', None)
                if not dc_ip_for_report:
                    try:
                        tracker = PwnedTracker(config)
                        if tracker.connect():
                            domain_config = tracker.get_domain_config()
                            dc_ip_for_report = domain_config.get("dc_ip") if domain_config else None
                            tracker.close()
                    except Exception:
                        pass

                report_stats = run_all_queries(
                    runner,
                    output_path=report_path,
                    skip_variable_queries=True,
                    oscp_high_only=False,
                    verbose=args.verbose,
                    show_commands=getattr(args, 'commands', False),
                    show_data=getattr(args, 'data', False),
                    dc_ip=dc_ip_for_report,
                )

                # Final summary
                print(f"{C}{B}╔══════════════════════════════════════════════════════════════════════╗{R}")
                print(f"{C}{B}║{R}   {G}✓{R} {B}BloodHound Trail Complete{R}                                     {C}{B}║{R}")
                print(f"{C}{B}╚══════════════════════════════════════════════════════════════════════╝{R}")
                print()
                print(f"  {D}Edges processed:{R}    {B}{total_processed}{R} ({stats.edges_imported} new, {stats.edges_already_existed} existed)")
                print(f"  {D}Queries with hits:{R}  {B}{report_stats['with_results']}{R} / {report_stats['total_queries']}")
                print(f"  {D}Report saved:{R}       {B}{report_path}{R}")
                print()

                if report_stats['findings']:
                    high_findings = [f for f in report_stats['findings'] if f['relevance'] == 'high']
                    if high_findings:
                        print(f"  {G}{B}🎯 Top Attack Paths Discovered:{R}")
                        for f in sorted(high_findings, key=lambda x: -x['count'])[:5]:
                            print(f"     {Y}►{R} {f['query']}: {B}{f['count']}{R} results")
                        print()

            finally:
                runner.close()
        else:
            print(f"{Y}[!]{R} Could not connect to Neo4j for report generation")
            print(f"    Run manually: crack bloodtrail --run-all")

    elif args.dry_run:
        print(f"{D}[*] Dry run - skipping report generation{R}")
    elif args.no_report:
        print(f"{D}[*] Report generation skipped (--no-report){R}")
    elif total_processed == 0 and not stats.errors:
        # No edges processed but no errors either - weird state
        print(f"{Y}[!]{R} No edges were processed. Run with --verbose for details.")

    # Return code based on errors
    if stats.errors:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
