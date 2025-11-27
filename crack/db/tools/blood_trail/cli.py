#!/usr/bin/env python3
"""
BloodHound Trail - Command Line Interface

Usage:
    # Edge enhancement
    crack blood-trail /path/to/bh/json/
    crack blood-trail /path/to/bh/json/ --preset attack-paths
    crack blood-trail /path/to/bh/json/ --dry-run --verbose

    # Query library
    crack blood-trail --list-queries
    crack blood-trail --list-queries --category lateral_movement
    crack blood-trail --run-query lateral-adminto-nonpriv
    crack blood-trail --run-query owned-what-can-access --var USER=PETE@CORP.COM
    crack blood-trail --search-query DCSync
    crack blood-trail --export-query lateral-adminto-nonpriv

Credentials (defaults):
    - Neo4j: neo4j / Neo4j123
    - BloodHound: admin / 1PlaySmarter*
"""

import argparse
import json
import sys
from pathlib import Path

from .config import Neo4jConfig, ATTACK_PATH_EDGES
from .main import BHEnhancer
from .query_runner import (
    QueryRunner,
    print_query_info,
    export_to_bloodhound_customqueries,
    export_to_bloodhound_ce,
    run_all_queries,
)


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blood-trail",
        description="BloodHound Trail - Edge enhancement and Neo4j query analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Attack-path focused edges (recommended)
  crack blood-trail /path/to/bh/json/ --preset attack-paths

  # All supported edges
  crack blood-trail /path/to/bh/json/

  # Dry run (validate without importing)
  crack blood-trail /path/to/bh/json/ --dry-run --verbose

  # Specific edge types only
  crack blood-trail /path/to/bh/json/ --edges AdminTo,GenericAll,GetChanges

  # Custom Neo4j credentials
  crack blood-trail /path/to/bh/json/ --uri bolt://host:7687 --user neo4j --password pass

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
        help="Directory containing BloodHound JSON exports (required for edge enhancement)",
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
        help="Run all queries and generate blood-trail.md",
    )
    query_group.add_argument(
        "--report-path",
        type=Path,
        help="Custom path for report output (default: ./blood-trail.md)",
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

    try:
        stats = run_all_queries(
            runner,
            output_path=args.report_path,
            skip_variable_queries=True,
            oscp_high_only=high_only
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

    if args.run_all:
        return handle_run_all(args)

    # Edge enhancement requires bh_data_dir
    if not hasattr(args, 'bh_data_dir') or args.bh_data_dir is None:
        parser.print_help()
        return 0

    # Validate data directory
    if not args.bh_data_dir.exists():
        print(f"[!] Directory not found: {args.bh_data_dir}")
        return 1

    if not args.bh_data_dir.is_dir():
        print(f"[!] Not a directory: {args.bh_data_dir}")
        return 1

    # Check for JSON files
    json_files = list(args.bh_data_dir.glob("*.json"))
    if not json_files:
        print(f"[!] No JSON files found in: {args.bh_data_dir}")
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
    print(f"  {D}Data directory:{R}  {B}{args.bh_data_dir}{R}")
    print(f"  {D}Neo4j endpoint:{R}  {B}{args.uri}{R}")
    print(f"  {D}JSON files:{R}      {B}{len(json_files)}{R} files found")
    print()

    stats = enhancer.run(
        preset=preset,
        edge_filter=edge_filter,
        dry_run=args.dry_run,
        verbose=args.verbose,
    )

    # Return code based on errors
    if stats.errors:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
