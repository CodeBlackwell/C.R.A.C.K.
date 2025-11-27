"""
BloodHound Cypher Query Runner

Loads and executes queries from the cypher_queries/*.json library.
Supports variable substitution, result formatting, and query search.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import zipfile
import io
import uuid

from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError

from .config import Neo4jConfig


@dataclass
class Query:
    """Represents a single Cypher query from the library"""
    id: str
    name: str
    description: str
    cypher: str
    category: str
    variables: Dict[str, Dict] = field(default_factory=dict)
    edge_types_used: List[str] = field(default_factory=list)
    oscp_relevance: str = "medium"
    expected_results: str = ""
    example_output: str = ""
    next_steps: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def has_variables(self) -> bool:
        """Check if query requires variable substitution"""
        return bool(self.variables)

    def get_required_variables(self) -> List[str]:
        """Get list of required variable names"""
        return [
            name for name, info in self.variables.items()
            if info.get("required", True)
        ]

    def substitute_variables(self, values: Dict[str, str]) -> str:
        """
        Substitute placeholders in the query with provided values.

        Args:
            values: Dict mapping variable names to their values

        Returns:
            Query string with placeholders replaced
        """
        result = self.cypher
        for var_name, var_value in values.items():
            placeholder = f"<{var_name}>"
            result = result.replace(placeholder, var_value)
        return result


@dataclass
class QueryResult:
    """Result from executing a query"""
    query_id: str
    success: bool
    records: List[Dict] = field(default_factory=list)
    record_count: int = 0
    error: Optional[str] = None
    cypher_executed: str = ""
    suggestions: List[Any] = field(default_factory=list)  # CommandSuggestion or AttackSequence


class QueryRunner:
    """
    Runs Cypher queries from the BloodHound Trail query library.

    Example:
        runner = QueryRunner()
        runner.connect()

        # List queries
        queries = runner.list_queries(category="lateral_movement")

        # Run query with variables
        result = runner.run_query(
            "owned-what-can-access",
            {"USER": "PETE@CORP.COM"}
        )

        # Export query for BloodHound paste
        cypher = runner.export_query("lateral-adminto-nonpriv")
    """

    def __init__(self, neo4j_config: Optional[Neo4jConfig] = None):
        self.config = neo4j_config or Neo4jConfig()
        self.driver = None
        self._queries: Dict[str, Query] = {}
        self._categories: Dict[str, List[str]] = {}
        self._load_all_queries()

    def _get_queries_dir(self) -> Path:
        """Get path to cypher_queries directory"""
        return Path(__file__).parent / "cypher_queries"

    def _load_all_queries(self):
        """Load all queries from JSON files"""
        queries_dir = self._get_queries_dir()

        if not queries_dir.exists():
            return

        for json_file in queries_dir.glob("*.json"):
            if json_file.name == "schema.json":
                continue

            try:
                with open(json_file) as f:
                    data = json.load(f)

                category = data.get("category", json_file.stem)
                self._categories[category] = []

                for query_data in data.get("queries", []):
                    query = Query(
                        id=query_data["id"],
                        name=query_data["name"],
                        description=query_data["description"],
                        cypher=query_data["cypher"],
                        category=category,
                        variables=query_data.get("variables", {}),
                        edge_types_used=query_data.get("edge_types_used", []),
                        oscp_relevance=query_data.get("oscp_relevance", "medium"),
                        expected_results=query_data.get("expected_results", ""),
                        example_output=query_data.get("example_output", ""),
                        next_steps=query_data.get("next_steps", []),
                        tags=query_data.get("tags", []),
                    )
                    self._queries[query.id] = query
                    self._categories[category].append(query.id)

            except Exception as e:
                print(f"[!] Error loading {json_file}: {e}")

    def connect(self) -> bool:
        """Establish Neo4j connection"""
        try:
            self.driver = GraphDatabase.driver(
                self.config.uri,
                auth=(self.config.user, self.config.password)
            )
            # Test connection
            with self.driver.session() as session:
                session.run("RETURN 1")
            return True
        except AuthError:
            print(f"[!] Neo4j authentication failed (user: {self.config.user})")
            return False
        except ServiceUnavailable:
            print(f"[!] Neo4j not available at {self.config.uri}")
            return False
        except Exception as e:
            print(f"[!] Neo4j connection error: {e}")
            return False

    def close(self):
        """Close Neo4j connection"""
        if self.driver:
            self.driver.close()

    def list_queries(
        self,
        category: Optional[str] = None,
        oscp_relevance: Optional[str] = None,
        tag: Optional[str] = None
    ) -> List[Query]:
        """
        List available queries with optional filtering.

        Args:
            category: Filter by category (e.g., "lateral_movement")
            oscp_relevance: Filter by relevance ("high", "medium", "low")
            tag: Filter by tag (e.g., "OSCP:HIGH")

        Returns:
            List of matching Query objects
        """
        queries = list(self._queries.values())

        if category:
            queries = [q for q in queries if q.category == category]

        if oscp_relevance:
            queries = [q for q in queries if q.oscp_relevance == oscp_relevance]

        if tag:
            tag_lower = tag.lower()
            queries = [
                q for q in queries
                if any(tag_lower in t.lower() for t in q.tags)
            ]

        return queries

    def get_categories(self) -> List[str]:
        """Get list of all query categories"""
        return list(self._categories.keys())

    def get_query(self, query_id: str) -> Optional[Query]:
        """Get a specific query by ID"""
        return self._queries.get(query_id)

    def search_queries(self, keyword: str) -> List[Query]:
        """
        Search queries by keyword in name, description, or tags.

        Args:
            keyword: Search term

        Returns:
            List of matching Query objects
        """
        keyword_lower = keyword.lower()
        matches = []

        for query in self._queries.values():
            if (
                keyword_lower in query.name.lower()
                or keyword_lower in query.description.lower()
                or keyword_lower in query.id.lower()
                or any(keyword_lower in tag.lower() for tag in query.tags)
            ):
                matches.append(query)

        return matches

    def run_query(
        self,
        query_id: str,
        variables: Optional[Dict[str, str]] = None,
        limit: int = 100
    ) -> QueryResult:
        """
        Execute a query from the library.

        Args:
            query_id: Query ID (e.g., "lateral-adminto-nonpriv")
            variables: Dict of variable substitutions (e.g., {"USER": "PETE@CORP.COM"})
            limit: Maximum records to return

        Returns:
            QueryResult with records or error
        """
        query = self.get_query(query_id)
        if not query:
            return QueryResult(
                query_id=query_id,
                success=False,
                error=f"Query not found: {query_id}"
            )

        # Check required variables
        if query.has_variables():
            variables = variables or {}
            missing = [
                v for v in query.get_required_variables()
                if v not in variables
            ]
            if missing:
                return QueryResult(
                    query_id=query_id,
                    success=False,
                    error=f"Missing required variables: {', '.join(missing)}"
                )

        # Substitute variables
        cypher = query.cypher
        if variables:
            cypher = query.substitute_variables(variables)

        # Add LIMIT if not present
        if "LIMIT" not in cypher.upper():
            cypher = f"{cypher}\nLIMIT {limit}"

        # Connect if needed
        if not self.driver:
            if not self.connect():
                return QueryResult(
                    query_id=query_id,
                    success=False,
                    error="Failed to connect to Neo4j"
                )

        # Execute query
        try:
            with self.driver.session() as session:
                result = session.run(cypher)
                records = [dict(record) for record in result]

                return QueryResult(
                    query_id=query_id,
                    success=True,
                    records=records,
                    record_count=len(records),
                    cypher_executed=cypher
                )

        except Exception as e:
            return QueryResult(
                query_id=query_id,
                success=False,
                error=str(e),
                cypher_executed=cypher
            )

    def run_category(
        self,
        category: str,
        variables: Optional[Dict[str, str]] = None
    ) -> Dict[str, QueryResult]:
        """
        Run all queries in a category.

        Args:
            category: Category name (e.g., "quick_wins")
            variables: Shared variables for queries that need them

        Returns:
            Dict mapping query IDs to their results
        """
        results = {}
        query_ids = self._categories.get(category, [])

        for query_id in query_ids:
            query = self.get_query(query_id)
            if query and not query.has_variables():
                # Only run queries that don't need variables
                results[query_id] = self.run_query(query_id, variables)
            elif query and variables:
                # Run if variables provided
                results[query_id] = self.run_query(query_id, variables)

        return results

    def export_query(
        self,
        query_id: str,
        variables: Optional[Dict[str, str]] = None
    ) -> Optional[str]:
        """
        Export a query as raw Cypher for copy-paste into BloodHound.

        Args:
            query_id: Query ID
            variables: Optional variable substitutions

        Returns:
            Cypher query string or None if not found
        """
        query = self.get_query(query_id)
        if not query:
            return None

        cypher = query.cypher
        if variables:
            cypher = query.substitute_variables(variables)

        return cypher

    def format_results_table(self, result: QueryResult, max_width: int = 50) -> str:
        """
        Format query results as an ASCII table.

        Args:
            result: QueryResult to format
            max_width: Maximum column width

        Returns:
            Formatted table string
        """
        if not result.success:
            return f"Error: {result.error}"

        if not result.records:
            return "No results found"

        # Get column headers from first record
        headers = list(result.records[0].keys())

        # Calculate column widths
        widths = {}
        for h in headers:
            max_val_len = max(
                len(str(r.get(h, ""))[:max_width]) for r in result.records
            )
            widths[h] = min(
                max(len(str(h)), max_val_len),
                max_width
            )

        # Build table
        lines = []

        # Header
        header_line = " | ".join(h.ljust(widths[h])[:widths[h]] for h in headers)
        lines.append(header_line)
        lines.append("-" * len(header_line))

        # Rows
        for record in result.records:
            row = []
            for h in headers:
                val = str(record.get(h, ""))[:max_width]
                row.append(val.ljust(widths[h])[:widths[h]])
            lines.append(" | ".join(row))

        lines.append(f"\n({result.record_count} records)")

        return "\n".join(lines)


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


def run_all_queries(
    runner: 'QueryRunner',
    output_path: Optional[Path] = None,
    skip_variable_queries: bool = True,
    oscp_high_only: bool = False,
    verbose: bool = False
) -> dict:
    """
    Run all queries and generate colorized console output + markdown report.

    Args:
        runner: QueryRunner instance
        output_path: Path for markdown report (default: ./blood-trail.md)
        skip_variable_queries: Skip queries requiring variables (default: True)
        oscp_high_only: Only run OSCP:HIGH queries
        verbose: Show full query results in console (no truncation)

    Returns:
        Dict with summary statistics
    """
    from datetime import datetime

    # Initialize command suggester for attack recommendations
    try:
        from .command_suggester import CommandSuggester, CommandTable
        from .display_commands import (
            print_command_tables_by_phase,
            format_tables_markdown,
            get_table_stats,
        )
        suggester = CommandSuggester()
        suggestions_enabled = bool(suggester.commands)
    except ImportError:
        suggester = None
        suggestions_enabled = False

    queries = runner.list_queries()
    if oscp_high_only:
        queries = [q for q in queries if q.oscp_relevance == "high"]

    # Category display names
    cat_names = {
        "quick_wins": "Quick Wins",
        "lateral_movement": "Lateral Movement",
        "privilege_escalation": "Privilege Escalation",
        "attack_chains": "Attack Chains",
        "operational": "Operational",
        "owned_principal": "Owned Principal",
    }

    # Group queries by category
    by_category = {}
    for q in queries:
        if q.category not in by_category:
            by_category[q.category] = []
        by_category[q.category].append(q)

    # Results storage
    all_results = {}
    all_tables = []       # DRY command tables
    all_sequences = []    # attack sequences from chain queries
    stats = {
        "total_queries": 0,
        "successful": 0,
        "with_results": 0,
        "skipped": 0,
        "failed": 0,
        "findings": [],
        "tables_generated": 0,
        "total_targets": 0,
        "sequences_generated": 0,
    }

    # Markdown report
    report_lines = [
        "# BloodHound Enhanced Report",
        f"",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"",
        "---",
        "",
    ]

    # Print header
    print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*70}")
    print(f"  BLOODHOUND ENHANCED REPORT")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}{Colors.RESET}\n")

    # Process each category
    category_order = ["quick_wins", "lateral_movement", "privilege_escalation",
                      "attack_chains", "owned_principal", "operational"]

    for category in category_order:
        if category not in by_category:
            continue

        cat_queries = by_category[category]
        cat_display = cat_names.get(category, category.replace("_", " ").title())

        # Category header
        print(f"{Colors.BOLD}{Colors.CYAN}┌{'─'*68}┐")
        print(f"│  {cat_display.upper():64} │")
        print(f"└{'─'*68}┘{Colors.RESET}")

        report_lines.append(f"## {cat_display}")
        report_lines.append("")

        for query in cat_queries:
            stats["total_queries"] += 1

            # Skip variable queries if requested
            if skip_variable_queries and query.has_variables():
                stats["skipped"] += 1
                print(f"  {Colors.DIM}○ {query.name} (skipped - requires variables){Colors.RESET}")
                report_lines.append(f"### {query.name}")
                report_lines.append(f"*Skipped - requires variables: {', '.join(query.variables.keys())}*")
                report_lines.append("")
                continue

            # Run query
            result = runner.run_query(query.id)

            # Relevance indicator
            rel_color = Colors.RED if query.oscp_relevance == "high" else (
                Colors.YELLOW if query.oscp_relevance == "medium" else Colors.DIM
            )
            rel_badge = f"[{query.oscp_relevance.upper()}]"

            if result.success:
                stats["successful"] += 1
                all_results[query.id] = result

                if result.record_count > 0:
                    stats["with_results"] += 1
                    # Console output - has findings
                    print(f"  {Colors.GREEN}●{Colors.RESET} {rel_color}{rel_badge}{Colors.RESET} {Colors.BOLD}{query.name}{Colors.RESET}")
                    print(f"    {Colors.GREEN}└─ {result.record_count} results{Colors.RESET}")

                    # Verbose: show full table in console
                    if verbose and result.records:
                        headers = list(result.records[0].keys())
                        # Calculate column widths (no truncation in verbose)
                        widths = {h: len(h) for h in headers}
                        for record in result.records:
                            for h in headers:
                                widths[h] = max(widths[h], len(str(record.get(h, ""))))
                        # Print table
                        header_line = " | ".join(h.ljust(widths[h]) for h in headers)
                        print(f"    {Colors.DIM}{header_line}{Colors.RESET}")
                        print(f"    {Colors.DIM}{'-' * len(header_line)}{Colors.RESET}")
                        for record in result.records:
                            row = " | ".join(str(record.get(h, "")).ljust(widths[h]) for h in headers)
                            print(f"    {row}")
                        print()

                    # Generate attack command tables (DRY approach)
                    if suggestions_enabled and suggester:
                        # Build DRY command tables
                        tables = suggester.build_command_tables(query.id, result.records)
                        if tables:
                            all_tables.extend(tables)
                            stats["tables_generated"] += len(tables)
                            stats["total_targets"] += sum(len(t.targets) for t in tables)

                        # Also check for attack sequences (chain queries)
                        from .command_mappings import QUERY_COMMAND_MAPPINGS
                        mapping = QUERY_COMMAND_MAPPINGS.get(query.id)
                        if mapping == "BUILD_SEQUENCE":
                            sequences = suggester.suggest_for_query(query.id, result.records)
                            if sequences:
                                all_sequences.extend(sequences)
                                stats["sequences_generated"] += len(sequences)

                    # Add to findings
                    stats["findings"].append({
                        "query": query.name,
                        "category": cat_display,
                        "count": result.record_count,
                        "relevance": query.oscp_relevance
                    })

                    # Markdown (always full output in report)
                    report_lines.append(f"### ✅ {query.name}")
                    report_lines.append(f"**OSCP Relevance:** {query.oscp_relevance.upper()} | **Results:** {result.record_count}")
                    report_lines.append("")
                    report_lines.append(f"> {query.description}")
                    report_lines.append("")

                    # Format results as table (full output in markdown)
                    if result.records:
                        headers = list(result.records[0].keys())
                        report_lines.append("| " + " | ".join(headers) + " |")
                        report_lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
                        for record in result.records:
                            row = [str(record.get(h, "")).replace("|", "\\|") for h in headers]
                            report_lines.append("| " + " | ".join(row) + " |")
                    report_lines.append("")

                else:
                    # Console output - no findings
                    print(f"  {Colors.DIM}○ {rel_badge} {query.name} (no results){Colors.RESET}")

                    # Markdown
                    report_lines.append(f"### ⚪ {query.name}")
                    report_lines.append(f"**OSCP Relevance:** {query.oscp_relevance.upper()} | **Results:** None")
                    report_lines.append("")
            else:
                stats["failed"] += 1
                print(f"  {Colors.RED}✗ {rel_badge} {query.name} (failed: {result.error[:40]}){Colors.RESET}")
                report_lines.append(f"### ❌ {query.name}")
                report_lines.append(f"**Error:** {result.error}")
                report_lines.append("")

        print()  # Space between categories
        report_lines.append("---")
        report_lines.append("")

    # Summary
    print(f"{Colors.BOLD}{Colors.HEADER}{'='*70}")
    print(f"  SUMMARY")
    print(f"{'='*70}{Colors.RESET}")
    print(f"  {Colors.CYAN}Total Queries:{Colors.RESET}  {stats['total_queries']}")
    print(f"  {Colors.GREEN}With Results:{Colors.RESET}   {stats['with_results']}")
    print(f"  {Colors.DIM}No Results:{Colors.RESET}     {stats['successful'] - stats['with_results']}")
    print(f"  {Colors.YELLOW}Skipped:{Colors.RESET}        {stats['skipped']}")
    print(f"  {Colors.RED}Failed:{Colors.RESET}         {stats['failed']}")
    print()

    # Key findings
    if stats["findings"]:
        high_findings = [f for f in stats["findings"] if f["relevance"] == "high"]
        if high_findings:
            print(f"{Colors.BOLD}{Colors.RED}  KEY FINDINGS (OSCP:HIGH):{Colors.RESET}")
            for f in high_findings[:10]:
                print(f"    {Colors.RED}►{Colors.RESET} {f['query']}: {Colors.BOLD}{f['count']}{Colors.RESET} results")
            print()

    # Summary in report
    report_lines.append("## Summary")
    report_lines.append("")
    report_lines.append(f"| Metric | Count |")
    report_lines.append(f"| ------ | ----- |")
    report_lines.append(f"| Total Queries | {stats['total_queries']} |")
    report_lines.append(f"| With Results | {stats['with_results']} |")
    report_lines.append(f"| No Results | {stats['successful'] - stats['with_results']} |")
    report_lines.append(f"| Skipped | {stats['skipped']} |")
    report_lines.append(f"| Failed | {stats['failed']} |")
    report_lines.append("")

    if stats["findings"]:
        report_lines.append("### Key Findings")
        report_lines.append("")
        high_findings = [f for f in stats["findings"] if f["relevance"] == "high"]
        for f in sorted(high_findings, key=lambda x: -x["count"]):
            report_lines.append(f"- **{f['query']}**: {f['count']} results ({f['category']})")
        report_lines.append("")

    # Attack Commands Section (Console + Report) - DRY tabular output
    if all_tables or all_sequences:
        print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*70}")
        print(f"  ATTACK COMMANDS (DRY TABULAR FORMAT)")
        print(f"{'='*70}{Colors.RESET}")

        # Print DRY command tables grouped by phase
        if all_tables:
            print_command_tables_by_phase(all_tables, use_colors=True)

            # Add to report
            report_lines.append(format_tables_markdown(all_tables))

        # Attack Sequences (chain queries)
        if all_sequences:
            print(f"\n{Colors.BOLD}{Colors.HEADER}Multi-Step Attack Chains{Colors.RESET}")
            report_lines.append("### Multi-Step Attack Chains")
            report_lines.append("")

            for seq in all_sequences:
                print(f"  {Colors.BOLD}{Colors.HEADER}{seq.name}{Colors.RESET}")
                print(f"  {Colors.DIM}{seq.description}{Colors.RESET}")
                report_lines.append(f"#### {seq.name}")
                report_lines.append(f"*{seq.description}*")
                report_lines.append("")

                for i, step in enumerate(seq.steps, 1):
                    print(f"    {i}. {Colors.DIM}{step.template}{Colors.RESET}")
                    print(f"       {Colors.GREEN}{step.ready_to_run}{Colors.RESET}")
                    report_lines.append(f"{i}. **{step.context}**")
                    report_lines.append(f"   - Template: `{step.template}`")
                    report_lines.append(f"   - Ready: `{step.ready_to_run}`")
                report_lines.append("")
                print()

        # Stats
        table_stats = get_table_stats(all_tables) if all_tables else {}
        print(f"\n{Colors.DIM}Command tables: {stats['tables_generated']} | Targets: {stats['total_targets']}")
        print(f"Attack chains: {stats['sequences_generated']}{Colors.RESET}")
        print()

    # Write report
    if output_path is None:
        output_path = Path.cwd() / "blood-trail.md"
    else:
        output_path = Path(output_path)

    with open(output_path, "w") as f:
        f.write("\n".join(report_lines))

    print(f"{Colors.GREEN}Report saved:{Colors.RESET} {output_path}")
    print()

    return stats


def print_query_info(query: Query):
    """Print detailed information about a query"""
    print(f"\n{'='*60}")
    print(f"ID:          {query.id}")
    print(f"Name:        {query.name}")
    print(f"Category:    {query.category}")
    print(f"OSCP:        {query.oscp_relevance}")
    print(f"Description: {query.description[:100]}...")
    if query.variables:
        print(f"Variables:   {', '.join(query.variables.keys())}")
    if query.edge_types_used:
        print(f"Edges Used:  {', '.join(query.edge_types_used)}")
    print(f"Tags:        {', '.join(query.tags[:5])}")
    print(f"{'='*60}\n")


def export_to_bloodhound_customqueries(
    runner: 'QueryRunner',
    output_path: Optional[Path] = None,
    category_filter: Optional[str] = None,
    oscp_high_only: bool = False
) -> str:
    """
    Export queries to BloodHound Legacy customqueries.json format.

    Args:
        runner: QueryRunner instance with loaded queries
        output_path: Path to save customqueries.json (default: ~/.config/bloodhound/)
        category_filter: Only export queries from this category
        oscp_high_only: Only export OSCP:HIGH queries

    Returns:
        Path where file was saved
    """
    queries = runner.list_queries(category=category_filter)

    if oscp_high_only:
        queries = [q for q in queries if q.oscp_relevance == "high"]

    # Group by category for BloodHound UI organization
    bh_queries = []

    # Map internal categories to BloodHound display names
    category_display = {
        "lateral_movement": "Lateral Movement",
        "quick_wins": "Quick Wins",
        "privilege_escalation": "Privilege Escalation",
        "attack_chains": "Attack Chains",
        "operational": "Operational",
        "owned_principal": "Owned Principal",
    }

    for query in queries:
        # Convert to BloodHound format
        # Use "[CRACK]" prefix to group all our queries together in BH sidebar
        display_cat = category_display.get(query.category, query.category.replace("_", " ").title())
        bh_query = {
            "name": f"[{query.oscp_relevance.upper()}] {query.name}",
            "category": f"[CRACK] {display_cat}",
            "queryList": []
        }

        # Handle queries with variables - create selection step
        if query.has_variables():
            for var_name, var_info in query.variables.items():
                # Add variable selection step
                var_type = "User" if "user" in var_name.lower() else "Computer"
                selection_query = f"MATCH (n:{var_type}) WHERE n.enabled = true RETURN n.name ORDER BY n.name"

                bh_query["queryList"].append({
                    "final": False,
                    "title": f"Select {var_info.get('description', var_name)}",
                    "query": selection_query
                })

            # Final query with $result substitution (for single variable)
            # BloodHound uses $result for the selected value
            final_cypher = query.cypher
            for var_name in query.variables.keys():
                final_cypher = final_cypher.replace(f"<{var_name}>", "$result")

            bh_query["queryList"].append({
                "final": True,
                "query": final_cypher,
                "allowCollapse": True
            })
        else:
            # Simple query without variables
            bh_query["queryList"].append({
                "final": True,
                "query": query.cypher,
                "allowCollapse": True
            })

        bh_queries.append(bh_query)

    # Build final structure
    output = {"queries": bh_queries}

    # Determine output path
    if output_path is None:
        output_path = Path.home() / ".config" / "bloodhound" / "customqueries.json"

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Check for existing file and merge
    if output_path.exists():
        try:
            with open(output_path) as f:
                existing = json.load(f)
            # Remove old CRACK queries, keep user's custom queries
            existing_queries = [
                q for q in existing.get("queries", [])
                if not q.get("category", "").startswith("[CRACK]")
                and not q.get("category", "").startswith("blood_trail/")  # Legacy cleanup
            ]
            output["queries"] = existing_queries + bh_queries
            print(f"[*] Merged with existing {len(existing_queries)} custom queries")
        except Exception:
            pass  # Overwrite if can't parse

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    return str(output_path)


def export_to_bloodhound_ce(
    runner: 'QueryRunner',
    output_path: Optional[Path] = None,
    category_filter: Optional[str] = None,
    oscp_high_only: bool = False,
    create_zip: bool = True
) -> str:
    """
    Export queries to BloodHound CE format (JSON array or ZIP).

    BloodHound CE requires this schema (from SpecterOps Query Library):
    {
        "name": "Query Name",
        "guid": "UUID",
        "prebuilt": false,
        "platforms": ["Active Directory"],
        "category": "Category",
        "description": "Description",
        "query": "MATCH...",
        "revision": 1,
        "resources": [],
        "acknowledgements": []
    }

    Can be uploaded via: Explore > Cypher > Saved Queries > drag-and-drop

    Args:
        runner: QueryRunner instance with loaded queries
        output_path: Path to save file (default: ./crack_queries.zip or .json)
        category_filter: Only export queries from this category
        oscp_high_only: Only export OSCP:HIGH queries
        create_zip: Create ZIP file for easier upload (default: True)

    Returns:
        Path where file was saved
    """
    queries = runner.list_queries(category=category_filter)

    if oscp_high_only:
        queries = [q for q in queries if q.oscp_relevance == "high"]

    # Short category codes for concise naming
    category_short = {
        "lateral_movement": "LM",
        "quick_wins": "QW",
        "privilege_escalation": "PE",
        "attack_chains": "AC",
        "operational": "OP",
        "owned_principal": "OWN",
    }

    # Short relevance codes
    relevance_short = {"high": "H", "medium": "M", "low": "L"}

    # Build BloodHound CE format (simple: query, name, description)
    ce_queries = []

    for query in queries:
        cat_code = category_short.get(query.category, query.category[:3].upper())
        rel_code = relevance_short.get(query.oscp_relevance, "M")

        # Concise name: [CAT:REL] Query Name
        if query.has_variables():
            var_hint = ",".join(query.variables.keys())
            name = f"[{cat_code}:{rel_code}] {query.name} <{var_hint}>"
        else:
            name = f"[{cat_code}:{rel_code}] {query.name}"

        ce_queries.append({
            "query": query.cypher,
            "name": name,
            "description": query.description
        })

    # Determine output path
    if output_path is None:
        ext = ".zip" if create_zip else ".json"
        output_path = Path.cwd() / f"crack_queries{ext}"
    else:
        output_path = Path(output_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    if create_zip:
        # Create ZIP with individual JSON files (one query per file)
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for i, q in enumerate(ce_queries):
                # Create safe filename from query name
                safe_name = q["name"][:60].replace("/", "-").replace("\\", "-")
                safe_name = re.sub(r'[<>:"|?*\[\]]', '', safe_name).strip()
                filename = f"{i+1:02d}_{safe_name}.json"

                # Write single query object (not array)
                json_content = json.dumps(q, indent=2)
                zf.writestr(filename, json_content)
    else:
        # Write as array for non-zip (backwards compat)
        with open(output_path, "w") as f:
            json.dump(ce_queries, f, indent=2)

    return str(output_path)
