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


# =============================================================================
# TIMESTAMP FORMATTING HELPERS
# =============================================================================

# Field names that contain timestamps (case-insensitive matching)
TIMESTAMP_FIELDS = {
    'passwordlastset', 'pwdlastset', 'lastlogon', 'lastlogontimestamp',
    'lastlogoff', 'whencreated', 'whenchanged', 'accountexpires',
    'badpasswordtime', 'lastpasswordset', 'pwdlastchange'
}


def format_timestamp_ago(timestamp: Any) -> str:
    """
    Convert a timestamp to human-readable "X time ago" format.

    Args:
        timestamp: Unix epoch in seconds or milliseconds, or None/0

    Returns:
        Human-readable string like "3 months ago" or "Never"
    """
    if timestamp is None or timestamp == 0 or timestamp == -1:
        return "Never"

    try:
        ts = int(timestamp)
    except (ValueError, TypeError):
        return str(timestamp)

    # BloodHound timestamps can be in milliseconds or seconds
    # If > year 3000 in seconds, it's probably milliseconds
    if ts > 32503680000:  # Year 3000 in seconds
        ts = ts // 1000

    # Handle Windows FILETIME (100-nanosecond intervals since 1601)
    # These are huge numbers > 100000000000000
    if ts > 100000000000000:
        # Convert FILETIME to Unix timestamp
        ts = (ts // 10000000) - 11644473600

    from datetime import datetime
    try:
        dt = datetime.fromtimestamp(ts)
        now = datetime.now()
        delta = now - dt

        seconds = int(delta.total_seconds())
        if seconds < 0:
            return "In the future"
        if seconds < 60:
            return f"{seconds} seconds ago"
        if seconds < 3600:
            mins = seconds // 60
            return f"{mins} minute{'s' if mins != 1 else ''} ago"
        if seconds < 86400:
            hours = seconds // 3600
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        if seconds < 2592000:  # 30 days
            days = seconds // 86400
            return f"{days} day{'s' if days != 1 else ''} ago"
        if seconds < 31536000:  # 365 days
            months = seconds // 2592000
            return f"{months} month{'s' if months != 1 else ''} ago"

        years = seconds // 31536000
        return f"{years} year{'s' if years != 1 else ''} ago"
    except (ValueError, OSError, OverflowError):
        return str(timestamp)


def is_timestamp_field(field_name: str) -> bool:
    """Check if a field name represents a timestamp."""
    return field_name.lower().replace('_', '') in TIMESTAMP_FIELDS


# =============================================================================
# NEO4J PATH FORMATTING
# =============================================================================

def is_neo4j_path(value: Any) -> bool:
    """Check if value is a Neo4j Path object."""
    # Check by type name since we may not have the exact import
    type_name = type(value).__name__
    return type_name == 'Path' or 'graph.Path' in str(type(value))


def get_node_name(node: Any) -> str:
    """Extract readable name from Neo4j Node object."""
    # Try common name properties in order of preference
    for prop in ['name', 'samaccountname', 'distinguishedname']:
        try:
            val = node.get(prop) or node.get(prop.upper())
            if val:
                return str(val)
        except (AttributeError, TypeError):
            pass
    # Fallback: try to get labels
    try:
        labels = list(node.labels) if hasattr(node, 'labels') else []
        if labels:
            return f"[{':'.join(labels)}]"
    except:
        pass
    return "<?>"


def format_neo4j_path(path: Any) -> Dict[str, Any]:
    """
    Parse a Neo4j Path object into structured data.

    Returns:
        {
            'start': str,       # Start node name
            'end': str,         # End node name
            'hops': int,        # Number of relationships
            'nodes': [str],     # All node names in order
            'edges': [str],     # All relationship types in order
            'steps': [(node, edge, node), ...]  # Step-by-step breakdown
        }
    """
    try:
        nodes = list(path.nodes)
        rels = list(path.relationships)

        node_names = [get_node_name(n) for n in nodes]
        edge_types = [r.type for r in rels]

        # Build steps: (from_node, edge, to_node)
        steps = []
        for i, rel in enumerate(rels):
            steps.append({
                'from': node_names[i],
                'edge': edge_types[i],
                'to': node_names[i + 1]
            })

        return {
            'start': node_names[0] if node_names else '?',
            'end': node_names[-1] if node_names else '?',
            'hops': len(rels),
            'nodes': node_names,
            'edges': edge_types,
            'steps': steps
        }
    except Exception as e:
        return {
            'start': '?',
            'end': '?',
            'hops': 0,
            'nodes': [],
            'edges': [],
            'steps': [],
            'error': str(e)
        }


def format_path_oneline(path: Any) -> str:
    """Format path as single-line summary for tables."""
    parsed = format_neo4j_path(path)
    if parsed.get('error'):
        return str(path)[:50]

    # Short format: START -[E1,E2,E3]-> END (N hops)
    edges_str = ','.join(parsed['edges'][:5])
    if len(parsed['edges']) > 5:
        edges_str += '...'
    return f"{parsed['start']} -[{edges_str}]-> {parsed['end']} ({parsed['hops']} hops)"


def print_attack_paths(
    records: List[Dict],
    query_name: str = "Attack Paths",
    use_colors: bool = True,
    max_paths: int = 10
) -> None:
    """
    Print attack paths in a visual, digestible format.

    Displays each path as a chain showing:
    - Start and end nodes
    - Each hop with edge type
    - Total hop count

    Args:
        records: Query results containing path objects
        query_name: Display name for the section header
        use_colors: Enable ANSI colors
        max_paths: Maximum number of paths to display
    """
    # Find path column(s)
    if not records:
        return

    path_columns = []
    for key, val in records[0].items():
        if is_neo4j_path(val):
            path_columns.append(key)

    if not path_columns:
        return  # No path objects found

    # Color setup
    if use_colors:
        BOLD = '\033[1m'
        DIM = '\033[2m'
        CYAN = '\033[96m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        RED = '\033[91m'
        RESET = '\033[0m'
    else:
        BOLD = DIM = CYAN = GREEN = YELLOW = RED = RESET = ''

    # Group paths by destination for deduplication summary
    paths_by_dest = {}
    all_parsed = []

    for record in records:
        for col in path_columns:
            path_obj = record.get(col)
            if path_obj and is_neo4j_path(path_obj):
                parsed = format_neo4j_path(path_obj)
                if not parsed.get('error'):
                    all_parsed.append(parsed)
                    dest = parsed['end']
                    if dest not in paths_by_dest:
                        paths_by_dest[dest] = []
                    paths_by_dest[dest].append(parsed)

    if not all_parsed:
        return

    # Print summary header
    unique_starts = len(set(p['start'] for p in all_parsed))
    unique_ends = len(set(p['end'] for p in all_parsed))
    print(f"\n  {BOLD}Found {len(all_parsed)} path(s){RESET}")
    print(f"  {DIM}From {unique_starts} user(s) to {unique_ends} target(s){RESET}")
    print()

    # Print each path visually
    displayed = 0
    for i, parsed in enumerate(all_parsed[:max_paths], 1):
        hops = parsed['hops']
        start = parsed['start']
        end = parsed['end']

        # Path header
        print(f"  {BOLD}{CYAN}Path {i}{RESET}: {GREEN}{start}{RESET} → {RED}{end}{RESET} ({hops} hop{'s' if hops != 1 else ''})")

        # Show each step
        for step in parsed['steps']:
            edge = step['edge']
            to_node = step['to']
            # Colorize edge types
            if edge in ('MemberOf',):
                edge_color = DIM
            elif edge in ('AdminTo', 'CanRDP', 'CanPSRemote'):
                edge_color = GREEN
            elif edge in ('GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'ForceChangePassword'):
                edge_color = RED
            elif edge in ('HasSession',):
                edge_color = YELLOW
            else:
                edge_color = CYAN

            print(f"      ↓ {edge_color}[{edge}]{RESET}")
            print(f"      {to_node}")

        print()  # Space between paths
        displayed += 1

    # Truncation notice
    if len(all_parsed) > max_paths:
        remaining = len(all_parsed) - max_paths
        print(f"  {DIM}... and {remaining} more path(s){RESET}")
        print()

    # Quick reference: paths grouped by start user
    paths_by_start = {}
    for p in all_parsed:
        start = p['start']
        if start not in paths_by_start:
            paths_by_start[start] = []
        paths_by_start[start].append(p)

    if len(paths_by_start) > 1:
        print(f"  {BOLD}Summary by Starting User:{RESET}")
        for start, paths in sorted(paths_by_start.items(), key=lambda x: -len(x[1])):
            targets = set(p['end'] for p in paths)
            min_hops = min(p['hops'] for p in paths)
            print(f"    {YELLOW}►{RESET} {start}: {len(paths)} path(s), min {min_hops} hops → {', '.join(list(targets)[:3])}")
        print()


def has_path_results(records: List[Dict]) -> bool:
    """Check if query results contain Neo4j Path objects."""
    if not records:
        return False
    for key, val in records[0].items():
        if is_neo4j_path(val):
            return True
    return False


def format_field_value(field_name: str, value: Any) -> str:
    """Format a field value, applying timestamp/path formatting if appropriate."""
    if value is None:
        return ""
    if is_timestamp_field(field_name):
        return format_timestamp_ago(value)
    if is_neo4j_path(value):
        return format_path_oneline(value)
    return str(value)


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
        self._pwned_users_cache: Optional[set] = None
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

    def get_pwned_users(self, force_refresh: bool = False) -> set:
        """
        Get set of pwned user names for highlighting.

        Returns:
            Set of user principal names that are marked as pwned
        """
        if self._pwned_users_cache is not None and not force_refresh:
            return self._pwned_users_cache

        if not self.driver:
            return set()

        try:
            with self.driver.session() as session:
                result = session.run(
                    "MATCH (u:User) WHERE u.pwned = true RETURN u.name AS name"
                )
                self._pwned_users_cache = {r["name"] for r in result if r["name"]}
        except Exception:
            self._pwned_users_cache = set()

        return self._pwned_users_cache

    def get_inventory(self) -> Dict[str, Any]:
        """
        Get BloodHound data inventory summary.

        Returns dict with counts and samples of:
        - domains, users, computers, groups
        - key relationships (AdminTo, CanRDP, etc.)
        """
        if not self.driver:
            return {}

        inventory = {
            "domains": [],
            "users": {"count": 0, "enabled": 0, "samples": []},
            "computers": {"count": 0, "samples": []},
            "groups": {"count": 0, "samples": []},
            "relationships": {},
        }

        try:
            with self.driver.session() as session:
                # Domains
                result = session.run(
                    "MATCH (d:Domain) RETURN d.name as name ORDER BY d.name"
                )
                inventory["domains"] = [r["name"] for r in result]

                # Users
                result = session.run("""
                    MATCH (u:User)
                    RETURN count(u) as total,
                           sum(CASE WHEN u.enabled = true THEN 1 ELSE 0 END) as enabled
                """)
                row = result.single()
                if row:
                    inventory["users"]["count"] = row["total"]
                    inventory["users"]["enabled"] = row["enabled"]

                # User samples (enabled, high value first)
                result = session.run("""
                    MATCH (u:User)
                    WHERE u.enabled = true
                    RETURN u.name as name, u.admincount as admincount
                    ORDER BY u.admincount DESC, u.name
                    LIMIT 10
                """)
                inventory["users"]["samples"] = [r["name"] for r in result]

                # Computers
                result = session.run("MATCH (c:Computer) RETURN count(c) as total")
                row = result.single()
                if row:
                    inventory["computers"]["count"] = row["total"]

                result = session.run("""
                    MATCH (c:Computer)
                    RETURN c.name as name
                    ORDER BY c.name
                    LIMIT 10
                """)
                inventory["computers"]["samples"] = [r["name"] for r in result]

                # Groups
                result = session.run("MATCH (g:Group) RETURN count(g) as total")
                row = result.single()
                if row:
                    inventory["groups"]["count"] = row["total"]

                result = session.run("""
                    MATCH (g:Group)
                    WHERE g.highvalue = true OR g.name CONTAINS 'ADMIN'
                    RETURN g.name as name
                    ORDER BY g.name
                    LIMIT 10
                """)
                inventory["groups"]["samples"] = [r["name"] for r in result]

                # Key relationships
                rel_queries = {
                    "AdminTo": "MATCH ()-[r:AdminTo]->() RETURN count(r) as c",
                    "CanRDP": "MATCH ()-[r:CanRDP]->() RETURN count(r) as c",
                    "CanPSRemote": "MATCH ()-[r:CanPSRemote]->() RETURN count(r) as c",
                    "HasSession": "MATCH ()-[r:HasSession]->() RETURN count(r) as c",
                    "MemberOf": "MATCH ()-[r:MemberOf]->() RETURN count(r) as c",
                    "GenericAll": "MATCH ()-[r:GenericAll]->() RETURN count(r) as c",
                    "WriteDacl": "MATCH ()-[r:WriteDacl]->() RETURN count(r) as c",
                    "DCSync": "MATCH (n)-[:GetChanges|GetChangesAll]->() RETURN count(DISTINCT n) as c",
                }
                for rel_type, query in rel_queries.items():
                    try:
                        result = session.run(query)
                        row = result.single()
                        if row and row["c"] > 0:
                            inventory["relationships"][rel_type] = row["c"]
                    except:
                        pass

        except Exception as e:
            inventory["error"] = str(e)

        return inventory

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

    def format_results_table(
        self,
        result: QueryResult,
        max_width: int = 50,
        highlight_pwned: bool = True
    ) -> str:
        """
        Format query results as an ASCII table with optional pwned user highlighting.

        Args:
            result: QueryResult to format
            max_width: Maximum column width
            highlight_pwned: If True, highlight pwned users in green

        Returns:
            Formatted table string
        """
        if not result.success:
            return f"Error: {result.error}"

        if not result.records:
            return "No results found"

        # Get pwned users for highlighting
        pwned_users = self.get_pwned_users() if highlight_pwned else set()

        # ANSI codes for highlighting
        GREEN = '\033[92m'
        BOLD = '\033[1m'
        RESET = '\033[0m'
        PWNED_MARKER = f"{GREEN}{BOLD}[P]{RESET} "

        # User-related column names (case-insensitive match)
        USER_COLUMNS = {
            'user', 'users', 'attacker', 'victim', 'target', 'principal',
            'pwneduser', 'pwnedwithaccess', 'newtargetusers', 'victimsession',
            'highvaluetarget', 'serviceaccount', 'member', 'gmsaaccount'
        }

        # Get column headers from first record
        headers = list(result.records[0].keys())

        # Identify user columns
        user_header_indices = {
            h for h in headers if h.lower() in USER_COLUMNS
        }

        # Pre-format all values (applies timestamp formatting)
        formatted_records = []
        for record in result.records:
            formatted = {}
            for h in headers:
                val = format_field_value(h, record.get(h, ""))
                formatted[h] = val
            formatted_records.append(formatted)

        # Calculate column widths using formatted values (without ANSI codes)
        widths = {}
        for h in headers:
            max_val_len = max(
                len(formatted[h][:max_width]) for formatted in formatted_records
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

        # Rows with pwned highlighting
        pwned_count = 0
        for formatted in formatted_records:
            row = []
            for h in headers:
                val = formatted[h][:max_width]
                display_val = val.ljust(widths[h])[:widths[h]]

                # Highlight if this is a user column and user is pwned
                if h in user_header_indices and val in pwned_users:
                    display_val = f"{GREEN}{display_val}{RESET}"
                    pwned_count += 1

                row.append(display_val)
            lines.append(" | ".join(row))

        # Footer with pwned indicator if any found
        footer = f"\n({result.record_count} records)"
        if pwned_count > 0:
            footer += f" | {GREEN}{BOLD}{pwned_count} pwned user(s) highlighted{RESET}"
        lines.append(footer)

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
    verbose: bool = False,
    show_commands: bool = False,
    show_data: bool = False,
    dc_ip: Optional[str] = None,
) -> dict:
    """
    Run all queries and generate colorized console output + markdown report.

    Args:
        runner: QueryRunner instance
        output_path: Path for markdown report (default: ./bloodtrail.md)
        skip_variable_queries: Skip queries requiring variables (default: True)
        oscp_high_only: Only run OSCP:HIGH queries
        verbose: Show full query results in console (no truncation)
        show_commands: Only show command suggestions in console (-c flag)
        show_data: Only show raw query data in console (-d flag)
        dc_ip: Domain Controller IP (for <DC_IP> placeholder - retrieved from Neo4j)

    Returns:
        Dict with summary statistics
    """
    # Determine what to show in console (default: both)
    # If neither flag set, show everything
    # If one flag set, show only that section
    show_all = not show_commands and not show_data
    from datetime import datetime

    # Initialize command suggester for attack recommendations
    try:
        from .command_suggester import CommandSuggester, CommandTable
        from .display_commands import (
            print_command_tables_by_phase,
            print_post_success,
            format_tables_markdown,
            get_table_stats,
        )
        suggester = CommandSuggester()
        suggestions_enabled = bool(suggester.commands)
    except ImportError:
        suggester = None
        suggestions_enabled = False

    # Fetch pwned users for credential auto-fill
    pwned_lookup = {}
    try:
        from .pwned_tracker import PwnedTracker
        tracker = PwnedTracker(runner.config)
        if tracker.connect():
            for u in tracker.list_pwned_users():
                pwned_lookup[u.name.upper()] = u
            tracker.close()
    except Exception:
        pass  # Continue without pwned user credentials

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

    # Print header (always show if any console output)
    if show_all or show_commands or show_data:
        print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*70}")
        print(f"  BLOODHOUND ENHANCED REPORT")
        print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}{Colors.RESET}\n")

    # Get and display inventory
    inventory = runner.get_inventory()
    if inventory and not inventory.get("error"):
        # Console output (only if showing data or all)
        if show_all or show_data:
            print(f"{Colors.BOLD}{Colors.CYAN}┌{'─'*68}┐")
            print(f"│  {'DATA INVENTORY':64} │")
            print(f"└{'─'*68}┘{Colors.RESET}")

            # Domain info
            if inventory["domains"]:
                print(f"  {Colors.BOLD}Domains:{Colors.RESET} {', '.join(inventory['domains'])}")

            # Counts table
            u = inventory["users"]
            c = inventory["computers"]
            g = inventory["groups"]
            print(f"\n  {Colors.BOLD}{'Type':<12} {'Count':>8}  {'Details':<45}{Colors.RESET}")
            print(f"  {'-'*12} {'-'*8}  {'-'*45}")
            print(f"  {'Users':<12} {u['count']:>8}  {Colors.GREEN}{u['enabled']} enabled{Colors.RESET}")
            print(f"  {'Computers':<12} {c['count']:>8}  {', '.join(c['samples'][:3]) if c['samples'] else '-'}")
            print(f"  {'Groups':<12} {g['count']:>8}  {', '.join(g['samples'][:3]) if g['samples'] else '-'}")

            # Relationships
            rels = inventory.get("relationships", {})
            if rels:
                print(f"\n  {Colors.BOLD}Relationships:{Colors.RESET}")
                rel_items = [f"{k}: {v}" for k, v in sorted(rels.items(), key=lambda x: -x[1])]
                print(f"  {Colors.DIM}{' | '.join(rel_items)}{Colors.RESET}")

            # User samples
            if u["samples"]:
                print(f"\n  {Colors.BOLD}Key Users:{Colors.RESET}")
                for user in u["samples"][:5]:
                    print(f"    {Colors.YELLOW}►{Colors.RESET} {user}")

            # Computer samples
            if c["samples"]:
                print(f"\n  {Colors.BOLD}Computers:{Colors.RESET}")
                for comp in c["samples"][:5]:
                    print(f"    {Colors.CYAN}►{Colors.RESET} {comp}")

            print()
        else:
            # Need these for report even if not printing
            u = inventory["users"]
            c = inventory["computers"]
            g = inventory["groups"]
            rels = inventory.get("relationships", {})
            rel_items = [f"{k}: {v}" for k, v in sorted(rels.items(), key=lambda x: -x[1])] if rels else []

        # Add to report (always)
        report_lines.append("## Data Inventory")
        report_lines.append("")
        report_lines.append(f"**Domains:** {', '.join(inventory['domains'])}")
        report_lines.append("")
        report_lines.append("| Type | Count | Details |")
        report_lines.append("|------|-------|---------|")
        report_lines.append(f"| Users | {u['count']} | {u['enabled']} enabled |")
        report_lines.append(f"| Computers | {c['count']} | {', '.join(c['samples'][:3]) if c['samples'] else '-'} |")
        report_lines.append(f"| Groups | {g['count']} | {', '.join(g['samples'][:3]) if g['samples'] else '-'} |")
        report_lines.append("")
        if rels:
            report_lines.append(f"**Relationships:** {' | '.join(rel_items)}")
            report_lines.append("")

    # =========================================================================
    # PHASE 1: Run all queries and collect results (no printing yet)
    # =========================================================================
    category_order = ["quick_wins", "lateral_movement", "privilege_escalation",
                      "attack_chains", "owned_principal", "operational"]

    # Storage for deferred output
    category_outputs = {}  # category -> list of (query, result, status) tuples

    for category in category_order:
        if category not in by_category:
            continue

        cat_queries = by_category[category]
        cat_display = cat_names.get(category, category.replace("_", " ").title())
        category_outputs[category] = {"display": cat_display, "queries": []}

        for query in cat_queries:
            stats["total_queries"] += 1

            # Skip variable queries if requested
            if skip_variable_queries and query.has_variables():
                stats["skipped"] += 1
                category_outputs[category]["queries"].append({
                    "query": query, "result": None, "status": "skipped"
                })
                continue

            # Run query
            result = runner.run_query(query.id)

            if result.success:
                stats["successful"] += 1
                all_results[query.id] = result

                if result.record_count > 0:
                    stats["with_results"] += 1

                    # Generate attack command tables (DRY approach)
                    if suggestions_enabled and suggester:
                        tables = suggester.build_command_tables(query.id, result.records, pwned_users=pwned_lookup, dc_ip=dc_ip)
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

                    category_outputs[category]["queries"].append({
                        "query": query, "result": result, "status": "results"
                    })
                else:
                    category_outputs[category]["queries"].append({
                        "query": query, "result": result, "status": "no_results"
                    })
            else:
                stats["failed"] += 1
                category_outputs[category]["queries"].append({
                    "query": query, "result": result, "status": "failed"
                })

    # =========================================================================
    # PHASE 2: Print ATTACK COMMANDS first (actionable items at top)
    # =========================================================================
    if all_tables or all_sequences:
        # Console output (only if showing commands or all)
        if show_all or show_commands:
            print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*70}")
            print(f"  ATTACK COMMANDS")
            print(f"{'='*70}{Colors.RESET}")

            # Print DRY command tables grouped by phase
            if all_tables:
                print_command_tables_by_phase(all_tables, use_colors=True)

                # Print post-success suggestions for tables that have them
                for table in all_tables:
                    if table.post_success and table.targets:
                        domain = table.targets[0].domain if table.targets else ""
                        print_post_success(table.post_success, domain=domain, use_colors=True)

            # Attack Sequences (chain queries)
            if all_sequences:
                print(f"\n{Colors.BOLD}{Colors.HEADER}Multi-Step Attack Chains{Colors.RESET}")
                for seq in all_sequences:
                    print(f"  {Colors.BOLD}{Colors.HEADER}{seq.name}{Colors.RESET}")
                    print(f"  {Colors.DIM}{seq.description}{Colors.RESET}")
                    for i, step in enumerate(seq.steps, 1):
                        print(f"    {i}. {Colors.DIM}{step.template}{Colors.RESET}")
                        print(f"       {Colors.GREEN}{step.ready_to_run}{Colors.RESET}")
                    print()

            # Stats
            print(f"\n{Colors.DIM}Command tables: {stats['tables_generated']} | Targets: {stats['total_targets']}")
            print(f"Attack chains: {stats['sequences_generated']}{Colors.RESET}")
            print()

        # Add to report (always)
        if all_tables:
            report_lines.append("## Attack Commands")
            report_lines.append("")
            report_lines.append(format_tables_markdown(all_tables))

        if all_sequences:
            report_lines.append("### Multi-Step Attack Chains")
            report_lines.append("")
            for seq in all_sequences:
                report_lines.append(f"#### {seq.name}")
                report_lines.append(f"*{seq.description}*")
                report_lines.append("")
                for i, step in enumerate(seq.steps, 1):
                    report_lines.append(f"{i}. **{step.context}**")
                    report_lines.append(f"   - Template: `{step.template}`")
                    report_lines.append(f"   - Ready: `{step.ready_to_run}`")
                report_lines.append("")

        report_lines.append("---")
        report_lines.append("")

    # =========================================================================
    # PHASE 3: Print query results (raw data at bottom)
    # =========================================================================
    if show_all or show_data:
        print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*70}")
        print(f"  QUERY RESULTS (RAW DATA)")
        print(f"{'='*70}{Colors.RESET}\n")

    for category in category_order:
        if category not in category_outputs:
            continue

        cat_data = category_outputs[category]
        cat_display = cat_data["display"]

        # Category header (console only if showing data)
        if show_all or show_data:
            print(f"{Colors.BOLD}{Colors.CYAN}┌{'─'*68}┐")
            print(f"│  {cat_display.upper():64} │")
            print(f"└{'─'*68}┘{Colors.RESET}")

        report_lines.append(f"## {cat_display}")
        report_lines.append("")

        for item in cat_data["queries"]:
            query = item["query"]
            result = item["result"]
            status = item["status"]

            rel_color = Colors.RED if query.oscp_relevance == "high" else (
                Colors.YELLOW if query.oscp_relevance == "medium" else Colors.DIM
            )
            rel_badge = f"[{query.oscp_relevance.upper()}]"

            if status == "skipped":
                if show_all or show_data:
                    print(f"  {Colors.DIM}○ {query.name} (skipped - requires variables){Colors.RESET}")
                report_lines.append(f"### {query.name}")
                report_lines.append(f"*Skipped - requires variables: {', '.join(query.variables.keys())}*")
                report_lines.append("")

            elif status == "results":
                if show_all or show_data:
                    print(f"  {Colors.GREEN}●{Colors.RESET} {rel_color}{rel_badge}{Colors.RESET} {Colors.BOLD}{query.name}{Colors.RESET}")
                    print(f"    {Colors.GREEN}└─ {result.record_count} results{Colors.RESET}")

                    # Check if results contain path objects
                    if result.records and has_path_results(result.records):
                        # Use visual path display for attack paths
                        print_attack_paths(result.records, query.name, use_colors=True)
                    # Verbose: show full table in console (non-path results)
                    elif verbose and result.records:
                        headers = list(result.records[0].keys())
                        widths = {h: len(h) for h in headers}
                        for record in result.records:
                            for h in headers:
                                val = format_field_value(h, record.get(h, ""))
                                widths[h] = max(widths[h], len(val))
                        header_line = " | ".join(h.ljust(widths[h]) for h in headers)
                        print(f"    {Colors.DIM}{header_line}{Colors.RESET}")
                        print(f"    {Colors.DIM}{'-' * len(header_line)}{Colors.RESET}")
                        for record in result.records:
                            row = " | ".join(format_field_value(h, record.get(h, "")).ljust(widths[h]) for h in headers)
                            print(f"    {row}")
                        print()

                # Markdown (always)
                report_lines.append(f"### ✅ {query.name}")
                report_lines.append(f"**OSCP Relevance:** {query.oscp_relevance.upper()} | **Results:** {result.record_count}")
                report_lines.append("")
                report_lines.append(f"> {query.description}")
                report_lines.append("")

                if result.records:
                    # Format paths nicely in markdown too
                    if has_path_results(result.records):
                        report_lines.append("**Attack Paths:**")
                        report_lines.append("")
                        for i, record in enumerate(result.records[:15], 1):
                            for key, val in record.items():
                                if is_neo4j_path(val):
                                    parsed = format_neo4j_path(val)
                                    if not parsed.get('error'):
                                        edges_str = ' → '.join(parsed['edges'])
                                        report_lines.append(f"{i}. **{parsed['start']}** → **{parsed['end']}** ({parsed['hops']} hops)")
                                        report_lines.append(f"   - Path: {' → '.join(parsed['nodes'])}")
                                        report_lines.append(f"   - Edges: {edges_str}")
                                        report_lines.append("")
                        if len(result.records) > 15:
                            report_lines.append(f"*... and {len(result.records) - 15} more paths*")
                    else:
                        headers = list(result.records[0].keys())
                        report_lines.append("| " + " | ".join(headers) + " |")
                        report_lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
                        for record in result.records:
                            row = [format_field_value(h, record.get(h, "")).replace("|", "\\|") for h in headers]
                            report_lines.append("| " + " | ".join(row) + " |")
                report_lines.append("")

            elif status == "no_results":
                if show_all or show_data:
                    print(f"  {Colors.DIM}○ {rel_badge} {query.name} (no results){Colors.RESET}")
                report_lines.append(f"### ⚪ {query.name}")
                report_lines.append(f"**OSCP Relevance:** {query.oscp_relevance.upper()} | **Results:** None")
                report_lines.append("")

            elif status == "failed":
                if show_all or show_data:
                    print(f"  {Colors.RED}✗ {rel_badge} {query.name} (failed: {result.error[:40]}){Colors.RESET}")
                report_lines.append(f"### ❌ {query.name}")
                report_lines.append(f"**Error:** {result.error}")
                report_lines.append("")

        if show_all or show_data:
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

    # Generate Pwned User Attack Paths section
    try:
        from .display_commands import generate_pwned_attack_paths
        if runner.driver:
            pwned_console, pwned_markdown = generate_pwned_attack_paths(runner.driver)
            if pwned_console:
                print(pwned_console)
                report_lines.append("")
                report_lines.append(pwned_markdown)
    except Exception as e:
        # Silently skip if generation fails
        pass

    # Write report
    if output_path is None:
        output_path = Path.cwd() / "bloodtrail.md"
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
