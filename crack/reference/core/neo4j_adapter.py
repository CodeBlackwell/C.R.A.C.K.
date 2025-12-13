"""
Neo4j Adapter - Graph database adapter for CommandRegistry

Provides graph-optimized implementation for complex relationship queries
with API parity to SQLCommandRegistryAdapter.

Optimized for:
- Multi-hop relationship traversal (alternatives, prerequisites)
- Attack chain dependency resolution
- Service-based command recommendations
"""

from typing import List, Dict, Optional, Any, Union
from dataclasses import dataclass
from functools import lru_cache
import time

try:
    from neo4j import GraphDatabase, Session
    from neo4j.exceptions import ServiceUnavailable, SessionExpired
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False

from .registry import Command, CommandVariable
from .command_filler import CommandFiller
from .command_mapper import CommandMapper
from .exceptions import AdapterErrorHandler
from .adapter_interface import CommandRegistryAdapter


class Neo4jConnectionError(Exception):
    """Raised when Neo4j is unavailable"""
    pass


@dataclass
class Path:
    """Represents a graph path between commands"""
    nodes: List[Command]
    relationships: List[Dict[str, Any]]
    length: int


class Neo4jCommandRegistryAdapter:
    """
    Neo4j-backed implementation of CommandRegistryInterface

    Optimized for graph queries:
    - Multi-hop relationship traversal
    - Attack chain path finding
    - Alternative command discovery
    """

    def __init__(
        self,
        config_manager=None,
        theme=None,
        neo4j_config: Optional[Dict] = None
    ):
        """
        Initialize Neo4j adapter

        Args:
            config_manager: ConfigManager instance for placeholder values
            theme: ReferenceTheme instance for colorized output
            neo4j_config: Optional Neo4j connection config

        Raises:
            Neo4jConnectionError: If Neo4j is unavailable
        """
        if not NEO4J_AVAILABLE:
            raise Neo4jConnectionError("neo4j package not installed")

        from db.config import Neo4jConfig

        self.config_manager = config_manager
        self.theme = theme

        if self.theme is None:
            from crack.themes.colors import ReferenceTheme
            self.theme = ReferenceTheme()

        # Initialize shared components
        self.filler = CommandFiller(config_manager, theme)
        self.error_handler = AdapterErrorHandler('neo4j')

        # API compatibility attributes (match HybridCommandRegistry and SQLAdapter)
        self.base_path = None  # Neo4j backend doesn't use file paths
        self.categories = {
            'recon': '01-recon',
            'web': '02-web',
            'exploitation': '03-exploitation',
            'post-exploit': '04-post-exploit',
            'enumeration': '05-enumeration',
            'pivoting': '06-pivoting',
            'file-transfer': '07-file-transfer',
            'custom': 'custom'
        }
        self.subcategories = {}  # Populated dynamically from database
        self.commands = {}  # Not pre-loaded (query on demand for performance)

        # Neo4j connection
        neo4j_cfg = neo4j_config or Neo4jConfig.from_env().to_dict()
        try:
            self.driver = GraphDatabase.driver(
                neo4j_cfg['uri'],
                auth=(neo4j_cfg['user'], neo4j_cfg['password']),
                max_connection_lifetime=neo4j_cfg.get('max_connection_lifetime', 3600),
                max_connection_pool_size=neo4j_cfg.get('max_connection_pool_size', 50)
            )
            self.database = neo4j_cfg.get('database', 'neo4j')

            # Test connection
            with self.driver.session(database=self.database) as session:
                session.run("RETURN 1")

        except Exception as e:
            self.error_handler.handle_connection_error(e, {'uri': neo4j_cfg.get('uri', 'unknown')})
            raise Neo4jConnectionError(f"Failed to connect to Neo4j: {e}")

    def __del__(self):
        """Close driver on cleanup"""
        if hasattr(self, 'driver'):
            self.driver.close()

    def _execute_read(self, query: str, **params):
        """
        Execute read query with error handling and retry logic

        Args:
            query: Cypher query string
            **params: Query parameters

        Returns:
            List of records or empty list on error
        """
        max_retries = 3
        for attempt in range(max_retries):
            try:
                with self.driver.session(database=self.database) as session:
                    result = session.run(query, **params)
                    return list(result)

            except (ServiceUnavailable, SessionExpired) as e:
                if attempt == max_retries - 1:
                    return self.error_handler.handle_query_error(
                        e, 'execute_read', {'query': query[:100], **params}, []
                    )
                time.sleep(2 ** attempt)

            except Exception as e:
                return self.error_handler.handle_query_error(
                    e, 'execute_read', {'query': query[:100], **params}, []
                )

        return []

    def _record_to_command(self, record) -> Optional[Command]:
        """
        Convert Neo4j record to Command dataclass - REFACTORED to use CommandMapper

        Args:
            record: Neo4j record with command node and relationships

        Returns:
            Command dataclass instance or None
        """
        try:
            # Convert Neo4j Record to dict for proper field access
            return CommandMapper.to_command(dict(record), CommandMapper.NEO4J_FIELD_MAPPING)
        except Exception as e:
            return self.error_handler.handle_mapping_error(e, {'record_keys': list(record.keys())}, None)

    def _validate_cypher_safety(self, query_fragment: str) -> None:
        """
        Validate Cypher query fragment for dangerous keywords.

        Prevents injection attacks by blocking destructive operations.

        Args:
            query_fragment: User-provided Cypher pattern or clause

        Raises:
            ValueError: If dangerous keywords detected
        """
        BLOCKED_KEYWORDS = {
            'DROP', 'DELETE', 'DETACH DELETE', 'CREATE', 'MERGE',
            'SET', 'REMOVE', 'LOAD CSV', 'CALL', 'WITH'
        }

        upper_fragment = query_fragment.upper()

        for keyword in BLOCKED_KEYWORDS:
            if keyword in upper_fragment:
                raise ValueError(
                    f"Cypher injection detected: '{keyword}' is not allowed. "
                    f"Only read-only queries are permitted."
                )

        if ';' in query_fragment:
            raise ValueError("Multiple queries (;) are not allowed")

    # === Basic Query Methods ===

    @lru_cache(maxsize=256)
    def get_command(self, command_id: str) -> Optional[Command]:
        """
        Get single command by ID with all relationships

        Args:
            command_id: Command identifier

        Returns:
            Command dataclass or None if not found
        """
        query = """
        MATCH (cmd:Command {id: $command_id})
        OPTIONAL MATCH (cmd)-[:TAGGED]->(tag:Tag)
        OPTIONAL MATCH (cmd)-[:HAS_INDICATOR]->(ind:Indicator)
        RETURN
            cmd,
            collect(DISTINCT tag.name) AS tags,
            collect(DISTINCT CASE WHEN ind.type = 'success' THEN ind.pattern ELSE null END) AS success_indicators,
            collect(DISTINCT CASE WHEN ind.type = 'failure' THEN ind.pattern ELSE null END) AS failure_indicators
        """

        results = self._execute_read(query, command_id=command_id)
        if not results:
            return None

        # Build command with simplified structure
        record = results[0]
        cmd_node = record['cmd']

        # Extract tags
        tags = [t for t in record['tags'] if t]

        # Extract indicators
        success_indicators = [s for s in record['success_indicators'] if s]
        failure_indicators = [f for f in record['failure_indicators'] if f]

        # Helper to parse JSON fields
        def parse_json_field(field_name, default=None):
            """Parse JSON field from cmd_node, return default if missing/invalid"""
            import json
            if field_name not in cmd_node:
                return default if default is not None else ({} if isinstance(default, dict) else [])

            raw_value = cmd_node[field_name]
            if isinstance(raw_value, str):
                try:
                    return json.loads(raw_value)
                except json.JSONDecodeError:
                    return default if default is not None else ({} if '{}' in raw_value else [])
            return raw_value if raw_value else (default if default is not None else ({} if isinstance(default, dict) else []))

        # Load JSON fields
        flag_explanations = parse_json_field('flag_explanations', {})
        advantages = parse_json_field('advantages', [])
        disadvantages = parse_json_field('disadvantages', [])
        use_cases = parse_json_field('use_cases', [])
        output_analysis = parse_json_field('output_analysis', [])
        common_uses = parse_json_field('common_uses', [])
        references = parse_json_field('references', [])
        alternatives = parse_json_field('alternatives', [])
        prerequisites = parse_json_field('prerequisites', [])
        next_steps = parse_json_field('next_steps', [])
        troubleshooting = parse_json_field('troubleshooting', {})

        return Command(
            id=cmd_node['id'],
            name=cmd_node['name'],
            command=cmd_node.get('command', ''),
            description=cmd_node['description'],
            category=cmd_node['category'],
            subcategory=cmd_node.get('subcategory', ''),
            filled_example=cmd_node.get('filled_example', ''),
            tags=tags,
            variables=[],  # Variables not linked in current schema
            flag_explanations=flag_explanations,
            success_indicators=success_indicators,
            failure_indicators=failure_indicators,
            next_steps=next_steps,
            alternatives=alternatives,
            prerequisites=prerequisites,
            troubleshooting=troubleshooting,
            oscp_relevance=cmd_node.get('oscp_relevance', 'medium'),
            notes=cmd_node.get('notes', ''),
            advantages=advantages,
            disadvantages=disadvantages,
            use_cases=use_cases,
            output_analysis=output_analysis,
            common_uses=common_uses,
            references=references
        )

    def search(
        self,
        query: str,
        category: Optional[str] = None,
        tags: Optional[List[str]] = None,
        oscp_only: bool = False
    ) -> List[Command]:
        """
        Full-text search with optional filters

        Multi-term queries (space-separated) use AND logic - all terms must match.
        Each term is matched against name, description, command text, and notes.

        Args:
            query: Search query string (space-separated for multi-term)
            category: Optional category filter
            tags: Optional tag filter (AND logic)
            oscp_only: Filter to high OSCP relevance only

        Returns:
            List of matching Command objects
        """
        # Normalize search terms for punctuation-insensitive matching
        search_terms = [
            term.lower().replace('-', '').replace('_', '').replace(':', '').replace('.', '').replace('/', '')
            for term in query.split()
        ]

        cypher = """
        MATCH (cmd:Command)
        WHERE ALL(term IN $search_terms WHERE (
            replace(replace(replace(replace(replace(toLower(cmd.id), '-', ''), '_', ''), ':', ''), '.', ''), '/', '') CONTAINS term
            OR replace(replace(replace(replace(replace(toLower(cmd.name), '-', ''), '_', ''), ':', ''), '.', ''), '/', '') CONTAINS term
            OR replace(replace(replace(replace(replace(toLower(cmd.description), '-', ''), '_', ''), ':', ''), '.', ''), '/', '') CONTAINS term
            OR replace(replace(replace(replace(replace(toLower(cmd.command), '-', ''), '_', ''), ':', ''), '.', ''), '/', '') CONTAINS term
            OR replace(replace(replace(replace(replace(toLower(cmd.notes), '-', ''), '_', ''), ':', ''), '.', ''), '/', '') CONTAINS term
        ))
          AND ($category IS NULL OR cmd.category = $category)
          AND ($oscp_only = false OR cmd.oscp_relevance = 'high')
        """

        # Add tag filter if specified
        if tags:
            cypher += """
            AND ALL(tag IN $tags WHERE EXISTS((cmd)-[:TAGGED]->(:Tag {name: tag})))
            """

        cypher += """
        RETURN cmd.id AS id
        ORDER BY cmd.name
        LIMIT 50
        """

        results = self._execute_read(
            cypher,
            search_terms=search_terms,
            category=category,
            oscp_only=oscp_only,
            tags=tags or []
        )

        # Fetch full command details for each result
        commands = []
        for record in results:
            cmd = self.get_command(record['id'])
            if cmd:
                commands.append(cmd)

        return commands

    def filter_by_category(self, category: str, subcategory: str = None) -> List[Command]:
        """
        Get all commands in a category

        Args:
            category: Category name
            subcategory: Optional subcategory filter

        Returns:
            List of Command objects in category
        """
        if subcategory:
            query = """
            MATCH (c:Command)
            WHERE c.category = $category AND c.subcategory = $subcategory
            RETURN c.id AS id
            ORDER BY c.name
            """
            results = self._execute_read(query, category=category, subcategory=subcategory)
        else:
            query = """
            MATCH (c:Command {category: $category})
            RETURN c.id AS id
            ORDER BY c.name
            """
            results = self._execute_read(query, category=category)

        commands = []
        for record in results:
            cmd = self.get_command(record['id'])
            if cmd:
                commands.append(cmd)

        return commands

    # === Tag and Category Filtering ===

    def filter_by_tags(
        self,
        tags: List[str],
        match_all: bool = True,
        exclude_tags: List[str] = None,
        include_hierarchy: bool = False
    ) -> List[Command]:
        """
        Filter commands by tags

        Args:
            tags: List of tags to match
            match_all: If True, command must have ALL tags (AND), else ANY tag (OR)
            exclude_tags: Optional list of tags to exclude
            include_hierarchy: If True, include tags that are children of specified parent tags

        Returns:
            List of Command objects with matching tags

        Examples:
            Exact tag match:
            >>> adapter.filter_by_tags(['OSCP'])
            [Command(id='cmd1'), ...]  # Only commands with exact "OSCP" tag

            Hierarchical tag match:
            >>> adapter.filter_by_tags(['OSCP'], include_hierarchy=True)
            [Command(id='cmd1'), ...]  # Commands with "OSCP", "OSCP:ENUM", "OSCP:EXPLOIT", etc.
        """
        if include_hierarchy:
            # Traverse tag hierarchy to include child tags
            if match_all:
                # AND logic with hierarchy: command must have all parent tags (or their children)
                # Neo4j 4.x compatible syntax (using EXISTS with pattern, not EXISTS { MATCH })
                query = """
                MATCH (cmd:Command)
                WHERE ALL(parent_tag IN $tags WHERE
                    EXISTS((cmd)-[:TAGGED]->(:Tag)-[:CHILD_OF*0..]->(:Tag {name: parent_tag}))
                )
                """
            else:
                # OR logic with hierarchy: command must have at least one parent tag (or its children)
                query = """
                MATCH (cmd:Command)-[:TAGGED]->(tag:Tag)-[:CHILD_OF*0..]->(parent:Tag)
                WHERE parent.name IN $tags
                """
        else:
            # Original exact tag matching
            if match_all:
                # AND logic: command must have all tags
                query = """
                MATCH (cmd:Command)
                WHERE ALL(tag IN $tags WHERE EXISTS((cmd)-[:TAGGED]->(:Tag {name: tag})))
                """
            else:
                # OR logic: command must have at least one tag
                query = """
                MATCH (cmd:Command)-[:TAGGED]->(t:Tag)
                WHERE t.name IN $tags
                """

        # Add exclusion filter
        if exclude_tags:
            query += """
            AND NOT EXISTS((cmd)-[:TAGGED]->(:Tag))
            WHERE (cmd)-[:TAGGED]->(et:Tag) AND et.name IN $exclude_tags
            """

        query += """
        WITH DISTINCT cmd
        RETURN cmd.id AS id
        ORDER BY cmd.id
        """

        results = self._execute_read(
            query,
            tags=tags,
            exclude_tags=exclude_tags or []
        )

        commands = []
        for record in results:
            cmd = self.get_command(record['id'])
            if cmd:
                commands.append(cmd)

        return commands
    def get_quick_wins(self) -> List[Command]:
        """
        Get commands tagged as quick wins

        Returns:
            List of Command objects with QUICK_WIN tag
        """
        return self.filter_by_tags(['QUICK_WIN'])

    def get_oscp_high(self) -> List[Command]:
        """
        Get OSCP high-relevance commands

        Lightweight wrapper around search() with oscp_only=True filter.

        Returns:
            List of high-priority OSCP commands
        """
        return self.search(query='', oscp_only=True)

    # === Graph Traversal Methods ===

    def find_alternatives(
        self,
        command_id: str,
        max_depth: int = 3,
        return_metadata: bool = False
    ) -> List[Union[Command, Dict[str, Any]]]:
        """
        Find multi-hop alternative command chains

        Args:
            command_id: Source command ID
            max_depth: Maximum traversal depth (default 3)
            return_metadata: If True, return detailed path metadata instead of Command objects

        Returns:
            If return_metadata=False (default): List of alternative Command objects ordered by depth
            If return_metadata=True: List of dicts with command_chain, metadata, depth, cumulative_priority

        Examples:
            Basic usage:
            >>> adapter.find_alternatives('gobuster-dir')
            [Command(id='ffuf-dir'), Command(id='wfuzz-dir')]

            With metadata:
            >>> adapter.find_alternatives('gobuster-dir', return_metadata=True)
            [{'command_chain': [{'id': 'gobuster-dir', 'name': 'Gobuster'},
                                 {'id': 'ffuf-dir', 'name': 'FFUF'}],
              'metadata': [{'priority': 1, 'reason': 'Faster for small wordlists'}],
              'depth': 1,
              'cumulative_priority': 1}]
        """
        # Neo4j variable-length paths can't use parameters for depth, use literal
        depth_range = f"1..{max_depth}"

        if return_metadata:
            # Enhanced query with relationship metadata
            query = f"""
            MATCH path = (start:Command {{id: $command_id}})-[:ALTERNATIVE*{depth_range}]->(alt:Command)
            WITH path, relationships(path) AS rels
            RETURN
                [node IN nodes(path) | {{id: node.id, name: node.name}}] AS command_chain,
                [rel IN rels | {{priority: COALESCE(rel.priority, 0), reason: COALESCE(rel.reason, '')}}] AS metadata,
                length(path) AS depth,
                reduce(total = 0, rel IN rels | total + COALESCE(rel.priority, 0)) AS cumulative_priority
            ORDER BY depth ASC, cumulative_priority ASC
            LIMIT 20
            """

            results = self._execute_read(query, command_id=command_id)

            return [
                {
                    'command_chain': record['command_chain'],
                    'metadata': record['metadata'],
                    'depth': record['depth'],
                    'cumulative_priority': record['cumulative_priority']
                }
                for record in results
            ]
        else:
            # Original behavior - return Command objects
            query = f"""
            MATCH path = (start:Command {{id: $command_id}})-[:ALTERNATIVE*{depth_range}]->(alt:Command)
            WITH alt, length(path) AS depth
            RETURN DISTINCT alt.id AS id, depth
            ORDER BY depth ASC
            LIMIT 20
            """

            results = self._execute_read(query, command_id=command_id)

            commands = []
            for record in results:
                cmd = self.get_command(record['id'])
                if cmd:
                    commands.append(cmd)

            return commands

    def find_prerequisites(
        self,
        command_id: str,
        depth: int = 3,
        execution_order: bool = False
    ) -> Union[List[Command], List[Dict[str, Any]]]:
        """
        Get all prerequisite commands (transitive closure)

        Args:
            command_id: Target command ID
            depth: Maximum traversal depth (default 3)
            execution_order: If True, return topological sort with dependency counts

        Returns:
            If execution_order=False (default): List of prerequisite Command objects ordered by depth (deepest first)
            If execution_order=True: List of dicts with command_id, command_name, dependency_count
                                    (sorted by dependency_count DESC - deepest dependencies first)

        Examples:
            Basic usage:
            >>> adapter.find_prerequisites('wordpress-sqli')
            [Command(id='mkdir-output'), Command(id='nmap-scan')]

            With execution order:
            >>> adapter.find_prerequisites('wordpress-sqli', execution_order=True)
            [{'command_id': 'mkdir-output', 'command_name': 'Create Output Dir', 'dependency_count': 0},
             {'command_id': 'nmap-scan', 'command_name': 'Nmap Scan', 'dependency_count': 1},
             {'command_id': 'wordpress-sqli', 'command_name': 'WP SQLi', 'dependency_count': 2}]
        """
        # Neo4j variable-length paths can't use parameters for depth, use literal
        depth_range = f"1..{depth}"

        if execution_order:
            # Topological sort query with dependency counting
            query = f"""
            MATCH (cmd:Command {{id: $command_id}})<-[:PREREQUISITE*0..{depth}]-(allPrereqs)
            OPTIONAL MATCH (allPrereqs)<-[:PREREQUISITE]-(deps)
            WITH allPrereqs, count(deps) AS dependency_count
            RETURN
                allPrereqs.id AS command_id,
                allPrereqs.name AS command_name,
                dependency_count
            ORDER BY dependency_count DESC, allPrereqs.id
            """

            results = self._execute_read(query, command_id=command_id)

            return [
                {
                    'command_id': record['command_id'],
                    'command_name': record['command_name'],
                    'dependency_count': record['dependency_count']
                }
                for record in results
            ]
        else:
            # Original behavior - return Command objects
            query = f"""
            MATCH path = (cmd:Command {{id: $command_id}})<-[:PREREQUISITE*{depth_range}]-(prereq:Command)
            WITH prereq, length(path) AS depth
            RETURN DISTINCT prereq.id AS id, depth
            ORDER BY depth DESC
            """

            results = self._execute_read(query, command_id=command_id)

            prerequisites = []
            for record in results:
                cmd = self.get_command(record['id'])
                if cmd:
                    prerequisites.append(cmd)

            return prerequisites

    def get_attack_chain_path(self, chain_id: str) -> Optional[Dict[str, Any]]:
        """
        Get attack chain execution plan with dependencies

        Args:
            chain_id: Attack chain ID

        Returns:
            Dict with chain info, steps, and execution order
        """
        query = """
        MATCH (chain:AttackChain {id: $chain_id})
        OPTIONAL MATCH (chain)-[:HAS_STEP]->(step:ChainStep)
        OPTIONAL MATCH (step)-[:DEPENDS_ON]->(dep:ChainStep)
        OPTIONAL MATCH (step)-[:EXECUTES]->(cmd:Command)
        WITH chain, step, collect(DISTINCT dep.id) AS dependencies, cmd
        RETURN
            chain.name AS chain_name,
            chain.description AS chain_description,
            collect({
                id: step.id,
                name: step.name,
                order: step.step_order,
                objective: step.objective,
                command_id: cmd.id,
                dependencies: dependencies
            }) AS steps
        """

        results = self._execute_read(query, chain_id=chain_id)

        if not results:
            return None

        record = results[0]
        steps_data = record['steps']

        # Filter out null steps
        steps_data = [s for s in steps_data if s['id'] is not None]

        # Enrich with full command objects
        steps = []
        for step_data in steps_data:
            command = None
            if step_data['command_id']:
                command = self.get_command(step_data['command_id'])

            steps.append({
                'id': step_data['id'],
                'name': step_data['name'],
                'order': step_data['order'],
                'objective': step_data['objective'],
                'command': command,
                'dependencies': step_data['dependencies']
            })

        # Calculate parallel execution groups
        parallel_groups = self._calculate_parallel_groups(steps)

        return {
            'id': chain_id,
            'name': record['chain_name'],
            'description': record['chain_description'],
            'steps': sorted(steps, key=lambda s: s['order']),
            'execution_order': [s['id'] for s in sorted(steps, key=lambda s: s['order'])],
            'parallel_groups': parallel_groups
        }

    def _calculate_parallel_groups(self, steps: List[Dict]) -> List[List[str]]:
        """
        Detect which steps can run in parallel

        Steps with no shared dependencies can run concurrently

        Args:
            steps: List of step dictionaries

        Returns:
            List of groups, where each group contains step IDs that can run in parallel
        """
        # Build dependency graph
        step_deps = {s['id']: set(s['dependencies']) for s in steps}

        groups = []
        remaining = set(s['id'] for s in steps)

        while remaining:
            # Find steps with all dependencies satisfied
            ready = set()
            for step_id in remaining:
                deps = step_deps[step_id]
                if all(d not in remaining for d in deps):
                    ready.add(step_id)

            if not ready:
                # Circular dependency detected
                break

            groups.append(sorted(ready))
            remaining -= ready

        return groups

    # === Registry Management and Utilities ===

    def get_stats(self) -> Dict[str, Any]:
        """
        Get registry statistics

        Returns:
            Dict with command counts and metadata
        """
        query = """
        MATCH (c:Command) WITH count(c) as commands
        MATCH (t:Tag) WITH commands, count(t) as tags
        MATCH (ac:AttackChain) WITH commands, tags, count(ac) as chains
        RETURN commands, tags, chains
        """

        results = self._execute_read(query)
        if not results:
            return {
                'total_commands': 0,
                'tags': 0,
                'attack_chains': 0
            }

        record = results[0]
        return {
            'total_commands': record['commands'],
            'tags': record['tags'],
            'attack_chains': record['chains']
        }

    def health_check(self) -> bool:
        """
        Test Neo4j connectivity

        Returns:
            True if connection successful, False otherwise
        """
        try:
            with self.driver.session(database=self.database) as session:
                result = session.run("RETURN 1 AS test")
                return result.single()['test'] == 1
        except:
            return False

    def interactive_fill(self, command: Command) -> str:
        """
        Interactively fill command placeholders - DELEGATES to CommandFiller

        Args:
            command: Command dataclass to fill

        Returns:
            Filled command string
        """
        return self.filler.fill_command(command)

    def get_all_commands(self) -> List[Command]:
        """
        Get all commands in registry

        Returns:
            List of all Command objects
        """
        query = """
        MATCH (c:Command)
        RETURN c.id AS id
        ORDER BY c.category, c.name
        """

        results = self._execute_read(query)
        return [self.get_command(r['id']) for r in results if self.get_command(r['id'])]

    def get_subcategories(self, category: str) -> List[str]:
        """
        Get all subcategories for a category

        Args:
            category: Category name

        Returns:
            List of subcategory names
        """
        query = """
        MATCH (c:Command {category: $category})
        WHERE c.subcategory IS NOT NULL AND c.subcategory <> ''
        RETURN DISTINCT c.subcategory AS subcategory
        ORDER BY subcategory
        """

        results = self._execute_read(query, category=category)
        return [r['subcategory'] for r in results]

    # ===== Graph Primitives (DRY Query Patterns) =====

    def traverse_graph(
        self,
        start_node_id: str,
        rel_type: str,
        direction: str = 'OUTGOING',
        max_depth: int = 3,
        filters: Optional[Dict[str, Any]] = None,
        return_metadata: bool = False,
        limit: int = 50
    ) -> List[Any]:
        """
        Generic graph traversal with variable-length paths

        Handles patterns:
        - Pattern 1: Multi-hop alternatives (rel_type='ALTERNATIVE')
        - Pattern 3: Prerequisites (rel_type='PREREQUISITE', direction='INCOMING')
        - Pattern 6: Tag hierarchy (rel_type='CHILD_OF')

        Args:
            start_node_id: Starting node ID
            rel_type: Relationship type to traverse (e.g., 'ALTERNATIVE', 'PREREQUISITE')
            direction: 'OUTGOING' (->), 'INCOMING' (<-), or 'BOTH' (<->)
            max_depth: Maximum traversal depth (default 3)
            filters: Optional node property filters (e.g., {'oscp_relevance': 'high'})
            return_metadata: Include relationship properties in results
            limit: Maximum results to return

        Returns:
            List of Command objects or dicts with metadata if return_metadata=True

        Example:
            alternatives = adapter.traverse_graph(
                'gobuster-dir',
                'ALTERNATIVE',
                max_depth=3,
                return_metadata=True
            )
        """
        try:
            # Build relationship pattern based on direction
            direction_map = {
                'OUTGOING': f'-[r:{rel_type}*1..{max_depth}]->',
                'INCOMING': f'<-[r:{rel_type}*1..{max_depth}]-',
                'BOTH': f'-[r:{rel_type}*1..{max_depth}]-'
            }

            if direction not in direction_map:
                return self.error_handler.handle_query_error(
                    ValueError(f"Invalid direction: {direction}"),
                    'traverse_graph',
                    {'direction': direction},
                    []
                )

            rel_pattern = direction_map[direction]

            # Build WHERE clause for filters
            where_clauses = []
            if filters:
                for key, value in filters.items():
                    where_clauses.append(f"target.{key} = ${key}")

            where_clause = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

            # Build query
            if return_metadata:
                # Full Pattern 1 spec: command chain with metadata
                query = f"""
                MATCH path = (start:Command {{id: $start_node_id}}){rel_pattern}(target:Command)
                {where_clause}
                WITH path, relationships(path) AS rels
                RETURN DISTINCT
                    [node IN nodes(path) | {{id: node.id, name: node.name}}] AS command_chain,
                    [rel IN rels | properties(rel)] AS metadata,
                    length(path) AS depth,
                    reduce(total = 0, rel IN rels | total + coalesce(rel.priority, 0)) AS cumulative_priority
                ORDER BY depth ASC, cumulative_priority ASC
                LIMIT $limit
                """
            else:
                query = f"""
                MATCH path = (start:Command {{id: $start_node_id}}){rel_pattern}(target:Command)
                {where_clause}
                WITH target, length(path) AS depth
                RETURN DISTINCT target.id AS id, depth
                ORDER BY depth ASC
                LIMIT $limit
                """

            # Execute query with filters as params
            params = {'start_node_id': start_node_id, 'limit': limit}
            if filters:
                params.update(filters)

            results = self._execute_read(query, **params)

            # Format results
            if return_metadata:
                # Return full chain as per Pattern 1 spec
                return [
                    {
                        'command_chain': r['command_chain'],
                        'metadata': r['metadata'],
                        'depth': r['depth'],
                        'cumulative_priority': r['cumulative_priority']
                    }
                    for r in results
                ]
            else:
                commands = []
                for r in results:
                    if r['id'] is not None:
                        cmd = self.get_command(r['id'])
                        if cmd:
                            commands.append(cmd)
                return commands

        except Exception as e:
            return self.error_handler.handle_query_error(
                e, 'traverse_graph',
                {'start_node_id': start_node_id, 'rel_type': rel_type, 'direction': direction},
                []
            )

    def aggregate_by_pattern(
        self,
        pattern: str,
        group_by: List[str],
        aggregations: Dict[str, str],
        filters: Optional[Dict[str, Any]] = None,
        order_by: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Template-based aggregation queries

        Handles patterns:
        - Pattern 5: Service-based recommendations
        - Pattern 7: Command success correlations
        - Pattern 10: Variable usage analysis

        Args:
            pattern: Cypher MATCH pattern (e.g., "(c:Command)-[:TAGGED]->(t:Tag)")
            group_by: List of variables to group by (e.g., ['c', 't'])
            aggregations: Dict of {result_key: aggregation_expression}
                         (e.g., {'count': 'COUNT(c)', 'tags': 'COLLECT(t.name)'})
            filters: Optional WHERE clause filters
            order_by: Optional ORDER BY expression (e.g., 'count DESC')
            limit: Maximum results

        Returns:
            List of dicts with grouped and aggregated results

        Example:
            results = adapter.aggregate_by_pattern(
                pattern="(c:Command)-[:TAGGED]->(t:Tag)",
                group_by=['t'],
                aggregations={'tag_name': 't.name', 'count': 'COUNT(c)'},
                order_by='count DESC',
                limit=10
            )
        """
        # Security: Validate pattern doesn't contain dangerous keywords (before try block)
        dangerous_keywords = ['DROP', 'DELETE', 'CREATE', 'MERGE', 'SET', 'REMOVE', 'DETACH']
        pattern_upper = pattern.upper()
        for keyword in dangerous_keywords:
            if keyword in pattern_upper:
                raise ValueError(f"Dangerous keyword '{keyword}' not allowed in pattern")

        try:
            # Build query
            query_parts = [f"MATCH {pattern}"]

            # Add WHERE clause with sanitized parameter names
            params = {}
            if filters:
                where_clauses = []
                for i, (key, value) in enumerate(filters.items()):
                    # Use simple parameter names (p0, p1, etc.) to avoid dots in param names
                    param_name = f"filter_{i}"
                    where_clauses.append(f"{key} = ${param_name}")
                    params[param_name] = value
                query_parts.append(f"WHERE {' AND '.join(where_clauses)}")

            # Build RETURN clause
            return_parts = []
            for result_key, agg_expr in aggregations.items():
                return_parts.append(f"{agg_expr} AS {result_key}")

            query_parts.append(f"RETURN {', '.join(return_parts)}")

            # Add ORDER BY
            if order_by:
                query_parts.append(f"ORDER BY {order_by}")

            # Add LIMIT
            query_parts.append(f"LIMIT {limit}")

            query = '\n'.join(query_parts)

            # Execute with sanitized params
            results = self._execute_read(query, **params)

            return [dict(r) for r in results]

        except Exception as e:
            return self.error_handler.handle_query_error(
                e, 'aggregate_by_pattern',
                {'pattern': pattern, 'group_by': group_by},
                []
            )

    def find_by_pattern(
        self,
        pattern: str,
        where_clause: Optional[str] = None,
        return_fields: Optional[List[str]] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Generic Cypher pattern matching with safety constraints

        Handles patterns:
        - Pattern 2: Shortest path queries
        - Pattern 8: Gap detection (negative EXISTS)
        - Pattern 9: Circular dependency detection

        Args:
            pattern: Cypher MATCH pattern (can include shortestPath, etc.)
            where_clause: Optional WHERE conditions
            return_fields: List of fields to return (if None, returns all matched nodes)
            limit: Maximum results

        Returns:
            List of dicts with matched results

        Security:
            Validates pattern against whitelist of allowed Cypher functions

        Example:
            cycles = adapter.find_by_pattern(
                pattern="(s:ChainStep)-[:DEPENDS_ON*]->(s)",
                return_fields=['s.id', 's.name'],
                limit=10
            )
        """
        # Security: Validate against dangerous keywords (before try block)
        dangerous_keywords = ['DROP', 'DELETE', 'CREATE', 'MERGE', 'SET', 'REMOVE', 'DETACH']
        pattern_upper = pattern.upper()
        for keyword in dangerous_keywords:
            if keyword in pattern_upper:
                raise ValueError(f"Dangerous keyword '{keyword}' not allowed in pattern")

        try:
            # Build query
            query_parts = [f"MATCH {pattern}"]

            if where_clause:
                query_parts.append(f"WHERE {where_clause}")

            # Build RETURN clause
            if return_fields:
                query_parts.append(f"RETURN {', '.join(return_fields)}")
            else:
                # Return all matched variables (extract from pattern)
                import re
                variables = re.findall(r'\((\w+):', pattern)
                if variables:
                    query_parts.append(f"RETURN {', '.join(variables)}")
                else:
                    query_parts.append("RETURN *")

            query_parts.append(f"LIMIT {limit}")

            query = '\n'.join(query_parts)

            results = self._execute_read(query)

            # Convert to dicts
            return [dict(r) for r in results]

        except Exception as e:
            return self.error_handler.handle_query_error(
                e, 'find_by_pattern',
                {'pattern': pattern, 'where_clause': where_clause},
                []
            )
