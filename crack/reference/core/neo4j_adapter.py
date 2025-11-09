"""
Neo4j Adapter - Graph database adapter for CommandRegistry

Provides graph-optimized implementation for complex relationship queries
with API parity to SQLCommandRegistryAdapter.

Optimized for:
- Multi-hop relationship traversal (alternatives, prerequisites)
- Attack chain dependency resolution
- Service-based command recommendations
"""

from typing import List, Dict, Optional, Any
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
            from .colors import ReferenceTheme
            self.theme = ReferenceTheme()

        # Initialize shared components
        self.filler = CommandFiller(config_manager, theme)
        self.error_handler = AdapterErrorHandler('neo4j')

        # Neo4j connection
        neo4j_cfg = neo4j_config or Neo4jConfig.from_env()
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
            return CommandMapper.to_command(record, CommandMapper.NEO4J_FIELD_MAPPING)
        except Exception as e:
            return self.error_handler.handle_mapping_error(e, {'record_keys': list(record.keys())}, None)

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

        return Command(
            id=cmd_node['id'],
            name=cmd_node['name'],
            command=cmd_node.get('command', ''),
            description=cmd_node['description'],
            category=cmd_node['category'],
            subcategory=cmd_node.get('subcategory', ''),
            tags=tags,
            variables=[],  # Variables not linked in current schema
            flag_explanations={},  # Flags not linked in current schema
            success_indicators=success_indicators,
            failure_indicators=failure_indicators,
            oscp_relevance=cmd_node.get('oscp_relevance', 'medium'),
            notes=cmd_node.get('notes', '')
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

        Args:
            query: Search query string
            category: Optional category filter
            tags: Optional tag filter (AND logic)
            oscp_only: Filter to high OSCP relevance only

        Returns:
            List of matching Command objects
        """
        # Use CONTAINS for simple text search (fallback if no fulltext index)
        query_lower = query.lower()

        cypher = """
        MATCH (cmd:Command)
        WHERE (toLower(cmd.name) CONTAINS $search_query
           OR toLower(cmd.description) CONTAINS $search_query
           OR toLower(cmd.command) CONTAINS $search_query
           OR toLower(cmd.notes) CONTAINS $search_query)
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
            search_query=query_lower,
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

    def filter_by_tags(
        self,
        tags: List[str],
        match_all: bool = True,
        exclude_tags: List[str] = None
    ) -> List[Command]:
        """
        Filter commands by tags

        Args:
            tags: List of tags to match
            match_all: If True, command must have ALL tags (AND), else ANY tag (OR)
            exclude_tags: Optional list of tags to exclude

        Returns:
            List of Command objects with matching tags
        """
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

        Returns:
            List of high-priority OSCP commands
        """
        query = """
        MATCH (c:Command {oscp_relevance: 'high'})
        RETURN c.id AS id
        ORDER BY c.category, c.name
        """

        results = self._execute_read(query)

        commands = []
        for record in results:
            cmd = self.get_command(record['id'])
            if cmd:
                commands.append(cmd)

        return commands

    def find_alternatives(
        self,
        command_id: str,
        max_depth: int = 3
    ) -> List[Command]:
        """
        Find multi-hop alternative command chains

        Args:
            command_id: Source command ID
            max_depth: Maximum traversal depth (default 3)

        Returns:
            List of alternative Command objects ordered by depth
        """
        # Neo4j variable-length paths can't use parameters for depth, use literal
        depth_range = f"1..{max_depth}"

        query = f"""
        MATCH path = (start:Command {{id: $command_id}})-[:ALTERNATIVE*{depth_range}]->(alt:Command)
        WITH alt, length(path) AS depth
        RETURN DISTINCT alt.id AS id, depth
        ORDER BY depth ASC
        LIMIT 20
        """

        results = self._execute_read(
            query,
            command_id=command_id
        )

        commands = []
        for record in results:
            cmd = self.get_command(record['id'])
            if cmd:
                commands.append(cmd)

        return commands

    def find_prerequisites(
        self,
        command_id: str,
        depth: int = 3
    ) -> List[Command]:
        """
        Get all prerequisite commands (transitive closure)

        Args:
            command_id: Target command ID
            depth: Maximum traversal depth (default 3)

        Returns:
            List of prerequisite Command objects ordered by depth (deepest first)
        """
        # Neo4j variable-length paths can't use parameters for depth, use literal
        depth_range = f"1..{depth}"

        query = f"""
        MATCH path = (cmd:Command {{id: $command_id}})<-[:PREREQUISITE*{depth_range}]-(prereq:Command)
        WITH prereq, length(path) AS depth
        RETURN DISTINCT prereq.id AS id, depth
        ORDER BY depth DESC
        """

        results = self._execute_read(
            query,
            command_id=command_id
        )

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

        commands = []
        for record in results:
            cmd = self.get_command(record['id'])
            if cmd:
                commands.append(cmd)

        return commands

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
