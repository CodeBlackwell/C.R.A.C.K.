"""
Advanced Neo4j Query Patterns for OSCP

Pre-built implementations of the 10 patterns from 06-ADVANCED-QUERIES.md
using the minimalist graph primitives.

Usage:
    from crack.reference.patterns.advanced_queries import GraphQueryPatterns

    patterns = GraphQueryPatterns(adapter)
    alternatives = patterns.multi_hop_alternatives('gobuster-dir', depth=3)
"""

from typing import List, Dict, Any, Optional


class GraphQueryPatterns:
    """
    Convenience wrappers for common query patterns.

    These methods demonstrate how to use the 3 minimalist primitives
    (traverse_graph, aggregate_by_pattern, find_by_pattern) to implement
    all 10 advanced patterns from the documentation.
    """

    def __init__(self, adapter):
        """
        Initialize pattern helper

        Args:
            adapter: Neo4jCommandRegistryAdapter instance
        """
        self.adapter = adapter

    def multi_hop_alternatives(
        self,
        command_id: str,
        depth: int = 3,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Pattern 1: Find alternative commands up to N hops away.

        Use Case: "If gobuster fails, try ffuf. If ffuf fails, try wfuzz."

        Example:
            alternatives = patterns.multi_hop_alternatives('gobuster-dir', depth=3)
            for alt in alternatives:
                print(f"Chain: {alt['command_chain']}")
                print(f"Priority: {alt['cumulative_priority']}")

        Args:
            command_id: Starting command ID
            depth: Maximum hops to traverse
            limit: Maximum results to return

        Returns:
            List of alternative chains with metadata
        """
        return self.adapter.traverse_graph(
            start_node_id=command_id,
            rel_type='ALTERNATIVE',
            direction='OUTGOING',
            max_depth=depth,
            return_metadata=True,
            limit=limit
        )

    def shortest_attack_path(
        self,
        start_tag: str = 'STARTER',
        end_tag: str = 'PRIVESC',
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Pattern 2: Find quickest path from enumeration to privilege escalation.

        Use Case: "What's the fastest way to get from nmap to root?"

        Example:
            paths = patterns.shortest_attack_path('STARTER', 'PRIVESC')
            fastest = paths[0]  # Shortest path first

        Args:
            start_tag: Starting tag (e.g., 'STARTER', 'ENUM')
            end_tag: Target tag (e.g., 'PRIVESC', 'EXPLOIT')
            limit: Maximum paths to return

        Returns:
            List of attack paths with step counts
        """
        return self.adapter.find_by_pattern(
            pattern="path = shortestPath((start:Command)-[:NEXT_STEP*]-(end:Command))",
            where_clause=f"start.tags CONTAINS '{start_tag}' AND end.tags CONTAINS '{end_tag}'",
            return_fields=['nodes(path) AS path', 'length(path) AS step_count'],
            limit=limit
        )

    def prerequisite_closure(
        self,
        command_id: str,
        with_execution_order: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Pattern 3: Get ALL prerequisites with execution order.

        Use Case: "What do I need to run BEFORE executing this exploit?"

        Example:
            prereqs = patterns.prerequisite_closure('wordpress-sqli')
            for prereq in prereqs:
                print(f"{prereq['dependency_count']}: {prereq['command_name']}")

        Args:
            command_id: Command to get prerequisites for
            with_execution_order: Include dependency count for ordering

        Returns:
            List of prerequisite commands with execution order
        """
        return self.adapter.find_prerequisites(
            command_id=command_id,
            execution_order=with_execution_order
        )

    def parallel_execution_plan(
        self,
        attack_chain_id: str
    ) -> Dict[str, Any]:
        """
        Pattern 4: Identify which steps can run simultaneously.

        Use Case: "Which enumeration commands can I run in parallel?"

        Example:
            plan = patterns.parallel_execution_plan('linux-privesc-sudo')
            wave1 = plan['parallel_groups'][0]  # No dependencies
            wave2 = plan['parallel_groups'][1]  # Depends on wave1

        Args:
            attack_chain_id: Attack chain to analyze

        Returns:
            Attack chain with parallel execution groups
        """
        return self.adapter.get_attack_chain_path(attack_chain_id)

    def service_recommendations(
        self,
        port_numbers: List[int],
        oscp_only: bool = True,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Pattern 5: Recommend commands for detected services.

        Use Case: "Ports 80, 445, 22 are open. What should I do?"

        Example:
            recs = patterns.service_recommendations([80, 445, 22])
            for rec in recs:
                print(f"{rec['command_name']}: {rec['services']}")

        Args:
            port_numbers: List of open ports
            oscp_only: Filter to high OSCP relevance
            limit: Maximum recommendations

        Returns:
            List of recommended commands with service mapping
        """
        filters = {'p.number': port_numbers}
        if oscp_only:
            filters['c.oscp_relevance'] = 'high'

        return self.adapter.aggregate_by_pattern(
            pattern="(p:Port)<-[:RUNS_ON]-(s:Service)-[:ENUMERATED_BY]->(c:Command)",
            group_by=['c'],
            aggregations={
                'command_id': 'c.id',
                'command_name': 'c.name',
                'services': 'COLLECT(DISTINCT s.name)',
                'service_count': 'COUNT(DISTINCT s)'
            },
            filters=filters,
            order_by='service_count DESC',
            limit=limit
        )

    def filter_by_tag_hierarchy(
        self,
        parent_tags: List[str],
        include_children: bool = True
    ) -> List:
        """
        Pattern 6: Filter commands with tag hierarchy inference.

        Use Case: "Show all OSCP commands (including sub-tags like OSCP:ENUM)"

        Example:
            commands = patterns.filter_by_tag_hierarchy(['OSCP'])
            # Returns commands tagged with OSCP, OSCP:ENUM, OSCP:EXPLOIT, etc.

        Args:
            parent_tags: Parent tag names
            include_children: Include hierarchical children

        Returns:
            List of Command objects
        """
        return self.adapter.filter_by_tags(
            tags=parent_tags,
            include_hierarchy=include_children
        )

    def success_correlation(
        self,
        min_co_occurrence: int = 5,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """
        Pattern 7: Find commands that frequently succeed together.

        Use Case: "What commands typically work on similar targets?"

        Note: Requires Session execution data ([:EXECUTED] relationships)

        Example:
            correlations = patterns.success_correlation(min_co_occurrence=5)
            for corr in correlations:
                print(f"{corr['command_a']} + {corr['command_b']}: {corr['count']}")

        Args:
            min_co_occurrence: Minimum times commands must succeed together
            limit: Maximum correlations to return

        Returns:
            List of command pairs with co-occurrence counts
        """
        return self.adapter.aggregate_by_pattern(
            pattern="""
                (s:Session)-[e1:EXECUTED]->(cmd1:Command),
                (s)-[e2:EXECUTED]->(cmd2:Command)
                WHERE e1.success = true AND e2.success = true AND cmd1.id < cmd2.id
            """,
            group_by=['cmd1', 'cmd2'],
            aggregations={
                'command_a': 'cmd1.name',
                'command_b': 'cmd2.name',
                'co_occurrence': 'COUNT(s)'
            },
            filters={},
            order_by='co_occurrence DESC',
            limit=limit
        )

    def find_coverage_gaps(
        self,
        oscp_only: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Pattern 8: Services lacking enumeration commands.

        Use Case: "Which services don't have good OSCP commands?"

        Example:
            gaps = patterns.find_coverage_gaps()
            for gap in gaps:
                print(f"Missing: {gap['service_name']} (ports: {gap['ports']})")

        Args:
            oscp_only: Only check for high OSCP relevance commands

        Returns:
            List of services with no enumeration commands
        """
        relevance_filter = "WHERE c.oscp_relevance = 'high'" if oscp_only else ""

        return self.adapter.find_by_pattern(
            pattern=f"""
                (s:Service)
                WHERE NOT exists {{
                    MATCH (s)-[:ENUMERATED_BY]->(c:Command)
                    {relevance_filter}
                }}
            """,
            return_fields=[
                's.name AS service_name',
                's.protocol AS protocol',
                '[(s)-[:RUNS_ON]->(p:Port) | p.number] AS ports'
            ],
            limit=50
        )

    def detect_circular_dependencies(
        self,
        chain_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Pattern 9: Find broken attack chains with circular dependencies.

        Use Case: "Are there any cyclic prerequisite chains?"

        Example:
            cycles = patterns.detect_circular_dependencies()
            if cycles:
                print("WARNING: Circular dependencies detected!")
                for cycle in cycles:
                    print(f"  {cycle['circular_steps']}")

        Args:
            chain_id: Optional chain to check (None = check all)

        Returns:
            List of circular dependency paths
        """
        chain_filter = f"WHERE step.chain_id = '{chain_id}'" if chain_id else ""

        return self.adapter.find_by_pattern(
            pattern=f"path = (step:ChainStep)-[:DEPENDS_ON*]->(step) {chain_filter}",
            return_fields=[
                '[s IN nodes(path) | s.id] AS circular_steps',
                'length(path) AS cycle_length'
            ],
            limit=50
        )

    def variable_usage_analysis(
        self,
        variable_name: Optional[str] = None,
        required_only: bool = True,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Pattern 10: Analyze which commands use which variables.

        Use Case: "Which commands need manual configuration (use <TARGET>)?"

        Example:
            # Find most common variables
            vars = patterns.variable_usage_analysis()
            print(f"Most used: {vars[0]['variable_name']} ({vars[0]['usage_count']} commands)")

            # Find commands using specific variable
            target_cmds = patterns.variable_usage_analysis(variable_name='<TARGET>')

        Args:
            variable_name: Optional specific variable to analyze
            required_only: Only count required variables
            limit: Maximum results to return

        Returns:
            List of variables with usage statistics
        """
        filters = {}
        if required_only:
            filters['u.required'] = True
        if variable_name:
            filters['v.name'] = variable_name

        return self.adapter.aggregate_by_pattern(
            pattern="(v:Variable)<-[u:USES_VARIABLE]-(c:Command)",
            group_by=['v'],
            aggregations={
                'variable_name': 'v.name',
                'usage_count': 'COUNT(c)',
                'sample_commands': 'COLLECT(c.id)[0..5]',
                'categories': 'COLLECT(DISTINCT c.category)'
            },
            filters=filters,
            order_by='usage_count DESC',
            limit=limit
        )


def create_pattern_helper(adapter) -> GraphQueryPatterns:
    """
    Factory function to create pattern helper.

    Usage:
        from crack.reference.patterns.advanced_queries import create_pattern_helper

        adapter = Neo4jCommandRegistryAdapter(...)
        patterns = create_pattern_helper(adapter)

        results = patterns.multi_hop_alternatives('gobuster-dir')

    Args:
        adapter: Neo4jCommandRegistryAdapter instance

    Returns:
        GraphQueryPatterns helper instance
    """
    return GraphQueryPatterns(adapter)
