"""
Graph Primitives Usage Examples

This file demonstrates how to use the three graph primitives added to
Neo4jCommandRegistryAdapter for advanced graph queries.

Author: Claude Code
Date: 2025-11-08
File: reference/core/neo4j_adapter.py (lines 798-1085)
"""

from reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter


def example_1_find_alternatives():
    """
    Example 1: Find multi-hop alternative commands

    Use Case: "If gobuster fails, try ffuf. If ffuf fails, try wfuzz."
    Replaces Pattern 1 from 06-ADVANCED-QUERIES.md
    """
    adapter = Neo4jCommandRegistryAdapter()

    # Find alternatives up to 3 hops deep
    alternatives = adapter.traverse_graph(
        start_node_id='gobuster-dir',
        rel_type='ALTERNATIVE',
        direction='OUTGOING',
        max_depth=3,
        filters={'oscp_relevance': 'high'},
        return_metadata=False,  # Just get Command objects
        limit=20
    )

    print(f"Found {len(alternatives)} alternatives for gobuster-dir")
    for cmd in alternatives:
        print(f"  - {cmd.name}: {cmd.description}")


def example_2_find_prerequisites():
    """
    Example 2: Find all prerequisite commands

    Use Case: "What do I need to run BEFORE executing this exploit?"
    Replaces Pattern 3 from 06-ADVANCED-QUERIES.md
    """
    adapter = Neo4jCommandRegistryAdapter()

    # Find prerequisites (reverse direction)
    prereqs = adapter.traverse_graph(
        start_node_id='wordpress-sqli',
        rel_type='PREREQUISITE',
        direction='INCOMING',
        max_depth=5,
        return_metadata=True  # Include relationship metadata
    )

    print(f"Prerequisites for wordpress-sqli:")
    for item in prereqs:
        cmd = item['command']
        depth = item['depth']
        print(f"  Depth {depth}: {cmd.name}")


def example_3_tag_analysis():
    """
    Example 3: Aggregate commands by tag

    Use Case: "Which tags are most common?"
    Replaces Pattern 10 from 06-ADVANCED-QUERIES.md
    """
    adapter = Neo4jCommandRegistryAdapter()

    # Find most common tags
    results = adapter.aggregate_by_pattern(
        pattern="(c:Command)-[:TAGGED]->(t:Tag)",
        group_by=['t'],
        aggregations={
            'tag_name': 't.name',
            'count': 'COUNT(c)',
            'commands': 'COLLECT(c.id)'
        },
        order_by='count DESC',
        limit=10
    )

    print("Top 10 most common tags:")
    for row in results:
        print(f"  {row['tag_name']}: {row['count']} commands")


def example_4_service_recommendations():
    """
    Example 4: Service-based attack recommendations

    Use Case: "Ports 80, 445, and 22 are open. What should I do?"
    Replaces Pattern 5 from 06-ADVANCED-QUERIES.md
    """
    adapter = Neo4jCommandRegistryAdapter()

    # Get OSCP-relevant commands for detected services
    recommendations = adapter.aggregate_by_pattern(
        pattern="(s:Service)-[:ENUMERATED_BY]->(c:Command)",
        group_by=['s', 'c'],
        aggregations={
            'service': 's.name',
            'command_id': 'c.id',
            'command_name': 'c.name',
            'priority': 'c.priority'
        },
        filters={'c.oscp_relevance': 'high'},
        order_by='priority ASC',
        limit=20
    )

    print("Service-based recommendations:")
    for row in recommendations:
        print(f"  [{row['service']}] {row['command_name']} (priority: {row['priority']})")


def example_5_circular_dependencies():
    """
    Example 5: Detect circular dependencies in attack chains

    Use Case: "Find broken attack chains with circular dependencies"
    Replaces Pattern 9 from 06-ADVANCED-QUERIES.md
    """
    adapter = Neo4jCommandRegistryAdapter()

    # Find cycles in step dependencies
    cycles = adapter.find_by_pattern(
        pattern="(s:ChainStep)-[:DEPENDS_ON*]->(s)",
        return_fields=['s.id', 's.name', 'length(path) as cycle_length'],
        limit=10
    )

    if cycles:
        print("WARNING: Circular dependencies detected!")
        for cycle in cycles:
            print(f"  {cycle['s.name']} (length: {cycle['cycle_length']})")
    else:
        print("No circular dependencies found.")


def example_6_shortest_path():
    """
    Example 6: Find shortest attack path

    Use Case: "What's the quickest way to get from nmap to privesc?"
    Replaces Pattern 2 from 06-ADVANCED-QUERIES.md
    """
    adapter = Neo4jCommandRegistryAdapter()

    # Find shortest path using shortestPath function
    paths = adapter.find_by_pattern(
        pattern="""
        shortestPath(
            (start:Command {id: 'nmap-quick-scan'})-[:NEXT_STEP*..10]->
            (end:Command)-[:TAGGED]->(:Tag {name: 'PRIVESC'})
        )
        """,
        where_clause="ALL(node IN nodes(path) WHERE node.oscp_relevance = 'high')",
        return_fields=['nodes(path) as commands', 'length(path) as steps'],
        limit=5
    )

    print("Shortest attack paths:")
    for path in paths:
        print(f"  {path['steps']} steps: {' -> '.join([n['name'] for n in path['commands']])}")


def example_7_gap_detection():
    """
    Example 7: Find services without enumeration commands

    Use Case: "Which services lack OSCP-relevant commands?"
    Replaces Pattern 8 from 06-ADVANCED-QUERIES.md
    """
    adapter = Neo4jCommandRegistryAdapter()

    # Find services without high-OSCP enumeration commands
    gaps = adapter.find_by_pattern(
        pattern="(s:Service)",
        where_clause="NOT exists((s)-[:ENUMERATED_BY]->(:Command {oscp_relevance: 'high'}))",
        return_fields=['s.name', 's.protocol'],
        limit=20
    )

    print("Services lacking OSCP-relevant commands:")
    for gap in gaps:
        print(f"  {gap['s.name']} ({gap['s.protocol']})")


def example_8_variable_usage():
    """
    Example 8: Analyze variable usage across commands

    Use Case: "Which commands need manual configuration?"
    Replaces Pattern 10 from 06-ADVANCED-QUERIES.md
    """
    adapter = Neo4jCommandRegistryAdapter()

    # Find most common variables
    results = adapter.aggregate_by_pattern(
        pattern="(c:Command)-[u:USES_VARIABLE]->(v:Variable)",
        group_by=['v'],
        aggregations={
            'variable': 'v.name',
            'usage_count': 'COUNT(c)',
            'categories': 'COLLECT(DISTINCT c.category)'
        },
        filters={'u.required': True},
        order_by='usage_count DESC',
        limit=10
    )

    print("Most common required variables:")
    for row in results:
        print(f"  {row['variable']}: used {row['usage_count']} times")
        print(f"    Categories: {', '.join(row['categories'])}")


# ===== Performance Comparison =====

def compare_performance():
    """
    Compare old hardcoded methods vs new primitives
    """
    import time

    adapter = Neo4jCommandRegistryAdapter()

    # Old method (hardcoded)
    start = time.time()
    old_result = adapter.find_alternatives('gobuster-dir', max_depth=3)
    old_time = time.time() - start

    # New primitive
    start = time.time()
    new_result = adapter.traverse_graph(
        'gobuster-dir',
        'ALTERNATIVE',
        'OUTGOING',
        max_depth=3
    )
    new_time = time.time() - start

    print(f"Old method: {len(old_result)} results in {old_time*1000:.2f}ms")
    print(f"New primitive: {len(new_result)} results in {new_time*1000:.2f}ms")
    print(f"Performance: {old_time/new_time:.2f}x {'faster' if new_time < old_time else 'slower'}")


# ===== Main Runner =====

if __name__ == '__main__':
    print("=== Graph Primitives Examples ===\n")

    examples = [
        ("Multi-hop Alternatives", example_1_find_alternatives),
        ("Prerequisites Chain", example_2_find_prerequisites),
        ("Tag Analysis", example_3_tag_analysis),
        ("Service Recommendations", example_4_service_recommendations),
        ("Circular Dependencies", example_5_circular_dependencies),
        ("Shortest Path", example_6_shortest_path),
        ("Gap Detection", example_7_gap_detection),
        ("Variable Usage", example_8_variable_usage),
    ]

    for name, func in examples:
        print(f"\n--- {name} ---")
        try:
            func()
        except Exception as e:
            print(f"Error: {e}")

    print("\n--- Performance Comparison ---")
    try:
        compare_performance()
    except Exception as e:
        print(f"Error: {e}")
