#!/usr/bin/env python3
"""
Neo4j Stats - Quick statistics and error detection for Neo4j database

Usage: python3 neo4j_stats.py [--verbose]
"""

import sys
from typing import Dict, List

# ANSI colors
class Colors:
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    RED = '\033[31m'
    BLUE = '\033[36m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

def get_neo4j_adapter():
    """Get Neo4j adapter instance"""
    try:
        from crack.reference.core import Neo4jCommandRegistryAdapter, ConfigManager, ReferenceTheme

        adapter = Neo4jCommandRegistryAdapter(
            config_manager=ConfigManager(),
            theme=ReferenceTheme()
        )

        if not adapter.health_check():
            print(f"{Colors.RED}✗ Neo4j connection failed{Colors.RESET}")
            print(f"{Colors.YELLOW}  Make sure Neo4j is running: sudo neo4j status{Colors.RESET}")
            return None

        return adapter
    except Exception as e:
        print(f"{Colors.RED}✗ Failed to initialize Neo4j adapter: {e}{Colors.RESET}")
        return None

def run_query(adapter, query: str, description: str = ""):
    """Run query and return results"""
    try:
        results = adapter._execute_read(query)
        return list(results) if results else []
    except Exception as e:
        print(f"{Colors.RED}✗ Query failed ({description}): {e}{Colors.RESET}")
        return []

def main():
    verbose = '--verbose' in sys.argv

    print(f"\n{Colors.BOLD}{'=' * 70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}NEO4J DATABASE - QUICK STATS{Colors.RESET}")
    print(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}\n")

    # Get adapter
    adapter = get_neo4j_adapter()
    if not adapter:
        return 1

    print(f"{Colors.GREEN}✓ Connected to Neo4j{Colors.RESET}\n")

    # Node counts
    print(f"{Colors.BOLD}Node Counts:{Colors.RESET}")

    node_types = [
        'Command', 'Tag', 'Service', 'Port', 'Variable',
        'AttackChain', 'ChainStep', 'Flag', 'FindingType'
    ]

    total_nodes = 0
    for node_type in node_types:
        query = f"MATCH (n:{node_type}) RETURN count(n) AS count"
        results = run_query(adapter, query, f"count {node_type}")
        count = results[0]['count'] if results else 0
        total_nodes += count

        if count > 0:
            print(f"  {node_type:15s} {count:6d}")

    print(f"  {Colors.BOLD}{'Total':15s} {total_nodes:6d}{Colors.RESET}")

    # Relationship counts
    print(f"\n{Colors.BOLD}Relationship Counts:{Colors.RESET}")

    rel_types = [
        'TAGGED', 'ALTERNATIVE', 'PREREQUISITE', 'NEXT_STEP',
        'USES_VARIABLE', 'ENUMERATED_BY', 'RUNS_ON', 'HAS_STEP',
        'DEPENDS_ON', 'CHILD_OF'
    ]

    total_rels = 0
    for rel_type in rel_types:
        query = f"MATCH ()-[r:{rel_type}]->() RETURN count(r) AS count"
        results = run_query(adapter, query, f"count {rel_type}")
        count = results[0]['count'] if results else 0
        total_rels += count

        if count > 0:
            print(f"  {rel_type:20s} {count:6d}")

    print(f"  {Colors.BOLD}{'Total':20s} {total_rels:6d}{Colors.RESET}")

    # Commands by category
    print(f"\n{Colors.BOLD}Commands by Category:{Colors.RESET}")
    query = """
    MATCH (c:Command)
    RETURN c.category AS category, count(c) AS count
    ORDER BY count DESC
    """
    results = run_query(adapter, query, "commands by category")

    cmd_total = sum(r['count'] for r in results)
    for result in results:
        category = result['category'] or 'MISSING'
        count = result['count']
        pct = count / cmd_total * 100 if cmd_total > 0 else 0
        bar = '█' * int(pct / 2)
        print(f"  {category:20s} {count:4d} ({pct:5.1f}%) {Colors.BLUE}{bar}{Colors.RESET}")

    # OSCP relevance
    print(f"\n{Colors.BOLD}OSCP Relevance:{Colors.RESET}")
    query = """
    MATCH (c:Command)
    RETURN c.oscp_relevance AS relevance, count(c) AS count
    ORDER BY
        CASE c.oscp_relevance
            WHEN 'high' THEN 1
            WHEN 'medium' THEN 2
            WHEN 'low' THEN 3
            ELSE 4
        END
    """
    results = run_query(adapter, query, "OSCP relevance")

    for result in results:
        relevance = result['relevance'] or 'MISSING'
        count = result['count']
        pct = count / cmd_total * 100 if cmd_total > 0 else 0
        color = Colors.GREEN if relevance == 'high' else Colors.YELLOW if relevance == 'medium' else Colors.DIM
        print(f"  {relevance:10s} {count:4d} ({pct:5.1f}%) {color}{'█' * int(pct/2)}{Colors.RESET}")

    # Top tags
    print(f"\n{Colors.BOLD}Top 10 Tags:{Colors.RESET}")
    query = """
    MATCH (c:Command)-[:TAGGED]->(t:Tag)
    RETURN t.name AS tag, count(c) AS count
    ORDER BY count DESC
    LIMIT 10
    """
    results = run_query(adapter, query, "top tags")

    for result in results:
        tag = result['tag']
        count = result['count']
        pct = count / cmd_total * 100 if cmd_total > 0 else 0
        print(f"  {tag:25s} {count:4d} ({pct:5.1f}%)")

    # Graph integrity checks
    print(f"\n{Colors.BOLD}Graph Integrity Checks:{Colors.RESET}")

    issues = []

    # Check for orphaned alternatives
    query = """
    MATCH (c1:Command)-[:ALTERNATIVE]->(c2)
    WHERE NOT EXISTS((c2:Command))
    RETURN count(*) AS count
    """
    results = run_query(adapter, query, "orphaned alternatives")
    orphaned_alts = results[0]['count'] if results else 0
    if orphaned_alts > 0:
        issues.append(f"{Colors.RED}✗ Orphaned alternatives: {orphaned_alts}{Colors.RESET}")
    else:
        print(f"  {Colors.GREEN}✓ No orphaned alternatives{Colors.RESET}")

    # Check for self-referencing alternatives
    query = """
    MATCH (c:Command)-[:ALTERNATIVE]->(c)
    RETURN count(*) AS count
    """
    results = run_query(adapter, query, "self-referencing alternatives")
    self_refs = results[0]['count'] if results else 0
    if self_refs > 0:
        issues.append(f"{Colors.RED}✗ Self-referencing alternatives: {self_refs}{Colors.RESET}")
    else:
        print(f"  {Colors.GREEN}✓ No self-referencing alternatives{Colors.RESET}")

    # Check for circular prerequisites (simple)
    query = """
    MATCH path = (c1:Command)-[:PREREQUISITE*2..]->(c1)
    RETURN count(path) AS count
    """
    results = run_query(adapter, query, "circular prerequisites")
    circular = results[0]['count'] if results else 0
    if circular > 0:
        issues.append(f"{Colors.RED}✗ Circular prerequisites: {circular}{Colors.RESET}")
    else:
        print(f"  {Colors.GREEN}✓ No circular prerequisites{Colors.RESET}")

    # Check for commands without tags
    query = """
    MATCH (c:Command)
    WHERE NOT EXISTS((c)-[:TAGGED]->())
    RETURN count(c) AS count
    """
    results = run_query(adapter, query, "untagged commands")
    untagged = results[0]['count'] if results else 0
    if untagged > 0:
        issues.append(f"{Colors.YELLOW}⚠ Commands without tags: {untagged}{Colors.RESET}")
    else:
        print(f"  {Colors.GREEN}✓ All commands have tags{Colors.RESET}")

    # Verbose mode - show examples
    if verbose and issues:
        print(f"\n{Colors.BOLD}Issue Details (--verbose):{Colors.RESET}")

        # Show orphaned alternatives
        if orphaned_alts > 0:
            print(f"\n  {Colors.YELLOW}Orphaned alternatives:{Colors.RESET}")
            query = """
            MATCH (c1:Command)-[r:ALTERNATIVE]->(c2)
            WHERE NOT EXISTS((c2:Command))
            RETURN c1.id AS from_cmd, c1.name AS from_name
            LIMIT 5
            """
            results = run_query(adapter, query)
            for r in results:
                print(f"    {r['from_cmd']}: {r['from_name']}")

        # Show circular prerequisites
        if circular > 0:
            print(f"\n  {Colors.YELLOW}Circular prerequisites:{Colors.RESET}")
            query = """
            MATCH path = (c1:Command)-[:PREREQUISITE*2..5]->(c1)
            RETURN c1.id AS cmd, [n IN nodes(path) | n.id] AS cycle
            LIMIT 3
            """
            results = run_query(adapter, query)
            for r in results:
                cycle_str = ' → '.join(r['cycle'])
                print(f"    {cycle_str}")

    # Graph patterns test
    print(f"\n{Colors.BOLD}Graph Pattern Support:{Colors.RESET}")

    # Test multi-hop alternatives
    query = """
    MATCH (start:Command {id: 'gobuster-dir'})
    MATCH path = (start)-[:ALTERNATIVE*1..3]->(alt)
    RETURN count(path) AS count
    """
    results = run_query(adapter, query, "multi-hop alternatives")
    multi_hop = results[0]['count'] if results else 0
    status = Colors.GREEN if multi_hop > 0 else Colors.YELLOW
    print(f"  {status}Multi-hop alternatives: {multi_hop} paths{Colors.RESET}")

    # Test tag hierarchy
    query = """
    MATCH (parent:Tag {name: 'OSCP'})
    MATCH (child:Tag)-[:CHILD_OF*]->(parent)
    RETURN count(child) AS count
    """
    results = run_query(adapter, query, "tag hierarchy")
    tag_children = results[0]['count'] if results else 0
    status = Colors.GREEN if tag_children > 0 else Colors.YELLOW
    print(f"  {status}Tag hierarchy depth: {tag_children} child tags{Colors.RESET}")

    # Test attack chains
    query = """
    MATCH (ac:AttackChain)
    RETURN count(ac) AS count
    """
    results = run_query(adapter, query, "attack chains")
    chains = results[0]['count'] if results else 0
    status = Colors.GREEN if chains > 0 else Colors.YELLOW
    print(f"  {status}Attack chains: {chains}{Colors.RESET}")

    # Summary
    print(f"\n{Colors.BOLD}{'=' * 70}{Colors.RESET}")

    if cmd_total == 0:
        print(f"{Colors.RED}✗ Database is empty - no commands loaded{Colors.RESET}")
        print(f"{Colors.YELLOW}  Run migration script to populate from JSON{Colors.RESET}")
    elif cmd_total < 100:
        print(f"{Colors.YELLOW}⚠ Database has limited data ({cmd_total} commands){Colors.RESET}")
        print(f"{Colors.YELLOW}  Expected: 795 commands from JSON files{Colors.RESET}")
    elif issues:
        print(f"{Colors.YELLOW}⚠ Database has {len(issues)} integrity issues{Colors.RESET}")
        for issue in issues:
            print(f"  {issue}")
    else:
        print(f"{Colors.GREEN}✓ Database healthy - {cmd_total} commands loaded{Colors.RESET}")

    print(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}\n")

    return 0

if __name__ == '__main__':
    sys.exit(main())
