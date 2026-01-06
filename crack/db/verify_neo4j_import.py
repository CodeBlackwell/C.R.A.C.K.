#!/usr/bin/env python3
"""
Verify Neo4j import by counting nodes and relationships
"""

from neo4j import GraphDatabase
import os

def get_neo4j_config():
    """Get Neo4j connection configuration"""
    return {
        'uri': os.getenv('NEO4J_URI', 'bolt://localhost:7687'),
        'user': os.getenv('NEO4J_USER', 'neo4j'),
        'password': os.getenv('NEO4J_PASSWORD', '')
    }

def verify_import():
    """Verify the Neo4j import"""
    config = get_neo4j_config()
    driver = GraphDatabase.driver(config['uri'], auth=(config['user'], config['password']))

    try:
        with driver.session() as session:
            print("=" * 60)
            print("NEO4J IMPORT VERIFICATION")
            print("=" * 60)
            print()

            # Count nodes by label
            print("NODE COUNTS:")
            print("-" * 60)

            node_labels = [
                'Command', 'AttackChain', 'Cheatsheet', 'Tag',
                'Variable', 'Flag', 'Indicator', 'ChainStep',
                'Writeup', 'CVE', 'Technique', 'Platform', 'Skill'
            ]

            total_nodes = 0
            for label in node_labels:
                result = session.run(f"MATCH (n:{label}) RETURN count(n) as count")
                count = result.single()['count']
                total_nodes += count
                print(f"  {label:20} {count:>6,}")

            print("-" * 60)
            print(f"  {'TOTAL':20} {total_nodes:>6,}")
            print()

            # Count relationships by type
            print("RELATIONSHIP COUNTS:")
            print("-" * 60)

            relationship_types = [
                'USES_VARIABLE', 'HAS_FLAG', 'HAS_INDICATOR', 'TAGGED',
                'ALTERNATIVE', 'PREREQUISITE', 'HAS_STEP', 'EXECUTES',
                'REFERENCES_COMMAND', 'DEMONSTRATES', 'FAILED_ATTEMPT',
                'EXPLOITS_CVE', 'TEACHES_TECHNIQUE', 'FROM_PLATFORM',
                'REQUIRES_SKILL', 'TEACHES_SKILL'
            ]

            total_rels = 0
            for rel_type in relationship_types:
                result = session.run(f"MATCH ()-[r:{rel_type}]->() RETURN count(r) as count")
                count = result.single()['count']
                total_rels += count
                if count > 0:  # Only show relationships with data
                    print(f"  {rel_type:25} {count:>6,}")

            print("-" * 60)
            print(f"  {'TOTAL':25} {total_rels:>6,}")
            print()

            # Sample queries
            print("SAMPLE QUERIES:")
            print("-" * 60)

            # Find commands with most alternatives
            print("\nTop 5 Commands with Most Alternatives:")
            result = session.run("""
                MATCH (c:Command)-[:ALTERNATIVE]->(alt:Command)
                WITH c, count(alt) as alt_count
                ORDER BY alt_count DESC
                LIMIT 5
                RETURN c.id as command, alt_count
            """)
            for record in result:
                print(f"  {record['command']:40} {record['alt_count']:>3} alternatives")

            # Find commands with most prerequisites
            print("\nTop 5 Commands with Most Prerequisites:")
            result = session.run("""
                MATCH (c:Command)-[:PREREQUISITE]->(pre:Command)
                WITH c, count(pre) as pre_count
                ORDER BY pre_count DESC
                LIMIT 5
                RETURN c.id as command, pre_count
            """)
            for record in result:
                print(f"  {record['command']:40} {record['pre_count']:>3} prerequisites")

            # Find most referenced commands in cheatsheets
            print("\nTop 5 Most Referenced Commands (Cheatsheets):")
            result = session.run("""
                MATCH (cs:Cheatsheet)-[:REFERENCES_COMMAND]->(c:Command)
                WITH c, count(cs) as ref_count
                ORDER BY ref_count DESC
                LIMIT 5
                RETURN c.id as command, ref_count
            """)
            for record in result:
                print(f"  {record['command']:40} {record['ref_count']:>3} references")

            # Find OSCP:HIGH priority commands
            print("\nOSCP:HIGH Priority Commands:")
            result = session.run("""
                MATCH (c:Command)-[:TAGGED]->(t:Tag {name: 'OSCP:HIGH'})
                RETURN count(c) as high_priority_count
            """)
            count = result.single()['high_priority_count']
            print(f"  Total OSCP:HIGH commands: {count}")

            # Writeup statistics
            print("\nWriteup Statistics:")
            result = session.run("""
                MATCH (w:Writeup)-[d:DEMONSTRATES]->(c:Command)
                RETURN w.name as writeup, count(c) as commands_used
                ORDER BY commands_used DESC
            """)
            for record in result:
                print(f"  {record['writeup']:30} {record['commands_used']:>3} commands demonstrated")

            print()
            print("=" * 60)
            print("VERIFICATION COMPLETE")
            print("=" * 60)
            print()
            print("Access Neo4j Browser: http://localhost:7474")
            print("Username: neo4j")
            print("Password: (set via NEO4J_PASSWORD env var)")
            print()

    finally:
        driver.close()

if __name__ == '__main__':
    verify_import()
