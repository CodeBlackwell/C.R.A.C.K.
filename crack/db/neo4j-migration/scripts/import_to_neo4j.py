#!/usr/bin/env python3
"""
Import CSV files into Neo4j using parameterized Cypher queries

Reads CSV files using Python's csv.DictReader and uses parameterized Cypher
queries to avoid CSV escaping issues with complex quoted strings.
"""

import os
import sys
import csv
import time
from pathlib import Path
from typing import Dict, Any, List
import argparse

try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False


def get_neo4j_config() -> Dict[str, str]:
    """Get Neo4j connection configuration"""
    return {
        'uri': os.getenv('NEO4J_URI', 'bolt://localhost:7687'),
        'user': os.getenv('NEO4J_USER', 'neo4j'),
        'password': os.getenv('NEO4J_PASSWORD', 'crack_password')
    }


def wait_for_neo4j(driver, timeout: int = 30) -> bool:
    """Poll Neo4j until ready or timeout"""
    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            with driver.session() as session:
                result = session.run("RETURN 1 AS test")
                result.single()
                print("Neo4j is ready!")
                return True
        except Exception as e:
            print(f"Waiting for Neo4j... ({int(time.time() - start_time)}s)")
            time.sleep(2)

    return False


def load_csv_file(csv_path: str) -> List[Dict[str, Any]]:
    """
    Load CSV file using Python's csv.DictReader

    Handles proper CSV parsing with quoted fields containing special characters.
    """
    rows = []
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(row)
    except Exception as e:
        print(f"ERROR reading CSV {csv_path}: {e}")
        raise

    return rows


def import_nodes(driver, node_type: str, csv_path: str, id_field: str, properties: Dict[str, str] = None, batch_size: int = 1000) -> int:
    """
    Import nodes from CSV using parameterized Cypher queries

    Args:
        driver: Neo4j driver instance
        node_type: Node label (e.g., 'Command', 'Tag', 'Variable')
        csv_path: Path to CSV file
        id_field: Field name to use as unique identifier (e.g., 'id', 'name')
        properties: Optional property mapping (unused, for compatibility)
        batch_size: Number of rows per transaction

    Reads CSV file with Python and uses UNWIND + parameterized queries
    to handle complex quoted strings without escaping issues.
    """
    rows = load_csv_file(csv_path)
    if not rows:
        print(f"  WARNING: No rows in {csv_path}")
        return 0

    created_count = 0

    with driver.session() as session:
        batch = []
        for row in rows:
            batch.append(row)

            if len(batch) >= batch_size:
                created_count += _create_node_batch(session, node_type, batch, id_field)
                batch = []

        if batch:
            created_count += _create_node_batch(session, node_type, batch, id_field)

    return created_count


def _create_node_batch(session, node_type: str, rows: List[Dict[str, Any]], id_field: str) -> int:
    """Create batch of nodes in single transaction

    Args:
        session: Neo4j session
        node_type: Node label
        rows: List of row dictionaries
        id_field: Field name to use as unique identifier
    """
    if not rows:
        return 0

    query = f"""
    UNWIND $rows AS row
    MERGE (n:{node_type} {{{id_field}: row.{id_field}}})
    SET n += row
    RETURN count(n) AS created
    """

    result = session.run(query, rows=rows)
    record = result.single()
    return record['created'] if record else 0


def import_relationships(driver, rel_type: str, csv_path: str, start_label: str, end_label: str,
                        start_id_col: str, end_id_col: str, start_id_field: str = 'id', end_id_field: str = 'id',
                        properties: Dict[str, str] = None, batch_size: int = 1000) -> int:
    """
    Import relationships from CSV using parameterized Cypher queries

    Args:
        driver: Neo4j driver instance
        rel_type: Relationship type (e.g., 'USES_VARIABLE', 'PREREQUISITE')
        csv_path: Path to CSV file
        start_label: Start node label
        end_label: End node label
        start_id_col: CSV column name containing start node ID
        end_id_col: CSV column name containing end node ID
        start_id_field: Field name in start node (default 'id')
        end_id_field: Field name in end node (default 'id')
        properties: Optional property mapping (unused, for compatibility)
        batch_size: Number of rows per transaction

    Reads CSV file with Python and uses UNWIND + parameterized queries
    to handle complex quoted strings without escaping issues.
    """
    rows = load_csv_file(csv_path)
    if not rows:
        print(f"  WARNING: No rows in {csv_path}")
        return 0

    created_count = 0

    with driver.session() as session:
        batch = []
        for row in rows:
            batch.append(row)

            if len(batch) >= batch_size:
                created_count += _create_relationship_batch(
                    session, rel_type, batch,
                    start_label, end_label,
                    start_id_col, end_id_col,
                    start_id_field, end_id_field
                )
                batch = []

        if batch:
            created_count += _create_relationship_batch(
                session, rel_type, batch,
                start_label, end_label,
                start_id_col, end_id_col,
                start_id_field, end_id_field
            )

    return created_count


def _create_relationship_batch(session, rel_type: str, rows: List[Dict[str, Any]],
                              start_label: str, end_label: str,
                              start_id_col: str, end_id_col: str,
                              start_id_field: str = 'id', end_id_field: str = 'id') -> int:
    """Create batch of relationships in single transaction

    Args:
        session: Neo4j session
        rel_type: Relationship type
        rows: List of row dictionaries
        start_label: Start node label
        end_label: End node label
        start_id_col: CSV column name for start node ID
        end_id_col: CSV column name for end node ID
        start_id_field: Field name in start node for matching
        end_id_field: Field name in end node for matching
    """
    if not rows:
        return 0

    query = f"""
    UNWIND $rows AS row
    MATCH (start:{start_label} {{{start_id_field}: row.{start_id_col}}})
    MATCH (end:{end_label} {{{end_id_field}: row.{end_id_col}}})
    MERGE (start)-[r:{rel_type}]->(end)
    SET r += row
    RETURN count(r) AS created
    """

    result = session.run(query, rows=rows)
    record = result.single()
    return record['created'] if record else 0


def validate_import(driver) -> Dict[str, int]:
    """Query Neo4j to get node/relationship counts"""
    counts = {}

    with driver.session() as session:
        # Count nodes by label
        result = session.run("""
            CALL db.labels() YIELD label
            CALL apoc.cypher.run('MATCH (n:' + label + ') RETURN count(n) AS count', {})
            YIELD value
            RETURN label, value.count AS count
        """)

        for record in result:
            counts[f"nodes_{record['label']}"] = record['count']

        # Count relationships by type
        result = session.run("""
            CALL db.relationshipTypes() YIELD relationshipType
            CALL apoc.cypher.run('MATCH ()-[r:' + relationshipType + ']->() RETURN count(r) AS count', {})
            YIELD value
            RETURN relationshipType, value.count AS count
        """)

        for record in result:
            counts[f"rels_{record['relationshipType']}"] = record['count']

    return counts


def import_all_to_neo4j(csv_dir: str, neo4j_config: Dict, batch_size: int = 1000,
                        skip_validation: bool = False) -> bool:
    """Orchestrate full import pipeline using parameterized queries"""

    if not NEO4J_AVAILABLE:
        print("ERROR: neo4j Python driver not installed")
        print("Install with: pip install neo4j")
        return False

    csv_path = Path(csv_dir)
    if not csv_path.exists():
        print(f"ERROR: CSV directory not found: {csv_dir}")
        return False

    print()
    print("Connecting to Neo4j...")
    try:
        driver = GraphDatabase.driver(
            neo4j_config['uri'],
            auth=(neo4j_config['user'], neo4j_config['password'])
        )
    except Exception as e:
        print(f"ERROR connecting to Neo4j: {e}")
        print("\nIs Neo4j running? Start with: sudo systemctl start neo4j")
        return False

    if not wait_for_neo4j(driver):
        print("ERROR: Neo4j did not become ready within timeout")
        driver.close()
        return False

    print()
    print("Starting import...")
    print()

    try:
        print("Importing nodes...")

        print("  Commands...")
        import_nodes(driver, 'Command', str(csv_path / 'commands.csv'), id_field='id', batch_size=batch_size)

        print("  Tags...")
        import_nodes(driver, 'Tag', str(csv_path / 'tags.csv'), id_field='name', batch_size=batch_size)

        print("  Variables...")
        import_nodes(driver, 'Variable', str(csv_path / 'variables.csv'), id_field='name', batch_size=batch_size)

        print("  Flags...")
        import_nodes(driver, 'Flag', str(csv_path / 'flags.csv'), id_field='id', batch_size=batch_size)

        print("  Indicators...")
        import_nodes(driver, 'Indicator', str(csv_path / 'indicators.csv'), id_field='id', batch_size=batch_size)

        print("  Attack Chains...")
        import_nodes(driver, 'AttackChain', str(csv_path / 'attack_chains.csv'), id_field='id', batch_size=batch_size)

        print("  Chain Steps...")
        import_nodes(driver, 'ChainStep', str(csv_path / 'chain_steps.csv'), id_field='id', batch_size=batch_size)

        print()
        print("Importing relationships...")

        print("  Command -> Variable...")
        import_relationships(driver, 'USES_VARIABLE', str(csv_path / 'command_has_variable.csv'),
                           'Command', 'Variable', 'command_id', 'variable_id',
                           start_id_field='id', end_id_field='name', batch_size=batch_size)

        print("  Command -> Flag...")
        import_relationships(driver, 'HAS_FLAG', str(csv_path / 'command_has_flag.csv'),
                           'Command', 'Flag', 'command_id', 'flag_id',
                           start_id_field='id', end_id_field='id', batch_size=batch_size)

        print("  Command -> Indicator...")
        import_relationships(driver, 'HAS_INDICATOR', str(csv_path / 'command_has_indicator.csv'),
                           'Command', 'Indicator', 'command_id', 'indicator_id',
                           start_id_field='id', end_id_field='id', batch_size=batch_size)

        print("  Command -> Tag...")
        import_relationships(driver, 'TAGGED', str(csv_path / 'command_tagged_with.csv'),
                           'Command', 'Tag', 'command_id', 'tag_name',
                           start_id_field='id', end_id_field='name', batch_size=batch_size)

        print("  Command -> Alternative Command...")
        import_relationships(driver, 'ALTERNATIVE', str(csv_path / 'command_alternative_for.csv'),
                           'Command', 'Command', 'command_id', 'alternative_command_id',
                           start_id_field='id', end_id_field='id', batch_size=batch_size)

        print("  Command -> Prerequisite Command...")
        import_relationships(driver, 'PREREQUISITE', str(csv_path / 'command_requires.csv'),
                           'Command', 'Command', 'command_id', 'prerequisite_command_id',
                           start_id_field='id', end_id_field='id', batch_size=batch_size)

        print("  Chain -> Step...")
        import_relationships(driver, 'HAS_STEP', str(csv_path / 'chain_contains_step.csv'),
                           'AttackChain', 'ChainStep', 'chain_id', 'step_id',
                           start_id_field='id', end_id_field='id', batch_size=batch_size)

        print("  Step -> Command...")
        import_relationships(driver, 'EXECUTES', str(csv_path / 'step_uses_command.csv'),
                           'ChainStep', 'Command', 'step_id', 'command_id',
                           start_id_field='id', end_id_field='id', batch_size=batch_size)

        print("  Chain -> Tag...")
        import_relationships(driver, 'TAGGED', str(csv_path / 'chain_tagged_with.csv'),
                           'AttackChain', 'Tag', 'chain_id', 'tag_name',
                           start_id_field='id', end_id_field='name', batch_size=batch_size)

        print()
        print("Import complete!")

        # 3. Validation
        if not skip_validation:
            print()
            print("Validating import...")
            try:
                counts = validate_import(driver)
                print("\nNode counts:")
                for label, count in sorted(counts.items()):
                    if label.startswith('nodes_'):
                        print(f"  {label.replace('nodes_', '')}: {count}")

                print("\nRelationship counts:")
                for rel_type, count in sorted(counts.items()):
                    if rel_type.startswith('rels_'):
                        print(f"  {rel_type.replace('rels_', '')}: {count}")

            except Exception as e:
                print(f"WARNING: Validation requires APOC plugin: {e}")
                print("Install APOC: https://neo4j.com/labs/apoc/")

        return True

    except Exception as e:
        print(f"\nERROR during import: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        driver.close()


def main():
    parser = argparse.ArgumentParser(
        description="Import CSV files into Neo4j using parameterized queries"
    )
    parser.add_argument(
        '--csv-dir',
        default='db/neo4j-migration/data/neo4j',
        help='CSV directory (default: db/neo4j-migration/data/neo4j/)'
    )
    parser.add_argument(
        '--batch-size',
        type=int,
        default=1000,
        help='Batch size for import transactions (default: 1000)'
    )
    parser.add_argument(
        '--skip-validation',
        action='store_true',
        help='Skip post-import validation'
    )

    args = parser.parse_args()

    if os.path.isabs(args.csv_dir):
        csv_dir = Path(args.csv_dir)
    else:
        csv_dir = Path.cwd() / args.csv_dir

    neo4j_config = get_neo4j_config()

    print("=" * 60)
    print("Neo4j CSV Import (Parameterized Queries)")
    print("=" * 60)
    print(f"CSV source: {csv_dir}")
    print(f"Neo4j URI: {neo4j_config['uri']}")
    print(f"Batch size: {args.batch_size}")
    print()

    success = import_all_to_neo4j(
        str(csv_dir),
        neo4j_config,
        args.batch_size,
        args.skip_validation
    )

    if success:
        print()
        print("=" * 60)
        print("Import successful!")
        print("=" * 60)
        print("Verify in Neo4j Browser: http://localhost:7474")
        print("Example query: MATCH (c:Command) RETURN count(c)")
        return 0
    else:
        print()
        print("=" * 60)
        print("Import failed!")
        print("=" * 60)
        return 1


if __name__ == '__main__':
    sys.exit(main())
