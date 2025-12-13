#!/usr/bin/env python3
"""
Add educational metadata fields to Command nodes in Neo4j

Migrates these fields from JSON to Neo4j as JSON properties:
- advantages, disadvantages, use_cases, comparison
- output_analysis, common_uses, references
"""
import json
import sys
from pathlib import Path
from neo4j import GraphDatabase

# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from db.config import Neo4jConfig


def load_commands_from_json(commands_dir: Path):
    """Load all commands with educational fields from JSON files"""
    commands = {}

    for json_file in commands_dir.rglob('*.json'):
        if '.backups' in str(json_file) or json_file.name.endswith('.bak'):
            continue

        try:
            with open(json_file, 'r') as f:
                data = json.load(f)

            if isinstance(data, dict) and 'commands' in data:
                for cmd in data['commands']:
                    cmd_id = cmd.get('id')
                    if not cmd_id:
                        continue

                    # Extract educational fields
                    educational_data = {}

                    # List fields
                    for field in ['advantages', 'disadvantages', 'use_cases',
                                  'output_analysis', 'common_uses', 'references',
                                  'alternatives', 'prerequisites', 'next_steps']:
                        if field in cmd and cmd[field]:
                            educational_data[field] = cmd[field]

                    # Dict fields
                    if 'troubleshooting' in cmd and cmd['troubleshooting']:
                        educational_data['troubleshooting'] = cmd['troubleshooting']

                    if educational_data:
                        commands[cmd_id] = educational_data
        except Exception as e:
            print(f"  ✗ Error loading {json_file}: {e}")

    return commands


def update_neo4j_commands(driver, commands_with_fields):
    """Update Neo4j Command nodes with educational fields"""
    updated = 0
    skipped = 0

    with driver.session() as session:
        for cmd_id, educational_data in commands_with_fields.items():
            # Build SET clause dynamically for fields that exist
            set_clauses = []
            params = {'cmd_id': cmd_id}

            for field, value in educational_data.items():
                set_clauses.append(f"cmd.{field} = ${field}")
                params[field] = json.dumps(value)

            if not set_clauses:
                continue

            cypher = f"""
            MATCH (cmd:Command {{id: $cmd_id}})
            SET {', '.join(set_clauses)}
            RETURN cmd.id AS id
            """

            result = session.run(cypher, **params)

            if result.single():
                updated += 1
                fields_list = ', '.join(educational_data.keys())
                print(f"  ✓ {cmd_id} [{fields_list}]")
            else:
                skipped += 1
                print(f"  ✗ Command not found: {cmd_id}")

    return updated, skipped


def main():
    print("=" * 70)
    print("Add educational metadata fields to Neo4j Command nodes")
    print("=" * 70)

    # Load commands from JSON
    commands_dir = Path(__file__).parent.parent.parent.parent / 'reference' / 'data' / 'commands'
    print(f"\n1. Loading commands from: {commands_dir}")
    commands_with_fields = load_commands_from_json(commands_dir)
    print(f"   Found {len(commands_with_fields)} commands with educational fields")

    # Count field usage
    field_counts = {
        'advantages': 0, 'disadvantages': 0, 'use_cases': 0,
        'output_analysis': 0, 'common_uses': 0, 'references': 0,
        'alternatives': 0, 'prerequisites': 0, 'next_steps': 0,
        'troubleshooting': 0
    }
    for data in commands_with_fields.values():
        for field in field_counts.keys():
            if field in data:
                field_counts[field] += 1

    print(f"\n   Field usage:")
    for field, count in field_counts.items():
        print(f"     {field}: {count}")

    # Connect to Neo4j
    print("\n2. Connecting to Neo4j...")
    config = Neo4jConfig.from_env()
    driver = GraphDatabase.driver(config.uri, auth=(config.user, config.password))

    try:
        # Test connection
        with driver.session() as session:
            result = session.run("RETURN 1 AS test")
            result.single()
        print("   ✓ Connected successfully")

        # Update commands
        print("\n3. Updating Command nodes...")
        updated, skipped = update_neo4j_commands(driver, commands_with_fields)

        print("\n" + "=" * 70)
        print(f"Results:")
        print(f"  Updated: {updated}")
        print(f"  Skipped: {skipped}")
        print("=" * 70)

    finally:
        driver.close()


if __name__ == '__main__':
    main()
