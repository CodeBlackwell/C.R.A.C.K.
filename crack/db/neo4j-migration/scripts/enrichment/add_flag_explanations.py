#!/usr/bin/env python3
"""
Add flag_explanations as JSON properties to Command nodes in Neo4j

This fixes the issue where flag_explanations were incorrectly stored as shared
Flag nodes, causing wrong explanations to appear for commands.
"""
import json
import sys
from pathlib import Path
from neo4j import GraphDatabase

# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from db.config import Neo4jConfig


def load_commands_from_json(commands_dir: Path):
    """Load all commands from JSON files"""
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
                    flag_exp = cmd.get('flag_explanations', {})
                    if cmd_id and flag_exp:
                        commands[cmd_id] = flag_exp
        except Exception as e:
            print(f"Error loading {json_file}: {e}")

    return commands


def update_neo4j_commands(driver, commands_with_flags):
    """Update Neo4j Command nodes with flag_explanations property"""
    updated = 0
    skipped = 0

    with driver.session() as session:
        for cmd_id, flag_explanations in commands_with_flags.items():
            # Convert to JSON string for storage
            flag_json = json.dumps(flag_explanations)

            result = session.run(
                """
                MATCH (cmd:Command {id: $cmd_id})
                SET cmd.flag_explanations = $flag_explanations
                RETURN cmd.id AS id
                """,
                cmd_id=cmd_id,
                flag_explanations=flag_json
            )

            if result.single():
                updated += 1
                print(f"  ✓ Updated {cmd_id}")
            else:
                skipped += 1
                print(f"  ✗ Command not found: {cmd_id}")

    return updated, skipped


def main():
    print("=" * 70)
    print("Add flag_explanations to Neo4j Command nodes")
    print("=" * 70)

    # Load commands from JSON
    commands_dir = Path(__file__).parent.parent.parent.parent / 'reference' / 'data' / 'commands'
    print(f"\n1. Loading commands from: {commands_dir}")
    commands_with_flags = load_commands_from_json(commands_dir)
    print(f"   Found {len(commands_with_flags)} commands with flag_explanations")

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
        updated, skipped = update_neo4j_commands(driver, commands_with_flags)

        print("\n" + "=" * 70)
        print(f"Results:")
        print(f"  Updated: {updated}")
        print(f"  Skipped: {skipped}")
        print("=" * 70)

    finally:
        driver.close()


if __name__ == '__main__':
    main()
