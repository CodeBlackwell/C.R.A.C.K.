#!/usr/bin/env python3
"""
CRACK Neo4j Migration - Single unified script.

Usage:
    python migrate.py                    # Full pipeline: transform + import
    python migrate.py --transform-only   # Just generate CSVs
    python migrate.py --import-only      # Just import existing CSVs
    python migrate.py --check            # Health check after import
"""

import argparse
import os
import sys
from pathlib import Path

# Resolve paths relative to this script
SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = SCRIPT_DIR.parent.parent.parent  # crack/
NEO4J_MIGRATION = SCRIPT_DIR.parent  # neo4j-migration/

# Default paths
DEFAULT_INPUT = PROJECT_ROOT / "db" / "data"
DEFAULT_OUTPUT = NEO4J_MIGRATION / "data" / "neo4j"
DEFAULT_SCHEMA = NEO4J_MIGRATION / "schema" / "neo4j_schema.yaml"

# Neo4j connection defaults
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "Neo4j123")


def transform(input_dir: Path, output_dir: Path, validate: bool = True) -> bool:
    """Transform JSON to Neo4j CSVs."""
    print("\n[1/2] TRANSFORM: JSON -> CSV")
    print(f"      Input:  {input_dir}")
    print(f"      Output: {output_dir}")

    # Import here to avoid loading everything for --import-only
    from load_existing_json import load_command_jsons, load_attack_chain_jsons, load_cheatsheet_jsons
    from load_writeups import load_writeup_jsons
    from transform_to_neo4j import transform_all_to_neo4j

    # Load data
    commands, cmd_err = load_command_jsons(str(input_dir / "commands"))
    chains, chain_err = load_attack_chain_jsons(str(input_dir / "chains"))
    cheatsheets, sheet_err = load_cheatsheet_jsons(str(input_dir / "cheatsheets"))
    writeups, writeup_err = load_writeup_jsons(str(input_dir / "writeups"))

    errors = cmd_err + chain_err + sheet_err + writeup_err
    if errors:
        print(f"      WARN: {len(errors)} load errors")
        for e in errors[:3]:
            print(f"        - {e}")
        if len(errors) > 3:
            print(f"        ... and {len(errors) - 3} more")

    print(f"      Loaded: {len(commands)} commands, {len(chains)} chains, "
          f"{len(cheatsheets)} cheatsheets, {len(writeups)} writeups")

    # Transform
    output_dir.mkdir(parents=True, exist_ok=True)
    transform_all_to_neo4j(commands, chains, cheatsheets, str(output_dir), validate=validate)

    csv_count = len(list(output_dir.glob("*.csv")))
    print(f"      Generated: {csv_count} CSV files")
    return True


def import_to_neo4j(csv_dir: Path, uri: str, user: str, password: str, batch_size: int = 1000) -> bool:
    """Import CSVs to Neo4j."""
    print("\n[2/2] IMPORT: CSV -> Neo4j")
    print(f"      Source: {csv_dir}")
    print(f"      Target: {uri}")

    from import_to_neo4j import import_all_to_neo4j

    config = {"uri": uri, "user": user, "password": password}
    success = import_all_to_neo4j(str(csv_dir), config, batch_size=batch_size)

    if success:
        print("      Import complete")
    else:
        print("      Import FAILED")
    return success


def health_check(uri: str, user: str, password: str) -> bool:
    """Quick Neo4j health check."""
    print("\n[CHECK] Neo4j Health")

    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(uri, auth=(user, password))
        with driver.session() as session:
            result = session.run("MATCH (c:Command) RETURN count(c) as cnt")
            cmd_count = result.single()["cnt"]
            result = session.run("MATCH (cs:Cheatsheet) RETURN count(cs) as cnt")
            cs_count = result.single()["cnt"]
            result = session.run("MATCH (ch:AttackChain) RETURN count(ch) as cnt")
            chain_count = result.single()["cnt"]
        driver.close()
        print(f"      Commands: {cmd_count}, Cheatsheets: {cs_count}, Chains: {chain_count}")
        return True
    except Exception as e:
        print(f"      FAILED: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="CRACK Neo4j Migration Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python migrate.py                    # Full pipeline
  python migrate.py --transform-only   # Just CSVs
  python migrate.py --import-only      # Just import
  python migrate.py --check            # Include health check

Environment variables:
  NEO4J_URI       (default: bolt://localhost:7687)
  NEO4J_USER      (default: neo4j)
  NEO4J_PASSWORD  (default: cracktrack)
"""
    )

    parser.add_argument("--transform-only", action="store_true",
                        help="Only generate CSVs, skip import")
    parser.add_argument("--import-only", action="store_true",
                        help="Only import existing CSVs")
    parser.add_argument("--check", action="store_true",
                        help="Run health check after import")
    parser.add_argument("--no-validate", action="store_true",
                        help="Skip validation during transform")
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT,
                        help=f"JSON source directory (default: {DEFAULT_INPUT})")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT,
                        help=f"CSV output directory (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--batch-size", type=int, default=1000,
                        help="Neo4j import batch size (default: 1000)")

    args = parser.parse_args()

    print("=" * 50)
    print("CRACK Neo4j Migration")
    print("=" * 50)

    success = True

    # Transform step
    if not args.import_only:
        success = transform(args.input_dir, args.output_dir, validate=not args.no_validate)
        if not success:
            return 1

    # Import step
    if not args.transform_only:
        success = import_to_neo4j(
            args.output_dir, NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD,
            batch_size=args.batch_size
        )
        if not success:
            return 1

    # Health check
    if args.check and not args.transform_only:
        health_check(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)

    print("\n" + "=" * 50)
    print("Done." if success else "Failed.")
    print("=" * 50)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
