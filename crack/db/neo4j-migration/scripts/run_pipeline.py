#!/usr/bin/env python3
"""
Unified Neo4j data pipeline - single command for transform and validation.

Usage:
    python run_pipeline.py                    # Transform with validation
    python run_pipeline.py --no-validate      # Transform without validation
    python run_pipeline.py --verbose          # Detailed logging
"""

import os
import sys
import argparse
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from pipeline import Neo4jPipeline
from scripts.load_existing_json import load_command_jsons, load_attack_chain_jsons, load_cheatsheet_jsons
import scripts.transform_to_neo4j as transform_module


def main():
    parser = argparse.ArgumentParser(
        description="Unified Neo4j data pipeline (transform + validate)"
    )
    parser.add_argument(
        '--input-dir',
        default='db/data',
        help='Input directory (default: db/data/)'
    )
    parser.add_argument(
        '--output-dir',
        default='db/neo4j-migration/data/neo4j',
        help='Output directory (default: db/neo4j-migration/data/neo4j/)'
    )
    parser.add_argument(
        '--schema',
        default='db/neo4j-migration/schema/neo4j_schema.yaml',
        help='Schema YAML file (default: db/neo4j-migration/schema/neo4j_schema.yaml)'
    )
    parser.add_argument(
        '--no-validate',
        action='store_true',
        help='Disable validation (faster but no error checking)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Detailed logging'
    )

    args = parser.parse_args()

    # Determine directories
    if os.path.isabs(args.input_dir):
        input_dir = Path(args.input_dir)
    else:
        input_dir = Path.cwd() / args.input_dir

    if os.path.isabs(args.output_dir):
        output_dir = Path(args.output_dir)
    else:
        output_dir = Path.cwd() / args.output_dir

    if os.path.isabs(args.schema):
        schema_path = Path(args.schema)
    else:
        schema_path = Path.cwd() / args.schema

    print("=" * 60)
    print("Neo4j Data Pipeline")
    print("=" * 60)
    print(f"Input:  {input_dir}")
    print(f"Output: {output_dir}")
    print(f"Schema: {schema_path}")
    print(f"Validation: {'DISABLED' if args.no_validate else 'ENABLED'}")
    print()

    # Load JSON data
    print(f"Loading JSON from: {input_dir}")
    commands, cmd_errors = load_command_jsons(str(input_dir / "commands"))
    chains, chain_errors = load_attack_chain_jsons(str(input_dir / "chains"))
    cheatsheets, sheet_errors = load_cheatsheet_jsons(str(input_dir / "cheatsheets"))

    if cmd_errors or chain_errors or sheet_errors:
        print("\n✗ Errors loading JSON files:")
        for err in cmd_errors + chain_errors + sheet_errors:
            print(f"  ERROR: {err}")
        return 1

    print(f"Loaded {len(commands)} commands, {len(chains)} chains, {len(cheatsheets)} cheatsheet entries")

    # Create pipeline
    pipeline = Neo4jPipeline(
        schema_path=str(schema_path),
        output_dir=str(output_dir),
        validate=not args.no_validate,
        verbose=args.verbose
    )

    # Run transformation
    success = pipeline.run_transform(
        commands=commands,
        chains=chains,
        cheatsheets=cheatsheets,
        extractor_module=transform_module
    )

    if success:
        print()
        print("=" * 60)
        print("Pipeline completed successfully!")
        print("=" * 60)
        return 0
    else:
        print()
        print("=" * 60)
        print("Pipeline completed with errors")
        print("=" * 60)
        return 1


if __name__ == '__main__':
    sys.exit(main())
