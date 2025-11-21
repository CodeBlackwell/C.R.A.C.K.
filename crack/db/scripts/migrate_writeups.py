#!/usr/bin/env python3
"""
Writeup Migration Script - Complete workflow for migrating writeups to Neo4j

This script handles:
1. Loading writeup JSON files
2. Validating against schema
3. Extracting nodes and relationships to CSV
4. Importing to Neo4j (optional)
5. Verifying import success

Usage:
    # Dry run (extract to CSV only, no Neo4j import)
    python3 migrate_writeups.py --dry-run

    # Full migration with import
    python3 migrate_writeups.py --import

    # Specific writeup
    python3 migrate_writeups.py --writeup htb-usage --import

    # Custom output directory
    python3 migrate_writeups.py --output /tmp/writeup_csvs --import

Author: Claude Code
Date: 2025-01-19
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Set
from collections import defaultdict
import csv

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "neo4j-migration" / "scripts"))

try:
    from load_writeups import load_writeup_jsons
    from writeup_extractors import (
        WriteupNodesExtractor,
        CVENodesExtractor,
        TechniqueNodesExtractor,
        PlatformNodesExtractor,
        SkillNodesExtractor,
        WriteupDemonstratesCommandExtractor,
        WriteupFailedAttemptExtractor,
        WriteupExploitsCVEExtractor,
        WriteupTeachesTechniqueExtractor,
        WriteupFromPlatformExtractor,
        WriteupRequiresSkillExtractor,
        WriteupTeachesSkillExtractor
    )
except ImportError as e:
    print(f"ERROR: Could not import writeup extractors: {e}")
    print("Make sure load_writeups.py and writeup_extractors.py exist in neo4j-migration/scripts/")
    sys.exit(1)


class WriteupMigration:
    """Handle complete writeup migration workflow"""

    def __init__(self, writeup_dir: str, output_dir: str, verbose: bool = False):
        """
        Initialize migration

        Args:
            writeup_dir: Path to writeups directory
            output_dir: Path to CSV output directory
            verbose: Enable verbose logging
        """
        self.writeup_dir = Path(writeup_dir)
        self.output_dir = Path(output_dir)
        self.verbose = verbose
        self.writeups = []
        self.errors = []
        self.stats = defaultdict(int)

    def log(self, message: str, level: str = "INFO"):
        """Log message with level"""
        prefix = {
            "INFO": "ℹ",
            "SUCCESS": "✓",
            "ERROR": "✗",
            "WARN": "⚠",
            "DEBUG": "→"
        }.get(level, "·")

        print(f"{prefix} {message}")

    def log_verbose(self, message: str):
        """Log verbose message"""
        if self.verbose:
            self.log(message, "DEBUG")

    def load_writeups(self) -> bool:
        """Load and validate writeup JSON files"""
        self.log(f"Loading writeups from: {self.writeup_dir}")

        if not self.writeup_dir.exists():
            self.log(f"Writeup directory not found: {self.writeup_dir}", "ERROR")
            return False

        # Load writeups using load_writeups module
        self.writeups, self.errors = load_writeup_jsons(str(self.writeup_dir))

        if self.errors:
            self.log(f"Found {len(self.errors)} error(s) loading writeups:", "WARN")
            for error in self.errors[:5]:  # Show first 5
                self.log(f"  {error}", "WARN")
            if len(self.errors) > 5:
                self.log(f"  ... and {len(self.errors) - 5} more", "WARN")

        self.log(f"Loaded {len(self.writeups)} writeup(s)", "SUCCESS")
        return len(self.writeups) > 0

    def extract_to_csv(self) -> bool:
        """Extract writeups to CSV files for Neo4j import"""
        self.log(f"Extracting to CSV in: {self.output_dir}")

        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Extract nodes
            self.log_verbose("Extracting writeup nodes...")
            writeup_nodes = WriteupNodesExtractor().extract_nodes(self.writeups)
            self._write_csv("writeup_nodes.csv", writeup_nodes)
            self.stats["writeup_nodes"] = len(writeup_nodes)

            self.log_verbose("Extracting CVE nodes...")
            cve_nodes = CVENodesExtractor().extract_nodes(self.writeups)
            self._write_csv("cve_nodes.csv", cve_nodes)
            self.stats["cve_nodes"] = len(cve_nodes)

            self.log_verbose("Extracting technique nodes...")
            technique_nodes = TechniqueNodesExtractor().extract_nodes(self.writeups)
            self._write_csv("technique_nodes.csv", technique_nodes)
            self.stats["technique_nodes"] = len(technique_nodes)

            self.log_verbose("Extracting platform nodes...")
            platform_nodes = PlatformNodesExtractor().extract_nodes(self.writeups)
            self._write_csv("platform_nodes.csv", platform_nodes)
            self.stats["platform_nodes"] = len(platform_nodes)

            self.log_verbose("Extracting skill nodes...")
            skill_nodes = SkillNodesExtractor().extract_nodes(self.writeups)
            self._write_csv("skill_nodes.csv", skill_nodes)
            self.stats["skill_nodes"] = len(skill_nodes)

            # Extract relationships
            self.log_verbose("Extracting DEMONSTRATES relationships...")
            demonstrates = WriteupDemonstratesCommandExtractor().extract_relationships(self.writeups)
            self._write_csv("writeup_demonstrates_command.csv", demonstrates)
            self.stats["demonstrates_rels"] = len(demonstrates)

            self.log_verbose("Extracting FAILED_ATTEMPT relationships...")
            failed_attempts = WriteupFailedAttemptExtractor().extract_relationships(self.writeups)
            self._write_csv("writeup_failed_attempt.csv", failed_attempts)
            self.stats["failed_attempt_rels"] = len(failed_attempts)

            self.log_verbose("Extracting EXPLOITS_CVE relationships...")
            exploits_cve = WriteupExploitsCVEExtractor().extract_relationships(self.writeups)
            self._write_csv("writeup_exploits_cve.csv", exploits_cve)
            self.stats["exploits_cve_rels"] = len(exploits_cve)

            self.log_verbose("Extracting TEACHES_TECHNIQUE relationships...")
            teaches_technique = WriteupTeachesTechniqueExtractor().extract_relationships(self.writeups)
            self._write_csv("writeup_teaches_technique.csv", teaches_technique)
            self.stats["teaches_technique_rels"] = len(teaches_technique)

            self.log_verbose("Extracting FROM_PLATFORM relationships...")
            from_platform = WriteupFromPlatformExtractor().extract_relationships(self.writeups)
            self._write_csv("writeup_from_platform.csv", from_platform)
            self.stats["from_platform_rels"] = len(from_platform)

            self.log_verbose("Extracting REQUIRES_SKILL relationships...")
            requires_skill = WriteupRequiresSkillExtractor().extract_relationships(self.writeups)
            self._write_csv("writeup_requires_skill.csv", requires_skill)
            self.stats["requires_skill_rels"] = len(requires_skill)

            self.log_verbose("Extracting TEACHES_SKILL relationships...")
            teaches_skill = WriteupTeachesSkillExtractor().extract_relationships(self.writeups)
            self._write_csv("writeup_teaches_skill.csv", teaches_skill)
            self.stats["teaches_skill_rels"] = len(teaches_skill)

            self.log("CSV extraction complete", "SUCCESS")
            return True

        except Exception as e:
            self.log(f"Error during CSV extraction: {e}", "ERROR")
            import traceback
            traceback.print_exc()
            return False

    def _write_csv(self, filename: str, data: List[Dict]):
        """Write data to CSV file"""
        if not data:
            self.log_verbose(f"  {filename}: 0 rows (skipped)")
            return

        filepath = self.output_dir / filename

        # Get headers from first row
        headers = list(data[0].keys())

        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(data)

        self.log_verbose(f"  {filename}: {len(data)} rows")

    def import_to_neo4j(self, neo4j_uri: str = "bolt://localhost:7687",
                        neo4j_user: str = "neo4j",
                        neo4j_password: str = "password") -> bool:
        """Import CSV files to Neo4j"""
        self.log(f"Importing to Neo4j at: {neo4j_uri}")

        try:
            from neo4j import GraphDatabase
        except ImportError:
            self.log("neo4j driver not installed. Install with: pip install neo4j", "ERROR")
            return False

        try:
            driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))

            with driver.session() as session:
                # Test connection
                result = session.run("RETURN 1 as test")
                result.single()
                self.log("Connected to Neo4j", "SUCCESS")

                # Import nodes
                self.log_verbose("Importing writeup nodes...")
                self._import_writeup_nodes(session)

                self.log_verbose("Importing CVE nodes...")
                self._import_cve_nodes(session)

                self.log_verbose("Importing technique nodes...")
                self._import_technique_nodes(session)

                self.log_verbose("Importing platform nodes...")
                self._import_platform_nodes(session)

                self.log_verbose("Importing skill nodes...")
                self._import_skill_nodes(session)

                # Import relationships
                self.log_verbose("Importing DEMONSTRATES relationships...")
                self._import_demonstrates_rels(session)

                self.log_verbose("Importing FAILED_ATTEMPT relationships...")
                self._import_failed_attempt_rels(session)

                self.log_verbose("Importing EXPLOITS_CVE relationships...")
                self._import_exploits_cve_rels(session)

                self.log_verbose("Importing TEACHES_TECHNIQUE relationships...")
                self._import_teaches_technique_rels(session)

                self.log_verbose("Importing FROM_PLATFORM relationships...")
                self._import_from_platform_rels(session)

                self.log_verbose("Importing REQUIRES_SKILL relationships...")
                self._import_requires_skill_rels(session)

                self.log_verbose("Importing TEACHES_SKILL relationships...")
                self._import_teaches_skill_rels(session)

            driver.close()
            self.log("Neo4j import complete", "SUCCESS")
            return True

        except Exception as e:
            self.log(f"Error importing to Neo4j: {e}", "ERROR")
            import traceback
            traceback.print_exc()
            return False

    def _import_writeup_nodes(self, session):
        """Import writeup nodes to Neo4j"""
        filepath = self.output_dir / "writeup_nodes.csv"
        if not filepath.exists():
            return

        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Store attack_phases as JSON string (already serialized in CSV)
                session.run("""
                    MERGE (w:Writeup {id: $id})
                    SET w.name = $name,
                        w.platform = $platform,
                        w.difficulty = $difficulty,
                        w.os = $os,
                        w.oscp_relevance = $oscp_relevance,
                        w.total_duration_minutes = toInteger($total_duration_minutes),
                        w.attack_phases = $attack_phases,
                        w.synopsis = $synopsis,
                        w.tags = $tags,
                        w.os_version = $os_version,
                        w.ip_address = $ip_address,
                        w.oscp_reasoning = $oscp_reasoning,
                        w.exam_applicable = ($exam_applicable = 'true'),
                        w.release_date = $release_date,
                        w.retire_date = $retire_date,
                        w.writeup_author = $writeup_author,
                        w.writeup_date = $writeup_date,
                        w.machine_author = $machine_author,
                        w.points = toInteger($points)
                """, **row)

    def _import_cve_nodes(self, session):
        """Import CVE nodes to Neo4j"""
        filepath = self.output_dir / "cve_nodes.csv"
        if not filepath.exists():
            return

        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                session.run("""
                    MERGE (c:CVE {cve_id: $cve_id})
                    SET c.name = $name,
                        c.severity = $severity,
                        c.component = $component
                """, **row)

    def _import_technique_nodes(self, session):
        """Import technique nodes to Neo4j"""
        filepath = self.output_dir / "technique_nodes.csv"
        if not filepath.exists():
            return

        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                session.run("""
                    MERGE (t:Technique {name: $name})
                    SET t.category = $category,
                        t.oscp_applicable = ($oscp_applicable = 'true')
                """, **row)

    def _import_platform_nodes(self, session):
        """Import platform nodes to Neo4j"""
        filepath = self.output_dir / "platform_nodes.csv"
        if not filepath.exists():
            return

        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                session.run("""
                    MERGE (p:Platform {name: $name})
                    SET p.type = $type,
                        p.url = $url
                """, **row)

    def _import_skill_nodes(self, session):
        """Import skill nodes to Neo4j"""
        filepath = self.output_dir / "skill_nodes.csv"
        if not filepath.exists():
            return

        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                session.run("""
                    MERGE (s:Skill {name: $name})
                    SET s.category = $category,
                        s.oscp_importance = $oscp_importance
                """, **row)

    def _import_demonstrates_rels(self, session):
        """Import DEMONSTRATES relationships"""
        filepath = self.output_dir / "writeup_demonstrates_command.csv"
        if not filepath.exists():
            return

        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                session.run("""
                    MATCH (w:Writeup {id: $writeup_id})
                    MATCH (c:Command {id: $command_id})
                    MERGE (w)-[r:DEMONSTRATES]->(c)
                    SET r.phase = $phase,
                        r.step_number = toInteger($step_number),
                        r.context = $context,
                        r.success = ($success = 'true')
                """, **row)

    def _import_failed_attempt_rels(self, session):
        """Import FAILED_ATTEMPT relationships"""
        filepath = self.output_dir / "writeup_failed_attempt.csv"
        if not filepath.exists():
            return

        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                session.run("""
                    MATCH (w:Writeup {id: $writeup_id})
                    MATCH (c:Command {id: $command_id})
                    MERGE (w)-[r:FAILED_ATTEMPT]->(c)
                    SET r.reason = $reason,
                        r.lesson_learned = $lesson_learned,
                        r.time_wasted_minutes = toInteger($time_wasted_minutes)
                """, **row)

    def _import_exploits_cve_rels(self, session):
        """Import EXPLOITS_CVE relationships"""
        filepath = self.output_dir / "writeup_exploits_cve.csv"
        if not filepath.exists():
            return

        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                session.run("""
                    MATCH (w:Writeup {id: $writeup_id})
                    MATCH (c:CVE {cve_id: $cve_id})
                    MERGE (w)-[r:EXPLOITS_CVE]->(c)
                    SET r.phase = $phase,
                        r.severity = $severity
                """, **row)

    def _import_teaches_technique_rels(self, session):
        """Import TEACHES_TECHNIQUE relationships"""
        filepath = self.output_dir / "writeup_teaches_technique.csv"
        if not filepath.exists():
            return

        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                session.run("""
                    MATCH (w:Writeup {id: $writeup_id})
                    MATCH (t:Technique {name: $technique_name})
                    MERGE (w)-[r:TEACHES_TECHNIQUE]->(t)
                    SET r.phase = $phase,
                        r.oscp_applicable = ($oscp_applicable = 'true')
                """, **row)

    def _import_from_platform_rels(self, session):
        """Import FROM_PLATFORM relationships"""
        filepath = self.output_dir / "writeup_from_platform.csv"
        if not filepath.exists():
            return

        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                session.run("""
                    MATCH (w:Writeup {id: $writeup_id})
                    MATCH (p:Platform {name: $platform_name})
                    MERGE (w)-[r:FROM_PLATFORM]->(p)
                    SET r.machine_type = $machine_type,
                        r.release_date = $release_date
                """, **row)

    def _import_requires_skill_rels(self, session):
        """Import REQUIRES_SKILL relationships"""
        filepath = self.output_dir / "writeup_requires_skill.csv"
        if not filepath.exists():
            return

        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                session.run("""
                    MATCH (w:Writeup {id: $writeup_id})
                    MATCH (s:Skill {name: $skill_name})
                    MERGE (w)-[r:REQUIRES_SKILL]->(s)
                    SET r.importance = $importance
                """, **row)

    def _import_teaches_skill_rels(self, session):
        """Import TEACHES_SKILL relationships"""
        filepath = self.output_dir / "writeup_teaches_skill.csv"
        if not filepath.exists():
            return

        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                session.run("""
                    MATCH (w:Writeup {id: $writeup_id})
                    MATCH (s:Skill {name: $skill_name})
                    MERGE (w)-[r:TEACHES_SKILL]->(s)
                    SET r.proficiency_level = $proficiency_level
                """, **row)

    def verify_import(self, neo4j_uri: str = "bolt://localhost:7687",
                     neo4j_user: str = "neo4j",
                     neo4j_password: str = "password") -> bool:
        """Verify Neo4j import was successful"""
        self.log("Verifying Neo4j import...")

        try:
            from neo4j import GraphDatabase
        except ImportError:
            self.log("neo4j driver not installed", "ERROR")
            return False

        try:
            driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))

            with driver.session() as session:
                # Count nodes
                result = session.run("MATCH (w:Writeup) RETURN count(w) as count")
                writeup_count = result.single()["count"]

                result = session.run("MATCH (c:CVE) RETURN count(c) as count")
                cve_count = result.single()["count"]

                result = session.run("MATCH (t:Technique) RETURN count(t) as count")
                technique_count = result.single()["count"]

                result = session.run("MATCH (p:Platform) RETURN count(p) as count")
                platform_count = result.single()["count"]

                result = session.run("MATCH (s:Skill) RETURN count(s) as count")
                skill_count = result.single()["count"]

                # Count relationships
                result = session.run("MATCH ()-[r:DEMONSTRATES]->() RETURN count(r) as count")
                demonstrates_count = result.single()["count"]

                result = session.run("MATCH ()-[r:FAILED_ATTEMPT]->() RETURN count(r) as count")
                failed_attempt_count = result.single()["count"]

                # Display results
                self.log("\nNeo4j Import Verification:", "SUCCESS")
                self.log(f"  Writeups: {writeup_count}")
                self.log(f"  CVEs: {cve_count}")
                self.log(f"  Techniques: {technique_count}")
                self.log(f"  Platforms: {platform_count}")
                self.log(f"  Skills: {skill_count}")
                self.log(f"  DEMONSTRATES relationships: {demonstrates_count}")
                self.log(f"  FAILED_ATTEMPT relationships: {failed_attempt_count}")

                # Verify counts match expectations
                if writeup_count != self.stats.get("writeup_nodes", 0):
                    self.log(f"  WARNING: Expected {self.stats['writeup_nodes']} writeups, found {writeup_count}", "WARN")
                    return False

                self.log("\nVerification PASSED", "SUCCESS")
                return True

            driver.close()

        except Exception as e:
            self.log(f"Error verifying import: {e}", "ERROR")
            import traceback
            traceback.print_exc()
            return False

    def print_summary(self):
        """Print migration summary"""
        self.log("\n" + "="*60)
        self.log("Migration Summary", "SUCCESS")
        self.log("="*60)
        self.log(f"Writeups processed: {len(self.writeups)}")
        self.log(f"Errors encountered: {len(self.errors)}")
        self.log("\nNodes extracted:")
        self.log(f"  Writeups: {self.stats.get('writeup_nodes', 0)}")
        self.log(f"  CVEs: {self.stats.get('cve_nodes', 0)}")
        self.log(f"  Techniques: {self.stats.get('technique_nodes', 0)}")
        self.log(f"  Platforms: {self.stats.get('platform_nodes', 0)}")
        self.log(f"  Skills: {self.stats.get('skill_nodes', 0)}")
        self.log("\nRelationships extracted:")
        self.log(f"  DEMONSTRATES: {self.stats.get('demonstrates_rels', 0)}")
        self.log(f"  FAILED_ATTEMPT: {self.stats.get('failed_attempt_rels', 0)}")
        self.log(f"  EXPLOITS_CVE: {self.stats.get('exploits_cve_rels', 0)}")
        self.log(f"  TEACHES_TECHNIQUE: {self.stats.get('teaches_technique_rels', 0)}")
        self.log(f"  FROM_PLATFORM: {self.stats.get('from_platform_rels', 0)}")
        self.log(f"  REQUIRES_SKILL: {self.stats.get('requires_skill_rels', 0)}")
        self.log(f"  TEACHES_SKILL: {self.stats.get('teaches_skill_rels', 0)}")
        self.log("="*60)


def main():
    parser = argparse.ArgumentParser(
        description="Migrate writeups to Neo4j",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dry run (CSV extraction only)
  python3 migrate_writeups.py --dry-run

  # Full migration with Neo4j import
  python3 migrate_writeups.py --import

  # Custom Neo4j connection
  python3 migrate_writeups.py --import --neo4j-uri bolt://localhost:7687 --neo4j-user neo4j --neo4j-password mypassword

  # Verbose output
  python3 migrate_writeups.py --import --verbose
        """
    )

    parser.add_argument(
        '--writeup-dir',
        default=None,
        help='Path to writeups directory (default: auto-detect)'
    )

    parser.add_argument(
        '--output',
        default=None,
        help='Output directory for CSV files (default: auto-detect)'
    )

    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Extract to CSV only, do not import to Neo4j'
    )

    parser.add_argument(
        '--import',
        action='store_true',
        dest='do_import',
        help='Import to Neo4j after CSV extraction'
    )

    parser.add_argument(
        '--neo4j-uri',
        default='bolt://localhost:7687',
        help='Neo4j connection URI (default: bolt://localhost:7687)'
    )

    parser.add_argument(
        '--neo4j-user',
        default='neo4j',
        help='Neo4j username (default: neo4j)'
    )

    parser.add_argument(
        '--neo4j-password',
        default='password',
        help='Neo4j password (default: password)'
    )

    parser.add_argument(
        '--verify',
        action='store_true',
        help='Verify import after completion'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    args = parser.parse_args()

    # Auto-detect paths if not specified
    script_dir = Path(__file__).parent
    if not args.writeup_dir:
        args.writeup_dir = script_dir.parent / "data" / "writeups"

    if not args.output:
        args.output = script_dir.parent / "neo4j-migration" / "csv" / "writeups"

    # Create migration instance
    migration = WriteupMigration(
        writeup_dir=str(args.writeup_dir),
        output_dir=str(args.output),
        verbose=args.verbose
    )

    # Execute migration workflow
    success = True

    # Step 1: Load writeups
    if not migration.load_writeups():
        migration.log("Failed to load writeups", "ERROR")
        sys.exit(1)

    # Step 2: Extract to CSV
    if not migration.extract_to_csv():
        migration.log("Failed to extract CSV files", "ERROR")
        sys.exit(1)

    # Step 3: Import to Neo4j (if requested)
    if args.do_import:
        if not migration.import_to_neo4j(
            neo4j_uri=args.neo4j_uri,
            neo4j_user=args.neo4j_user,
            neo4j_password=args.neo4j_password
        ):
            migration.log("Failed to import to Neo4j", "ERROR")
            success = False

        # Step 4: Verify import (if requested)
        if args.verify or args.do_import:
            if not migration.verify_import(
                neo4j_uri=args.neo4j_uri,
                neo4j_user=args.neo4j_user,
                neo4j_password=args.neo4j_password
            ):
                migration.log("Import verification failed", "ERROR")
                success = False

    # Print summary
    migration.print_summary()

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
