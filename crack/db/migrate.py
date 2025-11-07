"""
CRACK JSON → SQL Migration Script

Migrates existing JSON command definitions to SQL database.

Usage:
    python3 -m crack.db.migrate commands     # Migrate commands only
    python3 -m crack.db.migrate chains       # Migrate attack chains only
    python3 -m crack.db.migrate all          # Migrate everything
    python3 -m crack.db.migrate validate     # Validate migration

Migration Flow:
1. Load JSON files from reference/data/commands/
2. Parse command structure
3. Insert into normalized SQL tables
4. Create relationships (tags, variables, flags)
5. Validate referential integrity
"""

import json
import psycopg2
import psycopg2.extras
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from .config import get_db_config


class CRACKMigration:
    """Manages migration from JSON to SQL database"""

    def __init__(self, db_config: Dict[str, Any] = None):
        """
        Initialize migration

        Args:
            db_config: PostgreSQL connection config (default: from get_db_config())
        """
        if db_config is None:
            db_config = get_db_config()

        self.db_config = db_config
        self.conn = psycopg2.connect(**db_config)
        self.cursor = self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        # PostgreSQL has foreign keys enabled by default (no PRAGMA needed)

        # Statistics
        self.stats = {
            'commands': 0,
            'flags': 0,
            'variables': 0,
            'tags': 0,
            'relations': 0,
            'guidance_relations': 0,  # NEW: descriptive text relations
            'indicators': 0,
            'errors': []
        }

    def create_schema(self):
        """Create database schema from schema.sql if tables don't exist"""
        # Check if tables already exist
        self.cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_schema = 'public'
                AND table_name = 'commands'
            );
        """)

        if self.cursor.fetchone()[0]:
            print("✓ Database schema already exists")
            return

        print("📋 Creating database schema...")

        # Read schema.sql
        schema_path = Path(__file__).parent / 'schema.sql'
        if not schema_path.exists():
            raise FileNotFoundError(f"Schema file not found: {schema_path}")

        schema_sql = schema_path.read_text()

        # Execute schema creation
        try:
            self.cursor.execute(schema_sql)
            self.conn.commit()
            print("✓ Database schema created successfully")
        except Exception as e:
            self.conn.rollback()
            raise Exception(f"Failed to create schema: {e}")

    def migrate_commands(self, json_dir: Path = None):
        """
        Migrate commands from JSON files to SQL

        Args:
            json_dir: Directory containing JSON files (default: reference/data/commands)

        Returns:
            Dict with migration statistics
        """
        if json_dir is None:
            json_dir = Path('reference/data/commands')

        print(f"🔍 Scanning {json_dir} for JSON files...")

        json_files = list(json_dir.rglob("*.json"))
        print(f"✓ Found {len(json_files)} JSON files")

        for json_file in json_files:
            try:
                print(f"\n📄 Processing: {json_file.relative_to(json_dir)}")
                data = json.loads(json_file.read_text())

                # Handle both formats:
                # 1. {"commands": [...]} (array wrapper)
                # 2. {"category": "...", "commands": [...]} (category wrapper)
                commands = data.get('commands', [])

                if not commands:
                    print(f"  ⚠️  No commands found in {json_file.name}")
                    continue

                for cmd in commands:
                    self._insert_command(cmd)
                    self.stats['commands'] += 1

            except json.JSONDecodeError as e:
                error = f"JSON parse error in {json_file}: {e}"
                print(f"  ❌ {error}")
                self.stats['errors'].append(error)
            except Exception as e:
                error = f"Error processing {json_file}: {e}"
                print(f"  ❌ {error}")
                self.stats['errors'].append(error)

        self.conn.commit()
        return self.stats

    def _insert_command(self, cmd: Dict[str, Any]):
        """Insert single command with all metadata"""

        # 1. Insert base command
        try:
            self.cursor.execute("""
                INSERT INTO commands
                (id, name, command_template, description, category, subcategory, notes, oscp_relevance)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    name = EXCLUDED.name,
                    command_template = EXCLUDED.command_template,
                    description = EXCLUDED.description,
                    category = EXCLUDED.category,
                    subcategory = EXCLUDED.subcategory,
                    notes = EXCLUDED.notes,
                    oscp_relevance = EXCLUDED.oscp_relevance
            """, (
                cmd['id'],
                cmd['name'],
                cmd['command'],
                cmd.get('description', ''),
                cmd.get('category', 'custom'),
                cmd.get('subcategory', ''),
                cmd.get('notes', ''),
                cmd.get('oscp_relevance', 'medium')
            ))
            print(f"  ✓ Command: {cmd['id']}")
        except psycopg2.IntegrityError as e:
            print(f"  ⚠️  Skipping duplicate command: {cmd['id']}")
            return

        # 2. Insert flags
        for flag, explanation in cmd.get('flag_explanations', {}).items():
            try:
                self.cursor.execute("""
                    INSERT INTO command_flags (command_id, flag, explanation)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (command_id, flag) DO NOTHING
                """, (cmd['id'], flag, explanation))
                self.stats['flags'] += 1
            except Exception as e:
                print(f"    ⚠️  Flag error for {flag}: {e}")

        # 3. Insert variables
        for idx, var in enumerate(cmd.get('variables', [])):
            var_id = self._get_or_create_variable(
                var['name'],
                var['description'],
                var.get('example', ''),
                var.get('required', True)
            )

            try:
                self.cursor.execute("""
                    INSERT INTO command_vars
                    (command_id, variable_id, position, is_required, example_value)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (command_id, variable_id) DO NOTHING
                """, (cmd['id'], var_id, idx + 1, var.get('required', True), var.get('example', '')))
                self.stats['variables'] += 1
            except Exception as e:
                print(f"    ⚠️  Variable error for {var['name']}: {e}")

        # 4. Insert tags
        for tag_name in cmd.get('tags', []):
            tag_id = self._get_or_create_tag(tag_name)
            try:
                self.cursor.execute("""
                    INSERT INTO command_tags (command_id, tag_id)
                    VALUES (%s, %s)
                    ON CONFLICT (command_id, tag_id) DO NOTHING
                """, (cmd['id'], tag_id))
                self.stats['tags'] += 1
            except Exception as e:
                print(f"    ⚠️  Tag error for {tag_name}: {e}")

        # 5. Insert success indicators
        for pattern in cmd.get('success_indicators', []):
            try:
                self.cursor.execute("""
                    INSERT INTO command_indicators
                    (command_id, indicator_type, pattern, pattern_type)
                    VALUES (%s, 'success', %s, 'literal')
                """, (cmd['id'], pattern))
                self.stats['indicators'] += 1
            except Exception as e:
                print(f"    ⚠️  Success indicator error: {e}")

        # 6. Insert failure indicators
        for pattern in cmd.get('failure_indicators', []):
            try:
                self.cursor.execute("""
                    INSERT INTO command_indicators
                    (command_id, indicator_type, pattern, pattern_type)
                    VALUES (%s, 'failure', %s, 'literal')
                """, (cmd['id'], pattern))
                self.stats['indicators'] += 1
            except Exception as e:
                print(f"    ⚠️  Failure indicator error: {e}")

        # 7. Insert command relationships (deferred - needs two-pass)
        # Store for later processing after all commands exist
        if cmd.get('alternatives'):
            self._store_pending_relations(cmd['id'], cmd['alternatives'], 'alternative')
        if cmd.get('prerequisites'):
            self._store_pending_relations(cmd['id'], cmd['prerequisites'], 'prerequisite')
        if cmd.get('next_steps'):
            self._store_pending_relations(cmd['id'], cmd['next_steps'], 'next_step')

    def _get_or_create_variable(self, name: str, description: str, default: str = '', required: bool = True) -> int:
        """Get existing variable ID or create new one"""

        # Try to get existing
        self.cursor.execute("SELECT id FROM variables WHERE name = %s", (name,))
        row = self.cursor.fetchone()
        if row:
            return row['id']

        # Create new - use RETURNING clause instead of lastrowid
        self.cursor.execute("""
            INSERT INTO variables (name, description, default_value, source)
            VALUES (%s, %s, %s, 'user')
            RETURNING id
        """, (name, description, default if default else None))

        return self.cursor.fetchone()['id']

    def _get_or_create_tag(self, name: str) -> int:
        """Get existing tag ID or create new one"""

        # Try to get existing
        self.cursor.execute("SELECT id FROM tags WHERE name = %s", (name,))
        row = self.cursor.fetchone()
        if row:
            return row['id']

        # Create new - extract category from name if possible
        category = None
        if ':' in name:
            category = name.split(':')[0].lower()

        # Use RETURNING clause instead of lastrowid
        self.cursor.execute("""
            INSERT INTO tags (name, category)
            VALUES (%s, %s)
            RETURNING id
        """, (name, category))

        return self.cursor.fetchone()['id']

    def _store_pending_relations(self, source_id: str, targets: List[str], relation_type: str):
        """Store relationships for second-pass processing"""
        # Note: targets might be command IDs or text strings
        # We'll process these after all commands are loaded
        if not hasattr(self, '_pending_relations'):
            self._pending_relations = []

        for priority, target in enumerate(targets, 1):
            self._pending_relations.append({
                'source': source_id,
                'target': target,
                'type': relation_type,
                'priority': priority
            })

    def process_relations(self):
        """Second pass: process command relationships"""
        if not hasattr(self, '_pending_relations'):
            return

        print(f"\n🔗 Processing {len(self._pending_relations)} command relationships...")

        for rel in self._pending_relations:
            # Try to resolve target as command ID
            self.cursor.execute("SELECT id FROM commands WHERE id = %s", (rel['target'],))
            target_row = self.cursor.fetchone()

            if target_row:
                # Valid command ID - store in command_relations
                try:
                    self.cursor.execute("""
                        INSERT INTO command_relations
                        (source_command_id, target_command_id, relation_type, priority)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (source_command_id, target_command_id, relation_type) DO NOTHING
                    """, (rel['source'], rel['target'], rel['type'], rel['priority']))
                    self.stats['relations'] += 1
                except Exception as e:
                    print(f"  ⚠️  Relation error: {e}")
            else:
                # Not a command ID - store as descriptive guidance in command_relation_guidance
                try:
                    self.cursor.execute("""
                        INSERT INTO command_relation_guidance
                        (source_command_id, relation_type, guidance_text, display_order)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT DO NOTHING
                    """, (rel['source'], rel['type'], rel['target'], rel['priority']))
                    self.stats['guidance_relations'] += 1
                except Exception as e:
                    print(f"  ⚠️  Guidance relation error: {e}")

        self.conn.commit()
        print(f"✓ Created {self.stats['relations']} command relationships")
        print(f"✓ Created {self.stats['guidance_relations']} guidance relations")

    def migrate_attack_chains(self, json_dir: Path = None):
        """
        Migrate attack chains from JSON to SQL

        Args:
            json_dir: Directory containing chain JSON files
        """
        # TODO: Implement attack chain migration
        print("⚠️  Attack chain migration not yet implemented")
        pass

    def migrate_service_plugins(self):
        """
        Extract service→command mappings from Python plugins

        Analyzes track/services/*.py files to build service_commands table
        """
        # TODO: Implement service plugin extraction
        print("⚠️  Service plugin migration not yet implemented")
        pass

    def validate(self) -> Dict[str, Any]:
        """
        Validate migration integrity

        Returns:
            Dict with validation results
        """
        print("\n🔍 Validating migration...")

        results = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'stats': {}
        }

        # 1. Check command count
        self.cursor.execute("SELECT COUNT(*) as count FROM commands")
        cmd_count = self.cursor.fetchone()['count']
        results['stats']['commands'] = cmd_count
        print(f"  ✓ Commands in database: {cmd_count}")

        # 2. Check for orphaned relationships
        self.cursor.execute("""
            SELECT COUNT(*) as count FROM command_relations
            WHERE target_command_id NOT IN (SELECT id FROM commands)
        """)
        orphaned = self.cursor.fetchone()['count']
        if orphaned > 0:
            results['warnings'].append(f"{orphaned} orphaned command relationships")
            print(f"  ⚠️  {orphaned} orphaned relationships")

        # 3. Check for commands without tags
        self.cursor.execute("""
            SELECT COUNT(*) as count FROM commands c
            WHERE NOT EXISTS (
                SELECT 1 FROM command_tags WHERE command_id = c.id
            )
        """)
        no_tags = self.cursor.fetchone()['count']
        if no_tags > 0:
            results['warnings'].append(f"{no_tags} commands without tags")
            print(f"  ⚠️  {no_tags} commands without tags")

        # 4. Check variable consistency
        self.cursor.execute("SELECT COUNT(*) as count FROM variables")
        var_count = self.cursor.fetchone()['count']
        results['stats']['variables'] = var_count
        print(f"  ✓ Unique variables: {var_count}")

        # 5. Check tag usage
        self.cursor.execute("SELECT COUNT(*) as count FROM tags")
        tag_count = self.cursor.fetchone()['count']
        results['stats']['tags'] = tag_count
        print(f"  ✓ Unique tags: {tag_count}")

        print(f"\n{'✓' if results['valid'] else '❌'} Validation {'passed' if results['valid'] else 'failed'}")
        return results

    def print_statistics(self):
        """Print migration statistics"""
        print("\n" + "="*60)
        print("📊 MIGRATION STATISTICS")
        print("="*60)
        print(f"Commands migrated:      {self.stats['commands']}")
        print(f"Flags created:          {self.stats['flags']}")
        print(f"Variables created:      {self.stats['variables']}")
        print(f"Tags created:           {self.stats['tags']}")
        print(f"Relations created:      {self.stats['relations']} (command ID → command ID)")
        print(f"Guidance relations:     {self.stats['guidance_relations']} (descriptive text)")
        print(f"Indicators created:     {self.stats['indicators']}")

        if self.stats['errors']:
            print(f"\n❌ Errors encountered:   {len(self.stats['errors'])}")
            for error in self.stats['errors'][:5]:  # Show first 5
                print(f"  - {error}")
            if len(self.stats['errors']) > 5:
                print(f"  ... and {len(self.stats['errors']) - 5} more")
        else:
            print("\n✓ No errors encountered")

        print("="*60)

    def close(self):
        """Close database connection"""
        self.conn.close()


def main():
    """CLI entry point"""
    if len(sys.argv) < 2:
        print("Usage: python3 -m crack.db.migrate <commands|chains|all|validate>")
        sys.exit(1)

    action = sys.argv[1]

    # Initialize migration
    migration = CRACKMigration()

    try:
        if action == 'commands':
            print("🚀 Starting command migration...\n")
            migration.create_schema()
            migration.migrate_commands()
            migration.process_relations()
            migration.print_statistics()

        elif action == 'chains':
            print("🚀 Starting attack chain migration...\n")
            migration.create_schema()
            migration.migrate_attack_chains()
            migration.print_statistics()

        elif action == 'all':
            print("🚀 Starting full migration...\n")
            migration.create_schema()
            migration.migrate_commands()
            migration.process_relations()
            migration.migrate_attack_chains()
            migration.migrate_service_plugins()
            migration.print_statistics()
            migration.validate()

        elif action == 'validate':
            migration.validate()

        else:
            print(f"❌ Unknown action: {action}")
            print("Valid actions: commands, chains, all, validate")
            sys.exit(1)

    finally:
        migration.close()

    print("\n✅ Migration complete!")


if __name__ == '__main__':
    main()
