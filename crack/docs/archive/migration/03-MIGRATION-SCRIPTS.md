# 03 - Migration Scripts: PostgreSQL to Neo4j

## Prerequisites
- [01-ENVIRONMENT.md](01-ENVIRONMENT.md) - Both databases running
- [02-SCHEMA-DESIGN.md](02-SCHEMA-DESIGN.md) - Schema created in Neo4j

## Overview

Detailed specifications for data migration scripts from PostgreSQL to Neo4j graph database.

---

## Migration Strategy

### Three-Phase Approach

**Phase 1: Export** (PostgreSQL → JSON)
- Read all data from PostgreSQL
- Preserve relationships and metadata
- Output: `data/export/commands.json`, `attack_chains.json`, etc.

**Phase 2: Transform** (JSON → Neo4j Format)
- Convert relational structure to graph format
- Resolve foreign keys to node references
- Output: `data/neo4j/nodes.csv`, `relationships.csv`

**Phase 3: Import** (CSV → Neo4j)
- Batch import nodes
- Batch import relationships
- Validate integrity

---

## Script 1: Export from PostgreSQL

### Purpose

Extract all command, service, and attack chain data from PostgreSQL into intermediate JSON format.

### Script Specification

**File**: `scripts/export_postgresql.py`

**Command**:
```bash
python scripts/export_postgresql.py --output data/export/
```

**Output Files**:
```
data/export/
├── commands.json          # All commands with inline flags, variables
├── services.json          # Services with ports and aliases
├── attack_chains.json     # Chains with steps and dependencies
├── tags.json              # Tag definitions
├── variables.json         # Variable definitions
└── metadata.json          # Export timestamp, counts
```

### Required Data Extraction

#### Commands Export

**SQL Query**:
```sql
SELECT
    c.id,
    c.name,
    c.command_template,
    c.description,
    c.category,
    c.subcategory,
    c.oscp_relevance,
    c.notes,
    c.created_at,
    c.updated_at,
    -- Aggregate flags
    COALESCE(json_agg(DISTINCT jsonb_build_object(
        'flag', cf.flag,
        'explanation', cf.explanation,
        'required', cf.is_required
    )) FILTER (WHERE cf.flag IS NOT NULL), '[]') AS flags,
    -- Aggregate variables
    COALESCE(json_agg(DISTINCT jsonb_build_object(
        'name', v.name,
        'description', v.description,
        'data_type', v.data_type,
        'default_value', v.default_value,
        'position', cv.position,
        'required', cv.is_required,
        'example', cv.example_value
    )) FILTER (WHERE v.name IS NOT NULL), '[]') AS variables,
    -- Aggregate tags
    COALESCE(array_agg(DISTINCT t.name) FILTER (WHERE t.name IS NOT NULL), ARRAY[]::text[]) AS tags,
    -- Aggregate success indicators
    COALESCE(json_agg(DISTINCT jsonb_build_object(
        'pattern', si.pattern,
        'pattern_type', si.pattern_type,
        'priority', si.priority
    )) FILTER (WHERE si.indicator_type = 'success'), '[]') AS success_indicators,
    -- Aggregate failure indicators
    COALESCE(json_agg(DISTINCT jsonb_build_object(
        'pattern', fi.pattern,
        'pattern_type', fi.pattern_type,
        'priority', fi.priority
    )) FILTER (WHERE fi.indicator_type = 'failure'), '[]') AS failure_indicators
FROM commands c
LEFT JOIN command_flags cf ON c.id = cf.command_id
LEFT JOIN command_vars cv ON c.id = cv.command_id
LEFT JOIN variables v ON cv.variable_id = v.id
LEFT JOIN command_tags ct ON c.id = ct.command_id
LEFT JOIN tags t ON ct.tag_id = t.id
LEFT JOIN command_indicators si ON c.id = si.command_id AND si.indicator_type = 'success'
LEFT JOIN command_indicators fi ON c.id = fi.command_id AND fi.indicator_type = 'failure'
GROUP BY c.id;
```

**Python Implementation Pattern**:
```python
def export_commands(conn):
    """Export all commands with nested data"""
    cursor = conn.cursor()
    cursor.execute(COMMANDS_EXPORT_QUERY)

    commands = []
    for row in cursor.fetchall():
        command = {
            'id': row[0],
            'name': row[1],
            'template': row[2],
            'description': row[3],
            'category': row[4],
            'subcategory': row[5],
            'oscp_relevance': row[6],
            'notes': row[7],
            'created_at': row[8].isoformat() if row[8] else None,
            'updated_at': row[9].isoformat() if row[9] else None,
            'flags': row[10],
            'variables': row[11],
            'tags': row[12],
            'success_indicators': row[13],
            'failure_indicators': row[14]
        }
        commands.append(command)

    return commands
```

---

#### Command Relations Export

**SQL Query**:
```sql
SELECT
    source_command_id,
    target_command_id,
    relation_type,
    priority,
    condition,
    notes
FROM command_relations
ORDER BY source_command_id, priority;
```

**Output Format**:
```json
{
  "command_relations": [
    {
      "source": "gobuster-dir",
      "target": "ffuf-dir",
      "type": "alternative",
      "priority": 1,
      "condition": "When wordlist is small",
      "notes": "Faster for small scans"
    }
  ]
}
```

---

#### Attack Chains Export

**SQL Query**:
```sql
SELECT
    ac.id,
    ac.name,
    ac.description,
    ac.version,
    ac.category,
    ac.platform,
    ac.difficulty,
    ac.oscp_relevant,
    -- Steps with dependencies
    json_agg(json_build_object(
        'id', cs.id,
        'name', cs.name,
        'step_order', cs.step_order,
        'objective', cs.objective,
        'command_id', cs.command_id,
        'dependencies', (
            SELECT array_agg(depends_on_step_id)
            FROM step_dependencies
            WHERE step_id = cs.id
        )
    ) ORDER BY cs.step_order) AS steps,
    -- Prerequisites
    (SELECT array_agg(description ORDER BY priority)
     FROM chain_prerequisites
     WHERE chain_id = ac.id) AS prerequisites
FROM attack_chains ac
LEFT JOIN chain_steps cs ON ac.id = cs.chain_id
GROUP BY ac.id;
```

---

### Export Validation

**Checksum File**: `data/export/metadata.json`

```json
{
  "export_timestamp": "2025-11-08T10:30:00Z",
  "source_database": "postgresql://localhost/crack",
  "counts": {
    "commands": 1247,
    "services": 32,
    "attack_chains": 51,
    "tags": 104,
    "variables": 47,
    "command_relations": 3821,
    "chain_steps": 312
  },
  "checksums": {
    "commands.json": "sha256:abc123...",
    "services.json": "sha256:def456..."
  }
}
```

**Verification**:
```python
def validate_export(export_dir):
    """Ensure all data exported correctly"""
    metadata = json.load(open(f"{export_dir}/metadata.json"))

    # Count files
    commands = json.load(open(f"{export_dir}/commands.json"))
    assert len(commands) == metadata['counts']['commands']

    # Verify checksums
    for filename, expected_hash in metadata['checksums'].items():
        actual_hash = sha256_file(f"{export_dir}/{filename}")
        assert actual_hash == expected_hash
```

---

## Script 2: Transform to Neo4j Format

### Purpose

Convert exported JSON to Neo4j batch import CSV format.

### Script Specification

**File**: `scripts/transform_to_neo4j.py`

**Command**:
```bash
python scripts/transform_to_neo4j.py \
    --input data/export/ \
    --output data/neo4j/
```

**Output Structure**:
```
data/neo4j/
├── nodes/
│   ├── commands.csv
│   ├── variables.csv
│   ├── tags.csv
│   ├── services.csv
│   ├── attack_chains.csv
│   └── chain_steps.csv
└── relationships/
    ├── uses_variable.csv
    ├── has_flag.csv
    ├── tagged.csv
    ├── prerequisite.csv
    ├── alternative.csv
    ├── next_step.csv
    ├── enumerated_by.csv
    ├── has_step.csv
    └── depends_on.csv
```

### CSV Formats

#### Nodes: commands.csv

**Header**:
```csv
id:ID(Command),name,template,description,category,subcategory,oscp_relevance,notes,created_at:datetime,updated_at:datetime
```

**Example Rows**:
```csv
nmap-quick-scan,"Quick Full Port Scan","nmap -Pn -p- <TARGET>","Fast all-port scan",recon,enumeration,high,"Use for initial discovery",2025-01-15T10:00:00Z,2025-01-15T10:00:00Z
gobuster-dir,"Directory Brute Force","gobuster dir -u <URL> -w <WORDLIST>","Enumerate web directories",web,enumeration,high,,2025-01-16T08:30:00Z,2025-01-16T08:30:00Z
```

**Transformation Logic**:
```python
def transform_commands_to_csv(commands_json, output_csv):
    """Convert commands JSON to Neo4j CSV"""
    with open(output_csv, 'w', newline='') as f:
        writer = csv.writer(f, quoting=csv.QUOTE_NONNUMERIC)

        # Header
        writer.writerow([
            'id:ID(Command)', 'name', 'template', 'description',
            'category', 'subcategory', 'oscp_relevance', 'notes',
            'created_at:datetime', 'updated_at:datetime'
        ])

        # Rows
        for cmd in commands_json:
            writer.writerow([
                cmd['id'],
                cmd['name'],
                cmd['template'],
                cmd['description'],
                cmd['category'],
                cmd.get('subcategory', ''),
                cmd['oscp_relevance'],
                cmd.get('notes', ''),
                cmd.get('created_at', ''),
                cmd.get('updated_at', '')
            ])
```

---

#### Relationships: prerequisite.csv

**Header**:
```csv
:START_ID(Command),:END_ID(Command),priority:int,condition,notes
```

**Example Rows**:
```csv
bash-reverse-shell,nc-listener,1,"Requires listening port","Start listener before payload"
wordpress-sqli,nmap-service-enum,1,"Need to know WordPress is running",
```

**Transformation Logic**:
```python
def transform_relations_to_csv(relations_json, output_dir):
    """Split relations by type into separate CSVs"""

    # Group by relation type
    by_type = defaultdict(list)
    for rel in relations_json:
        by_type[rel['type']].append(rel)

    # Write each type to separate CSV
    for rel_type, rels in by_type.items():
        csv_file = f"{output_dir}/relationships/{rel_type}.csv"

        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f, quoting=csv.QUOTE_NONNUMERIC)

            writer.writerow([
                ':START_ID(Command)', ':END_ID(Command)',
                'priority:int', 'condition', 'notes'
            ])

            for rel in rels:
                writer.writerow([
                    rel['source'],
                    rel['target'],
                    rel.get('priority', 1),
                    rel.get('condition', ''),
                    rel.get('notes', '')
                ])
```

---

#### Special Case: Nested Data Extraction

**Tags** (many-to-many):
```python
def extract_command_tags(commands_json, tags_csv, tagged_csv):
    """Extract unique tags and create relationship CSV"""

    # Collect unique tags
    unique_tags = set()
    tagged_rels = []

    for cmd in commands_json:
        for tag_name in cmd.get('tags', []):
            unique_tags.add(tag_name)
            tagged_rels.append({
                'command_id': cmd['id'],
                'tag_name': tag_name
            })

    # Write tags nodes
    with open(tags_csv, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(['name:ID(Tag)', 'category'])
        for tag in sorted(unique_tags):
            # Infer category from tag name
            category = infer_tag_category(tag)
            writer.writerow([tag, category])

    # Write tagged relationships
    with open(tagged_csv, 'w') as f:
        writer = csv.writer(f)
        writer.writerow([':START_ID(Command)', ':END_ID(Tag)'])
        for rel in tagged_rels:
            writer.writerow([rel['command_id'], rel['tag_name']])
```

---

## Script 3: Import into Neo4j

### Purpose

Batch import CSV files into Neo4j using `neo4j-admin import` or Cypher `LOAD CSV`.

### Script Specification

**File**: `scripts/import_to_neo4j.py`

**Command**:
```bash
python scripts/import_to_neo4j.py \
    --data-dir data/neo4j/ \
    --neo4j-uri bolt://localhost:7687
```

### Import Strategy A: neo4j-admin (Fastest, Offline)

**Use When**: Initial bulk import, Neo4j is NOT running

**Command**:
```bash
# Stop Neo4j
docker-compose stop neo4j

# Run import
docker-compose run --rm neo4j neo4j-admin database import full \
    --nodes=Command=import/nodes/commands.csv \
    --nodes=Variable=import/nodes/variables.csv \
    --nodes=Tag=import/nodes/tags.csv \
    --relationships=USES_VARIABLE=import/relationships/uses_variable.csv \
    --relationships=TAGGED=import/relationships/tagged.csv \
    --relationships=PREREQUISITE=import/relationships/prerequisite.csv \
    --overwrite-destination=true \
    neo4j

# Start Neo4j
docker-compose start neo4j
```

**Advantages**:
- 10x faster than Cypher LOAD CSV
- No transaction overhead
- Optimized for large datasets

**Disadvantages**:
- Requires database downtime
- Cannot do incremental updates

---

### Import Strategy B: LOAD CSV (Incremental, Online)

**Use When**: Database is running, incremental sync

**Python Implementation**:
```python
def import_nodes_cypher(session, node_label, csv_path):
    """Import nodes using LOAD CSV"""

    query = f"""
    LOAD CSV WITH HEADERS FROM 'file:///{csv_path}' AS row
    CREATE (n:{node_label} {{
        id: row.`id:ID({node_label})`,
        name: row.name,
        template: row.template,
        description: row.description,
        category: row.category,
        oscp_relevance: row.oscp_relevance
    }})
    """

    session.run(query)

def import_relationships_cypher(session, rel_type, csv_path, start_label, end_label):
    """Import relationships using LOAD CSV"""

    query = f"""
    LOAD CSV WITH HEADERS FROM 'file:///{csv_path}' AS row
    MATCH (start:{start_label} {{id: row.`:START_ID({start_label})`}})
    MATCH (end:{end_label} {{id: row.`:END_ID({end_label})`}})
    CREATE (start)-[r:{rel_type} {{
        priority: toInteger(row.`priority:int`),
        condition: row.condition,
        notes: row.notes
    }}]->(end)
    """

    session.run(query)
```

**Batch Processing** (for large datasets):
```python
def import_nodes_batched(session, node_label, csv_path, batch_size=1000):
    """Import nodes in batches to avoid memory issues"""

    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        batch = []

        for row in reader:
            batch.append(row)

            if len(batch) >= batch_size:
                create_node_batch(session, node_label, batch)
                batch = []

        # Process remaining
        if batch:
            create_node_batch(session, node_label, batch)

def create_node_batch(session, label, rows):
    """Create multiple nodes in single transaction"""
    query = f"""
    UNWIND $rows AS row
    CREATE (n:{label})
    SET n = row
    """
    session.run(query, rows=rows)
```

---

## Script 4: Sync Strategy (Incremental Updates)

### Purpose

Keep Neo4j in sync with PostgreSQL after initial import.

### Script Specification

**File**: `scripts/sync_to_neo4j.py`

**Command**:
```bash
# Manual sync
python scripts/sync_to_neo4j.py

# Scheduled sync (cron)
0 2 * * * cd /home/kali/Desktop/OSCP/crack && python db/neo4j-migration/scripts/sync_to_neo4j.py
```

### Sync Logic

**Approach**: Timestamp-based incremental update

```python
def sync_commands(pg_conn, neo4j_session):
    """Sync only changed commands since last sync"""

    # Get last sync timestamp from Neo4j
    result = neo4j_session.run("""
        MATCH (m:SyncMetadata)
        RETURN m.last_sync_at AS last_sync
        ORDER BY m.last_sync_at DESC
        LIMIT 1
    """)
    last_sync = result.single()['last_sync'] if result.peek() else '1970-01-01'

    # Get changed commands from PostgreSQL
    cursor = pg_conn.cursor()
    cursor.execute("""
        SELECT id, name, command_template, updated_at
        FROM commands
        WHERE updated_at > %s
    """, (last_sync,))

    changed_commands = cursor.fetchall()

    # Upsert into Neo4j
    for cmd in changed_commands:
        neo4j_session.run("""
            MERGE (c:Command {id: $id})
            SET c.name = $name,
                c.template = $template,
                c.updated_at = datetime($updated_at)
        """, id=cmd[0], name=cmd[1], template=cmd[2], updated_at=cmd[3].isoformat())

    # Update sync timestamp
    neo4j_session.run("""
        MERGE (m:SyncMetadata {id: 'commands_sync'})
        SET m.last_sync_at = datetime()
    """)

    return len(changed_commands)
```

---

## Validation Queries

### Post-Import Verification

```cypher
// 1. Count nodes by label
CALL db.labels() YIELD label
CALL apoc.cypher.run('MATCH (n:' + label + ') RETURN count(n) AS count', {})
YIELD value
RETURN label, value.count AS node_count
ORDER BY node_count DESC;

// Expected output:
// Command: 1247
// Tag: 104
// Variable: 47
// Service: 32
// AttackChain: 51
// ChainStep: 312
```

```cypher
// 2. Count relationships by type
CALL db.relationshipTypes() YIELD relationshipType
CALL apoc.cypher.run('MATCH ()-[r:' + relationshipType + ']->() RETURN count(r) AS count', {})
YIELD value
RETURN relationshipType, value.count AS rel_count
ORDER BY rel_count DESC;

// Expected output:
// USES_VARIABLE: ~3000
// TAGGED: ~5000
// HAS_FLAG: ~1500
// PREREQUISITE: ~800
// ALTERNATIVE: ~600
```

```cypher
// 3. Check for orphaned nodes
MATCH (n)
WHERE NOT (n)-[]-()
RETURN labels(n)[0] AS label, count(n) AS orphan_count;

// Expected: 0 orphans (all nodes should have relationships)
```

```cypher
// 4. Verify command integrity
MATCH (c:Command)
WHERE c.template CONTAINS '<' AND NOT (c)-[:USES_VARIABLE]->()
RETURN c.id, c.template
LIMIT 10;

// Expected: 0 results (all placeholders should have variable relationships)
```

---

## Troubleshooting

### Issue: LOAD CSV File Not Found

**Error**: `Couldn't load the external resource`

**Solution**: Copy CSVs to Neo4j import directory
```bash
docker cp data/neo4j/nodes/. crack-neo4j:/var/lib/neo4j/import/nodes/
docker cp data/neo4j/relationships/. crack-neo4j:/var/lib/neo4j/import/relationships/
```

---

### Issue: Duplicate Nodes on Re-import

**Error**: `Node(123) already exists with label Command and property id='nmap-quick-scan'`

**Solution**: Use MERGE instead of CREATE
```cypher
// Wrong
CREATE (c:Command {id: $id})

// Correct
MERGE (c:Command {id: $id})
ON CREATE SET c.created_at = datetime()
ON MATCH SET c.updated_at = datetime()
```

---

### Issue: Import Timeout

**Error**: Transaction timeout after 30 seconds

**Solution**: Increase timeout or batch size
```python
# Increase driver timeout
driver = GraphDatabase.driver(
    uri,
    auth=auth,
    max_transaction_retry_time=300  # 5 minutes
)

# Reduce batch size
import_nodes_batched(session, 'Command', csv_path, batch_size=500)
```

---

## Performance Benchmarks

### Expected Import Times

| Dataset | Rows | neo4j-admin | LOAD CSV (Batched) | LOAD CSV (Naive) |
|---------|------|-------------|-------------------|------------------|
| Commands | 1,247 | 0.5s | 3s | 15s |
| Tags | 104 | 0.1s | 0.5s | 2s |
| Services | 32 | 0.1s | 0.2s | 1s |
| Command Relations | 3,821 | 1s | 8s | 45s |
| Attack Chains | 51 | 0.1s | 0.5s | 2s |
| **Total** | **~5,500** | **~2s** | **~15s** | **~70s** |

---

## Next Steps

1. **Run Export**: `python scripts/export_postgresql.py`
2. **Transform Data**: `python scripts/transform_to_neo4j.py`
3. **Import to Neo4j**: `python scripts/import_to_neo4j.py`
4. **Validate**: Run verification queries above
5. **Develop Adapter**: [04-ADAPTER-IMPLEMENTATION.md](04-ADAPTER-IMPLEMENTATION.md)

---

## See Also

- [02-SCHEMA-DESIGN.md](02-SCHEMA-DESIGN.md#schema-creation-script) - Neo4j schema
- [04-ADAPTER-IMPLEMENTATION.md](04-ADAPTER-IMPLEMENTATION.md) - Using imported data
- [../repositories/command_repository.py](../repositories/command_repository.py) - Current PostgreSQL queries

---

**Document Version**: 1.0.0
**Last Updated**: 2025-11-08
**Owner**: Data Migration Team
**Status**: Specification Complete (Scripts TBD)
