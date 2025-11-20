# Writeup Migration Guide

## Overview

The `migrate_writeups.py` script provides a complete workflow for migrating writeup JSON files to Neo4j graph database. It handles:

1. **Loading** - Reads writeup JSON files from the data directory
2. **Validation** - Validates against schema
3. **Extraction** - Converts writeups to CSV format for Neo4j
4. **Import** - Loads data into Neo4j database (optional)
5. **Verification** - Confirms successful import (optional)

## Quick Start

### Dry Run (CSV extraction only)
```bash
cd /home/kali/Desktop/OSCP/crack/db
python3 scripts/migrate_writeups.py --dry-run --verbose
```

This will:
- Load all writeups from `data/writeups/`
- Extract to CSV files in `neo4j-migration/csv/writeups/`
- **NOT** import to Neo4j

### Full Migration with Import
```bash
python3 scripts/migrate_writeups.py --import --verify --verbose
```

This will:
- Load writeups
- Extract to CSV
- Import to Neo4j
- Verify import success

## Usage Examples

### 1. Basic Dry Run
Extract writeups to CSV without Neo4j import:
```bash
python3 scripts/migrate_writeups.py --dry-run
```

### 2. Import to Local Neo4j
Full migration with default Neo4j connection:
```bash
python3 scripts/migrate_writeups.py --import --verify
```

### 3. Custom Neo4j Connection
Connect to remote or custom Neo4j instance:
```bash
python3 scripts/migrate_writeups.py --import \
  --neo4j-uri bolt://remote-server:7687 \
  --neo4j-user admin \
  --neo4j-password secretpassword
```

### 4. Custom Directories
Specify custom input/output directories:
```bash
python3 scripts/migrate_writeups.py \
  --writeup-dir /path/to/writeups \
  --output /path/to/csv/output \
  --dry-run
```

### 5. Verbose Output
Enable detailed logging:
```bash
python3 scripts/migrate_writeups.py --import --verify --verbose
```

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--writeup-dir PATH` | Path to writeups directory | `db/data/writeups` |
| `--output PATH` | CSV output directory | `db/neo4j-migration/csv/writeups` |
| `--dry-run` | Extract to CSV only, skip Neo4j import | False |
| `--import` | Import to Neo4j after extraction | False |
| `--neo4j-uri URI` | Neo4j connection URI | `bolt://localhost:7687` |
| `--neo4j-user USER` | Neo4j username | `neo4j` |
| `--neo4j-password PASS` | Neo4j password | `password` |
| `--verify` | Verify import after completion | False |
| `--verbose` | Enable detailed logging | False |

## CSV Files Generated

The script generates the following CSV files:

### Node Files
- `writeup_nodes.csv` - Writeup metadata (id, name, platform, difficulty, etc.)
- `cve_nodes.csv` - CVE information (cve_id, name, severity, component)
- `technique_nodes.csv` - Attack techniques (name, category, oscp_applicable)
- `platform_nodes.csv` - Platforms (HackTheBox, ProvingGrounds, etc.)
- `skill_nodes.csv` - Skills required/taught (category, oscp_importance)

### Relationship Files
- `writeup_demonstrates_command.csv` - Command usage in writeup
- `writeup_failed_attempt.csv` - Failed attempts and lessons learned
- `writeup_exploits_cve.csv` - CVEs exploited in writeup
- `writeup_teaches_technique.csv` - Techniques demonstrated
- `writeup_from_platform.csv` - Source platform
- `writeup_requires_skill.csv` - Prerequisites
- `writeup_teaches_skill.csv` - Skills acquired

## Workflow

### Step 1: Load Writeups
```
ℹ Loading writeups from: /path/to/writeups
✓ Loaded 1 writeup(s)
```

The script recursively searches the writeup directory for JSON files matching the writeup schema.

### Step 2: Extract to CSV
```
ℹ Extracting to CSV in: /path/to/output
→ Extracting writeup nodes...
→   writeup_nodes.csv: 1 rows
→ Extracting CVE nodes...
→   cve_nodes.csv: 1 rows
...
✓ CSV extraction complete
```

Each extractor class processes the writeups and generates CSV files with proper headers.

### Step 3: Import to Neo4j (if --import flag used)
```
ℹ Importing to Neo4j at: bolt://localhost:7687
✓ Connected to Neo4j
→ Importing writeup nodes...
→ Importing CVE nodes...
...
✓ Neo4j import complete
```

Uses Cypher queries to `MERGE` nodes and relationships into Neo4j.

### Step 4: Verify Import (if --verify flag used)
```
ℹ Verifying Neo4j import...

Neo4j Import Verification:
  Writeups: 1
  CVEs: 1
  Techniques: 1
  Platforms: 1
  Skills: 10
  DEMONSTRATES relationships: 45
  FAILED_ATTEMPT relationships: 2

Verification PASSED
```

Queries Neo4j to count nodes and relationships, comparing against expected values.

### Step 5: Summary
```
============================================================
Migration Summary
============================================================
Writeups processed: 1
Errors encountered: 0

Nodes extracted:
  Writeups: 1
  CVEs: 1
  Techniques: 1
  Platforms: 1
  Skills: 10

Relationships extracted:
  DEMONSTRATES: 45
  FAILED_ATTEMPT: 2
  EXPLOITS_CVE: 1
  TEACHES_TECHNIQUE: 1
  FROM_PLATFORM: 1
  REQUIRES_SKILL: 4
  TEACHES_SKILL: 6
============================================================
```

## Prerequisites

### Python Dependencies
```bash
pip install neo4j
```

### Neo4j Setup
Ensure Neo4j is running:
```bash
# Start Neo4j
sudo systemctl start neo4j

# Check status
sudo systemctl status neo4j

# Or use Docker
docker run -d \
  --name neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/password \
  neo4j:latest
```

Access Neo4j Browser: http://localhost:7474

## Troubleshooting

### Error: "Could not import writeup extractors"
**Cause**: Missing extractor modules

**Solution**: Ensure the following files exist:
- `db/neo4j-migration/scripts/load_writeups.py`
- `db/neo4j-migration/scripts/writeup_extractors.py`

### Error: "neo4j driver not installed"
**Cause**: Python neo4j package not installed

**Solution**:
```bash
pip install neo4j
```

### Error: "Failed to connect to Neo4j"
**Cause**: Neo4j not running or wrong credentials

**Solution**:
1. Check Neo4j is running: `sudo systemctl status neo4j`
2. Verify connection: `bolt://localhost:7687`
3. Check credentials (default: `neo4j`/`password`)
4. Reset password in Neo4j Browser if needed

### Warning: "Expected X nodes, found Y"
**Cause**: Import verification mismatch

**Solution**:
1. Check Neo4j logs for errors
2. Verify CSV files contain expected data
3. Clear database and re-import:
   ```cypher
   MATCH (n) DETACH DELETE n
   ```

### Error: "No writeups found"
**Cause**: Writeup directory empty or wrong path

**Solution**:
1. Verify directory: `ls -la db/data/writeups/`
2. Check for JSON files
3. Use `--writeup-dir` to specify correct path

## Integration with Existing Workflow

### After Adding New Writeup
1. Validate writeup:
   ```bash
   python3 db/scripts/validate_writeups.py db/data/writeups/platform/machine/machine.json
   ```

2. Migrate to CSV:
   ```bash
   python3 db/scripts/migrate_writeups.py --dry-run --verbose
   ```

3. Import to Neo4j:
   ```bash
   python3 db/scripts/migrate_writeups.py --import --verify
   ```

### Bulk Migration
For migrating multiple writeups:
```bash
# Extract all to CSV
python3 scripts/migrate_writeups.py --dry-run

# Review CSV files
ls -la neo4j-migration/csv/writeups/

# Import to Neo4j
python3 scripts/migrate_writeups.py --import --verify --verbose
```

## Neo4j Queries

### After successful import, query writeups:

```cypher
// List all writeups
MATCH (w:Writeup) RETURN w.name, w.difficulty, w.oscp_relevance

// Find writeups demonstrating a specific command
MATCH (w:Writeup)-[d:DEMONSTRATES]->(c:Command {id: 'sqlmap-from-request-level3'})
RETURN w.name, d.context, d.success

// Find all CRITICAL failed attempts (learning goldmine!)
MATCH (w:Writeup)-[fa:FAILED_ATTEMPT]->(c:Command)
WHERE fa.importance = 'critical'
RETURN w.name, c.name, fa.lesson_learned, fa.time_wasted_minutes
ORDER BY fa.time_wasted_minutes DESC

// Find skills taught by writeup
MATCH (w:Writeup {id: 'htb-usage'})-[ts:TEACHES_SKILL]->(s:Skill)
RETURN s.name, s.category, ts.proficiency_level
```

## Next Steps

1. **Add More Writeups**: Create writeup JSON files in `db/data/writeups/`
2. **Validate**: Run `validate_writeups.py` on each new writeup
3. **Migrate**: Use `migrate_writeups.py --import` to add to Neo4j
4. **Query**: Use Neo4j Browser to explore relationships
5. **Analyze**: Build learning paths, find patterns, identify gaps

## File Locations

```
OSCP/crack/db/
├── scripts/
│   ├── migrate_writeups.py          # Main migration script
│   ├── validate_writeups.py         # Validation script
│   └── WRITEUP_MIGRATION_GUIDE.md   # This file
├── data/
│   └── writeups/                    # Source writeup JSON files
│       ├── hackthebox/
│       │   └── Usage/Usage.json
│       ├── proving_grounds/
│       └── writeup-schema.json
└── neo4j-migration/
    ├── scripts/
    │   ├── load_writeups.py         # Writeup loader
    │   └── writeup_extractors.py    # CSV extractors
    └── csv/
        └── writeups/                # Generated CSV files
            ├── writeup_nodes.csv
            ├── cve_nodes.csv
            └── ...
```

## Conclusion

The writeup migration script provides a complete, reusable workflow for managing writeup data in Neo4j. Use `--dry-run` during development, `--import` for production, and `--verify` to ensure data integrity.

For questions or issues, refer to `/home/kali/Desktop/OSCP/crack/db/CLAUDE.md` for project conventions.
