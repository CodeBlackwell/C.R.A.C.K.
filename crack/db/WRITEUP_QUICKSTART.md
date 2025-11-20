# Writeup Migration Quickstart

## Add New Writeup in 4 Steps

### 1. Create Writeup JSON

```bash
cd /home/kali/Desktop/OSCP/crack/db/data/writeups

# Create directory structure
mkdir -p {platform}/{machine_name}

# Create writeup file (use Usage.json as template)
cp hackthebox/Usage/Usage.json {platform}/{machine_name}/{machine_name}.json
```

**Required structure:**
```
writeups/
  {platform}/          # hackthebox, proving_grounds, tryhackme
    {machine_name}/
      {machine_name}.json    # Main writeup
      {machine_name}.txt     # Original writeup (optional)
      images/                # Screenshots (optional)
```

**Template structure:**
- `id`: kebab-case (e.g., `htb-usage`, `pg-monsoon`)
- `name`: Machine name
- `source`: Platform, type, release date, URL
- `metadata`: Difficulty, OS, IP, author
- `oscp_relevance`: Score (high/medium/low), reasoning, exam_applicable
- `attack_phases`: Array of phases with commands used
- `time_breakdown`: Total minutes, flags captured

### 2. Validate Writeup

```bash
cd /home/kali/Desktop/OSCP/crack/db

# Basic validation
python3 scripts/validate_writeups.py \
  data/writeups/{platform}/{machine}/{machine}.json

# Check missing commands
python3 scripts/validate_writeups.py \
  data/writeups/{platform}/{machine}/{machine}.json --missing-only

# Show error summary
python3 scripts/validate_writeups.py \
  data/writeups/{platform}/{machine}/{machine}.json --summary
```

**Fix validation errors:**
- Missing command IDs → Create commands in `../../reference/data/commands/`
- Schema errors → Check field types, required fields
- Short contexts → Expand to 20+ chars

### 3. Create Missing Commands

**If validation shows missing command IDs:**

```bash
# Create command in appropriate category
nano ../../reference/data/commands/{category}/{subcategory}.json
```

**Minimal command structure:**
```json
{
  "id": "command-action-target",
  "name": "Human Readable Name",
  "category": "web|enumeration|exploitation|post-exploit|utilities",
  "command": "command <PLACEHOLDER>",
  "description": "Brief description",
  "tags": ["OSCP:HIGH", "CATEGORY", "ACTION"],
  "variables": [
    {
      "name": "<PLACEHOLDER>",
      "description": "What this is",
      "example": "example_value",
      "required": true
    }
  ],
  "oscp_relevance": "high"
}
```

**Re-validate until 0 errors:**
```bash
python3 scripts/validate_writeups.py data/writeups/{platform}/{machine}/{machine}.json
# Output: ✓ Writeup is VALID
```

### 4. Migrate to Neo4j

**Dry run (CSV only):**
```bash
python3 scripts/migrate_writeups.py --dry-run --verbose
```

**Full migration:**
```bash
python3 scripts/migrate_writeups.py --import --verify --verbose
```

**Verify in Neo4j:**
```cypher
// Check writeup imported
MATCH (w:Writeup) RETURN w.name, w.difficulty, w.oscp_relevance

// Count relationships
MATCH (w:Writeup {id: 'htb-usage'})-[d:DEMONSTRATES]->()
RETURN count(d)

// View failed attempts (learning goldmine)
MATCH (w:Writeup)-[fa:FAILED_ATTEMPT]->(c:Command)
RETURN w.name, c.name, fa.lesson_learned
```

---

## Quick Reference

### File Locations
```
db/
├── data/writeups/              # Source JSON files
│   ├── hackthebox/
│   ├── proving_grounds/
│   └── writeup-schema.json    # Schema reference
├── scripts/
│   ├── validate_writeups.py   # Validation
│   └── migrate_writeups.py    # Migration
└── neo4j-migration/csv/writeups/  # Generated CSVs
```

### Common Commands

```bash
# Validate
python3 scripts/validate_writeups.py data/writeups/{platform}/{machine}/{machine}.json

# Extract to CSV
python3 scripts/migrate_writeups.py --dry-run

# Import to Neo4j
python3 scripts/migrate_writeups.py --import --verify

# Count writeups
python3 -c "from load_writeups import load_writeup_jsons; w,e = load_writeup_jsons('data/writeups'); print(f'{len(w)} writeups')"
```

### Schema Reference

**Key writeup fields:**
- `id` - Unique identifier (kebab-case)
- `attack_phases[]` - Array of phase objects
  - `phase` - enumeration|foothold|lateral_movement|privilege_escalation|post_exploitation
  - `commands_used[]` - Array of command usage
    - `command_id` - References command in database
    - `context` - Why command was used (min 20 chars)
    - `success` - Boolean
  - `failed_attempts[]` - Array of failures
    - `lesson_learned` - Critical field (min 30 chars)
- `tags[]` - Must include OSCP:HIGH|MEDIUM|LOW

### Validation Checklist

✓ All `command_id` values exist in commands database
✓ Phase names are valid
✓ CVE format correct (CVE-YYYY-NNNNN or null)
✓ OSCP tag present (OSCP:HIGH|MEDIUM|LOW)
✓ Failed attempts have `lesson_learned` (min 30 chars)
✓ Context fields min 20 chars
✓ Time estimates present

### Troubleshooting

**"Unknown command ID 'foo-bar'"**
→ Create command in `../../reference/data/commands/{category}/`

**"Schema validation failed"**
→ Check `data/writeups/writeup-schema.json` for required fields

**"Writeup has X errors"**
→ Use `--summary` flag to group errors by type

**Neo4j import fails**
→ Ensure Neo4j running: `sudo systemctl status neo4j`

---

## Example Workflow

```bash
# 1. Create new writeup
cd db/data/writeups
cp -r hackthebox/Usage proving_grounds/Monsoon

# 2. Edit writeup
nano proving_grounds/Monsoon/Monsoon.json
# Update id, name, source, metadata, attack_phases

# 3. Validate
cd ../..
python3 scripts/validate_writeups.py data/writeups/proving_grounds/Monsoon/Monsoon.json --missing-only

# 4. Create missing commands (if needed)
nano ../../reference/data/commands/web/monsoon-specific.json

# 5. Re-validate
python3 scripts/validate_writeups.py data/writeups/proving_grounds/Monsoon/Monsoon.json
# ✓ Writeup is VALID

# 6. Migrate
python3 scripts/migrate_writeups.py --import --verify --verbose
# ✓ Migration complete

# 7. Query Neo4j
# Visit http://localhost:7474
# MATCH (w:Writeup) RETURN w.name
```

---

## Pro Tips

**Reuse existing commands** - Check commands database before creating new ones
**Document failures** - Most valuable learning comes from failed attempts
**Time tracking** - Include realistic time estimates for exam planning
**OSCP focus** - Prioritize techniques applicable to OSCP exam
**Template usage** - Copy `Usage.json` and modify rather than starting from scratch
**Validate early** - Run validation after each phase to catch errors quickly

---

**See also:**
- `data/writeups/writeup-schema.json` - Complete schema definition
- `scripts/WRITEUP_MIGRATION_GUIDE.md` - Detailed documentation
- `data/writeups/hackthebox/Usage/Usage.json` - Complete example
