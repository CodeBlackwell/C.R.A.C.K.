# Professional Writeup System - Documentation

## Overview

The writeup system integrates complete machine walkthroughs into the CRACK Track reference database, enabling:
- **Context-aware command learning**: See HOW and WHY commands are used
- **Failure documentation**: Learn from mistakes (more valuable than successes)
- **Time tracking**: Plan exam time management based on real data
- **Pattern recognition**: Identify similar machines for targeted practice
- **Skill progression**: Build learning paths from prerequisites to advanced techniques

## Quick Start

### 1. Validate Existing Writeup

```bash
cd /home/kali/Desktop/pentest/crack
python3 db/scripts/validate_writeups.py \
  db/data/writeups/hackthebox/Usage/Usage.json \
  --schema db/data/writeups/writeup-schema.json \
  --commands-dir reference/data/commands
```

**Expected output:**
- ✓ Valid: All checks pass
- ✗ Invalid: Lists specific errors (command IDs, missing fields, format issues)

### 2. Create New Writeup

**Directory structure:**
```bash
mkdir -p db/data/writeups/{platform}/{machine_name}/images
touch db/data/writeups/{platform}/{machine_name}/{machine_name}.json
```

**Use Usage.json as template:**
```bash
cp db/data/writeups/hackthebox/Usage/Usage.json \
   db/data/writeups/{platform}/{machine_name}/{machine_name}.json
```

**Edit the JSON file with your machine details.**

### 3. Extract to CSV (Future Neo4j Import)

```bash
cd /home/kali/Desktop/pentest/crack/db/neo4j-migration/scripts

# Load writeups
python3
>>> from load_writeups import load_writeup_jsons
>>> writeups, errors = load_writeup_jsons('../../data/writeups')
>>> print(f"Loaded {len(writeups)} writeups")

# Extract to CSV (integration with transform_to_neo4j.py TBD)
>>> from writeup_extractors import WRITEUP_EXTRACTORS
>>> writeup_nodes = WRITEUP_EXTRACTORS['writeups_nodes'].extract_nodes(writeups)
>>> print(f"Extracted {len(writeup_nodes)} writeup nodes")
```

## Schema Reference

### Minimum Required Fields

```json
{
  "id": "htb-machine-name",
  "name": "Machine Name",
  "source": {
    "platform": "HackTheBox",
    "type": "retired"
  },
  "metadata": {
    "difficulty": "easy",
    "os": "linux",
    "writeup_author": "Your Name",
    "writeup_date": "2025-01-01"
  },
  "relevance": {
    "score": "high",
    "reasoning": "Demonstrates security-critical SQL injection and privilege escalation",
    "exam_applicable": true
  },
  "synopsis": "Machine involves SQL injection to dump credentials, file upload to RCE, and symlink privilege escalation.",
  "skills": {
    "required": ["Web fundamentals", "Linux basics"],
    "learned": ["SQL Injection", "File upload bypass", "Symlink abuse"]
  },
  "tags": ["PRIORITY:HIGH", "SQL_INJECTION", "FILE_UPLOAD", "LINUX"],
  "attack_phases": [
    {
      "phase": "enumeration",
      "duration_minutes": 15,
      "description": "Port scanning and web enumeration",
      "commands_used": [
        {
          "command_id": "nmap-quick-scan",
          "context": "Initial port discovery",
          "step_number": 1,
          "success": true
        }
      ],
      "failed_attempts": [],
      "key_findings": ["SSH open", "HTTP with redirect to domain"]
    }
  ],
  "time_breakdown": {
    "total_minutes": 120,
    "flags_captured": {"user": "/home/user/user.txt", "root": "/root/root.txt"}
  },
  "key_learnings": [
    {
      "category": "web_exploitation",
      "lesson": "Always test SQL injection manually before using sqlmap",
      "detail": "Manual testing confirmed vulnerability that automated tool missed at default settings",
      "importance": "critical"
    }
  ]
}
```

### Valid Phase Names

- `enumeration`
- `foothold`
- `lateral_movement`
- `privilege_escalation`
- `post_exploitation`

### Valid Difficulty Levels

- `easy`
- `medium`
- `hard`
- `insane`

### Valid Relevance Scores

- `high` - Techniques directly applicable to professional assessment
- `medium` - Useful concepts but not exam-critical
- `low` - Educational but rarely encountered in assessments

## Failed Attempts - The Most Important Section!

**Why document failures?**
- Teaches troubleshooting skills
- Reveals tool limitations
- Shows real decision-making process
- Prevents repeating mistakes
- More valuable than successes for learning

**Example:**

```json
{
  "attempt": "sqlmap with default settings (no --level flag)",
  "command_executed": "sqlmap -r reset.req -p email --batch",
  "expected": "Detection of blind SQL injection",
  "actual": "WARNING: POST parameter 'email' does not seem to be injectable",
  "reason": "Default sqlmap test level (1) insufficient for detecting boolean-based blind SQLi in this application. Required --level 3 for more thorough test payloads.",
  "solution": "Increase test depth with --level 3 flag as suggested by sqlmap error message",
  "lesson_learned": "CRITICAL LESSON: Automated tools have limitations. Always trust manual verification over tool defaults. Manual testing with 'test' OR 1=1;-- -' confirmed injection, but tool missed it. Read tool error messages carefully - sqlmap explicitly suggested increasing --level.",
  "time_wasted_minutes": 15,
  "documentation_importance": "critical",
  "notes": "This is a common professional assessment scenario: blind SQLi that requires increased sqlmap sensitivity. Document this pattern for future reference."
}
```

## Command ID Mapping

### When Command Doesn't Exist

If validation reports `Unknown command ID`, you have two options:

**Option 1: Find existing similar command**
```bash
cd /home/kali/Desktop/pentest/crack
grep -r "sqlmap" reference/data/commands/ --include="*.json" | grep "\"id\""
```

**Option 2: Create placeholder command**
```json
{
  "id": "sqlmap-from-request-level3",
  "name": "Sqlmap with Request File and Level 3",
  "category": "web",
  "command": "sqlmap -r <REQUEST_FILE> -p <PARAMETER> --batch --level 3",
  "description": "Automated SQL injection with increased test depth for blind SQLi",
  "tags": ["PRIORITY:HIGH", "WEB", "SQLI", "SQLMAP"],
  "notes": "Use --level 3 for blind SQL injection detection. Default level (1) often insufficient."
}
```

Add to: `reference/data/commands/web/sql-injection.json`

## Neo4j Relationships (Once Imported)

### Query: Find All Commands in a Writeup

```cypher
MATCH (w:Writeup {id: 'htb-usage'})-[d:DEMONSTRATES]->(c:Command)
RETURN c.name, d.phase, d.step_number, d.context, d.success
ORDER BY d.phase, d.step_number
```

### Query: Find Critical Learning Moments

```cypher
MATCH (w:Writeup)-[fa:FAILED_ATTEMPT]->(c:Command)
WHERE fa.importance = 'critical'
RETURN w.name as machine,
       c.name as command,
       fa.lesson_learned as lesson,
       fa.time_wasted_minutes as time_lost
ORDER BY fa.time_wasted_minutes DESC
```

### Query: Find Similar Writeups

```cypher
MATCH (w1:Writeup {id: 'htb-usage'})-[:TEACHES_TECHNIQUE]->(t:Technique)<-[:TEACHES_TECHNIQUE]-(w2:Writeup)
WHERE w1.relevance = 'high' AND w2.relevance = 'high'
RETURN w2.name as similar_machine,
       w2.platform,
       w2.difficulty,
       collect(t.name) as shared_techniques
```

### Query: Build Learning Path

```cypher
MATCH (easy:Writeup {difficulty: 'easy'})-[:TEACHES_SKILL]->(s:Skill)<-[:REQUIRES_SKILL]-(medium:Writeup {difficulty: 'medium'})
WHERE easy.relevance = 'high' AND medium.relevance = 'high'
RETURN easy.name as start_with,
       s.name as learn_this_skill,
       medium.name as then_try
```

## Files and Structure

```
db/data/writeups/
├── README.md (this file)
├── writeup-schema.json              # JSON Schema for validation
│
├── hackthebox/
│   └── Usage/
│       ├── Usage.json               # Structured writeup metadata
│       ├── Usage.txt                # Original writeup (preserved)
│       └── images/                  # Screenshots
│
├── proving_grounds/
│   └── Monsoon/
│       └── Monsoon.json
│
└── tryhackme/
    └── Pickle/
        └── Pickle.json

db/scripts/
└── validate_writeups.py             # Validation script

db/neo4j-migration/schemas/
├── writeup_schema.cypher            # Node constraints and indexes
└── writeup_relationships.cypher     # Relationship definitions

db/neo4j-migration/scripts/
├── load_writeups.py                 # Load writeup JSON files
└── writeup_extractors.py            # Extract to CSV for Neo4j
```

## Best Practices

### 1. Document as You Go
Don't wait until machine completion - document each phase immediately while details are fresh.

### 2. Include Every Failed Attempt
Each failure is a learning opportunity. Document:
- What you tried
- Why it failed
- How you fixed it
- What this teaches

### 3. Cross-Reference Commands
Use command IDs that exist in the database. If needed, create the command first.

### 4. Time Tracking
Be honest with time estimates. This helps with exam planning:
- Enumeration: Typically 10-20 minutes
- Foothold: 30-90 minutes
- Privilege Escalation: 20-60 minutes

### 5. Professional Relevance
Ask yourself:
- Would this technique work in professional assessment?
- Can I do this without automated exploits?
- Is this time-efficient for exam context?

## Validation Checklist

Before considering a writeup complete:

- [ ] All attack phases documented with duration
- [ ] Every command has `command_id` and `context`
- [ ] Failed attempts include `lesson_learned` (min 30 chars)
- [ ] At least one PRIORITY:HIGH|MEDIUM|LOW tag
- [ ] CVE format correct (CVE-YYYY-NNNNN or null)
- [ ] Phase names valid (enumeration, foothold, etc.)
- [ ] Time breakdown includes `total_minutes` and `flags_captured`
- [ ] Key learnings documented with importance
- [ ] Validation script passes without errors

## Example Workflow

```bash
# 1. Complete machine
# 2. Create directory structure
mkdir -p db/data/writeups/hackthebox/NewMachine/images

# 3. Copy template
cp db/data/writeups/hackthebox/Usage/Usage.json \
   db/data/writeups/hackthebox/NewMachine/NewMachine.json

# 4. Edit JSON with machine details
# ... (use VSCode or vim)

# 5. Validate
python3 db/scripts/validate_writeups.py \
  db/data/writeups/hackthebox/NewMachine/NewMachine.json

# 6. Fix any validation errors

# 7. Commit to repository
git add db/data/writeups/hackthebox/NewMachine/
git commit -m "Add writeup: HackTheBox NewMachine"
```

## Philosophy

> **"Failed attempts documented well teach more than lucky successes explained poorly."**

Writeups transform static commands into living knowledge by answering:
- **Context**: WHY was this command needed?
- **Failure**: What DIDN'T work and why?
- **Timing**: How long did this ACTUALLY take?
- **Learning**: What does this TEACH for future machines?
- **Patterns**: How does this relate to OTHER writeups?

## Support

For issues or questions:
- Check `db/CLAUDE.md` for schema details
- Review `db/data/writeups/hackthebox/Usage/Usage.json` as reference
- Validate frequently to catch errors early
- Document liberally - more context is always better

---

**Last Updated**: 2025-11-19
**Schema Version**: 1.0
**Status**: Active Development
