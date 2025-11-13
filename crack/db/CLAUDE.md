# DB CLAUDE.md - Command Enrichment System

## ROLE
Command JSON enrichment agent for OSCP reference database. Validate schema, enrich educational fields, fix violations.

## PATHS
```
BASE=/home/kali/Desktop/OSCP/crack
COMMANDS=$BASE/reference/data/commands/
CHEATSHEETS=$BASE/reference/data/cheatsheets/
CHAINS=$BASE/reference/data/attack_chains/
DB_TOOLS=$BASE/db/scripts/
VALIDATION=$BASE/db/neo4j-migration/scripts/utils/
```

## DATA MODEL

### Hierarchy
```
COMMAND (atomic unit)
  - Executable with <PLACEHOLDERS>
  - Educational metadata (flags, troubleshooting, notes)
  - Links: prerequisites, alternatives, next_steps (by ID only)

CHAIN (ordered sequence)
  - Numbered steps referencing commands by ID
  - Conditional logic, alternate paths

CHEATSHEET (contextual collection)
  - Scenarios: context-driven workflows
  - Sections: phase-based groupings
  - References commands by ID only
  - Educational header (when/how to recognize)
```

### File Structures
```
COMMANDS:       {category, subcategory, description, commands: [...]}
CHEATSHEETS:    {cheatsheets: [{id, name, educational_header, scenarios, sections}]}
CHAINS:         {id, name, description, category, steps: [...]}
```

### Neo4j Nodes
```
Command:     id, name, command, category, description, notes, oscp_relevance
Cheatsheet:  id, name, description, educational_header, scenarios, sections
Chain:       id, name, description, steps
Tag:         name (OSCP:HIGH, ACTIVE_DIRECTORY, etc.)
Variable:    name (<PLACEHOLDER>), description, example, required
Flag:        flag (-v, --output), explanation
Indicator:   type (success|failure), pattern
```

### Neo4j Relationships
```
(Command)-[:TAGGED]->(Tag)
(Command)-[:HAS_VARIABLE|HAS_FLAG|HAS_INDICATOR]->(Variable|Flag|Indicator)
(Command)-[:PREREQUISITE|ALTERNATIVE|NEXT_STEP]->(Command)
(Cheatsheet)-[:REFERENCES_COMMAND {context, scenario_title}]->(Command)
(Chain)-[:INCLUDES_STEP {step_number, conditional_logic}]->(Command)
```

## SCHEMA

### Required Fields (Commands)
```
id:              string, kebab-case, unique_global
name:            string, human_readable
category:        enum[enumeration|web|exploitation|post-exploit|pivoting|utilities|av-evasion|active-directory]
command:         string, contains_<PLACEHOLDERS>
description:     string, 1-2 sentences
tags:            array[string], must_include OSCP:HIGH|MEDIUM|LOW
```

### Educational Fields (Optional)
```
subcategory:          string
variables:            array[{name, description, example, required}]
flag_explanations:    object {flag: explanation_with_WHY}
success_indicators:   array[string], specific_output_patterns
failure_indicators:   array[string], error_messages
troubleshooting:      object {issue: diagnostic_steps}
notes:                string, OSCP_methodology, manual_alternatives, time_estimates
oscp_relevance:       enum[high|medium|low]
prerequisites:        array[command_ids]
alternatives:         array[command_ids]
next_steps:           array[command_ids]
```

### Quality Grades
```
A: All educational fields, flag_explanations >200 chars/flag, notes >200 words, troubleshooting >3
B: Most educational fields, flag_explanations >100 chars, notes >100 words
C: Some educational fields, basic notes
D: Minimal educational content
F: Required fields only
```

## VALIDATION

### Rules
```
✓ All <PLACEHOLDERS> must have variables[] entry
✓ All variables[] must match <PLACEHOLDER> in command
✓ alternatives/prerequisites/next_steps = command IDs only (no text)
✓ Exactly one OSCP priority tag (OSCP:HIGH|MEDIUM|LOW)
✓ Command IDs globally unique
✓ flag_explanations keys match actual flags
```

### Tools
```bash
# Basic validation
python3 db/scripts/validate_commands.py reference/data/commands/{category}/{file}.json

# Advanced validation + metrics
python3 db/neo4j-migration/scripts/utils/validate_all_commands.py
python3 db/neo4j-migration/scripts/utils/json_stats.py --verbose

# Comprehensive diagnostic
cd db/neo4j-migration/scripts/utils && ./quick_report.sh --verbose --save
```

### Current Violations (High Priority)
```
alternatives field contains text (not IDs):    386/526 (73%)
prerequisites field contains text (not IDs):   189/332 (57%)
FIX: Replace "Use netcat" → "netcat-basic-connection"
```

## PATTERNS

### Naming Conventions
```
Command IDs:   {tool}-{action}-{target}  (e.g., kerbrute-userenum-ad)
               ^[a-z0-9]+(-[a-z0-9]+)*$ (kebab-case, lowercase)

Variables:     <TARGET>, <LHOST>, <LPORT>, <WORDLIST>  (uppercase, <ANGLE_BRACKETS>)
               Use <TARGET> consistently (not <IP> or <HOST>)

Tags:          CATEGORY_TAGS: ACTIVE_DIRECTORY, WEB, LINUX, WINDOWS
               ACTION_TAGS: USER_ENUMERATION, PASSWORD_CRACKING, RCE
               PRIORITY_TAGS: OSCP:HIGH|MEDIUM|LOW, QUICK_WIN
               TECH_TAGS: SMB, LDAP, KERBEROS, HTTP
```

### Educational Format
```
flag_explanations:  "{what} - {why}. {alternatives}. {oscp_context}. {pitfalls}."
                    Min 100 chars, focus on WHY not just WHAT

notes:              OSCP_methodology → Manual_alternative → Time_estimate → Exam_tips
                    Min 200 words (grade A), 100 words (grade B)

troubleshooting:    Common failures → Diagnostic steps → Fix
```

## ENRICHMENT WORKFLOW

```
Priority Order:
1. flag_explanations (WHY each flag matters, OSCP context)
2. notes (methodology, manual alternatives, time estimates)
3. troubleshooting (common failures, diagnostics)
4. success_indicators, failure_indicators
5. Link prerequisites/alternatives/next_steps (IDs only)

Fixes:
- Text in alternatives/prerequisites → Find matching command ID, replace
- Missing variables for placeholders → Create variables[] entry
- Insufficient flag_explanations → Add WHY context, OSCP relevance
```

## QUICK REFERENCE

### Creating Content
```bash
# COMMAND: Add to existing commands/{category}/{subcategory}.json
# Structure: Add to "commands" array
# Required: id, name, category, command, description, tags (with OSCP:*)

# CHEATSHEET: Create cheatsheets/{category?}/{name}.json
# Structure: {cheatsheets: [{id, name, educational_header, scenarios, sections}]}
# Critical: Use "cheatsheets" wrapper, reference commands by ID only

# CHAIN: Create attack_chains/{category}/{name}.json
# Structure: {id, name, description, category, steps: [{step_number, command_id}]}
```

### Common Mistakes
```
❌ Cheatsheet with "commands" array → ✓ Use "cheatsheets" array
❌ Embed full command objects → ✓ Reference by ID only
❌ Text in alternatives/prerequisites → ✓ Use command IDs
❌ Cheatsheet in commands/ dir → ✓ Place in cheatsheets/ dir
❌ Missing OSCP tag → ✓ Add OSCP:HIGH|MEDIUM|LOW
❌ Placeholder without variable → ✓ Add to variables[] array
```

### Migration Pipeline
```bash
cd /home/kali/Desktop/OSCP/crack/db/neo4j-migration/scripts
python3 transform_to_neo4j.py    # JSON → CSV
python3 import_to_neo4j.py       # CSV → Neo4j
python3 verify_import.py         # Verify
```

### Neo4j Verification
```cypher
# Count nodes
MATCH (c:Command) RETURN count(c)
MATCH (cs:Cheatsheet) RETURN count(cs)

# Verify cheatsheet
MATCH (cs:Cheatsheet {id: 'your-id'})-[:REFERENCES_COMMAND]->(c)
RETURN cs.name, count(c)

# Find broken references
MATCH (cs:Cheatsheet)
UNWIND cs.scenarios AS s
UNWIND s.commands AS cmd_id
WHERE NOT EXISTS((:Command {id: cmd_id}))
RETURN cs.id, cmd_id
```

## EXECUTION RULES

```
✓ Read before write
✓ Validate after changes
✓ One file per enrichment session
✓ Never delete valid content
✓ Never change command semantics
✓ Only add missing fields or fix violations
```

## METRICS (Current)
```
Total commands: 795, Files: 47
Categories: enumeration=198, web=245, exploitation=156, post-exploit=102
OSCP distribution: high=68%, medium=24%, low=8%
Field presence: flag_explanations=90%, notes=95%, troubleshooting=61%
Quality average: B-
```

END DOCUMENT
