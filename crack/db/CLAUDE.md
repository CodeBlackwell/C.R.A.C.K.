# DB CLAUDE.md - Command Enrichment System

## ROLE
Command JSON enrichment agent for OSCP reference database. Validate schema, enrich educational fields, fix violations.

## PATHS
```
BASE=/home/kali/Desktop/OSCP/crack
COMMANDS=$BASE/db/data/commands/
CHEATSHEETS=$BASE/db/data/cheatsheets/
CHAINS=$BASE/db/data/chains/
WRITEUPS=$BASE/db/data/writeups/
DB_TOOLS=$BASE/db/scripts/
VALIDATION=$BASE/db/neo4j-migration/scripts/utils/
```

## DATA MODEL

### Hierarchy
```
WRITEUP (real-world application narrative - TOP LEVEL)
  - Complete machine walkthrough with phases
  - Documents commands used, failed attempts, learning points
  - References commands, chains, techniques, CVEs
  - Time tracking for OSCP exam planning

CHAIN (ordered sequence)
  - Numbered steps referencing commands by ID
  - Conditional logic, alternate paths

CHEATSHEET (contextual collection)
  - Scenarios: context-driven workflows
  - Sections: phase-based groupings
  - References commands by ID only
  - Educational header (when/how to recognize)

COMMAND (atomic unit)
  - Executable with <PLACEHOLDERS>
  - Educational metadata (flags, troubleshooting, notes)
  - Links: prerequisites, alternatives, next_steps (by ID only)
```

### File Structures
```
COMMANDS:       {category, subcategory, description, commands: [...]}
CHEATSHEETS:    {cheatsheets: [{id, name, educational_header, scenarios, sections}]}
CHAINS:         {id, name, description, category, steps: [...]}
WRITEUPS:       {id, name, source, metadata, oscp_relevance, attack_phases: [...]}
```

### Neo4j Nodes
```
Writeup:     id, name, platform, difficulty, os, oscp_relevance, total_duration_minutes
Command:     id, name, command, category, description, notes, oscp_relevance
Cheatsheet:  id, name, description, educational_header, scenarios, sections
Chain:       id, name, description, steps
CVE:         cve_id, name, severity, component, description
Technique:   name, category, difficulty, oscp_applicable, steps
Platform:    name (HackTheBox, ProvingGrounds, etc.), type, url
Skill:       name, category, oscp_importance
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

WRITEUP RELATIONSHIPS:
(Writeup)-[:DEMONSTRATES {phase, step_number, context, success}]->(Command)
(Writeup)-[:FAILED_ATTEMPT {reason, lesson_learned, time_wasted}]->(Command)
(Writeup)-[:APPLIES_CHAIN {effectiveness, modifications}]->(Chain)
(Writeup)-[:EXPLOITS_CVE {phase, severity}]->(CVE)
(Writeup)-[:TEACHES_TECHNIQUE {phase, oscp_applicable}]->(Technique)
(Writeup)-[:FROM_PLATFORM {machine_type, release_date}]->(Platform)
(Writeup)-[:REQUIRES_SKILL {importance}]->(Skill)
(Writeup)-[:TEACHES_SKILL {proficiency_level}]->(Skill)
(Writeup)-[:SIMILAR_TO {similarity_score}]->(Writeup)
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
Writeups: 1 (htb-usage)
```

## WRITEUPS

### Purpose
Writeups sit at the **top of the data hierarchy** - they demonstrate real-world application of commands, chains, and techniques in complete machine compromises. Critical for OSCP learning because they:
- Show command usage in context (WHY not just WHAT)
- Document failed attempts (more valuable than successes)
- Track time for exam planning
- Teach decision-making under uncertainty
- Build pattern recognition across similar machines

### Directory Structure
```
db/data/writeups/
  {platform}/
    {machine_name}/
      {machine_name}.json       # Structured metadata
      {machine_name}.txt        # Original writeup (preserved)
      {machine_name}.md         # Formatted version (optional)
      images/                   # Screenshots

Examples:
  hackthebox/Usage/Usage.json
  proving_grounds/Monsoon/Monsoon.json
  tryhackme/Pickle/Pickle.json
```

### Required Fields (Writeups)
```
id:                string, kebab-case (e.g., htb-usage, pg-monsoon)
name:              string, machine name
source:            object {platform, type, release_date, url}
metadata:          object {difficulty, os, writeup_author, ip_address}
oscp_relevance:    object {score: high|medium|low, reasoning, exam_applicable}
synopsis:          string, min 100 chars, attack summary
skills:            object {required: [...], learned: [...]}
tags:              array[string], must include OSCP:HIGH|MEDIUM|LOW
attack_phases:     array[object], min 1 phase
  - phase:         enum[enumeration|foothold|lateral_movement|privilege_escalation|post_exploitation]
  - duration_minutes: integer
  - commands_used: array[{command_id, context, step_number, success}]
  - failed_attempts: array[{attempt, reason, solution, lesson_learned}]
  - key_findings:  array[string]
time_breakdown:    object {total_minutes, flags_captured}
key_learnings:     array[{category, lesson, detail, importance}]
```

### Attack Phase Structure
Each attack_phases entry:
```json
{
  "phase": "foothold",
  "duration_minutes": 90,
  "description": "SQL injection to admin access, Laravel file upload to RCE",
  "vulnerabilities": [
    {
      "name": "SQL Injection in Password Reset",
      "cve": null,
      "type": "boolean-based blind",
      "severity": "high"
    }
  ],
  "commands_used": [
    {
      "command_id": "sqlmap-from-request-level3",
      "context": "Retry sqlmap with increased test depth",
      "step_number": 4,
      "command_executed": "sqlmap -r reset.req -p email --batch --level 3",
      "success": true,
      "notes": "Success! --level 3 required for blind SQLi detection"
    }
  ],
  "failed_attempts": [
    {
      "attempt": "sqlmap with default settings",
      "reason": "Default level insufficient for blind SQLi",
      "solution": "Increase --level to 3",
      "lesson_learned": "Trust manual verification over tool defaults. CRITICAL OSCP lesson.",
      "time_wasted_minutes": 15,
      "importance": "critical"
    }
  ],
  "key_findings": ["Admin credentials: admin:whatever1"],
  "oscp_notes": "Standard OSCP web exploitation workflow"
}
```

### Failed Attempts (CRITICAL FOR LEARNING)
Document EVERY failure - this is more valuable than successes:
```
✓ attempt:         What you tried
✓ reason:          Why it failed (technical explanation)
✓ solution:        How to fix it
✓ lesson_learned:  What this teaches (min 30 chars, REQUIRED)
✓ time_wasted_minutes: Time lost
✓ importance:      critical|high|medium|low
```

Example failed attempt:
```
"sqlmap default level failed to detect blind SQLi that manual testing confirmed.
Required --level 3 flag. LESSON: Automated tools have limitations - always trust
manual verification. Read tool error messages carefully."
```

### Validation
```bash
# Validate single writeup
python3 db/scripts/validate_writeups.py \
  db/data/writeups/hackthebox/Usage/Usage.json

# Checks:
✓ All command_ids exist in commands database
✓ Phase names valid (enumeration, foothold, etc.)
✓ CVE format correct (CVE-YYYY-NNNNN)
✓ OSCP relevance tag present
✓ Failed attempts have lesson_learned (min 30 chars)
✓ Time estimates present for each phase
```

### Extraction & Neo4j Import
```bash
# Load writeup JSON files
from load_writeups import load_writeup_jsons
writeups, errors = load_writeup_jsons('db/data/writeups')

# Extract to CSV with writeup_extractors module:
- writeups_nodes.csv
- cve_nodes.csv
- technique_nodes.csv
- platform_nodes.csv
- skill_nodes.csv
- writeup_demonstrates_command.csv
- writeup_failed_attempt.csv
- writeup_exploits_cve.csv
- writeup_teaches_technique.csv
- writeup_from_platform.csv
- writeup_requires_skill.csv
- writeup_teaches_skill.csv

# Neo4j relationships enable powerful queries (see writeup_relationships.cypher)
```

### Neo4j Query Examples
```cypher
# Find all commands used successfully in writeups
MATCH (w:Writeup)-[d:DEMONSTRATES]->(c:Command)
WHERE d.success = true AND w.oscp_relevance = 'high'
RETURN c.name, count(w) as usage_count, collect(w.name) as machines
ORDER BY usage_count DESC

# Find all CRITICAL failed attempts (learning goldmine!)
MATCH (w:Writeup)-[fa:FAILED_ATTEMPT]->(c:Command)
WHERE fa.importance = 'critical'
RETURN w.name, c.name, fa.lesson_learned, fa.time_wasted_minutes
ORDER BY fa.time_wasted_minutes DESC

# Find similar writeups for practice
MATCH (w:Writeup {id: 'htb-usage'})-[:TEACHES_TECHNIQUE]->(t:Technique)<-[:TEACHES_TECHNIQUE]-(similar:Writeup)
WHERE w.oscp_relevance = 'high' AND similar.oscp_relevance = 'high'
RETURN similar.name, similar.platform, similar.difficulty,
       collect(t.name) as shared_techniques

# Build learning progression (easy → medium machines)
MATCH (easy:Writeup {difficulty: 'easy'})-[:TEACHES_SKILL]->(s:Skill)<-[:REQUIRES_SKILL]-(medium:Writeup {difficulty: 'medium'})
WHERE easy.oscp_relevance = 'high' AND medium.oscp_relevance = 'high'
RETURN easy.name as start_here, s.name as learn_this, medium.name as then_try

# Find writeups exploiting specific CVE
MATCH (w:Writeup)-[e:EXPLOITS_CVE]->(cve:CVE {cve_id: 'CVE-2023-24249'})
RETURN w.name, w.platform, w.difficulty, e.exploitation_method
```

### Creating New Writeups
```bash
# WRITEUP: Create in db/data/writeups/{platform}/{machine}/{machine}.json
# Structure: {id, name, source, metadata, oscp_relevance, attack_phases, ...}
# Reference: See db/data/writeups/hackthebox/Usage/Usage.json as template
# Schema: db/data/writeups/writeup-schema.json

# Critical: Reference commands by ID only (no embedded objects)
# Example:
#   "commands_used": [
#     {
#       "command_id": "sqlmap-from-request-level3",  // Must exist in commands DB
#       "context": "Why this command was used",
#       "step_number": 4,
#       "success": true
#     }
#   ]
```

### Common Mistakes
```
❌ Missing OSCP tag → ✓ Add OSCP:HIGH|MEDIUM|LOW to tags array
❌ Command ID doesn't exist → ✓ Create command in commands/ first or use existing ID
❌ Skipping failed attempts → ✓ Document ALL failures with lesson_learned
❌ Vague lesson_learned → ✓ Explain WHY it failed and what this teaches (min 30 chars)
❌ No time estimates → ✓ Add duration_minutes to each phase
❌ Invalid phase names → ✓ Use enumeration|foothold|lateral_movement|privilege_escalation|post_exploitation
❌ Invalid CVE format → ✓ Use CVE-YYYY-NNNNN or null
```

### Integration with Existing Schema
Commands gain new optional field:
```json
{
  "id": "sqlmap-from-request-level3",
  "demonstrated_in_writeups": ["htb-usage", "pg-monsoon"],
  "common_failures": [
    {
      "writeup": "htb-usage",
      "issue": "Default level insufficient",
      "lesson": "Always use --level 3 for blind SQLi"
    }
  ]
}
```

### Files Created
```
db/data/writeups/
  writeup-schema.json                     # JSON Schema for validation
  hackthebox/Usage/Usage.json             # First writeup (HackTheBox Usage machine)
  hackthebox/Usage/Usage.txt              # Original writeup (preserved)
  README.md                               # Writeup creation guide

db/scripts/
  validate_writeups.py                    # Validation script

db/neo4j-migration/schemas/
  writeup_schema.cypher                   # Node definitions and constraints
  writeup_relationships.cypher            # Relationship definitions

db/neo4j-migration/scripts/
  load_writeups.py                        # Load writeup JSON files
  writeup_extractors.py                   # Extract nodes/relationships to CSV
```

### Writeup Philosophy
```
"Failed attempts documented well teach more than lucky successes explained poorly."

Writeups transform static commands into living knowledge by showing:
- Context: WHY was this command needed?
- Failure: What DIDN'T work and why?
- Timing: How long did this ACTUALLY take?
- Learning: What does this TEACH for future machines?
- Patterns: How does this relate to OTHER writeups?
```

END DOCUMENT
