# DB CLAUDE.md - Command Enrichment System Rules

## ROLE
Command JSON enrichment agent for OSCP reference database. Validate schema compliance, enrich educational fields, fix violations, maintain quality standards.

## PATHS
```
BASE=/home/kali/Desktop/OSCP/crack
COMMANDS=$BASE/reference/data/commands/
DB_TOOLS=$BASE/db/scripts/
VALIDATION=$BASE/db/neo4j-migration/scripts/utils/
TESTS=$BASE/tests/track/
```

## COMMAND JSON SCHEMA

### Required Fields
```
id:string:req:kebab-case,unique_global
name:string:req:human_readable
category:string:req:enum[enumeration|web|exploitation|post-exploit|pivoting|utilities|monitoring|av-evasion|active-directory]
command:string:req:contains_placeholders
description:string:req:1-2_sentences
tags:array[string]:req:must_include_OSCP_priority_tag
```

### Optional Fields (Educational Enrichment)
```
subcategory:string:opt:category_subdivision
variables:array[object]:opt:all_placeholders_must_have_definition
variables[].name:string:req:exact_match_to_<PLACEHOLDER>
variables[].description:string:req:what_it_represents
variables[].example:string:req:default_value
variables[].required:bool:req:is_mandatory
flag_explanations:object:opt:key=flag,value=educational_explanation_with_WHY
success_indicators:array[string]:opt:specific_output_patterns
failure_indicators:array[string]:opt:error_messages
next_steps:array[string]:opt:command_IDs_not_text
alternatives:array[string]:opt:command_IDs_not_text
prerequisites:array[string]:opt:command_IDs_not_text
troubleshooting:object:opt:key=issue_name,value=diagnostic_steps
notes:string:opt:OSCP_methodology,manual_alternatives,time_estimates
oscp_relevance:string:opt:enum[high|medium|low]
```

### Quality Grading Criteria
```
A: All educational fields present, flag_explanations >200 chars per flag, notes >200 words, troubleshooting >3 scenarios
B: Most educational fields present, flag_explanations >100 chars, notes >100 words
C: Some educational fields, flag_explanations present, notes basic
D: Minimal educational content, flag_explanations sparse
F: No educational enrichment beyond required fields
```

## VALIDATION TOOLS

### Basic Validation
```
TOOL: db/scripts/validate_commands.py
CHECK: json_syntax,required_fields,oscp_tag,placeholder_variable_consistency,duplicate_ids
RUN: python3 validate_commands.py
OUTPUT: pass/fail per file, total command count, violations list
```

### Advanced Validation
```
TOOL: db/neo4j-migration/scripts/utils/validate_all_commands.py
CHECK: schema_compliance,educational_fields,quality_scoring
RUN: python3 validate_all_commands.py

TOOL: db/neo4j-migration/scripts/utils/json_stats.py
CHECK: field_presence_percentage,schema_violations,duplicate_detection
RUN: python3 json_stats.py [--verbose]
OUTPUT: category_distribution,oscp_distribution,tag_frequency,field_stats,violation_count

TOOL: db/neo4j-migration/scripts/utils/quick_report.sh
CHECK: json_analysis,neo4j_analysis,backend_comparison
RUN: ./quick_report.sh [--verbose] [--save]
OUTPUT: comprehensive_diagnostic_report
```

## SCHEMA VIOLATIONS (Current State)

### High Priority Fixes
```
VIOLATION: alternatives field contains text descriptions instead of command IDs
COUNT: 386/526 (73%)
FIX: Replace text with valid command ID from COMMANDS/ directory
PATTERN: "Use netcat for manual connection" → "netcat-basic-connection"

VIOLATION: prerequisites field contains text descriptions instead of command IDs
COUNT: 189/332 (57%)
FIX: Replace text with valid command ID from COMMANDS/ directory
PATTERN: "Enumerate users first" → "ldap-user-enumeration"
```

### Validation Rules
```
RULE: All <PLACEHOLDERS> in command field must have corresponding variables[] entry
RULE: All variables[] entries must match exactly one <PLACEHOLDER> in command
RULE: alternatives/prerequisites/next_steps must contain only command IDs that exist
RULE: tags array must include exactly one OSCP priority tag: OSCP:HIGH|OSCP:MEDIUM|OSCP:LOW
RULE: command IDs must be globally unique across all JSON files
RULE: flag_explanations keys must match actual flags in command field
```

## ENRICHMENT WORKFLOW

### Decision Tree
```
IF command missing educational fields THEN
  PRIORITY_1: Add flag_explanations (WHY each flag matters, alternatives, OSCP context)
  PRIORITY_2: Add notes (OSCP methodology, manual alternatives, time estimates)
  PRIORITY_3: Add troubleshooting (common failures, diagnostics)
  PRIORITY_4: Add success_indicators, failure_indicators
  PRIORITY_5: Link prerequisites/next_steps/alternatives (IDs only)
END

IF alternatives/prerequisites contains text THEN
  FIND: Matching command ID in COMMANDS/ directory
  REPLACE: Text with command ID
  VERIFY: ID exists and is valid
END

IF command has placeholders without variables THEN
  CREATE: variables[] entry for each <PLACEHOLDER>
  INCLUDE: name, description, example, required fields
END

IF flag_explanations exists but insufficient THEN
  ENHANCE: Add WHY context (not just WHAT)
  ADD: OSCP relevance per flag
  ADD: Common pitfalls, alternatives
  TARGET: >100 chars per flag minimum
END
```

## PATTERNS

### Command ID Format
```
PATTERN: {tool}-{action}-{target}
EXAMPLES: kerbrute-userenum-ad, hashcat-benchmark, sqli-union-mysql-info
REGEX: ^[a-z0-9]+(-[a-z0-9]+)*$
NO_SPACES: true
CASE: lowercase
```

### Variable Naming
```
STANDARD_VARS: <TARGET>, <LHOST>, <LPORT>, <WORDLIST>, <HASH_FILE>, <SESSION_NAME>
CASE: uppercase
FORMAT: <DESCRIPTIVE_NAME>
CONSISTENCY: Always use <TARGET> not <IP> or <HOST>
```

### Tag Patterns
```
CATEGORY_TAGS: ACTIVE_DIRECTORY, WEB, LINUX, WINDOWS, NETWORK
ACTION_TAGS: USER_ENUMERATION, PASSWORD_CRACKING, RCE, PRIVILEGE_ESCALATION
TOOL_TAGS: HASHCAT, KERBRUTE, SQLMAP, NMAP, METASPLOIT
PRIORITY_TAGS: OSCP:HIGH, OSCP:MEDIUM, OSCP:LOW, QUICK_WIN
TECH_TAGS: SMB, LDAP, KERBEROS, MYSQL, POSTGRESQL, HTTP, HTTPS
REQUIRED: Exactly one OSCP priority tag per command
```

### Flag Explanation Format
```
STRUCTURE: {what_it_does} - {why_use_it}. {alternatives}. {oscp_context}. {pitfalls}.
MIN_LENGTH: 100 chars
INCLUDE: Educational value (WHY not just WHAT)
EXAMPLE: "-w 3": "Workload profile - Controls GPU utilization. Levels: 1=Low (desktop usable), 2=Default (balanced), 3=High (GPU maxed). Use 3 for maximum speed in exam if machine dedicated. Pitfall: Level 3 may overheat laptops."
```

### Notes Format
```
INCLUDE: OSCP_methodology, manual_alternatives, time_estimates, when_to_use_in_exam, reality_checks
MIN_LENGTH: 200 words for grade A, 100 words for grade B
STRUCTURE: Methodology paragraph → Manual alternative → Time estimate → OSCP tips
```

## CONVENTIONS

### Nmap Commands
```
REQUIRED_FLAGS: sudo (privilege), -v (verbose), -Pn (skip ping)
PATTERN: sudo nmap -v -Pn {additional_flags} <TARGET>
```

### Placeholder Rules
```
NEVER: Hardcode IP addresses, ports, paths, filenames
ALWAYS: Use <PLACEHOLDERS> with full variable definitions
DEFINE: All variables with description, example, required fields
```

### Reference Linking
```
ALTERNATIVES: command_ids_only, no text descriptions
PREREQUISITES: command_ids_only, no text descriptions
NEXT_STEPS: command_ids_only, no text descriptions
VALIDATION: Verify all referenced IDs exist before saving
```

## QUALITY METRICS (Current State)
```
total_commands: 795
files: 47
categories: enumeration=198, web=245, exploitation=156, post-exploit=102, pivoting=48, utilities=45, monitoring=1
oscp_distribution: high=68%, medium=24%, low=8%
field_presence: flag_explanations=90%, alternatives=66%, prerequisites=42%, troubleshooting=61%, notes=95%
violations: alternatives_text=386, prerequisites_text=189
quality_average: B- (based on educational field presence)
```

## TOOL INVOCATION PATTERNS

### Validate Single File
```bash
python3 db/scripts/validate_commands.py reference/data/commands/{category}/{file}.json
```

### Validate All Commands
```bash
python3 db/neo4j-migration/scripts/utils/validate_all_commands.py
```

### Get Metrics
```bash
python3 db/neo4j-migration/scripts/utils/json_stats.py --verbose
```

### Comprehensive Diagnostic
```bash
cd db/neo4j-migration/scripts/utils && ./quick_report.sh --verbose --save
```

### Find Commands Needing Enrichment
```bash
python3 db/neo4j-migration/scripts/utils/json_stats.py | grep "alternatives.*text"
```

## ERROR HANDLING

### Common Failures
```
ERROR: "Command ID not unique"
FIX: Change ID to unique kebab-case string, verify globally unique

ERROR: "Placeholder <VAR> has no variable definition"
FIX: Add to variables[] array with all required subfields

ERROR: "Variable defined but not used in command"
FIX: Remove unused variable definition OR add placeholder to command

ERROR: "alternatives contains text not command ID"
FIX: Find matching command ID, replace text with ID

ERROR: "Missing OSCP priority tag"
FIX: Add one of OSCP:HIGH, OSCP:MEDIUM, OSCP:LOW to tags array

ERROR: "Referenced command ID does not exist"
FIX: Verify ID exists in COMMANDS/ directory OR remove reference
```

## BATCH OPERATIONS

### Fix All Text References in Category
```bash
cd reference/data/commands/{category}
# Manual process: Open each JSON, find text in alternatives/prerequisites, replace with IDs
```

### Enrich Multiple Commands
```bash
# Identify low-quality commands
python3 json_stats.py --verbose | grep "Grade: F"
# Edit each file manually to add educational fields
```

### Validate After Changes
```bash
python3 validate_commands.py && python3 validate_all_commands.py && ./quick_report.sh
```

## PRIORITY RANKINGS

### Enrichment Priority by Field
```
P1: flag_explanations (90% present but many insufficient)
P2: notes (95% present but quality varies)
P3: troubleshooting (61% present)
P4: prerequisites/alternatives ID fixes (57%/73% violations)
P5: success_indicators/failure_indicators (low presence)
```

### File Priority by Quality
```
HIGH: Commands with Grade F (no educational content)
MEDIUM: Commands with Grade D (minimal educational content)
LOW: Commands with Grade C (adequate but improvable)
MAINTAIN: Commands with Grade A/B (already high quality)
```

## REFERENCE MODELS

### Excellent Quality Example
```
FILE: reference/data/commands/password-attacks/password-attacks-methodology.json
GRADE: A+
CHARACTERISTICS: Extensive flag_explanations (300+ chars), comprehensive notes (200+ words), detailed troubleshooting, proper ID references, specific indicators
```

### Good Quality Example
```
FILE: reference/data/commands/active-directory/ad-user-enumeration.json
GRADE: A
CHARACTERISTICS: Informative flag_explanations, OSCP methodology in notes, proper ID references, comprehensive tags, logical next_steps
```

## EXECUTION RULES

### Read Before Write
```
ALWAYS: Read existing JSON file before modifying
VERIFY: Valid JSON syntax after editing
CHECK: All validations pass before committing
```

### Atomic Changes
```
ONE_FILE: Focus on single file per enrichment session
VALIDATE: Run validation after each file change
COMMIT: Document what was enriched in commit message
```

### No Destructive Edits
```
NEVER: Delete existing valid content
NEVER: Change command semantics
NEVER: Remove working flags
ALWAYS: Preserve existing structure
ONLY: Add missing fields or fix violations
```

## METRICS TRACKING

### Before Enrichment
```
RUN: python3 json_stats.py --verbose > baseline.txt
NOTE: Current field presence percentages
NOTE: Current violation counts
```

### After Enrichment
```
RUN: python3 json_stats.py --verbose > after.txt
COMPARE: Field presence increases
COMPARE: Violation count decreases
VERIFY: Quality grade improved
```

## SUCCESS CRITERIA

### Single Command Enrichment
```
PASS: All validation checks pass
PASS: Educational fields added (flag_explanations, notes, troubleshooting)
PASS: All placeholders have variable definitions
PASS: No text in alternatives/prerequisites/next_steps
PASS: Quality grade >= B
```

### Batch Enrichment
```
PASS: Violation count decreased
PASS: Field presence percentages increased
PASS: No new validation errors introduced
PASS: Average quality grade improved
```

END DOCUMENT
