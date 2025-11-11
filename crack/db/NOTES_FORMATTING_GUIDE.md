# Command Notes Formatting Guide

## Overview
This guide provides templates and examples for formatting command notes to improve readability without changing the JSON structure. All formatting uses strategic newlines (`\n`) and spacing to make large text blocks more digestible.

## Core Principles

1. **No data deletion** - All original content is preserved
2. **Strategic newlines** - Add `\n\n` between major sections, `\n` after steps/headings
3. **Consistent patterns** - Use standardized section headers and step markers
4. **Theme-aware** - Display code will automatically colorize recognized patterns

## Recognized Patterns (Auto-Colored)

The enhanced `_wrap_text()` method in `cheatsheet.py` automatically detects and colors:

| Pattern | Theme Color | Example |
|---------|-------------|---------|
| Section headers (ALL CAPS:) | `notes_section` (bold bright cyan) | `OSCP METHODOLOGY:`, `MANUAL ALTERNATIVE:` |
| Step markers | `notes_step` (bold yellow) | `Step 1:`, `(1)`, `1.` |
| Warning markers | `notes_warning` (yellow) | `WARNING:`, `CRITICAL:`, `PITFALL:` |
| Tip markers | `notes_tip` (bright cyan) | `TIP:`, `EXAM TIP:` |
| Success indicators | `notes_success` (green) | `SUCCESS:`, `EXPECTED OUTPUT:` |
| Failure indicators | `notes_failure` (red) | `FAILURE:`, `ERROR:`, `FAILED:` |
| Code/commands (indented) | `notes_code` (bright_black) | Lines with 2+ spaces indent |
| Timing info | `hint` (muted) | `Time:` |

## Formatting Rules

### Rule 1: Section Breaks
Add `\n\n` (double newline) between major sections:
- After section headers
- Between methodology and alternatives
- Between training examples and explanations

### Rule 2: Step Spacing
Add `\n` (single newline) after each step marker:
- After `Step 1:`, `Step 2:`, etc.
- After numbered lists `(1)`, `(2)`, `1.`, `2.`

### Rule 3: Code Examples
Indent code/commands with 2+ spaces and separate from surrounding text with `\n`:

```
descriptive text\n
  command here
  another command\n
more description
```

### Rule 4: Section Headers
Use ALL CAPS followed by colon for major sections:
- `OSCP METHODOLOGY:`
- `MANUAL ALTERNATIVE:`
- `WHY THIS MATTERS:`
- `TRAINING WORKFLOW:`
- `PREREQUISITES:`

## Before/After Examples

### Example 1: AD SID Enumeration (Compressed Steps)

**BEFORE:**
```json
"notes": "OSCP METHODOLOGY: This is the FASTEST and STEALTHIEST method to obtain the Domain SID during an exam. Unlike PowerView or other PowerShell tools, whoami is a native Windows binary that exists on every system since Windows XP and generates minimal security event logs. It requires NO special permissions, NO PowerShell execution policy bypasses, and NO external tool downloads.\n\nMANUAL ALTERNATIVE: If whoami is restricted (rare), use 'wmic useraccount get name,sid' to list all local and domain accounts with their SIDs. Domain accounts will share the same Domain SID prefix.\n\nWHY THIS MATTERS FOR SILVER/GOLDEN TICKETS: The Domain SID is a REQUIRED parameter when forging Kerberos tickets with Mimikatz or Rubeus..."
```

**AFTER:**
```json
"notes": "OSCP METHODOLOGY:\nThis is the FASTEST and STEALTHIEST method to obtain the Domain SID during an exam. Unlike PowerView or other PowerShell tools, whoami is a native Windows binary that exists on every system since Windows XP and generates minimal security event logs.\n\nIt requires NO special permissions, NO PowerShell execution policy bypasses, and NO external tool downloads.\n\nMANUAL ALTERNATIVE:\nIf whoami is restricted (rare), use 'wmic useraccount get name,sid' to list all local and domain accounts with their SIDs. Domain accounts will share the same Domain SID prefix.\n\nWHY THIS MATTERS FOR SILVER/GOLDEN TICKETS:\nThe Domain SID is a REQUIRED parameter when forging Kerberos tickets with Mimikatz or Rubeus..."
```

**CHANGES:**
- Added `\n` after each section header
- Added `\n\n` between sections
- Broke long paragraphs into digestible chunks

### Example 2: PowerShell Remoting Workflow (Numbered Steps)

**BEFORE:**
```json
"notes": "OSCP TRAINING MATERIAL - POWERSHELL REMOTING (ENTER-PSSESSION):\n\nTRAINING WORKFLOW: From OSCP module, PowerShell remoting demonstrated with session creation:\n1. Create PSCredential object (ConvertTo-SecureString + New-Object PSCredential)\n2. New-PSSession -ComputerName 192.168.50.73 -Credential $credential (creates session)\n3. Enter-PSSession 1 (connects to session ID 1 interactively)\n4. Commands execute remotely, verified with whoami/hostname showing FILES04..."
```

**AFTER:**
```json
"notes": "OSCP TRAINING MATERIAL - POWERSHELL REMOTING (ENTER-PSSESSION):\n\nTRAINING WORKFLOW:\nFrom OSCP module, PowerShell remoting demonstrated with session creation:\n\n1. Create PSCredential object (ConvertTo-SecureString + New-Object PSCredential)\n\n2. New-PSSession -ComputerName 192.168.50.73 -Credential $credential (creates session)\n\n3. Enter-PSSession 1 (connects to session ID 1 interactively)\n\n4. Commands execute remotely, verified with whoami/hostname showing FILES04..."
```

**CHANGES:**
- Added `\n` after "TRAINING WORKFLOW:"
- Added `\n\n` before each numbered step
- Steps now visually separated for easy scanning

### Example 3: MySQL SQLi Extraction (Parenthetical Numbers)

**BEFORE:**
```json
"notes": "MySQL-SPECIFIC extraction queries (order matters): (1) List databases: database() or CONCAT(schema_name) FROM information_schema.schemata. (2) List tables: CONCAT(table_schema,':',table_name) FROM information_schema.tables WHERE table_schema NOT IN ('mysql','information_schema'). (3) List columns: CONCAT(table_name,':',column_name) FROM information_schema.columns WHERE table_schema='target_db'. Time estimate: 5-10 min for full extraction."
```

**AFTER:**
```json
"notes": "MySQL-SPECIFIC extraction queries (order matters):\n\n(1) List databases:\n  database() or CONCAT(schema_name) FROM information_schema.schemata\n\n(2) List tables:\n  CONCAT(table_schema,':',table_name) FROM information_schema.tables WHERE table_schema NOT IN ('mysql','information_schema')\n\n(3) List columns:\n  CONCAT(table_name,':',column_name) FROM information_schema.columns WHERE table_schema='target_db'\n\nTime: 5-10 min for full extraction"
```

**CHANGES:**
- Added `\n\n` before each step marker
- Indented SQL queries with 2 spaces
- Added `\n` after step description
- Separated time estimate with `\n\n`

### Example 4: SSH Tunneling (Mixed Content)

**BEFORE:**
```json
"notes": "Local port forward limitation: One socket per -L flag. For multiple services, use multiple -L flags in single SSH command or use dynamic port forward (-D) with SOCKS proxy. Common OSCP use case: Access internal database/SMB from Kali through compromised DMZ host."
```

**AFTER:**
```json
"notes": "LIMITATION:\nOne socket per -L flag.\n\nFor multiple services, use multiple -L flags in single SSH command or use dynamic port forward (-D) with SOCKS proxy.\n\nOSCP USE CASE:\nAccess internal database/SMB from Kali through compromised DMZ host."
```

**CHANGES:**
- Extracted "limitation" into section header
- Added "OSCP USE CASE:" section header
- Separated concepts with `\n\n`

### Example 5: Training Examples with Code

**BEFORE:**
```json
"notes": "OSCP TRAINING EXAMPLE: From OSCP module, jen's credentials used to execute commands remotely on FILES04: 'winrs -r:files04 -u:jen -p:Nexus123! \"cmd /c hostname & whoami\"' Output confirmed remote execution: 'FILES04' and 'corp\\jen' WHAT IS WINRS: Windows Remote Shell - command-line WinRM client pre-dating PowerShell remoting..."
```

**AFTER:**
```json
"notes": "OSCP TRAINING EXAMPLE:\nFrom OSCP module, jen's credentials used to execute commands remotely on FILES04:\n\n  winrs -r:files04 -u:jen -p:Nexus123! \"cmd /c hostname & whoami\"\n\nEXPECTED OUTPUT:\n  FILES04\n  corp\\jen\n\nWHAT IS WINRS:\nWindows Remote Shell - command-line WinRM client pre-dating PowerShell remoting..."
```

**CHANGES:**
- Added `\n` after section headers
- Indented commands with 2 spaces
- Added "EXPECTED OUTPUT:" section with indented output
- Separated sections with `\n\n`

## Common Patterns Checklist

When updating a command's notes field, check for:

- [ ] Section headers using ALL CAPS: format (add `\n` after)
- [ ] Step markers like "Step 1:", "(1)", "1." (add `\n\n` before)
- [ ] Code examples or commands (indent with 2+ spaces, add `\n` before/after)
- [ ] Long paragraphs (break at logical points with `\n\n`)
- [ ] Training examples (separate with section headers + spacing)
- [ ] Time estimates (separate with `\n\n` and use "Time:" prefix)
- [ ] Warning/tips (use "WARNING:", "TIP:", "CRITICAL:" prefixes)
- [ ] Success/failure indicators (use "SUCCESS:", "FAILURE:", "ERROR:")

## JSON Escaping Rules

Remember in JSON:
- Newline: `\n` (not actual newline in JSON string)
- Double newline: `\n\n` (paragraph break)
- Backslash: `\\` (must escape backslashes)
- Quote: `\"` (must escape quotes inside string)

## Workflow for Manual Updates

1. **Read the command JSON file**
2. **Locate the "notes" field** (usually near bottom)
3. **Identify the patterns** (steps, sections, code examples)
4. **Add strategic newlines:**
   - `\n` after section headers
   - `\n\n` between sections and before steps
   - `\n` before/after code blocks
5. **Verify JSON syntax** (use `python3 -m json.tool <file>`)
6. **Test display** (if possible, view in cheatsheet CLI)

## Category-Specific Guidelines

### Active Directory Commands
- Heavy use of "OSCP TRAINING MATERIAL:" sections
- Workflow steps often numbered
- Include "PREREQUISITES:", "WHY THIS MATTERS:" sections
- Separate domain controller examples from member server examples

### Web/SQLi Commands
- Extraction queries often numbered (1), (2), (3)
- Indent SQL syntax examples
- Separate database-specific variations
- Include "ORDER MATTERS" warnings where applicable

### Pivoting/Tunneling Commands
- Traffic flow diagrams (keep "Traffic:" prefix)
- Step-by-step procedures
- Separate limitations from alternatives
- Include port forwarding examples with indentation

### Post-Exploitation Commands
- Privilege escalation steps often numbered
- Separate manual techniques from automated tools
- Include "DETECTION RISK:" sections
- Time estimates for exam planning

## Quality Indicators

Good formatting should achieve:
- [ ] No single paragraph longer than 4-5 sentences
- [ ] All steps visually separated
- [ ] Code examples clearly distinguished (indented)
- [ ] Section headers stand out
- [ ] Time estimates easy to find
- [ ] Warning/tips highlighted
- [ ] No loss of original content

## Examples by Priority Category

### High Priority (Fix First)

1. **Active Directory** - Commands with training workflows and numbered steps
2. **Pivoting** - Commands with traffic flows and step-by-step tunneling
3. **SQLi** - Commands with numbered extraction sequences

### Medium Priority

4. **Post-Exploitation** - Commands with privilege escalation procedures
5. **Password Attacks** - Commands with workflow steps

### Lower Priority

6. **Enumeration** - Commands with methodology notes
7. **Utilities** - Commands with brief single-paragraph notes

## Validation

After updating, validate with:

```bash
# JSON syntax check
python3 -m json.tool path/to/command.json > /dev/null

# Schema validation
python3 /home/kali/Desktop/OSCP/crack/db/scripts/validate_commands.py path/to/command.json
```

## Common Mistakes to Avoid

1. **DON'T** add actual newlines in JSON (use `\n` escape sequence)
2. **DON'T** delete content to make it shorter
3. **DON'T** change the meaning of technical content
4. **DON'T** add emojis or special characters
5. **DON'T** break JSON syntax (validate after each change)

## Tips for Efficiency

- Work on one category at a time (all AD, then all web, etc.)
- Use search/replace for common patterns in your editor
- Keep a backup of the original file before editing
- Test one file first before batch updating
- Use JSON syntax highlighting in your editor

---

**Remember:** The goal is readability, not brevity. Well-formatted verbose notes teach better than terse bullets.
