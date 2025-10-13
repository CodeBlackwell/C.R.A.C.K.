# Attack Chain Authoring Guide

**Purpose:** Complete specification for creating properly architected attack chains in CRACK Reference system.

**Target Audience:** Security researchers, OSCP students, CRACK contributors

---

## Table of Contents

1. [Overview](#overview)
2. [Schema Requirements](#schema-requirements)
3. [ID Naming Conventions](#id-naming-conventions)
4. [Command Reference Mapping](#command-reference-mapping)
5. [Step Structure](#step-structure)
6. [Metadata Guidelines](#metadata-guidelines)
7. [Validation Workflow](#validation-workflow)
8. [Complete Examples](#complete-examples)
9. [Migration from Track Module](#migration-from-track-module)
10. [Common Pitfalls](#common-pitfalls)

---

## Overview

### What is an Attack Chain?

An **attack chain** is a structured, step-by-step sequence representing a complete exploitation path from initial access to objective completion (shell, privilege escalation, data exfiltration, etc.).

### Architecture Principles

1. **Schema-First:** JSON Schema Draft 2020-12 validation ensures consistency
2. **Command Reuse:** Steps reference existing commands via `command_ref` (no duplication)
3. **Dependency Tracking:** Steps declare prerequisites via `dependencies` array
4. **Evidence-Based:** Each step documents success/failure indicators
5. **OSCP-Focused:** Includes time estimates, difficulty, manual alternatives

### File Location

```
crack/reference/data/attack_chains/
├── enumeration/           # Information gathering chains
├── privilege_escalation/  # PrivEsc chains (Linux/Windows)
├── lateral_movement/      # Pivoting, credential reuse
└── persistence/           # Backdoors, persistence mechanisms
```

---

## Schema Requirements

### Minimal Valid Chain

```json
{
  "id": "platform-category-technique-variant",
  "name": "Human Readable Name",
  "description": "One-sentence overview of attack path",
  "version": "1.0.0",
  "metadata": {
    "author": "Your Name",
    "created": "2025-10-13",
    "updated": "2025-10-13",
    "tags": ["TAG1", "TAG2"],
    "category": "enumeration"
  },
  "difficulty": "intermediate",
  "time_estimate": "30 minutes",
  "oscp_relevant": true,
  "steps": [
    {
      "name": "Step Name",
      "objective": "What this step achieves",
      "command_ref": "existing-command-id"
    }
  ]
}
```

### Required Fields

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `id` | string | Unique identifier following naming convention | `linux-privesc-sudo-gtfobins` |
| `name` | string | Human-readable chain name | `Sudo GTFOBins Privilege Escalation` |
| `description` | string | Concise overview (1-3 sentences) | `Exploit sudo misconfiguration using GTFOBins techniques to escalate from low-privilege user to root` |
| `version` | string | Semantic version (major.minor.patch) | `1.0.0` |
| `metadata` | object | Author and classification metadata | See metadata section |
| `difficulty` | enum | `beginner`, `intermediate`, `advanced`, `expert` | `intermediate` |
| `time_estimate` | string | Estimated completion time | `30 minutes`, `1 hour`, `45 minutes` |
| `oscp_relevant` | boolean | Whether chain is OSCP exam applicable | `true` |
| `steps` | array | Ordered list of attack steps | See step structure |

### Optional Fields

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `prerequisites` | array[string] | Conditions required before execution | `["SSH access as low-privilege user", "sudo permissions on at least one binary"]` |
| `notes` | string | Free-form additional information | `This chain is particularly effective when sudo NOPASSWD is configured. Always check sudo -l output for opportunities.` |

---

## ID Naming Conventions

### Pattern

```
{platform}-{category}-{technique}-{variant}
```

### Platform Values

- `linux` - Linux-specific chains
- `windows` - Windows-specific chains
- `web` - Platform-agnostic web application chains
- `network` - Network service exploitation
- `cloud` - Cloud platform chains (AWS, Azure, GCP)
- `multi` - Cross-platform applicable

### Category Values

- `enum` - Enumeration and information gathering
- `exploit` - Initial access exploitation
- `privesc` - Privilege escalation
- `lateral` - Lateral movement and pivoting
- `persist` - Persistence mechanisms
- `exfil` - Data exfiltration
- `cred` - Credential access

### Technique Values (Examples)

**Privilege Escalation:**
- `sudo` - Sudo misconfiguration
- `suid` - SUID binary exploitation
- `kernel` - Kernel exploit
- `capabilities` - Linux capabilities abuse
- `token` - Windows token impersonation
- `dll` - DLL hijacking

**Web Exploitation:**
- `sqli` - SQL injection
- `lfi` - Local file inclusion
- `rfi` - Remote file inclusion
- `upload` - File upload bypass
- `xxe` - XML external entity
- `ssti` - Server-side template injection
- `cmdinj` - Command injection

**Credential Access:**
- `reuse` - Credential reuse attack
- `bruteforce` - Brute force attack
- `dump` - Memory/database credential dump
- `kerberoast` - Kerberoasting

### Variant Values

- `basic` - Simple, straightforward technique
- `advanced` - Complex or multi-stage technique
- `bypass` - Includes filter/WAF bypass
- `manual` - Manual exploitation (no automated tools)
- `gtfobins` - Uses GTFOBins/LOLBAS
- `postgres` - PostgreSQL-specific
- `mysql` - MySQL-specific
- `error` - Error-based technique
- `blind` - Blind/inference-based

### ID Examples

```
✅ VALID:
linux-privesc-sudo-gtfobins
web-exploit-sqli-union
windows-privesc-token-advanced
linux-privesc-suid-basic
web-enum-sqli-error
network-lateral-ssh-pivot

❌ INVALID:
LinuxPrivEsc                    # Not following pattern
web_sqli_attack                 # Underscores not allowed
web-sqli                        # Missing category and variant
linux-sudo-privesc-gtfobins     # Wrong field order
linux-privesc-sudo              # Missing variant
```

---

## Command Reference Mapping

### The `command_ref` Field

**CRITICAL:** Steps do NOT contain raw commands. They reference existing commands by ID.

### Why Command References?

1. **DRY Principle:** Single source of truth for each command
2. **Validation:** Automatically verify all commands exist
3. **Updates:** Fix bugs in one place, applies to all chains
4. **Consistency:** Same command used everywhere has same syntax

### Finding Existing Commands

```bash
# List all available commands
crack reference --list

# Search for specific commands
crack reference sqli
crack reference sudo
crack reference postgres

# Get command details
crack reference --fill postgres-direct-connect
```

### Command Lookup Table

**Common OSCP Commands:**

| Task | Command ID | Location |
|------|-----------|----------|
| SQL injection detection | `sqli-detection-error` | `web/sql-injection.json` |
| SQL column enumeration | `sqli-column-enum-orderby` | `web/sql-injection.json` |
| UNION SELECT injection | `sqli-union-select-basic` | `web/sql-injection.json` |
| PostgreSQL info extraction | `sqli-union-postgresql-info` | `web/sql-injection.json` |
| PostgreSQL direct connect | `postgres-direct-connect` | `exploitation/postgresql-post-exploit.json` |
| PostgreSQL file read | `postgres-file-read` | `exploitation/postgresql-post-exploit.json` |
| SQLmap automated | `sqlmap-post-exploitation` | `web/sql-injection.json` |
| Reverse shell (bash) | `bash-reverse-shell` | `exploitation/general.json` |
| Netcat listener | `nc-listener` | `exploitation/general.json` |

### When Command Doesn't Exist

**Option 1: Check if similar command exists**
- Search variations: `sqli`, `sql-injection`, `postgresql`
- Check subcategories: `web/`, `exploitation/`, `post-exploit/`

**Option 2: Create new command**

1. Identify correct category file (e.g., `web/sql-injection.json`)
2. Add command following reference schema:

```json
{
  "id": "your-new-command-id",
  "name": "Human Readable Name",
  "category": "web",
  "subcategory": "sql-injection",
  "command": "command --flag <PLACEHOLDER>",
  "description": "Brief description",
  "tags": ["SQLI", "OSCP:HIGH"],
  "variables": [
    {
      "name": "<PLACEHOLDER>",
      "description": "What this value represents",
      "example": "192.168.45.100",
      "required": true
    }
  ],
  "flag_explanations": {
    "--flag": "What this flag does and why"
  },
  "success_indicators": ["keyword indicating success"],
  "failure_indicators": ["error message patterns"],
  "next_steps": ["command-id-to-run-next"],
  "alternatives": ["alternative-command-id"],
  "oscp_relevance": "high"
}
```

3. Validate: `crack reference --validate`
4. Test: `crack reference --fill your-new-command-id`

**Option 3: Document missing command**

If creating command is outside scope, document in chain `notes`:

```json
"notes": "Step 3 requires 'grep-config-passwords' command (not yet created). Manual alternative: grep -r 'password' /var/www/html/*.php"
```

---

## Step Structure

### Required Step Fields

```json
{
  "name": "Short Step Title",
  "objective": "What this step aims to achieve",
  "command_ref": "existing-command-id"
}
```

### Optional Step Fields

```json
{
  "id": "step-identifier",
  "name": "Enumerate Database Tables",
  "objective": "Extract table names from MySQL information_schema",
  "description": "Detailed instructions: Use UNION SELECT to query information_schema.tables WHERE table_schema NOT IN ('mysql','information_schema'). Focus on tables containing 'user', 'admin', 'credential' keywords.",
  "command_ref": "sqli-union-mysql-info",
  "evidence": [
    "Table names visible in page output",
    "users, admin, credentials tables identified"
  ],
  "dependencies": ["detect-sqli", "enum-columns"],
  "repeatable": true,
  "success_criteria": [
    "At least one table name extracted",
    "Table names documented for next step",
    "No SQL syntax errors"
  ],
  "failure_conditions": [
    "Column count mismatch error",
    "Access denied to information_schema",
    "WAF blocking UNION keyword"
  ],
  "next_steps": ["extract-credentials", "dump-user-table"]
}
```

### Field Explanations

| Field | Purpose | Example |
|-------|---------|---------|
| `id` | Reference this step in dependencies | `detect-sqli` |
| `name` | Brief step title (5-8 words) | `Confirm SQL Injection Vulnerability` |
| `objective` | Goal of step (1 sentence) | `Verify parameter is vulnerable to SQL injection using error-based technique` |
| `description` | Detailed instructions (optional) | `Test parameter with single quote payload. Look for PostgreSQL-specific error messages...` |
| `command_ref` | ID of command to execute | `sqli-detection-error` |
| `evidence` | Expected artifacts | `["ERROR: syntax error", "PostgreSQL version in error message"]` |
| `dependencies` | Step IDs that must complete first | `["step-1", "step-2"]` |
| `repeatable` | Can step run multiple times? | `true` (for fuzzing, enumeration) |
| `success_criteria` | How to confirm success | `["Error message visible", "Database type identified"]` |
| `failure_conditions` | Common failure modes | `["No error (not vulnerable)", "WAF blocking"]` |
| `next_steps` | Logical follow-up steps | `["enum-columns", "test-union"]` |

### Step Dependency Rules

**Linear Chain (No Dependencies):**
```json
"steps": [
  {"id": "step-1", "name": "First", "objective": "...", "command_ref": "cmd-1"},
  {"id": "step-2", "name": "Second", "objective": "...", "command_ref": "cmd-2"},
  {"id": "step-3", "name": "Third", "objective": "...", "command_ref": "cmd-3"}
]
```
Steps execute in order: 1 → 2 → 3

**Parallel Steps (Some Steps Independent):**
```json
"steps": [
  {"id": "scan-ports", "name": "Port Scan", "objective": "...", "command_ref": "nmap-scan"},
  {"id": "enum-web", "name": "Web Enum", "objective": "...", "command_ref": "gobuster", "dependencies": ["scan-ports"]},
  {"id": "enum-smb", "name": "SMB Enum", "objective": "...", "command_ref": "smbclient", "dependencies": ["scan-ports"]}
]
```
After `scan-ports` completes, `enum-web` and `enum-smb` can run in parallel.

**Branching Chain (Multiple Paths):**
```json
"steps": [
  {"id": "detect-sqli", "name": "Detect SQLi", "objective": "...", "command_ref": "sqli-detect"},
  {"id": "mysql-enum", "name": "MySQL Enum", "objective": "...", "command_ref": "sqli-mysql", "dependencies": ["detect-sqli"]},
  {"id": "postgres-enum", "name": "PostgreSQL Enum", "objective": "...", "command_ref": "sqli-postgres", "dependencies": ["detect-sqli"]},
  {"id": "extract-creds", "name": "Extract Credentials", "objective": "...", "command_ref": "dump-creds", "dependencies": ["mysql-enum", "postgres-enum"]}
]
```
After `detect-sqli`, try both database types. `extract-creds` waits for either to succeed.

**Validation Rule:** No circular dependencies allowed!

```json
❌ INVALID (Circular):
{"id": "step-a", "dependencies": ["step-b"]},
{"id": "step-b", "dependencies": ["step-a"]}

❌ INVALID (Self-referential):
{"id": "step-x", "dependencies": ["step-x"]}

❌ INVALID (Undefined):
{"id": "step-1", "dependencies": ["step-999"]}  // step-999 doesn't exist
```

---

## Metadata Guidelines

### Required Metadata Fields

```json
"metadata": {
  "author": "FirstName LastName or GitHub Username",
  "created": "2025-10-13",
  "updated": "2025-10-13",
  "tags": ["TAG1", "TAG2", "TAG3"],
  "category": "privilege_escalation"
}
```

### Tag Conventions

**Format:** UPPERCASE_UNDERSCORE

**Priority Tags (Include if applicable):**
- `OSCP` - Confirmed OSCP exam technique
- `HTB` - From HackTheBox walkthrough
- `QUICK_WIN` - Fast exploitation (<10 minutes)
- `MANUAL_REQUIRED` - Cannot be fully automated

**Technique Tags:**
- `SQL_INJECTION`, `LFI`, `RFI`, `COMMAND_INJECTION`, `XXE`, `SSTI`
- `SUDO`, `SUID`, `KERNEL_EXPLOIT`, `CAPABILITIES`
- `CREDENTIAL_REUSE`, `BRUTE_FORCE`, `PASSWORD_SPRAY`

**Target Tags:**
- `LINUX`, `WINDOWS`, `WEB`, `NETWORK`
- `MYSQL`, `POSTGRESQL`, `MSSQL`, `ORACLE`
- `SSH`, `SMB`, `FTP`, `HTTP`, `HTTPS`

**Example Tag Set:**
```json
"tags": [
  "OSCP",
  "SQL_INJECTION",
  "POSTGRESQL",
  "FILE_READ",
  "CREDENTIAL_ACCESS",
  "QUICK_WIN"
]
```

### Optional Metadata Fields

```json
"metadata": {
  // ... required fields ...
  "platform": "linux",
  "references": [
    "https://gtfobins.github.io/gtfobins/sudo/",
    "https://book.hacktricks.xyz/linux-unix/privilege-escalation"
  ]
}
```

### Category Values

| Category | Description | Example Chains |
|----------|-------------|----------------|
| `enumeration` | Information gathering | SQLi detection, directory fuzzing |
| `privilege_escalation` | Elevating permissions | Sudo exploit, SUID abuse, kernel exploit |
| `lateral_movement` | Moving through network | SSH pivoting, pass-the-hash |
| `persistence` | Maintaining access | Backdoor creation, SSH keys |
| `credential_access` | Obtaining credentials | Password dumps, Kerberoasting |
| `exfiltration` | Data extraction | File download, database dump |

---

## Validation Workflow

### 1. Schema Validation

```bash
# Validate single chain
crack reference chains validate linux-privesc-sudo-gtfobins

# Validate all chains
crack reference chains validate --all

# Validate specific category
find reference/data/attack_chains/privilege_escalation -name "*.json" -exec crack reference chains validate {} \;
```

**Common Schema Errors:**

```
❌ Missing required field:
Error: /metadata: 'author' is a required property

Fix: Add "author": "Your Name" to metadata object

❌ Invalid ID format:
Error: /id: 'Linux_Privesc_Sudo' does not match pattern '^[a-z0-9]+-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+$'

Fix: Change to "linux-privesc-sudo-basic" (lowercase, hyphens only)

❌ Invalid difficulty:
Error: /difficulty: 'hard' is not one of ['beginner', 'intermediate', 'advanced', 'expert']

Fix: Use exact enum value: "intermediate"

❌ Invalid time estimate:
Error: /time_estimate: '30min' does not match pattern '^\d+\s*(minutes?|hours?|days?)$'

Fix: Change to "30 minutes" (space + full word)
```

### 2. Command Reference Validation

```bash
# Check if all command_refs exist
crack reference chains validate linux-privesc-sudo-gtfobins
```

**Common Command Reference Errors:**

```
❌ Command not found:
Error: steps/2: Command 'sudo-exploit-vim' could not be resolved

Fix:
1. Search for existing command: crack reference sudo vim
2. If exists, use correct ID: "sudo-gtfobins-vim"
3. If doesn't exist, create command or document in notes

❌ Typo in command_ref:
Error: steps/0: Command 'sqli-detction-error' could not be resolved

Fix: Correct spelling: "sqli-detection-error"
```

### 3. Circular Dependency Check

```bash
# Automatically checked during validation
crack reference chains validate linux-privesc-sudo-gtfobins
```

**Common Dependency Errors:**

```
❌ Circular dependency:
Error: Circular dependency detected: step-a -> step-b -> step-c -> step-a

Fix: Break cycle by removing one dependency

❌ Undefined dependency:
Error: step 'extract-creds' depends on undefined step 'enum-db'

Fix:
1. Check step ID spelling
2. Ensure dependency step exists before reference
3. Add missing step

❌ Self-reference:
Error: step 'enum-tables' depends on itself

Fix: Remove self from dependencies array
```

### 4. CLI Testing

```bash
# List chains
crack reference chains list

# Filter by category
crack reference chains list --category privilege_escalation

# Show chain details
crack reference chains show linux-privesc-sudo-gtfobins

# Validate JSON format
jq empty reference/data/attack_chains/privilege_escalation/linux-privesc-sudo-gtfobins.json
```

---

## Complete Examples

### Example 1: Simple Linear Chain (Beginner)

**File:** `reference/data/attack_chains/privilege_escalation/linux-privesc-suid-basic.json`

```json
{
  "id": "linux-privesc-suid-basic",
  "name": "SUID Binary Privilege Escalation (Basic)",
  "description": "Exploit misconfigured SUID binary using GTFOBins to gain root shell",
  "version": "1.0.0",
  "metadata": {
    "author": "CRACK Development Team",
    "created": "2025-10-13",
    "updated": "2025-10-13",
    "tags": [
      "OSCP",
      "LINUX",
      "PRIVILEGE_ESCALATION",
      "SUID",
      "GTFOBINS",
      "QUICK_WIN"
    ],
    "category": "privilege_escalation",
    "platform": "linux",
    "references": [
      "https://gtfobins.github.io/",
      "https://book.hacktricks.xyz/linux-unix/privilege-escalation#suid"
    ]
  },
  "difficulty": "beginner",
  "time_estimate": "15 minutes",
  "oscp_relevant": true,
  "prerequisites": [
    "Shell access as low-privilege user (www-data, user, etc.)",
    "Target system is Linux"
  ],
  "notes": "SUID binaries with setuid bit set run with owner's privileges (usually root). Misconfigured binaries like find, vim, nmap, base64 can be exploited for privilege escalation. GTFOBins provides exploitation techniques. This chain covers the most common OSCP scenario: finding SUID binary and exploiting it for root shell.",
  "steps": [
    {
      "id": "find-suid",
      "name": "Enumerate SUID Binaries",
      "objective": "Locate all SUID binaries on system using find command",
      "description": "Search entire filesystem for files with SUID bit set (-perm -4000). Redirect errors to /dev/null to avoid permission denied noise.",
      "command_ref": "find-suid-binaries",
      "evidence": [
        "List of SUID binary paths",
        "Binaries owned by root",
        "Custom or unusual SUID binaries visible"
      ],
      "success_criteria": [
        "Find command executes without errors",
        "At least 10-20 SUID binaries discovered",
        "Results include non-standard binaries (not just passwd, sudo, ping)"
      ],
      "failure_conditions": [
        "Find command syntax error",
        "All directories permission denied (wrong user context)",
        "No results returned (unlikely on real system)"
      ]
    },
    {
      "id": "filter-interesting",
      "name": "Identify Exploitable SUID Binaries",
      "objective": "Filter out standard system binaries and focus on exploitable candidates",
      "description": "Exclude common system binaries (passwd, sudo, ping, mount) that are expected to have SUID. Look for: find, vim, nmap, base64, less, more, python, perl, awk, etc.",
      "command_ref": "filter-suid-binaries",
      "dependencies": ["find-suid"],
      "evidence": [
        "Shortened list of interesting binaries",
        "GTFOBins-listed binaries identified",
        "Custom application binaries"
      ],
      "success_criteria": [
        "Filtered list contains 1-5 interesting binaries",
        "At least one binary has known GTFOBins technique",
        "Binaries are executable by current user"
      ],
      "failure_conditions": [
        "No interesting binaries remain after filtering",
        "All binaries are standard system tools",
        "Binaries require specific conditions not present"
      ]
    },
    {
      "id": "check-gtfobins",
      "name": "Lookup GTFOBins Exploitation Technique",
      "objective": "Find exploitation technique for discovered SUID binary on GTFOBins website",
      "description": "Visit https://gtfobins.github.io/ and search for binary name. Look for 'SUID' section specifically. Copy exploitation command syntax.",
      "command_ref": "gtfobins-suid-lookup",
      "dependencies": ["filter-interesting"],
      "evidence": [
        "GTFOBins page loaded",
        "SUID section present for binary",
        "Exploitation command documented"
      ],
      "success_criteria": [
        "Binary has GTFOBins entry",
        "SUID exploitation technique documented",
        "Command syntax is clear and testable"
      ],
      "failure_conditions": [
        "Binary not listed on GTFOBins",
        "No SUID section for binary",
        "Technique requires additional prerequisites"
      ]
    },
    {
      "id": "exploit-suid",
      "name": "Execute SUID Exploitation",
      "objective": "Run GTFOBins command to escalate privileges and spawn root shell",
      "description": "Execute exploitation command exactly as documented on GTFOBins. Common example: /usr/bin/find . -exec /bin/bash -p \\; -quit",
      "command_ref": "execute-suid-exploit",
      "dependencies": ["check-gtfobins"],
      "evidence": [
        "Command executes without errors",
        "Shell prompt changes to root indicator",
        "Elevated privileges confirmed"
      ],
      "success_criteria": [
        "Root shell spawned (# prompt)",
        "whoami returns 'root'",
        "id shows uid=0(root) or euid=0(root)"
      ],
      "failure_conditions": [
        "Permission denied error",
        "Binary not found (wrong path)",
        "Shell spawns but not privileged (missing -p flag for bash)"
      ],
      "next_steps": ["verify-root"]
    },
    {
      "id": "verify-root",
      "name": "Verify Root Access",
      "objective": "Confirm effective UID is 0 and full root privileges obtained",
      "description": "Run whoami and id commands to verify root access. Check if you can read /etc/shadow or /root/ directory.",
      "command_ref": "verify-root-access",
      "dependencies": ["exploit-suid"],
      "evidence": [
        "whoami output: root",
        "id output: uid=0(root) gid=0(root) or euid=0(root)",
        "Can access /etc/shadow",
        "Can list /root/ directory"
      ],
      "success_criteria": [
        "Effective UID is 0",
        "Root filesystem access confirmed",
        "Can read sensitive files"
      ],
      "failure_conditions": [
        "UID is not 0 (privilege escalation failed)",
        "Cannot access root-only files",
        "Effective UID differs from real UID (may need -p flag)"
      ]
    }
  ]
}
```

### Example 2: Complex Chain with Branching (Intermediate)

**File:** `reference/data/attack_chains/enumeration/web-sqli-union-dump.json`

```json
{
  "id": "web-enum-sqli-union",
  "name": "SQL Injection UNION-Based Data Extraction",
  "description": "Detect SQL injection, enumerate database structure, and extract credentials using UNION SELECT technique",
  "version": "1.0.0",
  "metadata": {
    "author": "CRACK Development Team",
    "created": "2025-10-13",
    "updated": "2025-10-13",
    "tags": [
      "OSCP",
      "WEB",
      "SQL_INJECTION",
      "UNION",
      "ENUMERATION",
      "CREDENTIAL_ACCESS",
      "MANUAL_REQUIRED"
    ],
    "category": "enumeration",
    "references": [
      "https://portswigger.net/web-security/sql-injection/union-attacks",
      "https://book.hacktricks.xyz/pentesting-web/sql-injection"
    ]
  },
  "difficulty": "intermediate",
  "time_estimate": "30 minutes",
  "oscp_relevant": true,
  "prerequisites": [
    "Web application with user input parameters",
    "Network access to target web server",
    "curl or web browser available"
  ],
  "notes": "UNION SELECT is the most common SQLi technique in OSCP. This chain demonstrates MANUAL exploitation workflow required for exam documentation. Always attempt manual techniques before using sqlmap. Column count enumeration is CRITICAL - UNION requires exact column match between original query and injected SELECT.",
  "steps": [
    {
      "id": "detect-sqli",
      "name": "Detect SQL Injection Vulnerability",
      "objective": "Confirm parameter is vulnerable to SQL injection using error-based technique",
      "description": "Test parameter with single quote payload (e.g., id=1'). Look for database error messages in HTTP response revealing backend type (MySQL, PostgreSQL, MSSQL).",
      "command_ref": "sqli-detection-error",
      "evidence": [
        "Database error message visible",
        "Error reveals database type",
        "Query syntax visible in error"
      ],
      "success_criteria": [
        "Error message confirms SQL injection",
        "Database type identified (MySQL/PostgreSQL/MSSQL)",
        "Vulnerable parameter confirmed"
      ],
      "failure_conditions": [
        "No error messages (potential blind SQLi)",
        "WAF blocking requests (403 Forbidden)",
        "Generic error page (no database details)"
      ]
    },
    {
      "id": "enum-columns",
      "name": "Enumerate Column Count",
      "objective": "Determine number of columns in SQL query using ORDER BY technique",
      "description": "Increment ORDER BY value (ORDER BY 1, ORDER BY 2, ...) until error occurs. Last successful value = column count. Required for UNION SELECT.",
      "command_ref": "sqli-column-enum-orderby",
      "dependencies": ["detect-sqli"],
      "evidence": [
        "Last successful ORDER BY number",
        "Error when exceeding column count",
        "Column count documented"
      ],
      "success_criteria": [
        "Column count determined (e.g., 4 columns)",
        "ORDER BY X succeeds, ORDER BY X+1 fails",
        "No syntax errors"
      ],
      "failure_conditions": [
        "All ORDER BY values error (wrong syntax)",
        "No errors at any value (different technique needed)",
        "WAF blocking ORDER BY keyword"
      ]
    },
    {
      "id": "test-union",
      "name": "Test UNION SELECT Injection",
      "objective": "Verify UNION injection works and identify displayed columns",
      "description": "Use UNION SELECT with NULL values matching column count. Replace NULLs with test strings ('test1', 'test2') to identify which columns appear on page.",
      "command_ref": "sqli-union-select-basic",
      "dependencies": ["enum-columns"],
      "evidence": [
        "Test strings visible in page output",
        "Displayed column positions identified",
        "No column count mismatch errors"
      ],
      "success_criteria": [
        "UNION query executes successfully",
        "At least one test string visible",
        "Column positions documented for extraction"
      ],
      "failure_conditions": [
        "Column count mismatch error",
        "Type conversion error (need CAST)",
        "No injected data visible (hidden columns)"
      ]
    },
    {
      "id": "identify-database",
      "name": "Identify Database Type and Version",
      "objective": "Extract database type, version, current database, and user",
      "description": "Use database-specific functions in UNION SELECT: MySQL (version(), database(), user()), PostgreSQL (version(), current_database(), current_user), MSSQL (@@version, DB_NAME(), USER_NAME()).",
      "command_ref": "sqli-union-database-info",
      "dependencies": ["test-union"],
      "evidence": [
        "Database version string visible",
        "Current database name extracted",
        "Database user identified"
      ],
      "success_criteria": [
        "All metadata extracted successfully",
        "Database version confirmed",
        "Current database name known"
      ],
      "failure_conditions": [
        "Wrong database functions used",
        "Syntax error (wrong DBMS)",
        "Output not visible (wrong column position)"
      ],
      "next_steps": ["enum-mysql-tables", "enum-postgres-tables", "enum-mssql-tables"]
    },
    {
      "id": "enum-mysql-tables",
      "name": "Enumerate MySQL Tables",
      "objective": "Extract table names from MySQL information_schema",
      "description": "Query information_schema.tables to get all table names in current database. Filter out system databases.",
      "command_ref": "sqli-union-mysql-info",
      "dependencies": ["identify-database"],
      "evidence": [
        "Table names visible in output",
        "Users, admin, credentials tables identified"
      ],
      "success_criteria": [
        "At least one table name extracted",
        "Non-system tables identified",
        "Promising tables (users, admin, etc.) found"
      ],
      "failure_conditions": [
        "Access denied to information_schema",
        "No tables visible (wrong column position)",
        "Syntax error"
      ],
      "next_steps": ["extract-mysql-data"]
    },
    {
      "id": "enum-postgres-tables",
      "name": "Enumerate PostgreSQL Tables",
      "objective": "Extract table names from PostgreSQL pg_catalog",
      "description": "Query information_schema.tables or pg_catalog.pg_tables for table names in public schema.",
      "command_ref": "sqli-union-postgresql-info",
      "dependencies": ["identify-database"],
      "evidence": [
        "Table names visible",
        "Schema information extracted"
      ],
      "success_criteria": [
        "Tables extracted successfully",
        "Public schema tables identified"
      ],
      "failure_conditions": [
        "Wrong concatenation syntax (use || not CONCAT)",
        "Type mismatch (need ::text cast)",
        "Access denied"
      ],
      "next_steps": ["extract-postgres-data"]
    },
    {
      "id": "enum-mssql-tables",
      "name": "Enumerate MSSQL Tables",
      "objective": "Extract table names from MSSQL system views",
      "description": "Query sys.tables or information_schema.tables for table names in current database.",
      "command_ref": "sqli-union-mssql-info",
      "dependencies": ["identify-database"],
      "evidence": [
        "Table names extracted",
        "System and user tables visible"
      ],
      "success_criteria": [
        "Tables enumerated successfully",
        "User tables identified"
      ],
      "failure_conditions": [
        "Wrong concatenation (use + not ||)",
        "Type conversion error (need CAST)",
        "Access denied"
      ],
      "next_steps": ["extract-mssql-data"]
    },
    {
      "id": "extract-mysql-data",
      "name": "Extract MySQL Credentials",
      "objective": "Dump username and password columns from identified tables",
      "description": "Use UNION SELECT to extract data from users/admin tables. Use CONCAT or GROUP_CONCAT to combine multiple rows.",
      "command_ref": "sqli-union-mysql-info",
      "dependencies": ["enum-mysql-tables"],
      "evidence": [
        "Usernames and passwords visible",
        "Password hashes or plaintext extracted",
        "Multiple user records retrieved"
      ],
      "success_criteria": [
        "Credentials extracted successfully",
        "Usernames and passwords/hashes visible",
        "At least one admin/privileged account found"
      ],
      "failure_conditions": [
        "Empty result set (table empty)",
        "Wrong column names",
        "Access denied to table"
      ]
    },
    {
      "id": "extract-postgres-data",
      "name": "Extract PostgreSQL Credentials",
      "objective": "Dump credentials from PostgreSQL tables",
      "description": "Extract username and password columns using PostgreSQL concatenation (||) operator.",
      "command_ref": "sqli-union-postgresql-info",
      "dependencies": ["enum-postgres-tables"],
      "evidence": [
        "Credentials visible in output",
        "Password hashes extracted"
      ],
      "success_criteria": [
        "Data extraction successful",
        "Credentials documented"
      ],
      "failure_conditions": [
        "Syntax error (wrong concatenation)",
        "Empty table",
        "Access denied"
      ]
    },
    {
      "id": "extract-mssql-data",
      "name": "Extract MSSQL Credentials",
      "objective": "Dump credentials from MSSQL tables",
      "description": "Extract data using MSSQL + concatenation operator and CAST for type conversion.",
      "command_ref": "sqli-union-mssql-info",
      "dependencies": ["enum-mssql-tables"],
      "evidence": [
        "Usernames and passwords extracted",
        "Hash values visible"
      ],
      "success_criteria": [
        "Credentials successfully dumped",
        "Admin accounts identified"
      ],
      "failure_conditions": [
        "Type conversion error",
        "Access denied",
        "Empty result set"
      ]
    }
  ]
}
```

---

## Migration from Track Module

### Track vs Reference Schema Differences

| Track Field | Reference Field | Conversion |
|-------------|-----------------|------------|
| `command_template` | `command_ref` | Map to existing command ID |
| `manual_alternative` | `notes` or create new command | Document in notes or create command |
| `success_indicators` | `success_criteria` (step-level) | Move to step object |
| `failure_indicators` | `failure_conditions` (step-level) | Move to step object |
| `trigger_finding_types` | `tags` (metadata) | Convert to tags |
| `required_phase` | `category` (metadata) | Map phase to category |
| `oscp_relevance` (float) | `oscp_relevant` (boolean) | Convert: >0.7 = true |
| `estimated_time_minutes` | `time_estimate` (string) | Format: "X minutes" |

### Conversion Script Template

```python
#!/usr/bin/env python3
"""Convert track attack chains to reference format."""

import json
from pathlib import Path

def convert_track_chain(track_chain):
    """Convert single track chain to reference schema."""

    # Map phase to category
    phase_to_category = {
        "EXPLOITATION": "enumeration",
        "POST_EXPLOITATION": "privilege_escalation",
        "LATERAL_MOVEMENT": "lateral_movement"
    }

    # Map difficulty from OSCP relevance
    def get_difficulty(oscp_relevance):
        if oscp_relevance >= 0.9:
            return "beginner"
        elif oscp_relevance >= 0.75:
            return "intermediate"
        elif oscp_relevance >= 0.6:
            return "advanced"
        else:
            return "expert"

    return {
        "id": track_chain["id"],
        "name": track_chain["name"],
        "description": track_chain["description"],
        "version": "1.0.0",
        "metadata": {
            "author": "Migrated from Track Module",
            "created": "2025-10-13",
            "updated": "2025-10-13",
            "tags": track_chain.get("trigger_finding_types", []),
            "category": phase_to_category.get(
                track_chain.get("required_phase", "EXPLOITATION"),
                "enumeration"
            )
        },
        "difficulty": get_difficulty(track_chain.get("oscp_relevance", 0.5)),
        "time_estimate": f"{track_chain.get('estimated_total_time_minutes', 30)} minutes",
        "oscp_relevant": track_chain.get("oscp_relevance", 0) > 0.7,
        "steps": [
            convert_track_step(step) for step in track_chain.get("steps", [])
        ]
    }

def convert_track_step(track_step):
    """Convert track step to reference step."""

    # Map command template to command_ref
    # This requires manual mapping or command creation
    command_ref = map_command_template(track_step.get("command_template", ""))

    return {
        "id": track_step.get("id"),
        "name": track_step.get("name"),
        "objective": track_step.get("description", ""),
        "command_ref": command_ref,
        "evidence": track_step.get("success_indicators", []),
        "success_criteria": track_step.get("success_indicators", []),
        "failure_conditions": track_step.get("failure_indicators", [])
    }

def map_command_template(command_template):
    """Map track command template to reference command ID."""

    # Common mappings
    mappings = {
        "sqlmap -u": "sqlmap-post-exploitation",
        "curl.*sqli": "sqli-detection-error",
        "find / -perm -u=s": "find-suid-binaries",
        "sudo -l": "sudo-list-permissions",
        # ... add more mappings
    }

    for pattern, command_id in mappings.items():
        if pattern in command_template:
            return command_id

    # Default fallback
    return "UNMAPPED-COMMAND"

# Usage
track_chains_file = Path("crack/track/intelligence/patterns/attack_chains.json")
track_data = json.loads(track_chains_file.read_text())

for track_chain in track_data["attack_chains"]:
    reference_chain = convert_track_chain(track_chain)

    # Save to reference directory
    category = reference_chain["metadata"]["category"]
    output_dir = Path(f"crack/reference/data/attack_chains/{category}")
    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / f"{reference_chain['id']}.json"
    output_file.write_text(json.dumps(reference_chain, indent=2))

    print(f"✓ Converted: {reference_chain['id']}")
```

### Manual Migration Checklist

For each track chain:

- [ ] Copy chain structure to new file
- [ ] Update `id` to follow reference naming convention
- [ ] Add `version: "1.0.0"`
- [ ] Create `metadata` object with required fields
- [ ] Map `required_phase` to `category`
- [ ] Convert `oscp_relevance` float to boolean
- [ ] Format `time_estimate` as string with units
- [ ] For each step:
  - [ ] Map `command_template` to `command_ref`
  - [ ] Create missing commands if needed
  - [ ] Move `success_indicators` to step-level `success_criteria`
  - [ ] Move `failure_indicators` to step-level `failure_conditions`
  - [ ] Add `objective` field
- [ ] Validate: `crack reference chains validate <chain-id>`
- [ ] Test: `crack reference chains show <chain-id>`

---

## Common Pitfalls

### 1. ID Format Violations

```
❌ Using uppercase: Linux-PrivEsc-Sudo
✅ All lowercase: linux-privesc-sudo-basic

❌ Using underscores: linux_privesc_sudo
✅ Using hyphens: linux-privesc-sudo-basic

❌ Missing variant: web-sqli-union
✅ Include variant: web-sqli-union-manual

❌ Wrong order: linux-sudo-privesc-basic
✅ Correct order: linux-privesc-sudo-basic
```

### 2. Command Reference Errors

```
❌ Hardcoded command in step:
"command_ref": "sqlmap -u http://target --dump"

✅ Reference existing command:
"command_ref": "sqlmap-post-exploitation"

❌ Non-existent command:
"command_ref": "my-custom-exploit"  // Command doesn't exist

✅ Create command first or document:
"command_ref": "documented-exploit",
"notes": "Command 'documented-exploit' pending creation"
```

### 3. Circular Dependencies

```
❌ Circular dependency:
{
  "id": "step-a",
  "dependencies": ["step-b"]
},
{
  "id": "step-b",
  "dependencies": ["step-a"]
}

✅ Linear dependency:
{
  "id": "step-a"
},
{
  "id": "step-b",
  "dependencies": ["step-a"]
}
```

### 4. Missing Required Fields

```
❌ Missing step objective:
{
  "name": "Exploit SUID",
  "command_ref": "exploit-suid"
}

✅ Include objective:
{
  "name": "Exploit SUID",
  "objective": "Execute SUID binary to escalate privileges",
  "command_ref": "exploit-suid"
}
```

### 5. Time Estimate Format

```
❌ Wrong format: "30min", "1h", "45m"
✅ Correct format: "30 minutes", "1 hour", "45 minutes"

❌ Plural missing: "1 minute"
✅ Singular for 1: "1 minute"
✅ Plural for >1: "30 minutes"
```

### 6. Tag Conventions

```
❌ Lowercase tags: "oscp", "sqli", "linux"
✅ Uppercase with underscores: "OSCP", "SQLI", "LINUX"

❌ Spaces in tags: "SQL INJECTION"
✅ Underscores: "SQL_INJECTION"

❌ Inconsistent naming: "SQLi", "SQL_INJECTION", "sql-injection"
✅ Pick one: "SQL_INJECTION" (preferred)
```

### 7. Metadata Platform Inconsistency

```
❌ Platform doesn't match ID:
"id": "linux-privesc-sudo-basic"
"metadata": {
  "platform": "windows"  // Mismatch!
}

✅ Consistent:
"id": "linux-privesc-sudo-basic"
"metadata": {
  "platform": "linux"
}
```

---

## Quick Start Template

Copy this minimal template to start a new chain:

```json
{
  "id": "CHANGE-ME-category-technique-variant",
  "name": "CHANGE ME Human Readable Name",
  "description": "CHANGE ME: Brief one-sentence description",
  "version": "1.0.0",
  "metadata": {
    "author": "CHANGE ME",
    "created": "2025-10-13",
    "updated": "2025-10-13",
    "tags": ["TAG1", "TAG2", "TAG3"],
    "category": "CHANGE-ME-category"
  },
  "difficulty": "intermediate",
  "time_estimate": "30 minutes",
  "oscp_relevant": true,
  "prerequisites": [],
  "notes": "",
  "steps": [
    {
      "id": "step-1",
      "name": "Step 1 Name",
      "objective": "What this step achieves",
      "command_ref": "existing-command-id",
      "success_criteria": ["Success indicator 1"],
      "failure_conditions": ["Failure indicator 1"]
    }
  ]
}
```

---

## Validation Checklist

Before submitting chain:

- [ ] ID follows pattern: `{platform}-{category}-{technique}-{variant}`
- [ ] All required fields present (id, name, description, version, metadata, difficulty, time_estimate, oscp_relevant, steps)
- [ ] Metadata has all required fields (author, created, updated, tags, category)
- [ ] Tags are UPPERCASE_UNDERSCORE format
- [ ] Time estimate has space and full word ("30 minutes" not "30min")
- [ ] All `command_ref` values reference existing commands
- [ ] No circular dependencies between steps
- [ ] Step objectives are clear and concise
- [ ] Success criteria and failure conditions are specific
- [ ] Schema validation passes: `crack reference chains validate <chain-id>`
- [ ] CLI display works: `crack reference chains show <chain-id>`
- [ ] JSON is valid: `jq empty <file>.json`

---

## Getting Help

**Validation Errors:**
```bash
crack reference chains validate <chain-id>
```

**Command Lookup:**
```bash
crack reference --list | grep <keyword>
crack reference <keyword>
```

**Schema Reference:**
```bash
cat crack/reference/schemas/attack_chain.schema.json | jq
```

**Example Chains:**
```bash
ls crack/reference/data/attack_chains/**/*.json
crack reference chains list
```

**Documentation:**
- Attack Chain Schema: `crack/reference/schemas/attack_chain.schema.json`
- Command Reference Schema: `crack/reference/schemas/command.schema.json`
- Architecture Overview: `crack/attack-chains-checklist.md`

---

## Document Version

**Version:** 1.0.0
**Last Updated:** 2025-10-13
**Maintainer:** CRACK Development Team
